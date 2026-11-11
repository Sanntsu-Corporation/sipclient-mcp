package sipua

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func heldTestUA(t *testing.T, limit func() int) *UA {
	t.Helper()
	ua, err := New(context.Background(), Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn:  func(pc net.PacketConn) net.PacketConn { return pc },
		CallLimit: limit,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// heldReq builds an INVITE that sip.MakeServerTxKey accepts: a top Via with the
// given branch, Call-ID, From tag and CSeq.
func heldReq(callID, fromTag, branch string, cseq uint32) *sip.Request {
	req := sip.NewRequest(sip.INVITE, sip.Uri{Scheme: "sip", User: "alice", Host: "here"})
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Port: 5060, Params: sip.NewParams()}
	via.Params.Add("branch", branch)
	req.AppendHeader(via)
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	from.Params.Add("tag", fromTag)
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	req.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: sip.INVITE})
	return req
}

func TestMergedKeyIsForgottenWhenTheHoldEnds(t *testing.T) {
	u := heldTestUA(t, nil)
	k, st := u.claimInviteHold(heldReq("c", "t", "z9hG4bKM1", 1))
	if st != 0 {
		t.Fatalf("first claim = %d", st)
	}
	u.releaseInviteHold(k)
	if _, st := u.claimInviteHold(heldReq("c", "t", "z9hG4bKM2", 1)); st != 0 {
		t.Fatalf("claim after release = %d, want 0", st)
	}
}

func TestEqualKeyHoldsAreCounted(t *testing.T) {
	u := heldTestUA(t, nil)
	k1, s1 := u.claimInviteHold(heldReq("c", "t", "z9hG4bKM1", 1))
	k2, s2 := u.claimInviteHold(heldReq("c", "t", "z9hG4bKM1", 1))
	if s1 != 0 || s2 != 0 {
		t.Fatalf("equal-key claims = %d, %d", s1, s2)
	}
	u.releaseInviteHold(k1)
	if u.calls.heldInvites != 1 {
		t.Fatalf("heldInvites = %d, want 1", u.calls.heldInvites)
	}
	if _, st := u.claimInviteHold(heldReq("c", "t", "z9hG4bKM2", 1)); st != 482 {
		t.Fatalf("other-branch claim while one hold remains = %d, want 482", st)
	}
	u.releaseInviteHold(k2)
	if _, st := u.claimInviteHold(heldReq("c", "t", "z9hG4bKM2", 1)); st != 0 {
		t.Fatalf("other-branch claim after the last release = %d, want 0", st)
	}
}

func TestHeldInviteSlotIsFreedWhenTheHoldEnds(t *testing.T) {
	u := heldTestUA(t, func() int { return 1 }) // bound 4
	var keys []mergeKey
	for i := 0; i < 4; i++ {
		k, st := u.claimInviteHold(heldReq("c"+string(rune('a'+i)), "t", "z9hG4bKB", 1))
		if st != 0 {
			t.Fatalf("claim %d = %d", i, st)
		}
		keys = append(keys, k)
	}
	if _, st := u.claimInviteHold(heldReq("cz", "t", "z9hG4bKB", 1)); st != 503 {
		t.Fatalf("claim over the bound = %d, want 503", st)
	}
	u.releaseInviteHold(keys[0])
	if _, st := u.claimInviteHold(heldReq("cz", "t", "z9hG4bKB", 1)); st != 0 {
		t.Fatalf("claim after a release = %d, want 0", st)
	}
}

func TestHeldInviteUnboundedWithoutCallLimit(t *testing.T) {
	u := heldTestUA(t, nil)
	for i := 0; i < 100; i++ {
		if _, st := u.claimInviteHold(heldReq("c"+time.Duration(i).String(), "t", "z9hG4bKU", 1)); st != 0 {
			t.Fatalf("claim %d = %d", i, st)
		}
	}
}

func TestHeldInviteBoundFollowsTheLiveLimit(t *testing.T) {
	limit := 1
	u := heldTestUA(t, func() int { return limit })
	for i := 0; i < 4; i++ {
		if _, st := u.claimInviteHold(heldReq("c"+string(rune('a'+i)), "t", "z9hG4bKL", 1)); st != 0 {
			t.Fatalf("claim %d = %d", i, st)
		}
	}
	if _, st := u.claimInviteHold(heldReq("cz", "t", "z9hG4bKL", 1)); st != 503 {
		t.Fatalf("claim at bound 4 = %d, want 503", st)
	}
	limit = 2
	if _, st := u.claimInviteHold(heldReq("cz", "t", "z9hG4bKL", 1)); st != 0 {
		t.Fatalf("claim after the limit rose = %d, want 0", st)
	}
}
