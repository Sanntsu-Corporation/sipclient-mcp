package sipua_test

// Lane D (cf5-d) Task 4: the bound on held INVITE handlers (CF-177) and
// merged-request detection (CF-097, RFC 3261 8.2.2.2). No test calls
// t.Parallel.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// limitedUA is uasUA with Config.CallLimit set.
func limitedUA(t *testing.T, limit func() int) (*sipua.UA, func() []session.UAEvent, *rawUAC, string) {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		WrapConn:  func(pc net.PacketConn) net.PacketConn { return pc },
		CallLimit: limit,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, collect(t, ua), newRawUAC(t, ua), "sip:alice@" + ua.BoundAddr().String()
}

func waitInbound(t *testing.T, events func() []session.UAEvent, n int) {
	t.Helper()
	if !stubWait(func() bool { return countInbound(events()) >= n }, 3*time.Second) {
		t.Fatalf("%d inbound events, want %d", countInbound(events()), n)
	}
}

func TestRFC3261_NEWA28_MergedRequestDraws482(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	r.send(r.invite(ruri, "cf5d-merged@127.0.0.1", "z9hG4bKcf5dM1", 1, ""))
	waitInbound(t, events, 1)
	r.send(r.invite(ruri, "cf5d-merged@127.0.0.1", "z9hG4bKcf5dM2", 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 482) }, 3*time.Second) {
		t.Fatal("the merged INVITE drew no 482")
	}
	time.Sleep(200 * time.Millisecond)
	if n := countInbound(events()); n != 1 {
		t.Errorf("%d inbound calls for two merged INVITEs, want 1", n)
	}
}

func TestMergedCheckNeedsAllThreeKeys(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	r.send(r.invite(ruri, "cf5d-m3@127.0.0.1", "z9hG4bKcf5dK1", 1, ""))
	waitInbound(t, events, 1)
	r.send(r.invite(ruri, "cf5d-m3@127.0.0.1", "z9hG4bKcf5dK2", 2, "")) // CSeq differs
	waitInbound(t, events, 2)
	other := strings.Replace(r.invite(ruri, "cf5d-m3@127.0.0.1", "z9hG4bKcf5dK3", 1, ""), "tag=rfcsweepa", "tag=other", 1)
	r.send(other) // From tag differs
	waitInbound(t, events, 3)
	if r.hasCode("INVITE", 482) {
		t.Error("a request differing in one key element drew 482")
	}
}

func TestSameBranchFromAnotherSentByIsMerged(t *testing.T) {
	old1, old2, old4 := sip.T1, sip.T2, sip.T4
	sip.SetTimers(old1, old2, 200*time.Millisecond) // Timer I = 200 ms
	t.Cleanup(func() { sip.SetTimers(old1, old2, old4) })
	ua, events, r1, ruri := uasUA(t)
	r2 := newRawUAC(t, ua)
	const cid, br = "cf5d-sentby@127.0.0.1", "z9hG4bKcf5dSB"
	r1.send(r1.invite(ruri, cid, br, 1, ""))
	in := waitFor(t, events, session.UAEventInbound, 0)
	r2.send(r2.invite(ruri, cid, br, 1, ""))
	if !stubWait(func() bool { return r2.hasCode("INVITE", 482) }, 3*time.Second) {
		t.Fatal("the same-branch request from another sent-by drew no 482")
	}
	if n := countInbound(events()); n != 1 {
		t.Errorf("%d inbound events, want 1", n)
	}
	// End the first call's transaction: reject, ACK; its key is then released.
	if err := ua.Reject(context.Background(), in.DialogID, 486, ""); err != nil {
		t.Fatal(err)
	}
	if !stubWait(func() bool { return r1.hasCode("INVITE", 486) }, 3*time.Second) {
		t.Fatal("no 486")
	}
	_, msgs := r1.responses("INVITE")
	var to string
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 486") {
			to = stubHeaders(m, "To")[0]
		}
	}
	ack := "ACK " + ruri + " SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:" + r1.port() + ";branch=" + br + "\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\nTo: " + to + "\r\nCall-ID: " + cid + "\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
	r1.send(ack)
	if !stubWait(func() bool { h, _ := ua.HeldInviteCounts(); return h == 0 }, 3*time.Second) {
		t.Fatal("the first call's hold did not end")
	}
	r1.send(r1.invite(ruri, cid, "z9hG4bKcf5dSB3", 1, ""))
	waitInbound(t, events, 2)
}

func TestHeldInviteBoundDraws503(t *testing.T) {
	_, events, r, ruri := limitedUA(t, func() int { return 1 })
	for i := 0; i < 4; i++ {
		id := string(rune('a' + i))
		r.send(r.invite(ruri, "cf5d-hb"+id+"@127.0.0.1", "z9hG4bKcf5dHB"+id, 1, ""))
	}
	waitInbound(t, events, 4)
	r.send(r.invite(ruri, "cf5d-hbe@127.0.0.1", "z9hG4bKcf5dHBe", 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 503) }, 3*time.Second) {
		t.Fatal("the fifth INVITE drew no 503")
	}
	_, msgs := r.responses("INVITE")
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 503") {
			if ra := stubHeaders(m, "Retry-After"); len(ra) != 1 || ra[0] != "32" {
				t.Errorf("Retry-After = %q, want 32", ra)
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := countInbound(events()); n != 4 {
		t.Errorf("%d inbound events, want 4", n)
	}
}

func TestHeldInviteBoundCountsCancelledCalls(t *testing.T) {
	_, events, r, ruri := limitedUA(t, func() int { return 1 })
	for i := 0; i < 4; i++ {
		id := string(rune('a' + i))
		br := "z9hG4bKcf5dHC" + id
		cid := "cf5d-hc" + id + "@127.0.0.1"
		r.send(r.invite(ruri, cid, br, 1, ""))
		waitInbound(t, events, i+1)
		r.send(r.request("CANCEL", ruri, cid, br, 1, "", "", ""))
		if !stubWait(func() bool { return r.hasCode("INVITE", 487) }, 3*time.Second) {
			t.Fatal("no 487")
		}
		r.mu.Lock()
		r.got, r.at = nil, nil
		r.mu.Unlock()
	}
	r.send(r.invite(ruri, "cf5d-hce@127.0.0.1", "z9hG4bKcf5dHCe", 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 503) }, 3*time.Second) {
		t.Fatal("the fifth INVITE drew no 503 although every earlier call was cancelled")
	}
}

func TestOptionsWhenTheHeldInviteBoundIsFullGets503(t *testing.T) {
	_, events, r, ruri := limitedUA(t, func() int { return 1 })
	for i := 0; i < 4; i++ {
		id := string(rune('a' + i))
		r.send(r.invite(ruri, "cf5d-ho"+id+"@127.0.0.1", "z9hG4bKcf5dHO"+id, 1, ""))
	}
	waitInbound(t, events, 4)
	m := uasFinal(t, r, "OPTIONS", 503, r.request("OPTIONS", ruri, "cf5d-hoo@127.0.0.1", "z9hG4bKcf5dHOo", 1, "", "", ""))
	if ra := stubHeaders(m, "Retry-After"); len(ra) != 1 || ra[0] != "32" {
		t.Errorf("Retry-After = %q, want 32", ra)
	}
	time.Sleep(200 * time.Millisecond)
	if n := countInbound(events()); n != 4 {
		t.Errorf("OPTIONS changed the inbound count to %d", n)
	}
}

// With the held-INVITE bound full AND admission refusing for capacity, an INVITE
// meets the bound first (503), so OPTIONS answers 503 too: RFC 3261 11, "the
// same [status] that would have been chosen had the request been an INVITE".
func TestOptionsWithBoundFullAndCapacityExhaustedMatchesTheInvite(t *testing.T) {
	ua, events, r, ruri := limitedUA(t, func() int { return 1 })
	for i := 0; i < 4; i++ {
		id := string(rune('a' + i))
		r.send(r.invite(ruri, "cf5d-bc"+id+"@127.0.0.1", "z9hG4bKcf5dBC"+id, 1, ""))
	}
	waitInbound(t, events, 4)
	ua.OnAdmit(context.Background(), func(context.Context, session.UAEvent) session.Admission {
		return session.AdmitReject(486, "Busy Here") // capacity exhausted as well
	})
	uasFinal(t, r, "OPTIONS", 503, r.request("OPTIONS", ruri, "cf5d-bco@127.0.0.1", "z9hG4bKcf5dBCo", 1, "", "", ""))
	r.send(r.invite(ruri, "cf5d-bci@127.0.0.1", "z9hG4bKcf5dBCi", 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 503) }, 3*time.Second) {
		t.Fatal("the INVITE with the bound full and capacity exhausted did not draw 503")
	}
}

func TestCloseReleasesEveryHeldInvite(t *testing.T) {
	ua, events, r, ruri := limitedUA(t, nil)
	for i := 0; i < 3; i++ {
		id := string(rune('a' + i))
		r.send(r.invite(ruri, "cf5d-cl"+id+"@127.0.0.1", "z9hG4bKcf5dCL"+id, 1, ""))
	}
	waitInbound(t, events, 3)
	if h, m := ua.HeldInviteCounts(); h != 3 || m != 3 {
		t.Fatalf("held %d merged %d, want 3 and 3", h, m)
	}
	_ = ua.Close(context.Background())
	if !stubWait(func() bool { h, m := ua.HeldInviteCounts(); return h == 0 && m == 0 }, 2*time.Second) {
		h, m := ua.HeldInviteCounts()
		t.Fatalf("after Close held %d merged %d, want 0 and 0", h, m)
	}
}
