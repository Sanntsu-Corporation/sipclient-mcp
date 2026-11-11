package sipua

// CF-130 / CF-100 (rfc-fix-1 Task 5): an in-dialog BYE, UPDATE or INFO is
// matched to its dialog by Call-ID and both tags (RFC 3261 12.2.2, 15.1.2).

import (
	"context"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

const matchPeerTag = "peer-tag-1"

// matchInvite is an INVITE from a peer whose From tag is matchPeerTag.
func matchInvite(callID string) *sip.Request {
	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	inv.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	from.Params.Add("tag", matchPeerTag)
	inv.AppendHeader(from)
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	return inv
}

// matchAnswered registers an answered inbound dialog and returns our tag.
func matchAnswered(u *UA, callID string) (*dialog, string) {
	inv := matchInvite(callID)
	d := &dialog{id: "d-" + callID, direction: session.Inbound, phase: phaseAnswered,
		callID: callID, invite: inv}
	d.ok = sip.NewResponseFromRequest(inv, 200, "OK", nil)
	d.sessionTimer = &sessionTimerState{IntervalS: 600, Refresher: "uac"}
	u.register(d)
	tag, _ := d.ok.To().Params.Get("tag")
	return d, tag
}

// matchReq builds a BYE/UPDATE/INFO with the given tags (empty = none).
func matchReq(method sip.RequestMethod, callID, fromTag, toTag string) *sip.Request {
	req := sip.NewRequest(method, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	if fromTag != "" {
		from.Params.Add("tag", fromTag)
	}
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()}
	if toTag != "" {
		to.Params.Add("tag", toTag)
	}
	req.AppendHeader(to)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 5, MethodName: method})
	return req
}

func registered(u *UA, id string) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	_, ok := u.calls.byID[id]
	return ok
}

func TestOnByeForeignFromTagIs481AndKeepsTheDialog(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, tag := matchAnswered(u, "cid-bye")
	for _, c := range []struct {
		name          string
		from, to      string
		want          sip.StatusCode
		stillRegister bool
	}{
		{"foreign From tag", "someone-else", tag, 481, true},
		{"foreign To tag", matchPeerTag, "not-our-tag", 481, true},
		{"no To tag", matchPeerTag, "", 481, true},
		{"both tags match", matchPeerTag, tag, 200, false},
	} {
		tx := &stubServerTx{}
		u.onBye(matchReq(sip.BYE, "cid-bye", c.from, c.to), tx)
		if got := tx.last().StatusCode; got != c.want {
			t.Fatalf("%s: BYE -> %d, want %d", c.name, got, c.want)
		}
		if got := registered(u, d.id); got != c.stillRegister {
			t.Fatalf("%s: dialog registered = %v, want %v", c.name, got, c.stillRegister)
		}
	}
}

func TestOnUpdateForeignFromTagIs481AndDoesNotRearm(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, tag := matchAnswered(u, "cid-upd")
	tx := &stubServerTx{}
	u.onUpdate(matchReq(sip.UPDATE, "cid-upd", "someone-else", tag), tx)
	if got := tx.last().StatusCode; got != 481 {
		t.Fatalf("UPDATE with a foreign From tag -> %d, want 481", got)
	}
	if d.sessionTimer.watchdog != nil {
		t.Fatal("a 481'd UPDATE must not rearm the watchdog")
	}
}

func TestOnInfoForeignToTagIs481(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	_, tag := matchAnswered(u, "cid-info")
	for _, c := range []struct {
		name     string
		from, to string
		want     sip.StatusCode
	}{
		{"foreign To tag", matchPeerTag, "not-our-tag", 481},
		{"foreign From tag", "someone-else", tag, 481},
		{"both tags match", matchPeerTag, tag, 200},
	} {
		tx := &stubServerTx{}
		u.onInfo(matchReq(sip.INFO, "cid-info", c.from, c.to), tx)
		if got := tx.last().StatusCode; got != c.want {
			t.Fatalf("%s: INFO -> %d, want %d", c.name, got, c.want)
		}
	}
}

// The caller "MAY send a BYE for either confirmed or early dialogs"
// (rfc3261.txt:4980-4982), but an early dialog is named by the To tag of the
// provisional that created it (RFC 3261 12.1): the one we assigned, d.toTag
// (CF-209, B-D2).
func TestEarlyInboundByeWithOurToTagEndsTheRingingDialog(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d := &dialog{id: "d-early", direction: session.Inbound, phase: phaseRinging,
		callID: "cid-early", invite: matchInvite("cid-early"), toTag: "our-180-tag"}
	u.register(d)
	tx := &stubServerTx{}
	u.onBye(matchReq(sip.BYE, "cid-early", matchPeerTag, "our-180-tag"), tx)
	if got := tx.last().StatusCode; got != 200 {
		t.Fatalf("early BYE -> %d, want 200", got)
	}
	if registered(u, d.id) {
		t.Fatal("the ringing dialog survived the caller's BYE")
	}
}

// CF-209: any other To tag on an early inbound dialog matches no dialog (481).
func TestEarlyInboundByeWithAForeignToTagIs481(t *testing.T) {
	for _, method := range []sip.RequestMethod{sip.BYE, sip.UPDATE, sip.INFO} {
		t.Run(string(method), func(t *testing.T) {
			u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
			d := &dialog{id: "d-early", direction: session.Inbound, phase: phaseRinging,
				callID: "cid-early", invite: matchInvite("cid-early"), toTag: "our-180-tag"}
			u.register(d)
			tx := &stubServerTx{}
			req := matchReq(method, "cid-early", matchPeerTag, "forged")
			switch method {
			case sip.BYE:
				u.onBye(req, tx)
			case sip.UPDATE:
				u.onUpdate(req, tx)
			default:
				u.onInfo(req, tx)
			}
			if got := tx.last().StatusCode; got != 481 {
				t.Fatalf("%s with a foreign To tag -> %d, want 481", method, got)
			}
			if !registered(u, d.id) {
				t.Fatal("a foreign-tag request removed the early dialog")
			}
		})
	}
}

// An outbound dialog before the 200: the callee "MUST NOT send a BYE on early
// dialogs" (rfc3261.txt:4980-4982); its From tag cannot equal our empty peer tag.
func TestOutboundEarlyByeFromTheCalleeIs481(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	inv := matchInvite("cid-out")
	d := &dialog{id: "d-out", direction: session.Outbound, phase: phaseRinging,
		callID: "cid-out", invite: inv}
	u.register(d)
	ourTag, _ := inv.From().Params.Get("tag")
	// "" is a BYE without a From tag: it must not match the empty peer tag an
	// outbound dialog has before its 200.
	for _, fromTag := range []string{"callee-180-tag", ""} {
		tx := &stubServerTx{}
		u.onBye(matchReq(sip.BYE, "cid-out", fromTag, ourTag), tx)
		if got := tx.last().StatusCode; got != 481 {
			t.Fatalf("outbound early BYE (From tag %q) -> %d, want 481", fromTag, got)
		}
		if !registered(u, d.id) || d.phase != phaseRinging {
			t.Fatalf("the ringing outbound call was torn down by an early BYE (From tag %q)", fromTag)
		}
	}
}

// An inbound dialog still in phaseAnswering has no 200 of ours stored, so it
// has no tag an UPDATE could be checked against: a tagged UPDATE is 481, as it
// was before CF-130 (not a 200 without Session-Expires).
func TestOnUpdateOnAnInboundDialogStillAnsweringIs481(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d := &dialog{id: "d-ans", direction: session.Inbound, phase: phaseAnswering,
		callID: "cid-ans", invite: matchInvite("cid-ans")}
	u.register(d)
	tx := &stubServerTx{}
	u.onUpdate(matchReq(sip.UPDATE, "cid-ans", matchPeerTag, "some-tag"), tx)
	if got := tx.last().StatusCode; got != 481 {
		t.Fatalf("UPDATE on an inbound dialog still answering -> %d, want 481", got)
	}
}

// A self-call registers two dialogs with one Call-ID (an outbound and an
// inbound leg); the BYE must find the leg it is tagged for whichever one
// u.calls.byID yields first.
func TestSelfCallByeEndsTheLegItIsTaggedFor(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx := context.Background()
		ua, err := New(ctx, Config{
			Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
			Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
			Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
			MediaPortRange: [2]int{16384, 32767},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		inbound := make(chan session.UAEvent, 4)
		ua.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
			inbound <- ev
			return session.AdmitAccept()
		})
		res, err := ua.Dial(ctx, session.DialRequest{ToURI: "sip:alice@" + ua.LocalAddr().String()})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		var calleeLeg string
		select {
		case ev := <-inbound:
			calleeLeg = ev.DialogID
		case <-time.After(3 * time.Second):
			t.Fatal("no inbound leg")
		}
		if err := ua.AnswerEventually(ctx, session.AnswerRequest{DialogID: calleeLeg}); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			ua.calls.mu.Lock()
			ph := ua.calls.byID[res.DialogID].phase
			ua.calls.mu.Unlock()
			if ph == phaseAnswered {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("caller leg never answered (phase %v)", ph)
			}
			time.Sleep(5 * time.Millisecond)
		}
		// The callee leg's BYE, delivered to the UA while BOTH legs are still
		// registered (a real Hangup forgets its own leg before the BYE goes out,
		// which would hide a lookup that tries the wrong leg first).
		ua.calls.mu.Lock()
		callerD, calleeD := ua.calls.byID[res.DialogID], ua.calls.byID[calleeLeg]
		bye := matchReq(sip.BYE, callerD.callID, ourReInviteTagLocked(calleeD), ourReInviteTagLocked(callerD))
		ua.calls.mu.Unlock()
		tx := &stubServerTx{}
		ua.onBye(bye, tx)
		if got := tx.last().StatusCode; got != 200 {
			t.Fatalf("iteration %d: the callee leg's BYE -> %d, want 200", i, got)
		}
		if registered(ua, res.DialogID) {
			t.Fatalf("iteration %d: the caller leg survived the BYE tagged for it", i)
		}
		if !registered(ua, calleeLeg) {
			t.Fatalf("iteration %d: the BYE ended the leg that sent it", i)
		}
		_ = ua.Close(ctx)
	}
}
