package sipua_test

// CF-096 and CF-104: the inbound initial INVITE server transaction lives until
// sipgo's own FSM ends it (onInvite holds until tx.Done or UA close), so
// retransmissions are absorbed, the ACK of a non-2xx stops Timer G, and the
// UA's OnCancel hook vetoes sipgo's automatic 487 and writes its own.
// Raw UDP callers (rawUAC, rfc3261_pin_uas_test.go) send the exact copies.

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// onInviteHeld reports whether any goroutine is inside UA.onInvite. Inlined
// here because goroutineStackContains (ua_test.go) is in package sipua.
func onInviteHeld() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), "UA).onInvite")
}

func countCode(r *rawUAC, method string, code int) int {
	codes, _ := r.responses(method)
	n := 0
	for _, c := range codes {
		if c == code {
			n++
		}
	}
	return n
}

// toTagOfResponse returns the To tag of the first response to method with code.
func toTagOfResponse(t *testing.T, r *rawUAC, method string, code int) (to, tag string) {
	t.Helper()
	codes, msgs := r.responses(method)
	for i, c := range codes {
		if c == code {
			to = stubHeaders(msgs[i], "To")[0]
			_, tag, _ = strings.Cut(to, "tag=")
			return to, tag
		}
	}
	t.Fatalf("no %d to %s; got %v", code, method, codes)
	return "", ""
}

// ackFor builds the ACK of a non-2xx final: same branch as the INVITE, the
// final's To (RFC 3261 17.1.1.3).
func ackFor(r *rawUAC, ruri, callID, branch, to string) string {
	return "ACK " + ruri + " SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:" + r.port() + ";branch=" + branch + "\r\n" +
		"From: <sip:probe@127.0.0.1>;tag=rfcsweepa\r\nTo: " + to + "\r\nCall-ID: " + callID +
		"\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
}

func waitNoOnInvite(t *testing.T, within time.Duration, what string) {
	t.Helper()
	if !stubWait(func() bool { return !onInviteHeld() }, within) {
		t.Fatalf("a goroutine is still inside UA.onInvite %v after %s", within, what)
	}
}

// I4: a retransmitted INVITE after a late Reject draws the 486 again from the
// live transaction, before Timer G (500 ms) could, and creates no second call.
func TestInviteRetransmissionAfterRejectResendsTheFinal(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	callID := "rfcfix1-rejretx@127.0.0.1"
	msg := r.invite(ruri, callID, "z9hG4bKrfcfix1REJRETX", 1, "")
	r.send(msg)
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Reject(context.Background(), in.DialogID, 486, ""); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 486) }, 2*time.Second) {
		t.Fatal("no 486")
	}
	r.send(msg)
	if !stubWait(func() bool { return countCode(r, "INVITE", 486) >= 2 }, 300*time.Millisecond) {
		codes, _ := r.responses("INVITE")
		t.Errorf("the retransmitted INVITE drew no 486 within 300 ms (codes %v), want the final re-sent (RFC 3261 17.2.1)", codes)
	}
	time.Sleep(200 * time.Millisecond)
	if n := countInbound(events()); n != 1 {
		t.Errorf("%d inbound calls, want 1: the retransmission must not be a new call", n)
	}
}

// I3: a retransmitted INVITE after the 200 is absorbed by the transaction in
// Accepted (the 2xx re-send itself is CF-103, not done).
func TestInviteRetransmissionAfterAnswerIsAbsorbed(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	callID := "rfcfix1-ansretx@127.0.0.1"
	answered(t, ua, events, r, ruri, callID, 1)
	r.send(r.invite(ruri, callID, "z9hG4bKrfcsweepaI"+callID, 1, ""))
	time.Sleep(500 * time.Millisecond)
	if n := countInbound(events()); n != 1 {
		t.Errorf("%d inbound calls, want 1: the retransmission after the 200 must be absorbed", n)
	}
}

// I0 (CF-194, RFC 6026 7.1): a 2xx'd re-INVITE's server transaction outlives its
// handler (Accepted until Timer L), so a retransmitted re-INVITE is absorbed
// by the transaction: no second 200, nothing handled again.
func TestRetransmittedReInviteIsAbsorbedByItsAcceptedTransaction(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	callID := "rfcfix1-reinv@127.0.0.1"
	answered(t, ua, events, r, ruri, callID, 1)
	_, toTag := toTagOfResponse(t, r, "INVITE", 200)
	r.send(r.request("ACK", ruri, callID, "z9hG4bKrfcfix1REACK", 1, toTag, "", ""))
	re := r.request("INVITE", ruri, callID, "z9hG4bKrfcfix1RE", 2, toTag, "", stubSDP)
	r.send(re)
	if !stubWait(func() bool { return countCode(r, "INVITE", 200) == 2 }, 2*time.Second) {
		t.Fatal("no 200 to the re-INVITE")
	}
	// ACK the re-INVITE's 200 (CF-208 retransmits an un-ACKed one), then let the
	// first re-INVITE's handler return; its transaction must survive.
	r.send(r.request("ACK", ruri, callID, "z9hG4bKrfcfix1REACK2", 2, toTag, "", ""))
	time.Sleep(500 * time.Millisecond)
	r.send(re)
	if stubWait(func() bool { return countCode(r, "INVITE", 200) > 2 }, 1*time.Second) {
		t.Errorf("the retransmitted re-INVITE drew a further 200; its Accepted transaction must absorb it")
	}
	if n := countInbound(events()); n != 1 {
		t.Errorf("%d inbound calls, want 1", n)
	}
	for _, ev := range events() {
		if ev.Kind == session.UAEventDialogEnded {
			t.Errorf("the call ended (%v); a re-INVITE retransmission must leave it unchanged", ev)
		}
	}
}

// I10: UA.Close releases a held onInvite (the uaCtx case).
func TestInviteHandlerReleasedOnUAClose(t *testing.T) {
	ua, _, r, ruri := uasUA(t)
	r.send(r.invite(ruri, "rfcfix1-close@127.0.0.1", "z9hG4bKrfcfix1CLOSE", 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 3*time.Second) {
		t.Fatal("no 180")
	}
	if !stubWait(onInviteHeld, time.Second) {
		t.Fatal("onInvite is not held while the call rings; the transaction would be terminated")
	}
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitNoOnInvite(t, 3*time.Second, "UA.Close")
}

// I6a: an early BYE on a ringing inbound call draws 200 on the BYE and 487 on
// the INVITE (RFC 3261 15.1.2); while admitting (CF-209) a BYE carries no valid
// tag: 481, and a CANCEL ends the call, and once the 487 is ACKed the
// held onInvite returns (Timer I, T4 = 5 s on UDP; the real clock).
func TestEarlyByeOnARingingInboundCall487sTheInviteAndReleasesItsHandler(t *testing.T) {
	run := func(t *testing.T, admitting bool) {
		ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
		events := collect(t, ua)
		release := make(chan struct{})
		var released bool
		releaseOnce := func() {
			if !released {
				released = true
				close(release)
			}
		}
		t.Cleanup(releaseOnce)
		if admitting {
			ua.OnAdmit(context.Background(), func(context.Context, session.UAEvent) session.Admission {
				<-release
				return session.AdmitAccept()
			})
		}
		r := newRawUAC(t, ua)
		ruri := "sip:alice@" + ua.BoundAddr().String()
		callID, branch := "rfcfix1-earlybye@127.0.0.1", "z9hG4bKrfcfix1EBYE"
		r.send(r.invite(ruri, callID, branch, 1, ""))

		toTag := "rfcfix1-invented" // admitting: no 180 tag exists yet
		if admitting {
			if !stubWait(func() bool { return r.hasCode("INVITE", 100) }, 3*time.Second) {
				t.Fatal("no 100")
			}
		} else {
			if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 3*time.Second) {
				t.Fatal("no 180")
			}
			_, toTag = toTagOfResponse(t, r, "INVITE", 180)
		}
		r.send(r.request("BYE", ruri, callID, "z9hG4bKrfcfix1EBYEB", 2, toTag, "", ""))
		if admitting {
			// CF-209 (B-D2): no tagged response exists yet, so no BYE can name
			// a dialog of ours: 481, and the INVITE is not 487'd by it. The
			// caller's remedy is CANCEL.
			if !stubWait(func() bool { return r.hasCode("BYE", 481) }, 2*time.Second) {
				codes, _ := r.responses("BYE")
				t.Fatalf("the invented-tag BYE drew %v, want 481", codes)
			}
			if r.hasCode("INVITE", 487) {
				t.Fatal("the forged BYE ended the INVITE")
			}
			releaseOnce()
			if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 3*time.Second) {
				t.Fatal("no 180 after the admission was released")
			}
			r.send(r.request("CANCEL", ruri, callID, branch, 1, "", "", ""))
			if !stubWait(func() bool { return r.hasCode("INVITE", 487) }, 2*time.Second) {
				t.Fatal("no 487 after the CANCEL")
			}
			to, _ := toTagOfResponse(t, r, "INVITE", 487)
			r.send(ackFor(r, ruri, callID, branch, to))
			waitNoOnInvite(t, 7*time.Second, "the ACK of the 487")
			n := 0
			for _, ev := range events() {
				if ev.Kind == session.UAEventDialogEnded {
					n++
					if ev.Cause != session.UACauseCancelled {
						t.Errorf("dialog_ended cause %q, want %q", ev.Cause, session.UACauseCancelled)
					}
				}
			}
			if n != 1 {
				t.Errorf("%d dialog_ended events, want 1", n)
			}
			return
		}
		if !stubWait(func() bool { return r.hasCode("BYE", 200) }, 2*time.Second) {
			t.Fatal("no 200 to the BYE")
		}
		if !stubWait(func() bool { return r.hasCode("INVITE", 487) }, 2*time.Second) {
			codes, _ := r.responses("INVITE")
			t.Fatalf("no 487 to the INVITE after the early BYE (codes %v), want one (RFC 3261 15.1.2)", codes)
		}
		releaseOnce()
		if !onInviteHeld() {
			t.Fatal("onInvite is not held after the 487; the ACK could not reach the transaction")
		}
		to, _ := toTagOfResponse(t, r, "INVITE", 487)
		r.send(ackFor(r, ruri, callID, branch, to))
		waitNoOnInvite(t, 7*time.Second, "the ACK of the 487")

		codes, _ := r.responses("INVITE")
		for _, c := range codes {
			if c >= 200 && c != 487 {
				t.Errorf("INVITE final %d besides the 487 (codes %v): one final per transaction", c, codes)
			}
		}
		n := 0
		for _, ev := range events() {
			if ev.Kind == session.UAEventDialogEnded {
				n++
				if ev.Cause != session.UACausePeerBYE {
					t.Errorf("dialog_ended cause %q, want %q", ev.Cause, session.UACausePeerBYE)
				}
			}
		}
		if n != 1 {
			t.Errorf("%d dialog_ended events, want 1", n)
		}
	}
	t.Run("ringing", func(t *testing.T) { run(t, false) })
	t.Run("admitting", func(t *testing.T) { run(t, true) })
}

// I6: on the hook path the 487 is written before the cancelled event is
// emitted (the hook only claims; finishInboundCancel responds, then emits).
func TestCancelWritesThe487BeforeTheCancelledEvent(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	r := newRawUAC(t, ua)
	held := make(chan bool, 1)
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind != session.UAEventDialogEnded || ev.Cause != session.UACauseCancelled {
			return
		}
		// Blocks up to 300 ms: under the transaction's lock the 487 could not be
		// written meanwhile.
		held <- stubWait(func() bool { return r.hasCode("INVITE", 487) }, 300*time.Millisecond)
	})
	ruri := "sip:alice@" + ua.BoundAddr().String()
	callID, branch := "rfcfix1-cancel@127.0.0.1", "z9hG4bKrfcfix1CAN"
	r.send(r.invite(ruri, callID, branch, 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 3*time.Second) {
		t.Fatal("no 180")
	}
	r.send(r.request("CANCEL", ruri, callID, branch, 1, "", "", ""))
	select {
	case ok := <-held:
		if !ok {
			t.Error("the cancelled event was delivered before the 487 reached the caller")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no cancelled event")
	}
	if !stubWait(func() bool { return r.hasCode("CANCEL", 200) }, 2*time.Second) {
		t.Error("no 200 to the CANCEL")
	}
	if n := countCode(r, "INVITE", 487); n < 1 {
		t.Errorf("%d 487s, want the INVITE terminated", n)
	}
}

// I4a, D-096c (i): an admission rejection releases the hold before responding,
// so its final is sent once (no Timer G copies) and onInvite returns at once.
func TestAdmissionRejectIsSentOnceAndReleasesTheHandler(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	ua.OnAdmit(context.Background(), func(context.Context, session.UAEvent) session.Admission {
		return session.AdmitReject(486, "Busy Here")
	})
	r := newRawUAC(t, ua)
	ruri := "sip:alice@" + ua.BoundAddr().String()
	r.send(r.invite(ruri, "rfcfix1-admrej@127.0.0.1", "z9hG4bKrfcfix1ADMREJ", 1, ""))
	if !stubWait(func() bool { return r.hasCode("INVITE", 486) }, 3*time.Second) {
		t.Fatal("no 486")
	}
	time.Sleep(time.Second)
	if onInviteHeld() {
		t.Error("onInvite is still held 1 s after an admission rejection; D-096c (i) releases it")
	}
	time.Sleep(3 * time.Second)
	if n := countCode(r, "INVITE", 486); n != 1 {
		t.Errorf("%d 486s in 4 s with no ACK, want 1 (D-096c (i): no new reflection)", n)
	}
}
