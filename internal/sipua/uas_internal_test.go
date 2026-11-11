package sipua

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// respRecorder is a sip.ServerTransaction that records what it is asked to
// send; any other method panics on the nil embedded interface.
type respRecorder struct {
	sip.ServerTransaction
	got []*sip.Response
}

func (r *respRecorder) Respond(res *sip.Response) error {
	r.got = append(r.got, res)
	return nil
}

// TestScreenRefusedGatedRequestReleasesItsArrivalTicket: a BYE the gate
// refuses (Require: x) still holds the ticket the read loop stamped for it; the
// screen releases it so the NOTIFY behind it does not wait.
func TestScreenRefusedGatedRequestReleasesItsArrivalTicket(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-screen-ticket")
	claimForArrivalTest(t, u, d)
	bye := peerByeReq("cid-screen-ticket", ours)
	bye.AppendHeader(sip.NewHeader("Require", "x"))
	bye.Recipient.Scheme = "sip" // a parsed request always has one; a hand-built one does not
	notify := referNotifyReq("cid-screen-ticket", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK")
	notify.CSeq().SeqNo = 11
	waiting := setArrivalWaitHook(t, sip.NOTIFY)

	u.observeArrival(bye)
	u.observeArrival(notify)
	rec := &respRecorder{}
	u.screen(func(*sip.Request, sip.ServerTransaction) { t.Error("handler ran for a refused BYE") })(bye, rec)
	if len(rec.got) != 1 || rec.got[0].StatusCode != 420 {
		t.Fatalf("responses %v, want one 420", rec.got)
	}
	select {
	case tk := <-enterAsync(u, notify):
		leave(u, tk)
	case <-waiting:
		t.Fatal("the NOTIFY waited behind the refused BYE's ticket")
	case <-time.After(3 * time.Second):
		t.Fatal("the NOTIFY never passed")
	}
	u.calls.mu.Lock()
	n := len(d.arrivals.pending)
	u.calls.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d tickets pending, want 0", n)
	}
}

// TestOurAllowEqualsTheRegisteredHandlers: Allow lists exactly the methods
// installHandlers registers (RFC 3261 20.5).
func TestOurAllowEqualsTheRegisteredHandlers(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	allow := map[string]bool{}
	for _, m := range strings.Split(ourAllow(), ",") {
		allow[strings.TrimSpace(m)] = true
	}
	reg := map[string]bool{}
	for _, m := range u.Server().RegisteredMethods() {
		reg[strings.ToUpper(m)] = true
	}
	for m := range allow {
		if !reg[m] {
			t.Errorf("Allow lists %s but no handler is registered", m)
		}
	}
	for m := range reg {
		if !allow[m] {
			t.Errorf("handler registered for %s but Allow omits it", m)
		}
	}
}
