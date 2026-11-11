package sipua_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func TestAnswerSends422WhenThePeerAsksBelowOurMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 300)
	events := collect(t, ua)

	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "120;refresher=uac",
		"Min-SE":          "90",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID})
	if err == nil {
		t.Fatal("an interval below our min_se_s must not be answered 200")
	}
	waitForCode(t, p, 422)
	if got := p.LastResponseHeader("INVITE", 422, "Min-SE"); got != "300" {
		t.Fatalf("422 Min-SE=%q want our own 300", got)
	}
}

func TestAnswerClaimsUASAndAdvertisesTheNegotiatedInterval(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
	events := collect(t, ua)

	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "600",
		"Allow":           "INVITE, ACK, BYE, CANCEL, UPDATE",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	// Correction 1: Answer returns the instant tx.Respond hands the datagram to
	// the socket, before the peer's serve() goroutine has parsed it — without
	// this wait, the assertions below race the peer's own read loop and read an
	// empty map.
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "600;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 600;refresher=uas (decision 12)", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Require"); !strings.Contains(strings.ToLower(got), "timer") {
		t.Fatalf("200 Require=%q must name timer once we are the refresher", got)
	}
	// Correction 6: nothing else asserts Allow reaches the wire, which is
	// ourAllow()'s whole purpose — a refreshing peer that cannot see UPDATE in
	// our Allow falls back to a re-INVITE on every interval.
	if got := p.LastResponseHeader("INVITE", 200, "Allow"); !strings.Contains(got, "UPDATE") {
		t.Fatalf("200 Allow=%q must reach the wire naming UPDATE — that is what stops a "+
			"refreshing peer falling back to a re-INVITE", got)
	}
	v, ok := ua.SessionTimerView(inc.DialogID)
	if !ok || v.IntervalS != 600 || v.Refresher != "uas" {
		t.Fatalf("view=%+v ok=%v want 600/uas", v, ok)
	}
}

func TestAnswerHonoursAnExplicitPeerRefresherRequest(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "600;refresher=uac",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatal(err)
	}
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "600;refresher=uac" {
		t.Fatalf("200 Session-Expires=%q want the peer's own uac request honoured (decision 9)", got)
	}
}

func TestAnswerOmitsSessionExpiresWhenThePeerNeverAskedForATimer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
	events := collect(t, ua)
	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatal(err)
	}
	// Correction 1: without this wait the assertion below is vacuous — it reads
	// an empty, not-yet-parsed response either way and passes regardless of
	// what Answer actually did.
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "" {
		t.Fatalf("200 Session-Expires=%q must be absent — RFC 4028 is never imposed on a peer "+
			"that did not ask for it", got)
	}
	if _, ok := ua.SessionTimerView(inc.DialogID); ok {
		t.Fatal("no timer requested => no timer on the dialog")
	}
}

// TestAnswerOmitsRequireTimerWhenThePeerNeverAdvertisedIt (Correction 5): RFC
// 4028 §9 makes Require: timer a SHOULD, gated on the request's Supported:
// timer, when WE are the refresher — a peer that only sent a bare
// Session-Expires with no Supported must not be handed an extension it never
// claimed.
func TestAnswerOmitsRequireTimerWhenThePeerNeverAdvertisedIt(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Session-Expires": "600",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatal(err)
	}
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "600;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 600;refresher=uas", got)
	}
	if got := p.LastResponseHeader("INVITE", 200, "Require"); got != "" {
		t.Fatalf("200 Require=%q must be absent: the peer never advertised Supported: timer", got)
	}
}

func TestInboundUPDATEIsAnsweredAndRearmsNothingHarmful(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported":       "timer",
		"Session-Expires": "600;refresher=uac",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatal(err)
	}
	// Correction 1: SendUPDATE reads the peer's own recorded To-tag, which is
	// only populated once the peer's serve() goroutine has parsed the 200 OK —
	// without this wait, SendUPDATE fails "no To-tag observed yet".
	waitForCode(t, p, 200)
	// Supported: timer makes this Table 2's "Y, uac" row, which keeps the peer as
	// the refresher (a bare UPDATE would be the "N" row and hand refreshing to us).
	p.SendUPDATE(t, "600;refresher=uac", sip.NewHeader("Supported", "timer"))
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 200 })
	// status 0 = "the latest response to UPDATE, whatever its code", which is what
	// a caller wants when only one response is possible.
	if got := p.LastResponseHeader("UPDATE", 0, "Session-Expires"); got != "600;refresher=uac" {
		t.Fatalf("UPDATE 200 Session-Expires=%q want the negotiated value echoed", got)
	}
	// Correction 7: UPDATE is a target-refresh request (RFC 3261 §12.1.1); its
	// 2xx MUST carry a Contact.
	if got := p.LastResponseHeader("UPDATE", 0, "Contact"); got == "" {
		t.Fatal("UPDATE 200 Contact must not be empty — UPDATE is a target-refresh request")
	}
	// Fix round 1: this dialog negotiated refresher=uac (the PEER refreshes),
	// which is requireTimerInAnswer's MUST branch (role == "uac") — pins the
	// gate at sessiontimer.go so a future deletion or inversion of it is
	// caught here, not just on the INVITE's own 200.
	if got := p.LastResponseHeader("UPDATE", 0, "Require"); !strings.Contains(strings.ToLower(got), "timer") {
		t.Fatalf("UPDATE 200 Require=%q must name timer: refresher=uac is the MUST branch", got)
	}
	// A-M7 (D20): THE ASSERTION THIS TEST'S NAME ALREADY PROMISED. It checked
	// only the 200's Session-Expires/Contact/Require headers, so "rearms nothing
	// harmful" was an unverified claim in a name — the watchdog could have been
	// left disarmed, or armed twice, and this test would have passed either way.
	// CAVEAT: this does NOT catch a missed rearm; see the A-M7 audit
	// section.
	if v, ok := ua.SessionTimerView(inc.DialogID); !ok || !v.Armed || v.NextRefreshMs <= 0 {
		t.Fatalf("after inbound UPDATE: view=%+v ok=%v want Armed=true with a positive NextRefreshMs", v, ok)
	}
}

// TestInboundUPDATEOmitsRequireTimerWhenWeRefreshAndThePeerNeverAdvertisedSupported
// (fix round 1) pins requireTimerInAnswer's SHOULD branch from the OTHER
// side: the original INVITE carries a bare Session-Expires with no
// Supported: timer, so the negotiated role defaults to uas (decision 12) — WE
// refresh — and the peer never claimed the extension, so Require: timer must
// be ABSENT on the UPDATE's 200, exactly as it already is on the INVITE's own
// 200 (TestAnswerOmitsRequireTimerWhenThePeerNeverAdvertisedIt). peer.SendUPDATE
// never sets Supported on the UPDATE it sends either, so the UPDATE is Table 2's
// "N" row (RFC 4028 9): the 2xx's role is uas (we refresh) whatever the request
// names, and without a Supported: timer from the peer Require: timer is not owed.
func TestInboundUPDATEOmitsRequireTimerWhenWeRefreshAndThePeerNeverAdvertisedSupported(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Session-Expires": "600",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatal(err)
	}
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Require"); got != "" {
		t.Fatalf("precondition failed: INVITE 200 Require=%q must already be absent", got)
	}
	p.SendUPDATE(t, "600;refresher=uas")
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 200 })
	if got := p.LastResponseHeader("UPDATE", 0, "Require"); got != "" {
		t.Fatalf("UPDATE 200 Require=%q must be absent: refresher=uas and the peer never "+
			"advertised Supported: timer (SHOULD branch, not owed)", got)
	}
}

// TestAnswerRefusesAMinSEAboveTheCeilingWith400 (CF-118, LB-D14): a request whose
// Min-SE is above the 86400 s we honour is answered 400 whatever it lists in
// Supported, and the dialog is torn down.
func TestAnswerRefusesAMinSEAboveTheCeilingWith400(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"with Supported: timer", map[string]string{"Supported": "timer", "Session-Expires": "86401", "Min-SE": "86401"}},
		{"without Supported", map[string]string{"Session-Expires": "86401", "Min-SE": "86401"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
			ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1800, 90)
			events := collect(t, ua)
			p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), tc.headers)
			inc := waitFor(t, events, session.UAEventInbound, 0)
			err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID})
			if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed {
				t.Fatalf("Answer = %v, want a precondition_failed error", err)
			}
			waitForCode(t, p, 400)
			for _, c := range p.ResponseCodes() {
				if c == 200 {
					t.Fatalf("a 200 went out beside the 400: %v", p.ResponseCodes())
				}
			}
			if _, ok := ua.SessionTimerView(inc.DialogID); ok {
				t.Fatal("SessionTimerView reports a timer on a refused dialog")
			}
		})
	}
}

// TestAnswerHonoursAMinSEAtTheCeiling (CF-118): 86400 is honoured, and the
// refresher armed on it is at half of it with no time.Duration overflow.
func TestAnswerHonoursAMinSEAtTheCeiling(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
	events := collect(t, ua)
	p.DialWithHeaders(t, "sip:alice@"+ua.BoundAddr().String(), map[string]string{
		"Supported": "timer", "Session-Expires": "86400", "Min-SE": "86400",
	})
	inc := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: inc.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	if got := p.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "86400;refresher=uas" {
		t.Fatalf("200 Session-Expires=%q want 86400;refresher=uas", got)
	}
	clk.BlockUntil(1)
	v, ok := ua.SessionTimerView(inc.DialogID)
	if !ok || !v.Armed || v.NextRefreshMs <= 43_100_000 || v.NextRefreshMs > 43_200_000 {
		t.Fatalf("SessionTimerView = %+v, %v; want Armed with NextRefreshMs in (43100000, 43200000]", v, ok)
	}
}
