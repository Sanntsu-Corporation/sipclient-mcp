package sipua_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newSessionTimerUA is newDirectUA with SessionExpiresS/MinSES set. It
// deliberately does not set MediaPortRange — dialling still works.
//
// It delegates to newSessionTimerUAFull (sessiontimer_refresh_test.go): that
// helper's own doc comment argues a second hand-rolled sipua.New call site
// would drift from it, so this one does not carry its own Config literal.
func newSessionTimerUA(t *testing.T, clk *fakeclock.Clock, ses, minSE int) (*sipua.UA, *countingConn) {
	return newSessionTimerUAFull(t, clk, ses, minSE, "", 0, nil)
}

func TestDialAdvertisesSessionTimerHeaders(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	// Correction 7: non-default values, so this test cannot pass on a helper
	// that silently ignores its ses/minSE arguments.
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if got := p.LastRequestHeader("INVITE", "Session-Expires"); got != "1200;refresher=uac" {
		t.Fatalf("Session-Expires=%q want 1200;refresher=uac (decision 12)", got)
	}
	if got := p.LastRequestHeader("INVITE", "Min-SE"); got != "120" {
		t.Fatalf("Min-SE=%q want 120", got)
	}
	if got := p.LastRequestHeader("INVITE", "Supported"); !strings.Contains(strings.ToLower(got), "timer") {
		t.Fatalf("Supported=%q must name timer", got)
	}
}

// TestDialRetriesOnceAfter422AtThePeersMinSE (Correction 4): the peer's
// Reject422MinSE must be ABOVE our proposal — a conformant 422 always demands
// more than we offered (Correction 3's owner ruling) — so the demand (1800) is
// set above newSessionTimerUA's proposed interval (1200).
func TestDialRetriesOnceAfter422AtThePeersMinSE(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{Reject422MinSE: 1800},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	// Correction 14: tolerate a retransmit under -race/4-CPU contention rather
	// than pinning the exact count — assert substance (the retry happened and
	// carried the raised interval) instead.
	if n := p.Count("INVITE"); n < 2 {
		t.Fatalf("%d INVITEs want >= 2 (original + at least one 422 retry)", n)
	}
	if got := p.LastRequestHeader("INVITE", "Session-Expires"); !strings.HasPrefix(got, "1800") {
		t.Fatalf("retry Session-Expires=%q want the peer's Min-SE (1800)", got)
	}
	// Correction 10 (RFC 4028 §6): the retry's Min-SE echoes the PEER's floor,
	// not our own. Asserting only Session-Expires cannot see this — swapping
	// peerMinSE back for u.minSES() puts `Min-SE: 120` beside
	// `Session-Expires: 1800`, a self-contradictory pair the peer's own 422
	// gate never inspects, so the 200 still arrives and the suite stays green.
	if got := p.LastRequestHeader("INVITE", "Min-SE"); got != "1800" {
		t.Fatalf("retry Min-SE=%q want the peer's own floor 1800, not ours (120)", got)
	}
}

// rawSentConn captures the full raw bytes of every outbound datagram, not
// just the first line countingConn keeps. TestRetry422DrawsFreshChallenge...
// below needs it because peer.LastRequestHeader's map (peer_serve.go's
// record) only OVERWRITES a key when the current message carries that
// header — a message that legitimately carries NO Authorization at all
// leaves the map showing the PREVIOUS request's value, which is exactly the
// distinction this test must draw. Installed through the same Config.WrapConn
// seam countingConn uses.
type rawSentConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *rawSentConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

// invites returns every captured datagram that is an INVITE request, in send
// order.
func (c *rawSentConn) invites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	for _, b := range c.sent {
		if strings.HasPrefix(string(b), "INVITE ") {
			out = append(out, b)
		}
	}
	return out
}

// TestRetry422DrawsFreshChallengeInsteadOfReplayingTheStaleNonceCount (Rule 13
// Cycle 3 fix round, finding #3) pins that retry422 does not resend the
// digest-answered leg's Authorization header verbatim on the 422-retry:
// retry422's own doc comment says d.invite "IS DELIBERATELY MUTATED IN PLACE
// HERE, NOT COPIED", so without stripping it the 422-retry would silently
// REPLAY the prior attempt's already-consumed nc rather than drawing a fresh
// challenge (RFC 7616 §3.4.3 requires nc to be strictly increasing per
// nonce). This asserts directly on the wire bytes of the LAST INVITE sent —
// the 422-retry, nothing else follows it in this flow — regardless of how the
// dial's own final response resolves.
func TestRetry422DrawsFreshChallengeInsteadOfReplayingTheStaleNonceCount(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{Reject422MinSE: 1800},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	var rc *rawSentConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		AuthUser:           "alice",
		AuthPass:           "s3cr3t",
		AuthAnyHost:        true, // CF-046: the peer is on 127.0.0.1, not this AOR's host
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		SessionExpiresS:    1200,
		MinSES:             120,
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			rc = &rawSentConn{PacketConn: pc}
			return rc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	// code 0 = any: this fix does not need the dial to SUCCEED, only that the
	// 422-retry's own Authorization header is never a stale replay.
	final := waitFor(t, events, session.UAEventFinal, 0)

	// At least three INVITEs: unauthenticated (drew the 401), digest-answered
	// (drew the 422), and the 422-retry.
	invites := rc.invites()
	if len(invites) < 3 {
		t.Fatalf("%d INVITEs sent, want >= 3 (unauthenticated + digest + 422-retry); final code=%d",
			len(invites), final.Code)
	}
	last := string(invites[len(invites)-1])
	if strings.Contains(last, "Authorization:") {
		t.Fatalf("422-retry carries an Authorization header:\n%s\nwant none — a fresh challenge must "+
			"be drawn rather than replaying the digest-answered leg's already-consumed nc (final code=%d)",
			last, final.Code)
	}
}

func TestDialWithoutSessionExpiresInTheAnswerHasNoSessionTimer(t *testing.T) {
	// A peer that never advertises timer support: no session timer on the dialog,
	// so call_status.session_timer must be ABSENT (§4).
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	// Correction 8: non-vacuous — the INVITE must genuinely have OFFERED a
	// timer, so this asserts degradation rather than the mere absence of any
	// implementation.
	if got := p.LastRequestHeader("INVITE", "Session-Expires"); got == "" {
		t.Fatal("the INVITE must have offered a session timer for this to test degradation")
	}
	if _, ok := ua.SessionTimerView(res.DialogID); ok {
		t.Fatal("no Session-Expires in the answer => no session timer")
	}
}

func TestDialWithSessionExpiresInTheAnswerRecordsTheTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "120;refresher=uas"},
	})
	// Correction 7: non-default values throughout, even though this
	// particular assertion is on the ANSWER side rather than the offer.
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	v, ok := ua.SessionTimerView(res.DialogID)
	if !ok {
		t.Fatal("the answer's Session-Expires must record a session timer")
	}
	if v.IntervalS != 120 || v.Refresher != "uas" {
		t.Fatalf("view=%+v want 120/uas", v)
	}
}

// TestDialWithAnAnsweredIntervalBelowOurMinSEArmsNoTimer is the DISCRIMINATING
// input for buildOutboundSessionTimer's Min-SE floor. Every other fixture in
// the package pairs the peer's answered interval with a MinSES it meets exactly
// or exceeds (90/90, 120/120, 90/60), so "we refuse a too-short answered
// interval" and "we accept whatever the peer answers" give the same result on
// every input the suite uses — deleting the floor left the whole package green.
//
// The floor matters because the answered interval drives BOTH the refresh
// period and the watchdog: accepting 120 against a 300 s floor arms a refresher
// firing every 60 s for the life of the call. belowMinSE's OTHER caller
// (refreshSession's re-base) is separately covered, which is exactly why this
// site's silence was invisible.
func TestDialWithAnAnsweredIntervalBelowOurMinSEArmsNoTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "120;refresher=uas"},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 300)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	// The offer really did advertise the floor, or the answer below it proves
	// nothing about a floor we never stated.
	if got := p.LastRequestHeader("INVITE", "Min-SE"); got != "300" {
		t.Fatalf("Min-SE=%q want 300 — the answer below it is only meaningful "+
			"against a floor we actually advertised", got)
	}
	if v, ok := ua.SessionTimerView(res.DialogID); ok {
		t.Fatalf("session_timer=%+v — an answered 120 is below our advertised "+
			"Min-SE of 300 and must arm no timer at all", v)
	}
}

// TestDial422AboveOurCeilingFailsTheDialWithoutRetrying (Correction 15): the
// refusal path is untested by the brief, and it is precisely where
// Corrections 1 and 2 crashed. A 422 whose Min-SE is outside our bounds must
// fail the dial as an ordinary SIP failure (§11.1) — not panic, not hang.
func TestDial422AboveOurCeilingFailsTheDialWithoutRetrying(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{Reject422MinSE: 7201},
	})
	ua, _ := newSessionTimerUA(t, fakeclock.New(time.Unix(0, 0)), 1200, 120)
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 422)
	// Correction 14: a retransmit of the ORIGINAL INVITE must not turn "we did
	// not retry" into a false failure. Assert substance instead of an exact
	// count — no INVITE ever carried an interval other than our proposal.
	if got := p.LastRequestHeader("INVITE", "Session-Expires"); !strings.HasPrefix(got, "1200") {
		t.Fatalf("Session-Expires=%q want 1200... (no retry attempted above the ceiling)", got)
	}
}

// TestRetry422StripsProxyAuthorizationToo (Rule 13 Cycle 6, Phase 4 W3) is the
// 407 arm of the Cycle 3 finding TestRetry422DrawsFreshChallengeInsteadOf-
// ReplayingTheStaleNonceCount pins for the 401 arm.
//
// applyDigest (digestauth.go's `case 407`) writes PROXY-Authorization, not
// Authorization, whenever the challenge arrived from a proxy — the ordinary
// shape when anything sits in front of the callee. retry422 stripped only
// Authorization, so a 422-after-407 retry replayed the digest-answered leg's
// already-consumed nc under the other header name: identical bug class, other
// header, left open by the Cycle 3 fix.
//
// THE ASSERTION IS ON THE WIRE BYTES OF THE LAST INVITE SENT, which is the
// 422-retry — nothing follows it in this flow. As in the 401 test, the dial does
// NOT need to succeed: the stripped retry draws a fresh 407 and the dial ends
// there, which is correct and is not what this pins.
func TestRetry422StripsProxyAuthorizationToo(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{ProxyAuthInvite: true, Reject422MinSE: 1800},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	var rc *rawSentConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		AuthUser:           "alice",
		AuthPass:           "s3cr3t",
		AuthAnyHost:        true, // CF-046: the peer is on 127.0.0.1, not this AOR's host
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		SessionExpiresS:    1200,
		MinSES:             120,
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			rc = &rawSentConn{PacketConn: pc}
			return rc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	final := waitFor(t, events, session.UAEventFinal, 0) // code 0 = any

	invites := rc.invites()
	if len(invites) < 3 {
		t.Fatalf("%d INVITEs sent, want >= 3 (unauthenticated + proxy-authenticated + 422-retry); "+
			"final code=%d", len(invites), final.Code)
	}

	// NON-VACUITY FIRST. If no earlier INVITE ever carried Proxy-Authorization
	// the 407 path was never exercised and the strip assertion below would pass
	// against a UA that cannot do proxy auth at all.
	proxyAuthed := false
	for _, b := range invites[:len(invites)-1] {
		if strings.Contains(string(b), "Proxy-Authorization:") {
			proxyAuthed = true
		}
	}
	if !proxyAuthed {
		t.Fatalf("no INVITE before the 422-retry carried Proxy-Authorization — the 407 challenge "+
			"path was never exercised, so the strip below proves nothing (final code=%d)", final.Code)
	}

	last := string(invites[len(invites)-1])
	if strings.Contains(last, "Proxy-Authorization:") {
		t.Fatalf("the 422-retry carries a Proxy-Authorization header:\n%s\nwant none — a fresh "+
			"challenge must be drawn rather than replaying the proxy-authenticated leg's "+
			"already-consumed nc (RFC 7616 §3.4.3); final code=%d", last, final.Code)
	}
}
