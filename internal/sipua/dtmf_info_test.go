// internal/sipua/dtmf_info_test.go
package sipua_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/sipproxy"
)

// TestSendDTMFInfoPutsOneINFOPerDigitOnTheWire is a CORRECTED version of the
// brief's own Step-1 test: the brief called SendDTMF with gap_ms=20 against a
// fake clock nothing advances, which parks the gap-timing select on
// u.cfg.Clock.After(20ms) forever (reproduced: the test hangs to its real
// timeout). gap_ms=0 here is an explicit "no gap", honoured immediately with
// no clock wait, matching TestSendDTMFInbandHonoursAnExplicitZeroGap's
// convention for the other modes. The nonzero-gap path gets its own coverage
// below, driven explicitly through the fake clock.
func TestSendDTMFInfoPutsOneINFOPerDigitOnTheWire(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// 250, NOT the 100 every other INFO test uses: 100 is exactly
	// session.DefaultDTMFDurationMs, so on that input a sendDTMFInfo that
	// ignored durationMs outright and substituted the default was
	// indistinguishable from one that honoured it — assigning
	// `durationMs = session.DefaultDTMFDurationMs` at the top of sendDTMFInfo
	// left the whole package green. This is the only INFO test asserting the
	// wire body, so it is the one that has to carry a discriminating value.
	sent, emitted, err := ua.SendDTMF(context.Background(), res.DialogID, "1#", session.DTMFModeInfo, 250, 0)
	if err != nil {
		t.Fatalf("SendDTMF(info): %v", err)
	}
	if sent != 2 {
		t.Fatalf("digits_sent=%d want 2", sent)
	}
	// INFO carries the duration as a decimal body field, so there is no 20ms
	// frame grid to round to and the emitted value is the resolved request —
	// the PER-DIGIT figure, matching inband/rfc2833 and the spec's documented
	// "duration_ms is the emitted PER-DIGIT duration" contract (Task 16 reports
	// this straight through as dtmf_send's duration_ms).
	if emitted != 250 {
		t.Fatalf("emitted duration_ms=%d want 250 (the REQUESTED value, not the 100ms default)", emitted)
	}
	if n := p.Count("INFO"); n != 2 {
		t.Fatalf("%d INFO requests on the wire, want 2 (one per digit, decision 15): %v", n, p.Methods())
	}
	body := p.LastRequestBody("INFO")
	if !strings.Contains(body, "Signal=#") || !strings.Contains(body, "Duration=250") {
		t.Fatalf("INFO body = %q want application/dtmf-relay Signal/Duration lines", body)
	}
	if ct := p.LastRequestHeader("INFO", "Content-Type"); ct != "application/dtmf-relay" {
		t.Fatalf("Content-Type = %q want application/dtmf-relay", ct)
	}
}

// TestSendDTMFInfoHonoursANonzeroGapBetweenDigits covers the gap path the
// zero-gap test above cannot reach: it drives SendDTMF in a goroutine and
// advances the FAKE clock explicitly past the inter-digit gap, following the
// same goroutine+fake-clock-driving idiom TestInboundRingTimeoutAutoRejects480
// (call_inbound_test.go) uses for the ring timeout — BlockUntil(1)
// synchronises with the gap-timing select's own u.cfg.Clock.After(20ms) being
// armed before Advance crosses it, so the test cannot race the send.
func TestSendDTMFInfoHonoursANonzeroGapBetweenDigits(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 20)
		done <- result{sent, emitted, err}
	}()

	// The first INFO's 2xx has landed once the gap-timing select parks on
	// u.cfg.Clock.After(20ms) — that is the ONE waiter this dialog registers
	// on the fake clock (the outbound ring budget and RTP pacing both run on
	// real time, never u.cfg.Clock), so BlockUntil(1) cannot be satisfied by
	// anything else.
	clk.BlockUntil(1)
	clk.Advance(20 * time.Millisecond)

	res2 := <-done
	if res2.err != nil {
		t.Fatalf("SendDTMF(info): %v", res2.err)
	}
	if res2.sent != 2 {
		t.Fatalf("digits_sent=%d want 2", res2.sent)
	}
	if res2.emitted != 100 {
		t.Fatalf("emitted duration_ms=%d want 100", res2.emitted)
	}
	if n := p.Count("INFO"); n != 2 {
		t.Fatalf("%d INFO requests on the wire, want 2: %v", n, p.Methods())
	}
}

func TestSendDTMFInfoWorksWithNoMediaLoop(t *testing.T) {
	// §2.2: SIP INFO never touches mediaLoop, so it must not require one.
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	sipua.StopMediaLoopForTest(t, ua, res.DialogID)
	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "5", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info) must not require a media loop: %v", err)
	}
}

// TestSendDTMFInfoEachSendGetsAFreshViaBranch is the regression test for
// correction 2's wire-verified fix: buildInDialogRequest previously reused
// the answered INVITE's cloned Via (branch included) for EVERY in-dialog
// request it built, so two INFOs on one dialog carried IDENTICAL branch
// parameters — and a non-INVITE transaction is matched by
// branch|host|port|method (RFC 3261 §17.1.3), so a compliant peer (including
// this UA's own onInfo) would treat the second as a retransmission of the
// first and never actually deliver it, while digits_sent still reported both
// as sent. Two single-digit sends on the SAME dialog (rather than one
// multi-digit send) let the test read each INFO's Via back via the existing
// LastRequestHeader accessor between sends.
func TestSendDTMFInfoEachSendGetsAFreshViaBranch(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	inviteBranch := branchOf(p.LastRequestHeader("INVITE", "Via"))

	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "1", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info) #1: %v", err)
	}
	branch1 := branchOf(p.LastRequestHeader("INFO", "Via"))

	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "2", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info) #2: %v", err)
	}
	branch2 := branchOf(p.LastRequestHeader("INFO", "Via"))

	if branch1 == "" || branch2 == "" {
		t.Fatalf("an INFO's Via carried no branch: branch1=%q branch2=%q", branch1, branch2)
	}
	if branch1 == branch2 {
		t.Fatalf("both INFOs on one dialog carried the SAME branch %q — a compliant peer treats "+
			"the second as a retransmission of the first and never delivers it", branch1)
	}
	if branch1 == inviteBranch || branch2 == inviteBranch {
		t.Fatalf("an INFO reused the INVITE's own branch %q", inviteBranch)
	}
}

// branchOf extracts the "branch=" parameter off a raw Via header value.
func branchOf(via string) string { return headerParamOf(via, "branch") }

// tagOf extracts the "tag=" parameter off a raw From/To header value, which is
// how a test reads back the orientation of a request the peer received (the
// peer's header accessor hands back the rendered value, not a parsed header).
func tagOf(fromOrTo string) string { return headerParamOf(fromOrTo, "tag") }

func headerParamOf(value, name string) string {
	key := name + "="
	i := strings.Index(value, key)
	if i < 0 {
		return ""
	}
	rest := value[i+len(key):]
	if j := strings.IndexAny(rest, ";, "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// TestSendDTMFInfoThenHangupKeepsCSeqMonotonic is the regression test for
// correction 3's wire-verified CSeq bug: Hangup independently computed its
// BYE's CSeq as ok.CSeq()+1, ignoring d.localCSeq — reproduced on the wire as
// [{INVITE 2} {ACK 2} {INFO 4} {INFO 5} {BYE 4}], a BYE CSeq (4) that is NOT
// greater than the immediately preceding INFO's (5), violating RFC 3261
// §12.2.1.1 and drawing "500 Invalid CSeq" from a real server (Asterisk).
func TestSendDTMFInfoThenHangupKeepsCSeqMonotonic(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info): %v", err)
	}
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}

	var lastInfoCSeq, byeCSeq uint32
	var sawInfo, sawBye bool
	for _, mc := range p.RequestCSeqs() {
		switch mc.Method {
		case "INFO":
			lastInfoCSeq, sawInfo = mc.CSeq, true
		case "BYE":
			byeCSeq, sawBye = mc.CSeq, true
		}
	}
	if !sawInfo || !sawBye {
		t.Fatalf("expected both INFO and BYE on the wire; got %v", p.RequestCSeqs())
	}
	if byeCSeq <= lastInfoCSeq {
		t.Fatalf("BYE CSeq %d is not greater than the last INFO's CSeq %d (RFC 3261 §12.2.1.1): %v",
			byeCSeq, lastInfoCSeq, p.RequestCSeqs())
	}

	// The check above only compares the LAST INFO against the BYE.
	// RequestCSeqs() already returns the full arrival-ordered list, so assert
	// the WHOLE in-dialog sequence — INVITE, then both INFOs, then BYE — is
	// strictly increasing too, catching a regression between the two INFOs
	// that the last-vs-BYE check alone cannot see. ACK is excluded: RFC 3261
	// has it echo the INVITE's own CSeq, not advance a new one.
	var seqs []uint32
	for _, mc := range p.RequestCSeqs() {
		if mc.Method == "ACK" {
			continue
		}
		seqs = append(seqs, mc.CSeq)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("in-dialog CSeq sequence not strictly increasing at index %d: %v (full arrival order: %v)",
				i, seqs, p.RequestCSeqs())
		}
	}
}

// TestSendDTMFInfoRejectedByPeerReportsNotSupported covers two of correction
// 7's fixes: a peer's 405 must (a) map to not_supported, not
// precondition_failed, matching the rfc2833 arm's convention; and (b) never
// interpolate the raw digit into the error message (digit strings carry
// PINs/card numbers), naming the digit's INDEX instead. emittedDurationMs is
// the plain per-digit durationMs on this failure path too (never 0, never
// scaled by how many digits succeeded) — see sendDTMFInfo's doc comment;
// sent=0 alone is what says "nothing landed".
func TestSendDTMFInfoRejectedByPeerReportsNotSupported(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// Armed BEFORE the send, so it fails on THIS send's very first digit
	// (index 0) — this test is about the not_supported mapping and the
	// no-digit-leak message, not about the partial-send digit COUNT (that is
	// TestSendDTMFInfoPartialSendReportsTheCorrectDigitCount's job, which
	// fails mid-sequence instead).
	p.SetBehaviour(peer.Behaviour{RejectInfoStatus: 405})

	sent, emitted, err := ua.SendDTMF(context.Background(), res.DialogID, "23", session.DTMFModeInfo, 100, 0)
	if err == nil {
		t.Fatal("SendDTMF(info): want an error once the peer rejects the next INFO with 405, got nil")
	}
	if code := apierr.CodeOf(err); code != apierr.CodeNotSupported {
		t.Fatalf("code=%v want not_supported (matches rfc2833's 'far end can't/won't do this' convention): %v", code, err)
	}
	if sent != 0 {
		t.Fatalf("sent=%d want 0 — the FIRST digit of THIS send ('2') was rejected immediately", sent)
	}
	if emitted != 100 {
		t.Fatalf("emitted=%d want 100 (the plain per-digit duration, regardless of sent)", emitted)
	}
	if strings.Contains(err.Error(), "'2'") || strings.Contains(err.Error(), `"2"`) {
		t.Fatalf("error message must not interpolate the raw digit (PIN/card-number leak risk): %v", err)
	}
	if !strings.Contains(err.Error(), "index 0") {
		t.Fatalf("error message should name the digit's index, not its value: %v", err)
	}
}

// TestSendDTMFInfoPartialSendReportsTheCorrectDigitCount isolates correction
// 7's third fix from the not_supported-mapping test above: a three-digit send
// whose THIRD digit is rejected must report sent=2 — the two digits that DID
// land — never 0 or 3. emittedDurationMs stays the plain per-digit durationMs
// (100) here too, same as every other path; sent alone communicates
// partiality (see sendDTMFInfo's doc comment for why emittedDurationMs never
// also encodes it). A nonzero gap, driven explicitly through the fake clock
// (the same idiom as the gap test above), parks the sender deterministically
// between digits so the rejection can be armed with NO request in flight —
// racing a live peer response against SetBehaviour would make the exact digit
// rejected nondeterministic.
func TestSendDTMFInfoPartialSendReportsTheCorrectDigitCount(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := ua.SendDTMF(context.Background(), res.DialogID, "123", session.DTMFModeInfo, 100, 20)
		done <- result{sent, emitted, err}
	}()

	clk.BlockUntil(1) // parked in the gap after '1' succeeded, before '2'
	clk.Advance(20 * time.Millisecond)
	clk.BlockUntil(1) // parked in the gap after '2' succeeded, before '3' — no request in flight now
	p.SetBehaviour(peer.Behaviour{RejectInfoStatus: 501})
	clk.Advance(20 * time.Millisecond) // proceeds to send '3', which is now rejected

	res2 := <-done
	if res2.err == nil {
		t.Fatal("SendDTMF(info): want an error once the third INFO is rejected, got nil")
	}
	if apierr.CodeOf(res2.err) != apierr.CodeNotSupported {
		t.Fatalf("code=%v want not_supported", apierr.CodeOf(res2.err))
	}
	if res2.sent != 2 {
		t.Fatalf("sent=%d want 2 (digits '1' and '2' landed before '3' was rejected)", res2.sent)
	}
	if res2.emitted != 100 {
		t.Fatalf("emitted=%d want 100 (the plain per-digit duration, regardless of sent)", res2.emitted)
	}
	if n := p.Count("INFO"); n != 3 {
		t.Fatalf("%d INFO requests on the wire, want 3 (the third was sent and rejected, not skipped): %v", n, p.Methods())
	}
}

// TestSendDTMFInfoCallerCtxCancelledDuringGapIsClassifiable covers correction
// 7's second fix: the caller's own ctx (distinct from the UA's lifecycle
// uaCtx) must be watched during the inter-digit gap, and its cancellation
// must be classifiable through apierr.CodeOf — never a bare
// ctx.Err()/context.Canceled.
func TestSendDTMFInfoCallerCtxCancelledDuringGapIsClassifiable(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		sent, emitted int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		sent, emitted, err := ua.SendDTMF(ctx, res.DialogID, "12", session.DTMFModeInfo, 100, 20)
		done <- result{sent, emitted, err}
	}()

	// The first INFO's 2xx lands, then the gap-timing select parks on BOTH
	// ctx.Done() and u.cfg.Clock.After(20ms) — cancelling here proves the
	// select actually watches the caller's ctx (it did not, before this
	// task's fix), rather than only u.uaCtx.
	clk.BlockUntil(1)
	cancel()

	res2 := <-done
	if res2.err == nil {
		t.Fatal("SendDTMF(info): want an error after caller ctx cancellation, got nil")
	}
	if code := apierr.CodeOf(res2.err); code != apierr.CodeCancelled {
		t.Fatalf("code=%v want cancelled (classifiable via apierr.CodeOf, not a bare context error): %v", code, res2.err)
	}
	if res2.sent != 1 {
		t.Fatalf("sent=%d want 1 (the first digit landed before cancellation)", res2.sent)
	}
}

// TestSendDTMFInfoRejectsASecondConcurrentSendOnTheSameCall pins the info
// arm's single-flight claim. inband is serialised by the media slot and
// rfc2833 by the loop's rtpEvent slot — a second concurrent send on the same
// call gets precondition_failed from either — but the info arm took no claim
// at all and went straight into its per-digit INFO loop, so two concurrent
// sends interleaved their digits on the wire while BOTH reported success. A
// four-digit PIN and a two-digit menu selection issued together (a media
// plan's dtmf step and a discrete dtmf_send tool call are independent
// goroutines through one SendDTMF) reached the far end scrambled.
//
// The fake clock makes the race deterministic rather than probabilistic: the
// first send parks in its inter-digit gap on u.cfg.Clock.After(20ms) — the one
// waiter this dialog registers, which is what BlockUntil(1) synchronises on,
// the same idiom the gap and ctx-cancellation tests above use — and the second
// send is issued while it is provably parked mid-string.
func TestSendDTMFInfoRejectsASecondConcurrentSendOnTheSameCall(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 20)
		done <- result{sent, err}
	}()
	clk.BlockUntil(1)

	_, _, err2 := ua.SendDTMF(context.Background(), res.DialogID, "34", session.DTMFModeInfo, 100, 0)
	if err2 == nil {
		t.Fatal("the second concurrent info send succeeded; its INFOs interleave with the first send's digits")
	}
	if code := apierr.CodeOf(err2); code != apierr.CodePreconditionFailed {
		t.Fatalf("code=%v want precondition_failed (what the inband and rfc2833 arms return for the same race): %v", code, err2)
	}

	clk.Advance(20 * time.Millisecond)
	first := <-done
	if first.err != nil || first.sent != 2 {
		t.Fatalf("the first send returned sent=%d err=%v, want 2 and nil — the rejected send must not disturb it", first.sent, first.err)
	}
	// Nothing of the rejected send reached the wire: 2 INFOs, not 3 or 4.
	if n := p.Count("INFO"); n != 2 {
		t.Fatalf("%d INFOs on the wire, want exactly the first send's 2: %v", n, p.Methods())
	}
}

// TestSendDTMFInfoOnAnAnsweredDialogIsUASOriented is the INFO arm's only
// INBOUND coverage: every other test in this file establishes its dialog with
// ua.Dial, so buildInDialogRequest's whole dir == session.Inbound branch was
// untested for INFO — and answering a call and then signalling digits into its
// IVR is the primary scenario dtmf_send(mode:"info") exists for. All four
// direction-sensitive parts of the request are pinned here, because each is a
// separate correction that was applied (or missed) independently:
//
//   - REQUEST-URI must be the PEER's Contact, not the received INVITE's own
//     recipient (which is THIS UA's address). That is what p.Count("INFO") == 1
//     asserts: the URI is what the transport resolves the destination from, so
//     with that correction reverted the INFO is delivered to this UA's own
//     listener — where onInfo finds the dialog by Call-ID and 200s it, so the
//     send still reports success and only the peer's silence gives it away.
//   - FROM tag must be OURS (the tag we minted on our 200 OK) and TO tag the
//     PEER's; BuildByeFromInvite orients them for a UAC, which is backwards on
//     a dialog we answered.
//   - CONTACT must be OURS; the builder clones the INVITE's, which here is the
//     peer's own URI.
func TestSendDTMFInfoOnAnAnsweredDialogIsUASOriented(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	dialogID, invite, ourTag := establishInboundAnswered(t, ua, p, events)
	peerFrom := invite.From()
	if peerFrom == nil {
		t.Fatal("peer's own INVITE carries no From header")
	}
	peerTag, _ := peerFrom.Params.Get("tag")
	if ourTag == "" || peerTag == "" {
		t.Fatalf("empty tag(s): ours=%q peer's=%q", ourTag, peerTag)
	}

	sent, _, err := ua.SendDTMF(context.Background(), dialogID, "7", session.DTMFModeInfo, 100, 0)
	if err != nil {
		t.Fatalf("SendDTMF(info) on an answered inbound dialog: %v", err)
	}
	if sent != 1 {
		t.Fatalf("digits_sent=%d want 1", sent)
	}

	if n := p.Count("INFO"); n != 1 {
		t.Fatalf("the peer received %d INFOs, want 1 — the Request-URI did not resolve to the peer "+
			"(an inbound dialog's in-dialog Request-URI must come from the peer's Contact): %v", n, p.Methods())
	}
	if got := tagOf(p.LastRequestHeader("INFO", "From")); got != ourTag {
		t.Errorf("INFO From tag = %q, want this UA's own tag %q (UAS orientation)", got, ourTag)
	}
	if got := tagOf(p.LastRequestHeader("INFO", "To")); got != peerTag {
		t.Errorf("INFO To tag = %q, want the peer's tag %q — From/To were swapped", got, peerTag)
	}
	wantContact := "<sip:alice@" + ua.BoundAddr().String() + ">"
	if got := p.LastRequestHeader("INFO", "Contact"); got != wantContact {
		t.Errorf("INFO Contact = %q, want %q (ours, not the peer's)", got, wantContact)
	}
}

// The three tests below are buildInDialogRequest's OUTBOUND Contact coverage,
// and their absence is what let a behaviour change ship behind a code comment
// that asserted "this needs no direction test". The header the builder derives
// (u.localContact()) and the header its underlying builder CLONES off the
// dialog INVITE are the SAME STRING under default configuration — so a test
// written against a default UA cannot fail whichever one the builder emits, and
// pinning the outbound direction at all REQUIRES a configuration in which the
// two diverge. There are exactly two such vectors, both measured on the wire:
//
//   - DialRequest.FromUser, a public input (session's from_user), which sets
//     the outbound INVITE's Contact USER but never reaches u.localContact()'s
//     aorUser(u.cfg.AOR);
//   - the RFC 3581 learned public address, which replaces u.localContact()'s
//     HOST AND PORT once a registrar has stamped received/rport, where the
//     INVITE went out carrying the bound socket.
//
// Each test therefore opens by asserting its own vector is LIVE — that the two
// values really did diverge in this run — because a vector that silently failed
// to take effect turns the whole test back into the tautology above.

// TestOutboundInDialogContactIsTheINVITEsWhenFromUserOverridesTheAOR pins the
// from_user vector: INFO and BYE on a dialog we DIALLED must carry the Contact
// our own INVITE advertised, not a re-derived one. On an outbound dialog the
// cloned Contact is already ours — it is the exact URI this peer was told to
// reach us at — so re-deriving it moves the dialog's advertised contact
// mid-dialog for no reason.
func TestOutboundInDialogContactIsTheINVITEsWhenFromUserOverridesTheAOR(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI:    "sip:bob@" + p.Addr(),
		FromUser: "charlie",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	inviteContact := p.LastRequestHeader("INVITE", "Contact")
	if !strings.Contains(inviteContact, "charlie") {
		t.Fatalf("INVITE Contact=%q carries no from_user: the divergence vector is DEAD in this run, "+
			"so every assertion below would hold whichever Contact the builder emits", inviteContact)
	}

	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "7", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info): %v", err)
	}
	if got := p.LastRequestHeader("INFO", "Contact"); got != inviteContact {
		t.Errorf("INFO Contact=%q, want the INVITE's own %q — the contact this dialog advertises "+
			"must not change mid-dialog", got, inviteContact)
	}

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 3*time.Second)
	if got := p.LastRequestHeader("BYE", "Contact"); got != inviteContact {
		t.Errorf("BYE Contact=%q, want the INVITE's own %q", got, inviteContact)
	}
}

// TestOutboundInDialogContactIsTheINVITEsWhenAnRportPublicAddressWasLearned
// pins the second vector, which moves HOST AND PORT rather than the user: a
// register-mode UA whose registrar stamped a distinct received/rport learns a
// public address, and u.localContact() then answers with it while the INVITE
// already on this dialog carries the bound socket.
//
// sipproxy.SetObservedAddr is what makes learned and bound distinguishable at
// all — ordinary stamping mirrors the packet's real source, which on loopback
// IS the bound socket (see rport_integration_test.go's own note). The 200 this
// UA sends to a peer-originated UPDATE is the positive control: that response's
// Contact comes from u.localContact() unconditionally (sessiontimer.go), so it
// proves the learn took effect in THIS run before the INFO/BYE assertions read
// anything.
func TestOutboundInDialogContactIsTheINVITEsWhenAnRportPublicAddressWasLearned(t *testing.T) {
	reg := sipproxy.StartProxy(t, "127.0.0.1")
	defer reg.Close()
	reg.SetDigest("sipclient-test", "alice", policy.NewSecret("s3cr3t"))
	learned := netip.MustParseAddrPort("198.51.100.9:40000")
	reg.SetObservedAddr(learned)

	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + reg.Addr(),
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  300,
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
		Clock:     clock.System(),
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)

	regRes, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !regRes.Registered {
		t.Fatalf("Registered=%v Code=%d, want a 200 — nothing is learned off a failed registration",
			regRes.Registered, regRes.Code)
	}

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	inviteContact := p.LastRequestHeader("INVITE", "Contact")
	if wantBound := "<sip:alice@" + ua.BoundAddr().String() + ">"; inviteContact != wantBound {
		t.Fatalf("INVITE Contact=%q want the BOUND %q — the vector needs the INVITE to carry the "+
			"bound socket while localContact carries the learned one", inviteContact, wantBound)
	}
	p.SendUPDATEToCaller(t, "")
	waitForCond(t, func() bool { return p.LastResponseStatus("UPDATE") == 200 })
	if got := p.LastResponseHeader("UPDATE", 200, "Contact"); !strings.Contains(got, learned.String()) {
		t.Fatalf("the 200 to the peer's UPDATE carries Contact=%q, want the LEARNED %s: the RFC 3581 "+
			"learn never took effect, so the divergence vector is DEAD in this run", got, learned)
	}

	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "7", session.DTMFModeInfo, 100, 0); err != nil {
		t.Fatalf("SendDTMF(info): %v", err)
	}
	if got := p.LastRequestHeader("INFO", "Contact"); got != inviteContact {
		t.Errorf("INFO Contact=%q, want the INVITE's own %q — host and port must not change mid-dialog", got, inviteContact)
	}

	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	p.WaitForBye(t, 3*time.Second)
	if got := p.LastRequestHeader("BYE", "Contact"); got != inviteContact {
		t.Errorf("BYE Contact=%q, want the INVITE's own %q", got, inviteContact)
	}
}

// TestOutboundSessionTimerRefreshKeepsOurOwnContact is the other side of the
// same carve-out, and it is why the carve-out is on METHOD as well as
// direction. BYE and INFO are not target-refresh requests; UPDATE and the
// re-INVITE refresh ARE (RFC 3261 §12.2.2 / RFC 3311 §5), so the Contact they
// carry REPLACES the peer's remote target for this dialog and must stay
// u.localContact() in both directions. refreshSession used to patch that at its
// own call site and dropped the patch when the builder took it over; this test
// is what keeps the drop safe. Driven on the from_user vector, since under
// default configuration the two candidate Contacts coincide and the existing
// outbound-refresh Contact assertion cannot tell them apart.
func TestOutboundSessionTimerRefreshKeepsOurOwnContact(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI:    "sip:bob@" + p.Addr(),
		FromUser: "charlie",
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if got := p.LastRequestHeader("INVITE", "Contact"); !strings.Contains(got, "charlie") {
		t.Fatalf("INVITE Contact=%q carries no from_user: the divergence vector is DEAD in this run", got)
	}

	// RFC 4028 §10: we refresh at interval/2 = 45s.
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })

	want := "<sip:alice@" + ua.BoundAddr().String() + ">"
	if got := p.LastRequestHeader("UPDATE", "Contact"); got != want {
		t.Fatalf("UPDATE refresh Contact=%q want %q (ours): a target-refresh request REPLACES the "+
			"peer's remote target, so it must carry the address we want addressed", got, want)
	}
}

// TestOutboundReINVITERefreshKeepsOurOwnContact is the FOURTH method that
// reaches buildInDialogRequest's Contact guard, and until this test the guard's
// `method == sip.INVITE` arm was pinned by nothing: deleting that clause left
// the whole internal/sipua package green. The arm is a live production path —
// refreshMethodFor (sessiontimer.go) falls back to a re-INVITE whenever the
// peer's cached Allow omits UPDATE, which is the lever this test pulls.
//
// TestWeRefreshWithReINVITEWhenThePeerDoesNotAllowUPDATE
// (sessiontimer_refresh_test.go) already drives the same path, but asserts
// method/ACK/event and not Contact, and runs on DEFAULT configuration where the
// two candidate Contact values are the same string — so it could not pin
// Contact even if it asserted it. This test therefore takes the from_user
// vector and asserts the vector is live before asserting anything else, exactly
// as its three siblings above do.
func TestOutboundReINVITERefreshKeepsOurOwnContact(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			// No UPDATE in Allow: refreshMethodFor falls back to a re-INVITE.
			AnswerAllow: "INVITE, ACK, BYE, CANCEL",
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)

	if _, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI:    "sip:bob@" + p.Addr(),
		FromUser: "charlie",
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	if got := p.LastRequestHeader("INVITE", "Contact"); !strings.Contains(got, "charlie") {
		t.Fatalf("INVITE Contact=%q carries no from_user: the divergence vector is DEAD in this run, "+
			"so the assertion below would hold whichever Contact the builder emits", got)
	}
	before := p.Count("INVITE")

	// RFC 4028 §10: we refresh at interval/2 = 45s.
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return p.Count("INVITE") > before })
	if n := p.Count("UPDATE"); n != 0 {
		t.Fatalf("UPDATE count=%d want 0 — the refresh did not fall back to a re-INVITE, so this run "+
			"never exercised the arm under test", n)
	}

	want := "<sip:alice@" + ua.BoundAddr().String() + ">"
	if got := p.LastRequestHeader("INVITE", "Contact"); got != want {
		t.Fatalf("re-INVITE refresh Contact=%q want %q (ours): a target-refresh request REPLACES the "+
			"peer's remote target, so it must carry the address we want addressed", got, want)
	}
}

// TestSendDTMFInfoRejectsAConcurrentInbandSendOnTheSameCall is F1's info∥inband
// cross-mode pair, driven for REAL (both sends actually run) rather than by
// simulation: before F1, each of the three dtmf_send modes was single-flighted
// only against ITSELF (info via the old per-arm dtmfInfoInFlight, inband via
// claimOp(opDTMFInband)), so nothing excluded a DIFFERENT mode from running
// concurrently on the same dialog — which is what let an rfc2833/inband tick
// race corrupt an inband DTMFSource in the first place. This pins the FIX
// (SendDTMF's dialog-level dtmfSendInFlight claim, dtmf.go) at the
// info<->inband pair specifically.
func TestSendDTMFInfoRejectsAConcurrentInbandSendOnTheSameCall(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 20)
		done <- result{sent, err}
	}()
	// Parked in the gap after '1' succeeded, before '2' — the info send still
	// holds the dialog-level claim.
	clk.BlockUntil(1)

	_, _, err2 := ua.SendDTMF(context.Background(), res.DialogID, "9", session.DTMFModeInband, 20, 0)
	if code := apierr.CodeOf(err2); code != apierr.CodePreconditionFailed {
		t.Fatalf("inband concurrent with an in-flight info send: code=%v want precondition_failed: %v", code, err2)
	}

	clk.Advance(20 * time.Millisecond)
	first := <-done
	if first.err != nil || first.sent != 2 {
		t.Fatalf("info send = %+v, want sent=2 err=nil", first)
	}

	// Once info has released the claim, inband must succeed.
	if _, _, err3 := ua.SendDTMF(context.Background(), res.DialogID, "9", session.DTMFModeInband, 20, 0); err3 != nil {
		t.Fatalf("inband after info released the claim: %v", err3)
	}
}

// TestSendDTMFInfoRejectsAConcurrentRFC2833SendOnTheSameCall is F1's
// info∥rfc2833 cross-mode pair, the third of the brief's three pairs
// (info∥inband above, inband∥rfc2833 in dtmf_test.go's whitebox suite).
// telephone-event is negotiated by default on an outbound dial (sipua always
// offers it, and the test peer mirrors it — sdp.go, peer.go's
// buildDefaultAnswer), so no extra setup is needed.
func TestSendDTMFInfoRejectsAConcurrentRFC2833SendOnTheSameCall(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newDirectUA(t, clk)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	type result struct {
		sent int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 20)
		done <- result{sent, err}
	}()
	clk.BlockUntil(1)

	_, _, err2 := ua.SendDTMF(context.Background(), res.DialogID, "9", session.DTMFModeRFC2833, 20, 0)
	if code := apierr.CodeOf(err2); code != apierr.CodePreconditionFailed {
		t.Fatalf("rfc2833 concurrent with an in-flight info send: code=%v want precondition_failed: %v", code, err2)
	}

	clk.Advance(20 * time.Millisecond)
	first := <-done
	if first.err != nil || first.sent != 2 {
		t.Fatalf("info send = %+v, want sent=2 err=nil", first)
	}

	// Once info has released the claim, rfc2833 must succeed.
	if _, _, err3 := ua.SendDTMF(context.Background(), res.DialogID, "9", session.DTMFModeRFC2833, 20, 0); err3 != nil {
		t.Fatalf("rfc2833 after info released the claim: %v", err3)
	}
}

// TestSendDTMFInfoWithNilUACtxAndClockDuringTheGapDoesNotPanic is B-M1's
// regression test. sendDTMFInfo's inter-digit gap select dereferenced
// u.uaCtx.Done() and u.cfg.Clock.After() directly, with no nil guard — unlike
// waitForDigits' own `clk := u.cfg.Clock; if clk == nil {...}` idiom elsewhere
// in this package. A *UA built via New() (every production path) always sets
// both, so this could not panic in production; ZeroUALifecycleFieldsForTest
// simulates the one shape that could (a *UA assembled some other way) against
// a REAL established call, so the gap is reached exactly as it would be in
// sendDTMFInfo's real per-digit loop.
func TestSendDTMFInfoWithNilUACtxAndClockDuringTheGapDoesNotPanic(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	restore := sipua.ZeroUALifecycleFieldsForTest(ua)
	defer restore()

	// A small REAL gap (u.cfg.Clock is nil, so the B-M1 fallback is
	// clock.System(), a real timer) between two digits: the first INFO must
	// succeed, then the gap-select must be reached without panicking.
	sent, _, err := ua.SendDTMF(context.Background(), res.DialogID, "12", session.DTMFModeInfo, 100, 5)
	if err != nil {
		t.Fatalf("SendDTMF(info) with nil uaCtx/Clock: %v", err)
	}
	if sent != 2 {
		t.Fatalf("digits_sent=%d want 2", sent)
	}
}
