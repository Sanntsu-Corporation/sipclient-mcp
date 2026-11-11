package sipua

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// sessionExpires is a parsed RFC 4028 Session-Expires header value.
type sessionExpires struct {
	IntervalS int
	// Refresher is "uac", "uas" or "" when the header carried no ;refresher
	// param. "" is MEANINGFUL, not a default: RFC 4028 §7.2 gives it a
	// role-dependent fallback, so it must be distinguishable from an explicit
	// value.
	Refresher string
}

// parseSessionExpires parses "1800", "1800;refresher=uac" and their
// whitespace/case variants. An interval that is absent, non-numeric or
// non-positive is not a session timer at all, so ok is false.
func parseSessionExpires(h string) (sessionExpires, bool) {
	parts := strings.Split(h, ";")
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return sessionExpires{}, false
	}
	out := sessionExpires{IntervalS: n}
	for _, p := range parts[1:] {
		k, v, found := strings.Cut(p, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "refresher") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "uac":
			out.Refresher = "uac"
		case "uas":
			out.Refresher = "uas"
		}
	}
	return out, true
}

// formatSessionExpires renders a Session-Expires value, omitting the refresher
// param when the role is unset.
func formatSessionExpires(se sessionExpires) string {
	if se.Refresher == "" {
		return strconv.Itoa(se.IntervalS)
	}
	return fmt.Sprintf("%d;refresher=%s", se.IntervalS, se.Refresher)
}

// headerValues returns every value of a possibly-repeated header. SIP allows
// both repetition and comma-joining, so a caller that reads only a single
// header can miss a token the peer supplied in the other form.
//
// Rule 16 reuse: this is the CANONICAL form of observe.go's headerValue,
// which delegates here rather than duplicating the GetHeaders walk
// (Correction 13) — headerValue's existing callers are unchanged, since it
// still returns "" for an absent header and the first value otherwise.
func headerValues(msg sip.Message, name string) []string {
	var out []string
	for _, h := range msg.GetHeaders(name) {
		out = append(out, h.Value())
	}
	return out
}

// supportsTimer reports whether any Supported/Require value names the timer
// option tag, case-insensitively, whether repeated or comma-joined.
func supportsTimer(vals []string) bool {
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "timer") {
				return true
			}
		}
	}
	return false
}

// parseMinSE reads a Min-SE header off a message, or 0 when absent.
func parseMinSE(msg sip.Message) int {
	for _, v := range headerValues(msg, "Min-SE") {
		// Min-SE may carry generic params after a ';'; only the delta matters.
		head, _, _ := strings.Cut(v, ";")
		if n, err := strconv.Atoi(strings.TrimSpace(head)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// outboundRefresherRole applies RFC 4028 §7.2's fallback for a dialog WE
// initiated: an answer that names a refresher settles it, and an answer that
// omits the param leaves the UAC — us — refreshing.
func outboundRefresherRole(se sessionExpires) string {
	if se.Refresher != "" {
		return se.Refresher
	}
	return "uac"
}

// refresherRole names who refreshes, "uac" or "uas", as seen from a transaction
// in which we are the UAC iff weAreUAC: a refresh we send (true), a peer refresh
// we answer (false), or the dialog's initial INVITE (true iff the dialog is
// outbound). weRefresh says whether WE are the one refreshing.
func refresherRole(weRefresh, weAreUAC bool) string {
	if weRefresh == weAreUAC {
		return "uac"
	}
	return "uas"
}

// weRefreshFrom is refresherRole's inverse: whether a refresher value read in such
// a transaction names us.
func weRefreshFrom(role string, weAreUAC bool) bool { return (role == "uac") == weAreUAC }

// maxAcceptableSessionIntervalS bounds the interval we accept from a peer's grant
// or 422 (a request's Min-SE may raise a dialog's interval up to
// maxHonouredMinSES, CF-118). It is deliberately NOT sessionExpiresS: a conformant
// 422 ALWAYS demands more than the interval we proposed, so bounding by our
// own proposal would refuse every genuine 422 (owner ruling, Correction 3).
//
// IT IS ALSO THE OVERFLOW BOUND (F1). It used to be applied at exactly one
// site, retryIntervalFor422; every other path that took an interval off a peer
// was bounded BELOW and not above, and `time.Duration(n) * time.Second`
// overflows NEGATIVE above 9223372036 seconds. A negative delay is a deadline
// already in the past, so the refresh timer fires the instant it is armed and
// keeps firing — an unbounded UPDATE/re-INVITE flood aimed wherever the peer
// chooses, or, on the watchdog, an instant BYE on a healthy call.
//
// The REQUEST'S Min-SE is no longer clamped to it: negotiatedInterval honours it
// up to maxHonouredMinSES and refuses above (CF-118).
const maxAcceptableSessionIntervalS = 7200

// maxHonouredMinSES is the largest Min-SE we honour from a peer (CF-118, owner
// ruling LB-D14): a request whose Min-SE is above it draws 400, and it is the
// dialog-wide bound on any Min-SE we record. It is far below the 9223372036 s at
// which time.Duration(n) * time.Second overflows (F1), so honouring a peer's
// floor up to it needs no clamp. maxAcceptableSessionIntervalS no longer bounds
// the request's Min-SE.
const maxHonouredMinSES = 86400

// retryIntervalFor422 decides how to answer a 422 Session Interval Too Small.
// It returns the interval to retry at, or 0 to fail the dial.
func (u *UA) retryIntervalFor422(peerMinSE int) int {
	if peerMinSE < 90 || peerMinSE > maxAcceptableSessionIntervalS {
		return 0
	}
	return peerMinSE
}

// sessionTimerState is one dialog's negotiated RFC 4028 state.
type sessionTimerState struct {
	// IntervalS is the negotiated Session-Expires. Refresher is "uac" or "uas"
	// FROM THE DIALOG'S POINT OF VIEW, so weRefresh below is what callers
	// actually branch on.
	IntervalS int
	Refresher string
	// weRefresh is true when THIS UA owns the refresh: refresher=uac on a dialog
	// we dialled, refresher=uas on one we answered. It is set at build time and,
	// re-written when a refresh transaction hands the role over (refreshSession)
	// or a peer refresh we answer sets it (appendInDialogRefreshHeaders). Read and written only under
	// u.calls.mu; every writer calls armSessionTimer afterwards (invariant I4).
	weRefresh bool
	// peerAllow is the peer's Allow header, cached at establishment, which
	// decides UPDATE-vs-re-INVITE (decision 11).
	peerAllow []string
	// refresher drives our own refreshes; watchdog is armed instead when the PEER
	// refreshes. At most one of the two is non-nil (invariant I1), both guarded by
	// u.calls.mu and written only by armSessionTimer and stopSessionTimer.
	refresher *refresher
	watchdog  *refresher
	// armedTimers is the number of session timers (refresher or watchdog) that
	// have been STARTED for this dialog and not yet stopped. Written under
	// u.calls.mu in the SAME critical section as every write to the `refresher` and
	// `watchdog` fields above: ++ where a timer is stored, -- where a non-nil one is
	// taken out.
	//
	// IT IS A TEST SEAM AND IT EXISTS BECAUSE EACH KIND IS ONE SLOT. An arm that
	// overwrites a still-running timer makes it UNREACHABLE -- no teardown path can
	// see it and no assertion can name it, which is exactly why the lost update it
	// comes from was invisible to `-race` and to every wire assertion. Counting the
	// starts against the stops is the only way to observe the orphan at all: in a
	// correct run this is exactly the number of non-nil slots (0 or 1), and a 2 means
	// one timer is armed that nothing will ever stop. It is NOT read by production
	// code.
	armedTimers int
	// armGen is bumped under u.calls.mu by armSessionTimer when it claims the right
	// to replace this dialog's timer, and re-checked under the same lock before the
	// replacement is stored. It is ALSO THE COMMIT FENCE (I9): each refresher's Do
	// carries the generation it was armed under, and refreshSession writes nothing
	// to st when armGen has moved since, so a refresher that has been replaced or
	// stopped cannot overwrite what its successor's state says. stopSessionTimer
	// bumps it too.
	armGen uint64
	// minSE is the largest Min-SE seen on this dialog (RFC 4028 7.4), merged under
	// u.calls.mu. It is seeded from the inbound initial INVITE and raised by every peer
	// refresh request and by 422s to our refreshes. A value above
	// maxHonouredMinSES is never recorded.
	minSE int
	// armMu serialises arms (I8): armSessionTimer holds it from its claim until after
	// the successor has been Started, and stopSessionTimer takes it, so a successor
	// never runs beside its predecessor and a teardown waits for an arm in flight
	// and then stops what that arm stored. LOCK ORDER: armMu before u.calls.mu,
	// never the reverse, and never taken on a session timer's own goroutine (the
	// handover and teardown run through runOffRefresherGoroutine).
	armMu sync.Mutex
	// answerMu serialises our 2xx answers to peer refreshes per dialog, from the
	// staged negotiation through the 2xx write, the commit and the re-arm
	// (appendInDialogRefreshHeaders). Lock order: answerMu, armMu, u.calls.mu.
	answerMu sync.Mutex
	// cancel aborts whatever the armed timer's Do currently has in flight.
	// stopSessionTimer calls it BEFORE refresher.Stop() so Stop's (deliberately
	// blocking) wait cannot park a teardown behind a full Config.Timeout
	// transaction against a peer that has gone silent. Stop's contract is
	// UNCHANGED — this only shortens what it is waiting for (Correction 5).
	cancel context.CancelFunc
}

// addSessionTimerHeaders puts RFC 4028's three request headers on an outbound
// INVITE (or on a re-INVITE refresh). se is the interval/role we PROPOSE;
// minSE is the Min-SE floor we advertise — the caller's own for the initial
// INVITE, or the peer's advertised floor when this is a 422 retry
// (Correction 10).
func (u *UA) addSessionTimerHeaders(req *sip.Request, se sessionExpires, minSE int) {
	req.RemoveHeader("Session-Expires")
	req.RemoveHeader("Min-SE")
	req.AppendHeader(sip.NewHeader("Session-Expires", formatSessionExpires(se)))
	req.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(minSE)))
	ensureSupportedTimer(req)
}

// ensureSupportedTimer is the one writer of the "timer" option tag (RFC 4028
// 7.1: every request except ACK lists it). It is APPENDED rather than replaced:
// the vendored builder may already have set option tags we must not drop, and
// SIP permits the header to repeat.
func ensureSupportedTimer(req *sip.Request) {
	if !supportsTimer(headerValues(req, "Supported")) {
		req.AppendHeader(sip.NewHeader("Supported", "timer"))
	}
}

// retry422 rebuilds the INVITE at the peer's Min-SE and drives one more
// transaction. On a refusal (a demand outside our own bounds) it returns the
// ORIGINAL 422 untouched, so runDial's ordinary final-response path reports it
// to session exactly as it would any other rejection (§11.1). Like driveTx it
// returns the retry's client transaction, live, only with a 2xx.
func (u *UA) retry422(ctx context.Context, d *dialog, res422 *sip.Response,
	now func() time.Time) (*sip.Response, sip.ClientTransaction, error) {
	peerMinSE := parseMinSE(res422)
	interval := u.retryIntervalFor422(peerMinSE)
	if interval == 0 {
		u.log().Warn("422 Session Interval Too Small demands an interval outside our bounds",
			"peer_min_se", peerMinSE, "our_session_expires_s", u.sessionExpiresS())
		return res422, nil, nil
	}
	u.calls.mu.Lock()
	inv := d.invite
	u.calls.mu.Unlock()
	// The SAME request object is reused so the Call-ID, From tag and body
	// bookkeeping stay the dialog's; only the timer headers, Via, CSeq and
	// (below) Authorization change. sipgo bumps the CSeq itself on dispatch;
	// applyDigest bumps it by hand for the digest retry runDial performs a few
	// lines above, a DIFFERENT leg from this one.
	//
	// Correction 10: the retry's Min-SE echoes the PEER's floor, not our own —
	// RFC 4028 §6 says the retry SHOULD carry the 422's Min-SE.
	//
	// inv (== d.invite) IS DELIBERATELY MUTATED IN PLACE HERE, NOT COPIED. This
	// is not an oversight against call.go:1583's "never mutated" note — that
	// note covers only the From tag, body and Content-Type its two readers
	// (ourReInviteTagLocked, ourReInviteSDPLocked) depend on, none of which
	// this call touches. The ACK call.go builds at :1377 is built FROM
	// d.invite, so keeping it identical to the transaction that actually
	// established the dialog is load-bearing; copying first and writing back
	// would be the same mutation with an extra step and no benefit.
	//
	// Rule 13 Cycle 3 fix round, finding #3: inv may still carry an
	// Authorization header from an EARLIER digest-auth attempt on this same
	// INVITE, with an already-consumed nc. Stripping it here draws a fresh
	// challenge on the retry instead of replaying that stale nonce-count.
	//
	// BOTH HEADER NAMES, NOT JUST ONE (Rule 13 Cycle 6, Phase 4 W3). applyDigest
	// writes PROXY-Authorization rather than Authorization whenever the challenge
	// arrived as a 407 (digestauth.go's `case 407`), which is the ordinary shape
	// when a proxy sits in front of the callee. Stripping only Authorization left
	// the 422-after-407 path replaying a consumed nc under the other header name:
	// identical bug class, other header. Neither strip can replay a consumed nc.
	// Note the retry cannot ANSWER a challenge either: dialLegRetries (call.go)
	// runs its digest retry above its 422 retry, once per redirect target, so a
	// 401/407 drawn BY THIS RETRY fails the leg rather than being retried
	// again — tracked as P4-W3-N02.
	inv.RemoveHeader("Authorization")
	inv.RemoveHeader("Proxy-Authorization")
	u.addSessionTimerHeaders(inv, sessionExpires{IntervalS: interval, Refresher: "uac"}, peerMinSE)
	// A NEW TRANSACTION NEEDS A NEW BRANCH. sipgo only synthesises a Via when
	// none is present, so without this strip the retry reuses the first
	// INVITE's branch and a conformant UAS matches it as a RETRANSMISSION of
	// the request it already 422'd. Mirrors sipgo's own
	// digestTransactionRequest (third_party/sipgo/client.go:234).
	inv.RemoveHeader("Via")
	return u.transactionWithProvisional(ctx, inv, u.cfg.Timeout, d.cancelSent, u.dialProvisional(d, now)) //nolint:contextcheck // u.emit delivers on the RETAINED evCtx captured by OnEvent (u.uaCtx, the long-lived UA context), not the ctx retry422 runs under: a 422-retry provisional event must keep reaching session after the request that started the dial has ended.
}

// belowMinSE reports whether a peer-supplied Session-Expires interval sits under
// our advertised Min-SE floor, warning with the caller's consequence when it does.
//
// RFC 4028's own 90s floor and our advertised Min-SE both exist to keep the
// refresh cadence sane, and the interval a peer hands us drives OUR OWN outbound
// signalling rate directly: at sessionRefreshFraction a granted 1 refreshes twice
// a second, for the life of the dialog. BOTH sites that take an interval off a
// peer's response therefore apply the bound — the initial answer
// (buildOutboundSessionTimer) and the refresh re-base (refreshSession). It is ONE
// comparison and ONE warning rather than two copies (Rule 16/18), because the
// re-base site shipped with no bound at all while the answer site had one, which
// is exactly the divergence a shared check prevents.
func (u *UA) belowMinSE(intervalS int, consequence string) bool {
	if intervalS >= u.minSES() {
		return false
	}
	u.log().Warn("peer answered a Session-Expires below our Min-SE; "+consequence,
		"answered_interval_s", intervalS, "our_min_se_s", u.minSES())
	return true
}

// clampSessionInterval is belowMinSE's missing other half: the CEILING every
// session-timer interval taken off a peer passes through before it can become a
// time.Duration (F1).
//
// It lives at the DERIVE boundary — the functions that turn a peer's
// header into the interval we will actually run on (buildOutboundSessionTimer,
// negotiatedInterval's ceiling on our own session_expires_s, refreshSession's
// re-base) — rather than at the four timer
// sites that consume the result. Guarding the timers would leave the clamped
// value absent from the Session-Expires we echo back on our own refreshes, and
// would have to be re-remembered by every future consumer of st.IntervalS; one
// clamp where the number is derived cannot be missed by a later reader.
//
// It CLAMPS rather than rejects. An over-long offer is not a reason to run with
// no session timer at all (that is what the peer gets by simply omitting the
// header), and 7200 is already the longest dialog we agreed to hold open.
func (u *UA) clampSessionInterval(intervalS int, source string) int {
	if intervalS <= maxAcceptableSessionIntervalS {
		return intervalS
	}
	u.log().Warn("peer offered a session interval above the longest dialog we will hold open; clamping",
		"source", source, "offered_interval_s", intervalS,
		"clamped_interval_s", maxAcceptableSessionIntervalS)
	return maxAcceptableSessionIntervalS
}

// buildOutboundSessionTimer reads the answer's Session-Expires and returns the
// dialog's session-timer state, or nil when the answer negotiated none.
//
// IT TAKES NO LOCK AND TOUCHES NO DIALOG. runDial records the result in the SAME
// critical section that claims phaseAnswering — the claim that makes the dialog
// answerable to an in-dialog re-INVITE or UPDATE — so that no reader can ever
// observe an answerable dialog whose negotiated timer is not yet recorded and
// answer a session refresh WITHOUT Session-Expires (RFC 4028 §7.4: that tells
// the peer the timer is off). u.calls.mu is not reentrant, so the construction
// has to be callable with that critical section about to be entered: hence a
// pure builder rather than a function that assigns under its own lock.
//
// AN ANSWER WITH NO Session-Expires MEANS NO SESSION TIMER (spec §5), not a
// timer at our proposed interval: the peer either does not implement RFC 4028 or
// declined it, and arming a refresher against a peer that will not answer
// UPDATEs would tear down a perfectly healthy call.
func (u *UA) buildOutboundSessionTimer(res *sip.Response) *sessionTimerState {
	var se sessionExpires
	var ok bool
	for _, v := range headerValues(res, "Session-Expires") {
		if se, ok = parseSessionExpires(v); ok {
			break
		}
	}
	if !ok {
		return nil
	}
	// Correction 11: an answered interval below our Min-SE floor is not a
	// session timer we will arm.
	if u.belowMinSE(se.IntervalS, "no session timer") {
		return nil
	}
	role := outboundRefresherRole(se)
	return &sessionTimerState{
		IntervalS: u.clampSessionInterval(se.IntervalS, "answer"),
		Refresher: role,
		weRefresh: role == "uac", // we are the UAC on a dialog we dialled
		peerAllow: headerValues(res, "Allow"),
	}
}

// inboundTimerRequest is what an inbound INVITE asked for under RFC 4028.
//
// An UPDATE or re-INVITE refresh never PERSISTS one of these to d.timerReq: the
// 2xx to a refresh is built from a transient read of the refresh request
// (appendInDialogRefreshHeaders), whose interval, role and Min-SE are written to
// the dialog's sessionTimerState (RFC 4028 9, cf5-b Task 4).
type inboundTimerRequest struct {
	Requested sessionExpires
	// Present is true when the request carried Supported: timer, a
	// Session-Expires header, or Require: timer. It is the switch that
	// decides whether we put RFC 4028 headers in our 2xx at all.
	//
	// NOTE: Supported: timer ALONE sets this, even with no Session-Expires —
	// RFC 4028 §9 permits imposing a session timer on such a peer, and we do
	// (this is intentional, not the "never impose on a peer that never asked"
	// guard the name might suggest). Asterisk sends Supported: timer by
	// default, so this SHOULD-imposed timer fires on nearly every Asterisk
	// call, and Task 29 will refresh nearly all of them as a result — an
	// interop consequence of the design, not a defect.
	Present bool
	// Required is true for Require: timer, which forces Session-Expires into our
	// 2xx (spec §5).
	Required bool
	// Supported is true when the request advertised Supported: timer,
	// distinct from Present (which a bare Session-Expires also sets). RFC
	// 4028 §9 gates the 2xx's Require: timer on it when WE are the refresher.
	Supported bool
	MinSE     int
	Allow     []string
}

// readInboundSessionTimer extracts the peer's RFC 4028 request from a message.
func readInboundSessionTimer(msg sip.Message) inboundTimerRequest {
	out := inboundTimerRequest{
		MinSE: parseMinSE(msg),
		Allow: headerValues(msg, "Allow"),
	}
	out.Required = supportsTimer(headerValues(msg, "Require"))
	for _, v := range headerValues(msg, "Session-Expires") {
		if se, ok := parseSessionExpires(v); ok {
			out.Requested = se
			out.Present = true
			break
		}
	}
	out.Supported = supportsTimer(headerValues(msg, "Supported"))
	if out.Supported || out.Required {
		out.Present = true
	}
	return out
}

// inboundRefresherRole decides who refreshes a dialog WE answered.
//
// Decision 12: we claim "uas" for calls we accept. Decision 9 qualifies it: a
// peer that EXPLICITLY asked for a role gets it, because full RFC 4028
// negotiation means honouring the other end's stated preference rather than
// overriding it — and a peer that asked to refresh and was told it would not
// simply stops refreshing, and the call dies on our watchdog.
func inboundRefresherRole(req inboundTimerRequest) string {
	// CF-119: only a request that indicated support for the extension gets its
	// refresher honoured (RFC 3261 8.2.4; RFC 4028 Table 2).
	if req.Requested.Refresher != "" && (req.Supported || req.Required) {
		return req.Requested.Refresher
	}
	return "uas"
}

// requireTimerInAnswer applies RFC 4028 §9: Require: timer is a MUST when the
// answer names the UAC as refresher, and a SHOULD when we refresh AND the
// request advertised Supported: timer. A peer that advertised neither must not
// be handed an extension it never claimed.
func requireTimerInAnswer(req inboundTimerRequest, role string) bool {
	return role == "uac" || req.Supported
}

// peerAllowsUPDATE reports whether an Allow header set names UPDATE.
func peerAllowsUPDATE(allow []string) bool {
	for _, v := range allow {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "UPDATE") {
				return true
			}
		}
	}
	return false
}

// ourAllow is the Allow header this UA advertises. UPDATE IS ON IT FROM P3
// (spec §5) and that is required regardless of which end refreshes: when the
// PEER is the refresher it sends UPDATEs at us, and a peer that cannot see
// UPDATE in our Allow will refresh with a re-INVITE instead — replaying SDP for
// no reason on every interval. It lists exactly the methods installHandlers
// registers (RFC 3261 20.5), NOTIFY included.
func ourAllow() string {
	return "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, UPDATE, NOTIFY"
}

// negotiatedInterval applies RFC 4028 9 to a request's Session-Expires: the UAS
// MAY reduce it but MUST NOT set it below the request's Min-SE (nor below 90 s),
// and we cap it at our own session_expires_s unless the request's Min-SE is
// higher than that ceiling. It returns the interval and a refusal code:
//
//   - 400 when the request's Min-SE is above maxHonouredMinSES (CF-118, LB-D14),
//     checked first; intervalS is 0.
//   - 422 when the requested interval is below our min_se_s; intervalS is then
//     the value computed without our own floor, which the caller may ignore.
//   - 0 otherwise.
//
// The request's Min-SE is honoured as given up to maxHonouredMinSES, not clamped
// to the 7200 s config ceiling (CF-118): clamping it would set an interval below
// the Min-SE the request demanded, which RFC 4028 9 forbids.
func (u *UA) negotiatedInterval(req inboundTimerRequest) (intervalS, refuse int) {
	if req.MinSE > maxHonouredMinSES {
		return 0, 400
	}
	want := req.Requested.IntervalS
	if want == 0 {
		// Supported: timer with no Session-Expires: the peer is willing, so we
		// propose our own configured interval.
		want = u.sessionExpiresS()
	}
	floor := max(90, req.MinSE)
	// F1: the ceiling is our own session_expires_s, clamped to the overflow bound.
	ceiling := max(u.clampSessionInterval(u.sessionExpiresS(), "our session_expires_s"), floor)
	intervalS = min(max(want, floor), ceiling)
	if want < u.minSES() {
		return intervalS, 422
	}
	return intervalS, 0
}

// buildInboundSessionTimer returns the session-timer state for a call we are
// answering. Like buildOutboundSessionTimer it TAKES NO LOCK AND TOUCHES NO
// DIALOG, for the same reason: Answer records the result in the SAME critical
// section that publishes d.phase/d.ok, i.e. the one that makes the dialog
// answerable to an in-dialog request, so a re-INVITE or UPDATE arriving the
// instant our 200 OK lands can never be answered without the Session-Expires
// the dialog just negotiated.
func buildInboundSessionTimer(intervalS int, role string, allow []string, minSE int) *sessionTimerState {
	return &sessionTimerState{
		IntervalS: intervalS,
		minSE:     minSE,
		Refresher: role,
		// We are the UAS on a dialog we answered, so we refresh iff the role is
		// uas.
		weRefresh: role == "uas",
		peerAllow: allow,
	}
}

// armSessionTimer installs the session timer the dialog's CURRENT role calls for:
// our refresher when st.weRefresh, the peer-as-refresher watchdog otherwise, at the
// interval st.IntervalS. It REPLACES whatever was armed (either kind), so it is the
// one entry point for the first arm (via startSessionRefresher and
// startSessionWatchdog) and for every re-arm after a peer refresh or a role change.
//
// THE FULL INTERVAL, NOT HALF, IS THE RIGHT DEADLINE FOR THE WATCHDOG. The peer
// refreshes at interval/2 (RFC 4028 §10), so a watchdog at the full interval
// tolerates one lost refresh and fires only when the peer has genuinely stopped.
// Our own refresher fires at sessionRefreshFraction of the interval.
//
// IT REPLACES: TAKING THE OUTGOING TIMER OFF st IS PART OF ARMING, NOT SOMETHING
// THE CALLER DOES FIRST. A caller that took, Stopped and then called in would split
// the take from the store, and two refreshes interleaving across that gap lose an
// update: both store, the second overwriting a timer the first had already Started,
// which is then armed and unreachable -- stopSessionTimer reads the slot, which no
// longer names it -- and survives every teardown to fire a BYE (or a refresh) on a
// healthy or dead call. `-race` cannot see it: the mutex is held correctly
// throughout.
//
// TWO MECHANISMS MAKE THE SEQUENCE ATOMIC. st.armMu serialises arms (and teardown)
// per dialog, held across the blocking Stop of the predecessor, so a successor
// never runs beside its predecessor (I8). armGen is bumped at the claim and
// re-checked at the store, so an arm that a state writer (cf5-b Task 4) or a
// teardown has overtaken drops the timer it built; that drop leaks nothing, since
// the timer has not been Started and owns no goroutine. u.calls.mu is released
// across Stop because the predecessor's Do takes that lock.
//
// IT ARMS NOTHING ON A DIALOG THAT IS NOT ESTABLISHED (answered or in a control
// op), re-checked AFTER re-acquiring u.calls.mu, in the SAME critical section as the
// store: a peer BYE or an agent call_hangup can terminate the dialog while the
// predecessor is being stopped, and a timer stored after that would survive until
// the UA's context died.
//
// It must never run on a session timer's own goroutine (Stop would wait for
// itself); its callers are the dial and answer goroutines, sipgo's per-request
// handler goroutines, and runOffRefresherGoroutine.
//
// Correction 5: the timer runs on a CANCELLABLE child of u.uaCtx, cancelled
// BEFORE Stop, so a teardown or re-arm never blocks behind a full Config.Timeout
// transaction against a peer that has gone silent. Only the refresher's Do blocks
// on I/O; the watchdog's Do ignores its ctx, so the same cancel is harmless there
// and keeps one code path.
func (u *UA) armSessionTimer(d *dialog, st *sessionTimerState) {
	if st == nil {
		return
	}
	st.armMu.Lock()
	defer st.armMu.Unlock()
	u.calls.mu.Lock()
	if st.IntervalS <= 0 {
		u.calls.mu.Unlock()
		return
	}
	st.armGen++ // also fences the commits of the refresher taken below (I9)
	gen := st.armGen
	weRefresh, intervalS := st.weRefresh, st.IntervalS
	prevR, prevW, prevCancel := st.refresher, st.watchdog, st.cancel
	st.refresher, st.watchdog, st.cancel = nil, nil, nil
	if prevR != nil {
		st.armedTimers--
	}
	if prevW != nil {
		st.armedTimers--
	}
	u.calls.mu.Unlock()
	// Stop MUST NOT RUN UNDER u.calls.mu (I7): it waits for the timer's own
	// goroutine, and that goroutine's Do takes the same lock. cancel runs first.
	if prevCancel != nil {
		prevCancel()
	}
	if prevR != nil {
		prevR.Stop()
	}
	if prevW != nil {
		prevW.Stop()
	}
	ctx, cancel := context.WithCancel(u.uaCtx)
	var r *refresher
	if weRefresh {
		r = newRefresher(u.cfg.Clock, u.cfg.Logger, refreshPolicy{
			Name:     "session_timer",
			Fraction: sessionRefreshFraction,
			Initial:  time.Duration(intervalS) * time.Second,
			Do: func(ctx context.Context) (int, error) {
				return u.refreshSession(ctx, d, st, gen)
			},
			Retry: backoff{Attempts: 2, Base: 2 * time.Second, Cap: 8 * time.Second},
			// NO OnGiveUp, and that is NOT because "Timer F owns the failure path"
			// -- nothing below this layer converts a Timer F expiry into anything
			// (RawTransaction returns a bare error and stops). The retry budget
			// exists for the two RECOVERABLE failures: a refresh the peer REJECTS,
			// and one whose SEND fails outright (refreshSession's
			// refreshDrewNoResponse branch). A refresh that draws NO RESPONSE is
			// handled inside refreshSession, terminally and on the FIRST
			// occurrence, because §11.3.1's acceptance puts the termination at
			// Timer F expiry and a second 32s attempt would double it. Once
			// refreshSession has torn the dialog down it also Stops this
			// refresher, which aborts any pending retry wait, so the give-up path
			// is unreachable for that case and there is nothing for an OnGiveUp
			// to do. For the two recoverable failures the give-up is deliberately
			// SILENT: the refresher stops and the PEER's own session timer ends
			// the call, which is exactly what the rejected-refresh path already
			// relies on and what RFC 4028 §10 leaves the other end responsible
			// for.
		})
	} else {
		r = newRefresher(u.cfg.Clock, u.cfg.Logger, refreshPolicy{
			// "session_watchdog", NOT "session_timer": this instance's expiry ENDS THE
			// CALL, while the "session_timer" refresher sends a routine refresh. One
			// label for both makes those two indistinguishable in the logs, which is
			// the one distinction an operator reading them wants.
			Name:     "session_watchdog",
			Fraction: 1.0, // the full interval
			Initial:  time.Duration(intervalS) * time.Second,
			Do: func(context.Context) (int, error) {
				// THE TEARDOWN RUNS ON A NEW GOROUTINE, NEVER INLINE. expireSessionTimer
				// reaches stopSessionTimer, which Stops THIS watchdog -- and Stop waits
				// for this very goroutine to exit. Inline, it would wait for itself:
				// deadlock before the BYE is ever built (see runOffRefresherGoroutine).
				// Returning now lets this goroutine exit and close `done`, which is
				// exactly what unblocks the Stop the teardown is about to call.
				runOffRefresherGoroutine(func() { u.expireSessionTimer(d) }) //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as retry422 above: expireSessionTimer's dialog-ended event must keep reaching session after this goroutine's own teardown, which deliberately runs off the refresher's own goroutine (see the comment above) to avoid the self-join deadlock -- by which point the Do closure's ctx has no bearing on delivery.
				// A non-nil error stops the refresher, which is what we want: the
				// dialog is going away, so there is nothing left to watch, and Do
				// cannot fire a second expiry for the same dialog. OnGiveUp is nil, so
				// nothing escalates twice.
				//
				// C3: WRAPPED IN errRefresherStopped, not returned bare. This expiry
				// is intentional -- the timer did exactly what it exists to do -- not a
				// failure, and refresher.go's quietStop contract says a Do that wants
				// its own outcome treated as a shutdown must wrap the sentinel itself.
				// Without this, refreshPolicy's unset Retry (attempts=1) puts every
				// expiry on the n==attempts unclassified path, logging a misleading
				// "refresh gave up" WARN instead of the Debug "refresher stopping".
				return 0, fmt.Errorf("%w: %v", errRefresherStopped, errSessionExpired)
			},
		})
	}
	// The phase RE-CHECK, the generation RE-CHECK and the store are ONE critical
	// section (§6.3): the lock was released across the Stops above, so this is the
	// only place either the dialog's liveness or this arm's currency can be
	// established for this store.
	u.calls.mu.Lock()
	if !dialogEstablished(d.phase) || st.armGen != gen {
		u.calls.mu.Unlock()
		cancel()
		return
	}
	st.cancel = cancel
	if weRefresh {
		st.refresher = r
	} else {
		st.watchdog = r
	}
	st.armedTimers++
	u.calls.mu.Unlock()
	r.Start(ctx)
}

// startSessionWatchdog arms the peer-as-refresher watchdog. It is a no-op when WE
// refresh, so both callers can call it unconditionally alongside
// startSessionRefresher. See armSessionTimer.
func (u *UA) startSessionWatchdog(d *dialog, st *sessionTimerState) {
	if st == nil {
		return
	}
	u.calls.mu.Lock()
	weRefresh := st.weRefresh
	u.calls.mu.Unlock()
	if !weRefresh {
		u.armSessionTimer(d, st)
	}
}

// errRefresherSuperseded quietly stops a refresher whose generation has moved on
// (armSessionTimer or stopSessionTimer replaced it) before its commit (I9).
var errRefresherSuperseded = fmt.Errorf("%w: superseded by a newer session timer", errRefresherStopped)

// errSessionExpired stops the watchdog refresher after it has fired once.
// A-M8 (D20): errors.New, not fmt.Errorf — no format verbs.
var errSessionExpired = errors.New("session timer expired")

// onSessionRefreshReceived re-arms the dialog's session timer after an inbound
// refresh we answered 200 (RFC 4028 §9: the session expiration is the time of the
// last 2xx to a refresh plus the interval, so BOTH roles restart: the watchdog
// when the peer refreshes, our own refresher when we do). It REPLACES the timer
// rather than resetting it, because the refresher primitive deliberately has no
// Reset -- one owner, one goroutine, one schedule.
//
// THE STOP-AND-REPLACE IS armSessionTimer's, NOT THIS FUNCTION'S. Do not hoist
// either half back up here.
//
// The dialog passed in may have a nil sessionTimer (e.g. an UPDATE arriving on a
// dialog that never negotiated one) -- armSessionTimer's own nil check handles
// that.
func (u *UA) onSessionRefreshReceived(d *dialog) {
	if d == nil {
		return
	}
	u.calls.mu.Lock()
	st := d.sessionTimer
	u.calls.mu.Unlock()
	u.armSessionTimer(d, st)
}

// expireSessionTimer ends the dialog per spec §5: BYE carrying Reason:
// SIP;cause=408, then UAEventDialogEnded with cause session_timer_expired, which
// session maps to termination_reason "session_timer_expired".
//
// The BYE goes out through hangupWithReason — the SAME single BYE path
// call_hangup uses (Rule 18) — so the phase claim, the media-loop teardown and
// the registry forget all happen exactly once and a racing call_hangup gets
// precondition_failed rather than putting a second BYE on the wire. That path
// stops the media loop BEFORE it sends the BYE, exactly as every local hangup
// always has; the phase claim precedes both, so a dialog this function claims
// always reaches the wire with the Reason header attached.
//
// C10 (Cycle 5 finding K): "exactly once" here is the SIPUA-LOCAL half — one
// phase claim, one media teardown, one registry forget. The AUTHORITATIVE
// exactly-once guarantee for a call's terminal transition lives one layer up, in
// session.(*Call).TryTerminate's CAS on c.state (internal/session/call.go), which
// is what actually makes a second terminate attempt a precondition_failed rather
// than a second event. Read the two together: neither is sufficient alone.
//
// IT MUST NOT BE CALLED DIRECTLY FROM THE WATCHDOG'S Do. hangupWithReason
// reaches stopSessionTimer, which Stops the watchdog and WAITS for its
// goroutine; on that goroutine this would be a self-join deadlock. Its one
// production caller therefore goes through runOffRefresherGoroutine (Task 29).
func (u *UA) expireSessionTimer(d *dialog) {
	// Config.Logger is nil-able (see Config's own doc comment); u.log()
	// (keepalive.go) is this package's nil-safe accessor and is used at every
	// log site this function adds — a bare u.cfg.Logger.Warn/Debug SIGSEGVs on
	// every test in this package, where Config.Logger is never set.
	u.log().Warn("session timer expired; ending the dialog",
		"dialog_id", d.id, "call_id", d.callID)
	err := u.hangupWithReason(u.uaCtx, d.id, sip.NewHeader("Reason", "SIP;cause=408"))
	if err != nil {
		// A concurrent terminator already won: BOTH precondition_failed and
		// not_found mean some other path claimed this dialog first, and we
		// must not emit a second, contradictory UAEventDialogEnded on top of
		// whatever that other path already did (or deliberately did not).
		// not_found is the one that actually happens, PROVIDED no path forgets
		// a dialog (forgetLocked, call.go:1014) without also having set it a
		// terminal phase first: onBye, hangupWithReason, teardownDialog,
		// stopAllMediaLoops and endDialogInDialogTimeout all claim the phase
		// and forget in the SAME critical section, so hangupWithReason's
		// opening u.lookup fails not_found and the precondition_failed check
		// below is never reached. runDial's three pre-answer failure paths
		// (call.go:1316-1317, :1330-1331, :1378-1379) are the exception: they
		// set the phase and forgetLocked as two SEPARATE lock holds. That
		// split is harmless here only because no watchdog can be armed for a
		// dialog that never reached phaseAnswered (startSessionWatchdog
		// re-checks phaseAnswered under the lock before storing,
		// sessiontimer.go:487-491), so this function can never race one of
		// them. THAT IS A DOCUMENTED-BUT-UNENFORCED ASSUMPTION, not one the
		// code guarantees: nothing stops a future teardown path from
		// splitting the write the way runDial's does while also being
		// reachable from phaseAnswered, and if one ever is, this not_found
		// reasoning stops holding.
		//
		// It is also not true that the concurrent terminator always emitted
		// the dialog-end event: stopAllMediaLoops, Hangup and Reject claim and
		// forget the dialog but emit NOTHING. Returning silently here is still
		// correct for those — outside this race window they emit nothing for
		// the same dialogs anyway, so a silent return here is consistent with
		// their normal behaviour rather than a swallowed event that would
		// otherwise have fired.
		//
		// The race itself is real: teardown forgets the dialog under the lock,
		// then releases it and stops the media loop before reaching
		// stopSessionTimer, and a watchdog firing in that window has already
		// spawned this call off its own goroutine, so w.Stop() cannot prevent it.
		u.log().Debug("session-timer BYE did not claim the dialog", "err", err)
		if c := apierr.CodeOf(err); c == apierr.CodePreconditionFailed || c == apierr.CodeNotFound {
			return
		}
	}
	u.emit(session.UAEvent{
		Kind: session.UAEventDialogEnded, Cause: session.UACauseSessionTimerExpired,
		DialogID: d.id, CallID: d.callID, Direction: d.direction, At: u.now(),
	})
}

// onUpdate answers an inbound in-dialog UPDATE.
//
// IT IS REQUIRED WHETHER OR NOT WE REFRESH (spec §5). When the PEER is the
// refresher every interval arrives here, and the 200 must carry the interval and
// role this refresh negotiated (appendInDialogRefreshHeaders) so the peer can
// re-base its own timer; a request with a Min-SE above what we honour, or an
// interval below our min_se_s, is refused with 400 or 422 instead. The accepted
// refresh then re-arms whichever session timer the written role calls for.
//
// An UPDATE that does NOT match a known, ANSWERED dialog carrying OUR OWN tag
// draws 481, exactly as onInfo's wire-verified fix and onInvite's re-INVITE
// guard do — an unconditional 200 asserts a dialog that is not there, and would
// hand Task 30's refresh hook an early-dialog or torn-down call.
//
// The lookup, the phase/tag check and the sessionTimer snapshot are ONE critical
// section (§6.3): a concurrent Hangup between two sections would leave us 200ing
// a dead dialog with a stale timer.
//
// An UPDATE carrying an SDP offer is applied to the live session and answered
// with our SDP in the 200 (RFC 3311 5.2; applyOffer, reoffer.go).
func (u *UA) onUpdate(req *sip.Request, tx sip.ServerTransaction) {
	u.calls.mu.Lock()
	d := u.findDialogForRequestLocked(req)
	// phaseAnswering is accepted ALONGSIDE phaseAnswered for the same reason
	// onInvite's in-dialog branch accepts it (call.go): runDial claims it before
	// its ACK reaches the wire, so an UPDATE arriving in the ACK ->
	// phaseAnswered window is answered instead of drawing a terminal 481.
	//
	// The Call-ID and both tags are matched by findDialogForRequestLocked
	// (CF-130), which rejects a tagless To. On an inbound
	// dialog with no 200 stored it accepts only d.toTag (CF-209), so the
	// ourReInviteTagLocked(d) != "" check is kept: an INBOUND dialog still in
	// phaseAnswering (d.ok not yet set) answers an UPDATE 481, not a 200 with no
	// Session-Expires, and rearms no watchdog for a not-yet-confirmed dialog.
	known := d != nil && (dialogEstablished(d.phase) || d.phase == phaseAnswering) &&
		ourReInviteTagLocked(d) != ""
	var st *sessionTimerState
	ordered := known && remoteCSeqInOrderLocked(d, req) // CF-101
	// RFC 3311 5.2: an UPDATE carrying an offer while our own offer awaits its
	// answer is refused 491 (CF-166). An UPDATE without an offer is a refresh.
	pending, busy, owned := false, false, false
	if known {
		st = d.sessionTimer
		recordPeerMinSELocked(st, req)
		offer, _ := sdpBody(req)
		pending = len(offer) > 0 && ourOfferOutstandingLocked(d)
		// An offer carrying UPDATE owns the dialog's incoming-offer slot until its
		// final response is sent (RFC 3311 5.2); a refresh without an offer does not.
		if ordered && !pending && len(offer) > 0 {
			owned = claimPeerOfferLocked(d)
			busy = !owned
		}
	}
	u.calls.mu.Unlock()
	if owned {
		defer u.releasePeerOffer(d)
	}
	if !known {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	if !ordered {
		respondOutOfOrder(req, tx)
		return
	}
	if pending {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 491, "Request Pending", nil))
		return
	}
	if busy {
		_ = tx.Respond(peerOfferBusy(req))
		return
	}

	// CF-184: an unacceptable Contact is refused before anything is applied.
	if bad := u.contactRefusal(d, req); bad != nil {
		_ = tx.Respond(bad)
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	refusal, done := u.appendInDialogRefreshHeaders(res, req, d, st)
	sent := false
	// Deferred so a panic in Respond cannot leave answerMu held. done commits the
	// negotiated state and re-arms either timer kind, only if the 2xx was written.
	defer func() { done(sent) }()
	if refusal != nil {
		_ = tx.Respond(refusal)
		return
	}
	// CF-164: a changed offer is applied to the live session and answered.
	if rej := u.applyOffer(req, d, res); rej != nil {
		_ = tx.Respond(rej)
		return
	}
	sent = tx.Respond(res) == nil
	if sent {
		u.setRemoteTarget(d, req.Contact()) // CF-184: only after the 2xx is on the wire
	}
}

// appendInDialogRefreshHeaders puts the headers our 2xx to an in-dialog
// target-refresh request MUST carry onto res — one implementation shared by
// onUpdate and onInvite's re-INVITE branch (Rule 18), because the two answer
// the same thing and had drifted apart:
//
//   - Contact. RFC 3261 §12.1.1/§12.2.2: both UPDATE and re-INVITE are
//     target-refresh requests, so a 2xx answering one MUST name our contact.
//   - Session-Expires, when the dialog HAS a negotiated timer. RFC 4028
//     §7.4/§10: a 2xx to a session-refresh request that omits it tells the peer
//     the session timer is no longer in use. The 2xx is the initial-INVITE
//     answer applied again (RFC 4028 9, LB-D6): the interval is negotiatedInterval
//     of the request (never above it, never below its Min-SE or the dialog's) and
//     the role is Table 2's (inboundRefresherRole), both of which become the
//     dialog's interval and role (RFC 4028 9: the UA "remembers whether it or its
//     peer is the refresher ... based on the value of the refresher parameter from
//     the most recent 2xx response to a session refresh request", rfc4028.txt:918-921).
//     A request with no Session-Expires keeps the dialog's current interval.
//   - Require: timer, on RFC 4028 §9's terms (requireTimerInAnswer), now with the
//     role in this transaction's orientation.
//   - Allow, which is what keeps a refreshing peer on UPDATE instead of
//     falling back to a re-INVITE every interval (ourAllow).
//
// It returns the response to send INSTEAD of res when the request is refused (400
// for a Min-SE above maxHonouredMinSES; 422 for a Session-Expires below our
// min_se_s, only to a request that lists timer and carries its own
// Session-Expires, rfc4028.txt:828-832), else nil. A refusal writes no interval or
// role and bumps no generation (L1): only a 2xx extends the session
// (rfc4028.txt:937-938).
//
// ORDERING FOR CALLERS: any refusal decided in the caller (a glare 491, a 488, a
// 420) must be decided BEFORE this call, and an offer applied only AFTER it
// returns nil, because it commits the 2xx's interval and role to the dialog.
//
// THE NEGOTIATION IS STAGED, NOT COMMITTED: it is applied by the returned done(sent)
// only when the 2xx was actually written (a failed write leaves the old role,
// interval and timer: the peer never saw the new ones), and done then re-arms the
// matching timer (onSessionRefreshReceived). st.answerMu is held from here until
// done returns, so per dialog the order of commits, 2xx transmissions and re-arms
// agree (RFC 4028 9: the most recent 2xx decides). done is never nil and MUST be
// called exactly once, after tx.Respond (done(false) after a refusal or a failed
// write).
//
// st's fields are read and written under u.calls.mu, so this MUST be called with
// that lock RELEASED. Lock order: answerMu, then armMu, then u.calls.mu.
func (u *UA) appendInDialogRefreshHeaders(res *sip.Response, req *sip.Request, d *dialog, st *sessionTimerState) (*sip.Response, func(sent bool)) {
	res.AppendHeader(u.localContact())
	done := func(sent bool) {
		if sent {
			u.onSessionRefreshReceived(d)
		}
	}
	handedOff := false
	if st != nil {
		st.answerMu.Lock()
		unlock := st.answerMu.Unlock
		// A panic while staging (including in a response constructor) must not
		// leave answerMu held; ownership passes to done only at the final return,
		// once the response is complete.
		defer func() {
			if !handedOff {
				unlock()
			}
		}()
		done = func(sent bool) {
			defer unlock()
			if sent {
				u.onSessionRefreshReceived(d)
			}
		}
		treq := readInboundSessionTimer(req)
		hadSE := treq.Requested.IntervalS != 0
		u.calls.mu.Lock()
		// st.minSE already includes this request's Min-SE (recordPeerMinSELocked at
		// the dialog match).
		cur, dialogMinSE := st.IntervalS, st.minSE
		u.calls.mu.Unlock()
		if !hadSE {
			// LB-D6: no Session-Expires keeps the current interval.
			treq.Requested.IntervalS = cur
			treq.MinSE = max(treq.MinSE, cur)
		} else {
			// LB-D6: never below the dialog's Min-SE unless the request asks for less.
			treq.MinSE = max(treq.MinSE, min(dialogMinSE, treq.Requested.IntervalS))
		}
		intervalS, refuse := u.negotiatedInterval(treq)
		switch {
		case refuse == 400:
			r := sip.NewResponseFromRequest(req, 400, "Bad Request", nil)
			handedOff = true
			return r, done
		case refuse == 422 && hadSE && (treq.Supported || treq.Required):
			r := sip.NewResponseFromRequest(req, 422, "Session Interval Too Small", nil)
			r.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(u.minSES())))
			handedOff = true
			return r, done
		}
		role := inboundRefresherRole(treq) // Table 2; we are this transaction's UAS
		commit := func() {
			u.calls.mu.Lock()
			st.IntervalS = intervalS
			st.weRefresh = weRefreshFrom(role, false)
			st.Refresher = refresherRole(st.weRefresh, d.direction == session.Outbound)
			st.armGen++ // I9: a refresher armed before this write commits nothing after it
			u.calls.mu.Unlock()
		}
		done = func(sent bool) {
			defer unlock()
			if sent {
				commit()
				u.onSessionRefreshReceived(d)
			}
		}
		res.AppendHeader(sip.NewHeader("Session-Expires",
			formatSessionExpires(sessionExpires{IntervalS: intervalS, Refresher: role})))
		if requireTimerInAnswer(treq, role) {
			res.AppendHeader(sip.NewHeader("Require", "timer"))
		}
	}
	res.AppendHeader(sip.NewHeader("Allow", ourAllow()))
	handedOff = true
	return nil, done
}

// recordPeerMinSELocked remembers a matched refresh request's Min-SE as the
// dialog's (RFC 4028 7.4: the largest "received in session refresh requests",
// rfc4028.txt:600-603), whatever we answer. Values outside [90, maxHonouredMinSES]
// are not recorded (LB-D14). The caller holds u.calls.mu.
func recordPeerMinSELocked(st *sessionTimerState, req *sip.Request) {
	if st == nil {
		return
	}
	if m := parseMinSE(req); m >= 90 && m <= maxHonouredMinSES {
		st.minSE = max(st.minSE, m)
	}
}

// SessionTimerView implements session.UserAgent.SessionTimerView (§4). ok is
// false when RFC 4028 was NOT negotiated on the dialog — reporting a zeroed
// struct there would assert a timer that does not exist.
func (u *UA) SessionTimerView(dialogID string) (session.SessionTimerView, bool) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return session.SessionTimerView{}, false
	}
	// Correction 9: every field this function reads off sessionTimerState is
	// snapshotted INSIDE the one critical section — Tasks 29/30 will WRITE
	// refresher/watchdog under this same lock, so dereferencing them after
	// release is a designed-in data race -race will catch the moment either
	// task lands. NextAt() itself has its own lock and stays outside.
	u.calls.mu.Lock()
	st := d.sessionTimer
	var intervalS int
	var role string
	var rf, wd *refresher
	if st != nil {
		intervalS, role, rf, wd = st.IntervalS, st.Refresher, st.refresher, st.watchdog
	}
	u.calls.mu.Unlock()
	if st == nil {
		return session.SessionTimerView{}, false
	}
	// C9/A-M6: Armed is rf/wd non-nil, snapshotted in the SAME critical section
	// above — it needs no refresher.go internals, since "is a timer armed" is
	// already answered by which of the two fields (if either) this dialog
	// holds, independent of what NextAt() reads.
	out := session.SessionTimerView{IntervalS: intervalS, Refresher: role, Armed: rf != nil || wd != nil}
	// next_refresh_ms counts down to OUR next refresh when we refresh, or to the
	// watchdog deadline when the peer does. Exactly one of the two is armed.
	var at time.Time
	switch {
	case rf != nil:
		at = rf.NextAt()
	case wd != nil:
		at = wd.NextAt()
	}
	if !at.IsZero() {
		if ms := at.Sub(u.now()).Milliseconds(); ms > 0 {
			out.NextRefreshMs = ms
		}
	}
	return out, true
}

// sessionRefreshFraction is RFC 4028 §10: the refresher sends its refresh at
// HALF the session interval, so a lost refresh still leaves a full half-interval
// for a retry before the far end's own timer expires.
const sessionRefreshFraction = 0.5

// refreshMethodFor decides UPDATE-vs-re-INVITE (decision 11). The per-profile
// session_refresh_method forces one; "auto" reads the peer's cached Allow.
//
// UPDATE IS PREFERRED WHEN AVAILABLE because it carries no SDP and creates no
// offer/answer exchange: a re-INVITE refresh replays the established SDP through
// the full negotiation path twice per interval, and any peer that answers it
// with a different codec would trip §11.2.1's media_negotiation_failed on a call
// that was working perfectly.
func (u *UA) refreshMethodFor(st *sessionTimerState) sip.RequestMethod {
	switch u.refreshMethodPref() {
	case "update":
		return sip.UPDATE
	case "invite":
		return sip.INVITE
	}
	if peerAllowsUPDATE(st.peerAllow) {
		return sip.UPDATE
	}
	return sip.INVITE
}

// startSessionRefresher arms our own refresh timer for a dialog where WE are the
// refresher. It is a no-op for any other case, so both callers (runDial's
// outbound path and Answer's inbound one) can call it unconditionally. See
// armSessionTimer for the arm itself, including why it arms nothing on a dialog
// that is no longer established.
func (u *UA) startSessionRefresher(d *dialog, st *sessionTimerState) {
	if st == nil {
		return
	}
	// Correction 10: weRefresh is read under the SAME lock its writers use.
	u.calls.mu.Lock()
	weRefresh := st.weRefresh
	u.calls.mu.Unlock()
	if weRefresh {
		u.armSessionTimer(d, st)
	}
}

// refreshSession sends one refresh and returns the interval the peer's response
// re-bases us to (0 = unchanged), which is exactly what the shared refresher's
// Do contract asks for — the same mechanism re-register uses to follow the
// registrar's granted expiry.
//
// It runs in the REFRESH TRANSACTION'S orientation, where we are always the UAC:
// the refresher parameter we send is refresherRole(weRefresh, true) and the one
// on the 2xx is read with weRefreshFrom(role, true), so a 2xx naming the peer
// hands refreshing over (writes weRefresh/IntervalS/Refresher, re-arms the
// watchdog and ends this refresher quietly). gen is the generation this refresher
// was armed under: once armGen has moved on, it commits nothing (I9).
func (u *UA) refreshSession(ctx context.Context, d *dialog, st *sessionTimerState, gen uint64) (int, error) {
	// A refresh is only meaningful on a settled, answered dialog. This guard is
	// also what makes the in-dialog-timeout path below single-shot: once that
	// path has claimed and torn down the dialog, a retry that has not yet
	// observed the Stop finds a non-answered dialog and returns without putting
	// a second doomed request on the wire.
	//
	// Correction 10: method/minSE and the three sessionTimerState fields the
	// rest of this function reads are ALL snapshotted in this ONE critical
	// section, even though nothing races them today — refreshSession WRITES
	// st.IntervalS/st.Refresher later under the same lock, and Task 30's
	// watchdog will touch st from a second goroutine, at which point reading
	// them unlocked becomes a genuine race.
	u.calls.mu.Lock()
	phase := d.phase
	method := sip.RequestMethod("")
	if dialogEstablished(phase) {
		method = u.refreshMethodFor(st)
	}
	intervalS, weRefresh, dialogMinSE := st.IntervalS, st.weRefresh, st.minSE
	peerInviteBusy := d.peerOfferPending || (d.peerReinvite != nil && (!d.peerReinvite.acked || d.peerReinvite.answerPending))
	u.calls.mu.Unlock()
	if !dialogEstablished(phase) {
		return 0, apierr.PreconditionFailed("dialog is no longer answered; nothing to refresh")
	}
	if !weRefresh {
		// J1: the role was handed to the peer (a peer refresh we answered) between
		// the timer firing and this snapshot; the re-arm that follows that write
		// stops this refresher. Nothing goes on the wire.
		return 0, fmt.Errorf("%w: the peer refreshes this dialog", errRefresherStopped)
	}
	// B-D14 (RFC 3261 14.1): a re-INVITE of ours waits while the peer's INVITE
	// exchange is not confirmed (an offer still being answered, or a 2xx we sent
	// to its re-INVITE not yet ACKed). Retryable: the refresher's own retry covers
	// the race.
	if method == sip.INVITE && peerInviteBusy {
		return 0, fmt.Errorf("a re-INVITE exchange of the peer's is not confirmed yet (RFC 3261 14.1); retrying")
	}
	// RFC 4028 7.4: our refresh's Min-SE is the largest seen on the dialog, and its
	// Session-Expires SHOULD be at least that (rfc4028.txt:600-603, 625-627).
	minSEOut := max(u.minSES(), dialogMinSE)
	sentSE := max(intervalS, minSEOut)

	req, res, err := u.sendInDialog(ctx, d, method, func(req *sip.Request) {
		u.addSessionTimerHeaders(req,
			sessionExpires{IntervalS: sentSE, Refresher: refresherRole(weRefresh, true)}, minSEOut)
		req.RemoveHeader("Allow")
		req.AppendHeader(sip.NewHeader("Allow", ourAllow()))
		// UPDATE and re-INVITE are TARGET-REFRESH requests (RFC 3261 §12.2.2 / RFC
		// 3311 §5): the Contact they carry REPLACES the peer's remote target for
		// this dialog, so it MUST be OURS. Nothing is done here — buildInDialogRequest
		// derives the Contact from u.localContact() for an inbound dialog OR a
		// target-refresh method, so it covers both of this call site's methods
		// (UPDATE and the re-INVITE refresh) in BOTH directions (dtmf.go). It is
		// deliberately NOT applied to an outbound BYE or INFO, which inherit the
		// dialog INVITE's own Contact so the contact a dialog advertises does not
		// move mid-dialog. This call site used to patch it locally, which is
		// exactly why INFO and BYE still shipped the peer's own Contact on inbound
		// dialogs until the fix moved into the builder (Rule 18).
		if method == sip.INVITE {
			// A re-INVITE refresh replays the ESTABLISHED SDP unchanged (spec §5):
			// this is a keep-alive, not a renegotiation. ourReInviteSDPLocked is the
			// canonical, DIRECTION-AWARE source (call.go) that onInvite's re-INVITE
			// guard already uses: inbound takes d.ok (OUR answer), outbound takes
			// d.invite (OUR offer). Reading d.invite unconditionally re-offers the
			// PEER's own media address on a dialog we answered (Correction 6).
			u.calls.mu.Lock()
			body, ctHdr := ourReInviteSDPLocked(d)
			d.reinviteInFlight = true // CF-124/166: our offer is outstanding until sendInDialog returns
			u.calls.mu.Unlock()
			if body != nil {
				req.SetBody(body)
				req.RemoveHeader("Content-Type")
				if ctHdr != nil {
					req.AppendHeader(ctHdr)
				} else {
					req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
				}
			}
		}
	})
	if method == sip.INVITE {
		u.calls.mu.Lock()
		d.reinviteInFlight = false
		u.calls.mu.Unlock()
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The UA's OWN lifetime ended (Close, or the daemon ctx cancelled),
			// or Correction 5's cancel fired ahead of stopSessionTimer's Stop.
			// stopAllMediaLoops/stopSessionTimer own that teardown; this is not
			// a peer failure and must not be reported as one.
			//
			// THIS CHECK MUST STAY FIRST. It is also what makes
			// refreshDrewNoResponse's context.DeadlineExceeded test unambiguous:
			// past this line the parent ctx is live, so the only deadline that can
			// have fired is RawTransaction's own per-request one.
			//
			// C2: WRAPPED IN errRefresherStopped, not returned bare — the same
			// %w: %v convention attempt's own two interruption arms use (sentinel
			// as identity, cause as text; refresher.go:302). An unwrapped ctxErr
			// reaching attempt()'s FINAL retry attempt is indistinguishable from a
			// genuine failure, so refresher.go's quietStop misclassifies a UA/
			// dialog teardown as an exhausted retry budget and logs a misleading
			// "refresh gave up" WARN instead of recognising the intentional stop.
			return 0, fmt.Errorf("%w: %v", errRefresherStopped, ctxErr)
		}
		if req == nil {
			// Never built: buildInDialogRequest's own refusal, returned
			// exactly as before the seam (plan D12). Nothing was sent, so it is
			// neither a send failure nor an in-dialog timeout.
			return 0, err
		}
		if !refreshDrewNoResponse(err) {
			// THE SEND ITSELF FAILED, and that is NOT §11.3.1 case 2. The
			// transaction layer refused or abandoned the request without ever
			// running its Timer B/F budget — an immediate write error, an
			// unresolvable target, an ICMP-driven early termination — so no 32 s
			// elapsed and NOTHING was learned about the peer. Reporting
			// in_dialog_timeout here would put a claim in the ladder and the event
			// log that never happened.
			//
			// It is handled exactly as a REJECTED refresh is (same emitter, one
			// non-terminal event) and the error is RETURNED, so the refresher's own
			// retry/backoff gets its two attempts: an immediate send failure can be
			// transient in a way a full Timer F silence cannot. If the retries fail
			// too the refresher gives up and stops, and the peer's own session timer
			// owns the endgame — the same endgame the rejected-refresh branch below
			// already relies on. code is 0 because there IS no response code; the
			// error text is what an operator needs, and it is what `message` carries.
			u.emitSessionRefreshFailed(d, string(method), err.Error(), 0) //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as retry422 above: a session-refresh-failed event must keep reaching session even though the refresher's own retry/backoff (and this ctx) run independently of any single send attempt's lifetime.
			return 0, fmt.Errorf("session refresh (%s) could not be sent: %w", method, err)
		}
		// NO FINAL RESPONSE AT ALL — §11.3.1 case 2. This is categorically
		// different from both the send-failure branch above and the
		// rejected-response branch below: the transaction exhausted its FULL budget
		// (u.cfg.Timeout, defaulted to Timer B/F's 32s at ua.go:260) without the
		// peer answering once, so the peer is unreachable INSIDE THE DIALOG and the
		// dialog is dead. Leaving it `answered` — which is what a non-terminal error
		// event does — is the R9 failure the design spec §5 names explicitly.
		// sendInDialog has already ended the dialog (CF-109/110: it owns the
		// 481/408/no-response teardown for every in-dialog request), so this
		// branch only reports the refresh's own failure to the refresher.
		return 0, fmt.Errorf("session refresh (%s) drew no response: %w", method, err)
	}
	// A 2xx to a re-INVITE is ACKed, and re-ACKed on every retransmission, by
	// sendInDialog (CF-169).
	if !res.IsSuccess() {
		// A-M5: a 422 (Session Interval Too Small) re-bases st.IntervalS off the
		// peer's Min-SE, through the SAME retryIntervalFor422 helper retry422
		// already uses for the initial dial (Rule 16) — BEFORE returning, so the
		// refresher's own retry (Attempts: 2) reads the raised interval on its
		// next Do call rather than repeating the identical interval the peer
		// just told us was too low. retryIntervalFor422 already refuses a
		// Min-SE outside our bounds (returns 0), leaving IntervalS unchanged.
		//
		// CF-121: the 422's Min-SE is also remembered as the dialog's Min-SE (the
		// largest seen, RFC 4028 7.4), whether or not it re-bases the interval: our
		// retry carries it. A monotone max cannot be stale, so the merge is not
		// fenced; the interval re-base is (I9). A value above maxHonouredMinSES
		// is not recorded (LB-D14).
		if res.StatusCode == 422 {
			peerMinSE := parseMinSE(res)
			rebased := u.retryIntervalFor422(peerMinSE)
			u.calls.mu.Lock()
			if peerMinSE >= 90 && peerMinSE <= maxHonouredMinSES {
				st.minSE = max(st.minSE, peerMinSE)
			}
			stale := st.armGen != gen
			if !stale && rebased != 0 {
				st.IntervalS = rebased
			}
			u.calls.mu.Unlock()
			if stale { // I9: replaced or stopped, commit nothing more
				return 0, errRefresherSuperseded
			}
		}
		u.emitSessionRefreshFailed(d, string(method), res.Reason, int(res.StatusCode)) //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as the send-failure branch above: a rejected refresh's failure event must keep reaching session regardless of this refresh transaction's own ctx.
		return 0, fmt.Errorf("session refresh (%s) was rejected: %d %s",
			method, res.StatusCode, res.Reason)
	}

	// Re-base on the peer's Session-Expires if it named one.
	//
	// NO SEPARATELY-NUMBERED DECISION COVERS RE-BASING. It is a mechanism-level
	// consequence of decision 8 (the shared refresher primitive, spec §2.4): `Do`
	// returning the granted interval is precisely what lets a refresh RESPONSE
	// change the interval we run on, through the same single primitive re-register
	// uses for the registrar's grant. Decision 16 governs only the SHAPE of the
	// event emitted below — and its interval_s field is why the re-based value has
	// to be written back to st before we emit, since what we report must be the
	// interval we are now actually running.
	granted := 0
	handover := false
	for _, v := range headerValues(res, "Session-Expires") {
		se, ok := parseSessionExpires(v)
		if !ok {
			continue
		}
		// The SAME Min-SE floor the initial answer applies (Correction 11), for
		// the same reason one message later on the same dialog: parseSessionExpires
		// rejects only <= 0, so without this a peer answering our refresh with
		// `Session-Expires: 1` re-bases us to a 500 ms refresh cadence permanently.
		// An undersized grant is IGNORED — we keep refreshing on the interval that
		// was actually negotiated, which is still a valid session timer, rather
		// than tearing the dialog down over one bad header.
		//
		// AN OVER-LONG GRANT IS CLAMPED, and this comment used to say the opposite:
		// "no upper bound is applied: an over-long grant makes us refresh less
		// often". That reasoning is VOID UNDER OVERFLOW (F1). Past 9223372036 the
		// multiply into time.Duration wraps NEGATIVE, so an over-long grant makes us
		// refresh CONTINUOUSLY, not less often, and the peer's own timer bounds
		// nothing because we never stop long enough for it to matter.
		if u.belowMinSE(se.IntervalS, "keeping the negotiated interval") {
			break
		}
		// CF-115 (and CF-125): a refresher value on the 2xx is read in THIS
		// transaction, where we are the UAC (RFC 4028 7.2: "The UAC MUST set the
		// identity of the refresher to the value of this parameter",
		// rfc4028.txt:521-523). One that names the peer hands refreshing over; one
		// that names us, or none, keeps us refreshing.
		handover = se.Refresher != "" && !weRefreshFrom(se.Refresher, true)
		if handover {
			// The interval is what we asked for, reduced by the peer at most (the
			// UAS MUST NOT increase it, rfc4028.txt:850-851), not the 7200-clamped
			// grant: the watchdog must run on the agreed interval (LB-D5).
			granted = min(se.IntervalS, sentSE)
		} else {
			granted = u.clampSessionInterval(se.IntervalS, "refresh grant")
		}
		u.calls.mu.Lock()
		if st.armGen != gen { // I9: replaced or stopped, commit nothing
			u.calls.mu.Unlock()
			return 0, errRefresherSuperseded
		}
		if handover {
			st.weRefresh = false
			st.Refresher = refresherRole(false, d.direction == session.Outbound)
		}
		st.IntervalS = granted
		u.calls.mu.Unlock()
		break
	}
	u.calls.mu.Lock()
	interval, role := st.IntervalS, st.Refresher
	u.calls.mu.Unlock()
	u.emit(session.UAEvent{ //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as retry422 above: a successful session-refresh event must keep reaching session on the long-lived evCtx, not this refresh transaction's own ctx, which this function's caller (the refresher's Do) may already be past by the time delivery happens.
		Kind: session.UAEventSessionRefresh, DialogID: d.id, CallID: d.callID,
		Direction: d.direction, At: u.now(),
		// Decision 16: flat scalars, the same convention plan_step uses.
		Detail: map[string]any{
			"method": string(method), "refresher": role,
			"interval_s": interval, "code": int(res.StatusCode),
		},
	})
	if handover {
		// The peer is the refresher now: swap our refresher for the watchdog. The
		// arm Stops this very goroutine's refresher, so it must run elsewhere (I6),
		// and the quiet-stop error ends this refresher without a retry (J2).
		runOffRefresherGoroutine(func() { u.armSessionTimer(d, st) }) //nolint:contextcheck // the re-arm runs on u.uaCtx by design, as startSessionRefresher does.
		return 0, fmt.Errorf("%w: refresher role handed to the peer", errRefresherStopped)
	}
	return granted, nil
}

// emitSessionRefreshFailed appends §4's error event for a refresh that failed.
//
// It reuses UAEventMediaError DELIBERATELY: that kind is the generic
// non-terminal, per-dialog error channel (see its doc comment in
// internal/session/collaborators.go), discriminated by detail.kind, and this is a
// non-terminal per-dialog condition. A new UAEventKind for one detail shape would
// grow the enum and handleUAEvent's switch for no behavioural difference.
//
// EVERY KEY IS ALWAYS PRESENT, INCLUDING code. `code` is 0 when NO RESPONSE WAS
// EVER RECEIVED — the send failed outright — and a real SIP status when the peer
// rejected us. Omitting it on the zero value would force an agent to distinguish
// those two cases by testing for KEY ABSENCE, which is a far weaker contract than
// a documented sentinel for a §10.5 detail shape the spec pins down. 0 is not a
// valid SIP status code, so it cannot collide with a real one.
func (u *UA) emitSessionRefreshFailed(d *dialog, method, message string, code int) {
	u.emit(session.UAEvent{
		Kind: session.UAEventMediaError, DialogID: d.id, CallID: d.callID,
		Direction: d.direction, At: u.now(),
		Detail: map[string]any{
			"kind": "session_refresh_failed", "method": method, "message": message,
			// ALWAYS present; 0 means "no response was ever received".
			"code": code,
		},
	})
}

// runOffRefresherGoroutine runs fn on a NEW goroutine. EVERY dialog-ending
// teardown reached FROM a refresher callback MUST go through it — this task's
// in-dialog-timeout path and Task 30's watchdog expiry are both callers.
//
// IT PREVENTS A SELF-JOIN DEADLOCK; it is not a style choice. A refresher's Do
// and OnGiveUp run ON the refresher's own goroutine (refresher.go's Start), and
// every teardown path ends in stopSessionTimer -> refresher.Stop(), which BLOCKS
// on `<-r.done` — a channel closed only when that same goroutine exits. Called
// inline, the goroutine would be waiting for itself: the teardown would park
// before its BYE ever reached the wire, leaving the call half-torn-down locally
// with no terminal event and no Reason header — the exact opposite of what the
// timer exists to do, and invisible except as a hung dialog.
//
// Returning from the callback promptly is what breaks the cycle: the refresher
// goroutine then exits and closes `done`, which is precisely what unblocks the
// Stop() this new goroutine goes on to call. So the wait is short and bounded,
// not merely deferred.
//
// THE refresher PRIMITIVE'S SEMANTICS ARE UNCHANGED. Stop still means "halt and
// wait for the goroutine" for every EXTERNAL caller, which is exactly what Task
// 25's registration refresher and Task 26's keepalive depend on to guarantee no
// timer fires onto a closing transport. Neither of them ends a dialog from a
// callback, so neither is affected by this rule. Do NOT "simplify" this by making
// Stop() non-blocking or by having it SKIP its wait when the caller is the
// refresher's own goroutine — that would let an external Stop() return while a
// REGISTER was still in flight.
//
// Stop DOES detect the reentrant case, and PANICS on it (Task 23's guard). That is
// a different thing from changing control flow: the guard exists only so a future
// regression fails immediately and locally instead of hanging, which is how this
// exact bug survived a review pass once already. If you see that panic, the fix is
// to route the teardown through THIS helper — not to relax the guard.
func runOffRefresherGoroutine(fn func()) { go fn() }

// refreshDrewNoResponse reports whether err from RawTransaction means the
// transaction ran its FULL budget without the peer sending one final response —
// §11.3.1 case 2 — as opposed to the send having failed outright.
//
// doTx's tctx.Done() branch returns tctx.Err() BARE, so context.DeadlineExceeded
// survives unwrapped (verified). Its tx.Done() branch flattens tx.Err() with %v,
// which destroys the wrap — errors.Is/errors.Unwrap find nothing on that string —
// so the ONLY way to recognise it is the substring match below.
//
// Config.Timeout defaults to exactly 32s (ua.go), the same duration as sipgo's
// own Timer_B/F (third_party/sipgo/sip/transaction.go), and doTx arms both
// within about a microsecond of each other — a genuine tie, not a "Timeout >
// 32s" edge case: measured 7/24 trials at 32s took the tx.Done() branch (0/24
// at 30s, where the caller-side deadline has real headroom to win outright).
// Fix round 1, Item 7: an EARLIER version of this comment claimed the tx.Done()
// branch "can only win when Config.Timeout > 32s", concluding the production
// default was safe from it. That was refuted by measurement — equal deadlines
// race, and Go's select breaks the tie arbitrarily — so both branches below are
// required, not just the DeadlineExceeded one.
//
// A Timer_B/F expiry IS §11.3.1 case 2 either way: both branches mean "the
// full transaction budget elapsed with no final response", so classifying them
// identically makes the outcome of the tx.Done()-vs-tctx.Done() race
// irrelevant. sip.ErrTransactionTimeout.Error() is "transaction timeout",
// distinct from ErrTransactionTransport ("transaction transport error") and
// ErrTransactionCanceled ("transaction canceled") — ordinary send/cancel
// failures do not collide with this substring match.
//
// It remains a WHITELIST: an error matching neither check is treated as a send
// failure, so nothing unrecognised asserts "we waited 32 s and heard nothing".
// context.DeadlineExceeded is unambiguous here ONLY because refreshSession
// returns on a non-nil ctx.Err() first — do not reorder them.
func refreshDrewNoResponse(err error) bool {
	if strings.Contains(err.Error(), sip.ErrTransactionTimeout.Error()) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// endDialogInDialogTimeout ends the dialog when an in-dialog request WE sent
// proves the dialog is gone (RFC 3261 12.2.1.2): it drew a 481 or 408, or no
// final response before the transaction budget (Timer B/F) expired. detailCause
// is the event's detail.cause ("in_dialog_481", "in_dialog_408" or
// "in_dialog_timeout"). Its ONE caller is sendInDialog (CF-109/CF-110), which
// covers every in-dialog method except BYE.
//
// IT SENDS NO BYE, deliberately. §11.3.1: "in case 2 the BYE has already been
// sent and gone unanswered; it is not retried beyond Timer F" — a peer that
// answered nothing for a full Timer F will not answer a BYE either, and one that
// answered 481 has told us it has no dialog, so the dialog is released locally
// and the ladder shows no outbound BYE. That is also why this does NOT go through
// hangupWithReason: there is nothing to send.
//
// THE TERMINAL EVENT IS DIALOG-SCOPED. UAEventDialogEnded with Cause
// UACauseTransportFailure reaches session's handleDialogEnded, which resolves
// THIS dialog's call and terminates only it. UAEventTransportFault would have
// reached handleTransportFault instead, which terminates EVERY live call on the
// UA — turning one dead dialog into a UA-wide outage.
//
// The dialog is CLAIMED synchronously, before this returns, so a call_hangup
// issued right after the failed request finds no dialog (deterministic, not a
// race with a goroutine). The rest runs off the caller's goroutine (see
// runOffRefresherGoroutine), because stopSessionTimer below Stops the very
// refresher whose Do may have called it.
func (u *UA) endDialogInDialogTimeout(d *dialog, method string, cause error, detailCause string) {
	// Claim the dialog in ONE critical section, exactly as onBye and
	// hangupWithReason do: a concurrent call_hangup or peer BYE that already
	// claimed it owns the terminal event, and we emit nothing rather than
	// giving the call a second, contradictory termination_reason (§6.3).
	u.calls.mu.Lock()
	if !dialogEstablished(d.phase) {
		u.calls.mu.Unlock()
		return
	}
	d.phase = phaseDone
	endControlOpLocked(d)
	u.forgetLocked(d.id)
	ml, conn := d.mediaLoop, d.mediaConn
	d.mediaLoop, d.mediaConn = nil, nil
	u.calls.mu.Unlock()
	runOffRefresherGoroutine(func() {
		// stop() closes the conn, and MUST NOT run under u.calls.mu.
		if ml != nil {
			ml.stop()
		} else if conn != nil {
			_ = conn.Close()
		}
		u.stopSessionTimer(d)

		// Correction 3: u.cfg.Logger is nil-able (see Config's own doc comment);
		// u.log() (keepalive.go) is this package's nil-safe accessor and is used
		// at every log site this task adds.
		u.log().Warn("in-dialog request showed the dialog is gone; releasing it ("+detailCause+")",
			"dialog_id", d.id, "call_id", d.callID, "method", method, "err", cause)
		u.emit(session.UAEvent{
			Kind: session.UAEventDialogEnded, Cause: session.UACauseTransportFailure,
			DialogID: d.id, CallID: d.callID, Direction: d.direction,
			Err: cause, At: u.now(),
			// §11.3.1's detail object. `transport` and `cause` are the two keys the
			// spec names; `method` says which in-dialog request ended the dialog,
			// which is the only thing an operator needs that the other two do not
			// carry.
			Detail: map[string]any{
				"kind": "transport_failure", "transport": u.Transport(),
				"cause": detailCause, "method": method,
			},
		})
	})
}

// stopSessionTimer halts whichever timer this dialog armed. It is idempotent and
// safe to call from every teardown path.
//
// IT MUST NOT BE CALLED INLINE FROM A REFRESHER CALLBACK: r.Stop() below waits
// for the refresher's goroutine, which inside Do IS the caller. Every such path
// goes through runOffRefresherGoroutine. It takes st.armMu, so it also waits for
// an arm in flight and stops what that arm stored (I8).
//
// Correction 5: cancel is invoked BEFORE Stop() on either timer, so a Do
// currently blocked in RawTransaction against a silent peer is aborted rather
// than waited out for the full Config.Timeout. Stop's own blocking contract is
// unchanged — this only shortens what it is waiting for.
func (u *UA) stopSessionTimer(d *dialog) {
	u.calls.mu.Lock()
	st := d.sessionTimer
	u.calls.mu.Unlock()
	if st == nil {
		return
	}
	// armMu: wait for an arm in flight, then take and stop whatever it stored (I8).
	st.armMu.Lock()
	defer st.armMu.Unlock()
	u.calls.mu.Lock()
	r, w, cancel := st.refresher, st.watchdog, st.cancel
	st.refresher, st.watchdog, st.cancel = nil, nil, nil
	st.armGen++ // fences the commits of the refresher taken here (I9)
	if r != nil {
		st.armedTimers--
	}
	if w != nil {
		st.armedTimers--
	}
	u.calls.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if r != nil {
		r.Stop()
	}
	if w != nil {
		w.Stop()
	}
}
