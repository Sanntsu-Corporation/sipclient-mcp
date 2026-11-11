package sipua

// Rule 16 reuse decision for this file:
//
//   NO LONGER REUSED, AS OF PHASE 4 W1 M3 (Inputs §1): siptest.(*Client).
//     DoRequestWithDigest hardcodes the digest nc (nonce-count) parameter to
//     the literal 1 on every 401/407 challenge it answers (uac.go:189) —
//     spec-legal only for a single-shot exchange, and a defect once the same
//     registration is refreshed against a registrar that tracks nonce-count
//     (RFC 7616 §3.4.3): a refresh's nc=1 looks like a replay of the initial
//     REGISTER's nc=1. G4 forbids editing uac.go, so this file's own
//     (*UA).doRequestWithDigest (digestauth.go) reimplements the same
//     challenge -> recompute -> in-place header replace -> EXPLICIT CSeq bump
//     -> Via strip -> retry sequence with a real, tracked nc in place of the
//     hardcoded 1. See digestauth.go's own header for what IS still reused
//     from the vendored tree (RawTransaction, digest.ParseChallenge/
//     ComputeAuthorization, sipgo.ClientRequestAddVia).
//   REUSED from internal/sipengine:
//     siptest.BuildRegister — consumed with the O1 transport parameter Task
//       13 already added; the transport comes from UA.Transport(), never a
//       literal.
//     digest.ParseChallenge / digest.ComputeAuthorization — reused
//       transitively through DoRequestWithDigest.
//     sip.ParseUri (github.com/emiago/sipgo/sip) — reused directly to guard
//       against a bad registrar URI before it ever reaches the vendored
//       mustParseURI, which PANICS instead of erroring (D123). tryParseURI in
//       internal/sipengine/siptest/builders.go wraps the exact same call but
//       is unexported and cannot be called from this package; this file does
//       not re-implement URI grammar, only the same scheme-prefix normalising
//       tryParseURI itself does before delegating to sip.ParseUri.
//
//   NOT REUSED: siptest.RunUAC. §7.1 grades it "reference only" — blocking,
//     single-call, no handles, and it owns its own listener lifecycle, which
//     conflicts with Task 13's caller-supplied ServeUDP seam.
//
// P1 scope: ONE REGISTER with Expires: 300 and no refresh. P3 wires the
// refresh: setExpires puts Config.ExpiresS on the wire, responseExpires reads
// the registrar's grant, and refreshRegister runs on the shared refresher
// primitive (refresher.go).

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// There is NO sipua.RegisterResult. The DTO is session.RegisterResult
// (§6.2.1: the collaborator types are declared consumer-side in `session`),
// and a sipua-local duplicate would make (*UA).Register fail to satisfy
// session.UserAgent — which internal/sipua/assert_test.go catches at compile
// time.

// regState holds the UA's registration state under its own mutex, separate
// from any transport-level lock, so Registered/RegisterCode never block on a
// network write.
type regState struct {
	mu         sync.Mutex
	registered bool
	code       int
	expiresS   int
	contact    string

	// dest is the destination ("ip:port") the last ANSWERED REGISTER was sent
	// to, as the fork resolved it (SRV first, RFC 3263 4.2): the NAT keepalive
	// goes there so it refreshes the very flow REGISTER opened (CF-188, D6C-3).
	// Written only by sendRegister, read only by the keepalive; guarded by mu.
	dest string

	// callID and cseq pin ONE stable registration identity across the initial
	// REGISTER and every refresh — RFC 3261 §10.2 requires a registration's
	// REGISTERs to share a single Call-ID with a strictly increasing CSeq, but
	// siptest.BuildRegister (vendored, G4) mints a fresh random Call-ID and
	// hardcodes CSeq:1 on every call, making each refresh look like a brand-new
	// registration on the wire. Fixed the same way setExpires fixes the Expires
	// header: a post-build override, never a vendored-file edit.
	callID string
	cseq   uint32

	// minExpiresS is the Min-Expires floor a registrar has demanded of THIS
	// registration with a 423 Interval Too Brief (RFC 3261 §10.2.8), 0 until one
	// has. It clamps every later REGISTER on this UA — see requestedExpires.
	// Without the clamp the retry would register successfully and then the very
	// next refresh would send the too-short value again and be 423ed again,
	// forever.
	minExpiresS int

	// challenge is the digest challenge this UA most recently authenticated a
	// REGISTER against AND HAD ACCEPTED, cached so the NEXT REGISTER can present
	// a credential PREEMPTIVELY (RFC 3261 §22.1) instead of spending a whole
	// round trip drawing a fresh 401/407 — P4-D07. Its zero value (empty
	// HeaderName) means "nothing cached yet", which is the state of every
	// first-ever registration.
	//
	// "ACCEPTED", NOT "LAST ANSWERED", AND THE WORD IS THE INVARIANT (Rule 4
	// Cycle B, finding 2). Only sendRegister writes this field, and only when the
	// exchange it dispatched ended 200. A challenge answered by an exchange that
	// was then re-challenged, or whose dispatch failed, is NOT this UA's current
	// registrar identity and must never be presented preemptively — doing so
	// re-sends a credential the far end has already refused, costing the 401 round
	// trip this feature exists to remove PLUS a burnt nonce-count, every cycle.
	//
	// IT IS REGISTER-SPECIFIC AND LIVES HERE FOR THAT REASON, not by accident of
	// placement. digestauth.go's header comment forbids REGISTER knowledge in
	// that file, and presenting a cached challenge preemptively is only sound for
	// a leg that talks to ONE long-lived identity: true of the registrar, false
	// of call traffic, which dials a different destination on every Dial. The
	// INVITE leg deliberately keeps drawing its own challenge.
	challenge answeredChallenge

	// dispatchMu serializes REGISTER DISPATCH: one exchange, plus the cache write
	// that follows it, at a time per UA. IT IS DELIBERATELY NOT mu — mu guards
	// field reads/writes only, and this struct's own doc comment forbids holding
	// it across a network write, which dispatchMu does by design.
	//
	// WHAT THE INVESTIGATION FOUND (Rule 4 Cycle B, finding 3), recorded in full
	// so a future reviewer does not re-derive it or "simplify" this away. Four
	// paths dispatch a REGISTER — Register, retryIntervalTooBrief, Unregister and
	// refreshRegister — and THREE of the pairings are already serialized by
	// construction, with no lock:
	//
	//   - refresh vs refresh: refreshRegister runs ONLY as the register
	//     refresher's Do (startRegisterRefresher's policy), and refresher.attempt
	//     calls Do sequentially on ONE goroutine (refresher.go). Arming a
	//     replacement goes through startRegisterRefresher, which calls
	//     stopRefresher(prev, prevCancel) — a BLOCKING join — before r.Start.
	//   - Unregister vs refresh: Unregister's FIRST act is stopRegisterRefresher,
	//     and stopRefresher's cancel-then-Stop blocks until the in-flight Do has
	//     returned (refresher.Stop waits on the goroutine's done channel, and its
	//     doc comment calls that wait the whole point). No refresh REGISTER can
	//     still be in flight once Unregister reaches its own dispatch.
	//   - Register vs anything: Register has ONE production call site (session's
	//     handleUACreate, internal/session/toolservice.go), on a UA created moments
	//     earlier, so no refresher exists yet — startRegisterRefresher is the LAST
	//     thing Register does, after its own exchange has returned. A concurrent
	//     Unregister is a no-op besides: its opening guard reads reg.registered,
	//     which Register does not set until its exchange has completed.
	//
	// THE ONE RESIDUAL PATH, WHICH IS WHY THIS LOCK EXISTS RATHER THAN A COMMENT
	// SAYING NONE IS NEEDED: two Unregisters. session's destroyUA claims the UA
	// under the registry lock (MarkDestroyed) but leaves it in s.liveUAs until
	// RecordUADestroyed runs at the END of a teardown bounded only by the grace
	// period, while gracefulShutdown step 6's UnregisterAllUAs snapshots exactly
	// that map — and step 1 stops ACCEPTING connections without draining in-flight
	// tool calls. A ua_destroy still running when shutdown reaches step 6 puts two
	// REGISTER Expires: 0 exchanges on the wire for one UA at once. That is
	// pre-existing and unrelated to P4-D07, but it is REAL, and an unserialized
	// cache write lets the later-COMPLETING exchange publish the older challenge
	// over the newer one.
	//
	// A PLAIN Mutex, AND WHY ua.go's OBJECTION TO HOLDING digestRetryMu ACROSS A
	// DISPATCH DOES NOT TRANSFER. That field's comment gives two reasons it must
	// be released before dispatch: it is UA-GLOBAL ACROSS BOTH DIGEST LEGS, so an
	// unreachable callee's INVITE dial could stall a healthy registrar's refresh
	// on an unrelated identity; and Mutex.Lock takes no context, so a blocked leg
	// cannot honour its own deadline while waiting. Neither clause applies here.
	// Nothing but a REGISTER on THIS UA ever takes this lock, so the only exchange
	// that can be blocked is one already bound for the SAME registrar — there is
	// no unrelated identity to stall. And the wait is bounded by the holder's own
	// cfg.Timeout-bounded transactions (RawTransaction's timeout, then
	// doRequestWithDigest's context.WithTimeout), not by the far end's silence:
	// worst case one extra exchange's timeout, far below the per-UA teardown waits
	// stopRefresher's comment already documents as accepted (measured 29.70s /
	// 31.70s at production defaults).
	//
	// LOCK ORDER, AND THE ONE RULE THAT MUST NOT BE BROKEN. dispatchMu is acquired
	// FIRST and may be held while briefly taking digestRetryMu (inside
	// doRequestWithDigest) or mu (inside rememberChallenge); neither is ever held
	// while acquiring it, so there is no cycle. NEVER ACQUIRE IT BEFORE STOPPING A
	// REFRESHER WHOSE Do DISPATCHES A REGISTER: Unregister's stopRegisterRefresher
	// must stay ahead of its sendRegister, or the blocking join would wait for a
	// refreshRegister that is itself waiting for this lock. buildRegister (and
	// therefore presentCachedChallenge) runs BEFORE sendRegister at all four call
	// sites, so it never runs under this lock either.
	//
	// NOT WIDENED TO COVER buildRegister + recordRegisterCSeq (Rule 19). Doing so
	// would make the whole build-send-record triple atomic and would additionally
	// close a PRE-EXISTING CSeq-selection race on the same residual path — a
	// separate defect with its own restructuring cost across four call sites,
	// recorded as P4-W3-N01 rather than fixed here.
	// reg.cseq is safe under mu regardless and its only write is a monotone max
	// (recordRegisterCSeq's `if cs.SeqNo > u.reg.cseq`), so it cannot go BACKWARDS
	// under interleaving; it can only fail to advance far enough, which is the
	// pre-existing behaviour this task does not change.
	dispatchMu sync.Mutex

	// refresher is the R10 registration-refresh timer, nil until a successful
	// REGISTER starts one. Guarded by regState.mu, like every field here EXCEPT
	// dispatchMu itself (that field's own doc comment explains the exception),
	// so Registered()/RegisterCode() still never block on a network write.
	refresher *refresher
	// keepalive is Task 26's field; declared here alongside refresher so
	// stopRefreshers compiles now and Task 26 only fills in the constructor.
	keepalive *refresher

	// refresherCancel and keepaliveCancel cancel the context each refresher
	// above was Started with. THEY ARE THE SHUTDOWN BOUND — see stopRefresher.
	// Stored next to the refresher they belong to and cleared with it, so the
	// pair can never drift apart.
	refresherCancel context.CancelFunc
	keepaliveCancel context.CancelFunc
}

// refresherCtx derives the context a UA-owned refresher runs its attempts on:
// a cancellable child of the UA's own lifetime context, so a teardown can cut
// short an in-flight Do WITHOUT cancelling u.uaCtx (which would also close the
// transport out from under everything else on the UA).
//
// It is PER REFRESHER INSTANCE, not per UA: startRegisterRefresher replaces its
// refresher on every successful Register, and a shared cancel would leave the
// replacement running on an already-cancelled context.
func (u *UA) refresherCtx() (context.Context, context.CancelFunc) {
	return context.WithCancel(u.uaCtx)
}

// stopRefresher shuts one refresher down and waits for its goroutine.
//
// CANCELLING BEFORE Stop() IS THE WHOLE POINT, AND IT IS WHAT MAKES CLOSE AND
// UNREGISTER PROMPT. refresher.Stop() blocks until the in-flight Do returns
// (refresher.go's Stop contract, deliberately: it is what guarantees no timer
// puts a REGISTER or an OPTIONS onto a transport that is closing). Every Do in
// this package spends its time inside a SIP transaction that threads the
// refresher's ctx into context.WithTimeout (siptest.Client.doTx), so against an
// unreachable registrar Do runs for the FULL transaction timeout and Stop waits
// out every second of it: measured 29.70s (keepalive) and 31.70s (register
// refresh) per UA at production defaults, serial across UAs in
// Manager.UnregisterAllUAs.
//
// THE BOUND CHOSEN IS ZERO ADDITIONAL WAIT, not a shorter timeout. Cancelling
// the attempt context first aborts the transaction immediately, so the wait
// that remains is only the goroutine's own unwind — and it is independent of
// both the keepalive interval and the far end's responsiveness, which a
// timeout-shortening fix can never be. The blocking join is NOT weakened: the
// refresher still cannot start a new Do once r.stop is closed, so the
// no-request-onto-a-closing-transport guarantee is untouched.
func stopRefresher(r *refresher, cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
	if r != nil {
		r.Stop()
	}
}

// engineConfig projects the UA's Config onto the vendored config.Config the
// builders take.
//
// LocalAddr comes from BoundAddr() — the address read back from the bound
// socket — and NEVER from the configured local_addr string. A 0 port only
// becomes concrete at bind time, and sipgo keys the pooled (tapped) socket by
// conn.LocalAddr().String() (sip/transport_udp.go:65), so the Via and the
// pool key agree only if both come from the same post-bind read. If they
// disagree, ClientRequestConnection's lookup misses
// (sip/transport_layer.go:341-346) and sipgo silently opens a NEW, UNTAPPED
// socket on the first outbound request — a silently incomplete capture rather
// than a failure.
func (u *UA) engineConfig() config.Config {
	cfg := u.cfg // UNEXPORTED field, read directly: every call site is in this package
	user, domain := aorParts(cfg.AOR)
	return config.Config{
		Transport:  cfg.Transport,
		LocalAddr:  u.BoundAddr().String(),
		TargetURI:  cfg.Registrar,
		FromUser:   user,
		FromDomain: domain,
		AuthUser:   cfg.AuthUser,
		AuthPass:   cfg.AuthPass,
		Timeout:    cfg.Timeout,
	}
}

func aorParts(aor string) (user, domain string) {
	s := strings.TrimPrefix(strings.TrimPrefix(aor, "sips:"), "sip:")
	if i := strings.IndexByte(s, '@'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// parseSIPURI parses target as a sip:/sips: URI, defaulting a missing scheme
// (matched case-insensitively) to "sip". It is the one SIP-URI parse step:
// parseValidSIPURI adds its IPv6 rejection on top, and uriHost (the digest
// guard's anchor host) reads the parsed host.
func parseSIPURI(target string) (sip.Uri, error) {
	s := target
	ls := strings.ToLower(s)
	if !strings.HasPrefix(ls, "sip:") && !strings.HasPrefix(ls, "sips:") {
		s = "sip:" + s
	}
	var u sip.Uri
	if err := sip.ParseUri(s, &u); err != nil {
		return sip.Uri{}, err
	}
	return u, nil
}

// parseValidSIPURI parses target as a sip:/sips: URI, defaulting a missing
// scheme to "sip" (bare user@host is accepted here — validSIPURI's existing
// two callers, a dial target and a configured registrar, both allow that).
// ok is false for anything sip.ParseUri rejects, or a bracketed IPv6
// reference host (not yet a usable outbound target — see validSIPURI below).
func parseValidSIPURI(target string) (sip.Uri, bool) {
	u, err := parseSIPURI(target)
	if err != nil {
		return sip.Uri{}, false
	}
	if strings.HasPrefix(u.Host, "[") {
		// IPv6 reference host: parses fine now, but not yet a usable
		// outbound target (see doc comment above).
		return sip.Uri{}, false
	}
	return u, true
}

// validSIPURI reports whether target parses as a SIP URI without panicking.
// siptest.BuildRegister and siptest.BuildInvite ultimately call the vendored,
// unexported mustParseURI (internal/sipengine/siptest/builders.go), which
// PANICS on a malformed URI instead of returning an error — proven for an
// IPv6 registrar such as "sip:[::1]:5060" (D123: "bad uri: strconv.Atoi:
// parsing \":1]:5060\""), a crash inside the daemon triggered by an
// operator-supplied registrar address. BuildInvite instead uses the
// non-panicking tryParseURI, so a malformed to_uri does not crash Dial — but
// D134 found it fails SILENTLY there instead: tryParseURI returns false, the
// IP-to-IP branch never fires, and the call times out as a transport_fault
// rather than failing fast as invalid_argument. This guard runs the same
// underlying sip.ParseUri call mustParseURI/tryParseURI both wrap, so
// Register and Dial can both turn the failure into a clean
// apierr.InvalidArgument before ever reaching the builder. Named for both
// callers now that Dial uses it too (originally validRegistrarURI).
//
// Phase 4 M1 B7 taught sip.ParseUri to accept a bracketed IPv6 reference
// host ("[::1]") instead of failing the whole parse (fixing the original
// D123/D134 symptom's root cause: an IPv6 Contact used to kill an entire
// inbound message parse). That fix does NOT make outbound IPv6 targets
// usable here: newUA/newUAStream bind an IPv4 UDP/TCP socket, so a write to
// an IPv6 peer still fails — now at the OS level ("address ...: non-IPv4
// address") instead of at ParseUri. Without the check below, D134/C7 and
// D123 would regress from "fails fast as InvalidArgument" to "fails slow as
// an untyped transport error" (Register) or "fails slow as a
// transport_fault after cfg.Timeout" (Dial) — exactly what both were built
// to prevent. So an IPv6-literal host (recognizable by the retained "["
// B7's fix writes into Uri.Host) is still rejected here, same as before,
// just for the accurate reason: unsupported outbound target, not an
// unparseable one.
func validSIPURI(target string) bool {
	_, ok := parseValidSIPURI(target)
	return ok
}

// Register sends one REGISTER, answering a 401/407 digest challenge if the
// registrar issues one.
//
// A REJECTED REGISTRATION IS NOT AN ERROR (§11.1, §10.2): the returned error
// is nil, Registered is false, and Code carries the far end's final status.
// Credentials come from the policy profile BY NAME and never cross the MCP
// boundary (D6); RegisterResult carries no credential field.
func (u *UA) Register(ctx context.Context) (session.RegisterResult, error) {
	cfg := u.cfg
	if cfg.Mode != "register" {
		return session.RegisterResult{}, apierr.PreconditionFailed(
			fmt.Sprintf("ua is in mode %q; REGISTER requires mode \"register\"", cfg.Mode))
	}
	if cfg.Registrar == "" {
		return session.RegisterResult{}, apierr.InvalidArgument("register mode requires a registrar")
	}
	if !validSIPURI(cfg.Registrar) {
		return session.RegisterResult{}, apierr.InvalidArgument(
			fmt.Sprintf("registrar %q is not a valid SIP URI", cfg.Registrar))
	}

	requestedExpiresS := u.requestedExpires()

	// The REQUESTED expiry reaches the wire from P3 onward (spec §6); the
	// stable Call-ID/CSeq identity (R10) is applied the same way.
	req := u.buildRegister(requestedExpiresS)

	res, err := u.sendRegister(ctx, req)
	// Recorded BEFORE the err check — a failed send still reached the wire
	// with a bumped CSeq (see recordRegisterCSeq's doc comment), and skipping
	// this on the error path would have the next attempt collide with it.
	u.recordRegisterCSeq(req)
	if err != nil {
		return session.RegisterResult{}, fmt.Errorf("REGISTER: %w", err)
	}

	// RFC 3261 §10.2.8: a registrar whose Min-Expires exceeds what we asked for
	// answers 423 and names its floor. Retried ONCE, here, so a too-short
	// expires_s is a recoverable configuration rather than a total registration
	// failure.
	res, req, requestedExpiresS, err = u.retryIntervalTooBrief(ctx, res, req, requestedExpiresS)
	if err != nil {
		return session.RegisterResult{}, err
	}

	// RFC 3581 LEARN: a NAT-observed public address off the registrar's
	// received/rport, consulted by Answer's 200 OK Contact (call.go).
	if ap, ok := learnPublicAddr(res); ok {
		u.learnedPublic.Set(ap)
	}

	out := session.RegisterResult{
		Registered: res.StatusCode == 200,
		Code:       int(res.StatusCode),
		Reason:     res.Reason,
		ExpiresS:   u.responseExpires(res, req, requestedExpiresS),
	}
	// C7: symmetric with refreshRegister's registrationRemoved (RFC 3261
	// §10.2.4 — a 200 granting expires=0 removes the binding immediately).
	// The refresh-side half of this ruling shipped in Phase 3 (c7bbec3/
	// 55e3a35); the INITIAL Register path did not apply it, so a first
	// REGISTER granted expires=0 used to leave the UA permanently reporting
	// Registered:true, expires_s:0, with no refresher armed to ever
	// self-correct it (startRegisterRefresher already declines to arm on a
	// non-positive grant, but nothing corrected `out.Registered` itself).
	if out.Registered && out.ExpiresS <= 0 {
		out.Registered = false
	}
	// B6: res.Contact() reads only the LAST Contact header. A registrar MAY
	// list every binding for the AOR — other devices sharing the same AOR —
	// so matchingContact (shared with contactExpires) searches every listed
	// Contact for the one that matches OUR binding, not just whichever came
	// last.
	if c := matchingContact(res, req); c != nil {
		out.Contact = c.Address.String()
	} else if c := req.Contact(); c != nil {
		out.Contact = c.Address.String()
	}

	u.reg.mu.Lock()
	u.reg.registered = out.Registered
	u.reg.code = out.Code
	u.reg.expiresS = out.ExpiresS
	u.reg.contact = out.Contact
	u.reg.mu.Unlock()

	// R10: arm the refresh timer against the GRANTED expiry, not the requested
	// one (D24). Only on a confirmed registration — a rejected REGISTER is a
	// successful tool call (§11.1) with nothing to refresh.
	if out.Registered {
		u.startRegisterRefresher(out.ExpiresS)
	}

	return out, nil
}

// requestedExpires is the expiry this UA asks for on its NEXT REGISTER: the
// configured value (registerExpiresS), raised to any Min-Expires floor a
// registrar has already demanded of this registration with a 423.
//
// THE CLAMP IS WHAT MAKES THE 423 RETRY STICK. Retrying once with the named
// floor registers the UA, but refreshRegister re-derives its requested expiry
// from scratch every cycle, so without this the very next refresh would send the
// same too-short value, draw the same 423, burn all three retry attempts and
// reach OnGiveUp — a registration that succeeds once and then dies at the first
// refresh is barely better than one that never succeeds.
//
// Unregister does NOT go through here: it passes 0 to buildRegister explicitly,
// and a de-registration's Expires: 0 must never be clamped up to a floor.
func (u *UA) requestedExpires() int {
	want := u.registerExpiresS()
	u.reg.mu.Lock()
	floor := u.reg.minExpiresS
	u.reg.mu.Unlock()
	if floor > want {
		return floor
	}
	return want
}

// minExpiresHeader reads RFC 3261 §10.2.8's Min-Expires off a 423 response.
// A missing, unparseable or non-positive value is not a floor: the registrar
// said "too brief" without saying what would be long enough, and inventing a
// number would put a guessed interval on the wire.
//
// NEITHER IS A FLOOR ABOVE maxAcceptableRegisterExpiresS (F3). This value does
// not merely schedule a timer: requestedExpires raises EVERY later REGISTER to
// it, so it goes on the wire and comes back through responseExpires' fallback.
// A registrar demanding a minimum registration longer than a day is not one we
// can honour, and the honest answer is the one we already give for a missing
// header — no usable floor, no retry — rather than a clamp that would put a
// value the registrar has just told us it rejects on the wire in a loop. This
// is retryIntervalFor422's `peerMinSE > maxAcceptableSessionIntervalS` rule
// applied to the registration side.
func minExpiresHeader(res *sip.Response) (int, bool) {
	h := res.GetHeader("Min-Expires")
	if h == nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(h.Value()))
	if err != nil || v <= 0 || v > maxAcceptableRegisterExpiresS {
		return 0, false
	}
	return v, true
}

// retryIntervalTooBrief implements RFC 3261 §10.2.8: on a 423 Interval Too Brief
// carrying a usable Min-Expires, it re-sends the REGISTER ONCE at that value and
// records the floor so every later REGISTER on this registration honours it. It
// returns the response and request that should be treated as the exchange's
// outcome, together with the expiry actually requested for it (which
// responseExpires needs as its last-resort fallback).
//
// THIS WAVE CREATED THE FAILURE IT FIXES. Until Config.ExpiresS reached the wire
// every REGISTER carried the vendored builder's hardcoded 300, which essentially
// every registrar accepts; now policy permits values down to 30, and a registrar
// whose Min-Expires is higher rejects every single one of them. Failure was
// total — Register reported Registered: false with no refresher armed, and
// refreshRegister burned its whole retry budget on three identical too-short
// requests — on exactly the configuration (expires_s: 30..60) an operator sets
// to get faster NAT refresh.
//
// EXACTLY ONCE, NEVER IN A LOOP. A registrar that answers 423 to the value it
// itself just named is broken, and retrying that in a loop is how a shutdown
// hang gets shipped. A second 423 is returned to the caller as the final result,
// same as any other rejection. The `floor <= requestedExpiresS` guard is the
// other half of that: a floor we already meet is not a reason to re-send.
func (u *UA) retryIntervalTooBrief(ctx context.Context, res *sip.Response, req *sip.Request,
	requestedExpiresS int) (*sip.Response, *sip.Request, int, error) {
	if res.StatusCode != 423 {
		return res, req, requestedExpiresS, nil
	}
	floor, ok := minExpiresHeader(res)
	if !ok || floor <= requestedExpiresS {
		u.log().Warn("registrar rejected the REGISTER as 423 Interval Too Brief but named no "+
			"usable Min-Expires floor above what was requested; not retrying",
			"requested_expires_s", requestedExpiresS)
		return res, req, requestedExpiresS, nil
	}
	u.reg.mu.Lock()
	u.reg.minExpiresS = floor
	u.reg.mu.Unlock()
	u.log().Info("registrar requires a longer registration interval; retrying once at its Min-Expires",
		"requested_expires_s", requestedExpiresS, "min_expires_s", floor)

	retry := u.buildRegister(floor)
	retryRes, err := u.sendRegister(ctx, retry)
	// Recorded BEFORE the err check, exactly as every other call site does.
	u.recordRegisterCSeq(retry)
	if err != nil {
		return nil, nil, floor, fmt.Errorf(
			"REGISTER retry after 423 Interval Too Brief (Min-Expires: %d): %w", floor, err)
	}
	return retryRes, retry, floor, nil
}

// setExpires forces a built REGISTER's Expires header to seconds.
//
// IT EXISTS BECAUSE THE BUILDER IS VENDORED AND FROZEN BY OWNER POLICY (G4).
// siptest.BuildRegister hardcodes Expires: 300 (internal/sipengine/siptest/
// builders.go:41-42) and the vendored config.Config carries no Expires field to
// forward one through, so the ONLY way Config.ExpiresS reaches the wire is a
// post-build override. Unregister has done exactly this for Expires: 0 since
// P1; this is that same three-line pattern extracted so Register,
// refreshRegister and Unregister share ONE copy rather than growing a third
// (Rule 16). The vendored builder is not edited.
//
// NOT "hash-pinned", which this comment claimed until fix round 2 and which is
// false: internal/sipengine/** is a point-in-time SNAPSHOT that VENDOR.md:3-4
// calls "owned and modifiable" and free to "diverge freely from upstream". What
// forbids the builder edit is integrity gate G4, an owner-ruled standing freeze
// on that tree — a
// policy constraint, not a technical one. The sanctioned route under it is
// exactly this: a post-build override living in NON-vendored code, which is why
// setExpires and applyRegisterIdentity exist at all rather than the two fields
// simply being added to the builder.
func setExpires(req *sip.Request, seconds int) {
	req.RemoveHeader("Expires")
	// B4: sip.ExpiresHeader is a uint32; a seconds value outside its range
	// narrows SILENTLY (9999999999 mod 2^32 = 1410065407) rather than
	// erroring. The policy-side load-time ceiling (Phase 4 W1 M2, Inputs §3)
	// is the PRIMARY defence — this clamp is belt-and-suspenders at the exact
	// point of narrowing, for any caller (present or future) that reaches
	// here with a value policy never validated.
	if seconds < 0 {
		seconds = 0
	} else if seconds > math.MaxUint32 {
		seconds = math.MaxUint32
	}
	exp := sip.ExpiresHeader(seconds)
	req.AppendHeader(&exp)
}

// buildRegister builds one REGISTER with the requested expiry and this UA's
// stable registration identity applied.
func (u *UA) buildRegister(expiresS int) *sip.Request {
	req := siptest.BuildRegister(u.engineConfig(), u.Transport())
	setExpires(req, expiresS)
	u.applyRegisterIdentity(req)
	ensureSupportedTimer(req) // RFC 4028 7.1 (CF-113); every REGISTER path builds here
	// production-hardening spec Task 4 (supersedes P4-D09): once an RFC
	// 3581 learned public address is known, rewrite ONLY this REGISTER's
	// Contact host/port to it -- so a registrar with rewrite_contact=yes
	// matches our Contact against what it echoes back. Deliberately NOT
	// u.localContact() (call.go): that helper always stamps the AOR's
	// user (aorUser(u.cfg.AOR)), but BuildRegister's own Contact
	// intentionally uses AuthUser when the profile sets one
	// (siptest/builders.go's contactURI, fed by
	// "registerUser := cfg.FromUser; if cfg.AuthUser != "" { registerUser
	// = cfg.AuthUser }"), which can legitimately differ from the AOR user
	// (e.g. SIP trunking, where auth_user is a trunk identity distinct
	// from the registered AOR). Reusing localContact() wholesale would
	// silently swap that identity on every REGISTER; overriding only
	// host/port preserves everything else the builder already got right.
	// Nothing changes on the FIRST REGISTER of a session -- learnedPublic
	// can only be populated after a REGISTER response comes back (RFC
	// 3581's own chicken-and-egg).
	//
	// UDP ONLY (Rule 13 Cycle 3 fix round). learnPublicAddr reads the
	// registrar's received/rport off the REGISTER response's top Via, and
	// on UDP that genuinely reflects a NAT mapping: the same socket sends
	// every REGISTER, so a differing observed port means a NAT is
	// translating it. Over TCP/TLS the source port sipgo's buildVia stamps
	// on each REGISTER is ALWAYS the OS-assigned ephemeral port of a fresh
	// outbound connection, never the listening port -- so from the second
	// REGISTER onward this override would replace a Contact nothing is
	// wrong with with one advertising a port nothing listens on, breaking
	// inbound-call routing for any registrar that dials the Contact
	// directly rather than reusing the existing connection (RFC 5923). The
	// learned address carries no NAT-mapping signal at all on these
	// transports, so the override must not fire for them.
	//
	// Rebuilt via RemoveHeader+AppendHeader, matching the same idiom
	// setExpires/applyRegisterIdentity use above and dtmf.go's own Contact
	// override -- even though sipgo's AppendHeader caches the same typed
	// *ContactHeader pointer that a later Contact() call returns (so
	// mutating req.Contact()'s fields in place would also reach the wire
	// here), removing and re-appending keeps this override consistent with
	// every other post-build header override in this file, rather than
	// being the one call site that mutates a returned header in place.
	// addr := orig.Address copies the WHOLE URI struct by value first, so
	// every field BuildRegister set (User, and UriParams on a non-UDP
	// transport) survives untouched -- only Host/Port are then
	// overwritten -- rather than hand-listing individual fields to carry
	// forward, which silently drops any field added to sip.Uri later.
	if ap, ok := u.learnedPublic.Get(); ok && strings.EqualFold(u.Transport(), "udp") {
		if orig := req.Contact(); orig != nil {
			addr := orig.Address
			addr.Host = ap.Addr().String()
			addr.Port = int(ap.Port())
			req.RemoveHeader("Contact")
			req.AppendHeader(&sip.ContactHeader{
				DisplayName: orig.DisplayName,
				Address:     addr,
				Params:      orig.Params,
			})
		}
	}
	// P4-D07: present a cached challenge preemptively, so only the FIRST-EVER
	// registration spends a round trip drawing a 401. Placed here, AFTER the
	// identity is applied, so all four REGISTER call sites (Register,
	// retryIntervalTooBrief, Unregister, refreshRegister) get it from one place
	// and a fifth cannot be added without it. It runs BEFORE sendRegister at every
	// site, which is what keeps it out from under reg.dispatchMu — see that
	// field's lock-order rule.
	u.presentCachedChallenge(req)
	return req
}

// applyRegisterIdentity overrides BuildRegister's fresh-Call-ID/CSeq-1 output
// with this UA's STABLE registration identity (RFC 3261 §10.2). The first call
// (u.reg.callID == "") adopts whatever Call-ID the builder minted and seeds the
// CSeq high-water mark from the builder's own value; every later call reuses
// the SAME Call-ID and starts CSeq from the last value this UA has actually
// sent, so a fresh REGISTER after a refresh (or a refresh after the initial
// REGISTER) is recognisably the same registration to the far end.
//
// SCOPE, because the sentence above used to read "never looks like a new
// registration" without qualification and that overstates what this does
// (Cycle 4 / C4-A, item E(D)): Call-ID and CSeq are the whole of it. The From
// TAG is minted fresh by siptest.BuildRegister on every call and nothing here
// overrides it, so each refresh does carry a new From tag — observed live
// against the Asterisk rig, every cycle. That is legal (RFC 3261 §10.2 keys a
// binding on Call-ID plus CSeq plus the Contact, not the From tag) and it is
// deliberate scope, not an oversight; but a registrar that keyed on the From
// tag would see a new registration each time, and the old wording promised it
// would not.
func (u *UA) applyRegisterIdentity(req *sip.Request) {
	u.reg.mu.Lock()
	defer u.reg.mu.Unlock()
	if u.reg.callID == "" {
		if c := req.CallID(); c != nil {
			u.reg.callID = string(*c)
		}
		if cs := req.CSeq(); cs != nil {
			u.reg.cseq = cs.SeqNo
		}
	} else {
		callID := sip.CallIDHeader(u.reg.callID)
		req.ReplaceHeader(&callID)
	}
	req.RemoveHeader("CSeq")
	cseq := &sip.CSeqHeader{SeqNo: u.reg.cseq, MethodName: sip.REGISTER}
	req.AppendHeader(cseq)
}

// presentCachedChallenge stamps a preemptive digest credential onto req when this
// UA has already had a REGISTER challenge ACCEPTED (P4-D07).
//
// WHAT IT SAVES. Without it every REGISTER — initial, refresh, 423 retry and
// de-registration alike — is sent unauthenticated, draws a 401/407, and is sent
// again with a credential: two REGISTERs per cycle, forever, against a registrar
// whose nonce has not changed. With it only the FIRST-EVER registration pays that
// round trip.
//
// THE FALLBACK IS THE UNCHANGED PATH, NOT A SECOND RETRY LOOP. If the registrar
// rotated its nonce or realm it answers this REGISTER with a fresh 401/407, and
// doRequestWithDigest handles that exactly as it always has: applyDigest replaces
// the header this function wrote — and, since the Cycle B finding-1 fix, the
// header of the OTHER challenge family too, so a cached 401-credential meeting a
// fresh 407 cannot leave two credentials on the retry — and retries ONCE. So the
// worst case is the old two-REGISTER cycle, never a loop; and sendRegister then
// re-caches the NEW challenge only if THAT exchange succeeds, so the cycle after
// it is back to one message.
//
// IT DOES NOT BUMP CSeq OR TOUCH Via, deliberately. This credential rides on a
// request that has not been dispatched yet: applyRegisterIdentity's CSeq is
// already the right one and sipgo bumps it itself on the options-less first
// dispatch, and siptest.BuildRegister's Via is the one that should go out. That
// is precisely why credentialFor exists separately from applyDigest.
//
// IT RUNS OUTSIDE reg.dispatchMu, and must keep doing so: buildRegister calls it
// before any of the four call sites reach sendRegister. See dispatchMu's comment
// for the lock order and for the recorded investigation of which REGISTER paths
// can and cannot run concurrently.
func (u *UA) presentCachedChallenge(req *sip.Request) {
	u.reg.mu.Lock()
	cached := u.reg.challenge
	u.reg.mu.Unlock()
	if cached.HeaderName == "" {
		return
	}
	// digestRetryMu covers the RESERVATION ONLY and is released before the caller
	// dispatches (Rule 13 Cycle 5 fix round) — an inner closure so a future early
	// return cannot leak the hold. No network I/O runs under it.
	value, err := func() (string, error) {
		u.digestRetryMu.Lock()
		defer u.digestRetryMu.Unlock()
		return u.credentialFor(req, cached.Challenge, true)
	}()
	if err != nil {
		// A cached challenge we can no longer compute against (an algorithm the
		// MD5-only engine refuses) is NOT fatal here: send unauthenticated and let
		// the registrar challenge us, which is exactly the pre-P4-D07 behaviour.
		// Failing the REGISTER outright would turn an optimisation into an outage.
		u.log().Warn("cannot present the cached registrar challenge preemptively; "+
			"sending this REGISTER unauthenticated", "err", err)
		return
	}
	// BOTH names, mirroring applyDigest's strip for the same reason (Rule 4 Cycle
	// B, finding 1): the invariant "one request, at most one credential header" is
	// enforced at every site that writes one, so it holds by construction rather
	// than by every writer happening to be reached on a freshly built request.
	req.RemoveHeader("Authorization")
	req.RemoveHeader("Proxy-Authorization")
	req.AppendHeader(sip.NewHeader(cached.HeaderName, value))
}

// rememberChallenge caches the challenge a SUCCESSFUL REGISTER exchange answered,
// so the next REGISTER can present a credential for it preemptively (P4-D07).
//
// IT DOES NOT DECIDE SUCCESS — sendRegister does, and is the only caller. This
// function's own job is the zero-value guard below.
//
// A ZERO-VALUED answered IS IGNORED, NOT STORED, and that is load-bearing rather
// than defensive: "no challenge was answered" is the ORDINARY outcome once the
// cache is warm (the registrar answers the preemptive REGISTER with a 200 and
// never challenges), and overwriting a good cached challenge with "none" would
// put the UA straight back on the two-REGISTER cycle this exists to remove.
func (u *UA) rememberChallenge(answered answeredChallenge) {
	if answered.HeaderName == "" {
		return
	}
	u.reg.mu.Lock()
	u.reg.challenge = answered
	u.reg.mu.Unlock()
}

// forgetChallenge clears the cached registrar challenge (Rule 13 Cycle 3
// finding I1, Phase 4 W3 fix round). See sendRegister's second switch case
// for when this is called and why: a registrar that rejects a preemptively
// presented credential outright (neither accepting it with 200 nor
// re-challenging it with 401/407) has effectively invalidated the cached
// identity, and without this the next refresh would keep presenting the
// same dead credential forever.
func (u *UA) forgetChallenge() {
	u.reg.mu.Lock()
	u.reg.challenge = answeredChallenge{}
	u.reg.mu.Unlock()
}

// sendRegister dispatches one REGISTER through the shared digest path and, when
// that exchange SUCCEEDED, caches the challenge it answered (P4-D07). It is the
// ONLY way this file calls doRequestWithDigest, so no REGISTER can be sent
// without the cache decision being taken — which is what keeps the four call
// sites from drifting apart.
//
// THE CACHE HOLDS THE CURRENT ACCEPTED REGISTRAR CHALLENGE, NOT THE LAST
// COMPLETED EXCHANGE (Rule 4 Cycle B, finding 2). Caching whatever
// doRequestWithDigest returned would publish a challenge the registrar itself
// REFUSED: that function answers a challenge exactly once, so an exchange whose
// FINAL response is another 401/407 — wrong credentials, a nonce that expired
// between the challenge and the retry, a registrar that rotated its realm
// mid-exchange — still hands back the challenge it answered. Present that
// preemptively and the next REGISTER opens with a credential for an identity the
// far end has already rejected: the UA pays the 401 round trip it was trying to
// save AND burns a nonce-count on the refusal, every cycle. So the gate is the
// same success predicate Register uses for RegisterResult.Registered
// (`res.StatusCode == 200`) and refreshRegister uses for its own rejection check.
//
// `err == nil` IS REDUNDANT WITH THE STATUS CHECK TODAY, AND IS SPELLED OUT
// ANYWAY. Every error return in doRequestWithDigest hands back either a nil
// response (both dispatch-failure returns, and pumpFinal's) or the 401/407 that
// was being answered — so `res != nil && res.StatusCode == 200` already excludes
// every error path. It is written explicitly because that is a property of
// ANOTHER file's return table, and a future return there pairing a 200 with an
// error would silently re-open exactly the hole this gate closes.
//
// IT HOLDS reg.dispatchMu FOR THE WHOLE EXCHANGE, INCLUDING THE CACHE WRITE. See
// that field's comment for the recorded investigation of which REGISTER paths are
// already serialized by construction, which one is not, why a plain Mutex is safe
// here where digestRetryMu's would not be, and the ordering rule that keeps
// Unregister's stopRegisterRefresher ahead of this call.
func (u *UA) sendRegister(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	u.reg.dispatchMu.Lock()
	defer u.reg.dispatchMu.Unlock()
	res, answered, err := u.doRequestWithDigest(ctx, req)
	if res != nil {
		u.reg.mu.Lock()
		u.reg.dest = req.Destination()
		u.reg.mu.Unlock()
	}
	switch {
	case err == nil && res != nil && res.StatusCode == 200:
		u.rememberChallenge(answered)
	case err == nil && res != nil && res.StatusCode != 401 && res.StatusCode != 407:
		// Rule 13 Cycle 3 finding I1, Phase 4 W3 fix round. The registrar
		// rejected this identity outright (a realistic example: 403, some
		// SBC/Kamailio nonce-replay guards) rather than accepting it or
		// re-challenging it. sendRegister's own success gate only ever WRITES
		// the cache on a 200; before this fix nothing ever cleared it, so a
		// registrar that starts refusing a preemptively-presented credential
		// this way left the UA presenting the same dead credential on every
		// later refresh, forever — a permanent registration wedge that could
		// not happen pre-P4-D07 (every REGISTER used to always draw a fresh
		// 401/407 challenge). 401/407 are excluded here because
		// doRequestWithDigest already answers those by drawing and presenting
		// a fresh credential in the same exchange; only a FINAL response that
		// is neither an acceptance nor a challenge means the cached identity
		// itself was rejected.
		u.forgetChallenge()
	}
	return res, err
}

// registerDestination is the destination the last answered REGISTER was sent
// to, or "" before any (CF-188).
func (u *UA) registerDestination() string {
	u.reg.mu.Lock()
	defer u.reg.mu.Unlock()
	return u.reg.dest
}

// recordRegisterCSeq reads the CSeq DoRequestWithDigest actually sent back off
// the (mutated) request, so the NEXT REGISTER on this registration starts
// after it. Two things bump req's CSeq past what applyRegisterIdentity wrote:
// sipgo's own Client.TransactionRequest bumps it once, IN PLACE, before the
// very first (options-less) send — third_party/sipgo/client.go, undocumented
// outside that call site — and DoRequestWithDigest bumps it again, explicitly,
// on a 401/407 digest retry. Without recording the FIRST bump, the next call's
// applyRegisterIdentity would reuse the same stale u.reg.cseq and collide with
// the CSeq this UA already put on the wire.
//
// MUST BE CALLED EVEN WHEN DoRequestWithDigest RETURNS AN ERROR (transport
// timeout, connection failure): the failed send still reached the wire with a
// bumped CSeq (sipgo bumps before the write completes, not after it succeeds),
// so skipping this on the error path leaves u.reg.cseq stale and the NEXT
// attempt reuses — collides with — a CSeq that already went out. Call sites
// must call this immediately after DoRequestWithDigest returns, before
// checking err, exactly like Unregister already does.
func (u *UA) recordRegisterCSeq(req *sip.Request) {
	cs := req.CSeq()
	if cs == nil {
		return
	}
	u.reg.mu.Lock()
	if cs.SeqNo > u.reg.cseq {
		u.reg.cseq = cs.SeqNo
	}
	u.reg.mu.Unlock()
}

// responseExpires reads the registrar's GRANTED expiry off the response, in
// the order RFC 3261 §10.2.4 mandates:
//
//  1. the `expires` PARAMETER on the response Contact matching the binding we
//     registered — the REQUIRED, authoritative form of a registrar's grant;
//  2. the top-level Expires header — OPTIONAL in a 200 OK, and absent from
//     many real registrars that grant only via the Contact parameter;
//  3. requestedExpiresS — last resort, meaning "the registrar said nothing at
//     all, so it honoured what we asked for".
//
// READING ONLY THE HEADER WAS A SILENT BUG. Since P3 the value returned here
// is a CONTROL INPUT, not a status field: startRegisterRefresher arms the
// refresh timer at 0.85x it, and refreshRegister re-derives it the same way
// every cycle, so a too-long value is re-applied forever instead of
// self-correcting. A registrar answering `Contact: <...>;expires=60` with no
// Expires header against a requested 300 would refresh at 255s on a binding
// that lapsed at 60s — the UA unreachable for ~195s per cycle with nothing
// failing, nothing logged and ua_status still reporting expires_s=300.
//
// THE FALLBACK CHANGED IN P3, AND THE OLD ONE IS NOW WRONG. It used to return
// the literal 300 — correct while that was what siptest.BuildRegister
// unconditionally sent and Config.ExpiresS was inert. Now setExpires puts the
// REQUESTED value on the wire, so a registrar that grants silently (RFC 3261
// permits omitting Expires from the 200 when it honours the request) has
// granted the REQUESTED value, not 300. Without this change NextRefreshMS would
// count down against 300 on every such registrar regardless of configuration —
// refreshing far too late for a 60-second registration and needlessly often for
// a 3600-second one.
//
// req is the REGISTER we sent: its Contact is what identifies OUR binding
// among the several the registrar may list (see contactExpires).
//
// PARTIALLY FIXED (Phase 4 Wave 6, supersedes deferral P4-D09). Our REGISTER
// Contact now carries the RFC 3581 learned public address once one is known
// (buildRegister) — but ONLY on UDP (Rule 13 Cycle 3 fix round: a TCP/TLS
// source port is always ephemeral and carries no NAT-mapping signal, so the
// override is scoped off for those transports and this fallback still
// covers every REGISTER on them, not just the first). Even on UDP, the
// FIRST REGISTER of a session still cannot use the learned address,
// because learnedPublic is only populated by a REGISTER response, and this
// is that response's own request. Against a rewrite_contact=yes registrar,
// the 200 OK to that first REGISTER still lists the rewritten public
// binding, which sameBinding cannot match, so THIS FALLBACK — falling
// through to the Expires header — still fires on exactly that one message.
// From the first refresh onward, Contact matches and step 1 above succeeds
// normally. The warning in contactExpires firing on a session's very first
// registration cycle only is the expected residual shape of this partial
// fix, not a regression.
//
// EVERY BRANCH LEAVES THROUGH ONE CLAMP (F1). The three sources below — the
// Contact parameter, the Expires header and the requested fallback — all feed
// startRegisterRefresher's `time.Duration(grantedExpiresS) * time.Second`, which
// overflows NEGATIVE above 9223372036 and turns the refresh timer into an
// unbounded REGISTER flood at the registrar. Deriving the value once and
// clamping the single result is what makes it impossible for a later branch
// added here to skip the bound.
func (u *UA) responseExpires(res *sip.Response, req *sip.Request, requestedExpiresS int) int {
	granted := requestedExpiresS
	if v, ok := u.contactExpires(res, req); ok {
		granted = v
	} else if h := res.GetHeader("Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil {
			granted = v
		}
	}
	return u.clampRegisterExpires(granted, "granted expiry")
}

// maxAcceptableRegisterExpiresS bounds a registration expiry the way
// maxAcceptableSessionIntervalS bounds a session interval (F1). It is a SEPARATE
// constant because it bounds a different thing: 7200 is the longest CALL we will
// hold open, while a registrar granting a binding for a day is entirely ordinary
// and clamping it to two hours would quadruple our REGISTER rate against every
// such registrar. One day is far above any grant a real registrar issues
// (Asterisk defaults to 3600) and far below the ~292 years at which the multiply
// into time.Duration wraps negative.
const maxAcceptableRegisterExpiresS = 86400

// clampRegisterExpires bounds a registrar-supplied expiry to
// maxAcceptableRegisterExpiresS. Refreshing sooner than the registrar granted
// only ever renews the binding early, so clamping is safe in a way that
// rejecting the registration outright would not be.
func (u *UA) clampRegisterExpires(expiresS int, source string) int {
	if expiresS <= maxAcceptableRegisterExpiresS {
		return expiresS
	}
	u.log().Warn("registrar named an expiry above the longest registration we will run; clamping",
		"source", source, "named_expires_s", expiresS,
		"clamped_expires_s", maxAcceptableRegisterExpiresS)
	return maxAcceptableRegisterExpiresS
}

// matchingContact returns the Contact header in res that matches req's OWN
// REGISTER Contact per sameBinding, or nil if none does. Shared by Register
// (B6, the RegisterResult.Contact field) and contactExpires below (the
// granted-expiry lookup): res.GetHeaders("Contact") sees EVERY listed
// binding, unlike res.Contact(), which reads only the LAST one — a registrar
// that lists other devices' bindings for the same AOR ahead of or behind ours
// made both silently adopt a stranger's binding.
func matchingContact(res *sip.Response, req *sip.Request) *sip.ContactHeader {
	sent := req.Contact()
	if sent == nil {
		return nil
	}
	for _, h := range res.GetHeaders("Contact") {
		c, ok := h.(*sip.ContactHeader)
		if ok && sameBinding(c.Address, sent.Address) {
			return c
		}
	}
	return nil
}

// contactExpires returns the `expires` parameter on the response Contact that
// matches the binding req registered, and whether one was usable.
//
// WHICH CONTACT IS OURS. A registrar MAY list every binding for the AOR in its
// 200 OK, including other devices' — all sharing the same user part, since
// that is what an AOR is. What distinguishes one binding from another is the
// contact ADDRESS, so matchingContact matches on user + host + port + URI
// parameters against the Contact siptest.BuildRegister put on our own
// REGISTER (which is the UA's bound address, unique to this UA). Taking the
// first Contact in the list instead would be the same class of bug as reading
// only the Expires header: it silently adopts another device's expiry.
//
// A NON-MATCH IS NOT A GRANT. If no listed Contact is ours — a registrar that
// rewrote the contact under NAT, say — this reports false so responseExpires
// falls through to the Expires header rather than adopting a stranger's
// interval, and u.log() records that it happened; a wrong refresh interval is
// invisible in every other observable.
//
// A malformed or negative parameter is likewise not a grant: it reports false
// (never a nonsense timer). `expires=0` IS honoured — that is the registrar
// saying the binding is gone, and startRegisterRefresher already declines to
// arm anything for a non-positive grant.
func (u *UA) contactExpires(res *sip.Response, req *sip.Request) (int, bool) {
	sent := req.Contact()
	if sent == nil {
		return 0, false
	}
	c := matchingContact(res, req)
	if c == nil {
		if len(res.GetHeaders("Contact")) > 0 {
			u.log().Warn("no Contact in the REGISTER response matches our binding; "+
				"the granted expiry cannot be read from the authoritative parameter",
				"sent_contact", sent.Address.String(), "listed_contacts", len(res.GetHeaders("Contact")))
		}
		return 0, false
	}
	raw, ok := paramFold(c.Params, "expires")
	if !ok {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < 0 {
		u.log().Warn("registrar sent an unusable Contact expires parameter; falling back",
			"contact_expires", raw, "contact", c.Address.String())
		return 0, false
	}
	return v, true
}

// sameBinding compares two contact addresses as RFC 3261 §19.1.4 URI
// equivalence does for the parts that identify a registration binding: the
// scheme case-insensitively (B8 — sip: and sips: are DIFFERENT bindings, not
// the same one spelled two ways), the user part case-sensitively, the host
// case-insensitively, the port with an omitted port read as the
// scheme-and-transport default (registrars routinely normalise ":5060" away
// when echoing a binding back), and the URI parameters per §19.1.4's own
// rules.
//
// THE PARAMETERS ARE NOT DECORATION. siptest.contactURI puts
// `;transport=tcp|tls` on our REGISTER Contact for every non-UDP transport, and
// this project's own rig deliberately shares ONE AOR name between
// e2e-uac-register and e2e-uac-register-tls — so without the parameter
// comparison two bindings at the same host:port differing only by transport
// compare equal and contactExpires can adopt the wrong one's expiry.
//
// SCHEME GOES THROUGH normalizeScheme, NOT A RAW COMPARE. siptest.contactURI
// builds our OWN outbound Contact as `sip.Uri{User: ..., Host: ..., Port:
// ...}` with Scheme left at its Go zero value "" — it never sets "sip"
// explicitly. The SAME binding echoed back by a registrar has been through a
// wire round-trip (serialised to "sip:..." text, then re-parsed), which DOES
// fill Scheme in as an explicit "sip". A raw `a.Scheme == b.Scheme` compares
// "" against "sip" and finds them different, which made every registrar echo
// of our own binding a non-match — this is the exact fold uriPort already
// performs for the sips: default port, applied to the scheme itself.
func sameBinding(a, b sip.Uri) bool {
	return normalizeScheme(a.Scheme) == normalizeScheme(b.Scheme) &&
		a.User == b.User &&
		strings.EqualFold(a.Host, b.Host) &&
		uriPort(a) == uriPort(b) &&
		sameURIParams(a.UriParams, b.UriParams)
}

// sameURIParams applies RFC 3261 §19.1.4's uri-parameter rules: any parameter
// present in BOTH URIs must have the same value (parameter names and values
// both compare case-insensitively); a user, ttl, method or transport
// parameter present in only ONE never matches; a URI carrying maddr never
// matches one without it; every other parameter present in only one URI is
// IGNORED.
//
// TRANSPORT MOVED INTO THE NEVER-MATCHES SET (B9). It used to fall through to
// the "ignored" rule, so a registrar that echoed our binding back having
// dropped a `;transport=tcp` we sent (or added one we never sent) matched it
// anyway — folding "absent" and "present" together the same way uriPort still
// leniently folds a normalised-away PORT. A port omission is genuinely the
// same default value restated; a transport omission is not — it identifies a
// DIFFERENT wire path (UDP vs TCP vs TLS), and two bindings that disagree on
// it are not the same binding. This project's own rig shares ONE AOR name
// between e2e-uac-register and e2e-uac-register-tls, which is precisely the
// scenario the old leniency let two distinct bindings compare equal in.
func sameURIParams(a, b sip.HeaderParams) bool {
	for _, side := range [2][2]sip.HeaderParams{{a, b}, {b, a}} {
		for k, v := range side[0] {
			if w, ok := paramFold(side[1], k); ok {
				if !strings.EqualFold(v, w) {
					return false
				}
				continue
			}
			switch strings.ToLower(k) {
			case "user", "ttl", "method", "maddr", "transport":
				return false
			}
		}
	}
	return true
}

// uriPort is the URI's port, or RFC 3261 §19.1.1's default when it carries
// none: 5061 for a sips: URI and for a sip: URI over TLS, 5060 otherwise. The
// TRANSPORT half matters because our own non-UDP Contact is a `sip:` URI
// carrying `;transport=tls` (siptest.contactURI), which read by scheme alone
// defaults to the wrong port.
func uriPort(u sip.Uri) int {
	if u.Port != 0 {
		return u.Port
	}
	if strings.EqualFold(u.Scheme, "sips") {
		return 5061
	}
	if t, ok := paramFold(u.UriParams, "transport"); ok && strings.EqualFold(strings.TrimSpace(t), "tls") {
		return 5061
	}
	return 5060
}

// normalizeScheme reads a URI's scheme the way this file already treats it
// everywhere else (uriPort's `strings.EqualFold(u.Scheme, "sips")` check): an
// EMPTY scheme means "sip". siptest.contactURI never sets Scheme on the URI
// it builds for our own outbound Contact, so an in-memory comparison against
// a wire-round-tripped copy (which DOES carry an explicit "sip") must treat
// the two as equal, exactly as an omitted port is treated as equal to the
// scheme-and-transport default.
func normalizeScheme(s string) string {
	if s == "" {
		return "sip"
	}
	return strings.ToLower(s)
}

// paramFold looks a header parameter up case-insensitively: SIP parameter
// names are case-insensitive (RFC 3261 §7.3.1) but sipgo's HeaderParams stores
// whatever case arrived on the wire, so a registrar sending `;Expires=60`
// would miss a plain map lookup.
func paramFold(p sip.HeaderParams, key string) (string, bool) {
	for k, v := range p {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// Registered reports whether the UA currently holds a confirmed registration.
func (u *UA) Registered() bool {
	u.reg.mu.Lock()
	defer u.reg.mu.Unlock()
	return u.reg.registered
}

// RegisterCode reports the far end's last final REGISTER status code.
func (u *UA) RegisterCode() int {
	u.reg.mu.Lock()
	defer u.reg.mu.Unlock()
	return u.reg.code
}

// Unregister sends REGISTER with Expires: 0 when the UA is registered, and is
// a no-op otherwise. It reuses the same digest path as Register: registrars
// commonly challenge the Expires: 0 REGISTER too.
//
// session.UserAgent.Unregister requires nil ONLY on a 2xx; a non-2xx final
// response returns an error naming the code (D122) — (*Manager).
// UnregisterAllUAs's confirmed count depends on this distinction, and a nil
// return on any final response would make it meaningless.
func (u *UA) Unregister(ctx context.Context) error {
	u.reg.mu.Lock()
	registered := u.reg.registered
	u.reg.mu.Unlock()
	if !registered {
		return nil
	}
	// A deregistered UA that kept refreshing its own registration would
	// re-register itself — but the NAT keepalive is a DIFFERENT concern
	// (D20 D-M1): it exists to hold the signalling binding open regardless of
	// registration state, and a later Register() must find it still armed
	// rather than silently dead. stopRegisterRefresher halts ONLY the
	// register refresher; stopRefreshers (the undifferentiated form) stays
	// reserved for full UA teardown (Close, the ctx watcher), where nothing
	// is worth keeping open.
	u.stopRegisterRefresher()

	req := u.buildRegister(0)

	res, err := u.sendRegister(ctx, req)
	u.recordRegisterCSeq(req)

	u.reg.mu.Lock()
	u.reg.registered = false
	if res != nil {
		u.reg.code = int(res.StatusCode)
	}
	u.reg.mu.Unlock()

	if err != nil {
		return fmt.Errorf("REGISTER Expires=0: %w", err)
	}
	if !res.IsSuccess() {
		return fmt.Errorf("REGISTER Expires=0 was rejected: %d %s", res.StatusCode, res.Reason)
	}
	return nil
}

// registerRefreshFraction is where in the GRANTED expiry the refresh fires.
// 0.85 +/-0.05 sits under the 0.9 ceiling session/ua.go's NextRefreshMS doc
// comment already commits to, and above R10's 0.5 floor, so a refresh that
// slips by the full jitter is still inside the window session reports.
const (
	registerRefreshFraction = 0.85
	registerRefreshJitter   = 0.05
)

// refreshRegister sends one refresh REGISTER and returns the expiry the
// registrar GRANTED for it.
//
// IT REUSES DoRequestWithDigest, NOT A HAND-ROLLED RETRY (Rule 16). That
// vendored method already encodes the 401/407 -> digest recompute -> in-place
// header replace -> EXPLICIT CSeq bump -> Via strip -> retry sequence, together
// with a documented sipgo v0.24.1 workaround; a second copy here would repeat
// the bug its own comment block documents. What it does NOT provide is a
// STABLE registration identity across separate calls: siptest.BuildRegister
// mints a fresh random Call-ID and hardcodes CSeq:1 on every invocation, so
// without buildRegister/applyRegisterIdentity (register.go) every refresh
// would look like a brand-new registration on the wire (RFC 3261 §10.2).
// requestedExpiresS is computed ONCE, here, and reused for both setExpires and
// responseExpires' fallback — never u.cfg.ExpiresS directly, which would
// silently ignore an unset expires_s and de-register the UA (the same defect
// Task 24 fixed in Register).
func (u *UA) refreshRegister(ctx context.Context) (int, error) {
	// A REFRESH IS A REFRESH *OF* SOMETHING. Once registrationRemoved below has
	// cleared the flag there is no binding left to refresh, and without this the
	// refresher's own retry budget would put two more REGISTERs on the wire for a
	// binding the registrar has already told us it deleted — the "guessing an
	// interval" startRegisterRefresher's comment forbids, just spelled 2s and 4s.
	// Nothing else clears the flag while a refresher is armed: Unregister and
	// Close both call stopRefreshers FIRST, and OnGiveUp only runs after this loop
	// has already returned.
	u.reg.mu.Lock()
	registered := u.reg.registered
	u.reg.mu.Unlock()
	if !registered {
		return 0, fmt.Errorf("%w: the registration this refresher was armed for is gone",
			errRefresherStopped)
	}

	requestedExpiresS := u.requestedExpires()
	req := u.buildRegister(requestedExpiresS)

	res, err := u.sendRegister(ctx, req)
	// Recorded BEFORE the err check — a failed send still reached the wire
	// with a bumped CSeq (see recordRegisterCSeq's doc comment), and skipping
	// this on the error path would have the refresher's next retry collide
	// with a CSeq the previous, failed attempt already used.
	u.recordRegisterCSeq(req)
	if err != nil {
		return 0, fmt.Errorf("REGISTER refresh: %w", err)
	}
	// RFC 3261 §10.2.8, exactly as the initial Register does: a registrar can
	// raise its Min-Expires between refreshes, and without this the refresher
	// would spend all three attempts re-sending the same too-short value.
	res, req, requestedExpiresS, err = u.retryIntervalTooBrief(ctx, res, req, requestedExpiresS)
	if err != nil {
		return 0, err
	}
	if res.StatusCode != 200 {
		if res.StatusCode == 423 {
			// The code's MEANING, in the text: this error is what reaches
			// UAEventRegisterFailed.Err and then the operator, and "423" alone
			// does not say which knob to turn.
			return 0, fmt.Errorf("REGISTER refresh was rejected: %d %s — the registrar requires a "+
				"longer registration interval than the requested expires_s of %d and named no usable "+
				"Min-Expires to retry at (RFC 3261 §10.2.8)",
				res.StatusCode, res.Reason, requestedExpiresS)
		}
		return 0, fmt.Errorf("REGISTER refresh was rejected: %d %s", res.StatusCode, res.Reason)
	}
	// RFC 3581 LEARN, exactly as the initial Register does: a NAT rebind can
	// change the observed public address between refreshes.
	if ap, ok := learnPublicAddr(res); ok {
		u.learnedPublic.Set(ap)
	}
	grantedExpiresS := u.responseExpires(res, req, requestedExpiresS)
	if grantedExpiresS <= 0 {
		return 0, u.registrationRemoved(res)
	}

	u.reg.mu.Lock()
	u.reg.registered = true
	u.reg.code = int(res.StatusCode)
	u.reg.expiresS = grantedExpiresS
	u.reg.mu.Unlock()

	// D24: session's plumbing (Manager.handleRefresh -> UA.recordRefresh)
	// already exists, so sipua only fires the event. ExpiresS carries the NEWLY
	// GRANTED expiry — without it a registrar that shortens the expiry on a
	// refresh cannot be reported at all, and ua_status would count down against
	// a stale interval.
	u.emit(session.UAEvent{
		Kind: session.UAEventRefresh, ExpiresS: grantedExpiresS, At: u.now(),
	})
	return grantedExpiresS, nil
}

// registrationRemoved handles a refresh the registrar ANSWERED 200 OK to while
// granting no expiry at all (RFC 3261 §10.2.4: expires=0 deletes the binding) —
// an administrative deregister, a rebuilt registrar, a policy change. It marks
// the UA unregistered, clears the granted expiry, reports it, and returns the
// error that ends the refresh loop quietly.
//
// IT IS startRegisterRefresher's RULE APPLIED TO THE REFRESH PATH. That comment
// states the rule as a property of the GRANT, not of which exchange delivered
// it: "a registrar that granted no expiry has given us no interval to refresh
// against, and guessing one would put unsolicited REGISTERs on the wire". The
// initial REGISTER honoured it; the refresh path did not, because refresher.go's
// `if granted > 0` leaves the interval at the LAST POSITIVE grant — so a
// registrar that dropped the binding mid-registration was answered by
// re-registering forever against an interval nobody ever granted.
//
// THE FIX IS HERE AND NOT IN THE SHARED LOOP, and that is a correctness point
// rather than a placement preference: keepalive's Do returns `0, nil` on EVERY
// tick by design (keepalive.go) and depends on a non-positive grant meaning
// "interval unchanged". A blanket `granted <= 0 -> stop` in refresher.go would
// stop the keepalive after its first tick. Only this Do knows that for a
// REGISTER a zero grant means the binding is gone.
//
// THE ERROR WRAPS errRefresherStopped, WHICH IS THE SANCTIONED SELF-STOP.
// refresher.go's quietStop contract: "A Do that genuinely wants its own failure
// treated as a shutdown wraps errRefresherStopped itself — it is the only code
// that knows." The loop then exits WITHOUT firing OnGiveUp, so no
// UAEventRegisterFailed follows the removal event emitted here — which would
// report the registrar unreachable moments after it answered us 200.
//
// BUT NOTE WHICH WRAP ACTUALLY DELIVERS THAT: not this one. attempt() does not
// classify a Do error at all — it retries. With Attempts:3 this error is only
// ever attempt 1's lastErr and is overwritten twice, so the wrap that reaches
// quietStop is always refreshRegister's OPENING GUARD (the errRefresherStopped
// wrap on the now-cleared registered flag), which is what attempts 2 and 3
// return. Both wraps are needed and both send nothing, but the load-bearing one
// for the quiet exit is the guard's, not this. Measured: dropping the guard's
// wrap alone reddens the regression test; dropping this one alone does not.
// Stopping the refresher from in
// here instead is not an option — refresher.Stop panics when called from its own
// Do (self-join), by design.
//
// reg.code KEEPS THE REGISTRAR'S 200: the field is documented as the far end's
// last final REGISTER status and that is what it was. Session's ua_status takes
// the opposite line for its own copy (recordRegistrationLost zeroes it, so
// `registered: false` never sits beside `register_code: 200`); that is the
// consumer's locked shape, decided there, and neither field feeds the other.
func (u *UA) registrationRemoved(res *sip.Response) error {
	u.reg.mu.Lock()
	u.reg.registered = false
	u.reg.code = int(res.StatusCode)
	u.reg.expiresS = 0
	u.reg.mu.Unlock()

	u.emit(session.UAEvent{
		Kind:   session.UAEventRegisterRemoved,
		Reason: "the registrar granted expires=0 on a refresh and removed the binding",
		At:     u.now(),
	})
	return fmt.Errorf("%w: the registrar answered %d %s granting expires=0 and removed the binding",
		errRefresherStopped, res.StatusCode, res.Reason)
}

// startRegisterRefresher arms the R10 refresh timer against the expiry the
// registrar just GRANTED. A non-positive grant arms nothing: a registrar that
// granted no expiry has given us no interval to refresh against, and guessing
// one would put unsolicited REGISTERs on the wire.
//
// Calling it twice replaces the previous refresher, so a re-REGISTER through
// Register() (a reload, a manual re-register) does not leave two timers running.
func (u *UA) startRegisterRefresher(grantedExpiresS int) {
	if grantedExpiresS <= 0 {
		return
	}
	r := newRefresher(u.cfg.Clock, u.log(), refreshPolicy{
		Name:     "register",
		Fraction: registerRefreshFraction,
		Jitter:   registerRefreshJitter,
		Initial:  time.Duration(grantedExpiresS) * time.Second,
		Do:       u.refreshRegister,
		Retry:    backoff{Attempts: 3, Base: 2 * time.Second, Cap: 30 * time.Second},
		OnGiveUp: func(err error) {
			// Mark unregistered and report it on the REGISTRATION channel.
			//
			// NOT session.UAEventTransportFault, and this is the correctness
			// point rather than a naming preference: that kind is UA-WIDE, and
			// session's handleTransportFault (uaevent.go:212-278) snapshots every
			// live call on this UA and TryTerminates each one with
			// "transport_failure". A registrar outage would therefore tear down
			// established calls whose media and in-dialog signalling never touch
			// the registrar at all. Losing a registration means we can no longer
			// be REACHED; it says nothing about a dialog that is already up.
			// UAEventRegisterFailed carries exactly the fact that occurred, and
			// its handler updates only the UA's registration state.
			u.reg.mu.Lock()
			u.reg.registered = false
			u.reg.expiresS = 0
			u.reg.mu.Unlock()
			u.emit(session.UAEvent{
				Kind:   session.UAEventRegisterFailed,
				Reason: "registration refresh failed", Err: err, At: u.now(),
			})
		},
	})
	ctx, cancel := u.refresherCtx()
	u.reg.mu.Lock()
	prev, prevCancel := u.reg.refresher, u.reg.refresherCancel
	u.reg.refresher, u.reg.refresherCancel = r, cancel
	u.reg.mu.Unlock()
	stopRefresher(prev, prevCancel)
	r.Start(ctx)
}

// stopRegisterRefresher halts ONLY the R10 registration refresher, leaving
// the NAT keepalive (if any) running.
//
// D20 D-M1: the undifferentiated stopRefreshers used to be Unregister's only
// option, and it nils BOTH refreshers — so a subsequent Register() re-armed
// the register refresher but never the keepalive, which stayed silently dead
// until the next full UA restart (Close/newUA). This is the register-only
// half stopRefreshers itself is now built from.
func (u *UA) stopRegisterRefresher() {
	u.reg.mu.Lock()
	reg, regCancel := u.reg.refresher, u.reg.refresherCancel
	u.reg.refresher, u.reg.refresherCancel = nil, nil
	u.reg.mu.Unlock()
	stopRefresher(reg, regCancel)
}

// stopRefreshers halts every UA-owned refresher. Called from the ctx watcher
// (alongside stopAllMediaLoops) and from Close, so a UA teardown can never
// leave a timer putting REGISTERs or OPTIONS on a closed transport. A UA that
// is going away has no NAT binding left worth keeping open either, unlike
// Unregister (D20 D-M1), which stops only the register refresher via
// stopRegisterRefresher above.
func (u *UA) stopRefreshers() {
	u.stopRegisterRefresher()
	u.reg.mu.Lock()
	ka, kaCancel := u.reg.keepalive, u.reg.keepaliveCancel
	u.reg.keepalive, u.reg.keepaliveCancel = nil, nil
	u.reg.mu.Unlock()
	stopRefresher(ka, kaCancel)
}

// now is the UA's clock reading, defaulting to the system clock when Config
// left one unset (unit harnesses).
func (u *UA) now() time.Time {
	if u.cfg.Clock == nil {
		return time.Now()
	}
	return u.cfg.Clock.Now()
}

// There is no (*UA).Destroy. session/destroy.go:destroyUA is the ONE
// ua_destroy teardown implementation (locked decision D137): it orchestrates
// agent.Hangup -> agent.Unregister -> agent.Close itself, and Destroy had
// zero production callers and is not on session.UserAgent, so it could never
// be reached. Adding a BYE loop here would have created a SECOND teardown
// path — session/destroy.go:20 calls that a defect in capitals, and spec
// design.md:1408: "a second teardown path would be a second set of bugs."
