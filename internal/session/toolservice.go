package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// ToolService implements the thirteen §10 tool methods transport/mcp consumes.
//
// It is SEPARATE FROM Manager on purpose (contract Part 3). Manager owns and
// guards the registries; ToolService validates §10's inputs and shapes §10's
// response payloads. Folding thirteen payload-shaping methods into Manager
// produces exactly the god object §6.2.1 was written to prevent.
//
// §11.1 IS STRUCTURAL HERE: a SIP failure is a SUCCESSFUL tool call. A 486 is a
// PAYLOAD FIELD, returned with a nil error; only a POLICY or SERVER fault is an
// error. Returning a 486 as an error would make every rejection look like a
// malfunction to the agent.
type ToolService struct{ m *Manager }

// NewToolService wraps m. See ToolService's own doc comment for why this is a
// separate type rather than thirteen more methods on Manager.
func NewToolService(m *Manager) *ToolService { return &ToolService{m: m} }

// CallReject is the worked example every other per-handle method follows:
// validate the input, resolve under the session id, claim the transition, then
// perform the SIP write OUTSIDE every lock (§6.3).
func (t *ToolService) CallReject(ctx context.Context, sess string, in CallRejectInput) (any, error) {
	// U13: 300-699. §10.3, §11.2 and D11 all say so; only R14's prose says
	// "3xx-6xx", and U13 resolves it in the majority's favour.
	status := in.Status
	if status == 0 {
		status = 486 // §10.3's documented default
	}
	if status < 300 || status > 699 {
		return nil, apierr.InvalidArgument(fmt.Sprintf(
			"status %d outside the permitted range 300-699", status))
	}
	// HIGH-1: reason lands straight in the SIP status line
	// (sipua.(*UA).Reject -> sip.NewResponseFromRequest), so it is validated
	// here, before ResolveCall — see input.go's validateRejectReason.
	if err := validateRejectReason(in.Reason); err != nil {
		return nil, err
	}

	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err // not_found or gone, already shaped by the registry
	}
	if err := c.TryReject(t.m.clk.Now(), status, in.Reason); err != nil {
		return nil, err // precondition_failed: a concurrent actor won (§6.3)
	}
	// §6.0b INV-1 — THE TWO LINES ABOVE AND BELOW ARE ONE UNIT. No statement may
	// appear between a successful terminal Try* and its defer: not a log line,
	// not an error wrap, not a metrics call. TryReject has ALREADY claimed the
	// transition to `terminated` under the call mutex, so from this point on the
	// call is over as far as the state machine is concerned, and the REGISTRY
	// must be told on every path out of this function including the error ones.
	defer t.m.RecordTermination(c)

	// The SIP write happens with NO LOCK HELD, after the transition is claimed.
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	// DECISION 17: the rejection goes out on the DAEMON context, not on ctx. The
	// terminal transition is already claimed, so abandoning the write because
	// the agent's HTTP request timed out would leave the call terminated here
	// and ringing at the far end, with nothing left that can send the final
	// response.
	if err := ua.Agent().Reject(t.m.daemonCtx, c.DialogID(), status, in.Reason); err != nil {
		// THE ERROR IS STILL RETURNED, AND THAT IS CORRECT — but the deferred
		// RecordTermination above now runs on this path, which is the whole of
		// the fix. A Reject that fails is a TRANSPORT fault, not a SIP-level
		// rejection.
		return nil, err
	}

	return map[string]any{
		"call_handle": in.Call,
		"state":       string(StateTerminated),
		"sip_code":    status,
		"reason":      in.Reason,
	}, nil
}

// ---- §10.2 UA lifecycle -----------------------------------------------------
//
// profile_list and its policy.yaml-backed profile lookup are REMOVED in this
// wave (D1). Session-scoped UA lifecycle (owner-locked decision) means every
// account field ua_create needs travels INLINE on the request instead of
// being resolved server-side from a shared "profile" name — there is no
// registry left to name into, so a tool that could only ever return
// {"profiles":[]} would advertise a capability that does not exist.

// UACreate is §10.2. Return shape:
//
//	{ok, ua_handle, mode, transport, registered, register_code, expires_s,
//	 contact, session_cookie, expires_at}
//
// §11.1 IS THE LOAD-BEARING RULE HERE: A REJECTED REGISTRATION IS NOT AN ERROR.
// A registrar answering 403 returns ok:true with registered:false and the far
// end's register_code — a SIP failure is a successful tool call. Only a policy
// refusal, a malformed local_addr, a cap, or a TLS HANDSHAKE failure is an
// error.
//
// max_uas_per_session (default 8, configurable — see policy.go) is enforced
// by CreateUA's own cap check (checkUACapsLocked), not by a special case
// here — this handler has no UA-count logic of its own.
func (t *ToolService) UACreate(ctx context.Context, sess string, in UACreateInput) (any, error) {
	p := t.m.policy.Current()

	if err := validateKeepaliveMode(in.Keepalive); err != nil {
		return nil, err
	}
	if err := validateInlineAccount(in); err != nil {
		return nil, err
	}

	if in.AllowCleartextSDES && in.SRTP != "" && in.SRTP != "disabled" && sdesUnprotected(in) {
		t.m.log.Warn("ua_create: SDES keys offered over a transport that does not protect the SDP body (allow_cleartext_sdes)",
			"transport", defaultStr(in.Transport, string(TransportUDP)), "srtp", in.SRTP)
	}

	cfg := UAConfig{
		Mode:               in.Mode,
		Transport:          Transport(defaultStr(in.Transport, string(TransportUDP))),
		LocalAddr:          in.LocalAddr,
		SRTP:               defaultStr(in.SRTP, "disabled"),
		CodecPref:          in.CodecPref,
		AllowCleartextSDES: in.AllowCleartextSDES,
		AOR:                in.AOR,
		AuthUser:           in.AuthUser,
		// D5: the plaintext arrives as a JSON string (owner-accepted for this
		// local dev tool — it also appears in the request/response and may
		// appear in logs) but is wrapped in policy.Secret the instant it
		// enters UAConfig, so UAConfig itself stays unprintable and
		// internal/importguard's "exactly one .Reveal() call site outside
		// internal/policy" invariant (cmd/sipclient-mcpd/run.go) is unaffected.
		AuthPass:             policy.NewSecret(in.AuthPass),
		DTMFMode:             defaultStr(in.DTMFMode, "rfc2833"),
		SessionExpiresS:      defaultInt(in.SessionExpiresS, policy.DefaultSessionExpiresS),
		MinSES:               defaultInt(in.MinSES, 90),
		KeepaliveIntervalS:   defaultInt(in.KeepaliveIntervalS, 30),
		SessionRefreshMethod: defaultStr(in.SessionRefreshMethod, "auto"),
		AuthAnyHost:          in.AuthAnyHost,
	}
	switch in.Mode {
	case "register":
		// §7's defining difference from direct mode: register mode dials
		// through a registrar and needs an AOR to register AS.
		if in.AOR == "" {
			return nil, apierr.InvalidArgument(`aor is required when mode="register"`)
		}
		if in.Registrar == "" {
			return nil, apierr.InvalidArgument(`registrar is required when mode="register"`)
		}
		// CF-185 (RFC 3261 8.1.2/19.1; CF-172): a sips: registrar must be reached
		// over TLS; refuse it on a UA that cannot, rather than downgrade. An
		// unknown transport is left to sipua's own, clearer error.
		if r := strings.TrimSpace(in.Registrar); len(r) >= 5 && strings.EqualFold(r[:5], "sips:") &&
			(cfg.Transport == TransportUDP || cfg.Transport == TransportTCP) {
			return nil, apierr.InvalidArgument(fmt.Sprintf(
				"registrar %q is a sips: URI, which must be reached over TLS; this UA's transport is %q (create the ua with transport \"tls\")",
				in.Registrar, cfg.Transport))
		}
		cfg.Registrar, cfg.ExpiresS = in.Registrar, in.ExpiresS
		// register mode's own keepalive default, BELOW the explicit ua_create
		// input and ABOVE this default (Task 26 correction 9's shape,
		// preserved verbatim: a NAT keepalive is meaningless with nothing to
		// keep bound at a registrar).
		cfg.Keepalive = defaultStr(in.Keepalive, "crlf")
	case "direct":
		// §10.2: registrar is REJECTED for direct mode — direct mode sends the
		// INVITE to the literal to_uri, never via a registrar (§7), so a
		// registrar here names an intent the mode cannot act on.
		if in.Registrar != "" {
			return nil, apierr.InvalidArgument(`registrar is not permitted when mode="direct"`)
		}
		// DIRECT MODE'S KEEPALIVE FALLBACK IS DELIBERATELY NOT "crlf", which is
		// the one asymmetry with register mode's line above. keepaliveTarget()
		// returns "" in direct mode — there is no registrar to keep a NAT
		// binding open TOWARDS — so arming a keepalive here would only start a
		// timer that sends nowhere. An EXPLICIT ua_create input still wins,
		// because that names an intent the operator formed for this UA
		// specifically.
		cfg.Keepalive = defaultStr(in.Keepalive, "none")
	default:
		return nil, apierr.InvalidArgument(fmt.Sprintf(
			`mode %q is not "register" or "direct"`, in.Mode))
	}

	lim := p.Limits
	cfg.InboundRingTimeout = time.Duration(lim.InboundRingTimeoutS) * time.Second

	// §12.3's TWO UA CAPS ARE ENFORCED INSIDE CreateUA'S LOCK HOLD, NOT HERE.
	// There is deliberately no pre-check at this point (Task 11a's
	// checkUACapsLocked is the one enforcement point). DO NOT REINTRODUCE AN
	// ADVISORY PRE-CHECK HERE (Rule 18).

	// CreateUA runs sipua.New through the factory, which only builds a
	// listener — no handshake happens here. A local_addr that cannot be
	// reduced to a concrete IP surfaces at THIS call as invalid_argument
	// WITH NO UA CREATED. A TLS handshake failure surfaces one call later,
	// at ua.Agent().Register below, as tls_failure (Phase 4 W1 M7c, §1
	// item 5). CreateUA ALSO renews this session's 5-minute TTL (D7): an
	// agent that spends minutes on initialize -> ua_create must receive an
	// expires_at it can still act on.
	ua, err := t.m.CreateUA(ctx, sess, cfg)
	if err != nil {
		return nil, err
	}

	// REGISTER, if this is a register-mode UA. Its OUTCOME is payload, not
	// error (§11.1).
	var reg RegisterResult
	if in.Mode == "register" {
		// DECISION 17: the REGISTER goes out on the DAEMON context.
		reg, err = ua.Agent().Register(t.m.DaemonContext())
		if err != nil {
			// A transport or TLS fault during REGISTER is a real error; the UA
			// is torn down so a failed create leaves nothing behind.
			//
			// DestroyUA (the admin entry point) is used here rather than
			// UADestroy because this rollback is an internal cleanup, not an
			// agent-facing call with a session to check ownership against.
			// After the multi-UA-per-session wave both entry points destroy
			// only this one handle and leave the session alone either way, so
			// this choice no longer carries the session-invalidation stakes
			// it once did; DestroyUA is simply the ownership-check-free
			// variant of the one teardown implementation (Rule 18).
			_, _ = t.m.DestroyUA(t.m.DaemonContext(), string(ua.Handle()))
			return nil, err
		}
		ua.recordRegistration(reg, t.m.clk.Now())
	}

	// D2: the cookie is the EXISTING sess string ua_create was called with —
	// no second identifier is minted. D7: CreateUA above already renewed the
	// TTL, so this just reads the fresh deadline back.
	//
	// THE ok RESULT IS NOT DISCARDABLE. It used to be (`expiresAt, _ := ...`),
	// and the window between CreateUA renewing the TTL and this read is narrow
	// but real: a register-mode REGISTER sits in it, and the reaper can delete
	// or expire the session while it does. SessionExpiresAt then returns the
	// ZERO time, and the response carried "expires_at":"0001-01-01T00:00:00Z" —
	// a garbage deadline the calling agent has no way to tell from a real one
	// and would act on. SessionKeepalive propagates its equivalent failure
	// (RenewSession's not_found) rather than formatting a zero time, and this
	// does the same. The UA is torn down first, for the same reason the REGISTER
	// failure above tears it down: a create that returns an error must leave
	// nothing behind, and a live UA whose session record is gone is exactly the
	// orphan that burns a max_uas_total slot for the life of the daemon.
	expiresAt, ok := t.m.SessionExpiresAt(sess)
	if !ok {
		_, _ = t.m.DestroyUA(t.m.DaemonContext(), string(ua.Handle()))
		return nil, apierr.NotFound(fmt.Sprintf("unknown session %s", sess))
	}

	return map[string]any{
		"ua_handle":      string(ua.Handle()),
		"mode":           cfg.Mode,
		"transport":      string(cfg.Transport),
		"registered":     reg.Registered,
		"register_code":  reg.Code,
		"expires_s":      reg.ExpiresS,
		"contact":        reg.Contact,
		"session_cookie": sess,
		"expires_at":     expiresAt.Format(time.RFC3339Nano),
	}, nil
}

// defaultInt returns d when v is the zero value, and v otherwise — the int
// counterpart of defaultStr, used by D6's five Phase-3 settings so an omitted
// ua_create field resolves to its documented default rather than 0.
func defaultInt(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

// SessionKeepalive is session_keepalive (D2/D7): reset this session's 5-minute
// TTL and return the same {session_cookie, expires_at} shape ua_create does,
// so an agent can renew a session with no other side effect. Renewing the
// resume-window clock too (Seen-style) is NOT this tool's job — D7 is
// explicit that ONLY session_keepalive, Open and ua_create renew the TTL.
func (t *ToolService) SessionKeepalive(_ context.Context, sess string, _ SessionKeepaliveInput) (any, error) {
	expiresAt, err := t.m.RenewSession(sess)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"session_cookie": sess,
		"expires_at":     expiresAt.Format(time.RFC3339Nano),
	}, nil
}

// validateKeepaliveMode rejects a ua_create `keepalive` input naming a mode
// sipua's sendKeepalive does not implement. "" means "not supplied" and falls
// through to the profile's value and then the per-mode default, so it is valid
// here and is NOT the same thing as "none".
//
// IT IS A SECOND BOUNDARY, NOT A DUPLICATE ONE. policy.Load already rejects an
// invalid `keepalive` in policy.yaml, but that check cannot see this input: a UA
// created through the tool surface can name a mode the profile never did, and
// an unrecognised one reaches sipua, where startKeepalive refuses to arm and the
// UA silently keeps no NAT binding open at all while ua_status reports the mode
// as configured. The two entry points are independent, so each validates.
//
// The accept/reject decision itself is shared via policy.ValidKeepaliveMode
// (Rule 18): the enum lives in exactly one place, and only the error
// formatting differs between the two boundaries.
func validateKeepaliveMode(mode string) error {
	if policy.ValidKeepaliveMode(mode) {
		return nil
	}
	return apierr.InvalidArgument(fmt.Sprintf(
		"keepalive %q must be none, crlf or options", mode))
}

// validateInlineAccount bounds-checks the six inline account fields that used
// to be bounded by internal/policy's validate() over a policy.Profile.
//
// THIS IS NOT A NEW POLICY, IT IS THE OLD ONE AT ITS NEW BOUNDARY. Phase 1
// deleted policy.Profile (D1/D6) and with it every bound that ran at policy
// LOAD time — dtmf_mode and session_refresh_method's enums, min_se_s's RFC
// 4028 floor, session_expires_s's floor AND ceiling, keepalive_interval_s's
// range, expires_s's range. ua_create took over as the ONE way an account
// reaches a UA, so it has to take over the bounds too; otherwise every one of
// them became unbounded the moment the profile registry went away, and the
// overflow footguns the deleted checks were written to close (an int seconds
// value large enough that `n * time.Second` wraps NEGATIVE, turning a refresh
// interval into a re-INVITE or REGISTER flood from a single typo) came back
// with the tool surface as their entry point instead of policy.yaml.
//
// The LIMITS ARE COPIED VERBATIM from that deleted validate() — same numbers,
// same "bounded both ways" shape, same reasons — so a UA created through
// ua_create is bounded exactly as a profile-backed one was. Only the error
// type differs: apierr.InvalidArgument naming the field and the value, since
// this is a per-request refusal, not a whole-file load failure.
//
// keepalive itself is NOT checked here: validateKeepaliveMode above already
// owns that enum, and UACreate calls it first (Rule 18 — one place decides).
func validateInlineAccount(in UACreateInput) error {
	// The four FREE-TEXT account fields. They were operator-authored in
	// policy.yaml until Phase 1 deleted policy.Profile; they are now
	// agent-reachable over MCP, so they need the boundary the numeric fields
	// below already have. See validateAccountString for the two bounds and
	// why the list stops there.
	for _, f := range []struct{ name, value string }{
		{"aor", in.AOR},
		{"auth_user", in.AuthUser},
		{"auth_pass", in.AuthPass},
		{"registrar", in.Registrar},
	} {
		if err := validateAccountString(f.name, f.value); err != nil {
			return err
		}
	}
	switch in.DTMFMode {
	case "", "rfc2833", "inband", "info":
	default:
		return apierr.InvalidArgument(fmt.Sprintf(
			"dtmf_mode %q must be rfc2833, inband or info", in.DTMFMode))
	}
	switch in.SRTP {
	case "", "disabled":
	case "optional", "required":
		// CF-134, RFC 4566 section 7: SDES puts the SRTP master key in the SDP
		// body, which only TLS protects. optional offers keys too (CF-170).
		if sdesUnprotected(in) && !in.AllowCleartextSDES {
			return sdesRefusal(in.SRTP)
		}
	default:
		return apierr.InvalidArgument(fmt.Sprintf(
			"srtp %q must be disabled, optional or required", in.SRTP))
	}
	switch in.SessionRefreshMethod {
	case "", "auto", "update", "invite":
	default:
		return apierr.InvalidArgument(fmt.Sprintf(
			"session_refresh_method %q must be auto, update or invite", in.SessionRefreshMethod))
	}
	if in.MinSES != 0 && in.MinSES < 90 {
		return apierr.InvalidArgument(fmt.Sprintf(
			"min_se_s must be >= 90 (RFC 4028's floor), got %d", in.MinSES))
	}
	// RFC 4028 §5: the Min-SE we advertise can never exceed the
	// Session-Expires we offer on the same INVITE. The check runs WHETHER OR
	// NOT session_expires_s was supplied — `min_se_s: 2000` alone would
	// otherwise pass and then put `Session-Expires: 1800` (the default
	// UACreate substitutes below) next to `Min-SE: 2000` on the wire.
	floor := 90
	if in.MinSES > floor {
		floor = in.MinSES
	}
	switch {
	case in.SessionExpiresS == 0:
		if policy.DefaultSessionExpiresS < floor {
			// The offer is the default, so it is min_se_s that has to move,
			// and the message says so rather than naming a field the caller
			// never sent.
			return apierr.InvalidArgument(fmt.Sprintf(
				"min_se_s %d exceeds the default session_expires_s of %d; send session_expires_s >= min_se_s",
				in.MinSES, policy.DefaultSessionExpiresS))
		}
	case in.SessionExpiresS < floor:
		return apierr.InvalidArgument(fmt.Sprintf(
			"session_expires_s must be >= %d (max of 90 and min_se_s), got %d", floor, in.SessionExpiresS))
	case in.SessionExpiresS > 7200:
		// 7200 is not a fresh number: internal/sipua already refuses a
		// peer-demanded interval above maxAcceptableSessionIntervalS = 7200,
		// and our OWN offer must not exceed what we would refuse a peer for
		// demanding. The literal is repeated rather than shared because that
		// constant is unexported and sipua is not importable from here
		// (contract Part 1). The cross-reference is MECHANICAL, not merely this
		// comment: internal/sipua/ceiling_crosscheck_test.go drives ua_create at
		// maxAcceptableSessionIntervalS and at one past it, and fails if either
		// side moves without the other. Change this number and that test is what
		// tells you. (For a while it was only prose: the original cross-check
		// pinned policy.validate()'s profile bounds and was deleted along with
		// policy.Profile, leaving the claim with nothing behind it.)
		return apierr.InvalidArgument(fmt.Sprintf(
			"session_expires_s must be <= 7200 (the longest dialog we accept), got %d", in.SessionExpiresS))
	}
	if in.KeepaliveIntervalS != 0 && (in.KeepaliveIntervalS < 5 || in.KeepaliveIntervalS > 3600) {
		return apierr.InvalidArgument(fmt.Sprintf(
			"keepalive_interval_s must be between 5 and 3600, got %d", in.KeepaliveIntervalS))
	}
	// expires_s's ceiling is one day, deliberately NOT session_expires_s's
	// 7200: that bound is how long a PEER may hold a dialog of ours open,
	// which is a different question from how long our own registrar binding
	// lasts. RFC 3261 §10.2's own default Expires is 3600 and a registration
	// is only useful while the binding it refreshes is alive, so a lifetime
	// beyond a day buys nothing and costs the overflow.
	//
	// 86400 is sipua's own maxAcceptableRegisterExpiresS, and is pinned against
	// it by internal/sipua/ceiling_crosscheck_test.go for the same reason the
	// 7200 above is.
	if in.ExpiresS != 0 && (in.ExpiresS < 30 || in.ExpiresS > 86400) {
		return apierr.InvalidArgument(fmt.Sprintf(
			"expires_s must be between 30 and 86400, got %d", in.ExpiresS))
	}
	return nil
}

// sdesUnprotected reports whether in's signalling transport (default udp) is
// not TLS, i.e. does not protect SDES keys carried in the SDP body.
func sdesUnprotected(in UACreateInput) bool {
	return defaultStr(in.Transport, string(TransportUDP)) != string(TransportTLS)
}

// sdesRefusal is the invalid_argument for an srtp value that would put SDES
// keys in an unprotected SDP body.
func sdesRefusal(srtp string) error {
	return apierr.InvalidArgument(fmt.Sprintf(
		"srtp %q needs transport \"tls\": SRTP keys are offered in the SDP body (SDES, RFC 4566 section 7), "+
			"which this transport does not protect; set allow_cleartext_sdes to accept that risk", srtp))
}

// srtpRank orders the srtp policies: disabled < optional < required.
var srtpRank = map[string]int{"": 0, "disabled": 0, "optional": 1, "required": 2}

// perCallSRTP validates a call_dial / call_answer srtp override against the
// UA's policy (CF-170): it may only tighten it, and any value above disabled
// obeys ua_create's SDES rule. It returns the override ("" = the UA's policy).
func perCallSRTP(cfg UAConfig, in string) (string, error) {
	if in == "" {
		return "", nil
	}
	rank, ok := srtpRank[in]
	if !ok {
		return "", apierr.InvalidArgument(fmt.Sprintf("srtp %q must be disabled, optional or required", in))
	}
	if rank < srtpRank[cfg.SRTP] {
		return "", apierr.InvalidArgument(fmt.Sprintf(
			"srtp %q would loosen the UA's policy %q; a per-call srtp may only tighten it", in, cfg.SRTP))
	}
	if rank > 0 && cfg.Transport != TransportTLS && !cfg.AllowCleartextSDES {
		return "", sdesRefusal(in)
	}
	return in, nil
}

// maxAccountFieldBytes bounds aor, auth_user, auth_pass and registrar.
//
// 256 is generous for what these fields actually hold — RFC 3261 names no
// length limit, but a SIP AOR, a registrar URI and an auth username are
// human-scale identifiers, and every real one is well under a hundred bytes.
// The number is a CEILING, not a spec claim: its job is that a 100 KB `aor`
// cannot be pushed through ua_create and out onto the wire.
const maxAccountFieldBytes = 256

// validateAccountString applies the two bounds every free-text ua_create
// account field gets: a length ceiling and a raw-CR/LF floor.
//
// IT IS DELIBERATELY NOT SIP URI GRAMMAR VALIDATION. Parsing these strings
// properly is internal/sipua's job at the point it builds a request, and a
// half-correct grammar check here would reject valid URIs while still not
// being the authority. What this closes is narrower and does not need a
// grammar: unbounded length, and the raw CR/LF that would let a field the UA
// interpolates into a header carry a header break with it. auth_pass gets the
// SAME two rules rather than a looser set — a credential may legitimately
// contain almost any character, but never a line terminator, because nothing
// guarantees it is not echoed somewhere a header break would matter.
func validateAccountString(field, value string) error {
	if len(value) > maxAccountFieldBytes {
		return apierr.InvalidArgument(fmt.Sprintf(
			"%s must be at most %d bytes, got %d", field, maxAccountFieldBytes, len(value)))
	}
	if i := strings.IndexAny(value, "\r\n"); i >= 0 {
		return apierr.InvalidArgument(fmt.Sprintf(
			"%s must not contain a carriage return or line feed (found one at byte %d)", field, i))
	}
	return nil
}

// UAStatus is §10.2:
//
//	{ok, uas:[{ua_handle, mode, transport, registered, register_code,
//	           expires_s, next_refresh_ms, active_calls, keepalive}]}
//
// `ua` omitted means EVERY UA in this session — and only this session's, so
// R11 holds without a special case.
func (t *ToolService) UAStatus(ctx context.Context, sess string, in UAStatusInput) (any, error) {
	var uas []*UA
	if in.UA != "" {
		u, err := t.m.ResolveUA(ctx, sess, Handle(in.UA))
		if err != nil {
			return nil, err
		}
		uas = []*UA{u}
	} else {
		uas = t.m.sessionUAs(sess)
	}

	out := make([]map[string]any, 0, len(uas))
	for _, u := range uas {
		cfg := u.Config()
		out = append(out, map[string]any{
			"ua_handle":     string(u.Handle()),
			"mode":          cfg.Mode,
			"transport":     string(cfg.Transport),
			"registered":    u.Registered(),
			"register_code": u.RegisterCode(),
			// expires_s is the registrar's most recently GRANTED expiry (D136),
			// not cfg.ExpiresS — the operator-REQUESTED value (see
			// sipua.UAConfig.ExpiresS's doc comment). 0 on a direct-mode UA or
			// one that has never completed a REGISTER, matching NextRefreshMS
			// below.
			"expires_s": u.ExpiresS(),
			// next_refresh_ms is R10's registration-refresh countdown. 0 on a
			// direct-mode UA, which has no registration to refresh.
			"next_refresh_ms": u.NextRefreshMS(t.m.clk.Now()),
			"active_calls":    t.m.activeCallCount(sess, u.Handle()),
			"keepalive":       cfg.Keepalive,
		})
	}
	return map[string]any{"uas": out}, nil
}

// UADestroy is §10.2: {ok, ua_handle, unregistered, calls_terminated}.
//
// IT DELEGATES AND ADDS NOTHING. Task 11a's Manager.UADestroy is the ONE
// teardown orchestration; §12.7's admin DELETE is its other entry point.
func (t *ToolService) UADestroy(ctx context.Context, sess string, in UADestroyInput) (any, error) {
	res, err := t.m.UADestroy(ctx, sess, Handle(in.UA))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ua_handle":        res.UAHandle,
		"unregistered":     res.Unregistered,
		"calls_terminated": res.CallsTerminated,
	}, nil
}

// ---- §10.3 Call control -----------------------------------------------------

// dialErrorHook, when non-nil, is called at the end of CallDial's dial-error
// branch on every exit path. Tests use it as a completion barrier for that
// branch (export_test.go's setter); it is nil in production.
var dialErrorHook func()

// CallDial is §10.3:
//
//	{ok, call_handle, ua_handle, state:"dialing", to_uri, capture_armed}
//
// IT RETURNS IMMEDIATELY (D2, N2's 50ms budget). The INVITE is sent on the
// DAEMON context in a goroutine; this function does not wait for 100/180/200.
// An agent learns the outcome through call_wait or call_events.
func (t *ToolService) CallDial(ctx context.Context, sess string, in CallDialInput) (any, error) {
	// D72: to_uri accepts only §10.3's enumerated forms and rejects "sips:"
	// (any case-fold), control characters/CRLF, internal whitespace, host
	// percent-encoding and more than one "@" — BEFORE CheckDestination runs,
	// so a sips: URI cannot evade a deny pattern anchored on "sip:" (a TLS UA
	// dials a sip: target over TLS).
	if err := validateToURI(in.ToURI); err != nil {
		return nil, err
	}
	// HIGH-1: headers and from_user flow verbatim to sipua's Dial (see
	// input.go's validateHeaders/validateFromUser doc comments) and are
	// validated at THIS boundary, same as to_uri above and for the same
	// reason — BEFORE CheckDestination, so a Route header cannot smuggle a
	// destination CheckDestination never evaluates.
	if err := validateHeaders(in.Headers); err != nil {
		return nil, err
	}
	if err := validateFromUser(in.FromUser); err != nil {
		return nil, err
	}
	// D9b dial-time capture (INV-1): validate the capture request BEFORE
	// CreateCall, so a rejected in.Capture creates no call and does not
	// strand one in `dialing` holding a §12.2.2 concurrency-cap slot. This
	// wave supports signaling-only, plaintext capture; the file itself is
	// NOT created here — see the OnDialogBound closure below.
	if in.Capture != nil {
		if in.Capture.Scope != "" && in.Capture.Scope != "signaling" {
			return nil, apierr.NotSupported("dial-time media capture is W4; signaling only")
		}
		if in.Capture.PayloadMode == "ciphertext" {
			return nil, apierr.NotSupported("dial-time ciphertext capture is P4; plaintext only")
		}
	}

	p := t.m.policy.Current()

	// §12.2's destination filter, BEFORE anything is created. The denial names
	// the rule that fired. dialURI is the NORMALISED string CheckDestination
	// evaluated (Task 11d, D85): it is what gets dialled below, at setURIs and
	// in this call's own response, so the evaluated and dialled strings can
	// never diverge — this is what closes the to_uri bypass class Task 11b
	// spent five rounds closing rule-by-rule.
	dialURI, _, err := p.CheckDestination(in.ToURI)
	if err != nil {
		return nil, err
	}

	// §10.7 up-front media_plan validation: rejected BEFORE CreateCall (and so
	// before the INVITE) so a bad plan strands no call and arms no duration cap.
	var planSteps []MediaPlanStep
	if len(in.MediaPlan) > 0 {
		planSteps, err = validateMediaPlan(p, in.MediaPlan)
		if err != nil {
			return nil, err
		}
	}

	ua, err := t.m.ResolveUA(ctx, sess, Handle(in.UA))
	if err != nil {
		return nil, err
	}

	// CF-170: the per-call srtp is validated BEFORE CreateCall, so a refused
	// request creates nothing.
	srtp, err := perCallSRTP(ua.Config(), in.SRTP)
	if err != nil {
		return nil, err
	}

	// CreateCall enforces §12.2.2's two concurrency caps and §11.4's shutdown
	// refusal; both surface as errors naming the exact key that bound.
	c, err := t.m.CreateCall(ctx, sess, ua.Handle(), Outbound, StateDialing)
	if err != nil {
		return nil, err
	}

	// §2.3: the call owns its media_plan view; register the total BEFORE the UA
	// can emit its first plan_step.
	c.SetPlanTotal(len(planSteps))

	// §11.3's duration cap: max_duration_s is CLAMPED DOWN to the policy cap,
	// NEVER UP (§10.3).
	if d := p.ClampDuration(time.Duration(in.MaxDurationS) * time.Second); d > 0 {
		t.m.StartDurationCap(c, d, func() { t.m.RecordTermination(c) })
	}

	// captureArmed is the ACCEPTED-INTENT flag (D9b): the request is valid and
	// wired to arm at dialog bind, knowable synchronously. The actual arm
	// completes inside OnDialogBound below, and only once the real UA fires
	// it — a fake that never invokes OnDialogBound (every fake in
	// internal/testutil/fakes, and nopAgent) simply never captures, with no
	// file ever created and so no orphan (finding NEW-2 residual).
	captureArmed := in.Capture != nil && t.m.artifacts != nil && t.m.tap != nil

	// THE INVITE GOES OUT ON THE DAEMON CONTEXT (locked decision 17).
	go func() {
		res, err := ua.Agent().Dial(t.m.daemonCtx, DialRequest{
			SRTP:       srtp,
			ToURI:      dialURI,
			FromUser:   in.FromUser,
			Headers:    in.Headers,
			CallHandle: string(c.Handle()),
			MediaPlan:  planSteps,
			CallLimit:  min(p.Limits.MaxConcurrentCallsPerSession, p.Limits.MaxConcurrentCallsTotal),
			// CF-090: a redirect target passes the same two checks to_uri did,
			// against the LIVE policy (a deny added mid-dial applies).
			MaxRedirects: p.Limits.MaxRedirects,
			CheckRedirect: func(target string) (string, error) {
				if err := validateToURI(target); err != nil {
					return "", err
				}
				uri, _, err := t.m.policy.Current().CheckDestination(target)
				return uri, err
			},
			// SDPOffer is nil at P1: sipua synthesises the fixed single-codec
			// PCMU body from its own bound address.

			// THE BIND HAPPENS HERE, NOT ON Dial's RETURN. sipua invokes this
			// between registering the dialog and spawning the INVITE
			// goroutine, so it is the last moment at which nothing can yet
			// have emitted an event for this dialog. Binding only below —
			// which is what this code did — loses every response that lands
			// before Dial returns, and an instantly-answering peer on
			// loopback lands the 200 inside that ~1 ms window: the call then
			// sits in `dialing` with an empty last_response while the far end
			// holds our ACK. See DialRequest.OnDialogBound.
			//
			// It is the SAME setter the post-return path below calls, with
			// the same two values, and calling it twice is idempotent — see
			// that block's comment for why it stays.
			OnDialogBound: func(dialogID, callID string) {
				c.setDialogIdentity(dialogID, callID)

				// D9b dial-time capture arm. NO FILE IS CREATED IN CallDial's
				// synchronous body (finding NEW-2 residual): OnDialogBound is
				// OPTIONAL (nil means "do not call me", and every fake in
				// internal/testutil/fakes plus nopAgent never invokes it), and the
				// dial-error path below returns without ever reaching here — so
				// creating the file any earlier than this closure would orphan it
				// whenever arming never happens. The file is created immediately
				// before the arm that will own it, with the SAME Close+Remove
				// rollback CaptureStart uses on arm failure, so a created file
				// never survives without a live armed capture.
				if !captureArmed || callID == "" {
					return // nothing requested, or no Call-ID to key — create NOTHING
				}
				ch := string(c.Handle())
				if err := t.m.artifacts.OpenCallDir(t.m.daemonCtx, ch); err != nil {
					t.m.log.Warn("dial-time capture: open dir failed", "call", ch, "err", err)
					return
				}
				w, err := t.m.artifacts.Create(t.m.daemonCtx, ch, "capture.pcap")
				if err != nil {
					t.m.log.Warn("dial-time capture: create failed", "call", ch, "err", err)
					return
				}
				cfg := CaptureConfig{
					Scope:    "signaling",
					MaxBytes: t.m.policy.Current().Capture.MaxBytesPerCall,
				}
				if err := t.m.tap.ArmCapture(t.m.daemonCtx, string(c.UAHandle()), callID, w, cfg); err != nil {
					// ROLLBACK: no live capture => leave NO file (same invariant as
					// CaptureStart's finding NEW-2 rollback).
					_ = w.Close()
					_ = t.m.artifacts.Remove(t.m.daemonCtx, ch, "capture.pcap")
					t.m.log.Warn("dial-time capture: arm failed; removed orphan", "call", ch, "err", err)
					return
				}
				// RACE GUARD (Cycle-2 2b): if the call reached a terminal state before this
				// late dialog-bind fired, RecordTermination's terminal-close ran with an empty
				// Call-ID and could not close this just-armed capture. Disarm now so the fd is
				// released promptly rather than lingering until registry Evict. Idempotent: a
				// later capture_stop/Evict returns the cached result. NOT a Remove: a
				// terminal-closed capture is a valid finalized pcap capture_stop can still
				// fetch, exactly as the normal terminal-close path closes but never Removes.
				if c.State().terminal() {
					_, _ = t.m.tap.DisarmCapture(t.m.daemonCtx, string(c.UAHandle()), callID)
				}
			},
		})
		if err != nil {
			// Runs last, after the claim and RecordTermination, on every exit of
			// this branch (test-only barrier; nil in production).
			defer func() {
				if dialErrorHook != nil {
					dialErrorHook()
				}
			}()
			// A UA refusal (CF-038's live-dialog bound) rides as the detail of the
			// single terminal event, claimed in ONE call-mutex critical section:
			// a separate Append before the claim could land after a competing
			// call_hangup's bye. Every other Dial error keeps its nil detail.
			now := t.m.clk.Now()
			var ae *apierr.Error
			var terr error
			if apierr.CodeOf(err) == apierr.CodeDenied && errors.As(err, &ae) {
				detail := map[string]any{"kind": "dial_refused", "code": string(ae.Code), "rule": ae.Rule}
				if ae.Limit != nil {
					detail["limit"] = *ae.Limit
				}
				if ae.Current != nil {
					detail["current"] = *ae.Current
				}
				terr = c.TryTransportFailure(now, detail)
			} else {
				terr = c.TryTerminate(now, "transport_failure", EventError)
			}
			// §6.0b INV-1: the defer is on the line immediately following the
			// successful claim, with no statement in between.
			if terr == nil {
				defer t.m.RecordTermination(c)
			}
			return
		}
		// THE OUTBOUND CALL-ID CHANNEL. res.CallID is the SIP Call-ID sipua
		// minted when it built the INVITE (contract §2.5.3, as amended).
		//
		// THIS IS NOW A REDUNDANT-BUT-REQUIRED SECOND BIND, and it is kept
		// deliberately. OnDialogBound above is OPTIONAL by contract, so an
		// implementation of UserAgent that does not invoke it — every fake in
		// internal/testutil/fakes, and nopAgent — would otherwise leave the
		// call with no dialog identity at all. The values are identical (the
		// hook receives the same dialog's two ids) and the setter is a
		// two-field write under the call mutex, so the second call is a
		// no-op. Removing it would silently break every fake-driven caller;
		// removing the hook would reopen the race the hook closes.
		c.setDialogIdentity(res.DialogID, res.CallID)
		// D76: to_uri/from_uri are recorded on the same statement pair as the
		// dialog identity, from the same path — without it call_status,
		// call_list and the N5 log record would carry an empty to_uri/from_uri
		// forever on the outbound path.
		c.setURIs(dialURI, "")

		// U18 — RETAIN THE LADDER RING, IMMEDIATELY AFTER THE SETTER RETURNS AND
		// HOLDING NO LOCK. This is one of exactly two Retain call sites in the
		// project; admitInbound is the other (I2).
		//
		// NO LOCK IS HELD HERE, AND THAT IS LOAD-BEARING. Retain is called
		// AFTER setDialogIdentity returns, so the call mutex is already
		// released, and m.mu is not held either. It therefore adds NO edge to
		// §6.3's hierarchy — unlike evictCallLocked's Tap.Evict, which is a
		// sanctioned registry -> Sink edge (§6.0b INV-2 class 3). Do NOT
		// "tidy" this inside setDialogIdentity's critical section: that would
		// create a call -> Sink edge the hierarchy does not have.
		//
		// The retention is released by Tap.Evict at registry eviction (Task
		// 10's evictCallLocked), which is the ONLY release.
		if t.m.tap != nil && res.CallID != "" {
			// HIGH-3: key the retention by (ua_handle, call_id). c.UAHandle()
			// is this call's OWN owning UA, set at CreateCall.
			t.m.tap.Retain(t.m.daemonCtx, string(c.UAHandle()), res.CallID)
		}
	}()

	return map[string]any{
		"call_handle":   string(c.Handle()),
		"ua_handle":     in.UA,
		"state":         string(StateDialing),
		"to_uri":        dialURI,
		"capture_armed": captureArmed,
	}, nil
}

// CallAnswer is §10.3: {ok, call_handle, state:"answered", codec}.
//
// Errors: not_found, gone, precondition_failed (not in `ringing`), invalid_argument,
// media_negotiation (no codec in common, or srtp="required" against an RTP/AVP
// offer; the far end receives 488 Not Acceptable Here).
func (t *ToolService) CallAnswer(ctx context.Context, sess string, in CallAnswerInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	// §10.7 up-front media_plan validation: rejected BEFORE TryAnswer, so a bad
	// plan cannot claim ringing -> answered and send a 200 OK it then has no way
	// to retract.
	var planSteps []MediaPlanStep
	if len(in.MediaPlan) > 0 {
		planSteps, err = validateMediaPlan(t.m.policy.Current(), in.MediaPlan)
		if err != nil {
			return nil, err
		}
	}
	// CF-170: resolve the UA and validate the per-call srtp BEFORE TryAnswer, so
	// a refused request claims nothing.
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	srtp, err := perCallSRTP(ua.Config(), in.SRTP)
	if err != nil {
		return nil, err
	}
	// TryAnswer claims ringing -> answered ATOMICALLY. Two concurrent
	// call_answers resolve to exactly one winner; the loser gets
	// precondition_failed (§6.3). The 200 OK is written only after this returns
	// nil, and never under the lock.
	//
	// §6.0b INV-1 — CLASSIFIED. TryAnswer claims ringing -> ANSWERED, which is
	// not terminal, so the claim itself is a NON-SITE (U22): an Answer that
	// fails for any ordinary reason leaves the call in `answered` and fully
	// LIVE, reachable by call_hangup, the duration cap, ua_destroy and
	// shutdown — all four of which do run RecordTermination. The one SITE is
	// the refusal path below (CF-131): when the UA tore the dialog down
	// (AnswerRefusedError) TryAnswerRefused makes the call terminal, and the
	// call that wins that transition records the termination.
	if err := c.TryAnswer(t.m.clk.Now()); err != nil {
		return nil, err
	}
	// §2.3: the call owns its media_plan view; register the total AFTER
	// TryAnswer's claim succeeds, not before. SetPlanTotal unconditionally
	// mutates shared Call state with no precondition check of its own, so
	// calling it before TryAnswer resolves would violate §6.3's "check and
	// transition in ONE critical section": a call_answer against an
	// already-answered/terminated call would still stamp planPresent=true
	// forever (PlanView deliberately survives teardown), reporting a plan
	// that never ran a single step — and two racing call_answers with
	// different plans could have their loser clobber the winner's
	// planTotal/planState after the winner already claimed. Placed here, only
	// TryAnswer's actual winner ever reaches this line, and it is still
	// BEFORE ua.Agent().Answer below, so no plan_step can arrive first.
	c.SetPlanTotal(len(planSteps))
	// §11.3's duration cap, ARMED ON THIS PATH TOO. max_duration_s was
	// declared on CallAnswerInput and read by nothing: the only reader of
	// MaxDurationS and the only caller of StartDurationCap both lived in
	// CallDial, so an inbound call answered here was bounded by NEITHER the
	// agent's request NOR the policy cap and ran forever, while the identical
	// outbound call was bounded.
	//
	// Armed BEFORE the 200 OK goes out, exactly as CallDial arms before its
	// INVITE: the call is live from TryAnswer's claim onward, so the cap must
	// cover the whole of that window and not just the part after the network
	// write returns. ClampDuration is the SAME clamp CallDial applies — down
	// to the policy cap, never up (§12.2).
	if d := t.m.policy.Current().ClampDuration(time.Duration(in.MaxDurationS) * time.Second); d > 0 {
		t.m.StartDurationCap(c, d, func() { t.m.RecordTermination(c) })
	}
	// DECISION 17: the 200 OK goes out on the DAEMON context. The `answered`
	// event is appended by the UA's OnAnswered hook once the 200 is on the wire
	// (CF-131), so a refused answer leaves none.
	if err := ua.Agent().Answer(t.m.daemonCtx, AnswerRequest{
		SRTP: srtp, DialogID: c.DialogID(), CallHandle: string(c.Handle()), MediaPlan: planSteps,
		OnAnswered: func() { c.NoteAnswered(t.m.clk.Now()) },
	}); err != nil {
		var refused *AnswerRefusedError
		if errors.As(err, &refused) {
			// The UA sent a final (422/488/500) and tore the dialog down: the
			// call ends here, with no `answered` event. Only the call that wins
			// the transition records the termination (a racing hangup that
			// already ended it has recorded its own).
			if c.TryAnswerRefused(t.m.clk.Now(), refused.Status, refused.Reason) == nil {
				t.m.RecordTermination(c)
			}
			return nil, err
		}
		c.NoteAnswered(t.m.clk.Now())
		return nil, err
	}
	// Redundant when the UA called the hook, required for a UA that never does.
	c.NoteAnswered(t.m.clk.Now())

	res := map[string]any{"call_handle": in.Call, "state": string(StateAnswered)}
	// codec is absent until negotiated: an INVITE without SDP gets our offer in
	// the 200 and the answer arrives in the ACK (CF-145).
	if mv, ok := ua.Agent().MediaView(c.DialogID()); ok && mv.Codec != "" {
		res["codec"] = mv.Codec
	}
	return res, nil
}

// CallHangup is §10.3: {ok, call_handle, state:"terminated", sip_code, duration_ms}.
//
// THERE IS DELIBERATELY NO invalid_argument. `reason` is FREE TEXT and NO VALUE
// OF IT IS REJECTED. Do not add validation here.
func (t *ToolService) CallHangup(ctx context.Context, sess string, in CallHangupInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	// Spec 2026-09-26 §3 (as amended) / D2 / D17: refused only while a call
	// control operation BLOCKS hangup — for a transfer, only while its REFER's
	// own response is pending. Once the REFER is accepted the hangup proceeds,
	// and sipua settles the still-pending transfer as "the transferor hung up
	// before a final NOTIFY". The check MUST precede TryHangup: that claim is
	// irreversible, so a refusal after it would leave the call recorded
	// terminated while the dialog stays up. An operation claiming between this
	// check and the BYE is harmless — sipua's hangup accepts phaseControlOp and
	// settles it, so the hangup simply wins. A ResolveUA failure falls through
	// to the existing path. The message is phrased from the operation's kind
	// (D15).
	//
	// CF-061: the agent resolved here is KEPT and is the one the hangup below
	// reaches. Once TryHangup has claimed the call, the session record can be
	// deleted (the reaper's last step) before a second lookup, which would then
	// fail and the claimed hangup would never reach sipua.
	var agent UserAgent
	if ua, uerr := t.m.ResolveUA(ctx, sess, c.UAHandle()); uerr == nil {
		agent = ua.Agent()
		if kind, blocked := agent.ControlOpBlocksHangup(c.DialogID()); blocked {
			return nil, apierr.PreconditionFailed(controlOpHangupRefusal(kind))
		}
	}
	started := c.StartedAt()
	// TryHangup records termination_reason "local_hangup" regardless of
	// `reason`'s text (§10.3): the reason phrase is a SIP header, not the
	// §10.3 enum value.
	if err := c.TryHangup(t.m.clk.Now(), in.Reason); err != nil {
		return nil, err
	}
	// §6.0b INV-1, ON THE LINE IMMEDIATELY FOLLOWING THE CLAIM, NO STATEMENT IN
	// BETWEEN.
	defer t.m.RecordTermination(c)
	if agent == nil {
		// The pre-claim lookup failed: today's post-claim lookup and its error.
		ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
		if err != nil {
			return nil, err
		}
		agent = ua.Agent()
	}
	// DECISION 17: the BYE goes out on the DAEMON context.
	if err := agent.Hangup(t.m.daemonCtx, c.DialogID(), in.Reason); err != nil {
		return nil, err
	}

	return map[string]any{
		"call_handle": in.Call,
		"state":       string(StateTerminated),
		// The CALL's last observed response, not the BYE's own (D100): an
		// outbound call answered with a 200 reports sip_code: 200 here, from
		// the INVITE's final response recorded by handleResponse — what is
		// genuinely unreachable is the BYE's own response code. 0 reports "no
		// response observed" rather than asserting one that never arrived.
		"sip_code":    c.LastResponseCode(),
		"duration_ms": t.m.clk.Now().Sub(started).Milliseconds(),
	}, nil
}

// controlOpHangupRefusal is call_hangup's precondition_failed text while a call
// control operation blocks hangup on the call (plan D15/D17). Operation-specific
// wording lives HERE, in the tool that explains the refusal, not in sipua's
// shared guard. The default arm is deliberately generic and still correct, so
// an operation added later without its own arm (e.g. hold) never gets
// transfer-specific advice.
func controlOpHangupRefusal(kind ControlOpKind) string {
	switch kind {
	case ControlOpTransfer:
		// Only the REFER's own transaction blocks hangup (D17), and that is
		// bounded by the UA's transaction timeout, so the advice is "retry
		// shortly", not "wait for the outcome".
		return "call_hangup: a call transfer's REFER is awaiting the far end's response on this call; " +
			"retry once call_transfer has returned"
	default:
		return "call_hangup: a call control operation is in progress on this call; " +
			"retry once it has completed"
	}
}

// CallTransfer is §10.14 (spec 2026-09-26 §4.1): {ok, accepted, status_code,
// reason} — the REFER's OWN final response; the NOTIFY-reported outcome arrives
// as `transfer` events. Both calls must be answered in session state (D9) and
// in this session. mode/target validation is sipua's (the single choke
// point, like dtmf_send's digits). "Same UA" needs no check here (D1). The
// REFER goes out on the DAEMON context,
// like every other in-dialog request this file sends.
func (t *ToolService) CallTransfer(ctx context.Context, sess string, in CallTransferInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	if st := c.State(); st != StateAnswered {
		return nil, apierr.PreconditionFailed(fmt.Sprintf(
			"call_transfer: call is %s; only an answered call can be transferred", st))
	}
	req := TransferRequest{DialogID: c.DialogID(), Mode: TransferMode(in.Mode), Target: in.Target}
	if in.ConsultCall != "" {
		cc, err := t.m.ResolveCall(ctx, sess, Handle(in.ConsultCall))
		if err != nil {
			return nil, err
		}
		// TransferRequest's contract (collaborators.go): consult_call must be
		// on the SAME UA as call. Under multi-UA-per-session this is no
		// longer automatic, so it is checked explicitly here rather than
		// left to a confusing lookup failure deep inside sipua.
		if cc.UAHandle() != c.UAHandle() {
			return nil, apierr.InvalidArgument(fmt.Sprintf(
				"call_transfer: consult_call belongs to a different UA (%s) than call (%s); "+
					"attended transfer requires both dialogs on the same UA", cc.UAHandle(), c.UAHandle()))
		}
		if st := cc.State(); st != StateAnswered {
			return nil, apierr.PreconditionFailed(fmt.Sprintf(
				"call_transfer: consult_call is %s; it must be answered", st))
		}
		req.ConsultDialogID = cc.DialogID()
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	res, err := ua.Agent().Transfer(t.m.daemonCtx, req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"accepted": res.Accepted, "status_code": res.StatusCode, "reason": res.Reason}, nil
}

// tlsVerifiedField is call_status's tls_verified producer (Phase 4 W1 M7c,
// §1 item 5). THE DIRECTION GATE IS THE LOAD-BEARING RULE, NOT OPTIONAL: the
// server config sets no ClientAuth (mTLS is deferred, P4-D05), so nothing
// about an INBOUND peer is ever verified, and consulting TLSVerified() for
// an inbound call would report a false security claim. Only an outbound
// call reaches ua.Agent().TLSVerified() at all; every other case (inbound,
// or ok=false for a non-tls transport) reports null, exactly like the
// pre-existing non-tls-transport case.
func tlsVerifiedField(ua *UA, dir Direction) any {
	if dir != Outbound {
		return nil
	}
	verified, ok := ua.Agent().TLSVerified()
	if !ok {
		return nil
	}
	return verified
}

// CallStatus is §10.3's worked JSON.
//
// §10.3's example names fields later phases produce. srtp, codec,
// local_media_addr, remote_media_addr, media_latched and media_plan arrived
// with P2 (P3 only re-sourced media_plan from the Call, §2.3); dtmf_mode and
// session_timer arrive here at P3. artifacts is still unproduced. EVERY
// UNPRODUCED FIELD IS OMITTED, NOT EMITTED AS NULL — and so is a PRODUCED
// field whose producer reports absent: session_timer is absent on a call with
// no RFC 4028 timer, which is not the same statement as session_timer: null.
//
// tls_verified is null on any transport other than tls (§10.3), and — Phase
// 4 W1 M7c — is ALSO null for every INBOUND tls call, direction gated: the
// server config sets no ClientAuth (mTLS is deferred, P4-D05), so nothing
// about an inbound peer is ever verified, and reporting true for an inbound
// call would be a false security claim. Only an OUTBOUND tls call consults
// ua.TLSVerified(), which reflects the UA's construction-time snapshot. THIS
// DIRECTION CHECK SHOULD BE REMOVED, NOT WORKED AROUND, once P4-D05 (mTLS)
// lands and inbound verification becomes real.
func (t *ToolService) CallStatus(ctx context.Context, sess string, in CallStatusInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"call_handle":  in.Call,
		"ua_handle":    string(c.UAHandle()),
		"state":        string(c.State()),
		"direction":    string(c.Direction()),
		"to_uri":       c.ToURI(),
		"from_uri":     c.FromURI(),
		"transport":    string(ua.Config().Transport),
		"tls_verified": tlsVerifiedField(ua, c.Direction()),
		"sip_call_id":  c.CallID(),
		"started_at":   c.StartedAt().UTC().Format(time.RFC3339),
		"duration_ms":  c.DurationMS(t.m.clk.Now()),
		"last_response": map[string]any{
			"code":   c.LastResponseCode(),
			"reason": c.LastResponseReason(),
		},
	}
	// termination_reason is present only once there is one — §10.3's enum
	// describes a terminated call, and an empty string on a live call would
	// read as an unnamed reason.
	if r := c.TerminationReason(); r != "" {
		out["termination_reason"] = r
	}
	if mv, ok := ua.Agent().MediaView(c.DialogID()); ok {
		out["codec"] = mv.Codec
		out["local_media_addr"] = mv.LocalMediaAddr
		out["remote_media_addr"] = mv.RemoteMediaAddr
		out["srtp"] = mv.SRTP
		out["media_latched"] = mv.Latched
	}
	if qv, ok := ua.Agent().QualityView(c.DialogID()); ok {
		out["rogue_source_packets"] = qv.RogueSourcePackets
	}
	// §2.3: media_plan is sourced from the CALL, not the UA — a UA-sourced view
	// vanishes the moment teardownDialog forgets the dialog.
	if pv, ok := c.PlanView(); ok {
		out["media_plan"] = map[string]any{
			"state":           pv.State,
			"steps_total":     pv.StepsTotal,
			"steps_completed": pv.StepsCompleted,
			"failed_index":    pv.FailedIndex,
			"failed_op":       pv.FailedOp,
		}
	}
	// §4: the EFFECTIVE per-call DTMF mode. Absent (not null) when the UA cannot
	// report one — a call whose dialog is already forgotten, for instance.
	if mode, ok := ua.Agent().DTMFMode(c.DialogID()); ok {
		out["dtmf_mode"] = mode
	}
	// §4: session_timer is present ONLY when RFC 4028 was actually negotiated.
	// A zeroed object would assert a session timer on every call, including the
	// large majority against peers that never advertise timer support.
	if st, ok := ua.Agent().SessionTimerView(c.DialogID()); ok {
		out["session_timer"] = map[string]any{
			"interval_s":      st.IntervalS,
			"refresher":       st.Refresher,
			"next_refresh_ms": st.NextRefreshMs,
			// armed disambiguates next_refresh_ms == 0 (C9/A-M6): see
			// SessionTimerView.Armed's doc comment (collaborators.go).
			"armed": st.Armed,
		}
	}
	// E-M5 (D20, W2): THIS IS THE SAME DEFECT CLASS media_plan WAS FIXED FOR,
	// left open here deliberately. media_plan is now Call-owned (rebuilt from the
	// event stream), so it survives teardown; dtmf_mode and session_timer are
	// still read LIVE from ua.Agent(), so a call_status on a terminated call
	// reports them ABSENT rather than reporting their last known values.
	//
	// Closing it means giving both the same Call-owned treatment — a real change
	// to what the Call records, not a comment fix, so it is out of W2's
	// no-behavior-change charter. Recorded here so it is not rediscovered
	// as a new finding a third time.
	return out, nil
}

// CallList is §10.3: {ok, calls:[{call_handle, ua_handle, state, to_uri, duration_ms}]}.
//
// THIS SESSION'S CALLS ONLY (R11 isolation). It walks the session record rather
// than the global m.calls map, so isolation is structural: there is no filter
// to forget.
func (t *ToolService) CallList(_ context.Context, sess string, _ CallListInput) (any, error) {
	now := t.m.clk.Now()
	calls := t.m.sessionCalls(sess)
	out := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		out = append(out, map[string]any{
			"call_handle": string(c.Handle()),
			"ua_handle":   string(c.UAHandle()),
			"state":       string(c.State()),
			"to_uri":      c.ToURI(),
			"duration_ms": c.DurationMS(now),
		})
	}
	return map[string]any{"calls": out}, nil
}

// ---- §10.5 Events -----------------------------------------------------------

// CallWait is §10.5, THE ONLY BLOCKING TOOL. Two shapes, both ok:true:
//
//	event:   {ok, event, seq, elapsed_ms, timed_out:false, call_state, detail}
//	timeout: {ok:true, timed_out:true, elapsed_ms, call_state}
//
// A TIMEOUT IS NOT AN ERROR. §10.5: "it never rang" is a legitimate and often
// expected test outcome.
//
// ctx IS THE HTTP REQUEST CONTEXT AND IS PASSED THROUGH UNCHANGED (§6.3 rule 4,
// locked decision 17). This is the ONE method whose ctx parks.
func (t *ToolService) CallWait(ctx context.Context, sess string, in CallWaitInput) (any, error) {
	res, err := t.m.Wait(ctx, WaitRequest{
		SessionID: sess,
		Handle:    Handle(in.Call),
		Until:     in.Until,
		TimeoutMs: in.TimeoutMs,
		Since:     in.Since,
	})
	if err != nil {
		return nil, err
	}
	if res.TimedOut {
		return map[string]any{
			"timed_out":  true,
			"elapsed_ms": res.ElapsedMs,
			"call_state": string(res.CallState),
		}, nil
	}
	out := map[string]any{
		"elapsed_ms": res.ElapsedMs,
		"timed_out":  false,
		"call_state": string(res.CallState),
	}
	// A terminal call with an empty log resolves immediately with no event, so
	// these stay absent rather than being emitted as zero values.
	if res.Event != nil {
		out["event"] = res.Event.Type
	}
	if res.Seq != nil {
		out["seq"] = *res.Seq
	}
	if len(res.Detail) > 0 {
		out["detail"] = res.Detail
	}
	return out, nil
}

// CallEvents is §10.5: {ok, events:[{seq, at_ms, type, detail}], next_since}.
//
// `since` defaults to 0, which drains the whole retained log. next_since is
// what the caller passes on its NEXT poll.
//
// truncated_before is PRESENT ONLY WHEN EVENTS WERE ACTUALLY EVICTED.
func (t *ToolService) CallEvents(ctx context.Context, sess string, in CallEventsInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	evs, truncatedBefore, nextSince := c.Events(in.Since)
	out := map[string]any{
		"events":     evs,
		"next_since": nextSince,
	}
	if truncatedBefore != 0 {
		out["truncated_before"] = truncatedBefore
	}
	return out, nil
}

// ---- §10.10 Quality ----------------------------------------------------------

// QualityGetInput is §10.10's request: a single call handle.
type QualityGetInput struct {
	Call string `json:"call"`
}

// QualityGet is §10.10. It returns the tier-1 passive metrics and the E-model
// mos_estimate for an answered call; tier is always 1 and mos_lqo/pesq_raw/
// reference are null this wave (tier-2 PESQ needs a returned reference — W5).
func (t *ToolService) QualityGet(ctx context.Context, sess string, in QualityGetInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	qv, ok := ua.Agent().QualityView(c.DialogID())
	if !ok {
		return nil, apierr.PreconditionFailed("call has no media stream (not answered or already torn down)")
	}
	// mos_lqo/pesq_raw/reference are *T: a nil *T stored directly into a
	// map[string]any is a NON-NIL interface value (Go's typed-nil gotcha), which
	// would render as a present-but-non-null field instead of §10.10's null. Each
	// is unwrapped into an `any` explicitly so a nil pointer becomes the untyped
	// interface nil this wave's tier-1-only response requires.
	var mosLQO, pesqRaw, reference any
	if qv.MOSLQO != nil {
		mosLQO = *qv.MOSLQO
	}
	if qv.PESQRaw != nil {
		pesqRaw = *qv.PESQRaw
	}
	if qv.Reference != nil {
		reference = *qv.Reference
	}
	return map[string]any{
		"tier":                 qv.Tier,
		"codec":                qv.Codec,
		"duration_ms":          c.DurationMS(t.m.clk.Now()),
		"packets_sent":         qv.PacketsSent,
		"packets_received":     qv.PacketsReceived,
		"packets_lost":         qv.PacketsLost,
		"loss_pct":             qv.LossPct,
		"out_of_order":         qv.OutOfOrder,
		"duplicates":           qv.Duplicates,
		"late_discards":        qv.LateDiscards,
		"rogue_source_packets": qv.RogueSourcePackets,
		"tx_underruns":         qv.TXUnderruns,
		"srtp_auth_failures":   qv.SRTPAuthFailures,
		"burst_gaps":           qv.BurstGaps,
		"jitter_ms_avg":        qv.JitterMsAvg,
		"jitter_ms_peak":       qv.JitterMsPeak,
		"r_factor":             qv.RFactor,
		"mos_estimate":         qv.MOSEstimate,
		"mos_lqo":              mosLQO,
		"pesq_raw":             pesqRaw,
		"reference":            reference,
	}, nil
}

// ---- §10.9 Media -------------------------------------------------------------

// MediaPlay is §10.9: {ok, prompt, duration_ms, started_at_ms}. The prompt name
// is resolved and validated inside sipua against policy prompts:; an unregistered
// name returns invalid_argument. wait_complete defaults to true.
func (t *ToolService) MediaPlay(ctx context.Context, sess string, in MediaPlayInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	repeat := in.Repeat
	if repeat < 1 {
		repeat = 1
	}
	waitComplete := true
	if in.WaitComplete != nil {
		waitComplete = *in.WaitComplete
	}
	startedAt := t.m.clk.Now().UnixMilli()
	dur, err := ua.Agent().Play(t.m.daemonCtx, c.DialogID(), in.Prompt, repeat, waitComplete)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"prompt": in.Prompt, "duration_ms": dur, "started_at_ms": startedAt,
	}, nil
}

// MediaRecordStart is §10.9: {ok, name, started_at_ms}. The artifact call dir is
// ensured first (§13.1). name defaults per-call in sipua (recording.wav, ...).
func (t *ToolService) MediaRecordStart(ctx context.Context, sess string, in MediaRecordStartInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	if t.m.artifacts == nil {
		return nil, apierr.NotSupported("no artifact store in this build")
	}
	callHandle := string(c.Handle())
	if err := t.m.artifacts.OpenCallDir(t.m.daemonCtx, callHandle); err != nil {
		return nil, err
	}
	// §13.3's watermark guard is enforced inside sipua.UA.RecordStart (the single
	// choke point shared with a media_plan's record step); this just propagates
	// whatever error it returns.
	name, err := ua.Agent().RecordStart(t.m.daemonCtx, c.DialogID(), callHandle, in.Name)
	if err != nil {
		return nil, err
	}
	now := t.m.clk.Now()
	c.Append(now, EventRecordStart, map[string]any{"name": name})
	return map[string]any{"name": name, "started_at_ms": now.UnixMilli()}, nil
}

// MediaRecordStop is §10.9:
//
//	{ok, name, duration_ms, bytes, uri, format:{sample_rate:8000, channels:1, bits:16}}
func (t *ToolService) MediaRecordStop(ctx context.Context, sess string, in MediaRecordStopInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	info, dur, err := ua.Agent().RecordStop(t.m.daemonCtx, c.DialogID(), string(c.Handle()), in.Name)
	if err != nil {
		return nil, err
	}
	c.Append(t.m.clk.Now(), EventRecordStop, map[string]any{
		"name": info.Name, "duration_ms": dur, "bytes": info.Bytes, "uri": info.URI,
	})
	return map[string]any{
		"name": info.Name, "duration_ms": dur, "bytes": info.Bytes, "uri": info.URI,
		"format": map[string]any{"sample_rate": 8000, "channels": 1, "bits": 16},
	}, nil
}

// ---- §10.8 DTMF --------------------------------------------------------------

// checkDTMFSendBounds is dtmf_send's half of §10.8's input contract, and it is
// DELIBERATELY THE SAME CONTRACT decodeDTMF applies to a media_plan `dtmf` step
// (mediaplan_validate.go). Both surfaces pre-render len(digits) x (duration_ms +
// gap_ms) of PCM or telephone-event ticks before a single packet leaves, so both
// answer the same three rejections, and the budget charged here is LITERALLY
// the plan path's own: checkDTMFRenderBudget (mediaplan_validate.go) is the one
// copy of the formula and both surfaces call it, rather than each writing out
// limits.max_call_duration_s arithmetic of their own (Rule 18). Writing it
// twice is how the uncapped-policy hole below came to exist on both surfaces at
// once.
//
// Without it the discrete tool was strictly weaker than the plan step wrapping
// the identical operation: only duration_ms was capped (in sipua), so
// {"digits":"1","gap_ms":60000000} pre-rendered ~3,000,000 silence frames —
// roughly 1 GB — inside one codec.NewDTMFSource call and OOM-killed the daemon,
// taking every other live call with it. The same payload stayed reachable under
// `max_call_duration_s: 0` until the budget grew its own ceiling; see
// dtmfRenderCeilingMs, now a standalone 300,000ms constant (P4-N01, Phase 4
// W1 M2) rather than a figure derived from max_call_duration_s's default.
//
// THIS FUNCTION IS UNTOUCHED BY max_step_duration_s (Inputs §4/RN-1, same
// wave). That key bounds a media-plan step's declared or derived length, and
// dtmf_send is not a media-plan step — decodeDTMF's sibling render-budget
// check for a `dtmf` step CAN name a tighter bound than this function does
// for the same oversized payload; both still reject it, just not necessarily
// with the same bound name (mediaplan_validate_test.go).
//
// OUT OF RANGE IS REJECTED, NEVER DEFAULTED. ResolveDTMFTiming's "unset"
// encoding (durationMs <= 0, gapMs < 0) exists for a caller who named NO value;
// letting an explicit -5 fall into it silently rewrites the caller's argument,
// which is exactly how the two surfaces came to give different answers to one
// input. An omitted duration_ms is still indistinguishable from an explicit 0 —
// the field is a plain int (input.go) — so 0 keeps meaning "unset" here and only
// negatives are rejected; gap_ms is a pointer, so its absence is nil and an
// explicit negative is always visible.
func checkDTMFSendBounds(in DTMFSendInput, maxCallDurationS int) error {
	if in.DurationMs < 0 {
		return apierr.InvalidArgument(fmt.Sprintf(
			"dtmf_send: duration_ms %d must be > 0; omit duration_ms for the default of %dms",
			in.DurationMs, DefaultDTMFDurationMs))
	}
	if in.GapMs != nil && *in.GapMs < 0 {
		return apierr.InvalidArgument(fmt.Sprintf(
			"dtmf_send: gap_ms %d must be >= 0; omit gap_ms for the default of %dms",
			*in.GapMs, DefaultDTMFGapMs))
	}
	gapIn := int64(DTMFGapUnset)
	if in.GapMs != nil {
		gapIn = int64(*in.GapMs)
	}
	dur, gap := ResolveDTMFTiming(int64(in.DurationMs), gapIn)
	if err := checkDTMFRenderBudget(in.Digits, dur, gap, maxCallDurationS); err != nil {
		return apierr.InvalidArgument("dtmf_send: " + err.Error())
	}
	return nil
}

// DTMFSend is §10.8: {ok, digits_sent, mode, duration_ms}.
//
// IT VALIDATES ONLY WHAT SIPUA CANNOT. The digit alphabet, the mode enum, the
// answered precondition and telephone-event availability are all decided in one
// place — sipua.UA.SendDTMF, the single choke point shared with a media_plan's
// dtmf step — and this handler propagates whatever error that returns, exactly
// as MediaRecordStart does for §13.3's watermark guard. The one exception is
// checkDTMFSendBounds above: its budget is a POLICY value sipua cannot see, and
// leaving it out is what let a single tool call OOM the daemon. See its comment.
//
// `mode` is passed through EMPTY when the agent omitted it, so the profile
// default is applied by sipua rather than being resolved twice; the mode
// REPORTED back is the call's effective mode read after the send.
//
// gap_ms is forwarded as sipua's TRI-STATE int: nil (absent) becomes the negative
// "unset" sentinel, and an explicit 0 is forwarded AS 0, because "no gap" and "no
// preference" are different requests and only sipua's one resolver collapses
// them. duration_ms in the response is the EMITTED figure sipua returns, not
// in.DurationMs — the same fact-not-intention rule digits_sent obeys.
func (t *ToolService) DTMFSend(ctx context.Context, sess string, in DTMFSendInput) (any, error) {
	// BEFORE ResolveCall, and before anything renders: an out-of-range argument
	// is a caller error that must not reach the pre-render, and the check has no
	// side effects to sequence against the registries (CallReject validates its
	// status the same way).
	if err := checkDTMFSendBounds(in, t.m.policy.Current().Limits.MaxCallDurationS); err != nil {
		return nil, err
	}
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	ua, err := t.m.ResolveUA(ctx, sess, c.UAHandle())
	if err != nil {
		return nil, err
	}
	// The send goes out on the DAEMON context, like every other media tool in
	// this file (MediaPlay, MediaRecordStart): a client disconnect must not
	// truncate a digit string mid-flight and leave the far end holding a tone.
	// This is the existing ToolService convention, not a §9 locked decision.
	gapMs := DTMFGapUnset // NOT a literal -1: the one sentinel, see collaborators.go
	if in.GapMs != nil {
		gapMs = *in.GapMs
	}
	sent, emittedDurationMs, err := ua.Agent().SendDTMF(t.m.daemonCtx, c.DialogID(), in.Digits,
		DTMFMode(in.Mode), in.DurationMs, gapMs)
	if err != nil {
		// F4(a): a partial send's progress must reach the caller even on
		// error — a double-send into an IVR is the alternative, since a
		// caller who cannot tell whether 0 or 5 digits landed cannot safely
		// retry. apierr.Error.Detail is already copied unconditionally into
		// the MCP envelope (envelope.go), so attaching it here is the only
		// change needed; the error's Code/Message/Rule/Limit are untouched.
		var ae *apierr.Error
		if errors.As(err, &ae) {
			if ae.Detail == nil {
				ae.Detail = map[string]any{}
			}
			ae.Detail["digits_sent"] = sent
			ae.Detail["duration_ms"] = emittedDurationMs
		}
		return nil, err
	}
	mode := in.Mode
	if mode == "" {
		if effective, ok := ua.Agent().DTMFMode(c.DialogID()); ok {
			mode = effective
		}
	}
	return map[string]any{
		"digits_sent": sent, "mode": mode, "duration_ms": emittedDurationMs,
	}, nil
}

// DTMFReceived is §10.8: {ok, digits:[{digit, at_ms, duration_ms, mode}], next_since}.
//
// IT READS session.Call ONLY, AND THAT IS THE POINT (§2.3). Reading the UA
// instead would make it fail the moment teardownDialog forgets the dialog — the
// same defect call_status.media_plan carried until this phase. Reading the call
// means it answers a terminated call for as long as the registry holds it, and
// returns `gone` only after §N3 eviction — which ResolveCall already does for
// every per-call tool, so there is no error handling of its own here.
//
// next_since is a SEQ CURSOR, matching call_events' pagination exactly
// (decision 16): pass it back as `since` to drain only what has arrived since.
func (t *ToolService) DTMFReceived(ctx context.Context, sess string, in DTMFReceivedInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	digits, nextSince := c.DigitsSince(in.Since)
	return map[string]any{"digits": digits, "next_since": nextSince}, nil
}

// ---- §10.11 Trace -----------------------------------------------------------

// CallLadder is §10.11: {ok, format, ladder, messages, truncated}.
//
// ALWAYS AVAILABLE, NO ARMING (D9a). There is no enable flag and no policy key
// that turns the ladder off.
func (t *ToolService) CallLadder(ctx context.Context, sess string, in CallLadderInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	format := LadderFormat(defaultStr(in.Format, string(LadderText))) // §10.11: text is the default
	switch format {
	case LadderText, LadderMermaid, LadderJSON:
	default:
		return nil, apierr.InvalidArgument(fmt.Sprintf(
			"format %q is not text, mermaid or json", in.Format))
	}
	if t.m.tap == nil {
		return nil, apierr.NotSupported("no trace sink is installed in this build")
	}
	// THE TAP IS KEYED BY (UA HANDLE, SIP Call-ID), NOT BY THE CALL HANDLE (U7;
	// HIGH-3). Both come from the call the session-scoped ResolveCall above
	// returned: c.UAHandle() is the call's OWN owning UA and c.CallID() its
	// own Call-ID. call_ladder takes no ua_handle input (CallLadderInput has
	// only Call + Format), so an agent CANNOT widen access to a foreign UA's
	// ring — the UA identity is resolved server-side from its own call handle.
	l, err := t.m.tap.Ladder(ctx, string(c.UAHandle()), c.CallID(), format)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"format":    string(l.Format),
		"ladder":    l.Rendered,
		"messages":  l.Messages,
		"truncated": l.Truncated,
	}, nil
}

// CaptureStart is §10.11 (D9b): {ok, name, scope, payload_mode, started_at_ms}.
//
// finding NEW-2 — ALL VALIDATION RUNS BEFORE THE STORE Create, so a rejected
// arm never creates an (O_EXCL-orphaning) capture.pcap. This wave supports
// signaling-only, plaintext capture only; §10.11 also names "media"/"both" and
// "ciphertext", which arrive at W4/P4 respectively.
func (t *ToolService) CaptureStart(ctx context.Context, sess string, in CaptureStartInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	scope := defaultStr(in.Scope, "signaling") // §10.11 default is "both"; W2 supports "signaling" only
	mode := defaultStr(in.PayloadMode, "plaintext")
	if t.m.artifacts == nil || t.m.tap == nil {
		return nil, apierr.NotSupported("no artifact store / trace sink in this build")
	}
	// ---- validate EVERYTHING before creating the exclusive file (finding NEW-2) ----
	if scope != "signaling" {
		return nil, apierr.NotSupported("capture scope " + scope + " arrives with the RTP path in W4; W2 captures signaling only")
	}
	if mode != "plaintext" {
		return nil, apierr.NotSupported("ciphertext capture is P4; W2 captures plaintext only")
	}
	maxBytes := t.m.policy.Current().Capture.MaxBytesPerCall
	if maxBytes > 0 && maxBytes < 24 { // pcap global header; policy load-validation also rejects this
		return nil, apierr.InvalidArgument("capture.max_bytes_per_call must be 0 (unbounded) or at least 24")
	}
	if c.CallID() == "" { // a still-dialing call has no Call-ID yet; nothing to key/arm
		return nil, apierr.PreconditionFailed("call has no SIP Call-ID yet; cannot arm capture")
	}
	// ---- only now create the exclusive file; validation above cannot fail after this ----
	callHandle := string(c.Handle())
	if err := t.m.artifacts.OpenCallDir(t.m.daemonCtx, callHandle); err != nil {
		return nil, err
	}
	w, err := t.m.artifacts.Create(t.m.daemonCtx, callHandle, "capture.pcap")
	if err != nil {
		// finding 1a: O_EXCL Create fails os.ErrExist when capture.pcap already
		// exists (a capture is/was armed for this call) — a clean
		// precondition_failed, never a truncation.
		if errors.Is(err, os.ErrExist) {
			return nil, apierr.PreconditionFailed("a capture is already armed for this call")
		}
		return nil, err
	}
	cfg := CaptureConfig{Scope: scope, PayloadMode: mode, MaxBytes: maxBytes}
	if err := t.m.tap.ArmCapture(t.m.daemonCtx, string(c.UAHandle()), c.CallID(), w, cfg); err != nil {
		// ROLLBACK (finding NEW-2 residual): ArmCapture is an interface — the
		// fake defaults to not_supported and the real Sink can error. A created
		// file with NO live armed capture would orphan (O_EXCL blocks every
		// retry as "already armed"). So close AND Remove before returning: a
		// failed arm leaves NO file.
		_ = w.Close()
		_ = t.m.artifacts.Remove(t.m.daemonCtx, callHandle, "capture.pcap")
		return nil, err
	}
	// §10.11 (L991) capture_start response shape — normative. NOT
	// {call_handle, capture_armed}.
	return map[string]any{
		"name":          "capture.pcap",
		"scope":         scope, // normalized: "signaling" this wave
		"payload_mode":  mode,  // normalized: "plaintext" this wave
		"started_at_ms": t.m.clk.Now().UnixMilli(),
	}, nil
}

// CaptureStop is §10.11 (D9b):
//
//	{ok, name, bytes, packets, truncated, signaling_ciphertext, capture_fidelity, uri}
//
// This works even after the call terminated: DisarmCapture is idempotent and
// returns the cached counters (Task 3), and artifacts.Close just stats the
// already-closed file.
func (t *ToolService) CaptureStop(ctx context.Context, sess string, in CaptureStopInput) (any, error) {
	c, err := t.m.ResolveCall(ctx, sess, Handle(in.Call))
	if err != nil {
		return nil, err
	}
	if t.m.artifacts == nil || t.m.tap == nil {
		return nil, apierr.NotSupported("no artifact store / trace sink in this build")
	}
	res, err := t.m.tap.DisarmCapture(t.m.daemonCtx, string(c.UAHandle()), c.CallID())
	if err != nil {
		return nil, err
	}
	callHandle := string(c.Handle())
	info, err := t.m.artifacts.Close(t.m.daemonCtx, callHandle, res.Name)
	if err != nil {
		return nil, err
	}
	uri := t.m.artifacts.URI(callHandle, res.Name)
	return map[string]any{
		"name":                 res.Name,
		"bytes":                info.Bytes,
		"packets":              res.Packets,
		"truncated":            res.Truncated,
		"signaling_ciphertext": res.SignalingCiphertext,
		"capture_fidelity":     res.CaptureFidelity,
		"uri":                  uri,
	}, nil
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
