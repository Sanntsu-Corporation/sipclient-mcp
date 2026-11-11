// Package session owns handles, lifecycle, event ordering, the §6.3 waiter
// lifecycle, the §N3 retention janitor and §12.6 session identity.
//
// This file declares the four narrow interfaces of spec §6.2.1 that are the
// COMPLETE set of outbound dependencies session has on the engine layer:
// anything not reachable through them is not reachable from session at all.
// They are declared HERE, consumer-side, and satisfied by internal/sipua,
// internal/media, internal/trace and internal/artifact — so session imports
// none of those packages and each collaborator is independently fakeable.
//
// Four rules govern every change to this file:
//
//  1. No sipgo, pion/rtp, sipengine, SDP or codec type may appear in any
//     signature. Negotiation results cross as plain structs (§6.2.1). The
//     import-boundary test in internal/importguard fails the build if one
//     does. internal/policy is the ONE permitted first-party import (U9):
//     it is a leaf below session, and UAConfig.AuthPass must name
//     policy.Secret for the redaction guarantee of B2 to hold.
//  2. An explicit context.Context is the FIRST parameter of every method
//     (locked decision 17). The one exception is URI, which formats a string
//     and cannot fail. Callback registrations take the LONG-LIVED DAEMON
//     context, never an HTTP request context: wiring a request context into
//     a call's lifetime would break D11 point 5 and R8, and decision 17
//     flags it as the most likely P1 correctness bug.
//  3. UserAgent is TRANSPORT-NEUTRAL (obligation O1, §15.1): transport is an
//     explicit parameter and never a literal. No method name, field or
//     constant here may be transport-specific.
//  4. MediaSession and ArtifactStore carry their FULL §6.2.1 surface even
//     though P1 wires no media and no artifacts. Trimming them would force P2
//     to reshape session, which is the forward dependency §6.2.1 exists to
//     prevent. P1 installs NOTHING for either: ManagerConfig and Manager carry
//     no field for them, so neither interface is reachable from production at
//     all, and the only implementations are internal/testutil/fakes. (This
//     previously read "installs no-op implementations of both", which was never
//     true — Rule 13 Cycle 1, D383.)
//
// Owed compile-time satisfaction assertions (not written by this task, because
// their concrete types do not exist yet and importing them from session would
// invert §6.2's layering; each belongs in a _test.go file of the package that
// defines the concrete type):
//
//	var _ session.UserAgent     = (*sipua.UA)(nil)        internal/sipua/assert_test.go    Task 13
//	var _ session.Tap           = (*trace.Sink)(nil)       internal/trace/assert_test.go    Task 16
//	var _ session.MediaSession  = (*media.Session)(nil)    internal/media/assert_test.go    P2
//	var _ session.ArtifactStore = (*artifact.Store)(nil)   internal/artifact/assert_test.go P2
//
// The concrete Tap implementation is named trace.Sink, NOT trace.Tap: a
// trace.Tap would collide confusingly with session.Tap, the interface it
// satisfies. The MediaSession and ArtifactStore assertions cannot be written
// at P1 at all — internal/media and internal/artifact are P2 packages and no
// concrete type exists yet to assert against; P1 declares both interfaces in
// full and installs neither (see rule 4 above).
package session

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// ---- shared plain types ----------------------------------------------------

// Handle is an opaque UA or call handle: a "ua_"/"call_" prefix plus 64 bits
// of crypto/rand as hex (decision 12). Handles are NEVER reused.
//
// THE PREFIX IS FOR LOG READABILITY ONLY AND MUST NEVER BE PARSED FOR
// AUTHORIZATION. Ownership is decided solely by registry membership of the
// owning logical session (§12.2, §12.6).
//
// Session ids are a SEPARATE construct: §12.6 specifies 128-bit CSPRNG hex,
// UNPREFIXED. They are minted in transport/mcp, not here.
type Handle string

// Transport is a SIP signalling transport. It is a parameter everywhere it
// appears; obligation O1 forbids a transport literal in any signature here.
type Transport string

// The three transports UAConfig.Transport may name.
const (
	TransportUDP Transport = "udp"
	TransportTCP Transport = "tcp"
	TransportTLS Transport = "tls"
)

// Direction is the direction of a call or of a captured message. It is a
// TYPE, not a bare string, so a record cannot carry "in"/"inbound" variants
// that a renderer then has to normalise.
type Direction string

// The two Direction values.
const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
)

// CallState is §10.3's call state set. THIS IS THE ONLY DECLARATION OF CALL
// STATE IN THE PROJECT (Rule 18). internal/sipua exports no CallState: it
// emits protocol-level UAEvents and session maps them onto this machine, in
// one place.
type CallState string

// The five CallState values.
const (
	StateDialing    CallState = "dialing"
	StateRinging    CallState = "ringing"
	StateAnswered   CallState = "answered"
	StateTerminated CallState = "terminated"
	StateFailed     CallState = "failed"
)

// TerminationReasons is §10.3's exhaustive enum, in document order.
// metrics.New takes it as the label set for calls_by_termination_reason, so a
// typo becomes a panic in a test rather than a counter that never appears in
// /metrics.
var TerminationReasons = []string{
	"local_hangup", "remote_bye", "rejected_locally", "inbound_ring_timeout",
	string(apierr.CodeCancelled), "policy_timeout", "session_timer_expired", "transport_failure",
	"media_negotiation_failed",
}

// UAConfig is everything sipua needs to construct a user agent. It carries
// no sipgo type and no credential file path: the caller has already resolved
// credentials through policy.Credentials.
type UAConfig struct {
	// Handle is the owning UA's handle, minted by CreateUA BEFORE the factory
	// builds the agent and passed down so the per-UA tap (sipua.ObservingConn)
	// can stamp it into every SIPRecord (HIGH-3: the sink keys by
	// (ua_handle, call_id) so a peer-chosen Call-ID cannot collide two UAs'
	// ladders). It is the same value as (*UA).Handle(), already exposed as
	// ua_handle in ua_status, so carrying it here reveals nothing new.
	Handle    Handle
	Mode      string    // "register" | "direct"
	Transport Transport // O1: an explicit parameter, NEVER a literal
	LocalAddr string    // caller-supplied local_addr; may be "", wildcard or bare port
	AOR       string
	AuthUser  string
	// AuthPass is a policy.Secret, NOT a string. THIS TYPE IS A SECURITY
	// CONTROL AND MUST NOT BE WIDENED (B2).
	//
	// policy.Secret exists so that String, GoString, MarshalJSON and LogValue
	// all render "[REDACTED]". Typing this field as a plain string discards
	// every one of those hooks at exactly the wrong place: UAConfig is
	// reachable through (*UA).Config() and so feeds ua_status and
	// AdminUAView payloads, and locked decision 5 threads a *slog.Logger
	// through every package. ONE `%+v` or one slog.Any of a UAConfig would
	// then fail §14.2's "no credential appears in any tool response or log
	// line" and N5's grep-for-auth_pass assertion.
	//
	// Getting the plaintext out requires an explicit call to policy.Secret's
	// Reveal method, which is greppable — and internal/importguard asserts it
	// appears exactly once outside internal/policy.
	AuthPass  policy.Secret
	Registrar string
	// ExpiresS is the REQUESTED registration expiry in seconds (see
	// sipua.Config.ExpiresS). The GRANTED value is RegisterResult.ExpiresS.
	ExpiresS  int      // REQUESTED
	Keepalive string   // "none" | "crlf" | "options"
	CodecPref []string // [P2]
	SRTP      string   // [P4] "disabled" | "optional" | "required"
	// AllowCleartextSDES records ua_create's allow_cleartext_sdes so a per-call
	// srtp override is checked against the same rule (CF-170).
	AllowCleartextSDES bool

	InboundRingTimeout time.Duration // limits.inbound_ring_timeout_s (R14)
	Timeout            time.Duration // per-transaction timeout

	// DTMFMode/SessionExpiresS/MinSES/KeepaliveIntervalS/SessionRefreshMethod
	// are per-UA settings. As of Phase 1's session-scoped UA lifecycle they
	// arrive as ua_create's own INLINE fields (D6), like AOR and the
	// credentials, rather than being resolved server-side from a
	// policy.yaml profile name (the pre-Phase-1 model this comment used to
	// describe). The only per-call override remains dtmf_send's own `mode`.
	DTMFMode             string // "rfc2833" (default) | "inband" | "info"
	SessionExpiresS      int    // REQUESTED RFC 4028 interval; 0 => 1800
	MinSES               int    // Min-SE floor; 0 => 90
	KeepaliveIntervalS   int    // NAT keepalive period; 0 => 30
	SessionRefreshMethod string // "auto" (default) | "update" | "invite"

	// AuthAnyHost is ua_create's auth_any_host (CF-046): answer an INVITE digest
	// challenge from any host, not only the registrar/AOR host.
	AuthAnyHost bool
}

// ---- UserAgent (satisfied by internal/sipua) -------------------------------

// RegisterResult carries NO credential field and MUST NEVER gain one (D6).
type RegisterResult struct {
	Registered bool
	Code       int
	Reason     string
	// ExpiresS is the expiry the registrar GRANTED on the INITIAL REGISTER.
	// Refreshes report their own grant through UAEvent.ExpiresS.
	ExpiresS int
	Contact  string
}

// DialRequest is the outbound dial the UA is asked to place.
type DialRequest struct {
	// SRTP is the per-call srtp override ("" = the UA's policy), validated by
	// session's perCallSRTP: it may only tighten the UA's policy (CF-170).
	SRTP     string
	ToURI    string
	FromUser string
	Headers  map[string]string
	// SDPOffer is the offer body. NIL at P1 — sipua synthesises the fixed
	// single-codec PCMU body from its own bound address. P2 populates it from
	// the real negotiator. CallHandle (below) is the one exception: an opaque,
	// uninterpreted string sipua never parses or branches on, added by W5
	// solely so media_plan's record step can key artifacts the same way the
	// discrete tools do — it does not couple sipua to session.Handle's type,
	// and the layering §6.2.1 protects still holds.
	SDPOffer []byte

	// OnDialogBound is called ONCE, SYNCHRONOUSLY, at the instant the UA has
	// minted the dialog id and the Call-ID but BEFORE it has started anything
	// that can emit a UAEvent for them. It is OPTIONAL: nil means "do not call
	// me", and every implementation MUST tolerate nil.
	//
	// IT CLOSES A LOST-EVENT RACE, AND IT IS NOT A CONVENIENCE. `Dial` is
	// asynchronous by contract (N2's budget): it spawns the INVITE and returns.
	// So the only binding a caller had was DialResult on Dial's RETURN, and on
	// loopback against a peer that answers instantly the whole INVITE/200/ACK
	// exchange completes in ~1 ms — INSIDE that window. Every event emitted in
	// it arrives at a Manager that cannot yet map DialogID to a *Call, and
	// (*Manager).handleResponse drops it silently. The far end then holds our
	// ACK and believes the call is up while the MCP client sees `dialing`
	// forever with an empty last_response: a desynchronised live call, not a
	// clean failure.
	//
	// The window CANNOT be narrowed away, only closed: the ids exist before
	// the spawn, so the bind belongs before the spawn. Reproduced 1-in-10,000
	// full-stack dials, with the dropped 200 captured at the socket seam.
	//
	// THE CALLBACK MUST NOT BLOCK AND MUST TAKE NO LOCK THE UA HOLDS: it runs
	// on Dial's own goroutine, inside Dial, and the UA has already registered
	// the dialog when it fires. It receives the same two values DialResult
	// carries, and they are the SAME dialog — a caller may bind on either, and
	// binding on both is idempotent.
	//
	// It takes no context: it is a pure in-memory bind on the caller's side,
	// performs no I/O and cannot fail, which is decision 17's stated exception
	// (the same one UserAgent.URI and ArtifactStore.URI take).
	OnDialogBound func(dialogID, callID string)

	// MediaPlan is the OPTIONAL §10.7 plan, VALIDATED by session before this call.
	// sipua stores it on the dialog and launches the executor at the same
	// publish-and-launch critical section as the media loop (§3.5). Empty means no
	// plan.
	MediaPlan []MediaPlanStep

	// CallHandle is the session-level call handle (string(c.Handle())), resolved
	// server-side by ToolService and never agent-supplied. sipua stores it
	// opaquely on the dialog and passes it through to Store.Create/Close so a
	// media_plan's record step and the discrete media_record_* tools key the
	// same call's artifacts identically (§3.4/§3.5). sipua never parses or acts
	// on its contents.
	CallHandle string

	// CallLimit is the most concurrent calls this dial's UA may legitimately
	// hold: session sets it to min(max_concurrent_calls_per_session,
	// max_concurrent_calls_total), read live once per dial. sipua refuses the
	// dial (apierr.DeniedLimit, rule "ua_live_dialogs") when the UA already
	// holds that many dialogs plus a fixed internal headroom for hung-up dials
	// still being torn down. 0 means unbounded (every direct caller and fake).
	CallLimit int

	// MaxRedirects is how many new INVITEs this dial may send to 3xx redirect
	// targets (CF-090); 0 follows none. A snapshot of limits.max_redirects at
	// dial time, while CheckRedirect reads the live policy.
	MaxRedirects int
	// CheckRedirect validates one redirect target exactly as to_uri is
	// validated and returns the string to dial. nil means no redirect is
	// followed (fail closed). Same calling rules as OnDialogBound: it must not
	// block on, or take, a lock the UA holds; sipua calls it on the dial
	// goroutine holding no lock.
	CheckRedirect func(target string) (string, error)
}

// DialResult is what Dial hands back once the dialog is established.
type DialResult struct {
	DialogID string
	// CallID is the SIP Call-ID. REQUIRED, not informational: §2.5.4 declares
	// (*Call).CallID() to be the Tap's ladder key, and U7 keys every per-call
	// Tap method by it — so without this field `session` has no channel by
	// which to learn it, `call_ladder` cannot find its ladder, and Task 10's
	// janitor cannot call Tap.Evict, so a terminated call's ring is held
	// until the LRU reaches it rather than being freed promptly. (§N3's
	// bound itself is limits.max_ladders + LRU over the UNRETAINED rings,
	// not Evict — U15 as amended by U18.)
	//
	// IT IS ALSO THE CHANNEL FOR Tap.Retain (U18): the outbound path calls
	// Retain with this value at dialog establishment, so without the field
	// there is nothing to retain with and the LRU evicts the live call's own
	// ladder. UAEvent.CallID is the inbound half.
	// `sipua` is the only package that ever sees the Call-ID; this field and
	// UAEvent.CallID are the only two ways it reaches `session`.
	CallID string
}

// AnswerRequest is the request to answer an inbound dialog.
type AnswerRequest struct {
	DialogID string
	// SRTP is the per-call srtp override, as DialRequest.SRTP.
	SRTP string
	// SDPAnswer is nil at P1 — same synthesis rule as DialRequest.SDPOffer.
	SDPAnswer []byte

	// MediaPlan is the OPTIONAL §10.7 plan, VALIDATED by session before this call.
	// sipua stores it on the dialog and launches the executor at the same
	// publish-and-launch critical section as the media loop (§3.5). Empty means no
	// plan.
	MediaPlan []MediaPlanStep

	// CallHandle is the session-level call handle (string(c.Handle())), resolved
	// server-side by ToolService and never agent-supplied. sipua stores it
	// opaquely on the dialog and passes it through to Store.Create/Close so a
	// media_plan's record step and the discrete media_record_* tools key the
	// same call's artifacts identically (§3.4/§3.5). sipua never parses or acts
	// on its contents.
	CallHandle string

	// OnAnswered is the OPTIONAL hook the UA calls once, synchronously, when its
	// 200 OK is on the wire and the dialog is answered, before any media or
	// timer starts (the DialRequest.OnDialogBound pattern). session records the
	// call's `answered` event here, so a refused answer (AnswerRefusedError)
	// never produces one. A UA that never calls it is covered by CallAnswer's
	// own NoteAnswered after Answer returns nil.
	OnAnswered func()
}

// AnswerRefusedError is returned by UserAgent.Answer when it tore the dialog
// down instead of answering it: the 400, 422, 488 or 500 it sent (CF-131). Status
// and Reason are the SIP final it sent. Err is the error the agent sees, whose
// apierr code is preserved through Unwrap.
type AnswerRefusedError struct {
	Status int
	Reason string
	Err    error
}

func (e *AnswerRefusedError) Error() string { return e.Err.Error() }
func (e *AnswerRefusedError) Unwrap() error { return e.Err }

// UAEventKind enumerates what a UA delivers upward. Provisional and final
// responses, refreshes, transport faults and dialog terminations all arrive
// through the single one-way callback registered by OnEvent. UAEventInbound is
// the one exception: an inbound INVITE is admitted through the SYNCHRONOUS
// OnAdmit channel (I2), which returns an Admission verdict, so this kind is
// carried on the AdmitFunc's UAEvent rather than delivered one-way.
type UAEventKind string

// The sixteen UAEventKind values.
const (
	UAEventInbound        UAEventKind = "inbound"
	UAEventProvisional    UAEventKind = "provisional"
	UAEventFinal          UAEventKind = "final"
	UAEventRefresh        UAEventKind = "refresh"
	UAEventTransportFault UAEventKind = "transport_fault"

	// UAEventDialogEnded reports that the dialog ended for a reason `session`
	// cannot observe from any other kind. Added by U14.
	UAEventDialogEnded UAEventKind = "dialog_ended"

	// UAEventMediaError is THE GENERIC NON-TERMINAL, PER-DIALOG ERROR CHANNEL,
	// and its name is narrower than its contract. It carries any condition that
	// (a) concerns ONE dialog, (b) deserves a §10.5 `error` event in that call's
	// log, and (c) does NOT end the call. handleMediaError appends ev.Detail
	// verbatim as an EventError; the ONLY call state it touches is the
	// media_plan view, and only for the one kind applyPlanError recognizes
	// (plan_aborted_call_terminated) — every other kind is log-only.
	//
	// Its detail is DISCRIMINATED BY detail.kind, which is what makes one kind
	// sufficient. The kinds in use:
	//
	//	tx_underrun                   the TX ticker skipped frames (§6.5.2, P2)
	//	plan_aborted_call_terminated  the plan executor's abort (P2 W5)
	//	plan_step_failed              a §10.7 step failed; the plan stopped
	//	wait_dtmf_mismatch            collected digits != expected (P3, decision 14)
	//
	// Task 29 adds session_refresh_failed here — an RFC 4028 refresh rejected,
	// or its send failed, with the dialog SURVIVING (P3, §4). It is named now
	// only as the second non-media user of this channel; it is not emitted yet.
	//
	// DO NOT ADD A NEW UAEventKind for a new non-terminal per-dialog condition:
	// add a `kind` here. Conversely, a condition that ENDS the dialog does NOT
	// belong on this channel — that is UAEventDialogEnded with a cause, and the
	// two are not interchangeable (a §11.3.1 in-dialog timeout ends the call and
	// therefore uses the latter; see Task 29).
	UAEventMediaError UAEventKind = "media_error"

	// UAEventMediaStart is the first authenticated RX packet on an answered
	// call: session appends EventMediaStart. It carries the negotiated local
	// media address, the observed remote address, and whether TX latched to a
	// source distinct from the signalled one (R10).
	UAEventMediaStart UAEventKind = "media_start"

	// UAEventPlanStep carries a §10.7 media_plan step event (entry or completion).
	// Detail: {index int, op string, status? string} — status "ok"/"failed" on a
	// completion, absent on entry. session appends EventPlanStep with ev.Detail.
	UAEventPlanStep UAEventKind = "plan_step"

	// UAEventRecordStart/UAEventRecordStop carry §10.5's record_start/record_stop
	// for a media_plan's record step (Task 10 maps each to the matching
	// EventType with ev.Detail passed through unchanged), matching the
	// UAEventMediaStart/EventMediaStart naming convention above. The discrete
	// media_record_start/stop tools append their own session events directly
	// (ToolService holds a *Call there) and never go through this path — this
	// pair exists only because sipua's plan executor does not.
	UAEventRecordStart UAEventKind = "record_start"
	UAEventRecordStop  UAEventKind = "record_stop"

	// UAEventDTMF carries one RECEIVED digit up the existing one-way channel
	// (§2.3). There is deliberately NO UserAgent getter for received digits:
	// they land on session.Call, which is what makes dtmf_received answerable
	// after teardown. Fields: Digit, DTMFMode, DurationMs.
	UAEventDTMF UAEventKind = "dtmf"

	// UAEventSessionRefresh reports one completed RFC 4028 refresh (R9).
	// Detail: {method:"UPDATE"|"INVITE", refresher:"uac"|"uas", interval_s, code}.
	UAEventSessionRefresh UAEventKind = "session_refresh"

	// UAEventRegisterFailed reports that the R10 registration refresh exhausted
	// its retry budget: the UA is NO LONGER REGISTERED. Err carries the last
	// failure. It concerns the UA's REGISTRATION STATE and nothing else.
	//
	// IT IS DELIBERATELY NOT UAEventTransportFault. That kind is UA-WIDE and its
	// handler terminates EVERY LIVE CALL on the UA (§11.3.1), which would make a
	// registrar outage end established dialogs whose media and in-dialog
	// signalling never traverse the registrar. A lost registration means we can no
	// longer be REACHED; §10.3 has no termination_reason for "the call ended
	// because a REGISTER went unanswered", and inventing one by reusing
	// transport_failure reports a fault that did not happen to the call.
	//
	// handleRegisterFailed MUST NOT touch s.liveCalls. If a future phase wants a
	// call-affecting consequence of deregistration, it needs its own §10.3 reason
	// and its own spec text — not this kind.
	UAEventRegisterFailed UAEventKind = "register_failed"

	// UAEventRegisterRemoved reports that the REGISTRAR removed the binding on a
	// refresh: it answered 200 OK and granted an expiry of 0 (RFC 3261 §10.2.4 —
	// an administrative deregister, a rebuilt registrar, a policy change). The UA
	// is NO LONGER REGISTERED and has no interval left to refresh against, so its
	// refresh timer is disarmed at the source (sipua's refreshRegister).
	//
	// IT IS DELIBERATELY NOT UAEventRegisterFailed, and the distinction is the
	// whole reason this kind exists. Nothing failed: the registrar was reachable,
	// answered, and answered correctly. That kind carries Err and its handler logs
	// "registration refresh gave up", which would describe an unreachable registrar
	// to an operator — and to any agent consuming the event stream — whose
	// registrar in fact replied 200. The CONSEQUENCE is the same (unregistered, no
	// granted expiry, no countdown), so both handlers land on recordRegistrationLost;
	// the FACT reported is not, so the kinds are separate.
	//
	// It carries no Err. Like UAEventRegisterFailed it concerns the UA's
	// REGISTRATION STATE and nothing else: handleRegisterRemoved MUST NOT touch
	// s.liveCalls, for exactly the reason spelled out above UAEventRegisterFailed —
	// established dialogs do not traverse the registrar.
	UAEventRegisterRemoved UAEventKind = "register_removed"

	// UAEventTransfer reports one call_transfer outcome (spec 2026-09-26 §4.4,
	// master spec §10.14): the REFER's own rejection, each NOTIFY sipfrag
	// status, or the final settle (final NOTIFY, NOTIFY timeout, dialog ended,
	// UA closed). Code/Reason carry the status (0/"" when no wire status was
	// ever received). Detail: {mode, status_code, reason, final, success};
	// session appends it verbatim as a §10.5 `transfer` event. It is its own
	// kind, not a UAEventMediaError `kind`, because it maps onto its own
	// EventType — exactly as UAEventSessionRefresh does.
	UAEventTransfer UAEventKind = "transfer"
)

// UADialogEndCause is the PROTOCOL-LEVEL cause carried by UAEventDialogEnded.
// It is deliberately NOT §10.3's termination_reason: that enum is exhaustive and
// owned by `session`, which maps these causes onto it. Keeping the mapping in
// one place is the same Rule 18 reasoning that stops sipua exporting CallState.
//
// This also regularises an inconsistency the original five kinds carried:
// `transport_fault` was a termination cause with its own kind while every other
// termination cause had none. From P4 it folds in here as a cause.
type UADialogEndCause string

const (
	// UACausePeerBYE — the far end sent BYE in an established dialog.
	// `session` maps it to termination_reason `remote_bye`.
	UACausePeerBYE UADialogEndCause = "peer_bye"
	// UACauseRingTimeout — an inbound call was neither answered nor rejected
	// within limits.inbound_ring_timeout_s, so sipua auto-rejected it 480
	// (R14). `session` maps it to termination_reason `inbound_ring_timeout`.
	UACauseRingTimeout UADialogEndCause = "ring_timeout"
	// UACauseCancelled — the peer sent CANCEL for a still-ringing inbound
	// INVITE (RFC 3261 §9.2), so sipua 487'd the pending INVITE. `session`
	// maps it to termination_reason `cancelled`, deliberately reusing
	// apierr.CodeCancelled's spelling via the constant itself (not a
	// duplicated literal, satisfying §11.2's no-string-literal guard). It
	// remains a distinct concept from apierr.CodeCancelled: this is a UA
	// dialog-end termination_reason, not an MCP-layer apierr.Code.
	UACauseCancelled UADialogEndCause = UADialogEndCause(apierr.CodeCancelled)
	// UACauseMediaNegotiationFailed — an outbound call's 200 OK answered with a
	// codec we did not offer, a downgraded SRTP profile, or absent/unparseable
	// SDP, so sipua ACK'd then BYE'd (§11.2.1). `session` maps it to
	// termination_reason `media_negotiation_failed` and appends an EventError
	// carrying UAEvent.Detail's kind.
	UACauseMediaNegotiationFailed UADialogEndCause = "media_negotiation_failed"
	// UACauseTransportFailure — §11.3.1 CASE 2, DIALOG-SCOPED: an in-dialog
	// request WE sent (P3's session-timer refresh; the BYE of call_hangup is the
	// other) drew NO final response before Timer F, so the peer is unreachable
	// inside the dialog. sipua releases the dialog locally and sends no BYE.
	// `session` maps it to termination_reason `transport_failure` and appends the
	// §11.3.1 error detail (kind/transport/cause) on the terminal event.
	//
	// THIS IS THE EARLY, DIALOG-SCOPED HALF of the fold-in UADialogEndCause's
	// comment reserved for P4, adopted here because §11.3.1 case 2 is P3-scoped
	// (governing spec: "until P3 the only in-dialog request is the BYE of
	// call_hangup"). UAEventTransportFault is NOT retired and is NOT reused: it is
	// UA-WIDE, and its handler terminates every live call on the UA, so routing a
	// single dead dialog through it would reap that UA's healthy calls. What P4
	// still owes is the UA-WIDE half (a closed connection, a failed reestablish),
	// after which the kind can retire.
	//
	// It ALSO carries an OUTBOUND DIAL that drew no usable final response (the
	// INVITE transaction timed out, or the mandatory ACK could not be written),
	// with a nil Detail (CF-037, D-A): dialog-scoped, so a sibling call on the UA
	// is untouched. The call lands `terminated` (not `failed`), with the same
	// terminal `error` event, as the UA-wide sweep gave it before. sipua emits
	// nothing when it sees the caller's hangup first (cancelRequested, read at
	// the teardown's linearization point); a hangup that reaches it only after
	// the teardown is dropped by session (live-only lookup, terminal guard).
	UACauseTransportFailure UADialogEndCause = "transport_failure"
	// UACauseSessionTimerExpired — RFC 4028's session timer expired: the PEER
	// held the refresher role and stopped refreshing, so sipua BYE'd with
	// Reason: SIP;cause=408 (R9, spec §5). `session` maps it to
	// termination_reason `session_timer_expired`.
	//
	// IT IS DISTINCT FROM UACauseTransportFailure (Task 29), and the pair must
	// not be collapsed: this one means the peer stopped REFRESHING but may be
	// perfectly reachable — it answers our BYE — whereas transport_failure means
	// an in-dialog request of ours drew no response at all, so no BYE is even
	// attempted. Different wire behaviour, different §10.3 reason.
	UACauseSessionTimerExpired UADialogEndCause = "session_timer_expired"
	// With both P3 causes wired, the only fold-in P4 still owes is the UA-WIDE
	// half of §11.3.1 (a closed connection, a failed reestablish), after which
	// UAEventTransportFault can retire. The DIALOG-SCOPED half already lives on
	// UACauseTransportFailure above.
)

// UAEvent is PROTOCOL-LEVEL, exactly as §6.2.1 describes it ("inbound
// INVITEs, provisional and final responses, refreshes and transport faults"),
// plus U14's dialog_ended. It carries NO CallState and NO termination_reason:
// mapping protocol facts onto §10.3's call state machine and its
// termination_reason enum is session's job, and keeping that mapping in one
// place is why sipua exports no CallState (Rule 18).
//
// U14's two P1-reachable causes exist because the original five kinds could
// express NEITHER. `remote_bye` is an inbound IN-DIALOG REQUEST, which no kind
// denoted — `inbound` means an inbound INVITE and `final` means a final
// response to a request WE sent. And `inbound_ring_timeout` is a final
// response WE sent on a timer, indistinguishable on the wire from the 480 that
// call_reject(480) sends, so disambiguating by Direction would have collapsed
// two distinct §10.3 reasons into one event.
type UAEvent struct {
	Kind     UAEventKind
	DialogID string
	// CallID is the SIP Call-ID. REQUIRED for the same reason as
	// DialResult.CallID, and amending DialResult alone is INSUFFICIENT: an
	// inbound call never returns a DialResult, so R14's incoming_call path
	// would still have no channel for it. Both fields are load-bearing.
	CallID        string
	Direction     Direction
	Code          int    // final/provisional status; 0 otherwise
	Reason        string // reason phrase
	FromURI       string
	ToURI         string
	OfferedCodecs []string // R14's incoming_call detail; sipua parses the SDP, session never does
	SDP           []byte
	// AdmitProbe is set only on the event sipua passes to the AdmitFunc to ask
	// "would an INVITE be admitted now?" for an OPTIONS request (RFC 3261 11:
	// the status is the one an INVITE would get). A probe admits nothing: no
	// call is created and no event is appended; the verdict is the answer.
	AdmitProbe bool
	// Cause is set IF AND ONLY IF Kind == UAEventDialogEnded, and is the empty
	// string on every other kind (U14). `session` maps it onto §10.3's
	// termination_reason; sipua never names a termination_reason itself.
	Cause UADialogEndCause
	// ExpiresS is the expiry the REGISTRAR GRANTED, set on UAEventRefresh (and 0
	// on every other kind). Without it a registrar that grants a SHORTER expiry
	// on a refresh than it granted on the initial REGISTER cannot be reported at
	// all: §10.2's `ua_status` returns `expires_s` and `next_refresh_ms`, R10
	// drives three refresh cycles and asserts the refresh lands between 50% and
	// 90% of **the granted expiry**, and RegisterResult.ExpiresS is only ever
	// populated once, by the initial Register call. This is the same
	// channel-gap species as the Call-ID defect and U14: `session` has a
	// declared consumer and no channel. P1's constant-60s acceptance does not
	// exercise it, so the gap would surface at P3 as a UA refreshing against a
	// stale interval. (D24)
	ExpiresS int
	// Err carries the failure on transport_fault and register_failed; nil on
	// every other kind.
	Err error
	At  time.Time
	// Detail carries kind-specific structured data. Set on: dialog_ended (only
	// when Cause == UACauseMediaNegotiationFailed, §11.2.1, or
	// Cause == UACauseTransportFailure, §11.3.1 case 2: {kind, transport,
	// cause, method}), media_error, plan_step, record_start, record_stop,
	// session_refresh and transfer. Nil on every other kind.
	Detail map[string]any
	// Media fields — set only on UAEventMediaStart.
	LocalMediaAddr  string
	RemoteMediaAddr string
	MediaLatched    bool

	// Digit/DTMFMode/DurationMs are set ONLY on UAEventDTMF and describe one
	// RECEIVED digit. Digit is a single character from 0-9A-D*#; DTMFMode is
	// "rfc2833" or "inband" (SIP INFO is send-only this phase, decision 3);
	// DurationMs is the observed tone/event length.
	Digit      string
	DTMFMode   string
	DurationMs int
}

// UAEventFunc is the callback signature registered by OnEvent.
type UAEventFunc func(ctx context.Context, ev UAEvent)

// Admission is the SYNCHRONOUS inbound-admission verdict (I2). `session`
// returns it from the AdmitFunc registered via OnAdmit, so sipua can decide
// ring-vs-immediate-final BEFORE it rings — a rejected INVITE never rings and
// leaks no dialog.
//
// It is DISTINCT from the one-way UAEventFunc/OnEvent channel, which keeps its
// fire-and-forget shape: only admission is a request/response.
type Admission struct {
	// Accept true rings the call; false sends Status/Reason as the SIP final.
	Accept bool
	// Status is the SIP final status sent when !Accept — 486 for any
	// concurrency cap, 503 for shutdown (Rule 6a D2). 488 is reserved for W3's
	// media-negotiation reject; there is no P2 producer.
	Status int
	// Reason is the SIP reason phrase carried on the final response.
	Reason string
}

// AdmitAccept is the "ring it" verdict.
func AdmitAccept() Admission { return Admission{Accept: true} }

// AdmitReject is the "send this final, do not ring" verdict.
func AdmitReject(status int, reason string) Admission {
	return Admission{Status: status, Reason: reason}
}

// AdmitFunc is the SYNCHRONOUS inbound-admission verdict callback. Unlike
// UAEventFunc it RETURNS a value, so the UA can act (ring vs immediate final)
// before ringing. The UA calls it OUTSIDE its registry lock; the handler must
// not re-enter the UA. ctx is the LONG-LIVED DAEMON context (decision 17),
// never an HTTP request context.
type AdmitFunc func(ctx context.Context, ev UAEvent) Admission

// ControlOpKind names WHICH call control operation holds a dialog (spec
// 2026-09-26 §3). The guard itself is operation-neutral (plan D15): it stores
// the kind its owner claims with and reports it through
// UserAgent.ControlOpBlocksHangup, so a caller that must EXPLAIN a refusal
// (call_hangup) can phrase it for the operation actually in progress. Each
// operation adds its own value; a consumer MUST treat a kind it does not
// recognise generically, never as some other operation.
type ControlOpKind string

// ControlOpTransfer is call_transfer's REFER-through-final-NOTIFY window.
const ControlOpTransfer ControlOpKind = "transfer"

// TransferMode is call_transfer's mode (spec 2026-09-26 §4.1).
type TransferMode string

// The two TransferMode values.
const (
	TransferBlind    TransferMode = "blind"
	TransferAttended TransferMode = "attended"
)

// TransferRequest is what session hands UserAgent.Transfer. It carries DIALOG
// ids — session resolves the call and consult_call handles, and checks both are
// on the same UA — and an UNVALIDATED mode/target: sipua is the single
// validation choke point, exactly as SendDTMF validates its own digits.
type TransferRequest struct {
	DialogID string
	Mode     TransferMode
	// Target is the blind transfer's Refer-To SIP URI; "" for attended.
	Target string
	// ConsultDialogID is the attended transfer's consultation dialog, on the
	// SAME UA; "" for blind. It is only READ (spec §4.6).
	ConsultDialogID string
}

// TransferResult is the REFER's OWN final response (spec §4.1). Accepted is true
// only for a 2xx. A non-2xx — or no response at all (StatusCode 0) — is a RESULT,
// not an error (§11.1); the asynchronous outcome arrives as UAEventTransfer.
type TransferResult struct {
	Accepted   bool
	StatusCode int
	Reason     string
}

// UserAgent is the §6.2.1 surface session drives for signalling.
//
// THE THREE TERMINATION METHODS BLOCK FOR THE FAR END'S FINAL RESPONSE. This is
// normative and was previously unstated, which is the defect: "sends BYE" reads
// as fire-and-forget, and under that reading THREE CONSUMERS PASS FOR THE WRONG
// REASON.
//
//   - (*Manager).HangupAllLive(ctx, grace) (byeSent, confirmed int) — P1b Task 11a
//     — can only count `confirmed` if Hangup reports the 200 OK. Fire-and-forget
//     makes `confirmed` either always 0 or a copy of `byeSent`.
//   - Part 4.1 step 3 — P1b Task 11a — "wait up to limits.shutdown_grace_period
//     for 200 OK" has nothing to wait ON.
//   - §2.10's peer.Behaviour.SwallowBye exists SOLELY to make Hangup not return
//     promptly, and Part 4.2's wire test (P1e Task 23) asserts the admin DELETE
//     "still returns 200 after the grace period elapses". Against a
//     fire-and-forget Hangup that test passes instantly and asserts nothing.
//
// Hangup is written by P1c Task 15; the three consumers are P1b Tasks 11a/11b
// and P1e Task 23.
type UserAgent interface {
	Register(ctx context.Context) (RegisterResult, error)

	// Unregister sends REGISTER Expires: 0 and BLOCKS until the registrar's final
	// response or ctx is done. It returns nil ONLY on a 2xx; a non-2xx returns an
	// error naming the code, and ctx expiry returns ctx.Err() with the
	// registration abandoned. (*Manager).UnregisterAllUAs's `confirmed` count is
	// meaningless under any other reading — it counts CONFIRMED deregistrations,
	// which is why §2.5.5 names both of its returns rather than returning a bare
	// int (an unnamed count that three §11.4 assertions depend on is how this
	// ambiguity arose in the first place).
	Unregister(ctx context.Context) error

	Dial(ctx context.Context, req DialRequest) (DialResult, error)
	Answer(ctx context.Context, req AnswerRequest) error

	// Reject sends the final response and returns once it has been handed to
	// the transport. It does NOT block until the far end's ACK (amended by
	// D151, dropping an earlier blocking guarantee this contract shipped
	// with): sipgo v0.24.1's OnInvite-handler contract
	// (sipgo/server.go:271-277) calls tx.Terminate() the instant the handler
	// returns, and the handler returns right after the 180 — so by the time
	// Reject (or the ring timer) calls tx.Respond, the server transaction
	// that would retransmit on Timer G and match an incoming ACK is already
	// gone. There is no live transaction left for Reject to block on; this
	// is architectural, not a test-mechanics workaround. A nil return means
	// the final response was handed to the transport — session MUST NOT
	// read it as "the far end ACKed".
	Reject(ctx context.Context, dialogID string, status int, reason string) error

	// Hangup ends the dialog the way its phase allows. For an ESTABLISHED
	// (answered) dialog it sends BYE and BLOCKS UNTIL THE FAR END'S FINAL
	// RESPONSE OR ctx IS DONE; it returns nil ONLY on a 2xx, and a non-2xx final
	// response returns an error naming the code. ctx expiry returns ctx.Err() and
	// THE DIALOG IS ABANDONED per §11.4 — no retry, no background goroutine
	// outliving the call; the local state machine moves to terminated
	// regardless, because §11.4's shutdown must complete whether or not the peer
	// answered.
	//
	// A dialog NOT YET ANSWERED ends one of three pre-answer ways instead, and
	// a nil return there is NOT a peer acknowledgement:
	//   - outbound dialing/ringing with a provisional in: nil once the CANCEL is
	//     WRITTEN (the 487 is not awaited);
	//   - outbound with no provisional yet: it blocks until the deferred CANCEL
	//     is written (its write error is returned), the dial settles otherwise
	//     (final response, or runDial's own ACK-then-BYE of a crossing 200), a
	//     peer BYE ends it, ctx is done, or a fixed 2 s cap elapses — nil on the
	//     cap, with NO CANCEL sent yet (it still goes out if a provisional
	//     arrives later);
	//   - outbound with a 200 in but not yet established: no CANCEL ever; it
	//     blocks until runDial's BYE transaction has returned (an unwritten BYE
	//     is returned as an error), a peer BYE ends it, ctx is done, or the same
	//     2 s cap elapses — nil on the cap even if that BYE is still awaiting its
	//     response;
	//   - inbound ringing/admitting: nil once a 603 is handed to the transport.
	// HangupAllLive's `confirmed` count (shutdown.go) therefore counts these as
	// confirmed although no peer response was seen.
	//
	// CALLERS IMPOSE THE GRACE PERIOD AS A ctx DEADLINE. Hangup reads no policy
	// key and holds no timer of its own EXCEPT that fixed 2 s pre-answer cap:
	// HangupAllLive and Part 4.1 step 3 derive their ctx from
	// limits.shutdown_grace_period and pass it in. This keeps the policy read in
	// `session`, which owns policy (U9), and keeps `sipua` free of a second,
	// independent notion of how long a teardown may take.
	Hangup(ctx context.Context, dialogID string, reason string) error

	Close(ctx context.Context) error

	// LocalAddr is the CONCRETE post-bind signalling address (§3d). It is the
	// seam the D9d/§3d wildcard-resolution acceptance gate reads; NO production
	// payload carries it — §10.2's ua_status has no address key
	// (toolservice.go's UAStatus) and AdminUAView (admin.go) has no address
	// field. (This previously claimed "session needs it for ua_status and for
	// the §12.7 admin view", which was true of neither — Rule 13 Cycle 1, D383.)
	// It is the address the Via is pinned to — read back from the socket, never the configured
	// local_addr string — so a wildcard bind cannot silently reach a caller.
	//
	// IT RETURNS net.Addr, NOT *net.UDPAddr (U17). This is O1's requirement,
	// not a style preference: §15.1's O1 promises that at P4 the diff adding
	// TCP and TLS changes NO SIGNATURE in this interface — the same interface
	// P1 shipped. On TCP or TLS the post-bind local signalling address is a
	// *net.TCPAddr, so a *net.UDPAddr return makes that promise unkeepable
	// and leaves O1 UNDISCHARGED AT P1 while its gate passes green. Every
	// consumer in session needs only .String() (ua_status and AdminUAView
	// both render a string), so net.Addr costs nothing today.
	//
	// The concrete UDP accessor is UNCHANGED: sipua.UA.BoundAddr()
	// *net.UDPAddr stays exactly as it is (P1c Task 13), and its ~8 in-package
	// call sites that need .IP and .Port are unaffected. Only this
	// interface-facing alias widens. Note that Go requires an EXACT signature
	// match for interface satisfaction, so a method returning *net.UDPAddr
	// does NOT satisfy this method even though *net.UDPAddr implements
	// net.Addr — do not "fix" either side back.
	//
	// net.Addr is a plain stdlib interface, not an engine type: it adds no
	// sipgo or sipengine edge and the import-boundary test still holds.
	LocalAddr() net.Addr

	// TLSVerified reports whether this UA's construction-time TLS posture
	// verifies the peer (Phase 4 W1 M7c, §7.2). ok is false on any
	// non-`tls` transport, exactly like every other transport-scoped
	// accessor's absent-producer convention; verified is meaningful only
	// when ok is true and reflects the UA's CONSTRUCTION-TIME SNAPSHOT
	// (tls.insecure_skip_verify at ua_create), never a live policy read or a
	// per-call handshake result.
	TLSVerified() (verified bool, ok bool)

	// OnEvent registers the single upward callback. ctx is the LONG-LIVED
	// DAEMON context (decision 17), never an HTTP request context.
	OnEvent(ctx context.Context, fn UAEventFunc)

	// OnAdmit registers the SYNCHRONOUS inbound-admission decision channel
	// (I2). It is DISTINCT from OnEvent's one-way delivery: for an inbound
	// INVITE the UA calls this handler and honours its Admission verdict —
	// ringing on Accept, sending the verdict's SIP final on Reject with no ring
	// and no dialog leak. ctx is the LONG-LIVED DAEMON context (decision 17),
	// never an HTTP request context. The UA calls the handler OUTSIDE its
	// registry lock, and the handler must not re-enter the UA.
	OnAdmit(ctx context.Context, fn AdmitFunc)

	// MediaView returns the negotiated media for a dialog, or ok=false when no
	// media.Session has been negotiated on it yet.
	MediaView(dialogID string) (MediaView, bool)

	// QualityView returns §10.10 tier-1 quality for an answered dialog, or
	// ok=false when no media loop is running on it.
	QualityView(dialogID string) (QualityView, bool)

	// Play plays a policy-registered prompt into TX (§10.9 media_play). prompt is
	// a NAME, resolved server-side against policy prompts:; an arbitrary path is
	// never accepted. duration_ms is deterministic (frame count × 20 ms). A second
	// play or an active record returns precondition_failed.
	Play(ctx context.Context, dialogID, prompt string, repeat int, waitComplete bool) (durationMs int64, err error)

	// RecordStart begins recording RX to a WAV artifact (§10.9). callHandle is the
	// artifact store key, resolved server-side. name "" uses a per-call default
	// (recording.wav, recording-2.wav, ...). Returns the resolved name. A second
	// record or an active play returns precondition_failed.
	RecordStart(ctx context.Context, dialogID, callHandle, name string) (resolvedName string, err error)
	// RecordStop finalises the active recording and returns its ArtifactInfo and
	// duration_ms (§10.9). name "" finalises the active recording.
	RecordStop(ctx context.Context, dialogID, callHandle, name string) (info ArtifactInfo, durationMs int64, err error)

	// MediaPlanView returns §10.7 plan state for a dialog, or ok=false when no
	// media_plan ran on it.
	MediaPlanView(dialogID string) (MediaPlanView, bool)

	// SendDTMF sends digits in the given mode (§10.8 dtmf_send). mode "" means
	// the UA's profile default. It BLOCKS until every digit has been emitted, so
	// the returned count is what actually went out. Errors: invalid_argument (a
	// digit outside 0-9A-D*#, or an unknown mode), precondition_failed (call not
	// answered, or the media slot is occupied for mode "inband"), not_supported
	// (mode "rfc2833" but telephone-event was not negotiated — REPORTED, NEVER
	// silently downgraded).
	//
	// durationMs <= 0 means "unset" (ResolveDTMFTiming applies
	// DefaultDTMFDurationMs). gapMs is TRI-STATE: a positive value is a gap, 0
	// means NO GAP, and a NEGATIVE value (DTMFGapUnset) means "unset"
	// (DefaultDTMFGapMs). 0 cannot double as the sentinel, because back-to-back
	// digits are a legal request that must not be quietly turned into a gap.
	//
	// emittedDurationMs is the PER-DIGIT duration the sender actually put on the
	// wire, which for the two RTP-path modes is the request rounded UP to whole
	// 20 ms ticks. dtmf_send reports THIS as duration_ms — a fact about the wire,
	// on the same footing as digits_sent — never the caller's own input.
	SendDTMF(ctx context.Context, dialogID, digits string, mode DTMFMode, durationMs, gapMs int) (sent int, emittedDurationMs int, err error)

	// DTMFMode reports the EFFECTIVE per-call DTMF mode for call_status's
	// dtmf_mode. ok is false for an unknown dialog.
	DTMFMode(dialogID string) (string, bool)

	// SessionTimerView reports call_status's session_timer, present ONLY when
	// RFC 4028 was actually negotiated on the dialog (§4). ok is false
	// otherwise — including for a call on a peer that never advertised timer
	// support, where reporting a zeroed struct would assert a timer that does
	// not exist.
	SessionTimerView(dialogID string) (SessionTimerView, bool)

	// Transfer sends a REFER in an answered dialog (§10.14 call_transfer) and
	// BLOCKS only for the REFER's OWN final response. Accepted false with a
	// status is a RESULT, not an error; the asynchronous NOTIFY outcome arrives
	// as UAEventTransfer. Errors: invalid_argument (mode/target/consult
	// problems), not_found (unknown dialog), precondition_failed (not answered,
	// or a control operation or dtmf_send already holds the dialog).
	Transfer(ctx context.Context, req TransferRequest) (TransferResult, error)

	// ControlOpBlocksHangup reports WHICH call control operation, if any,
	// currently holds dialogID AND needs call_hangup refused (spec 2026-09-26
	// §3 and its amendment; plan D15/D17). For a transfer that is only while
	// its REFER's own response is pending, not the whole NOTIFY outcome wait.
	// call_hangup consults it BEFORE its own termination claim and phrases its
	// refusal from kind. ("", false) for an unknown dialog, or one whose
	// operation allows hangup. No ctx: a pure in-memory read, like DTMFMode.
	ControlOpBlocksHangup(dialogID string) (kind ControlOpKind, blocked bool)
}

// SessionTimerView is §4's call_status.session_timer readout as plain scalars.
// Refresher is "uac" or "uas" — WHICH END REFRESHES, from our point of view:
// "uac" means we do when we dialled, the peer does when we answered.
// NextRefreshMs counts down to the next refresh (ours) or to the watchdog
// deadline (the peer's).
//
// Armed disambiguates NextRefreshMs == 0 (C9/A-M6): that value alone cannot
// tell "no timer armed at all" apart from "armed, but the deadline has
// passed" or "armed, but read in the brief window right after Start() before
// the timer's first schedule is recorded" — three different situations with
// the same zero reading. Armed is true whenever either the refresher or the
// watchdog is present, regardless of what NextRefreshMs currently reads.
type SessionTimerView struct {
	IntervalS     int
	Refresher     string
	NextRefreshMs int64
	Armed         bool
}

// MediaView is the negotiated media a UA reports for a dialog (§10.3's codec,
// local_media_addr, srtp). It carries no RTP state — none exists at W3.
type MediaView struct {
	Codec           string
	LocalMediaAddr  string
	SRTP            bool
	RemoteMediaAddr string // observed (latched) or signalled remote (R10)
	Latched         bool   // TX latched to a source distinct from the signalled one
}

// QualityView is §10.10's tier-1 readout as plain scalars. session never imports
// internal/media/quality; sipua translates the media Snapshot into this.
type QualityView struct {
	Tier               int
	Codec              string
	DurationMs         int64
	PacketsSent        int64
	PacketsReceived    int64
	PacketsLost        int64
	LossPct            float64
	OutOfOrder         int64
	Duplicates         int64
	LateDiscards       int64
	RogueSourcePackets int64
	TXUnderruns        int64
	SRTPAuthFailures   int64
	BurstGaps          []map[string]any
	JitterMsAvg        float64
	JitterMsPeak       float64
	RFactor            float64
	MOSEstimate        float64
	MOSLQO             *float64
	PESQRaw            *float64
	Reference          *string
}

// MediaPlanStep is one validated §10.7 plan step as a PLAIN STRUCT — no map, no
// codec/SDP type crosses this boundary. Op ∈ "play"|"record"|"wait"|"dtmf"|
// "wait_dtmf"|"hangup". Fields are op-specific and zero when not applicable.
type MediaPlanStep struct {
	Op         string
	Prompt     string // play
	Repeat     int    // play (default 1)
	DurationMs int64  // record, wait, dtmf (per-digit tone length)
	Name       string // record (optional artifact name)
	Reason     string // hangup
	Digits     string // dtmf (to send), wait_dtmf (expected; "" = any)
	Mode       string // dtmf ("" = the profile default)
	GapMs      int64  // dtmf (inter-digit gap)
	TimeoutMs  int64  // wait_dtmf (bounds the WHOLE collection window)
}

// MediaPlanView is §10.7's call_status.media_plan readout as plain scalars.
// State ∈ "running"|"completed"|"failed"|"aborted". FailedIndex is -1 unless
// State is "failed" or "aborted" (aborted records the in-progress step's
// index, not a failure). Present is false when no plan ran on the call.
type MediaPlanView struct {
	State          string
	StepsTotal     int
	StepsCompleted int
	FailedIndex    int
	FailedOp       string
	Present        bool
}

// ---- MediaSession (satisfied by internal/media) ----------------------------

// MediaConfig is the negotiated media plan as a PLAIN STRUCT. SDP never
// crosses this boundary (§6.2.1).
type MediaConfig struct {
	LocalAddr      string
	RemoteAddr     string
	Codec          string
	PayloadType    uint8
	PtimeMS        int
	SRTP           bool
	JitterBufferMS int
}

// MediaStats is the snapshot Stats returns.
type MediaStats struct {
	PacketsSent     int64
	PacketsReceived int64
	Lost            int64
	OutOfOrder      int64
	Duplicates      int64
	JitterMS        float64
	LossPct         float64
	RFactor         float64
	MOSEstimate     float64
}

// DTMFMode names how a DTMF digit is signalled.
type DTMFMode string

// The three DTMFMode values. DTMFModeInfo is P3's addition (spec §2.1): SIP
// INFO with an application/dtmf-relay body (decision 15).
const (
	DTMFModeRFC2833 DTMFMode = "rfc2833"
	DTMFModeInband  DTMFMode = "inband"
	DTMFModeInfo    DTMFMode = "info"
)

// §10.8's per-digit DTMF timing defaults and the "unset" sentinel for gap_ms.
//
// THEY ARE UNTYPED ON PURPOSE. internal/session works in int64 (MediaPlanStep's
// fields, planInt64) and internal/sipua works in int (SendDTMF's arguments); an
// untyped constant serves both without a conversion at either site, which is what
// keeps `const dtmfGapUnset = session.DTMFGapUnset` an int over in sipua.
const (
	// DefaultDTMFDurationMs is the per-digit tone length applied when the caller
	// named none.
	DefaultDTMFDurationMs = 100
	// DefaultDTMFGapMs is the inter-digit gap applied when the caller named none.
	DefaultDTMFGapMs = 50
	// DTMFGapUnset is the gapMs value meaning "the caller named no gap at all", as
	// distinct from an explicit zero.
	//
	// IT IS NEGATIVE ON PURPOSE. 0 is a LEGAL, MEANINGFUL gap — "send the digits
	// back to back" — so it cannot double as the sentinel for "unset"; a resolver
	// that rewrote 0 to DefaultDTMFGapMs would silently override a plan author's or
	// an agent's explicit choice. Callers with no value pass this; callers holding
	// a real 0 pass 0.
	DTMFGapUnset = -1
)

// ResolveDTMFTiming applies §10.8's per-digit defaults. IT IS THE ONE FUNCTION
// THAT KNOWS THEIR VALUES OR THE TRI-STATE RULE (Rule 18):
//
//	durationMs <= 0             => unset => DefaultDTMFDurationMs
//	gapMs < 0 (DTMFGapUnset)    => unset => DefaultDTMFGapMs
//	gapMs == 0                  => NO GAP, preserved verbatim
//
// IT HAS EXACTLY TWO CALL SITES, AND BOTH ARE NECESSARY. decodeDTMF
// (mediaplan_validate.go) calls it at VALIDATION time, because §4's plan bound
// `len(digits) × (duration_ms + gap_ms)` needs concrete numbers before the call
// is dialed and cannot be deferred. sipua.resolveDTMFTiming calls it at SEND
// time, for the three dtmf_send mode arms. Neither can be deleted in favour of
// the other — what is shared is the values and the rule, and nothing else needs
// to be.
//
// It is IDEMPOTENT on already-resolved input, which is what makes the two call
// sites compose: a plan step resolved at validation time passes through the
// sender's resolver again unchanged, including a deliberate 0 gap.
//
// It lives in internal/session rather than internal/media/codec because
// internal/importguard bans internal/media from internal/session's production
// dependency set (§14.2), and internal/sipua already imports internal/session.
func ResolveDTMFTiming(durationMs, gapMs int64) (int64, int64) {
	if durationMs <= 0 {
		durationMs = DefaultDTMFDurationMs
	}
	if gapMs < 0 {
		gapMs = DefaultDTMFGapMs
	}
	return durationMs, gapMs
}

// DTMFEvent is one received DTMF digit.
type DTMFEvent struct {
	Digit      rune
	DurationMS int
	At         time.Time
}

// DTMFFunc is the callback signature registered by OnDTMF.
type DTMFFunc func(ctx context.Context, ev DTMFEvent)

// MediaSession is CONFIRMED-DEAD P1 scaffolding (W5 §3.1, locked decision 2).
// W3/W4 built the media loop in internal/sipua and exposed it through the flat
// UA views (MediaView/QualityView, and W5's Play/RecordStart/RecordStop/
// MediaPlanView) — NOT through this interface. The ONLY implementer in the tree
// is a hand-written test fake; nothing production wires it. It is documented
// here rather than deleted (Rule 19: pre-existing dead code is reported, not
// removed, and W5's changes do not orphan it — the fake and interface predate
// this wave). DO NOT REVIVE IT; add media capability to UserAgent instead.
type MediaSession interface {
	Start(ctx context.Context, cfg MediaConfig) error
	Stop(ctx context.Context) error
	Play(ctx context.Context, promptName string) error
	RecordStart(ctx context.Context, name string) error
	RecordStop(ctx context.Context) error
	SendDTMF(ctx context.Context, digits string, mode DTMFMode) error
	Stats(ctx context.Context) (MediaStats, error)
	OnDTMF(ctx context.Context, fn DTMFFunc)
}

// ---- Tap (satisfied by internal/trace) -------------------------------------

// SIPRecord is one captured signalling message. Raw is non-nil exactly on the
// seam-backed paths of D9d/U1 (UDP, accepted TCP, accepted TLS) and nil where
// only canonical reserialisation is available; Fidelity reports which.
//
// IT CARRIES ONLY PLAIN SCALARS AND MUST NOT GAIN A sip.Message FIELD. If it
// did, session would import sipgo; transport/mcp imports session; and §14.2's
// transport-boundary test would fail. internal/sipua extracts every field
// here from the wire bytes and hands over a fully-populated record, which is
// also what makes internal/trace a pure renderer testable against hand-built
// records.
type SIPRecord struct {
	At         time.Time
	Direction  Direction
	Transport  Transport
	LocalAddr  string
	RemoteAddr string
	// UAHandle namespaces CallID in the tap's keyspace (HIGH-3). Inbound
	// Call-IDs are peer-chosen verbatim, so a peer reaching two UAs in
	// different sessions can send an identical Call-ID; keying the sink on
	// Call-ID alone then collides their rings and lets one session read the
	// other's traffic through its own handle. The producer (sipua's
	// ObservingConn, a per-UA object) stamps its owning UA handle here, and the
	// sink keys by (UAHandle, CallID). "" on records from a tap with no UA
	// identity — which is exactly the pre-existing per-Call-ID behaviour,
	// preserved for every non-UA path.
	UAHandle   string
	CallID     string
	CSeq       string
	Method     string // "" on a response
	StatusCode int    // 0 on a request
	Reason     string // reason phrase; "" on a request
	FromURI    string
	ToURI      string
	SDPCodecs  []string // codec names from the SDP body, if any
	Serialized string   // the rendered message, always set
	Raw        []byte   // observed octets; non-nil on the seam-backed paths (U1)
	Fidelity   string   // "byte_exact" | "canonical"
}

// MediaRecord is [P2]: P1 sends no RTP.
type MediaRecord struct {
	At         time.Time
	Direction  Direction
	LocalAddr  string
	RemoteAddr string
	Payload    []byte
}

// LadderFormat names how Ladder renders a call's tapped messages.
type LadderFormat string

// The three LadderFormat values.
const (
	LadderText    LadderFormat = "text"
	LadderMermaid LadderFormat = "mermaid"
	LadderJSON    LadderFormat = "json"
)

// Ladder is a rendered call ladder.
type Ladder struct {
	Format    LadderFormat
	Rendered  string
	Messages  int
	Truncated bool
}

// CaptureConfig configures an armed capture.
type CaptureConfig struct { // [P2]
	Scope       string // "signaling" | "media" | "both"
	PayloadMode string // "plaintext" | "ciphertext"
	MaxBytes    int64
}

// CaptureResult is what DisarmCapture returns.
type CaptureResult struct { // [P2]
	Name                string
	Bytes               int64
	Packets             int64
	Truncated           bool
	SignalingCiphertext string            // "captured" | "unavailable" | "not_requested"
	CaptureFidelity     map[string]string // transport -> "byte_exact" | "canonical"
}

// Tap is the sink session installs into sipua and media at construction, so
// those packages depend on THIS interface and never on the renderer.
//
// It is SEVEN methods and every per-call method is KEYED BY SIP Call-ID (U7,
// which AMENDS §6.2.1's sketch; U18, which amends U7 from six to seven).
// §6.2.1 wrote `Ladder(format)`; that cannot work, because the sink is
// server-wide and the ladder is per-call, so the key is not optional.
// `Evict` is likewise declared: it frees a terminated call's ring PROMPTLY,
// ahead of LRU pressure, and (U18) releases the Retain taken on it.
// `Retain` is the seventh, and it is what makes U15's LRU bound correct
// rather than backwards — see its comment below.
//
// EVICT IS AN OPTIMISATION, NOT §N3's BOUND (U15). An earlier form of this
// comment claimed the bound leaked without it; that claim is WITHDRAWN.
// §N3's actual bound is limits.max_ladders + LRU eviction over the UNRETAINED
// rings, plus one retained ring per registry-resident call (§2.7, as amended
// by U21) — live calls bounded by limits.max_concurrent_calls_total, plus
// terminated-but-retained calls bounded by limits.max_terminated_calls_per_session
// per session and limits.registry_retention in time — and
// it has to be, because Evict is reachable ONLY for Call-IDs the session
// registry knows about. REGISTER refreshes, OPTIONS keepalives, dials that
// error before returning a DialResult, and inbound INVITEs rejected before a
// Call record exists are all tapped and NONE of them is ever evictable. A
// design resting on Evict for its memory bound would therefore grow without
// limit on exactly the long-lived-daemon workload §N3 was written for.
//
// BUT EVICT IS NO LONGER OPTIONAL IN THE WAY U15 LEFT IT: with U18, failing
// to release a retained ring leaks it, because the LRU cannot reclaim a
// retained ring. THE RELEASE IS NOT AT TERMINAL BOOKKEEPING (U21 corrects
// U18 point 5): it is evictCallLocked, at registry eviction, reached by
// EVERY path a call takes out of the registry — the janitor's §N3 sweep, the
// max_terminated_calls_per_session cap, and EvictCallForTest.
//
// U7 requires a P1 closeout record; so does U18's amendment of it.
//
// D9a and D9b are DIFFERENT SWITCHES and are not in conflict:
//   - SIPMessage/Ladder are the LADDER, which D9a makes UNCONDITIONAL. There
//     is no arming, no enable flag and no policy key on that path. An
//     implementation that adds an arming check to SIPMessage is a defect.
//   - ArmCapture/DisarmCapture govern PCAP, which D9b makes OPT-IN and which
//     arrives at P2 with capture_start/capture_stop.
//
// AT P1 ArmCapture AND DisarmCapture RETURN apierr.NotSupported and record
// nothing. They are NOT silent no-ops returning nil: a silent no-op is
// indistinguishable from a working capture, and not_supported is §11.2's
// exact code for "capability unavailable in this build". They are unreachable
// from the P1 tool surface anyway — capture_start/capture_stop are in
// DeferredTools, not P1Tools — so this is a defence against a future caller
// rather than a live path.
type Tap interface {
	SIPMessage(ctx context.Context, rec SIPRecord)
	MediaFrame(ctx context.Context, rec MediaRecord)
	// Ladder, Retain and Evict are keyed by (uaHandle, callID) (HIGH-3). The
	// sink is daemon-wide, and inbound Call-IDs are peer-chosen verbatim, so
	// the UA handle is what keeps two UAs' identical Call-IDs in separate
	// rings. The session-side callers pass the OWNING UA's handle, resolved
	// server-side from the call handle (never agent-supplied), and the
	// producer stamps the same handle into SIPRecord.UAHandle.
	Ladder(ctx context.Context, uaHandle, callID string, format LadderFormat) (Ladder, error)

	// Retain marks callID's ring as belonging to a LIVE CALL, so the LRU may
	// never evict it and the ring is excluded from the limits.max_ladders
	// count. ADDED BY U18, WHICH AMENDS U7 (six methods -> seven) AND U15's
	// EVICTION POLICY.
	//
	// WHY IT IS REQUIRED — U15's LRU, as U15 left it, EVICTS LIVE CALLS
	// FIRST. This is not a tuning problem; the ordering is exactly backwards,
	// by construction:
	//   - A P1 call writes NOTHING to its ladder between the ACK and the BYE.
	//     There is no media (R14's split), no session timers (P3) and no
	//     re-INVITEs. Its ring's last write is the ACK, so A LONG-HELD LIVE
	//     CALL IS THE LEAST-RECENTLY-WRITTEN OBJECT IN THE STORE.
	//   - `keepalive: "options"` mints a fresh ring per OPTIONS (R10 requires
	//     each in the ladder) and REFRESHES ITS OWN RECENCY ON EVERY WRITE.
	// So pure LRW evicts live calls' ladders in preference to rings belonging
	// to dialogs that ended minutes ago. It is reachable at the DOCUMENTED
	// DEFAULTS: max_ladders 512, OPTIONS at 30 s is ~120 new rings/hour/UA,
	// so one UA exhausts 512 in about four hours and five UAs in under one,
	// while R8 makes long-held calls a shipped P1 use case.
	//
	// THE OBSERVABLE FAILURE IS OUT OF SPEC, which is why this is not a
	// degradation the wave may accept: `call_ladder` on a LIVE CALL THE
	// SESSION OWNS returns apierr.NotFound. §10.11 defines call_ladder's only
	// errors as not_found (unknown handle) and gone (terminated call evicted
	// from the retention window), and §13.5 makes that distinction
	// load-bearing. A live, owned handle answering not_found is outside both,
	// and it is NOT covered by U10's accepted degradation.
	//
	// WHO CALLS IT, AND WHEN. session.Manager, at DIALOG ESTABLISHMENT — the
	// same code that sets the Call-ID on the *Call: on the returned
	// DialResult for an outbound call, on the admitted UAEventInbound (I2's
	// admitInbound) for an inbound one. Retain is called IMMEDIATELY AFTER the unexported Call-ID setter
	// returns and HOLDING NO LOCK — not the call mutex, not m.mu — so it adds
	// NO new lock edge to §6.3's hierarchy. Do not "tidy" it inside the
	// setter's critical section. That call site is P1b Task 8's, not this
	// task's; this task declares the method.
	//
	// A Retain for a callID with no ring yet creates an empty retained ring.
	// The retained set is bounded by the REGISTRY-RESIDENT CALL COUNT — one
	// retained ring per call the registry still holds, live or inside its
	// §N3 retention window — because Evict releases the retention at
	// registry eviction (U21); it is not a second unbounded key space.
	Retain(ctx context.Context, uaHandle, callID string)

	// Evict drops a call's ladder AND RELEASES THE Retain TAKEN ON IT (U18).
	// It is the ONLY release: there is no separate Release method, because a
	// retention is exactly as long-lived as the ring it protects and a second
	// method would be a pinning framework built for one caller (Rule 15).
	//
	// Task 10's janitor calls it as part of registry eviction, freeing the
	// ring promptly rather than waiting for LRU pressure. It is an
	// optimisation for the UNRETAINED case, not §N3's bound — see above — but
	// for a RETAINED ring it is the only thing that ever frees it.
	Evict(ctx context.Context, uaHandle, callID string)

	// ArmCapture and DisarmCapture are keyed by (uaHandle, callID), like the
	// five other per-call Tap methods above (HIGH-3): inbound Call-IDs are
	// peer-chosen and can collide across sessions, so a callID-only signature
	// cannot scope a capture to one ring without reintroducing that collision.
	// w is the capture destination the streaming engine writes to — the
	// per-call capture.pcap, opened by session from the artifact store
	// (§4.3) — kept as an io.WriteCloser rather than injecting
	// session.ArtifactStore into trace, so internal/trace stays free of
	// internal/artifact (the engineLayer guard).
	//
	// OWNERSHIP OF w (Cycle-5 #1): on a NIL error return the Sink takes
	// ownership of w and closes it (at DisarmCapture, terminal-close or Evict);
	// the caller MUST NOT close it. On a NON-NIL error return the arm did NOT
	// take ownership — the CALLER must Close (and roll back) w itself, which is
	// exactly what CaptureStart and the dial-time OnDialogBound path do.
	ArmCapture(ctx context.Context, uaHandle, callID string, w io.WriteCloser, cfg CaptureConfig) error
	DisarmCapture(ctx context.Context, uaHandle, callID string) (CaptureResult, error)
}

// ---- ArtifactStore (satisfied by internal/artifact) ------------------------

// ArtifactInfo describes one closed artifact.
type ArtifactInfo struct {
	CallHandle string
	Name       string
	URI        string
	Bytes      int64
	ClosedAt   time.Time
}

// ArtifactStore is declared in full at P1 and satisfied by a no-op: P1 writes
// no artifacts. Resolution is registry-independent (§N3), which this
// interface makes structural — Resolve takes a URI and nothing else.
type ArtifactStore interface {
	OpenCallDir(ctx context.Context, callHandle string) error
	Create(ctx context.Context, callHandle, name string) (io.WriteCloser, error)
	Close(ctx context.Context, callHandle, name string) (ArtifactInfo, error)

	// Remove deletes a just-created artifact for capture-arm rollback: when a
	// Create succeeds but the subsequent ArmCapture fails, session calls
	// Remove so the O_EXCL slot Create holds is freed for a retry rather than
	// blocking forever on an orphaned file. It is idempotent — removing an
	// already-gone artifact is not an error.
	Remove(ctx context.Context, callHandle, name string) error

	// URI is the one method without a context: it formats a string, performs
	// no I/O and cannot fail (decision 17's stated exception).
	URI(callHandle, name string) string

	Resolve(ctx context.Context, uri string) (ArtifactInfo, io.ReadCloser, error)

	// UsageBytes returns the store's total bytes on disk, for the record-time
	// high-watermark guard (§13.3). Errors are treated as unknown usage.
	UsageBytes(ctx context.Context) (int64, error)

	// NonLiveUsageBytes returns the store's total bytes on disk EXCLUDING
	// live-call dirs — the exact population the §13.3 janitor watermark
	// eviction can reclaim. The record-time high-watermark guard uses this to
	// refuse a new recording only when nothing is actually evictable, rather
	// than whenever total usage (including protected live data) exceeds the
	// cap. Errors are treated as unknown usage.
	NonLiveUsageBytes(ctx context.Context) (int64, error)
}
