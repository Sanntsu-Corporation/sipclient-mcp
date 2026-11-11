package sipua

// Rule 16 reuse decision for this file:
//
//   REUSED from internal/sipengine:
//     siptest.BuildInvite            — as delivered by Task 13, with the O1
//                                      transport parameter; the Via host and
//                                      port come from UA.BoundAddr(). The
//                                      Request-URI is driven through
//                                      builders.go:52's IP-to-IP branch with a
//                                      USERLESS TargetURI, carrying the user
//                                      separately via ToUser — the only
//                                      combination that survives HostPort()
//                                      (D127/C1: ToDomain alone doubles the
//                                      port into the string and HostPort()
//                                      rejects it with "too many colons").
//     siptest.BuildByeFromInvite     — verbatim; it encodes the v0.24.1
//                                      "To-tag comes from the 200 OK and is a
//                                      param" fix.
//     (*UA).digestAuthTransaction   — for a CHALLENGED INVITE (D5/D8, P4-D06).
//                                      digestauth.go, this package's own digest
//                                      engine, which both legs now share. It
//                                      returns a client transaction driveTx
//                                      drives through the same
//                                      provisional-aware loop as the first leg,
//                                      so the authed leg surfaces 180 (the
//                                      vendored DoRequestWithDigest's own
//                                      response pump swallows every 1xx). The
//                                      CSeq is still advanced on the retry
//                                      (applyDigest bumps it explicitly), so
//                                      the Hangup CSeq reasoning below is
//                                      unchanged. sipgo.Client.DoDigestAuth,
//                                      which this replaced, could not carry an
//                                      RFC 7616 nonce-count at all.
//     siptest.(*Client).RawTransaction — for the BYE, matching RunUAC's shape.
//     validSIPURI (register.go)      — reused, not reimplemented, to reject a
//                                      malformed to_uri (e.g. an IPv6 literal
//                                      sip.ParseUri cannot parse) BEFORE
//                                      BuildInvite, so Dial fails fast with
//                                      invalid_argument instead of a slow,
//                                      misattributed transport_fault (D134).
//
//   NOT REUSED: siptest.DefaultSDP (§7.1 "Replace" — hardcoded 127.0.0.1;
//     see sipua.FixedPCMUSDP), and siptest.RunUAC / RunUAS /
//     newPersistentEndpointServer (§7.1 "reference only"; each owns its own
//     listener, which conflicts with Task 13's caller-supplied ServeUDP seam).
//
//   ADDITIVE, NOT vendored: transactionWithProvisional is an UNEXPORTED
//     method on *UA here, built directly over u.Client().Raw().
//     TransactionRequest — NOT a new method on siptest.Client. Locked
//     decision D138: internal/sipengine/siptest/client.go is UNPINNED, so it
//     is byte-diffed against the vendored snapshot (G4); appending to it
//     would trip that gate. It mirrors siptest.(*Client).doTx's shape exactly
//     rather than duplicating it under a different name.
//
// P1 scope: NO media session and NO RTP (§15's R14 split). Assertions here
// are on state transitions and message sequences only, never on a negotiated
// codec or packet counts.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// THIS PACKAGE DECLARES NO CallState, Direction, DialRequest, DialResult,
// AnswerRequest OR CallEvent (Rule 18). All of them are session's: §10.3's
// call state machine and its termination_reason enum live in session.Call, in
// exactly one place, and session.UAEvent is deliberately PROTOCOL-LEVEL so
// that mapping protocol facts onto call states happens once, there.
//
// What sipua keeps is an UNEXPORTED dialog record whose unexported `phase`
// field is all it needs to choose BYE vs CANCEL.

// DefaultInboundRingTimeout is R14's fallback when Config.InboundRingTimeout
// is unset (limits.inbound_ring_timeout_s defaults to 60).
const DefaultInboundRingTimeout = 60 * time.Second

// phase is sipua's private notion of how far a dialog has got. It is NOT
// §10.3's CallState and is never exported: its only job is to decide whether
// a teardown sends BYE or CANCEL, and whether an Answer/Reject is still legal.
type phase int

const (
	phaseDialing phase = iota
	phaseRinging
	phaseAnswered
	phaseDone
	// phaseAnswering is Answer's CLAIM, held for the duration of its 200 OK
	// write. It is deliberately APPENDED rather than inserted in ringing ->
	// answering -> answered order: `phase` is rendered with %d in three
	// precondition_failed messages, so renumbering the existing four values
	// would silently change strings that are already asserted.
	//
	// It is neither phaseRinging nor phaseAnswered, and BOTH halves are
	// load-bearing — see Answer's comment.
	phaseAnswering
	// phaseAdmitting is the inbound dialog's state from registration until the
	// 180 Ringing is confirmed on the wire (M2). Answer/Reject/finalRespond all
	// require phaseRinging, so a call_answer racing in during admission cannot
	// race a 200 ahead of the 180: Answer and Reject WAIT for the admission to
	// finish (waitAdmission), then apply the phaseRinging check.
	// A CANCEL arriving during phaseAdmitting is intercepted by sipgo's own
	// transaction layer (the INVITE ServerTx is still registered while onInvite
	// is blocked in admit()); the tx.OnCancel hook onInvite registers handles
	// sipua's side of that. Appended, not inserted, for the same %d-stability
	// reason as phaseAnswering.
	phaseAdmitting
	// phaseMediaTeardown is the offering side's state across the §11.2.1
	// ACK-then-BYE: the INVITE reached 200 OK (session sees the call answered via
	// the transient UAEventFinal(200)), but ParseAnswer failed, so runDial is
	// about to ACK, send its OWN BYE, and terminate. It is deliberately NEITHER
	// phaseAnswered (so a racing call_hangup is refused precondition_failed
	// instead of firing a SECOND, concurrent BYE — a duplicate BYE with a
	// nondeterministic termination_reason) NOR phaseDone. It is released only by
	// teardownDialog. runDial holds a hung-up dial's crossing 200 here too, for
	// the same ACK-then-BYE and for the same reason, and so does Answer for a
	// call_hangup recorded during its 200 write (CF-041). Appended, not inserted,
	// for the same %d-stability reason as phaseAnswering.
	phaseMediaTeardown
	// phaseControlOp is an ANSWERED dialog that is running a call control
	// operation which must be exclusive on the dialog: call_transfer's
	// REFER-through-final-NOTIFY window (transfer.go) today; the sibling
	// call-hold plan's re-INVITE (call_media_direction) is its intended second
	// owner and needs nothing from this file beyond calling
	// claimControlOpLocked (with its own session.ControlOpKind) and
	// releaseControlOpLocked (controlop.go). It is entered
	// ONLY from phaseAnswered and left ONLY back to phaseAnswered (the owner's
	// release) or to phaseDone (a teardown path, which also closes
	// controlOpEnded) — an operation never moves a dialog to phaseDone itself.
	// dialogEstablished() treats it as live, so peer in-dialog requests, RFC
	// 4028 maintenance and teardown all proceed; operator-initiated operations
	// (a second control op, dtmf_send, media_record_*) refuse it with
	// precondition_failed for its WHOLE duration. The call_hangup TOOL (one
	// layer up) is refused only while controlOpBlocksHangup is set: from the
	// claim until the owner calls allowHangupDuringControlOpLocked (plan D17 —
	// a transfer does so once its REFER is accepted). A HOLD OWNER MUST ALSO
	// SERIALIZE ITS OWN re-INVITE AGAINST refreshSession's periodic refresh
	// (glare: sendInDialog orders their CSeqs on the wire, but does not stop two
	// INVITE transactions being outstanding at once); this phase deliberately
	// does not stop the refresher, because a transfer's REFER does not conflict
	// with it. Appended, not inserted, for
	// the same %d-stability reason as phaseAnswering.
	phaseControlOp
)

type dialog struct {
	id        string
	direction session.Direction
	phase     phase
	// admissionDone is closed when onInvite has finished admitting this inbound
	// dialog, whatever the verdict (CF-052). Answer and Reject that find the
	// dialog phaseAdmitting wait on it, holding no lock. Nil on every dialog
	// that did not come through onInvite's new-dialog path.
	admissionDone chan struct{}
	// callID is read from the INVITE ONCE, at dialog creation, and is the
	// SINGLE SOURCE for DialResult.CallID, every UAEvent.CallID and every
	// SIPRecord.CallID the tap emits for this dialog. Deriving it
	// independently in two places is how a ladder key and its records diverge,
	// leaving call_ladder to return an empty ladder with nothing to explain it.
	callID string
	// toTag is the one To tag of every non-100 response to an inbound
	// initial INVITE (RFC 3261 8.2.6.2). Minted by onInvite before register
	// publishes the dialog and never written again, so it needs no lock.
	toTag     string
	invite    *sip.Request
	ok        *sip.Response
	serverTx  sip.ServerTransaction
	ringTimer clock.Timer

	// mediaSession/mediaConn are P2 W3's negotiated media state (M5).
	// mediaConn is bound before the SDP is built (§6.5.3) and its release is
	// centralized in teardownDialog / Hangup / onBye.
	mediaSession *media.Session
	mediaConn    *net.UDPConn
	// CF-145 (RFC 3261 13.3.1): an INVITE without SDP is answered with our
	// offer in the 200 and the answer arrives in the ACK. mediaAwaitingAnswer
	// is set by Answer with that offer session and cleared by applyAckAnswer in
	// the section that swaps in the answered session (or claims media
	// teardown); startMediaLoop starts nothing while it is set. answerTag is
	// the To tag of Answer's 200, set before the write and cleared by
	// releaseAnsweringClaim; onAck accepts only an ACK carrying it. acked and
	// ackBody record the first such ACK of the INVITE. All guarded by
	// u.calls.mu.
	mediaAwaitingAnswer bool
	// reinviteInFlight is true from the moment refreshSession builds its
	// re-INVITE until that transaction returns (CF-124). The session refresher
	// is the only in-dialog INVITE sender today and one dialog runs one
	// refresher, so a bool is exact; a second sender must make it a counter.
	// Guarded by u.calls.mu; read through ourOfferOutstandingLocked.
	reinviteInFlight bool
	// mediaStarting is set by applyAckAnswer in the section that installs the
	// answer and cleared once its startMediaLoop returns (published or not),
	// so no control operation claims the dialog in between and makes the
	// media loop's publication check drop the loop. Guarded by u.calls.mu.
	mediaStarting bool
	answerTag     string
	acked         bool
	ackBody       []byte
	// mediaLoop owns this dialog's RTP goroutines once it is answered. nil until
	// phaseAnswered; stopped by teardownDialog / Hangup / onBye alongside
	// mediaConn's close.
	mediaLoop *mediaLoop
	// recCounter/recName back media_record's per-call default naming (§3.4):
	// recording.wav, recording-2.wav, ... so two sequential unnamed recordings
	// never collide on the store's O_EXCL create. recName is the active
	// recording's resolved name, "" when none is active.
	recCounter int
	recName    string

	// callHandle is the session-level call handle (DialRequest/AnswerRequest.
	// CallHandle), opaque to sipua — used ONLY as the artifact-store key so a
	// media_plan record step (Task 8) and the discrete media_record_* tools
	// (Task 6) key the same call's artifacts identically. "" until Dial/Answer
	// sets it below.
	callHandle string

	// mediaPlanSteps is the §10.7 plan (DialRequest/AnswerRequest.MediaPlan),
	// set by Dial/Answer. startMediaLoop launches the executor from this field
	// once the media loop is up.
	mediaPlanSteps []session.MediaPlanStep

	// mediaPlan is the per-call §10.7 executor. nil until Task 8 launches one;
	// MediaPlanView reports absent until then.
	mediaPlan *mediaPlan

	// dtmfMode is this dialog's EFFECTIVE DTMF mode: "" means "use the
	// profile default" (Config.DTMFMode via dtmfModeDefault). It is set by the
	// first dtmf_send that names a mode explicitly, so call_status.dtmf_mode
	// reports what the call is actually using (§4). Guarded by u.calls.mu.
	dtmfMode string

	// dtmfWaiter is the collector of the ONE in-flight wait_dtmf plan step
	// (§10.7), or nil when no such step is parked. waitForDigits installs it and
	// always compare-and-clears it before returning; handleDigit reads it on the
	// RX goroutine. Guarded by u.calls.mu — the waiter's OWN contents are
	// guarded by its own mutex (see digitWaiter).
	dtmfWaiter *digitWaiter

	// dtmfSendInFlight is SendDTMF's dialog-level single-flight claim: true
	// while ANY dtmf_send (any of the three modes) is running on this dialog.
	//
	// F1 (Phase 4 W1): this field used to be named dtmfInfoInFlight and was
	// claimed only by the info arm, which meant each mode was excluded only
	// against ITSELF — inband via claimOp(opDTMFInband), rfc2833 via
	// claimEventTX (deliberately independent of st.op, per medialoop.go's own
	// doc comment), info via this flag. Nothing excluded a concurrent send of
	// a DIFFERENT mode on the same dialog, which let a stolen tick violate
	// inband's DTMFSource continuous-phase assumption: runTX skips pulling
	// currentSrc().Frame() on any tick an rfc2833 event is active (RFC 4733
	// §2.5.2.2 audio suppression, correct for a PromptSource, but not
	// tolerated by a DTMFSource). Generalizing this ONE field (Rule 16/18,
	// not a fourth mechanism) to cover every mode, and claiming it once in
	// SendDTMF — after the phase/ml read, before the mode dispatch, released
	// by defer — closes that gap at the single choke point every mode passes
	// through. The per-arm mechanisms (claimOp, claimEventTX) are UNCHANGED
	// and keep serving their own purposes: claimOp also excludes play/record,
	// and claimEventTX is deliberately independent of the media slot so an
	// rfc2833 send coexists with a play. Guarded by u.calls.mu; claimed and
	// released only by SendDTMF (dtmf.go).
	dtmfSendInFlight bool

	// localCSeq is the offset added to the answered INVITE's CSeq for each
	// in-dialog request THIS UA originates (INFO, UPDATE, BYE). sipgo's own
	// TransactionRequest (called with no options, per RawTransaction) bumps CSeq
	// ONE MORE TIME on top of the value computed here, wire-verified. An
	// OUTBOUND dialog therefore starts at 0, so the first such request is
	// invite_cseq+1 (CF-085, RFC 3261 12.2.1.1: contiguous). An INBOUND dialog
	// starts at 1: there the base is the PEER's INVITE CSeq and our own local
	// sequence number is empty until our first request (12.1.1), so any first
	// value is compliant. buildInDialogRequest bumps this field under u.calls.mu
	// so two concurrent senders cannot reuse a number, satisfying
	// §12.2.1.1's strictly-increasing rule.
	localCSeq uint32

	// remoteCSeq is the highest CSeq the PEER has used in this dialog and
	// remoteCSeqSet says it is not empty (RFC 3261 12.2.2, CF-101). An inbound
	// dialog seeds it lazily from its INVITE's CSeq (12.1.1), an outbound one
	// from the peer's first in-dialog request (12.1.2). Guarded by u.calls.mu;
	// see remoteCSeqBelowLocked.
	remoteCSeq    uint32
	remoteCSeqSet bool

	// sessionTimer is this dialog's RFC 4028 state, nil when no session timer
	// was negotiated (which is the common case against a peer that never
	// advertises timer support). Guarded by u.calls.mu; Tasks 29 and 30 own its
	// refresher and watchdog.
	sessionTimer *sessionTimerState

	// timerReq is what the INBOUND INVITE asked for under RFC 4028, read ONCE at
	// dialog creation. Answer reads it to decide 422-vs-200 and which refresher
	// role to claim. Zero-valued (Present false) on an outbound dialog.
	timerReq inboundTimerRequest

	// controlOpEnded is non-nil exactly while phase == phaseControlOp. The
	// owning operation receives it from claimControlOpLocked and selects on it;
	// every teardown path that can end an established dialog closes it
	// (endControlOpLocked) in the SAME critical section that sets phaseDone, so
	// the owner settles at once instead of waiting out its own timeout on a
	// dead dialog. Guarded by u.calls.mu.
	controlOpEnded chan struct{}

	// referWaiter collects the NOTIFYs of this dialog's ONE in-flight
	// call_transfer (transfer.go), or is nil. Installed BEFORE the REFER is sent
	// (so an early NOTIFY is matched) and compare-and-cleared by concludeRefer.
	// Guarded by u.calls.mu; the waiter's own state has its own mutex.
	referWaiter *referWaiter

	// referSubsMaybeLive counts the earlier REFERs on this dialog that
	// concluded without their implicit subscription being known to be over
	// (plan D13: the outcome deadline, no REFER response, teardown mid-wait, or
	// a final NOTIFY that did not say terminated), and referSubsLiveUntil is
	// the instant after which no stray NOTIFY from any of them is plausible
	// (CF-012). While referSubsMaybeLive > 0 and now is before that instant, a
	// NOTIFY without an Event id is ambiguous — it could belong to an earlier
	// subscription — and is not routed to the in-flight transfer, which needs
	// an exact id. Evaluated when a NOTIFY is routed (referIdlessAmbiguousLocked),
	// not snapshotted. concludeRefer adds to the count and extends the instant;
	// a terminated refer NOTIFY from the peer that arrives with no transfer in
	// flight ends one counted subscription (noteReferSubEndedLocked). A REFER
	// rejected outright (no subscription) or whose subscription the notifier
	// terminated adds nothing. Guarded by u.calls.mu.
	referSubsMaybeLive int
	referSubsLiveUntil time.Time
	// referEndedCSeq is the CSeq of the last NOTIFY counted as termination
	// evidence, so a retransmission of it is not counted again.
	referEndedCSeq uint32

	// arrivals orders this dialog's gated inbound requests (NOTIFY, BYE) by
	// wire arrival, not by goroutine scheduling (arrival.go, plan D18). Zero
	// value ready. Guarded by u.calls.mu.
	arrivals arrivalOrder

	// controlOpKind is WHICH control operation holds the dialog — set by
	// claimControlOpLocked, cleared with controlOpEnded; "" whenever phase !=
	// phaseControlOp. Reported by ControlOpState and ControlOpBlocksHangup
	// (plan D15). Guarded by u.calls.mu.
	controlOpKind session.ControlOpKind

	// controlOpBlocksHangup is true while the running control operation still
	// needs the call_hangup TOOL held off (plan D17, spec §3 amendment): set by
	// claimControlOpLocked, cleared by the owner's
	// allowHangupDuringControlOpLocked (a transfer: once its REFER is accepted)
	// and by release/end. The phase itself — and so the refusal of dtmf_send,
	// media_record_* and a second control op — is unaffected. Guarded by
	// u.calls.mu.
	controlOpBlocksHangup bool

	// controlOpEndedByHangup records that THIS UA's own BYE (hangupWithReason)
	// ended the dialog while a control operation held it — set by
	// endControlOpByLocalHangupLocked in the SAME critical section that closes
	// controlOpEnded, so an owner woken by that close reads it reliably under
	// u.calls.mu and can report "the transferor hung up" rather than "the
	// dialog ended" (plan D17). Never cleared: the dialog is phaseDone and
	// forgotten by then. Guarded by u.calls.mu.
	controlOpEndedByHangup bool

	// sendOrder is the per-dialog send-order token (plan D12): a 1-slot channel
	// sendInDialog (indialog.go) holds from BEFORE buildInDialogRequest reserves
	// a CSeq until the transaction layer has written the request, so in-dialog
	// requests reach the wire in CSeq order. Created lazily by
	// sendOrderTokLocked, so a dialog literal needs no initialisation. The
	// pointer is guarded by u.calls.mu; the token itself is not a lock order
	// peer of u.calls.mu — it is always taken FIRST.
	sendOrder chan struct{}

	// cancelReq is the RFC 3261 §9.1 CANCEL for the INVITE leg currently
	// outstanding on an OUTBOUND dialog, or nil while that leg has drawn no
	// provisional (a CANCEL MUST NOT be sent before one). Built from d.invite
	// by dialProvisional on the leg's first 1xx — on runDial's goroutine, the
	// only one that mutates d.invite — and cleared by nextDialLeg before a
	// digest or 422 retry sends a NEW INVITE (new branch, new CSeq).
	// cancelRequested is set, never cleared, by a Hangup before the dialog is
	// established: outbound (up to and including phaseAnswering) or, since CF-041,
	// inbound in phaseAnswering (Answer is writing its 200; whichever Answer
	// section settles it ends the call). While an outbound dial
	// is still dialing/ringing, whichever of the two is set SECOND sends the
	// CANCEL, so it goes out exactly once per leg. Once the 200 is in
	// (phaseAnswering) no CANCEL is sent at all: runDial's final claim BYEs the
	// call instead, as it ACK-then-BYEs a 200 that crossed a CANCEL. Both
	// guarded by u.calls.mu.
	cancelReq       *sip.Request
	cancelRequested bool
	// cancelWait is non-nil while a Hangup of a not-yet-established dialog
	// (outbound dial, or inbound in phaseAnswering) waits (bounded by
	// cancelWaitCap) for its deferred CANCEL or for the answering-window BYE
	// (runDial's, or Answer's). Whoever clears it under u.calls.mu
	// resolves it, exactly once, with an already-wrapped result: dialProvisional
	// sends the CANCEL's write result AFTER the write, runDial's answering-window
	// path sends the BYE's (resolveCancelWait) once its transaction returns — the
	// 1-buffered send never blocks — and teardownDialog or onBye close it (a nil
	// result) when the dial settles or the peer ends it otherwise.
	cancelWait chan error
	// cancelSent is closed, exactly once, when a CANCEL for this outbound dial
	// has been ATTEMPTED (markCancelSent), so driveTx re-arms its wait to
	// postCancelWait instead of the ring budget (CF-030). nil on an inbound
	// dialog; Dial is the only constructor of an outbound one and makes it.
	cancelSent chan struct{}

	// earlyAnswers holds, per To tag, the first SDP body seen in a provisional
	// response on the INVITE leg in flight (RFC 3261 13.2.1: the first session
	// description received is the answer, per early dialog; CF-161). Written by
	// dialProvisional, reset by nextDialLeg (a new INVITE is a new exchange),
	// read by runDial's answer site; bounded by maxForkTags. Guarded by
	// u.calls.mu. A first SDP over maxEarlySDPLen is not kept: its tag maps to an
	// empty entry ("the first SDP is unusable"), so a later SDP for that tag is
	// not taken as the first one and the 2xx for it fails the call (CF-205).
	// Bytes held are bounded by maxForkTags x maxEarlySDPLen. answerSDP is the outbound answer body chosen at the 2xx,
	// applied or attempted (the early entry for the 2xx's tag, else the 2xx's
	// body); guarded by u.calls.mu.
	earlyAnswers map[string][]byte
	answerSDP    []byte
	// localSDP is our last SDP sent in this dialog after a peer re-offer was
	// applied (nil: derive it as before, from d.ok or d.invite); peerSDP is the
	// peer's last SDP we accepted (nil: derive it, see peerSDPLocked). A
	// refresh re-INVITE replays localSDP. peerOfferPending is held by an incoming
	// in-dialog INVITE (offer or not) or offer-carrying UPDATE until its final
	// response is sent (RFC 3261 14.2: another one meanwhile draws 500). All
	// guarded by u.calls.mu.
	localSDP         []byte
	peerSDP          []byte
	peerOfferPending bool
	// localSDPIsOffer: d.localSDP is our offer (an offerless re-INVITE's 2xx,
	// CF-207), not an answer. Guarded by u.calls.mu.
	localSDPIsOffer bool

	// remoteTarget is the remote target once a target-refresh request we answered
	// 2xx, or a 2xx to ours, replaced it (RFC 3261 12.2.1.2, 12.2.2, RFC 6141
	// 4.6/4.7); nil means the one dialogRoute derives from the INVITE and its 2xx.
	// Guarded by u.calls.mu; the pointed-to Uri is a private clone, never mutated
	// after it is stored.
	remoteTarget *sip.Uri

	// peerReinvite is the newest re-INVITE from the peer that we answered 2xx,
	// from just before that 2xx is written until the dialog ends (CF-208); its
	// ACK sets acked (onAck). A later re-INVITE's 2xx replaces it (B-D10).
	// Guarded by u.calls.mu.
	peerReinvite *peerReinviteState

	// Redirect state (CF-090). maxRedirects and checkRedirect are copied from
	// the DialRequest by Dial before runDial starts; redirected and everSips are
	// set as legs are retargeted. All four are touched only by runDial's
	// goroutine after Dial (the d.invite convention).
	maxRedirects  int
	checkRedirect func(string) (string, error)
	redirected    bool // a redirect has been followed: a later 4xx/5xx may fail over
	everSips      bool // some leg had a sips: Request-URI: never downgrade to sip:
}

// callIDOf reads a request's Call-ID. sipua is the ONLY package that ever sees
// it: session.Call keys its ladder on the value handed up from here.
func callIDOf(req *sip.Request) string {
	if h := req.CallID(); h != nil {
		return h.Value()
	}
	return ""
}

// toTagOf reads the "tag" param off a message's To header, or "" if the
// message carries none. A populated To-tag is what marks an INVITE as
// IN-DIALOG (D2): a genuinely new call's To header never carries one.
func toTagOf(req sip.Message) string {
	to := req.To()
	if to == nil {
		return ""
	}
	tag, _ := to.Params.Get("tag")
	return tag
}

// fromTagOf reads the "tag" param off a request's From header, or "" if the
// request carries none. onNotify matches it against the peer's tag (plan D13).
func fromTagOf(req *sip.Request) string {
	from := req.From()
	if from == nil {
		return ""
	}
	tag, _ := from.Params.Get("tag")
	return tag
}

type callRegistry struct {
	mu      sync.Mutex
	byID    map[string]*dialog
	onEvent session.UAEventFunc
	evCtx   context.Context // the DAEMON context OnEvent was registered with
	// onAdmit is the SYNCHRONOUS inbound-admission decision channel (I2),
	// registered by OnAdmit and DISTINCT from the one-way onEvent. admitCtx is
	// the DAEMON context it was registered with.
	onAdmit  session.AdmitFunc
	admitCtx context.Context
	// closed is set by UA.Close's sweep (stopAllMediaLoops(true)) and never
	// cleared. byes counts each BYE owed for an ESTABLISHED dialog, from its
	// claim until that BYE's sendInDialog returns; Close waits for it, bounded
	// by closeByeWait, before it closes the transport (CF-061). Add runs ONLY
	// under mu, and only while closed is false or in the sweep that sets it,
	// so no Add can start from zero once Close is waiting.
	closed bool
	byes   sync.WaitGroup
	// heldInvites counts the initial-INVITE handlers onInvite holds until their
	// transaction ends (CF-177), and merged records the (Call-ID, From tag,
	// CSeq) of each so a second transaction with the same triple is a merged
	// request (CF-097, RFC 3261 8.2.2.2). Both guarded by mu; the table's size
	// is at most heldInvites, which claimInviteHold bounds.
	heldInvites int
	merged      map[mergeKey]*mergeHold
}

// mergeKey is the (Call-ID, From tag, CSeq number) triple of RFC 3261 8.2.2.2.
type mergeKey struct {
	callID, fromTag string
	cseq            uint32
}

// mergeHold is the server transaction that owns a mergeKey and how many held
// handlers share that exact transaction identity.
type mergeHold struct {
	txKey string
	holds int
}

// heldInviteFactor times the live call limit bounds the held INVITE handlers:
// each live call's handler is held until Timer L (32 s after its 200), and up
// to three generations of ended-but-held transactions per call slot can still
// wait out Timer H (32 s).
const heldInviteFactor = 4

// heldInviteBound is the most INVITE handlers onInvite may hold, saturating at
// math.MaxInt. CallLimit reads the policy store, which has its own lock, so
// this runs before u.calls.mu is taken.
func (u *UA) heldInviteBound() int {
	if u.cfg.CallLimit == nil {
		return math.MaxInt
	}
	limit := max(u.cfg.CallLimit(), 1)
	if limit > math.MaxInt/heldInviteFactor {
		return math.MaxInt
	}
	return limit * heldInviteFactor
}

// claimInviteHold admits req's handler to the held set. status is 0 on success
// (the caller must releaseInviteHold(key) once the hold ends), 482 when another
// transaction already owns req's merge key, 503 when the bound is full.
func (u *UA) claimInviteHold(req *sip.Request) (key mergeKey, status int) {
	key = mergeKey{callID: callIDOf(req), fromTag: fromTagOf(req)}
	if cs := req.CSeq(); cs != nil {
		key.cseq = cs.SeqNo
	}
	// The transaction layer computed this key to route req here, so it cannot
	// fail for a request that reached a handler.
	txKey, _ := sip.MakeServerTxKey(req)
	bound := u.heldInviteBound()
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	m := u.calls.merged[key]
	if m != nil && m.txKey != txKey {
		return key, 482
	}
	if u.calls.heldInvites >= bound {
		return key, 503
	}
	u.calls.heldInvites++
	if m == nil {
		if u.calls.merged == nil {
			u.calls.merged = map[mergeKey]*mergeHold{}
		}
		m = &mergeHold{txKey: txKey}
		u.calls.merged[key] = m
	}
	m.holds++
	return key, 0
}

// releaseInviteHold undoes one successful claimInviteHold. Caller holds no lock.
// Equal-key holds can overlap (sipgo can create two transactions for identical
// requests, and a replacement can claim before the old release runs), so the
// entry goes away only with its last hold.
func (u *UA) releaseInviteHold(key mergeKey) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	u.calls.heldInvites--
	m := u.calls.merged[key] // non-nil: every release pairs with a successful claim
	if m.holds--; m.holds == 0 {
		delete(u.calls.merged, key)
	}
}

func newDialogID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b)
}

// OnEvent installs THE single upward callback; a second call replaces the
// first.
//
// ctx is the LONG-LIVED DAEMON context (locked decision 17) and is retained,
// so every emitted event is delivered on it. It is NEVER an HTTP request
// context: a client disconnect must not cancel event delivery for a live call,
// or D11 point 5 and R8 both break.
func (u *UA) OnEvent(ctx context.Context, fn session.UAEventFunc) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	u.calls.onEvent, u.calls.evCtx = fn, ctx
}

func (u *UA) emit(ev session.UAEvent) {
	u.calls.mu.Lock()
	fn, ctx := u.calls.onEvent, u.calls.evCtx
	u.calls.mu.Unlock()
	if fn == nil {
		return
	}
	if ctx == nil {
		ctx = u.uaCtx
	}
	fn(ctx, ev)
}

// OnAdmit installs THE synchronous inbound-admission handler (I2); a second
// call replaces the first. The handler (and OnEvent's) must not call Answer or
// Reject for the dialog being admitted: they wait for this admission to
// finish and would block on their own onInvite until the UA closes.
//
// It is DISTINCT from OnEvent — that channel stays one-way — and its ctx is the
// LONG-LIVED DAEMON context (decision 17), retained so every admission decision
// is made on it.
func (u *UA) OnAdmit(ctx context.Context, fn session.AdmitFunc) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	u.calls.onAdmit, u.calls.admitCtx = fn, ctx
}

// admit asks the registered handler whether to accept an inbound INVITE. It is
// the request/response twin of emit, and — like emit — it copies the callback
// out UNDER u.calls.mu and invokes it AFTER releasing the lock (§6.0b lock
// discipline: the admit call runs OUTSIDE u.calls.mu, and the handler must not
// re-enter the UA). With no handler registered it accepts, preserving the
// pre-I2 "ring every inbound INVITE" behaviour.
func (u *UA) admit(ev session.UAEvent) session.Admission {
	u.calls.mu.Lock()
	fn, ctx := u.calls.onAdmit, u.calls.admitCtx
	u.calls.mu.Unlock()
	if fn == nil {
		return session.AdmitAccept()
	}
	if ctx == nil {
		ctx = u.uaCtx
	}
	return fn(ctx, ev)
}

func (u *UA) lookup(id string) (*dialog, error) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d, ok := u.calls.byID[id]
	if !ok {
		return nil, apierr.NotFound("unknown call handle")
	}
	return d, nil
}

// MediaView reports the negotiated codec/local media addr/srtp for a dialog
// (§10.3). ok is false when no media.Session has been negotiated on it.
func (u *UA) MediaView(dialogID string) (session.MediaView, bool) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return session.MediaView{}, false
	}
	u.calls.mu.Lock()
	s, ml := d.mediaSession, d.mediaLoop
	u.calls.mu.Unlock()
	if s == nil {
		return session.MediaView{}, false
	}
	mv := session.MediaView{
		Codec:           s.Codec,
		LocalMediaAddr:  s.LocalAddr,
		SRTP:            s.LocalCrypto != nil && s.RemoteCrypto != nil,
		RemoteMediaAddr: s.RemoteAddr,
	}
	if ml != nil {
		if addr, latched := ml.observedRemote(); addr != "" {
			mv.RemoteMediaAddr, mv.Latched = addr, latched
		}
	}
	return mv, true
}

// QualityView is §10.10. ok is false when no media loop is running (the call is
// not answered, or has been torn down).
func (u *UA) QualityView(dialogID string) (session.QualityView, bool) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return session.QualityView{}, false
	}
	u.calls.mu.Lock()
	ml := d.mediaLoop
	u.calls.mu.Unlock()
	if ml == nil {
		return session.QualityView{}, false
	}
	return qualityViewFromLoop(ml), true
}

// qualityViewFromLoop translates the pure media Snapshot into the session view.
func qualityViewFromLoop(ml *mediaLoop) session.QualityView {
	s := ml.snapshot()
	gaps := make([]map[string]any, 0, len(s.BurstGaps))
	for _, g := range s.BurstGaps {
		gaps = append(gaps, map[string]any{"at_ms": g.AtMs, "packets": g.Packets})
	}
	return session.QualityView{
		Tier: s.Tier, Codec: s.Codec, DurationMs: s.DurationMs,
		PacketsSent: s.PacketsSent, PacketsReceived: s.PacketsReceived, PacketsLost: s.PacketsLost,
		LossPct: s.LossPct, OutOfOrder: s.OutOfOrder, Duplicates: s.Duplicates,
		LateDiscards: s.LateDiscards, RogueSourcePackets: s.RogueSourcePackets,
		TXUnderruns: s.TXUnderruns, SRTPAuthFailures: s.SRTPAuthFailures,
		BurstGaps: gaps, JitterMsAvg: s.JitterMsAvg, JitterMsPeak: s.JitterMsPeak,
		RFactor: s.RFactor, MOSEstimate: s.MOSEstimate,
		MOSLQO: s.MOSLQO, PESQRaw: s.PESQRaw, Reference: s.Reference,
	}
}

// MediaPlanView implements session.UserAgent.MediaPlanView (§10.7). ok is false
// when no media_plan ran on the dialog.
func (u *UA) MediaPlanView(dialogID string) (session.MediaPlanView, bool) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return session.MediaPlanView{}, false
	}
	u.calls.mu.Lock()
	mp := d.mediaPlan
	u.calls.mu.Unlock()
	if mp == nil {
		return session.MediaPlanView{}, false
	}
	return mp.view(), true
}

// mediaPlan is the per-call §10.7 executor: its run loop strictly orders the
// plan's steps, emits plan_step/record_start/record_stop/error events, and
// aborts (without tearing down the call) on a step failure or a call
// termination mid-plan.
type mediaPlan struct {
	u          *UA
	ml         *mediaLoop
	dialogID   string
	callID     string
	direction  session.Direction
	callHandle string
	steps      []session.MediaPlanStep

	mu             sync.Mutex
	state          string
	stepsTotal     int
	stepsCompleted int
	failedIndex    int
	failedOp       string
}

func (mp *mediaPlan) view() session.MediaPlanView {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return session.MediaPlanView{
		State: mp.state, StepsTotal: mp.stepsTotal, StepsCompleted: mp.stepsCompleted,
		FailedIndex: mp.failedIndex, FailedOp: mp.failedOp, Present: true,
	}
}

func (mp *mediaPlan) setState(s string) {
	mp.mu.Lock()
	mp.state = s
	mp.mu.Unlock()
}

// terminated reports whether the call's media loop has stopped (call torn down).
func (mp *mediaPlan) terminated() bool {
	select {
	case <-mp.ml.done:
		return true
	default:
		return false
	}
}

// run executes the plan strictly in order (§10.7). A step failure aborts the
// plan (not the call); a call termination mid-plan aborts with
// plan_aborted_call_terminated. It runs on its own goroutine and never holds
// u.calls.mu across a blocking wait.
func (mp *mediaPlan) run() {
	for i := range mp.steps {
		if mp.terminated() {
			mp.abortTerminated(i)
			return
		}
		step := mp.steps[i]
		mp.emitStep(i, step.Op, "") // entry

		code, msg := mp.execStep(step)

		if code == "" && mp.terminated() && step.Op != "hangup" {
			// The call ended DURING the step (not by our own hangup).
			mp.abortTerminated(i)
			return
		}
		if code != "" {
			mp.emitStep(i, step.Op, "failed")
			mp.emitError(map[string]any{
				"kind": "plan_step_failed", "index": i, "op": step.Op,
				"code": code, "message": msg,
			})
			mp.mu.Lock()
			mp.state, mp.failedIndex, mp.failedOp = "failed", i, step.Op
			mp.mu.Unlock()
			return
		}
		mp.emitStep(i, step.Op, "ok")
		mp.mu.Lock()
		mp.stepsCompleted = i + 1
		mp.mu.Unlock()
		if step.Op == "hangup" {
			break // a hangup step ends the plan
		}
	}
	mp.setState("completed")
}

// planCode maps err to the §11.2 code execStep reports on step failure. Any
// error apierr.CodeOf cannot classify (a raw, non-apierr error from real I/O —
// e.g. Artifacts.Create/NewWAVRecorder/rec.Close/Artifacts.Close/a rejected
// BYE) still means the step failed; it must not be silently treated as an
// empty ("" == success) code.
func planCode(err error) string {
	if err == nil {
		return ""
	}
	if code := apierr.CodeOf(err); code != "" {
		return string(code)
	}
	return string(apierr.CodeInternal)
}

// execStep performs one step, returning ("","" ) on success or the §11.2 code +
// message the equivalent discrete tool would have returned on failure.
func (mp *mediaPlan) execStep(step session.MediaPlanStep) (code, msg string) {
	ctx := context.Background()
	switch step.Op {
	case "play":
		// Inside a plan, play is always wait_complete=true — sequencing is the
		// plan's job (§3.5).
		if _, err := mp.u.Play(ctx, mp.dialogID, step.Prompt, step.Repeat, true); err != nil {
			return planCode(err), err.Error()
		}
	case "record":
		name, err := mp.u.RecordStart(ctx, mp.dialogID, mp.callHandle, step.Name)
		if err != nil {
			return planCode(err), err.Error()
		}
		// §10.5's record_start/record_stop events fire for a plan-driven
		// recording exactly as they do for the discrete media_record_* tools —
		// the canonical event list draws no distinction by trigger. Mirrors
		// handleMediaStart's pattern: sipua emits, session appends (Task 8/§4.5
		// keeps sipua from importing session's Call/event-log types directly).
		mp.emitRecord(session.UAEventRecordStart, map[string]any{"name": name})
		if !mp.sleep(step.DurationMs) { // returns false if call terminated
			// stop the recording best-effort; the run loop will detect termination
			_, _, _ = mp.u.RecordStop(ctx, mp.dialogID, mp.callHandle, "")
			return "", ""
		}
		info, dur, err := mp.u.RecordStop(ctx, mp.dialogID, mp.callHandle, "")
		if err != nil {
			return planCode(err), err.Error()
		}
		mp.emitRecord(session.UAEventRecordStop, map[string]any{
			"name": info.Name, "duration_ms": dur, "bytes": info.Bytes, "uri": info.URI,
		})
	case "wait":
		mp.sleep(step.DurationMs)
	case "dtmf":
		// Inside a plan a dtmf step is always synchronous — sequencing is the
		// plan's job (§3.5), exactly as play is always wait_complete=true. The
		// mode is the step's own when it named one, else "" so SendDTMF applies
		// the profile default; there is no second place that resolves it.
		//
		// step.GapMs is passed through VERBATIM, including a 0. decodeDTMF
		// already resolved the tri-state at validation time, through the same
		// session.ResolveDTMFTiming that SendDTMF's resolver calls — it had to,
		// because the plan's min-duration bound needs concrete numbers before
		// the call is dialed. An explicit `gap_ms: 0` in the plan means NO GAP,
		// and because the shared resolver is idempotent 0 stays 0 and
		// DefaultDTMFGapMs stays DefaultDTMFGapMs on the second pass (Rule 18:
		// one resolver function, one meaning, two necessary call sites).
		if _, _, err := mp.u.SendDTMF(ctx, mp.dialogID, step.Digits,
			session.DTMFMode(step.Mode), int(step.DurationMs), int(step.GapMs)); err != nil {
			if mp.terminated() {
				// The call ended DURING the send. §10.7 says a mid-plan call
				// termination is plan_aborted_call_terminated, not a step
				// failure — surfacing SendDTMF's "the call ended before the
				// digits were sent" precondition_failed here would make dtmf
				// the ONLY op whose mid-plan teardown reports
				// media_plan.state == "failed". The sibling arms already have
				// this exact shape: Play returns nil on a mid-play teardown and
				// the record arm returns ("",""), both so run()'s own
				// terminated() check does the reporting.
				return "", ""
			}
			return planCode(err), err.Error()
		}
	case "wait_dtmf":
		// Decision 14: timeout_ms bounds the WHOLE collection window — no
		// inter-digit timeout, no terminator digit. A timeout is a STEP
		// FAILURE (the plan aborts, the call stays answered); a digit
		// MISMATCH is not (it is recorded and the plan continues).
		//
		// mp.dialog() can be nil if the call already ended (the registry
		// forgets the dialog BEFORE ml.stop() closes ml.done) — waitForDigits
		// tolerates a nil dialog by skipping the waiter install and still
		// parking on ml.done, so mp.terminated() reads true by the time this
		// returns and the guard below correctly aborts instead of reporting a
		// false step success.
		//
		// The failure code is precondition_failed: §11.2's enum
		// (internal/apierr/apierr.go) defines no timeout or deadline code,
		// and inventing one would put a value on the wire no consumer can
		// interpret.
		d := mp.dialog()
		collected, timedOut := mp.u.waitForDigits(d, mp.ml, step.Digits, step.TimeoutMs)
		if timedOut {
			if mp.terminated() {
				// The call ended DURING the collection window: waitForDigits
				// parks on ml.done as well as the timeout and cannot tell the
				// two apart from its bool alone. §10.7 says a mid-plan call
				// termination is plan_aborted_call_terminated, not a step
				// failure — and the dtmf arm above carries this exact guard
				// for this exact reason. Without it wait_dtmf would join
				// dtmf as an op whose mid-plan teardown reports
				// media_plan.state == "failed", which is the bug that
				// comment describes.
				return "", ""
			}
			// B-M2: the message must not name the collected digits (this
			// codebase's convention elsewhere is to never leak a digit
			// string that can carry a PIN or card number — see
			// sendDTMFInfo's index-only error text) and must not
			// contradict itself: "no digits" was misleading whenever
			// step.Digits names a specific count, since a partial prefix
			// can have already arrived before the timeout fired.
			return string(apierr.CodePreconditionFailed), fmt.Sprintf(
				"wait_dtmf: timed out after %dms before collecting the expected digits", step.TimeoutMs)
		}
		if step.Digits != "" && collected != step.Digits {
			mp.emitError(map[string]any{
				"kind": "wait_dtmf_mismatch", "expected": step.Digits, "received": collected,
			})
		}
	case "hangup":
		if err := mp.u.Hangup(ctx, mp.dialogID, step.Reason); err != nil {
			return planCode(err), err.Error()
		}
	default:
		// Unreachable: validation rejects unknown ops before the plan launches.
		return string(apierr.CodeInvalidArgument), "unknown op " + step.Op
	}
	return "", ""
}

// dialog resolves the executor's dialog through the registry. It returns nil
// once the dialog has been forgotten (the call ended mid-plan), which every
// caller treats as "the call is gone" — the run loop's own terminated() check
// then aborts the plan on the next iteration. Resolving through the registry
// rather than holding a *dialog field keeps the executor's existing shape: it
// carries dialogID, callID and direction, and nothing that could outlive them.
func (mp *mediaPlan) dialog() *dialog {
	d, err := mp.u.lookup(mp.dialogID)
	if err != nil {
		return nil
	}
	return d
}

// sleep waits duration_ms or until the call terminates; returns false if the
// call terminated first.
func (mp *mediaPlan) sleep(ms int64) bool {
	if ms <= 0 {
		return !mp.terminated()
	}
	select {
	case <-mp.ml.done:
		return false
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return true
	}
}

func (mp *mediaPlan) abortTerminated(index int) {
	mp.mu.Lock()
	mp.state, mp.failedIndex, mp.failedOp = "aborted", index, ""
	mp.mu.Unlock()
	mp.emitError(map[string]any{
		"kind": "plan_aborted_call_terminated", "index": index,
	})
}

func (mp *mediaPlan) emitStep(index int, op, status string) {
	if mp.ml.emit == nil {
		return
	}
	detail := map[string]any{"index": index, "op": op}
	if status != "" {
		detail["status"] = status
	}
	mp.ml.emit(session.UAEvent{
		Kind: session.UAEventPlanStep, DialogID: mp.dialogID, CallID: mp.callID,
		Direction: mp.direction, Detail: detail,
	})
}

func (mp *mediaPlan) emitError(detail map[string]any) {
	if mp.ml.emit == nil {
		return
	}
	mp.ml.emit(session.UAEvent{
		Kind: session.UAEventMediaError, DialogID: mp.dialogID, CallID: mp.callID,
		Direction: mp.direction, Detail: detail,
	})
}

// emitRecord fires §10.5's record_start/record_stop for a plan-driven record
// step (kind is session.UAEventRecordStart or session.UAEventRecordStop).
func (mp *mediaPlan) emitRecord(kind session.UAEventKind, detail map[string]any) {
	if mp.ml.emit == nil {
		return
	}
	mp.ml.emit(session.UAEvent{
		Kind: kind, DialogID: mp.dialogID, CallID: mp.callID,
		Direction: mp.direction, Detail: detail,
	})
}

// launchMediaPlan constructs and starts the per-call plan executor. Caller
// MUST hold u.calls.mu (production calls it from startMediaLoop's critical
// section, §3.5); it stores mp on the dialog for MediaPlanView and starts the
// run goroutine (non-blocking).
func (u *UA) launchMediaPlan(d *dialog, ml *mediaLoop, steps []session.MediaPlanStep) {
	mp := &mediaPlan{
		u: u, ml: ml, dialogID: d.id, callID: d.callID, direction: d.direction,
		callHandle: d.callHandle, steps: steps,
		state: "running", stepsTotal: len(steps), failedIndex: -1,
	}
	d.mediaPlan = mp
	go mp.run()
}

// Play implements session.UserAgent.Play (§10.9 media_play). It resolves the
// prompt NAME against the injected policy prompts map (never an arbitrary path),
// loads and validates the WAV as 8000/mono/16-bit, and atomically swaps the
// call's TX source to a PromptSource. On exhaustion the PromptSource restores the
// prior source and releases the play-or-record slot. duration_ms is deterministic
// (frame count × 20 ms) regardless of wait_complete. A second play or an active
// record on the same call returns precondition_failed (§3.3 step 3).
func (u *UA) Play(ctx context.Context, dialogID, prompt string, repeat int, waitComplete bool) (int64, error) {
	path, ok := u.cfg.Prompts[prompt]
	if !ok {
		return 0, apierr.InvalidArgument("media_play: unregistered prompt " + prompt)
	}
	f, err := os.Open(path)
	if err != nil {
		// The underlying I/O error is logged, not returned: err.Error() embeds
		// the server's configured filesystem path, which an agent must never
		// see (matches this codebase's consistent error-redaction convention
		// everywhere else raw I/O errors are surfaced).
		//
		// C-M6: this inline `if u.cfg.Logger != nil` was already nil-safe —
		// converging it onto u.log() (the package's one nil-safe accessor,
		// keepalive.go) is pure idiom convergence, not a bug fix.
		u.log().Warn("media_play: cannot open prompt file", "prompt", prompt, "err", err)
		return 0, apierr.InvalidArgument("media_play: cannot open prompt " + prompt)
	}
	pcm, err := codec.ReadWAV(f)
	_ = f.Close()
	if err != nil {
		return 0, apierr.InvalidArgument("media_play: prompt " + prompt + ": " + err.Error())
	}
	frames := codec.FramesFromPCM(pcm)
	if len(frames) == 0 {
		return 0, apierr.InvalidArgument("media_play: prompt " + prompt + " is empty")
	}

	d, err := u.lookup(dialogID)
	if err != nil {
		return 0, err
	}
	u.calls.mu.Lock()
	ml := d.mediaLoop
	u.calls.mu.Unlock()
	if ml == nil {
		return 0, apierr.PreconditionFailed("media_play: call has no media stream (not answered)")
	}

	// Claim the single play-or-record-or-DTMF slot AND install the prompt in ONE
	// transition (§2.2). claimOp now owns saving the prior source, so the local
	// `prior` variable the old code kept is gone: releaseOp restores it.
	//
	// B12: the onExhaust hook releases via releaseOpFor(ps), NOT the bare
	// releaseOp() — see releaseOpFor's doc comment (medialoop.go) for the
	// stale-release hazard this closes. var+assign (rather than :=) is
	// required here so the closure can capture ps by reference before its own
	// construction call returns.
	var ps *codec.PromptSource
	ps = codec.NewPromptSource(frames, repeat, func() { ml.releaseOpFor(ps) })
	if !ml.claimOp(opPlay, ps) {
		return 0, apierr.PreconditionFailed("media_play: a play, recording or DTMF is already active on this call")
	}

	dur := ps.DurationMs()
	if !waitComplete {
		return dur, nil
	}
	// Block until the prompt exhausts OR the media loop stops (call torn down).
	select {
	case <-ps.Done():
	case <-ml.done:
		// The call ended mid-play. Ensure the slot is freed so a subsequent op
		// on a still-open call is not wedged. B12: releaseOpFor(ps), not the
		// bare releaseOp() — this arm is exactly the stale-release race
		// releaseOpFor exists to close (see its doc comment): if ps had
		// already exhausted and released itself via onExhaust just before
		// ml.done also fired, and a NEW op had already claimed the slot in
		// that window, an unconditional releaseOp() here would clobber it.
		ml.releaseOpFor(ps)
	case <-ctx.Done():
		// B13: the caller's ctx was cancelled while Play was blocked waiting
		// for the prompt to exhaust. Free the slot so a subsequent op on a
		// still-open call is not wedged, exactly as the ml.done arm above
		// does, and report the cancellation instead of hanging until
		// ps.Done()/ml.done eventually fires (or never does).
		//
		// B12: releaseOpFor(ps), not the bare releaseOp() — this arm has the
		// EXACT SAME stale-release hazard as the ml.done arm above: ps.Done()
		// and ctx.Done() can both be ready near-simultaneously (ps exhausts
		// and releases itself via onExhaust right as the caller's ctx is
		// cancelled), and if a NEW op had already claimed the slot in that
		// window, an unconditional releaseOp() here would clobber it exactly
		// like the ml.done arm's would.
		ml.releaseOpFor(ps)
		return 0, classifyCtxErr(ctx, "media_play")
	}
	return dur, nil
}

// RecordStart implements session.UserAgent.RecordStart (§10.9). It claims the
// single play-or-record slot, resolves the artifact name (default naming from a
// per-call counter, §3.4), creates the artifact through the store, wraps it in a
// WAVRecorder and installs the RX recorder tap. callHandle is the store key
// (resolved server-side by session, never agent-supplied).
func (u *UA) RecordStart(ctx context.Context, dialogID, callHandle, name string) (string, error) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return "", err
	}
	u.calls.mu.Lock()
	ml := d.mediaLoop
	inControlOp := d.phase == phaseControlOp
	u.calls.mu.Unlock()
	if inControlOp {
		return "", apierr.PreconditionFailed("media_record: " + controlOpBusyMsg)
	}
	if ml == nil {
		return "", apierr.PreconditionFailed("media_record: call has no media stream (not answered)")
	}
	if u.cfg.Artifacts == nil {
		return "", apierr.NotSupported("media_record: no artifact store in this build")
	}
	// §13.3: refuse a new recording when the tree is at/over the watermark and
	// no non-live artifacts can be evicted (the janitor never deletes live
	// data). Checking total UsageBytes alone is not enough: the janitor's own
	// watermark eviction (Store.Sweep) only ever considers non-live usage, so
	// a store can be over cap purely because of protected live-call data while
	// still having non-live headroom the janitor would reclaim on its next
	// pass — refusing in that case would be wrong. The single enforcement
	// point for BOTH the discrete media_record_start tool (via ToolService,
	// which just propagates this error) and a media_plan's record step (which
	// calls RecordStart directly) — do not duplicate this check anywhere else.
	if u.cfg.ArtifactMaxBytes > 0 {
		if used, uerr := u.cfg.Artifacts.UsageBytes(ctx); uerr == nil && used >= u.cfg.ArtifactMaxBytes {
			if nonLive, nlErr := u.cfg.Artifacts.NonLiveUsageBytes(ctx); nlErr == nil && nonLive == 0 {
				return "", apierr.ResourceLimit("artifact.max_bytes", int(u.cfg.ArtifactMaxBytes), int(used),
					"artifact store is over its high-watermark and only live-call data remains")
			}
		}
	}
	if !ml.claimOp(opRecord, nil) {
		return "", apierr.PreconditionFailed("media_record: a play, recording or DTMF is already active on this call")
	}
	// Resolve the name under the lock so the counter increments atomically.
	u.calls.mu.Lock()
	resolved := name
	if resolved == "" {
		d.recCounter++
		if d.recCounter == 1 {
			resolved = "recording.wav"
		} else {
			resolved = fmt.Sprintf("recording-%d.wav", d.recCounter)
		}
	}
	d.recName = resolved
	u.calls.mu.Unlock()

	w, err := u.cfg.Artifacts.Create(ctx, callHandle, resolved)
	if err != nil {
		ml.releaseOp()
		u.calls.mu.Lock()
		d.recName = ""
		u.calls.mu.Unlock()
		if errors.Is(err, os.ErrExist) {
			return "", apierr.PreconditionFailed("media_record: an artifact named " + resolved + " already exists")
		}
		return "", err
	}
	rec, err := codec.NewWAVRecorder(w)
	if err != nil {
		_ = w.Close()
		_ = u.cfg.Artifacts.Remove(ctx, callHandle, resolved)
		ml.releaseOp()
		u.calls.mu.Lock()
		d.recName = ""
		u.calls.mu.Unlock()
		return "", err
	}
	if !ml.installRecorder(rec) {
		// stop() already won: it took the terminal transition before this
		// install, so nothing else will ever finalize this recorder.
		_, _ = rec.Close()
		ml.releaseOp()
		u.calls.mu.Lock()
		d.recName = ""
		u.calls.mu.Unlock()
		return "", apierr.PreconditionFailed("media_record: call ended while starting the recording")
	}
	return resolved, nil
}

// RecordStop clears the RX recorder tap, finalises the WAV header, closes the
// store artifact and returns its info plus the recorded duration. name may be ""
// (finalise the active recording) or the explicit name RecordStart returned.
func (u *UA) RecordStop(ctx context.Context, dialogID, callHandle, name string) (session.ArtifactInfo, int64, error) {
	d, err := u.lookup(dialogID)
	if err != nil {
		return session.ArtifactInfo{}, 0, err
	}
	u.calls.mu.Lock()
	ml := d.mediaLoop
	active := d.recName
	inControlOp := d.phase == phaseControlOp
	u.calls.mu.Unlock()
	if inControlOp {
		return session.ArtifactInfo{}, 0, apierr.PreconditionFailed("media_record: " + controlOpBusyMsg)
	}
	if ml == nil {
		return session.ArtifactInfo{}, 0, apierr.PreconditionFailed("media_record: call has no media stream")
	}
	if active == "" {
		return session.ArtifactInfo{}, 0, apierr.PreconditionFailed("media_record: no recording is active on this call")
	}
	if name != "" && name != active {
		return session.ArtifactInfo{}, 0, apierr.PreconditionFailed("media_record: no recording named " + name + " is active")
	}

	// takeRecorder IS the claim, and its atomicity is load-bearing: two
	// concurrent RecordStops (or a RecordStop racing mediaLoop.stop's teardown
	// finalize, Task 4) must resolve to exactly one winner, matching every
	// other concurrent-tool-call pair's one-winner guarantee (governing spec
	// §6.0's concurrent-tool-call invariant). The loser observes nil, hence
	// precondition_failed.
	rec := ml.takeRecorder()
	if rec == nil {
		return session.ArtifactInfo{}, 0, apierr.PreconditionFailed("media_record: no recording is active on this call")
	}
	samples, cerr := rec.Close()
	ml.releaseOp()
	u.calls.mu.Lock()
	d.recName = ""
	u.calls.mu.Unlock()
	if cerr != nil {
		return session.ArtifactInfo{}, 0, cerr
	}
	info, err := u.cfg.Artifacts.Close(ctx, callHandle, active)
	if err != nil {
		return session.ArtifactInfo{}, 0, err
	}
	return info, int64(samples/codec.SamplesPerFrame) * 20, nil
}

func (u *UA) register(d *dialog) {
	_ = u.registerBounded(d, 0)
}

// registerBounded inserts d unless callLimit > 0 and the registry already holds
// callLimit + lingeringDialHeadroom dialogs (CF-038). The count and the insert
// share one u.calls.mu critical section, so concurrent dials cannot overshoot.
// The bound saturates at math.MaxInt: callLimit has no upper bound, so the plain
// sum could wrap negative and refuse every dial. Only Dial passes a limit.
func (u *UA) registerBounded(d *dialog, callLimit int) error {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if callLimit > 0 {
		bound := math.MaxInt
		if callLimit <= math.MaxInt-lingeringDialHeadroom {
			bound = callLimit + lingeringDialHeadroom
		}
		if n := len(u.calls.byID); n >= bound {
			return apierr.DeniedLimit("ua_live_dialogs", bound, n, fmt.Sprintf(
				"this user agent already holds %d SIP dialogs (%d concurrent calls plus %d for calls "+
					"still being torn down); wait for hung-up calls to finish and dial again",
				n, callLimit, lingeringDialHeadroom))
		}
	}
	if u.calls.byID == nil {
		u.calls.byID = map[string]*dialog{}
	}
	u.calls.byID[d.id] = d
	return nil
}

// findByCallIDLocked returns the registered dialog whose SIP Call-ID matches
// cid, or nil. Caller MUST hold u.calls.mu. Canonical Call-ID lookup (Rule 18).
func (u *UA) findByCallIDLocked(cid string) *dialog {
	for _, d := range u.calls.byID {
		if d.callID == cid {
			return d
		}
	}
	return nil
}

// peerReinviteState is the ACK bookkeeping of one re-INVITE of the peer's that we
// answered 2xx.
type peerReinviteState struct {
	cseq  uint32
	acked bool
	// offer and offerSDP are our offer in the 2xx to an offerless re-INVITE (nil
	// when the 2xx carried an answer); the ACK's answer is applied against offer
	// (CF-207). answerPending (B-D13): true from the moment the offer-carrying 2xx
	// is on the wire, or from the ACK's first section if the ACK beats the handler
	// to it, until that ACK's answer is installed or refused; false while the 2xx
	// is still being written, so RFC 3261 14.2's 500 keeps applying in that window.
	offer         *media.Session
	offerSDP      []byte
	answerPending bool
}

// ourOfferOutstandingLocked reports whether an offer of ours on d awaits its
// answer: our re-INVITE is in flight, or our 200's offer awaits the ACK's
// answer (CF-145), or the offer in our 2xx to an offerless re-INVITE awaits the
// answer in its ACK (CF-207, RFC 3264 4). A peer offer arriving meanwhile is glare
// (RFC 3261 14.2, RFC 3311 5.2): 491. Caller MUST hold u.calls.mu.
func ourOfferOutstandingLocked(d *dialog) bool {
	return d.reinviteInFlight || d.mediaAwaitingAnswer || (d.peerReinvite != nil && d.peerReinvite.answerPending)
}

// dialogMatchesLocked reports whether the in-dialog request req belongs to d:
// RFC 3261 12.2.2 / 15.1.2 match by Call-ID (the caller's), the peer's tag (the
// request's From tag) and our tag (its To tag). Caller MUST hold u.calls.mu.
// An inbound dialog whose 200 is not yet stored (admitting, ringing, answering)
// is named by the one To tag we put on its provisionals, d.toTag (CF-072); any
// other tag matches nothing (CF-209, RFC 3261 12.1/15.1.2: 481), and before the
// first tagged response no request can match. An outbound dialog before the 200
// has no peer tag, so no From tag matches (an empty one included): the callee
// "MUST NOT send a BYE on early dialogs" (rfc3261.txt:4980-4982).
func dialogMatchesLocked(d *dialog, req *sip.Request) bool {
	to, peer := toTagOf(req), peerTagLocked(d)
	if to == "" || fromTagOf(req) != peer || (peer == "" && d.direction == session.Outbound) {
		return false
	}
	ours := ourReInviteTagLocked(d)
	if ours == "" {
		return d.direction == session.Inbound && d.toTag != "" && to == d.toTag
	}
	return to == ours
}

// findDialogForRequestLocked returns the registered dialog req belongs to
// (same Call-ID and dialogMatchesLocked), or nil. The match is inside the loop:
// a self-call registers two dialogs with one Call-ID, so a check after a
// Call-ID-only lookup could reject a correctly tagged request. Caller MUST hold
// u.calls.mu. findByCallIDLocked stays the Call-ID-only lookup.
func (u *UA) findDialogForRequestLocked(req *sip.Request) *dialog {
	cid := callIDOf(req)
	for _, d := range u.calls.byID {
		if d.callID == cid && dialogMatchesLocked(d, req) {
			return d
		}
	}
	return nil
}

// remoteCSeqBelowLocked reports whether an in-dialog request (not ACK or CANCEL)
// is out of order under RFC 3261 12.2.2: its CSeq is lower than the remote
// sequence number. It seeds an inbound dialog's remote number from the peer's
// INVITE but never raises it: onBye calls it alone, because a BYE ends the
// dialog and must not make an earlier NOTIFY that the arrival gate (D18) applies
// after it look out of order. Caller MUST hold u.calls.mu.
func remoteCSeqBelowLocked(d *dialog, req *sip.Request) bool {
	cs := req.CSeq()
	if cs == nil {
		return false // nothing to compare; not this check's concern
	}
	if !d.remoteCSeqSet && d.direction == session.Inbound && d.invite != nil {
		if ic := d.invite.CSeq(); ic != nil { // UAS: seeded from the peer's INVITE
			d.remoteCSeq, d.remoteCSeqSet = ic.SeqNo, true
		}
	}
	return d.remoteCSeqSet && cs.SeqNo < d.remoteCSeq
}

// remoteCSeqInOrderLocked is the check for every in-dialog request that keeps
// the dialog (INFO, UPDATE, re-INVITE, NOTIFY): false means out of order (answer
// 500, apply nothing); true raises the remote number. An equal CSeq passes, so a
// retransmission that re-runs a handler keeps its answer. Caller MUST hold
// u.calls.mu.
func remoteCSeqInOrderLocked(d *dialog, req *sip.Request) bool {
	if remoteCSeqBelowLocked(d, req) {
		return false
	}
	if cs := req.CSeq(); cs != nil && (!d.remoteCSeqSet || cs.SeqNo > d.remoteCSeq) {
		d.remoteCSeq, d.remoteCSeqSet = cs.SeqNo, true
	}
	return true
}

// respondOutOfOrder answers an in-dialog request whose CSeq is below the
// dialog's remote number (RFC 3261 12.2.2).
func respondOutOfOrder(req *sip.Request, tx sip.ServerTransaction) {
	_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil))
}

// findByCallID is the locking wrapper — for callers that do NOT hold u.calls.mu
// (onCancel/D3, onInvite's re-INVITE guard/D2).
func (u *UA) findByCallID(cid string) *dialog {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return u.findByCallIDLocked(cid)
}

// ourReInviteTagLocked returns OUR OWN local dialog tag — the identity an
// in-dialog re-INVITE must carry (in its To header) to match this dialog
// (D2) — direction-aware (Task 11). For an INBOUND dialog this UA is the
// UAS: d.ok is the 200 OK THIS UA SENT, and its To-tag IS our local tag. For
// an OUTBOUND dialog this UA is the UAC: d.ok is the 200 OK THIS UA
// RECEIVED, whose To-tag is the REMOTE (peer) tag, not ours — our local tag
// is instead the one WE generated on d.invite's From header. Without this
// split, a real PBX's direct_media=yes re-INVITE to the CALLER leg (carrying
// our UAC From-tag) was misread against the callee-only d.ok.To() tag and
// fell through to 481, killing every answered outbound call (§14.5 loop gate
// find). Caller MUST hold u.calls.mu; d.ok/d.invite are only safe to read at
// all under the lock (D147/F1's phase/ok invariant, call.go ~659-688).
func ourReInviteTagLocked(d *dialog) string {
	switch d.direction {
	case session.Inbound:
		if d.ok == nil {
			return ""
		}
		to := d.ok.To()
		if to == nil {
			return ""
		}
		tag, _ := to.Params.Get("tag")
		return tag
	default: // session.Outbound
		if d.invite == nil {
			return ""
		}
		from := d.invite.From()
		if from == nil {
			return ""
		}
		tag, _ := from.Params.Get("tag")
		return tag
	}
}

// ourReInviteSDPLocked returns (SDP body, Content-Type) for the 200 OK an
// in-dialog re-INVITE guard (D2) echoes back — direction-aware (Task 11),
// mirroring ourReInviteTagLocked's split. It is our last SDP to the peer, an offer
// or an answer: after an applied peer re-offer d.localSDP (see answerInDialogOffer),
// else the one the dialog was set up with. Inbound (UAS) uses d.ok — our answer
// (or our offer, on an offerless INVITE). Outbound (UAC) uses d.invite — our
// offer. Answering an unchanged re-offer with it is done only when it was an
// answer (ourLastSDPIsAnswerLocked, CF-186). Caller MUST hold u.calls.mu.
func ourReInviteSDPLocked(d *dialog) ([]byte, sip.Header) {
	var body []byte
	var ct sip.Header
	if d.localSDP != nil {
		return d.localSDP, sip.NewHeader("Content-Type", "application/sdp")
	}
	if d.direction == session.Inbound {
		if d.ok == nil {
			return nil, nil
		}
		body = d.ok.Body()
		if c := d.ok.ContentType(); c != nil {
			ct = c
		}
		return body, ct
	}
	if d.invite == nil {
		return nil, nil
	}
	body = d.invite.Body()
	if c := d.invite.ContentType(); c != nil {
		ct = c
	}
	return body, ct
}

// forgetLocked deletes a terminated dialog from the registry (fixes I3: byID
// grew unbounded — no delete existed anywhere). Caller MUST hold u.calls.mu.
// Idempotent.
func (u *UA) forgetLocked(id string) { delete(u.calls.byID, id) }

// forget is the locking wrapper — for callers that do NOT hold u.calls.mu.
func (u *UA) forget(id string) {
	u.calls.mu.Lock()
	u.forgetLocked(id)
	u.calls.mu.Unlock()
}

// dialProvisional is the provisional-response callback of EVERY INVITE leg of
// an outbound dial: runDial's first and digest-retry legs and retry422's leg.
// On a 180/183 it moves the dialog to phaseRinging and emits the provisional,
// exactly as each leg's own copy of this code used to.
//
// On the leg's FIRST 1xx of any code it also builds that leg's CANCEL — RFC
// 3261 §9.1 allows one from the first provisional on — and, if a Hangup came
// in before any provisional (cancelRequested with no cancelReq yet), sends it
// now. It runs on runDial's goroutine, which is the only one that mutates
// d.invite, so reading d.invite here is race-free.
func (u *UA) dialProvisional(d *dialog, now func() time.Time) func(*sip.Response) {
	return func(prov *sip.Response) {
		ringing := prov.StatusCode == 180 || prov.StatusCode == 183
		var deferred *sip.Request
		u.calls.mu.Lock()
		if d.cancelReq == nil {
			d.cancelReq = newCancelRequest(d.invite)
			if d.cancelRequested {
				deferred = d.cancelReq
			}
		}
		// Claimed here (not closed): the waiting Hangup is woken only once the
		// CANCEL below is on the wire.
		wake := d.cancelWait
		if deferred != nil {
			d.cancelWait = nil
		} else {
			wake = nil
		}
		if ringing {
			d.phase = phaseRinging
		}
		// RFC 3261 13.2.1: the first session description received is the
		// answer, kept per early dialog (To tag) until the 2xx (CF-161).
		if tag := toTagOf(prov); tag != "" && isSDPBody(prov) {
			if _, seen := d.earlyAnswers[tag]; !seen && len(d.earlyAnswers) < maxForkTags {
				if d.earlyAnswers == nil {
					d.earlyAnswers = map[string][]byte{}
				}
				if len(prov.Body()) > maxEarlySDPLen {
					d.earlyAnswers[tag] = []byte{}
					u.log().Info("early SDP over the cap is not kept; the call fails at the 2xx",
						"dialog", d.id, "to_tag", tag, "size", len(prov.Body()), "cap", maxEarlySDPLen)
				} else {
					d.earlyAnswers[tag] = append([]byte(nil), prov.Body()...)
				}
			}
		}
		u.calls.mu.Unlock()
		var sendErr error
		if deferred != nil {
			if sendErr = u.sendCancel(u.uaCtx, deferred); sendErr != nil {
				u.log().Warn("deferred CANCEL could not be sent", "dialog", d.id, "err", sendErr)
			}
			markCancelSent(d)
		}
		if wake != nil {
			if sendErr != nil {
				sendErr = fmt.Errorf("send CANCEL: %w", sendErr)
			}
			wake <- sendErr // the waiting Hangup reports a failed write, never a false nil
		}
		if !ringing {
			return
		}
		// A PROTOCOL FACT, not a call state. session.Call maps 180/183 onto
		// §10.3's "ringing".
		u.emit(session.UAEvent{Kind: session.UAEventProvisional, DialogID: d.id, CallID: d.callID,
			Direction: session.Outbound, Code: int(prov.StatusCode), Reason: prov.Reason, At: now()})
	}
}

// isSDPBody reports whether res carries a non-empty application/sdp body.
func isSDPBody(res *sip.Response) bool {
	if len(res.Body()) == 0 {
		return false
	}
	ct := res.ContentType()
	if ct == nil {
		return false
	}
	mt, _, _ := strings.Cut(ct.Value(), ";")
	return strings.EqualFold(strings.TrimSpace(mt), "application/sdp")
}

// nextDialLeg is called between two INVITE legs of one dial (the digest and
// 422 retries, and a followed redirect or failover to the next target). It returns false when a Hangup has been requested — the caller
// must then NOT send another INVITE, and the final response in hand ends the
// dial as usual — and otherwise disarms the finished leg's CANCEL, so the next
// leg's first provisional arms its own.
func (u *UA) nextDialLeg(d *dialog) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.cancelRequested {
		return false
	}
	d.cancelReq = nil
	d.earlyAnswers = nil // a new INVITE is a new offer/answer exchange
	return true
}

// markCancelSent records that a CANCEL for d has been ATTEMPTED (written or
// not: the RFC 3261 §9.1 wait starts at the attempt, and a failed write is
// still followed by nothing that would end the dial earlier). A bare close is
// safe because a dialog has exactly ONE CANCEL sender: hangupWithReason's
// direct path runs only when !repeat with a CANCEL armed, dialProvisional's
// deferred path only when hangup found none armed (cancelReq nil) and set
// cancelRequested — mutually exclusive, and nextDialLeg refuses every later
// leg once cancelRequested, so no second CANCEL can follow.
func markCancelSent(d *dialog) {
	close(d.cancelSent)
}

// resolveCancelWait hands result to the Hangup waiting on d (if any) and clears
// the wait, under u.calls.mu, so it is resolved exactly once — the same
// single-resolution rule dialProvisional, teardownDialog and onBye follow. The
// channel is 1-buffered and only the one resolver that cleared it ever sends
// on it (here, or dialProvisional for its deferred CANCEL), so the send never
// blocks.
func (u *UA) resolveCancelWait(d *dialog, result error) {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.cancelWait != nil {
		d.cancelWait <- result
		d.cancelWait = nil
	}
}

// newCancelRequest builds RFC 3261 §9.1's CANCEL for inv, the INVITE leg
// outstanding: the same Request-URI, Call-ID, From, To and CSeq number (method
// CANCEL), ONLY the INVITE's top Via — branch included, which is how the UAS
// matches the CANCEL to the INVITE transaction — the same Route set, and no
// body. Modelled on the vendored sipgo builder
// (third_party/sipgo/sip/request.go's newCancelRequest), which is unexported.
func newCancelRequest(inv *sip.Request) *sip.Request {
	c := sip.NewRequest(sip.CANCEL, *inv.Recipient.Clone())
	c.SipVersion = inv.SipVersion
	if h := inv.Via(); h != nil {
		c.AppendHeader(h.Clone())
	}
	sip.CopyHeaders("Route", inv, c)
	maxFwd := sip.MaxForwardsHeader(70)
	c.AppendHeader(&maxFwd)
	if h := inv.From(); h != nil {
		c.AppendHeader(sip.HeaderClone(h))
	}
	if h := inv.To(); h != nil {
		c.AppendHeader(sip.HeaderClone(h))
	}
	if h := inv.CallID(); h != nil {
		c.AppendHeader(sip.HeaderClone(h))
	}
	if h := inv.CSeq(); h != nil {
		c.AppendHeader(&sip.CSeqHeader{SeqNo: h.SeqNo, MethodName: sip.CANCEL})
	}
	c.SetTransport(inv.Transport())
	c.SetSource(inv.Source())
	c.SetDestination(inv.Destination())
	ensureSupportedTimer(c) // RFC 4028 7.1: every request except ACK (CF-113)
	return c
}

// sendCancel puts cancel on the wire as its own non-INVITE client transaction
// and returns once it is WRITTEN (sipgo's ClientTx.Init writes synchronously
// before TransactionRequest returns), not once it is answered: the INVITE's
// 487 — or a crossing 200 — is runDial's to handle. The transaction's own 200
// is drained in the background, bounded by the UA's lifetime. ClientRequestBuild
// is passed for two reasons: a NON-EMPTY options list stops sipgo bumping the
// CSeq, which must stay the INVITE's (absorbInvite2xx sends a fork's BYE through
// here for the same reason: its CSeq is set by hand); and it adds the CANCEL's only
// Content-Length (0), which newCancelRequest does not set and which is
// mandatory over TCP/TLS (RFC 3261 §20.14).
func (u *UA) sendCancel(ctx context.Context, cancel *sip.Request) error {
	tx, err := u.Client().Raw().TransactionRequest(ctx, cancel, sipgo.ClientRequestBuild)
	if err != nil {
		return err
	}
	go func() { _, _ = u.pumpFinal(u.uaCtx, tx) }()
	return nil
}

// Dial sends an INVITE and RETURNS IMMEDIATELY (D2, N2's 50 ms budget).
// Dialling is asynchronous and the agent gates on call_wait.
//
// It returns session.DialResult, which carries ONLY a DialogID: asserting a
// call state here would be sipua naming a CallState it does not own (Rule 18).
//
// The transaction runs on the DAEMON context, never on the caller's request
// context (locked decision 17): a client disconnect must never cancel a live
// call, or D11 point 5 and R8 both break. The ctx parameter is therefore
// DELIBERATELY IGNORED for the transaction's lifetime — it is present because
// every session and sipua method is ctx-first, and ignoring it here is the
// whole point.
func (u *UA) Dial(_ context.Context, req session.DialRequest) (session.DialResult, error) {
	if strings.TrimSpace(req.ToURI) == "" {
		return session.DialResult{}, apierr.InvalidArgument("to_uri is required")
	}
	// D134/C7: reject a malformed to_uri (e.g. an IPv6 literal sip.ParseUri
	// cannot parse) BEFORE BuildInvite, so this fails fast as
	// invalid_argument instead of a slow transport_fault after the full
	// Timeout once BuildInvite's non-panicking parse silently falls through.
	if !validSIPURI(req.ToURI) {
		return session.DialResult{}, apierr.InvalidArgument(
			fmt.Sprintf("to_uri %q is not a valid SIP URI", req.ToURI))
	}

	// CF-172: derive the Request-URI before any resource is allocated, so a
	// sips: target on a UA that cannot honour it is refused up front.
	reqURI, err := u.dialRequestURI(req.ToURI)
	if err != nil {
		return session.DialResult{}, err
	}

	ecfg := u.engineConfig()
	// D127/C1: splitSIPURI's second return is host WITH THE PORT when one is
	// present. Setting ecfg.ToDomain to that directly (the naive reading)
	// makes builders.go:49 build sip.Uri{Host: ToDomain, Port: 0} — the start
	// line looks correct but HostPort() renders "host:port:0" and the
	// transaction dies with "too many colons in address". A userless
	// TargetURI drives builders.go:52's IP-to-IP branch instead, the only
	// path that carries a port into the Request-URI; the user travels via
	// ToUser. Probe-verified: FIX recipient.HostPort="127.0.0.1:56035" -> far
	// end RECEIVED the INVITE.
	user, hostport, _ := splitSIPURI(req.ToURI)
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport // no port supplied; sipgo defaults to 5060
	}
	ecfg.TargetURI = "sip:" + hostport
	ecfg.ToUser, ecfg.ToDomain = user, host
	if req.FromUser != "" {
		ecfg.FromUser = req.FromUser
	}
	// §14.5: a direct-mode UA has NO AOR (session/toolservice.go's "direct"
	// case never sets one), so engineConfig's aorParts("") leaves FromDomain
	// empty and BuildInvite renders `From: <sip:>`. A loopback peer accepts
	// that; Asterisk (RFC 3261) silently drops it and the call sticks in
	// dialing. Fall back to the UA's BOUND LOCAL IP — the same concrete
	// address LocalAddr, Via and Contact already carry (it is never wildcard
	// by the time Dial runs; §6.5.3 rules 3/4 resolve it at ua_create) — so
	// the From is a routable sip:[from_user@]<bound-ip>. Scoped to the empty
	// case only, so a register-mode UA dialling out keeps its real AOR domain.
	if ecfg.FromDomain == "" {
		ecfg.FromDomain = u.BoundAddr().IP.String()
	}

	// Resolve the local media address (§6.5.3 r1/2, r3/4 via the injected
	// resolver) and bind an even media port BEFORE the offer is built, so the
	// SDP never advertises a port we do not yet own (M3: no RTP is sent here).
	_, hp, _ := splitSIPURI(req.ToURI)
	remoteHost := hp
	if h, _, err := net.SplitHostPort(hp); err == nil {
		remoteHost = h
	}
	mip, err := media.ResolveMediaAddr(u.cfg.LocalAddr, u.cfg.MediaLocalIP, remoteHost, u.cfg.Logger)
	if err != nil {
		return session.DialResult{}, apierr.Internal("", fmt.Sprintf("resolve media addr: %v", err))
	}
	mconn, mport, err := u.bindMediaPort(mip)
	if err != nil {
		return session.DialResult{}, apierr.Internal("", err.Error())
	}
	offer, offerSess, err := media.BuildOffer(u.codecPrefs(),
		net.JoinHostPort(mip.String(), strconv.Itoa(mport)), u.srtpPolicy(req.SRTP))
	if err != nil {
		_ = mconn.Close()
		return session.DialResult{}, apierr.Internal("", fmt.Sprintf("build offer: %v", err))
	}
	inv := siptest.BuildInvite(ecfg, u.Transport(), offer)
	// The Request-URI (scheme, user, host, port and, for a sip: target on a
	// non-UDP UA, the transport parameter) comes from dialRequestURI. A sips:
	// target carries no transport parameter: the fork derives TLS from the
	// scheme for every request of the dialog that is rebuilt without a Via.
	inv.Recipient = reqURI
	// CF-117: a TLS UA's INVITE Contact is a sips: URI with no transport
	// parameter. Copy-and-edit BuildInvite's Contact (user FromUser, bound IP),
	// as REGISTER's override does; localContact's user and host can differ.
	if orig := inv.Contact(); orig != nil && strings.EqualFold(u.Transport(), "tls") {
		inv.RemoveHeader("Contact")
		inv.AppendHeader(&sip.ContactHeader{
			DisplayName: orig.DisplayName,
			Address:     contactAddr(orig.Address, "tls"),
			Params:      orig.Params,
		})
	}
	for k, v := range req.Headers {
		inv.AppendHeader(sip.NewHeader(k, v))
	}
	// RFC 4028 (decision 12): we PROPOSE ourselves as refresher when we dial.
	u.addSessionTimerHeaders(inv, sessionExpires{IntervalS: u.sessionExpiresS(), Refresher: "uac"}, u.minSES())

	d := &dialog{
		id: newDialogID(), direction: session.Outbound, phase: phaseDialing,
		callID: callIDOf(inv), invite: inv,
		mediaConn: mconn, mediaSession: offerSess,
		callHandle: req.CallHandle, mediaPlanSteps: req.MediaPlan,
		localCSeq: 0, cancelSent: make(chan struct{}),
		maxRedirects: req.MaxRedirects, checkRedirect: req.CheckRedirect,
		everSips: reqURI.Scheme == "sips",
	}
	if err := u.registerBounded(d, req.CallLimit); err != nil {
		_ = mconn.Close()
		return session.DialResult{}, err
	}

	// THE SYNCHRONOUS BIND, AND ITS POSITION IS THE WHOLE POINT (see
	// session.DialRequest.OnDialogBound). The dialog id and the Call-ID are
	// already computed above, and `go u.runDial(d)` below can complete
	// INVITE/200/ACK in ~1 ms on loopback — before this function returns. A
	// caller that binds on Dial's RETURN therefore loses every event runDial
	// emits in that window, and session.handleResponse drops them silently.
	//
	// NOTHING MAY BE INSERTED BETWEEN THIS CALL AND THE GO STATEMENT that
	// could emit an event, or the window reopens. The hook is optional: a nil
	// OnDialogBound is the documented "do not call me".
	if req.OnDialogBound != nil {
		req.OnDialogBound(d.id, d.callID)
	}

	go u.runDial(d)

	// CallID is the Tap's ladder key. session.Call stores it and passes it to
	// Tap.Ladder and Tap.Evict; without it call_ladder cannot find the ladder
	// and the janitor cannot evict it promptly (§N3's bound is the Sink's
	// LRU — U15).
	return session.DialResult{DialogID: d.id, CallID: d.callID}, nil
}

// dialRequestURI derives the INVITE's Request-URI from a dial target (CF-172,
// RFC 3261 19.1 / 26.4.2): a sips: target means TLS all the way, so it is
// dialled over a TLS UA or refused, never downgraded to sip:. The result has the
// scheme lower-cased and carries only user, host and port; URI parameters,
// headers and any password in target are dropped. A sip: target on a non-UDP UA
// gets transport=<tcp|tls>; a sips: target gets no transport parameter.
func (u *UA) dialRequestURI(target string) (sip.Uri, error) {
	parsed, ok := parseValidSIPURI(target)
	if !ok {
		return sip.Uri{}, apierr.InvalidArgument(
			fmt.Sprintf("to_uri %q is not a valid SIP URI", target))
	}
	uri := sip.Uri{Scheme: strings.ToLower(parsed.Scheme), User: parsed.User, Host: parsed.Host, Port: parsed.Port}
	if uri.Scheme == "" {
		uri.Scheme = "sip"
	}
	t := strings.ToLower(u.Transport())
	if uri.Scheme == "sips" {
		if t != "tls" {
			return sip.Uri{}, apierr.InvalidArgument(fmt.Sprintf(
				"to_uri %q is a sips: URI, which must be dialled over TLS; this UA's transport is %q (create a ua with transport \"tls\")",
				target, t))
		}
		return uri, nil
	}
	if t != "udp" {
		uri.UriParams = sip.NewParams()
		uri.UriParams.Add("transport", t)
	}
	return uri, nil
}

// lingeringDialHeadroom is the number of registered dialogs Dial admits beyond
// DialRequest.CallLimit, for hung-up dials still waiting for their final
// response (CF-038, D-B2). It is a fixed internal constant, not configuration.
//
// What the bound does and does not promise:
//   - A hung-up dial holds a slot up to postCancelWait (32 s) after a direct
//     CANCEL, or up to Timeout + 32 s when the CANCEL was deferred. A sustained
//     hang-up rate above headroom/lifetime against a far end that never
//     finalises fills the headroom, and later dials on that UA are refused until
//     slots drain. That refusal is bounded and intended, not a defect.
//   - The limit is captured per dial request: a concurrent config_set of
//     max_concurrent_calls_* affects only dials issued after it.
//   - The count includes lingering and inbound dialogs, so inbound calls consume
//     the same headroom outbound dials use. Inbound is never refused by this
//     check, but can cause an outbound refusal.
//   - It is a per-UA bound. The daemon-wide total still scales with the
//     configured UA and session ceilings.
//   - A refused dial still binds and closes one media socket: the SDP needs a
//     port the UA owns before the offer is built, and the atomic check can only
//     sit at the registry insert.
const lingeringDialHeadroom = 32

// outboundRingBudget is B1's finite, Timer-C-style bound on how long an
// outbound INVITE may sit ringing after its first provisional. sipgo v0.24.1
// stops Timer B on the first provisional and implements NO Timer C, and the
// outbound path has no ring reaper, so without this a ring-then-silent peer
// would park runDial's goroutine and pin the Call in ringing until UA
// teardown. 180s survives any realistic human answer time while still reaping
// a vanished peer.
const outboundRingBudget = 180 * time.Second

// cancelWaitCap bounds how long a Hangup of a not-yet-established outbound
// dial waits: for its deferred CANCEL when no provisional has arrived yet, or
// for runDial's BYE when the hangup landed in the answering window (200 in,
// not yet established), or for Answer's BYE or 603 when it landed while an
// inbound call_answer was writing its 200 (CF-041; at the cap the hangup stays
// recorded and is still enacted when the answer settles). Long enough for a far end about to ring, or for the
// BYE's transaction, so ua_destroy's CANCEL/BYE precedes the transport close;
// short enough that call_hangup/ua_destroy never stall on a silent peer.
const cancelWaitCap = 2 * time.Second

// postCancelWait is what driveTx RE-ARMS its wait to once a CANCEL for the
// INVITE has been attempted: 64*T1, the transaction timeout RFC 3261 §9.1
// gives a UAC for the 487 (or a crossing 200). It is a re-arm, not a ceiling on
// the whole dial: a hangup late in the ring can extend what was left of the
// ring budget (worst case pre-ring + ring budget + 32s). Without it the dial
// would wait out the whole outboundRingBudget after the hangup, holding the
// dialog, its bound RTP socket and runDial's goroutine.
const postCancelWait = 64 * 500 * time.Millisecond // 64*T1 (= sipgo sip.Timer_B at default T1)

// C-M5 (D20, W2): THESE FIVE, PLUS medialoop.go's seq0, digestauth.go's anchorLookup, caplistener.go's evictIdleOverride AND ua.go's dnsResolverOverride, ARE TEST-ONLY SEAMS ON
// PRODUCTION SURFACE. All are nil/zero in production and individually
// documented; the Cycle 3 review flagged the growing TREND and proposed no fix,
// and W2's bounded action is to make their load-bearing invariant EXPLICIT rather
// than to remove them.
//
// THE INVARIANT: no test under internal/sipua calls t.Parallel(). These globals
// are unsynchronised, so two tests mutating them concurrently would interleave.
// It currently holds (zero t.Parallel() calls in the package) and is now ENFORCED
// by parallel_invariant_test.go rather than merely observed — which is the whole
// difference between a documented assumption and a checked one.

// ringBudgetOverride is a TEST-ONLY seam (set via export_test.go's
// SetOutboundRingBudget): 0 in production, so ringBudget returns the const.
var ringBudgetOverride time.Duration

// mediaTeardownHook is a TEST-ONLY seam (set via export_test.go's
// SetMediaTeardownHook): nil in production. It is invoked once, on runDial's
// goroutine, while the dialog is held in phaseMediaTeardown and BEFORE the
// internal BYE, so a test can prove a racing call_hangup is refused in that
// window.
var mediaTeardownHook func()

// dialAnsweringHook is a TEST-ONLY seam (set via export_test.go's
// SetDialAnsweringHook): nil in production. It is invoked once, on runDial's
// goroutine, AFTER the ACK is on the wire and BEFORE setPhase(phaseAnswered)
// — i.e. while the outbound dialog holds the phaseAnswering claim — so a test
// can land an in-dialog re-INVITE or UPDATE inside exactly the window a real
// PBX's direct-media re-INVITE arrives in and prove it draws 200, not 481.
var dialAnsweringHook func()

// hangupByeHook is a TEST-ONLY seam (set via export_test.go's
// SetHangupByeHook): nil in production. It is invoked once, on the goroutine
// ending a recorded answering-window hangup (runDial's, or Answer's for an
// inbound call), after it has claimed the dialog (phaseMediaTeardown) and BEFORE
// its BYE, so a test can land a peer BYE there.
var hangupByeHook func()

// answerRespondedHook is a TEST-ONLY seam (set via export_test.go's
// SetAnswerRespondedHook): nil in production. It is invoked once, on Answer's
// goroutine, holding no lock, AFTER its 200 is on the wire and BEFORE the
// final claim, so a test can land the caller's ACK while the dialog is still
// phaseAnswering.
var answerRespondedHook func()

// ackAnswerAppliedHook is a TEST-ONLY seam (set via export_test.go's
// SetAckAnswerAppliedHook): nil in production. applyAckAnswer invokes it,
// holding no lock, AFTER installing a valid ACK answer and BEFORE
// startMediaLoop, so a test can land a control operation in that window. An
// atomic.Pointer (the referOutcomeArmHook precedent, transfer.go): it is read
// on sipgo's ACK handler goroutine, not the test's.
var ackAnswerAppliedHook atomic.Pointer[func()]

// failedDialHook is a TEST-ONLY seam (set via export_test.go's
// SetFailedDialHook): nil in production. endFailedDial invokes it on runDial's
// goroutine immediately BEFORE teardownDialog, so a test can land a Hangup at
// exactly the timeout/hangup linearization point. A synchronous Hangup from it
// is valid only in the no-final-response branch after a provisional has armed
// cancelReq; in the ACK-failure branch (phaseAnswering) it would wait on
// cancelWait until teardown.
var failedDialHook func()

// postCancelWaitOverride is a TEST-ONLY seam (set via export_test.go's
// SetPostCancelWait): 0 in production, so postCancel returns the const.
var postCancelWaitOverride time.Duration

// ringBudget is the post-ring bound to re-arm to, honouring the test override.
func (u *UA) ringBudget() time.Duration {
	if ringBudgetOverride > 0 {
		return ringBudgetOverride
	}
	return outboundRingBudget
}

// postCancel is the post-CANCEL bound to re-arm to, honouring the test override.
func postCancel() time.Duration {
	if postCancelWaitOverride > 0 {
		return postCancelWaitOverride
	}
	return postCancelWait
}

// driveTx drives a client transaction to its final response, invoking
// onProvisional for every 1xx. It applies preRing until the FIRST provisional,
// then RE-ARMS its timer to postRing (B1's finite post-ring bound) rather than
// dropping it — so a ringing call survives past the short pre-ring budget but a
// peer that rings and then goes silent is still reaped. It mirrors
// siptest.(*Client).doTx's shape (built directly over the vendored *sipgo.Client
// via u.Client().Raw() rather than duplicating doTx in the unpinned,
// byte-diffed siptest/client.go — D138), but doTx swallows every 1xx and caps
// at a single upfront timeout; driveTx surfaces provisionals (R14 needs the 180
// observable) and extends the deadline once ringing.
//
// cancelSent (the dialog's, closed once a CANCEL for it is attempted) re-arms
// the timer once more, to postCancel() (RFC 3261 §9.1's 64*T1; a re-arm, so it
// can extend the remaining ring budget, not only shorten it): the far end owes a
// 487 (or a crossing 200, which still returns through the response arm and is
// ACKed and BYE'd by runDial), and a silent one must not hold the dialog for
// the rest of postRing. Expiry is the ordinary timeout below.
//
// Both the first (unchallenged) leg and the digest-retry leg drive their
// transaction through here, so a challenged INVITE surfaces 180 exactly as an
// unchallenged one does (D5).
//
// THE TRANSACTION OUTLIVES A 2xx (CF-107/CF-088, RFC 3261 13.2.2.4). On every
// exit but a 2xx final driveTx terminates tx and returns it nil. On a 2xx it
// returns tx LIVE, in sipgo's Accepted state, where every further 2xx (a
// retransmission, or another fork's) is passed up on tx.Responses() until
// Timer M deletes it; the caller then owns it: runDial hands it to
// absorbInvite2xx once the ACK is out, and terminates it on every other path.
// Terminating it here, as this function used to, deleted it at the first final
// and sipgo dropped every later 2xx as unhandled, un-ACKed.
func (u *UA) driveTx(ctx context.Context, tx sip.ClientTransaction, preRing, postRing time.Duration, cancelSent <-chan struct{}, onProvisional func(*sip.Response)) (*sip.Response, sip.ClientTransaction, error) {
	accepted := false
	defer func() {
		if !accepted {
			tx.Terminate()
		}
	}()
	timer := time.NewTimer(preRing)
	defer timer.Stop()
	// Read once, up front, like ringBudget's callers: the override is an
	// unsynchronised test seam a finished test restores while its dial's
	// goroutine may still be running.
	afterCancel := postCancel()
	gotProvisional, cancelled := false, false
	for {
		select {
		case res := <-tx.Responses():
			if res == nil {
				continue
			}
			if res.StatusCode < 200 {
				if !gotProvisional {
					gotProvisional = true
					// B1: re-arm to the finite post-ring budget (do NOT drop the
					// timer). This module is go 1.25.0 with no GODEBUG override,
					// so Go 1.23+ synchronous-timer semantics are active: after
					// Stop no stale value is ever delivered, which makes the
					// pre-1.23 drain `if !timer.Stop() { <-timer.C }` both
					// unnecessary AND unsafe here — the bare receive would block
					// forever when nothing is buffered. Stop then Reset is the
					// version-correct re-arm (validated by the reap test passing
					// without hanging).
					timer.Stop()
					timer.Reset(postRing)
				}
				if onProvisional != nil {
					onProvisional(res)
				}
				continue
			}
			if !res.IsSuccess() {
				return res, nil, nil
			}
			accepted = true
			return res, tx, nil
		case <-tx.Done():
			return nil, nil, fmt.Errorf("tx done: %v", tx.Err())
		case <-cancelSent:
			cancelSent = nil // a nil channel never fires again
			cancelled = true
			timer.Stop()
			timer.Reset(afterCancel)
		// C1: THE COINCIDENT-DEADLINE TWIN of the Task 33 race, benign today and
		// documented so it stays benign. When the ring deadline and a final
		// response (or tx.Done) become ready in the same instant, Go's select
		// picks at random, so a call that WAS answered can still leave here as a
		// timeout error. Harmless right now only because runDial routes BOTH
		// error branches to the identical endFailedDial path (a dialog-scoped
		// UAEventDialogEnded) — no code discriminates them. A future change that starts discriminating (a
		// distinct "ring timeout" reason, a retry, a metric) MUST re-check the
		// transaction's own final-response state before trusting this arm, or it
		// reintroduces exactly the bug Task 33 fixed for its sibling.
		case <-timer.C:
			if cancelled {
				return nil, nil, fmt.Errorf("no final response after %s following CANCEL", afterCancel)
			}
			if gotProvisional {
				return nil, nil, fmt.Errorf("invite ring timeout after %s (no final response)", postRing)
			}
			return nil, nil, fmt.Errorf("invite timeout after %s with no provisional", preRing)
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

// transactionWithProvisional dispatches req and drives it through driveTx,
// applying preRing until the first provisional and the finite outbound ring
// budget thereafter (B1). It is the thin wrapper the first, unchallenged INVITE
// leg uses; the digest-retry leg calls driveTx directly over the tx
// digestAuthTransaction returns (P4-D06; digestauth.go). Like driveTx it
// returns the transaction, live, only with a 2xx.
func (u *UA) transactionWithProvisional(ctx context.Context, req *sip.Request, preRing time.Duration, cancelSent <-chan struct{}, onProvisional func(*sip.Response)) (*sip.Response, sip.ClientTransaction, error) {
	tx, err := u.Client().Raw().TransactionRequest(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	return u.driveTx(ctx, tx, preRing, u.ringBudget(), cancelSent, onProvisional)
}

// maxForkTags bounds the extra To tags absorbInvite2xx ACKs and BYEs per
// INVITE, so a flood of forged 2xx cannot make us send unbounded BYEs (D-107).
const maxForkTags = 16

// maxEarlySDPLen is the largest early SDP kept per To tag: the largest UDP
// payload, 65535 - 20 (IP) - 8 (UDP), which is the sipgo fork's unexported
// udpMaxDatagramPayload (third_party/sipgo/sip/transport_udp.go, CF-168).
// Every early SDP UDP can carry is kept; TCP and TLS get the same bound (CF-205).
const maxEarlySDPLen = 65535 - 20 - 8

// absorbInvite2xx owns our answered INVITE's client transaction from runDial's
// ACK until sipgo's Timer M (64*T1) deletes it, or the UA closes. RFC 3261
// 13.2.2.4: every 2xx is ACKed (rfc3261.txt:4571-4572 and 4587-4590), and a
// dialog we do not want is ended with a BYE (4605-4607). A 2xx with the first
// 2xx's To tag is a retransmission and gets the same ack again (CF-088). A 2xx
// with a new To tag is another fork's (CF-107): it gets its own ACK, re-sent
// for its retransmissions, and one BYE; that dialog is never registered and
// raises no event. Past maxForkTags new tags are logged and dropped, and a 2xx
// with no To tag (unless the first 2xx had none either) is ignored.
//
// The fork's ACK and BYE are addressed by the fork's own 2xx: its Contact and
// Record-Route (newAckFor2xx, addressInDialog), as dialog A's ACK is (CF-193).
// The BYE is sent in its own goroutine: a TCP/TLS dial inside TransactionRequest
// can block up to Timer B, and while this loop is blocked sipgo gives up
// passing a retransmitted 2xx up after T1, leaving it un-ACKed.
func (u *UA) absorbInvite2xx(ctx context.Context, tx sip.ClientTransaction, invite *sip.Request, firstOK *sip.Response, ack *sip.Request) {
	defer tx.Terminate()
	firstTag := toTagOf(firstOK)
	forks := map[string]*sip.Request{}
	for {
		select {
		case res := <-tx.Responses():
			tag := toTagOf(res)
			if tag == firstTag {
				u.writeAck(ack)
				continue
			}
			if tag == "" {
				// A 2xx with no To tag names no dialog to ACK or end.
				u.log().Debug("2xx without a To tag ignored", "call_id", invite.CallID().Value())
				continue
			}
			if forkAck, ok := forks[tag]; ok {
				if forkAck != nil {
					u.writeAck(forkAck)
				}
				continue
			}
			if len(forks) >= maxForkTags {
				u.log().Warn("2xx from another fork dropped: fork cap reached",
					"call_id", invite.CallID().Value(), "to_tag", tag, "cap", maxForkTags)
				continue
			}
			target, routes := dialogRoute(session.Outbound, invite, res, nil)
			forkAck, aerr := u.newAckFor2xx(invite, res, target, routes)
			forks[tag] = forkAck // nil when refused: a retransmission is then ignored
			if aerr != nil {
				u.log().Warn("2xx from another fork not acknowledged", "to_tag", tag, "err", aerr)
				continue
			}
			u.writeAck(forkAck)
			bye := forkAck.Clone()
			bye.Method = sip.BYE
			bye.RemoveHeader("Via")
			// A BYE in an established dialog carries no INVITE credentials.
			bye.RemoveHeader("Authorization")
			bye.RemoveHeader("Proxy-Authorization")
			bye.CSeq().SeqNo++
			bye.CSeq().MethodName = sip.BYE
			ensureSupportedTimer(bye) // the ACK it was cloned from carries none (CF-113)
			go func() {
				// sendCancel's idiom: its non-empty option list keeps our CSeq.
				if err := u.sendCancel(ctx, bye); err != nil {
					u.log().Warn("BYE to another fork's 2xx not sent", "to_tag", tag, "err", err)
				}
			}()
		case <-tx.Done():
			return
		case <-ctx.Done():
			// Defensive: UA.Close also ends tx (closeConn's transaction layer
			// terminates every transaction), so this case is not separately
			// testable; it keeps the exit from depending on that.
			return
		}
	}
}

// newAckFor2xx builds the ACK of a 2xx to inv, addressed by the dialog's remote
// target and route set like every other in-dialog request (CF-193, RFC 3261
// 13.2.2.4 and 12.2.1.1, addressInDialog). sip.NewAckRequest builds the header
// set. An error (a sips: target on a non-TLS UA, CF-171) means no ACK is built
// (B-D6). RFC 3261 13.2.2.4: "The ACK MUST contain the same credentials as the
// INVITE" (CF-087); inv holds the credentials of the INVITE that was answered
// (the digest leg and retry422 rewrite it in place). They are copied only when the
// next hop, the remote target and the Request-URI are all hosts digestHostAllowed
// admits (B-D5), else the ACK goes without them and one Warn is logged.
func (u *UA) newAckFor2xx(inv *sip.Request, res *sip.Response, target sip.Uri, routes []sip.Uri) (*sip.Request, error) {
	transport, err := inDialogTransport(u.Transport(), target, routes)
	if err != nil {
		return nil, err
	}
	ack := sip.NewAckRequest(inv, res, nil)
	hop := addressInDialog(ack, target, routes, transport)
	if digestHostAllowed(u.cfg, hop.Host) && digestHostAllowed(u.cfg, target.Host) && digestHostAllowed(u.cfg, ack.Recipient.Host) {
		sip.CopyHeaders("Authorization", inv, ack)
		sip.CopyHeaders("Proxy-Authorization", inv, ack)
	} else if inv.GetHeader("Authorization") != nil || inv.GetHeader("Proxy-Authorization") != nil {
		u.log().Warn("ACK sent without the INVITE's credentials: its next hop or remote target is not the account host",
			"call_id", inv.CallID().Value(), "hop_host", hop.Host, "target_host", target.Host)
	}
	return ack, nil
}

func (u *UA) writeAck(ack *sip.Request) {
	if err := u.Client().Raw().WriteRequest(ack); err != nil {
		u.log().Warn("ACK of a 2xx not sent", "err", err)
	}
}

// dialLegRetries completes one redirect target's INVITE leg: the digest retry
// for a 401/407 and the one 422 retry. refusedReason is non-empty when CF-046 or
// CF-054 withheld credentials from a challenge (the 401/407 in hand is then the
// leg's final response).
func (u *UA) dialLegRetries(ctx context.Context, d *dialog, now func() time.Time,
	res *sip.Response, inviteTx sip.ClientTransaction, err error,
) (*sip.Response, sip.ClientTransaction, string, error) {
	var refusedReason string
	// A leg that ends in a challenge or a 422 is retried with a NEW INVITE, once
	// per redirect target (runDial's leg loop calls this for each) —
	// unless the call was hung up meanwhile (nextDialLeg), in which case the
	// challenge/422 in hand is simply the dial's final response.
	if err == nil && (res.StatusCode == 401 || res.StatusCode == 407) && u.nextDialLeg(d) {
		// A challenging proxy. P4-D06: answered through internal/sipua's OWN
		// digest engine (digestauth.go's digestAuthTransaction), which returns
		// the same client transaction we drive through the SAME
		// provisional-aware loop as the first leg (D5) — unlike the vendored
		// DoRequestWithDigest, whose doTx/doTxWithAddVia swallow every 1xx, so
		// the authed leg never surfaced 180 Ringing. sipgo's DoDigestAuth,
		// which this replaced, could not carry an RFC 7616 §3.4.3 nonce-count:
		// its digest.Options leaves Count at the zero value, so every
		// challenged INVITE sent nc=1 and a nonce-count-tracking proxy could
		// reject the second as a replay.
		//
		// TWO MORE CONSEQUENCES OF LEAVING DoDigestAuth, both deliberate
		// (design §13 Amendment 3). It takes SHA-256/512/512-256 support with
		// it — applyDigest is MD5-only and now REFUSES any other algorithm by
		// name rather than hashing MD5 under the wrong label — and it takes
		// this path off sipgo's digestAuthApply, which dereferences a missing
		// WWW-Authenticate header with no nil check (client.go:438-440) and so
		// PANICS the daemon on a bare 401 from any peer. applyDigest returns
		// an error there instead.
		//
		// driveTx re-arms to the finite ring budget on the first provisional,
		// so the digest leg also survives past the pre-ring cap but is still
		// reaped if the peer rings then goes silent (B1).
		//
		// CF-046 (D-C): the challenge is answered only when the INVITE target
		// host is this account's registrar/AOR host (or AuthAnyHost is set).
		// Otherwise digestAuthTransaction is never called, so no digest is
		// computed, the password is never read and no nonce-count is consumed;
		// the 401/407 in hand is the dial's final response, with a fixed
		// non-secret reason.
		if target := d.invite.Recipient.Host; !digestHostAllowed(u.cfg, target) {
			u.log().Warn("digest challenge not answered: target is not the account's registrar or AOR host",
				"dialog_id", d.id, "target_host", target, "status", int(res.StatusCode))
			refusedReason = fmt.Sprintf("credentials withheld: %s is not this account's registrar or AOR host (ua_create auth_any_host allows it)", target)
		} else if reason := u.challengeSourceRefusal(ctx, d.id, d.invite.Recipient.Host, d.invite.Destination(), res); reason != "" {
			// CF-054: the name matched, but the challenge did not come from an
			// address the anchor resolved to (or it could not be resolved): the
			// same withhold path as above, with its own fixed reason.
			refusedReason = reason
		} else if tx, derr := u.digestAuthTransaction(ctx, d.invite, res); derr != nil {
			res, err = nil, derr
		} else {
			res, inviteTx, err = u.driveTx(ctx, tx, u.cfg.Timeout, u.ringBudget(), d.cancelSent, u.dialProvisional(d, now))
		}
	}

	if err == nil && res != nil && res.StatusCode == 422 && u.nextDialLeg(d) {
		// RFC 4028 §6: ONE retry at the peer's advertised Min-SE, bounded by our
		// own ceiling. A second 422 falls through to the ordinary final-response
		// path and fails the dial — a peer that rejects its own stated minimum is
		// not going to be satisfied by a third guess. Placed ABOVE the err
		// handler below so a retry that draws no response at all (err != nil,
		// res == nil) lands on the transport-fault path instead of dereferencing
		// a nil res (Correction 2).
		res, inviteTx, err = u.retry422(ctx, d, res, now)
	}
	return res, inviteTx, refusedReason, err
}

func (u *UA) runDial(d *dialog) {
	ctx := u.uaCtx
	now := u.cfg.Clock.Now

	res, inviteTx, err := u.transactionWithProvisional(ctx, d.invite, u.cfg.Timeout, d.cancelSent, u.dialProvisional(d, now))
	// inviteTx is non-nil only with a 2xx (driveTx). Once the ACK is on the wire
	// it passes to absorbInvite2xx and is set nil; every other way out of
	// runDial terminates it here, the ACK-write failure included.
	defer func() {
		if inviteTx != nil {
			inviteTx.Terminate()
		}
	}()
	var refusedReason string // set when CF-046 withholds credentials from a challenge
	// CF-090: a 300/301/302 is followed to its Contacts, one new INVITE per
	// target, bounded by maxRedirects; a 4xx/5xx from a redirected target fails
	// over to the next pending one. Each target's leg gets the same digest and
	// 422 retries as the first (dialLegRetries).
	budget := d.maxRedirects
	seen := map[string]bool{redirectKey(d.invite.Recipient): true}
	var pending []redirectTarget
	for {
		res, inviteTx, refusedReason, err = u.dialLegRetries(ctx, d, now, res, inviteTx, err)
		if err != nil || res == nil || res.StatusCode < 300 || budget == 0 || d.checkRedirect == nil {
			break
		}
		if isFollowed3xx(res.StatusCode) {
			pending = append(pending, redirectTargets(res, d.everSips, u.dialRequestURI, seen,
				budget-len(pending), d.checkRedirect, u.cfg.Logger, d.id)...)
		} else if res.StatusCode < 400 || res.StatusCode >= 600 || !d.redirected {
			break // 305, 380, other 3xx; 6xx; a failure of the original target
		}
		if len(pending) == 0 {
			break // nothing left to try: the response in hand is final
		}
		next, rest, ok := u.nextRedirectTarget(d, pending)
		pending = rest
		if !ok || !u.nextDialLeg(d) {
			break // nothing dispatchable, or hung up: the response in hand is final
		}
		budget--
		if u.offersSDES(d) { // CF-198: a fresh SDES key for every new target
			if rerr := u.rekeyOffer(d); rerr != nil {
				refusedReason = "redirect not followed: a fresh SDES key could not be made"
				break
			}
		}
		retarget(d, next)
		res, inviteTx, err = u.transactionWithProvisional(ctx, d.invite, u.cfg.Timeout, d.cancelSent, u.dialProvisional(d, now))
	}

	if err != nil {
		// No response at all ends THIS dialog only: endFailedDial releases it
		// and emits a dialog-scoped end (or nothing, when sipua saw the
		// caller's hangup first). It is NOT the UA-wide UAEventTransportFault, which would
		// terminate every sibling call on the UA (CF-037, D-A). session maps the
		// end onto state `terminated`, termination_reason "transport_failure"
		// and a bare error event (Call.TryTransportFailure).
		//
		// C14/C11: teardownDialog (inside endFailedDial) does the phaseDone flip
		// and the registry removal in ONE u.calls.mu critical section. Its
		// superset elements (d.ringTimer, stopSessionTimer) are confirmed
		// no-ops here: this dialog is outbound and never reaches armRingTimeout
		// (inbound-only), so d.ringTimer is always nil, and d.sessionTimer is
		// not yet built at this point in runDial (buildOutboundSessionTimer runs
		// only after the 2xx/timer branch below), so stopSessionTimer's
		// refresher/watchdog/cancel are all nil too.
		u.endFailedDial(d, "no response", err)
		return
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// §11.1: A SIP FAILURE RESPONSE IS A SUCCESSFUL OPERATION. No error is
		// returned anywhere on this path; the code is a RESULT. sipua does not
		// decide that 486 means "failed" — it reports the final response and
		// session.Call does the mapping. A 3xx in hand here was not followed
		// (budget spent, no acceptable Contact, no CheckRedirect, or a fresh SDES key could not be made).
		//
		// C14/C11: see the no-response branch above — same fix, same
		// confirmed no-ops (d.ringTimer nil, d.sessionTimer not yet built).
		u.teardownDialog(d)
		reason := res.Reason
		if refusedReason != "" {
			reason = refusedReason
		}
		u.emit(session.UAEvent{Kind: session.UAEventFinal, DialogID: d.id, CallID: d.callID,
			Direction: session.Outbound, Code: int(res.StatusCode), Reason: reason, At: now()})
		return
	}

	// RFC 4028: the negotiated session timer is BUILT here and RECORDED in the
	// claim below, in the same critical section — never after it. The claim is
	// what makes the dialog answerable to an in-dialog re-INVITE or UPDATE, and
	// both answer with the dialog's negotiated Session-Expires; recording the
	// timer any later (it used to be recorded past ParseAnswer, ~80 lines below)
	// left d.sessionTimer nil for the whole of that window, so the 200 answering
	// a session refresh that landed in it went out WITHOUT Session-Expires —
	// which per RFC 4028 §7.4/§10 tells the peer the session timer is no longer
	// in use. Where the negotiated role is uas the peer then stops refreshing
	// while our watchdog stays armed, and we tear down a healthy call.
	// buildOutboundSessionTimer reads only res and takes no lock, precisely so it
	// can run here: u.calls.mu is NOT reentrant.
	st := u.buildOutboundSessionTimer(res)

	u.calls.mu.Lock()
	d.ok = res
	d.sessionTimer = st
	// THE ANSWERING CLAIM, IN THE SAME CRITICAL SECTION AS d.ok, AND BEFORE THE
	// ACK BELOW REACHES THE WIRE. The instant the ACK is on the wire the peer is
	// free to send in-dialog requests, and a real PBX does: with
	// direct_media=yes Asterisk re-INVITEs the caller leg a MEASURED median of
	// 0.8 ms (minimum 42 µs) after the ACK. Everything between here and
	// setPhase(phaseAnswered) below — ParseAnswer — used to leave the dialog in
	// phaseDialing/phaseRinging, so onInvite's
	// in-dialog branch and onUpdate answered 481 Call/Transaction Does Not
	// Exist to that re-INVITE. RFC 3261 §12.2.1.2 makes a 481 to an in-dialog
	// request TERMINAL: Asterisk ACKs it and BYEs both legs. Claiming
	// phaseAnswering here — the SAME third phase Answer already uses on the
	// inbound side — makes the dialog answerable to an in-dialog request from
	// the moment the ACK goes out, while still keeping Hangup from firing its
	// own BYE (a racing call_hangup is RECORDED and runDial's final claim BYEs
	// the call, so no BYE races the one ParseAnswer's failure path may send)
	// and refusing Reject/finalRespond (which require phaseRinging).
	//
	// A 200 THAT CROSSED OUR CANCEL (the call was hung up while ringing, and the
	// far end answered before the CANCEL reached it) is claimed
	// phaseMediaTeardown instead, in this SAME critical section — so a Hangup
	// racing in from here on is refused rather than firing a second BYE — and
	// is ACKed and BYE'd below without ever being reported answered.
	//
	// THE ANSWER IS APPLIED IN THIS SAME SECTION, BEFORE THE ACK (CF-161,
	// CF-173): a dialog answerable to an in-dialog request must already hold the
	// negotiated session. The first SDP received is the answer (RFC 3261 13.2.1):
	// the early SDP of the 2xx's To tag if a provisional carried one, else the
	// 2xx's. ParseAnswer runs on a copy and the pointer is swapped, never mutating
	// the published session in place (MediaView reads its fields after unlocking;
	// applyAckAnswer's discipline). ParseAnswer is pure, so holding u.calls.mu
	// across it adds no lock-order edge.
	cancelled := d.cancelRequested
	ackTarget, ackRoutes := dialogRoute(session.Outbound, d.invite, res, d.remoteTarget)
	var nerr error
	var earlyUsed bool
	var answered []byte
	if cancelled {
		d.phase = phaseMediaTeardown
	} else {
		d.phase = phaseAnswering
		answerBody := res.Body()
		early, hasEarly := d.earlyAnswers[toTagOf(res)]
		if hasEarly && len(early) == 0 {
			nerr = media.SDPUnparseable() // the first SDP was over the cap (CF-205)
		} else {
			if hasEarly {
				answerBody, earlyUsed = early, true
			}
			d.answerSDP, answered = answerBody, answerBody
			cp := *d.mediaSession
			var sess *media.Session
			if sess, nerr = media.ParseAnswer(&cp, answerBody); nerr == nil {
				d.mediaSession = sess
			}
		}
	}
	u.calls.mu.Unlock()
	if earlyUsed && len(res.Body()) > 0 && !bytes.Equal(res.Body(), answered) {
		u.log().Info("the 2xx's SDP differs from the early answer and is ignored, RFC 3261 13.2.1",
			"dialog_id", d.id, "call_id", d.callID)
	}

	// ACK is mandatory and comes FIRST (§11.2.1 step 1), whatever the answer says.
	ack, err := u.newAckFor2xx(d.invite, res, ackTarget, ackRoutes)
	if err == nil {
		err = u.Client().Raw().WriteRequest(ack)
	}
	if err != nil {
		// C14/C11: same fix as the two branches above. d.ringTimer is still
		// confirmed nil here (outbound-only dialog). d.sessionTimer is
		// non-nil by this point (set alongside d.phase = phaseAnswering just
		// above), but its refresher/watchdog/cancel fields are still all nil
		// — buildOutboundSessionTimer's literal sets only IntervalS/
		// Refresher/weRefresh/peerAllow, and the actual timer goroutines are
		// armed later, past ParseAnswer, which this branch never reaches —
		// so stopSessionTimer is still a confirmed no-op here too.
		u.endFailedDial(d, "ack send: "+err.Error(), err)
		return
	}
	go u.absorbInvite2xx(ctx, inviteTx, d.invite, res, ack)
	inviteTx = nil // the absorber owns it now

	if cancelled {
		// RFC 3261 §15: the caller hung up, so the session the far end just
		// accepted is ended with a BYE at once — through the same canonical
		// sendInDialog the media-failure ACK-then-BYE below uses (Rule 18). No
		// event: session initiated the hangup and already recorded the call
		// terminated; reporting a 200 now would contradict that.
		_, _, _ = u.sendInDialog(ctx, d, sip.BYE, nil)
		u.teardownDialog(d)
		return
	}

	// TEST SEAM: widen the ACK -> phaseAnswered window so an in-dialog request
	// landing inside it can be proven answered 200 rather than 481. nil in
	// production. Mirrors mediaTeardownHook below.
	if dialAnsweringHook != nil {
		dialAnsweringHook()
	}

	if nerr != nil {
		// §11.2.1: the INVITE genuinely reached 200 OK, so session must see the
		// call as answered (result.sip_code == 200) — delivered by the transient
		// UAEventFinal(200) below. But sipua must NOT leave the dialog in
		// phaseAnswered: a call_hangup racing in during the ACK-then-BYE would pass
		// Hangup's phaseAnswered precondition and put a SECOND BYE on the wire,
		// concurrent with the internal one (duplicate BYE, nondeterministic
		// termination_reason). Claim phaseMediaTeardown in one critical section
		// instead — Hangup refuses it, and only teardownDialog releases it.
		u.calls.mu.Lock()
		d.phase = phaseMediaTeardown
		u.calls.mu.Unlock()

		u.emit(session.UAEvent{Kind: session.UAEventFinal, DialogID: d.id, CallID: d.callID,
			Direction: session.Outbound, Code: int(res.StatusCode), Reason: res.Reason,
			SDP: res.Body(), At: now()})

		// TEST SEAM: widen the phaseMediaTeardown window so a racing call_hangup
		// can be proven refused here. nil in production.
		if mediaTeardownHook != nil {
			mediaTeardownHook()
		}

		u.endNegotiationFailed(ctx, d, nerr)
		return
	}

	// THE FINAL TRANSITION IS A CLAIM, NOT AN ASSIGNMENT. It must be conditional
	// on the phaseAnswering claim made above still being ours, because the window
	// this transition closes is one a TEARDOWN can win: onBye matches purely on
	// Call-ID and is phase-blind, so a peer BYE landing between the ACK and here
	// sets phaseDone and forgetLocked's the dialog out of u.calls.byID. An
	// unconditional setPhase(phaseAnswered) wrote phaseAnswered straight back over
	// that phaseDone — resurrecting a dialog no teardown path can ever reach
	// again, since it is no longer in the registry for Hangup/onBye/
	// stopAllMediaLoops to find. Every guard below is `phase != phaseAnswered`, so
	// all of them then passed on the corpse: startSessionRefresher put refreshes
	// on the wire for a call the peer had ended, and startSessionWatchdog fired at
	// the full interval into expireSessionTimer, whose lookup returns not_found
	// (not precondition_failed) and so emits a SECOND, contradictory dialog_ended
	// — observed as provisional/180, dialog_ended{peer_bye}, final/200,
	// dialog_ended{session_timer_expired} 121 s later.
	//
	// Losing the race means runDial is done: the dialog is already terminated and
	// dialog_ended has already told session the call is over, so the trailing
	// UAEventFinal(200) is deliberately suppressed too — session's handleResponse
	// would find no live call for it anyway.
	//
	// A Hangup that landed in the ACK -> here window recorded cancelRequested
	// (see hangupWithReason) instead of being refused: the call is ended here,
	// in the SAME critical section, with the crossing-200 path's ACK-then-BYE
	// (the ACK is already out) — phaseMediaTeardown, ONE BYE through
	// sendInDialog (skipped if a peer BYE ended the dialog meanwhile), then
	// resolveCancelWait releases the waiting Hangup with the BYE's result and
	// teardownDialog releases the resources (its own close of the wait is only
	// the fallback) — and no answered event, media loop or session timer.
	u.calls.mu.Lock()
	if d.phase != phaseAnswering {
		u.calls.mu.Unlock()
		return
	}
	if d.cancelRequested {
		d.phase = phaseMediaTeardown
		u.calls.mu.Unlock()
		_ = u.byeRecordedHangup(ctx, d)
		return
	}
	d.phase = phaseAnswered
	u.calls.mu.Unlock()
	// The timer is armed only once the dialog IS answered: both arms re-check
	// d.phase under u.calls.mu, so calling them before setPhase would silently
	// arm nothing. st is the very pointer stored into d.sessionTimer above and
	// nothing replaces it (refreshSession re-bases its FIELDS under the lock,
	// never the pointer), so no re-read is needed.
	u.startSessionRefresher(d, st)
	u.startSessionWatchdog(d, st)
	u.startMediaLoop(d)
	u.emit(session.UAEvent{Kind: session.UAEventFinal, DialogID: d.id, CallID: d.callID,
		Direction: session.Outbound, Code: int(res.StatusCode), Reason: res.Reason,
		SDP: res.Body(), At: now()})
}

// byeRecordedHangup ends a dialog whose answering-window hangup was recorded
// (cancelRequested) once the 200 is out: the caller has already moved the dialog
// to phaseMediaTeardown. It sends ONE BYE (skipped when a peer BYE ended the
// dialog meanwhile), resolves the waiting Hangup with the BYE's result and
// releases the dialog. It returns that BYE result: the send error when the BYE
// never reached the wire, nil otherwise (also when no BYE was needed). Shared
// by runDial's answering window and, for an inbound call, Answer (CF-041).
func (u *UA) byeRecordedHangup(ctx context.Context, d *dialog) error {
	if hangupByeHook != nil {
		hangupByeHook()
	}
	// A peer BYE may have ended the dialog since the claim (onBye is
	// phase-blind: phaseDone, and it already released the waiting Hangup).
	// buildInDialogRequest lets every BYE through its liveness check, so the
	// re-check is here: no BYE of ours on a dialog the peer has ended. The
	// residual — a peer BYE landing between this re-check and the BYE's
	// build — is the ordinary BYE-crossing-BYE case (answered 481).
	u.calls.mu.Lock()
	ended := d.phase != phaseMediaTeardown
	u.calls.mu.Unlock()
	if ended {
		u.resolveCancelWait(d, nil)
		u.teardownDialog(d)
		return nil
	}
	// The waiting Hangup gets the BYE's result: an error only when the BYE
	// never reached the wire (not built, or no transaction could start). A
	// BYE that was written but drew no or a non-2xx response still ends the
	// call locally, exactly as hangupWithReason's own BYE path treats it.
	bye, _, berr := u.sendInDialog(ctx, d, sip.BYE, nil)
	var sendErr error
	if berr != nil && (bye == nil || noTransactionErr(berr)) {
		sendErr = fmt.Errorf("send BYE: %w", berr)
	}
	u.resolveCancelWait(d, sendErr)
	u.teardownDialog(d)
	return sendErr
}

// endNegotiationFailed is the ACK-then-BYE end of a dialog whose 2xx exchange
// carried no usable answer: runDial's 200 (the ACK is already out), or the ACK
// answering the offer in Answer's 200 (CF-145). The caller has claimed
// phaseMediaTeardown. It sends ONE BYE with Reason cause 488, releases a waiting
// Hangup with its result, tears the dialog down (teardownDialog closes the media
// socket bound at Dial or Answer) and emits dialog_ended
// media_negotiation_failed with the negotiation error's detail.
//
// THE CANONICAL IN-DIALOG BUILDER, NOT A SECOND DERIVATION (Rule 18). runDial's
// copy of this BYE used to call siptest.BuildByeFromInvite directly and was
// recorded as "behaviourally equivalent" to buildInDialogRequest. It was not:
// that builder clones the INVITE's Via WHOLESALE, branch included
// (sipengine/siptest/builders.go), where buildInDialogRequest strips it
// (dtmf.go's RemoveHeader("Via"), with the wire-verified justification) so the
// transport mints a FRESH branch on dispatch — an RFC 3261 §8.1.1.7 violation
// that never failed observably only because non-INVITE transaction matching is
// keyed on the METHOD too (§17.1.3). buildInDialogRequest also owns the
// direction rules (From/To orientation, Request-URI, Contact) and the §14.5
// CSeq arithmetic (d.localCSeq: see its field comment).
//
// A transaction (sendInDialog), not a fire-and-forget Raw().WriteRequest: this
// must retransmit on UDP and wait for the far end's 200 OK, exactly like
// Hangup's own BYE and the §11.2.1 ladder (BYE -> 200 OK). ctx is u.uaCtx (the
// UA's own lifetime): this is an internal cleanup send, so it must not depend
// on a call_answer/call_dial request context. A build refusal (nil d.invite,
// unreachable here) sends nothing.
func (u *UA) endNegotiationFailed(ctx context.Context, d *dialog, nerr error) {
	var ne *media.NegotiationError
	errors.As(nerr, &ne)
	bye, _, berr := u.sendInDialog(ctx, d, sip.BYE, func(bye *sip.Request) {
		bye.AppendHeader(sip.NewHeader("Reason", `SIP;cause=488;text="media negotiation failed"`))
	})
	// A Hangup recorded in the answering window is waiting on this, the one
	// BYE of the dial: it gets the BYE's result, by the same rule as
	// byeRecordedHangup (an error only if it was never written).
	var sendErr error
	if berr != nil && (bye == nil || noTransactionErr(berr)) {
		sendErr = fmt.Errorf("send BYE: %w", berr)
	}
	u.resolveCancelWait(d, sendErr)
	u.teardownDialog(d)
	u.emit(session.UAEvent{Kind: session.UAEventDialogEnded, Cause: session.UACauseMediaNegotiationFailed,
		DialogID: d.id, CallID: d.callID, Direction: d.direction,
		Detail: ne.Detail(), At: u.cfg.Clock.Now()})
}

// onAck takes the ACK of an inbound dialog's 2xx (CF-145): srv.OnAck for an
// ACK with a fresh branch, and onInvite's hold for one that matched the held
// INVITE transaction. Only an ACK matching the dialog by Call-ID and both tags
// (findDialogForRequestLocked), carrying our 200's To tag (answerTag: the
// matcher accepts only d.toTag until d.ok is stored), with the INVITE's CSeq,
// while the dialog is answering or answered and not yet acked, is recorded;
// so is the ACK of a re-INVITE of the peer's that we answered 2xx (its CSeq on the
// matched dialog, CF-208), which stops that 2xx's retransmission. Any other ACK is
// ignored (an ACK has no response), so a forged one can neither end the call nor
// redirect our RTP. On a dialog offered in its INVITE the record is all that
// happens: applyAckAnswer finds no offer awaiting.
func (u *UA) onAck(req *sip.Request, _ sip.ServerTransaction) {
	u.calls.mu.Lock()
	d := u.findDialogForRequestLocked(req)
	live := d != nil && (d.phase == phaseAnswering || dialogEstablished(d.phase))
	// answerTag is set only by Answer, so an outbound dialog never matches the
	// initial-INVITE clause; a request without CSeq never reaches a handler (the
	// transaction layer cannot key it). The phase check is defensive: answerTag is
	// empty before Answer's claim and after its release.
	if live && !d.acked && d.answerTag != "" && toTagOf(req) == d.answerTag && req.CSeq().SeqNo == d.invite.CSeq().SeqNo {
		d.acked = true
		d.ackBody = req.Body()
		u.calls.mu.Unlock()
		u.applyAckAnswer(d)
		return
	}
	// The ACK of a re-INVITE of the peer's we answered 2xx (CF-208).
	if live && d.peerReinvite != nil && !d.peerReinvite.acked && req.CSeq().SeqNo == d.peerReinvite.cseq {
		pr := d.peerReinvite
		pr.acked = true
		if pr.offer == nil {
			u.calls.mu.Unlock()
			return
		}
		// Our 2xx carried an offer: this ACK carries the answer (RFC 3261 13.2.2.4).
		pr.answerPending = true
		offer, prev, body := *pr.offer, d.mediaSession, req.Body()
		u.calls.mu.Unlock()
		if claimed, err := u.applyReAnswer(d, pr, offer, prev, body); claimed && err != nil {
			u.endNegotiationFailed(u.uaCtx, d, err)
		}
		return
	}
	u.calls.mu.Unlock() // any other ACK is ignored (an ACK has no response)
}

// applyAckAnswer applies the answer in the ACK to the offer in our 200 once
// both have happened: the dialog is phaseAnswered (Answer's tail) and acked
// (onAck). Both call it; whichever comes second does the work. The check, the
// ParseAnswer on a copy, the pointer swap (MediaView reads the old session's
// fields unlocked, so it is never mutated) or the media-teardown claim are ONE
// critical section, and clearing mediaAwaitingAnswer in it makes a second
// caller do nothing. The winner then starts the media loop, or ends the call
// ACK-then-BYE (the ACK is in): no body, unparseable, a codec we did not offer,
// or RTP/AVP where SRTP is required.
func (u *UA) applyAckAnswer(d *dialog) {
	u.calls.mu.Lock()
	if d.phase != phaseAnswered || !d.acked || !d.mediaAwaitingAnswer {
		u.calls.mu.Unlock()
		return
	}
	d.mediaAwaitingAnswer = false
	offer := *d.mediaSession
	sess, nerr := media.ParseAnswer(&offer, d.ackBody)
	if nerr == nil {
		d.mediaSession = sess
		d.mediaStarting = true
	} else {
		d.phase = phaseMediaTeardown
	}
	u.calls.mu.Unlock()
	if nerr != nil {
		u.endNegotiationFailed(u.uaCtx, d, nerr)
		return
	}
	if hook := ackAnswerAppliedHook.Load(); hook != nil {
		(*hook)()
	}
	u.startMediaLoop(d)
	u.calls.mu.Lock()
	d.mediaStarting = false
	u.calls.mu.Unlock()
}

// splitSIPURI splits a "sip:"/"sips:" URI into its user and host[:port] parts.
// It does NOT strip a port off the host half: callers that need the bare host
// must do that separately (see Dial, which needs both forms).
func splitSIPURI(raw string) (user, host string, ok bool) {
	s := strings.TrimPrefix(strings.TrimPrefix(raw, "sips:"), "sip:")
	i := strings.IndexByte(s, '@')
	if i < 0 {
		return "", s, false
	}
	return s[:i], s[i+1:], true
}

// installHandlers registers this UA's inbound SIP handlers on the server
// Task 13 already constructed and already drives via ServeUDP over the
// WrapConn-decorated conn. Called ONCE, unconditionally, from newUA (D129/C3)
// — NOT gated behind Dial or Register — so a UA driven purely as a UAS still
// answers an inbound INVITE.
func (u *UA) installHandlers() {
	srv := u.Server()
	// Every handler except ACK and CANCEL (which take no 4xx) is registered
	// through u.screen, the RFC 3261 8.2 gate (uas.go). A method added here
	// must go through it and into ourAllow.
	srv.OnInvite(u.screen(u.onInvite))
	srv.OnAck(u.onAck)
	srv.OnBye(u.screen(u.onBye))
	srv.OnCancel(u.onCancel)
	srv.OnInfo(u.screen(u.onInfo))
	srv.OnUpdate(u.screen(u.onUpdate))
	srv.OnNotify(u.screen(u.onNotify))
	srv.OnOptions(u.screen(u.onOptions))
	srv.OnNoRoute(u.onNoRoute)
	// Plan D18: the arrival-order observer. sipgo runs it on the transport read
	// loop, in wire order, before reading the next message. Registered here,
	// before startServe (newUACore), so no read loop exists yet to race the
	// append to sipgo's handler list.
	u.agent.TransportLayer().OnMessage(u.observeArrival)
}

// onInvite implements the sipua half of D11's routing rule.
//
// An inbound INVITE routes to the UA whose AOR/Contact it targets, INDEPENDENT
// of which MCP session created that UA. If this UA is not that identity, the
// answer is 404 Not Found — NOT 480 — because the truthful statement is that
// the targeted identity does not exist here, not that it exists and is
// unavailable. The registry half (no live UA matches at all; ownership fixed
// at ua_create and never changing; R11's not_found for a foreign session)
// belongs to `session`.
//
// NOTHING in this function consults connection state. That is deliberate and
// is what makes D11 point 3 hold: if the owning session has no connection
// attached but the UA is still live, the INVITE IS STILL ACCEPTED, and the
// incoming_call and ringing events queue for that session to read whenever it
// next connects.
func (u *UA) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	// 100 Trying IMMEDIATELY (R14), before any allocation that could fail.
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))

	// D2: dialog matching. An INVITE carrying a To-tag is IN-DIALOG — e.g.
	// Asterisk's connected-line/codec-lock re-INVITE, carrying OUR OWN To-tag
	// on an already-answered dialog — never a new call. Left unguarded, every
	// INVITE below built a fresh dialog and called u.admit(ev) unconditionally,
	// so a re-INVITE spawned a phantom ringing call and wedged teardown. W1
	// answers it, applying a changed offer to the live media (reoffer.go); a re-INVITE on
	// any OTHER phase, or a To-tag matching no confirmed dialog at all, is
	// answered 481 per RFC 3261 §12.2.2.
	if toTag := toTagOf(req); toTag != "" {
		u.calls.mu.Lock()
		// CF-176: matched by Call-ID and both tags, as BYE, UPDATE and INFO are.
		d := u.findDialogForRequestLocked(req)
		var (
			matched bool
			pending bool
			ordered bool
			busy    bool
			owned   bool
			sdp     []byte
			ctHdr   sip.Header
			st      *sessionTimerState
		)
		// phaseAnswering is accepted ALONGSIDE phaseAnswered: on an OUTBOUND
		// dialog runDial claims it in the same critical section as d.ok, before
		// its ACK reaches the wire, so the whole ACK -> phaseAnswered window is
		// covered and a direct-media re-INVITE arriving 0.8 ms after the ACK is
		// answered rather than 481'd (a 481 here is terminal — RFC 3261
		// §12.2.1.2 — and tore the call down). It changes nothing INBOUND: there
		// phaseAnswering is Answer's claim, held while its 200 OK is being
		// written, and ourReInviteTagLocked reads d.ok — still nil in that
		// window — so the tag comparison below fails and the 481 stands.
		//
		// C-M2 (D20, W2): this asymmetry with the outbound fix now has a durable
		// record in the known-limitations notes, not only this comment.
		if d != nil && (dialogEstablished(d.phase) || d.phase == phaseAnswering) &&
			ourReInviteTagLocked(d) == toTag {
			matched = true
			ordered = remoteCSeqInOrderLocked(d, req) // CF-101
			// The From tag, body and Content-Type that ourReInviteTagLocked and
			// ourReInviteSDPLocked read off d.invite/d.ok are set once
			// (Answer/runDial) and never mutated after (D147/F1) — safe to read
			// here. d.invite ITSELF is not immutable: the digest-retry CSeq/Via
			// bump (client.go:462-465) and retry422's timer-header/Via rewrite
			// (sessiontimer.go) both mutate it in place on an outbound dialog,
			// deliberately (see retry422's own note) — neither touches the From
			// tag, body or Content-Type these two readers depend on.
			sdp, ctHdr = ourReInviteSDPLocked(d)
			st = d.sessionTimer
			pending = ourOfferOutstandingLocked(d)
			recordPeerMinSELocked(st, req)
			// RFC 3261 14.2: this INVITE owns the dialog's incoming-INVITE slot
			// until its final response is sent, offer or not; another one meanwhile
			// draws 500 with a Retry-After.
			if ordered && !pending {
				owned = claimPeerOfferLocked(d)
				busy = !owned
			}
		}
		u.calls.mu.Unlock()
		if owned {
			defer u.releasePeerOffer(d) // runs after the final response (and after done, below)
		}

		if matched && !ordered {
			respondOutOfOrder(req, tx)
			return
		}
		if matched && pending {
			// RFC 3261 14.2: an INVITE received while an INVITE we sent on the
			// dialog is in progress (or our offer awaits its answer) is 491.
			_ = tx.Respond(sip.NewResponseFromRequest(req, 491, "Request Pending", nil))
			return
		}
		if matched && busy {
			_ = tx.Respond(peerOfferBusy(req))
			return
		}
		if matched {
			// CF-184: an unacceptable Contact is refused before anything is applied.
			if bad := u.contactRefusal(d, req); bad != nil {
				_ = tx.Respond(bad)
				return
			}
			// CF-207/CF-165 (RFC 3261 14.2): a re-INVITE without an offer is answered
			// with a fresh offer built from the live session, not our last SDP. After
			// the Contact refusal (an unacceptable Contact draws 400 first) and before
			// appendInDialogRefreshHeaders (its refusals-first rule).
			var reOffer *media.Session
			var reOfferSDP []byte
			if offer, _ := sdpBody(req); len(offer) == 0 {
				u.calls.mu.Lock()
				live := d.mediaSession
				u.calls.mu.Unlock()
				body, sess, err := media.BuildReOffer(live, u.codecPrefs())
				if err != nil {
					_ = tx.Respond(peerOfferBusy(req))
					return
				}
				sdp, ctHdr, reOffer, reOfferSDP = body, sip.NewHeader("Content-Type", "application/sdp"), sess, body
			}
			res := sip.NewResponseFromRequest(req, 200, "OK", sdp)
			if ctHdr != nil {
				res.AppendHeader(ctHdr)
			}
			// A re-INVITE is a TARGET-REFRESH request AND, from a refreshing
			// peer, a SESSION REFRESH — so its 2xx carries the same Contact +
			// Session-Expires + Allow set onUpdate's does, built by the one
			// helper both call (Rule 18). Answering with only the echoed
			// Content-Type, as this branch used to, dropped the Contact RFC 3261
			// §12.2.2 requires and told the peer, per RFC 4028 §7.4/§10, that the
			// session timer was no longer in use — silently cancelling at the far
			// end the timer this side still keeps a refresher and watchdog armed
			// against.
			refusal, done := u.appendInDialogRefreshHeaders(res, req, d, st)
			sent := false
			defer func() { done(sent) }() // also on a panic in Respond (answerMu)
			if refusal != nil {
				_ = tx.Respond(refusal)
				return
			}
			// CF-163: a changed offer is applied to the live session and answered.
			if rej := u.applyOffer(req, d, res); rej != nil {
				_ = tx.Respond(rej)
				return
			}
			// RFC 4028: an in-dialog re-INVITE from a refreshing peer IS a session
			// refresh. Only a MATCHED re-INVITE counts: one we answered 481 belongs
			// to no dialog by our own reckoning, and letting it rearm would keep a
			// session alive off requests we just told the peer do not exist. done
			// commits the negotiation and re-arms once the 2xx is written.
			// CF-208: the 2xx is retransmitted until its ACK (RFC 3261 13.3.1.4, 14.2),
			// and a missing ACK ends the call. The record is published BEFORE the
			// write so an ACK arriving the instant the 2xx is out is matched; the
			// transaction stays in Accepted past this handler (Task 1, B-D12), so the
			// copies and the ACK pass through it, and this handler returns at once
			// (its defers release the peer-offer claim and the session-timer lock,
			// B-D11). T1 is read here, on the handler goroutine (Answer's rule).
			pr := &peerReinviteState{cseq: req.CSeq().SeqNo, offer: reOffer, offerSDP: reOfferSDP}
			t1 := ack2xxT1
			if t1 == 0 {
				t1 = sip.T1
			}
			t2 := min(8*t1, sip.T2) // read here with t1: sip.T2 is a process-wide variable tests reset
			u.calls.mu.Lock()
			d.peerReinvite = pr
			u.calls.mu.Unlock()
			sent = tx.Respond(res) == nil
			if !sent {
				u.calls.mu.Lock()
				if d.peerReinvite == pr {
					d.peerReinvite = nil
				}
				u.calls.mu.Unlock()
				return
			}
			u.setRemoteTarget(d, req.Contact()) // CF-184: only after the 2xx is on the wire
			if reOffer != nil {
				// B-D13: our offer is outstanding once its 2xx is on the wire, unless
				// its ACK (and answer) already arrived.
				u.calls.mu.Lock()
				if d.peerReinvite == pr && !pr.acked {
					pr.answerPending = true
				}
				u.calls.mu.Unlock()
			}
			go u.retransmit2xx(d, tx, res, t1, t2, func() bool { return u.reinviteUnacknowledged(d, pr) })
			go u.forwardAcks(tx)
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}

	// CF-096 (RFC 3261 17.2.1): sipgo's server.handleRequest terminates the
	// transaction when this handler returns (CF-194: except a non-INVITE that
	// sent its final over UDP, and an INVITE that sent a 2xx, which the FSM keeps
	// to Timer J and Timer L), so an initial INVITE still holds here, because its
	// non-2xx finals need Timers G/H/I, until sipgo's own FSM ends the
	// transaction (Timer L after a 2xx, Timer I after the ACK of a non-2xx,
	// Timer H without one, a transport error) or the UA closes. Retransmissions then meet the live transaction (the latest
	// response is re-sent, no second call) and the ACK of a non-2xx stops Timer
	// G (CF-104). Re-INVITEs and the in-dialog 481 returned above (and the
	// gate's 404, uas.go) are not held. Registered before close(d.admissionDone), so it runs after
	// it: a waiting Answer/Reject is released first. Each request runs on its
	// own goroutine (transaction_layer.go handleMessage), so this blocks nothing
	// else. The admission/cap rejection below clears hold (D-096c (i)).
	// An ACK of our 2xx that reuses the INVITE's branch (or comes from an RFC
	// 2543 peer) matches this held transaction and is passed up on tx.Acks()
	// instead of reaching srv.OnAck, so the hold forwards it to the same onAck
	// (CF-145), on its own goroutine so the hold is back in its select at once.
	// CF-177/CF-097: bound the held handlers and detect a merged request. The
	// release defer is registered BEFORE the hold defer below, so it runs after
	// the hold loop exits (defers run last-in first-out).
	key, status := u.claimInviteHold(req)
	switch status {
	case 482:
		_ = tx.Respond(sip.NewResponseFromRequest(req, 482, "Loop Detected", nil))
		return
	case 503:
		res := sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil)
		res.AppendHeader(sip.NewHeader("Retry-After", retryAfterHeld))
		_ = tx.Respond(res)
		return
	}
	defer u.releaseInviteHold(key)

	hold := true
	defer func() {
		if hold {
			u.forwardAcks(tx)
		}
	}()

	now := u.cfg.Clock.Now
	d := &dialog{id: newDialogID(), direction: session.Inbound, phase: phaseAdmitting,
		callID: callIDOf(req), toTag: newDialogID(), invite: req, serverTx: tx, localCSeq: 1,
		timerReq: readInboundSessionTimer(req), admissionDone: make(chan struct{})}
	// M2: register in phaseAdmitting (NOT phaseRinging). admit()'s accept path
	// appends EventRinging, but the dialog is not call_answer-able until the 180
	// is actually on the wire below — that is the whole ordering fix.
	u.register(d)
	// Every return below ends the admission, whatever the verdict or failure
	// (CF-052): a waiting Answer/Reject is released here, then meets the phase.
	defer close(d.admissionDone)

	// CANCEL on the live transaction (Issue 2, CF-096). The INVITE ServerTx stays
	// registered while onInvite is held, so a CANCEL matches it and is handled by
	// sipgo's transaction layer (which answers the CANCEL's 200 itself); the
	// srv-level u.onCancel is not reached. actCancel calls this hook under the
	// transaction's FSM lock, so the hook only claims: it never responds (the
	// lock is held) and never emits (emit is synchronous into the session layer,
	// which would end the call and close its capture before the 487 is written).
	// It always vetoes sipgo's automatic 487 (returns false). On a won claim the
	// 487 and the cancelled event go to finishInboundCancel on a goroutine,
	// whose Respond waits for the FSM lock; on a lost claim (Answer, Reject, the
	// ring timeout, a 603 or an early BYE already owns the final) nothing is
	// sent and the owner's final goes out. Registered before admit() can block.
	tx.OnCancel(func(*sip.Request) bool {
		if u.claimForCancel(d) {
			go u.finishInboundCancel(tx, req, d.toTag, d.id, d.callID)
		}
		return false
	})

	// SYNCHRONOUS ADMISSION (I2). session decides accept/reject BEFORE we ring —
	// over the concurrency cap or during shutdown — so a reject sends an
	// immediate SIP final with no 180 and no dialog leak. The event is
	// PROTOCOL-LEVEL and carries R14's incoming_call detail; sipua parses the
	// SDP so session never has to. CallID is LOAD-BEARING on this path in a way
	// it is not outbound: the inbound path NEVER returns a DialResult, so this
	// event is R14's ONLY channel for the ladder key.
	offer, _ := sdpBody(req) // the gate (uas.go) already refused an unusable body
	ev := session.UAEvent{
		Kind: session.UAEventInbound, DialogID: d.id, CallID: d.callID,
		Direction: session.Inbound,
		FromURI:   headerURI(req.From()), ToURI: headerURI(req.To()),
		OfferedCodecs: sdpCodecNames(offer), SDP: offer, At: now(),
	}

	if v := u.admit(ev); !v.Accept {
		// M1 reject. admit() ran with NO lock held and can block arbitrarily
		// long, so a CANCEL (via the tx.OnCancel hook above) or an early BYE may
		// have claimed this dialog (phaseDone) meanwhile; that claimant writes the
		// 487, and the hold stays so the transaction can absorb its ACK.
		// claimAdmitting tells us whether we still own the transaction; if not,
		// we must send no second final.
		if !u.claimAdmitting(d) {
			return
		}
		u.teardownDialog(d)
		// D-096c (i): the overload path is not held, so this final is sent once
		// and the transaction ends on return (no Timer G copies to a source that
		// may be spoofed). A retransmitted INVITE after this is admitted afresh.
		hold = false
		_ = tx.Respond(inviteResponse(req, d.toTag, sip.StatusCode(v.Status), v.Reason, nil))
		return
	}

	// The dialog is answerable ONLY after the 180 is on the wire, so it stays
	// phaseAdmitting across the 180 write. A CANCEL (the tx.OnCancel hook) or an
	// early BYE that raced the (possibly long) admission decision may already
	// have claimed phaseDone, so re-check ownership before writing — otherwise a
	// 180 would follow a 487 (a provisional after a final, which is illegal).
	u.calls.mu.Lock()
	stillAdmitting := d.phase == phaseAdmitting
	u.calls.mu.Unlock()
	if !stillAdmitting {
		return // a CANCEL resolved this dialog while admit() was running
	}
	if err := tx.Respond(inviteResponse(req, d.toTag, 180, "Ringing", nil)); err != nil {
		u.teardownDialog(d) // 180 never reached the wire; no leaked dialog
		return
	}
	// Only now, with the 180 confirmed, is call_answer legal. Guarded: a CANCEL
	// or an early BYE may have raced the 180 write itself and already claimed
	// phaseDone; if so it owns the outcome, so leave it. claimForCancel accepts
	// BOTH phaseAdmitting and phaseRinging: the ServerTx stays live while
	// onInvite is held (CF-096), so a CANCEL on a ringing call also routes
	// through actCancel to the hook.
	u.calls.mu.Lock()
	if d.phase != phaseAdmitting {
		u.calls.mu.Unlock()
		return
	}
	d.phase = phaseRinging
	u.calls.mu.Unlock()

	u.armRingTimeout(d)
}

// armRingTimeout drives R14's no-answer case from the INJECTED clock (locked
// decision 18), never time.After: an inbound call neither answered nor
// rejected within limits.inbound_ring_timeout_s is auto-rejected 480
// Temporarily Unavailable with termination_reason "inbound_ring_timeout".
func (u *UA) armRingTimeout(d *dialog) {
	timer := u.cfg.Clock.NewTimer(u.InboundRingTimeout())
	u.calls.mu.Lock()
	d.ringTimer = timer
	u.calls.mu.Unlock()

	go func() {
		select {
		case <-timer.C():
		case <-u.uaCtx.Done():
			timer.Stop()
			return
		}
		u.calls.mu.Lock()
		stillRinging := d.phase == phaseRinging
		u.calls.mu.Unlock()
		if !stillRinging {
			return
		}
		// R14: send the 480 first, then tell session (U14).
		if err := u.finalRespond(d, 480, "Temporarily Unavailable"); err != nil {
			return // a losing race with Answer/Reject; the winner already reported
		}
		// The CAUSE, not a termination_reason. session maps ring_timeout onto
		// §10.3's "inbound_ring_timeout"; sipua names no reason (Rule 18).
		//
		// This is the ONLY thing distinguishing this 480 from call_reject(480)'s:
		// same code, same reason phrase, same direction, same dialog. Reject
		// emits nothing (session initiated it and knows); the timer emits this.
		u.emit(session.UAEvent{
			Kind: session.UAEventDialogEnded, Cause: session.UACauseRingTimeout,
			DialogID: d.id, CallID: d.callID, Direction: session.Inbound,
			Code: 480, Reason: "Temporarily Unavailable", At: u.cfg.Clock.Now(),
		})
	}()
}

// InboundRingTimeout is the configured R14 ring timeout, or
// DefaultInboundRingTimeout when Config.InboundRingTimeout is unset.
func (u *UA) InboundRingTimeout() time.Duration {
	return effectiveInboundRingTimeout(u.cfg.InboundRingTimeout)
}

// effectiveInboundRingTimeout is d, or DefaultInboundRingTimeout when d is not
// positive: one defaulting rule for the ring timer and the listener's eviction
// floor (caplistener.go).
func effectiveInboundRingTimeout(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return DefaultInboundRingTimeout
}

// localContact builds the Contact header this UA advertises in a response,
// extracted from Answer (Rule 16/19 reuse) so the 2xx to an in-dialog UPDATE —
// a TARGET-REFRESH request, whose 2xx MUST carry a Contact (RFC 3261 §12.1.1) —
// gets the identical construction, RFC 3581 learned-public-address rule and all.
func (u *UA) localContact() *sip.ContactHeader {
	ba := u.BoundAddr()
	contactHost, contactPort := ba.IP.String(), ba.Port
	if ap, ok := u.learnedPublic.Get(); ok {
		contactHost, contactPort = ap.Addr().String(), int(ap.Port())
	}
	return &sip.ContactHeader{
		Address: contactAddr(sip.Uri{User: aorUser(u.cfg.AOR), Host: contactHost, Port: contactPort}, u.Transport()),
	}
}

// contactAddr applies the transport rule to our dialog Contact URI (CF-117).
// A TLS UA advertises a sips: URI with no transport parameter (RFC 4028 11.2,
// RFC 3261 26.2.2 deprecates transport=tls); any other non-UDP transport adds
// ;transport=<t>; UDP adds nothing. It copies the parameters before editing
// (sip.Uri copies share the params map).
func contactAddr(addr sip.Uri, transport string) sip.Uri {
	if strings.EqualFold(transport, "tls") {
		addr.Scheme = "sips"
		addr.UriParams = addr.UriParams.Clone().Remove("transport")
		return addr
	}
	if !strings.EqualFold(transport, "udp") {
		addr.UriParams = sip.NewParams()
		addr.UriParams.Add("transport", strings.ToLower(transport))
	}
	return addr
}

// Answer sends 200 OK and transitions the dialog to answered. P1 starts NO
// media (§15's R14 split).
//
// req.SDPAnswer is NIL at P1 and sipua synthesises the fixed PCMU body from
// its own bound address — the SAME rule DialRequest.SDPOffer follows, which is
// why it is one rule and not two. P2 populates the field from the real
// negotiator with no signature change.
//
// It takes session.AnswerRequest, not a bare dialogID, because that is what
// session.UserAgent declares (contract §2.5.3) — and because the SDP has to
// reach this method somehow once P2 negotiates it.
//
// An inbound dialog still being admitted (before its 180 is on the wire) is
// waited for, holding no lock, until the admission finishes, the UA closes or
// ctx ends; the phaseRinging check below then decides. Must not be called from
// the OnAdmit/OnEvent callback of the dialog being admitted (it would wait on
// its own onInvite until the UA closes).
func (u *UA) Answer(ctx context.Context, req session.AnswerRequest) error {
	d, err := u.lookup(req.DialogID)
	if err != nil {
		return err
	}
	if err := u.waitAdmission(ctx, d, "call_answer"); err != nil {
		return err
	}
	u.calls.mu.Lock()
	if d.direction != session.Inbound || d.phase != phaseRinging {
		p := d.phase
		u.calls.mu.Unlock()
		return apierr.PreconditionFailed(
			fmt.Sprintf("dialog is in phase %d; call_answer requires a ringing inbound dialog", p))
	}
	// THE CLAIM, IN THE SAME CRITICAL SECTION AS THE CHECK ABOVE. Stopping the
	// timer is NOT a claim: Stop() on an ALREADY-FIRED timer is a no-op and
	// that timer's goroutine is already past `<-timer.C()`, so it will still
	// take this lock, still read d.phase, and — while the dialog was left
	// phaseRinging for the duration of the tx.Respond below — still send 480
	// on the SAME ServerTransaction the 200 OK is going out on. Two final
	// responses on one INVITE transaction is a wire-protocol violation, and
	// the 480's UAEventDialogEnded{ring_timeout} made session tear down the
	// call call_answer had just reported as answered.
	//
	// finalRespond and Reject both require phaseRinging, so this claim locks
	// both out for the whole write. See phaseAnswering's own comment for why
	// it is a THIRD phase rather than an early phaseAnswered.
	d.phase = phaseAnswering
	d.callHandle = req.CallHandle
	d.mediaPlanSteps = req.MediaPlan
	if d.ringTimer != nil {
		d.ringTimer.Stop()
	}
	tx, inv, timerReq := d.serverTx, d.invite, d.timerReq
	u.calls.mu.Unlock()

	// RFC 4028 §6: an interval below our own min_se_s is refused with 422 and our
	// Min-SE, BEFORE any media resource is bound — a 422 is a negotiation
	// outcome, and binding an RTP port for a call we are about to refuse would
	// leak one per attempt.
	negotiatedS := 0
	role := ""
	if timerReq.Present {
		var refuse int
		negotiatedS, refuse = u.negotiatedInterval(timerReq)
		if refuse == 400 {
			// CF-118: a Min-SE above what we honour is a malformed demand, refused
			// whatever the request lists in Supported.
			_ = tx.Respond(inviteResponse(inv, d.toTag, 400, "Bad Request", nil))
			u.teardownDialog(d)
			return &session.AnswerRefusedError{Status: 400, Reason: "Bad Request",
				Err: apierr.PreconditionFailed(fmt.Sprintf(
					"call_answer: peer's Min-SE of %ds is above the %ds we honour; sent 400",
					timerReq.MinSE, maxHonouredMinSES))}
		}
		if refuse == 422 && !timerReq.Supported && !timerReq.Required {
			// CF-120: RFC 3261 8.2.4 forbids applying an extension the request
			// never listed in Supported, and the 422 is RFC 4028 9's remedy for
			// a request that did. Answer with no timer (RFC 4028 7.2: a 2xx
			// without Session-Expires means no session expiration).
			timerReq = inboundTimerRequest{}
		} else if refuse == 422 {
			res422 := inviteResponse(inv, d.toTag, 422, "Session Interval Too Small", nil)
			res422.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(u.minSES())))
			_ = tx.Respond(res422)
			u.teardownDialog(d)
			return &session.AnswerRefusedError{Status: 422, Reason: "Session Interval Too Small",
				Err: apierr.PreconditionFailed(fmt.Sprintf(
					"call_answer: peer requested a %ds session interval, below our min_se_s of %d; sent 422",
					timerReq.Requested.IntervalS, u.minSES()))}
		}
		if timerReq.Present {
			role = inboundRefresherRole(timerReq)
		}
	}

	// Negotiate the answer SDP (M5). The offer is the INVITE body we stored.
	mip, err := media.ResolveMediaAddr(u.cfg.LocalAddr, u.cfg.MediaLocalIP, "", u.cfg.Logger)
	if err != nil {
		u.releaseAnsweringClaim(d)
		return apierr.Internal("", fmt.Sprintf("resolve media addr: %v", err))
	}
	mconn, mport, err := u.bindMediaPort(mip)
	if err != nil {
		u.releaseAnsweringClaim(d)
		return apierr.Internal("", err.Error())
	}
	// Store the media socket on the dialog immediately, so the shared teardownDialog
	// owns its release on EITHER outcome — the answer-side 488 below and the happy
	// path alike — instead of a scattered mconn.Close() at each exit (M1; Cycle B #2).
	u.calls.mu.Lock()
	d.mediaConn = mconn
	u.calls.mu.Unlock()
	localMediaAddr := net.JoinHostPort(mip.String(), strconv.Itoa(mport))
	// CF-145 (RFC 3261 13.3.1): an INVITE without a session description asks
	// us for the offer, which goes in the 200; the caller's ACK carries the
	// answer (onAck, applyAckAnswer), so no media starts here. BuildOffer fails
	// only on a local fault (prefs, crypto/rand): the 500 branch below.
	offer, _ := sdpBody(inv)
	offerless := len(offer) == 0
	var (
		answer []byte
		sess   *media.Session
		nerr   error
	)
	if offerless {
		answer, sess, nerr = media.BuildOffer(u.codecPrefs(), localMediaAddr, u.srtpPolicy(req.SRTP))
	} else {
		answer, sess, nerr = media.BuildAnswer(offer, media.AnswerOptions{Prefs: u.codecPrefs(), LocalAddr: localMediaAddr, SRTP: u.srtpPolicy(req.SRTP)})
	}
	if nerr != nil {
		var ne *media.NegotiationError
		if errors.As(nerr, &ne) {
			// Answer-side 488 (§11.2). No 200 OK is ever sent. Send 488 and tear down
			// through the shared helper, which closes d.mediaConn; surface the
			// media_negotiation apierr synchronously as call_answer's error.
			_ = tx.Respond(inviteResponse(inv, d.toTag, 488, "Not Acceptable Here", nil))
			u.teardownDialog(d)
			return &session.AnswerRefusedError{Status: 488, Reason: "Not Acceptable Here",
				Err: apierr.MediaNegotiation(ne.Kind, ne.Detail(), ne.Error())}
		}
		// A non-negotiation fault (e.g. GenerateCryptoAttr's crypto/rand failing) is
		// an internal error, not a policy refusal — no 488. Guard against dereferencing
		// a nil *NegotiationError (the bug this branch exists to prevent).
		_ = tx.Respond(inviteResponse(inv, d.toTag, 500, "Server Internal Error", nil))
		u.teardownDialog(d)
		return &session.AnswerRefusedError{Status: 500, Reason: "Server Internal Error",
			Err: apierr.Internal("", fmt.Sprintf("build answer: %v", nerr))}
	}

	res := inviteResponse(inv, d.toTag, 200, "OK", answer)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(u.localContact())
	// Our Allow always names UPDATE from P3 (spec §5), whether or not this dialog
	// has a session timer: it is what stops a refreshing peer falling back to a
	// re-INVITE on every interval.
	res.AppendHeader(sip.NewHeader("Allow", ourAllow()))
	if timerReq.Present {
		res.AppendHeader(sip.NewHeader("Session-Expires",
			formatSessionExpires(sessionExpires{IntervalS: negotiatedS, Refresher: role})))
		if requireTimerInAnswer(timerReq, role) {
			res.AppendHeader(sip.NewHeader("Require", "timer"))
		}
	}
	// The session, the awaiting-answer mark and the 200's To tag (the one
	// d.toTag) are published together before the write, so
	// an ACK arriving the instant the 200 is out is matched (onAck).
	u.calls.mu.Lock()
	d.mediaSession = sess
	d.mediaAwaitingAnswer = offerless
	d.answerTag = toTagOf(res)
	u.calls.mu.Unlock()
	if err := tx.Respond(res); err != nil {
		// RELEASE THE CLAIM. The dialog goes back exactly where it was before
		// this call: phaseRinging, with its ring timer stopped — which is the
		// state the pre-claim code also left behind on this path, since it
		// stopped the timer before responding too. call_reject therefore stays
		// available on an answer that failed to reach the wire.
		//
		// ALSO release the media socket bound above (line ~920). teardownDialog
		// is NOT called here — this is a retryable write failure, not a
		// rejection, and teardownDialog would forget the dialog's registry
		// entry. But bindMediaPort already ran and stored its result on
		// d.mediaConn, so leaving it there would leak the socket (nothing else
		// closes it while the dialog sits phaseRinging) and, on a retried
		// Answer(), bindMediaPort would bind and unconditionally overwrite a
		// SECOND socket onto d.mediaConn, permanently leaking the first.
		u.calls.mu.Lock()
		if d.mediaConn != nil {
			_ = d.mediaConn.Close()
		}
		d.mediaConn = nil
		d.mediaSession = nil
		u.calls.mu.Unlock()
		// A hangup recorded during this write declines the call (CF-041).
		u.releaseAnsweringClaim(d)
		return fmt.Errorf("respond 200: %w", err)
	}
	// CF-131: the 200 is on the wire and the dialog still phaseAnswering, so
	// nothing can start media or a timer before the final claim below; session
	// records `answered` here, ahead of media_start and any refresh event.
	if req.OnAnswered != nil {
		req.OnAnswered()
	}
	// The 2xx retransmission's T1 is read here, on the caller's goroutine, so the
	// goroutine started below never reads the package variable.
	retransmitT1 := ack2xxT1
	if retransmitT1 == 0 {
		retransmitT1 = sip.T1
	}
	// TEST SEAM: the 200 is out, the final claim not yet made. nil in production.
	if answerRespondedHook != nil {
		answerRespondedHook()
	}
	// D147/F1: d.phase and d.ok are set together, in ONE critical section,
	// only after tx.Respond has succeeded. The original code set d.phase =
	// phaseAnswered BEFORE this point and stored d.ok only here, which opened
	// a window where a concurrent Hangup observed an answered dialog with
	// d.ok == nil and fabricated a fresh To-tag via sip.NewResponseFromRequest
	// (sipgo v0.24.1 sip/response.go:227-233 mints a NEW RANDOM UUID To-tag on
	// every call) — the BYE then carried a tag the far end never issued and
	// drew a 481. Reproduced 57/60 iterations under -race (no data race; the
	// locking was correct, this was a LOGICAL race). Combining the two writes
	// closes the window: any reader that observes d.phase == phaseAnswered is
	// guaranteed d.ok is already the response actually sent on the wire.
	//
	// AND THE SECOND WINDOW THAT FIX CREATED, which this comment used to be
	// silent about. Deferring the phase write to here left the dialog in
	// phaseRinging for the whole of the tx.Respond above, so an ALREADY-FIRED
	// ring timer could take the lock mid-write, read phaseRinging, and put a
	// SECOND final response (480) on the same INVITE transaction — closed by
	// the phaseAnswering claim made in the check's own critical section above.
	//
	// THE TWO HAZARDS PULL IN OPPOSITE DIRECTIONS, and phaseAnswering is what
	// satisfies both at once: claiming EARLY as phaseAnswered would reopen
	// D147/F1 (Hangup would see an answered dialog with d.ok still nil);
	// claiming LATE — not at all — reopens the double-response. A third phase
	// that is neither is the only state that locks out finalRespond and Reject
	// (both require phaseRinging) while keeping Hangup from sending anything
	// (a BYE needs d.ok): a Hangup in this phase is RECORDED and Answer ends the
	// call when it settles (CF-041). Pinned by
	// TestAnsweringPhaseDefersHangupAndRefusesReject.
	//
	// d.sessionTimer JOINS THE SAME CRITICAL SECTION, for the same reason it does
	// on the outbound side (runDial's claim above). It is still recorded only
	// AFTER the 200 reached the wire — this whole block is past tx.Respond, so a
	// dialog that fell back to phaseRinging on a failed Respond still reports no
	// timer it never agreed — but it is no longer recorded a few lines LATER than
	// d.phase/d.ok. It used to be, and the 200 OK is already on the wire by then:
	// a peer's re-INVITE arriving in that gap matched an answered dialog (the tag
	// compare reads d.ok, published in this same section) with d.sessionTimer
	// still nil, and was answered without Session-Expires — RFC 4028 §7.4's "the
	// session timer is no longer in use". buildInboundSessionTimer is a pure
	// builder so the store can happen here; u.calls.mu is NOT reentrant.
	//
	// st is nil exactly when the peer asked for no timer, in which case
	// d.sessionTimer is nil already — the store is a no-op, not a clobber (this
	// is the only inbound writer, and Answer is the only path that reaches it).
	var st *sessionTimerState
	if timerReq.Present {
		st = buildInboundSessionTimer(negotiatedS, role, timerReq.Allow, timerReq.MinSE)
	}
	//
	// THE FINAL TRANSITION IS A CLAIM, NOT AN ASSIGNMENT (CF-041), for the same
	// reason as runDial's: onBye is phase-blind, so a caller BYE landing during
	// the write above has already set phaseDone and forgotten the dialog, and
	// writing phaseAnswered over it would arm session timers (and a media loop)
	// on a dialog nothing can reach. And a call_hangup that landed in this
	// window was RECORDED (cancelRequested), not refused: the call is ended here,
	// after the 200, with ONE BYE — d.ok is set first so the BYE carries the To-tag
	// the far end was given (D147).
	u.calls.mu.Lock()
	if d.phase != phaseAnswering {
		u.calls.mu.Unlock()
		u.teardownDialog(d) // releases what Answer bound after onBye's cleanup
		return nil
	}
	d.ok = res
	if d.cancelRequested {
		d.phase = phaseMediaTeardown
		u.calls.mu.Unlock()
		if err := u.byeRecordedHangup(ctx, d); err != nil {
			u.log().Warn("the call_hangup recorded during call_answer could not be sent; dialog released",
				"dialog", d.id, "err", err)
		}
		return nil
	}
	d.phase = phaseAnswered
	d.sessionTimer = st
	u.calls.mu.Unlock()
	go u.retransmit2xx(d, tx, res, retransmitT1, min(8*retransmitT1, sip.T2), func() bool { return u.unacknowledged(d) })
	u.startSessionRefresher(d, st)
	u.startSessionWatchdog(d, st)
	if offerless {
		// An ACK accepted while the dialog was still phaseAnswering is applied
		// here; one arriving later applies itself (onAck).
		u.applyAckAnswer(d)
	} else {
		u.startMediaLoop(d)
	}
	// No further UAEvent: session INITIATED this answer, so it already knows
	// the call is answered the moment this returns nil. Emitting one would
	// make session learn the same fact twice, by two paths, with no ordering
	// guarantee between them.
	return nil
}

// ack2xxT1 is a test seam: 0 in production, meaning sip.T1. It sets the base
// interval of the 2xx retransmission and so the 64*T1 no-ACK deadline.
var ack2xxT1 time.Duration

// retransmit2xx re-sends a 2xx we sent through its INVITE server transaction at
// t1, 2*t1, ... capped at T2, until awaiting reports it is no longer awaiting an
// ACK, or the UA closes (RFC 3261 13.3.1.4, on every transport: hops between UAS
// and UAC may be unreliable). At 64*t1 while still awaiting, the session is
// terminated (BYE). Its two callers: Answer (the initial INVITE's 200, awaiting =
// unacknowledged) and onInvite's re-INVITE branch (CF-208, awaiting =
// reinviteUnacknowledged).
//
// The timers are real, not u.cfg.Clock: they are RFC 3261 transaction timers
// like sipgo's own Timer G/H/L, and a fake-clock timer would change the waiter
// count fakeclock.BlockUntil sees in every inbound-call test (decision D-12).
func (u *UA) retransmit2xx(d *dialog, tx sip.ServerTransaction, res *sip.Response, t1, t2 time.Duration, awaiting func() bool) {
	interval := t1
	deadline := time.NewTimer(64 * t1)
	tick := time.NewTimer(interval)
	defer deadline.Stop()
	defer tick.Stop()
	for {
		select {
		case <-u.uaCtx.Done():
			return
		case <-deadline.C:
			if awaiting() {
				u.endUnacknowledged(d)
			}
			return
		case <-tick.C:
			if !awaiting() {
				return
			}
			_ = tx.Respond(res)
			interval = min(2*interval, t2)
			tick.Reset(interval)
		}
	}
}

// unacknowledged reports whether d is established and its 200 has not been ACKed.
func (u *UA) unacknowledged(d *dialog) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return dialogEstablished(d.phase) && !d.acked
}

// reinviteUnacknowledged reports whether pr, the peer's re-INVITE we answered 2xx,
// is still the newest one and has not been ACKed on a live dialog (CF-208, B-D10).
func (u *UA) reinviteUnacknowledged(d *dialog, pr *peerReinviteState) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return (dialogEstablished(d.phase) || d.phase == phaseAnswering) && d.peerReinvite == pr && !pr.acked
}

// forwardAcks passes ACKs that matched tx (same Via branch as the INVITE, or an
// RFC 2543 peer) to onAck until the transaction ends or the UA closes. sipgo hands
// such an ACK up on tx.Acks() instead of srv.OnAck; each goes to its own
// goroutine so the loop is back in its select at once.
func (u *UA) forwardAcks(tx sip.ServerTransaction) {
	for {
		select {
		case ack := <-tx.Acks():
			go u.onAck(ack, nil)
		case <-tx.Done():
			return
		case <-u.uaCtx.Done():
			return
		}
	}
}

// endUnacknowledged ends a call whose 200 drew no ACK in 64*T1 (RFC 3261
// 13.3.1.4: "the session SHOULD be terminated"). It goes through
// hangupWithReason, the single BYE path, and emits the dialog end the way
// expireSessionTimer does: nothing when another path already ended the call,
// nothing when the UA is closing (Close sent its own BYE).
func (u *UA) endUnacknowledged(d *dialog) {
	u.log().Warn("no ACK for the 200 within 64*T1; ending the call",
		"dialog_id", d.id, "call_id", d.callID)
	if err := u.hangupWithReason(u.uaCtx, d.id, nil); err != nil {
		if c := apierr.CodeOf(err); c == apierr.CodePreconditionFailed || c == apierr.CodeNotFound {
			return
		}
	}
	u.calls.mu.Lock()
	closed := u.calls.closed
	u.calls.mu.Unlock()
	if closed {
		return
	}
	u.emit(session.UAEvent{
		Kind: session.UAEventDialogEnded, Cause: session.UACauseTransportFailure,
		DialogID: d.id, CallID: d.callID, Direction: d.direction, At: u.now(),
		Detail: map[string]any{
			"kind": "transport_failure", "transport": u.Transport(),
			"cause": "no_ack", "method": "ACK",
		},
	})
}

// releaseAnsweringClaim returns a dialog that failed AFTER claiming
// phaseAnswering back to phaseRinging, mirroring the tx.Respond error path, so
// call_reject stays available. When a call_hangup was recorded meanwhile
// (CF-041) the call is declined 603 instead, which is what the hangup does to a
// ringing call, and released; the waiting Hangup gets the 603's write result.
func (u *UA) releaseAnsweringClaim(d *dialog) {
	u.calls.mu.Lock()
	decline := d.phase == phaseAnswering && d.cancelRequested
	d.answerTag = ""
	if decline {
		d.phase = phaseDone
	} else if d.phase == phaseAnswering {
		d.phase = phaseRinging
	}
	tx, inv := d.serverTx, d.invite
	u.calls.mu.Unlock()
	if !decline {
		return
	}
	var werr error
	if err := tx.Respond(inviteResponse(inv, d.toTag, 603, "Decline", nil)); err != nil {
		werr = fmt.Errorf("respond 603: %w", err)
		u.log().Warn("the call_hangup recorded during call_answer could not decline the call; dialog released",
			"dialog", d.id, "err", werr)
	}
	u.resolveCancelWait(d, werr)
	u.teardownDialog(d)
}

// Reject sends the given final response (DEFAULT 486 Busy Here) and starts NO
// media. session.Call records termination_reason "rejected_locally".
//
// PERMITTED STATUS IS 300-699; anything else is invalid_argument. This is
// SETTLED as locked decision U13, not open: §10.3, §11.2 and D11 all say
// 300-699 against R14's prose alone saying "3xx-6xx" — three normative sources
// against one piece of prose. R14's wording is being corrected.
//
// An inbound call NEVER enters "failed" (§10.3): a locally-chosen rejection is
// a "terminated" with a reason, not a failure of this server's operation. That
// invariant is session's to hold; this method's contribution is that it emits
// nothing from which session could derive "failed".
//
// Like Answer, it waits (holding no lock) for an inbound dialog still being
// admitted, and must not be called from the OnAdmit/OnEvent callback of the
// dialog being admitted.
func (u *UA) Reject(ctx context.Context, dialogID string, status int, reason string) error {
	if status == 0 {
		status, reason = 486, "Busy Here"
	}
	if status < 300 || status > 699 {
		return apierr.InvalidArgument(
			fmt.Sprintf("status %d is outside the permitted range 300-699", status))
	}
	if reason == "" {
		reason = defaultReason(status)
	}
	d, err := u.lookup(dialogID)
	if err != nil {
		return err
	}
	if err := u.waitAdmission(ctx, d, "call_reject"); err != nil {
		return err
	}
	u.calls.mu.Lock()
	if d.direction != session.Inbound || d.phase != phaseRinging {
		p := d.phase
		u.calls.mu.Unlock()
		return apierr.PreconditionFailed(
			fmt.Sprintf("dialog is in phase %d; call_reject requires a ringing inbound dialog", p))
	}
	u.calls.mu.Unlock()
	// No UAEvent: session INITIATED this rejection and records
	// "rejected_locally" itself. The ring timer, which nobody initiated, emits
	// a UAEventDialogEnded instead — that asymmetry IS the disambiguation, and
	// Step 11 asserts it.
	return u.finalRespond(d, status, reason)
}

// waitAdmission blocks while d is an inbound dialog still in phaseAdmitting,
// until onInvite has finished admitting it (admissionDone), ctx ends, or the UA
// closes. It holds no lock while waiting and claims nothing: the caller applies
// its own phase check afterwards, so M2 (no 200 before the 180) is unchanged.
func (u *UA) waitAdmission(ctx context.Context, d *dialog, op string) error {
	u.calls.mu.Lock()
	ch, admitting := d.admissionDone, d.phase == phaseAdmitting
	u.calls.mu.Unlock()
	if !admitting || ch == nil {
		return nil
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return classifyCtxErr(ctx, op)
	case <-u.uaCtx.Done():
		return apierr.PreconditionFailed(op + ": the user agent closed while the call was being admitted")
	}
}

// finalRespond sends a locally-chosen final response on a ringing inbound
// dialog, and sends NO event. It is shared by Reject and by the ring timeout;
// the two callers differ only in what they emit afterwards, which is the whole
// distinction between "rejected_locally" and "inbound_ring_timeout". It is not
// the only sender of a local final: hangupWithReason repeats the same claim
// inline and sends its own 603 for a ringing or admitting inbound dialog.
//
// It returns precondition_failed when the dialog is no longer ringing, so a
// ring timer racing a concurrent Answer or Reject loses cleanly and stays
// silent rather than reporting a termination the winner already reported.
func (u *UA) finalRespond(d *dialog, status int, reason string) error {
	u.calls.mu.Lock()
	if d.phase != phaseRinging {
		u.calls.mu.Unlock()
		return apierr.PreconditionFailed("dialog is no longer ringing")
	}
	d.phase = phaseDone
	u.forgetLocked(d.id)
	if d.ringTimer != nil {
		d.ringTimer.Stop()
	}
	tx, inv := d.serverTx, d.invite
	u.calls.mu.Unlock()

	if err := tx.Respond(inviteResponse(inv, d.toTag, sip.StatusCode(status), reason, nil)); err != nil {
		return fmt.Errorf("respond %d: %w", status, err)
	}
	return nil
}

// Hangup ends the dialog the way its phase allows (§6.2.1's UserAgent.Hangup
// contract). session.Call records termination_reason "local_hangup" whichever
// way it went — sipua does not name §10.3's enum.
//
//   - Established (answered, or running a control operation): a BYE; it
//     BLOCKS until the far end's final response, u.cfg.Timeout, or ctx.
//   - Outbound with a provisional in (phaseRinging, or phaseDialing after a
//     100 Trying): a CANCEL; it returns once the CANCEL is WRITTEN, never
//     waiting for the 487.
//   - Outbound, no provisional yet: the hangup is recorded and it BLOCKS until
//     runDial has written the deferred CANCEL on the first 1xx (a failed write
//     is returned), or the dial settles otherwise (final response, crossing
//     200's ACK-then-BYE, teardown, peer BYE).
//   - Outbound, 200 in but not yet established (phaseAnswering): recorded, no
//     CANCEL; runDial's final claim ACK-then-BYEs the call instead of
//     establishing it, and Hangup BLOCKS until that BYE's transaction has
//     returned (its final response or u.cfg.Timeout; an unwritten BYE is
//     returned as an error), or a peer BYE ends the call.
//   - In both waiting cases, ctx ending returns ctx.Err(), and cancelWaitCap
//     (2s) returns nil — even if the CANCEL is still pending or the BYE is
//     still awaiting its response.
//   - Inbound, ringing or being admitted: declined 603, handed to the
//     transaction layer.
//   - Inbound phaseAnswering (Answer is writing its 200): recorded, nothing
//     sent (d.ok is unset). Hangup waits until Answer settles, ctx ends, or
//     cancelWaitCap (nil; the hangup stays recorded). Answer then sends ONE BYE
//     after the 200, or declines 603 if the 200 was not written; a peer BYE ends
//     it without a BYE of ours (CF-041).
//   - phaseMediaTeardown (an ACK-then-BYE in progress): refused
//     precondition_failed.
//
// Its errors: not_found and gone (no such live dialog), precondition_failed
// (the refusals above), ctx.Err() when the caller's ctx ended a wait, and a
// wrapped transport/protocol error when the CANCEL, BYE or 603 could not be
// sent or the BYE was rejected. DELIBERATELY NO invalid_argument, because
// `reason` is free text and no value of it is rejected. The reason parameter
// is therefore accepted and never validated.
//
// On a UA that Close has closed, an id that is no longer registered returns nil
// and sends nothing (Close took over an established dialog and sent its BYE;
// CF-061), while a dialog still registered takes its phase's path above,
// closed or not.
//
// No UAEvent is emitted: session INITIATED the hangup and learns the outcome
// from this method's return, so an event would deliver the same fact twice.
//
// THE reason PARAMETER NEVER REACHES THE WIRE, AND THAT IS A SECURITY PROPERTY,
// not an oversight (spec §7). It is agent-supplied free text; turning it into a
// structured Reason header would be a header-injection surface (CRLF in the
// value splits the message). Internal callers that need a REAL Reason header —
// the RFC 4028 watchdog's `SIP;cause=408` — call hangupWithReason with a header
// THIS PACKAGE built.
func (u *UA) Hangup(ctx context.Context, dialogID string, _ string) error {
	return u.hangupWithReason(ctx, dialogID, nil)
}

// hangupWithReason is Hangup's implementation, plus an optional Reason header
// built by THIS PACKAGE. reason nil sends no Reason header at all.
//
// ITS BYE IS BUILT BY buildInDialogRequest (dtmf.go), WHICH IS WHERE THE CSeq
// COMES FROM. Task 15 extracted that builder for INFO and recorded that BYE would
// join it here, and the CSeq is the reason it matters: buildInDialogRequest
// allocates from dialog.localCSeq under u.calls.mu, so INFO, UPDATE and BYE draw
// from ONE strictly-increasing sequence space (RFC 3261 §12.2.1.1). This is a
// de-duplication (Rule 16/18) onto the allocator Task 15 already built for INFO,
// and it closes two latent edge cases the old hand-rolled construction carried:
// a nil panic when d.invite == nil (buildInDialogRequest returns
// precondition_failed instead) and a BYE that reused the answered INVITE's
// cloned Via branch (buildInDialogRequest strips it, matching every other
// in-dialog request on the same dialog).
func (u *UA) hangupWithReason(ctx context.Context, dialogID string, reason sip.Header) error {
	d, err := u.lookup(dialogID)
	if err != nil {
		// CF-061 (R-13): on a closed UA there is no dialog left to end; Close
		// took over an established one (and sent its BYE). Only the lookup miss
		// is checked: a dialog still registered takes its phase's path below.
		u.calls.mu.Lock()
		closed := u.calls.closed
		u.calls.mu.Unlock()
		if closed {
			return nil
		}
		return err
	}
	u.calls.mu.Lock()
	if d.phase == phaseAnswering || (d.direction == session.Outbound && (d.phase == phaseDialing || d.phase == phaseRinging)) {
		// NOT YET ESTABLISHED: CANCEL the INVITE (RFC 3261 §9.1) instead of a
		// BYE. Returns once the CANCEL is WRITTEN, never waiting for the 487:
		// runDial owns the INVITE transaction and ends the dialog on its final
		// response (a 200 that crossed the CANCEL is ACKed and BYE'd there). With
		// no provisional yet there is nothing we may CANCEL: the request is
		// recorded, dialProvisional sends it on the first 1xx, and this call
		// WAITS — with u.calls.mu released — until that CANCEL is written (its
		// write error is returned), the dial settles otherwise (teardownDialog),
		// ctx ends, or cancelWaitCap elapses; on the cap it returns nil and the
		// CANCEL stays pending. In phaseAnswering (outbound: runDial claimed the
		// 200 and is between its ACK and phaseAnswered; inbound, CF-041: Answer is
		// writing its 200) there is nothing to CANCEL either: the hangup is
		// recorded the same way and the settling section (runDial's final claim,
		// or Answer's) BYEs the call instead of establishing it, or declines it
		// 603 when Answer's 200 was not written; this call waits until that
		// transaction returns (or the cap: nil, the hangup stays recorded and is
		// still enacted). A repeated hangup finds cancelRequested already set and
		// returns at once.
		repeat, send := d.cancelRequested, d.cancelReq
		if d.phase == phaseAnswering {
			// Nothing to CANCEL: the settling section (runDial's final claim,
			// or Answer's) BYEs or declines the call.
			send = nil
		}
		d.cancelRequested = true
		var wait chan error
		if !repeat && send == nil {
			wait = make(chan error, 1)
			d.cancelWait = wait
		}
		u.calls.mu.Unlock()
		switch {
		case repeat:
			return nil
		case send != nil:
			err := u.sendCancel(ctx, send)
			markCancelSent(d)
			if err != nil {
				return fmt.Errorf("send CANCEL: %w", err)
			}
			return nil
		}
		timer := time.NewTimer(cancelWaitCap)
		defer timer.Stop()
		select {
		case err := <-wait:
			return err // already wrapped by its resolver: "send CANCEL: ..." / "send BYE: ..."
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			u.log().Warn("hangup wait elapsed before the CANCEL, BYE or 603 went out; the hangup stays recorded",
				"dialog", d.id, "wait", cancelWaitCap)
			return nil
		}
	}
	if d.direction == session.Inbound && (d.phase == phaseRinging || d.phase == phaseAdmitting) {
		// NOT YET ANSWERED, INBOUND (ua_destroy reaches here for a call still
		// ringing): decline it 603. Ringing and still-being-admitted dialogs
		// share ONE claim, made under the lock this phase check was read under,
		// so a concurrent Answer cannot slip in between the check and the claim
		// and draw a precondition error from a hangup that saw it ringing. An
		// admitting dialog has had no 180 yet: onInvite, finding it no longer
		// phaseAdmitting, sends none. teardownDialog stops the ring timer and
		// forgets the dialog (a ringing inbound dialog has no media conn).
		d.phase = phaseDone
		tx, inv := d.serverTx, d.invite
		u.calls.mu.Unlock()
		u.teardownDialog(d)
		if err := tx.Respond(inviteResponse(inv, d.toTag, 603, "Decline", nil)); err != nil {
			return fmt.Errorf("respond 603: %w", err)
		}
		return nil
	}
	if !dialogEstablished(d.phase) {
		// Only a settled, answered dialog can be BYE'd here — INCLUDING one running
		// a call control operation (phaseControlOp). The call_hangup TOOL refuses
		// that case one layer up only while the operation blocks hangup
		// (session.ToolService.CallHangup's ControlOpBlocksHangup pre-check, which
		// runs BEFORE its own termination claim — plan D17); ua_destroy, shutdown's
		// HangupAllLive and the RFC 4028 watchdog can always end the dialog. Ending
		// it settles the operation through endControlOpByLocalHangupLocked below,
		// which tells the owner it was OUR hangup. phaseMediaTeardown in
		// particular is refused: runDial's offering-side ACK-then-BYE (§11.2.1)
		// holds the dialog there while it sends its OWN internal BYE, and a racing
		// call_hangup must get precondition_failed rather than fire a duplicate BYE
		// on the wire.
		p := d.phase
		u.calls.mu.Unlock()
		return apierr.PreconditionFailed(
			fmt.Sprintf("dialog is in phase %d; a BYE can only end an answered dialog", p))
	}
	d.phase = phaseDone
	endControlOpByLocalHangupLocked(d) // D17: the owner learns OUR BYE ended it
	u.forgetLocked(d.id)
	ml, conn := d.mediaLoop, d.mediaConn
	d.mediaLoop, d.mediaConn = nil, nil
	// CF-061: a claim made before Close's sweep counts its BYE, so Close waits
	// for it (bounded) before closing the transport. After closed is set
	// nothing is counted: Close may already be waiting.
	counted := !u.calls.closed
	if counted {
		u.calls.byes.Add(1)
	}
	u.calls.mu.Unlock()
	if counted {
		defer u.calls.byes.Done()
	}
	if ml != nil {
		ml.stop()
	} else if conn != nil {
		_ = conn.Close()
	}
	// Step 6/Correction 5: disarm the session timer alongside the media loop,
	// OUTSIDE u.calls.mu — refresher.Stop() waits for a goroutine that may be
	// inside refreshSession, which takes that lock.
	u.stopSessionTimer(d)

	// ONE in-dialog SEND path (sendInDialog, indialog.go — plan D12). It builds
	// the BYE with buildInDialogRequest, which owns the From/To orientation, the
	// inbound Request-URI fix AND the CSeq allocation from d.localCSeq, and it
	// holds the dialog's send-order token from that reservation until the BYE
	// is written, so the BYE can neither reuse nor be overtaken by the CSeq of
	// an INFO, refresh or REFER in flight on this dialog. It takes u.calls.mu
	// itself, so it MUST be called with that lock released — already true here —
	// and never moved into the claim's critical section above.
	//
	// ctx here IS the caller's, deliberately and unlike Dial: a hangup is a
	// synchronous request whose result the caller is waiting for, so cancelling
	// the request may cancel the BYE transaction. What must never hang off a
	// request context is a call's LIFETIME, which is Dial's concern. The one
	// exception is sendInDialog's WAIT for the send-order token, which for a
	// BYE is detached from ctx (bounded by u.cfg.Timeout): the dialog is already
	// forgotten above, so a cancelled caller must not skip the BYE entirely.
	bye, res, err := u.sendInDialog(ctx, d, sip.BYE, func(bye *sip.Request) {
		if reason != nil {
			// A REAL Reason header, built by this package — never the exported
			// Hangup's agent-supplied free text.
			bye.AppendHeader(reason)
		}
	})
	if err != nil {
		// D152/F5: if the CALLER's ctx (not sipua's own internal
		// u.cfg.Timeout budget) is what ended the wait, session.UserAgent's
		// contract requires ctx.Err() be returned, with the dialog abandoned
		// — d.phase is already phaseDone, set unconditionally above, so
		// local state moves to terminated regardless of whether the peer
		// ever answered. session/destroy.go derives its ctx from
		// limits.shutdown_grace_period; without this check a grace-period
		// timeout was indistinguishable from a clean hangup and got counted
		// as a confirmed CallsTerminated.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if bye == nil {
			// Never built: buildInDialogRequest's own refusal (no dialog
			// INVITE). Returned exactly as before the seam; nothing was sent.
			return err
		}
		// Otherwise the caller's ctx is still live and it was sipua's own
		// per-request u.cfg.Timeout budget that elapsed with no response: a
		// BYE that draws no response still ends the dialog locally — §11.4's
		// grace period exists precisely because a peer may never 200 it.
		return nil
	}
	// session.UserAgent.Hangup's contract: nil ONLY on a 2xx; a non-2xx final
	// response returns an error naming the code (mirrors Unregister's D122
	// distinction, register.go). Not exercised by this task's own suite (the
	// test peer always 200s a BYE it receives), but implemented to match the
	// documented interface rather than left silently wrong.
	if !res.IsSuccess() {
		return fmt.Errorf("BYE was rejected: %d %s", res.StatusCode, res.Reason)
	}
	return nil
}

// targets reports whether req addresses this UA's identity — its AOR user or
// its bound Contact. This is the sipua half of D11's routing rule.
func (u *UA) targets(req *sip.Request) bool {
	want := aorUser(u.cfg.AOR)
	if want == "" {
		return true // no AOR user configured: this UA answers for its socket
	}
	if req.Recipient.User == want {
		return true
	}
	if to := req.To(); to != nil && to.Address.User == want {
		return true
	}
	return false
}

func aorUser(aor string) string {
	user, _, ok := splitSIPURI(aor)
	if !ok {
		return ""
	}
	return user
}

func headerURI(h sip.Header) string {
	if h == nil {
		return ""
	}
	return h.Value()
}

// sdpCodecNames lists the rtpmap encoding names in an SDP offer. P1 does NOT
// negotiate on them (§15's R14 split); they populate R14's incoming_call
// detail so an agent can see what the far end offered.
func sdpCodecNames(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\r\n") {
		if !strings.HasPrefix(line, "a=rtpmap:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "a=rtpmap:"))
		if len(fields) < 2 {
			continue
		}
		if name, _, found := strings.Cut(fields[1], "/"); found {
			out = append(out, name)
		}
	}
	return out
}

func defaultReason(status int) string {
	switch status {
	case 404:
		return "Not Found"
	case 480:
		return "Temporarily Unavailable"
	case 486:
		return "Busy Here"
	case 603:
		return "Decline"
	default:
		return "Rejected"
	}
}

func (u *UA) onBye(req *sip.Request, tx sip.ServerTransaction) {
	// RFC 3261 15.1.2: a BYE that matches no dialog (Call-ID and both tags) is
	// answered 481 and changes nothing (CF-130, CF-100). The lookup is a map
	// read, so the 200 below is still never delayed (D18).
	u.calls.mu.Lock()
	first := u.findDialogForRequestLocked(req)
	// CF-101: compare only. A BYE ends the dialog, so it never raises the remote
	// number (see remoteCSeqBelowLocked).
	outOfOrder := first != nil && remoteCSeqBelowLocked(first, req)
	u.calls.mu.Unlock()
	if first == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	if outOfOrder {
		respondOutOfOrder(req, tx)
		// Leave the arrival ticket, so no later gated request waits out
		// u.cfg.Timeout behind a request that applies nothing (C10).
		tk := u.arrivalEnter(req)
		u.calls.mu.Lock()
		arrivalLeaveLocked(tk)
		u.calls.mu.Unlock()
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	// Plan D18: a NOTIFY that reached the transport before this BYE is applied
	// first, however sipgo scheduled the two goroutines. Waits with no lock held.
	// After the 200, which onBye sends unconditionally, so the answer is never
	// delayed.
	tk := u.arrivalEnter(req)
	u.calls.mu.Lock()
	// Matched against the STORED callID, the same value handed upward in
	// DialResult and every UAEvent — so the dialog a BYE ends and the
	// ladder it ends cannot be two different things. Re-checked here: the
	// dialog may have been claimed since the lookup above.
	hit := u.findDialogForRequestLocked(req)
	var ml *mediaLoop
	var conn *net.UDPConn
	var earlyTx sip.ServerTransaction
	var earlyInv *sip.Request
	var earlyTag string
	if hit != nil {
		if hit.direction == session.Inbound && (hit.phase == phaseAdmitting || hit.phase == phaseRinging) {
			earlyTx, earlyInv, earlyTag = hit.serverTx, hit.invite, hit.toTag
		}
		hit.phase = phaseDone
		endControlOpLocked(hit)
		u.forgetLocked(hit.id)
		if hit.ringTimer != nil {
			hit.ringTimer.Stop()
		}
		ml, conn = hit.mediaLoop, hit.mediaConn
		hit.mediaLoop, hit.mediaConn = nil, nil
		// The peer ended a call we had a hangup pending on (the no-1xx wait or
		// the answering window), so the waiting Hangup is released now (nil)
		// rather than at cancelWaitCap. Cleared under this lock, so no other
		// resolver can resolve it again. We may still send something after this:
		// in the no-1xx wait, a later 1xx still arms and sends the deferred
		// CANCEL (harmless, now unawaited); after a 200, runDial's
		// media-negotiation-failure path does not re-check the phase, so its BYE
		// can still go out. runDial's answering-window BYE re-checks and is
		// skipped.
		if hit.cancelWait != nil {
			close(hit.cancelWait)
			hit.cancelWait = nil
		}
	}
	arrivalLeaveLocked(tk) // D18: in the SAME critical section that applied the teardown
	u.calls.mu.Unlock()
	// RFC 3261 15.1.2: an early BYE leaves the INVITE pending, and "The UAS MUST
	// still respond to any pending requests received for that dialog" (487
	// RECOMMENDED). Without it the held INVITE transaction (CF-096) would sit in
	// Proceeding, which has no timer, until UA.Close.
	if earlyTx != nil && earlyInv != nil {
		_ = earlyTx.Respond(inviteResponse(earlyInv, earlyTag, 487, "Request Terminated", nil))
	}
	if ml != nil {
		ml.stop()
	} else if conn != nil {
		_ = conn.Close()
	}
	if hit == nil {
		return
	}
	// Step 6/Correction 9: disarm this dialog's session timer alongside the
	// media loop. OUTSIDE u.calls.mu, for the same reason every other
	// stopSessionTimer call site is: refresher.Stop() waits for a goroutine
	// that may be inside refreshSession, which takes that lock.
	u.stopSessionTimer(hit)
	// A remote BYE is a fact session cannot learn any other way: it did not
	// initiate it. U14's dialog_ended kind carries the CAUSE; session maps
	// peer_bye onto §10.3's "remote_bye". sipua names no termination_reason
	// (Rule 18), exactly as it names no CallState.
	//
	// Direction is the DIALOG's direction, not the BYE's: a peer can BYE a call
	// we dialled as readily as one we answered, and session needs to know which
	// call ended, not which way the last message travelled.
	u.emit(session.UAEvent{
		Kind: session.UAEventDialogEnded, Cause: session.UACausePeerBYE,
		DialogID: hit.id, CallID: hit.callID, Direction: hit.direction,
		Code: 200, Reason: "OK", At: u.cfg.Clock.Now(),
	})
}

// onCancel is RFC 3261 §9.2's UAS half for the case sipgo routes to a
// srv-level handler: a CANCEL that matches no live INVITE ServerTx. Since
// CF-096 an inbound initial INVITE's transaction lives until its FSM ends it
// (onInvite is held), so a CANCEL for a pending INVITE normally meets the live
// transaction and its tx.OnCancel hook instead; this is the fallback (for
// example the transaction already ended, or the UA was closing). It draws TWO
// finals on TWO transactions — 200 on the CANCEL transaction itself (below,
// per §9.2), and, if a ringing dialog is still found, 487 Request Terminated on
// that INVITE's transaction via finishInboundCancel. The guard stays
// phaseRinging-only: an admitting dialog's onInvite is still running, so its
// transaction is live and a CANCEL for it reaches the hook.
//
// Concurrency mirrors finalRespond's claim-then-write (D3): d.phase, d.serverTx
// and d.invite are read/written under u.calls.mu everywhere else in this file.
// The claim (phaseDone, forgetLocked, stop the now-moot ring timer) runs in ONE
// critical section, and the wire writes + emit run after unlocking — exactly
// one of {487 here, 200 in Answer} can win a ringing dialog.
func (u *UA) onCancel(req *sip.Request, tx sip.ServerTransaction) {
	// Always 200 the CANCEL transaction itself.
	_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))

	u.calls.mu.Lock()
	d := u.findByCallIDLocked(callIDOf(req))
	if d == nil || d.phase != phaseRinging {
		u.calls.mu.Unlock()
		return // nothing pending to cancel (already answered/terminated) — RFC 3261 §9.2
	}
	d.phase = phaseDone
	serverTx, inv, toTag, id, callID := d.serverTx, d.invite, d.toTag, d.id, d.callID
	u.forgetLocked(d.id)
	if d.ringTimer != nil {
		d.ringTimer.Stop()
	}
	u.calls.mu.Unlock()

	u.finishInboundCancel(serverTx, inv, toTag, id, callID)
}

// finishInboundCancel is the one cancel finisher (Rule 18) for a CANCEL that
// won an inbound dialog, from the srv-level onCancel or the tx.OnCancel hook:
// it writes the INVITE's 487 and only then emits the cancelled dialog_ended, so
// the 487 precedes the event (and is in the call's capture). Called with NO
// lock held and never under the transaction's FSM lock.
func (u *UA) finishInboundCancel(serverTx sip.ServerTransaction, inv *sip.Request, toTag, id, callID string) {
	if serverTx != nil && inv != nil {
		_ = serverTx.Respond(inviteResponse(inv, toTag, 487, "Request Terminated", nil))
	}
	u.emit(session.UAEvent{
		Kind: session.UAEventDialogEnded, DialogID: id, CallID: callID,
		Direction: session.Inbound, Code: 487, Reason: "Request Terminated",
		Cause: session.UACauseCancelled, At: u.cfg.Clock.Now(),
	})
}
