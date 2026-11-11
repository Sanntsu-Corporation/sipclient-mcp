// Package peer provides a minimal in-process SIP peer for tests: a registrar
// that issues a digest challenge and then a configurable final response.
//
// Rule 16 reuse: digest verification is NOT reimplemented — it delegates to
// internal/sipengine/digest (ParseAuthorization, VerifyMD5Auth), the same two
// functions the vendored siptest.RunUAS uses. RunUAS itself is not reused:
// §7.1 grades it "reference only", it hardcodes its REGISTER response, it
// auto-answers INVITEs after a fixed 300 ms sleep, and it owns its own
// listener — all three conflict with what these tests must control.
//
// This is the canonical far-end peer for the whole wave (Rule 18): P1e Task
// 22's unexported loopback.Peer is deleted in favour of this package. This
// task implements the registrar half of the surface (Start, Addr, Methods,
// Count, LastExpires, LastVia, UnregisterCount, Close, SetBehaviour); Task 15
// implements the call half.
package peer

import (
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

const testNonce = "peer-static-nonce"

// Behaviour is the call-side knob set. Task 15 wires AnswerAfter,
// RejectStatus and SwallowBye; it is declared here so the type exists for
// loopback.PeerBehaviour, which is a plain alias for it.
type Behaviour struct {
	AnswerAfter  time.Duration
	RejectStatus int
	SwallowBye   bool
	// RingThenSilent makes the peer send 100 Trying and 180 Ringing and then
	// NO final response at all — modelling a peer that rings and then vanishes.
	// It is the far-end half of B1's outbound ring-reaper coverage: sipgo
	// v0.24.1 stops Timer B on the first provisional and has no Timer C, so
	// without a finite post-ring bound the caller's runDial would park forever
	// on a ring-then-silent peer. Gated ahead of the AnswerAfter select so no
	// final is ever written.
	RingThenSilent bool
	// HoldProvisionals, when non-nil, makes the peer send NOTHING for a fresh
	// INVITE — no 100 Trying, no 180 Ringing, and no digest challenge or 422
	// either — until the channel is closed, then carry on with the ordinary
	// flow. It is how a test holds an outbound dial in the "no provisional
	// yet" window RFC 3261 §9.1 forbids a CANCEL in, and then releases the
	// ringing deterministically rather than by sleep.
	HoldProvisionals <-chan struct{}
	// AnswerSDP, when set, supplies the EXACT SDP body this peer answers a 200 OK
	// with, replacing its fixed PCMU/AVP body at the precise point inviteFlow
	// would otherwise hardcode it. It receives the offer bytes the UA under test
	// sent and returns the answer body: a non-nil body is sent as the 200 OK's
	// SDP (Content-Type application/sdp); a nil return sends a 200 OK with NO SDP
	// body at all (the sdp_absent case). Unset (nil) keeps the historical
	// fixed-PCMU answer every non-negotiation call test relies on. This is the
	// only non-compliant-answer knob (the old OnInvite, which required a
	// sip.ServerTransaction this raw-socket peer never has, is gone).
	AnswerSDP func(offer []byte) []byte

	// StripTelephoneEvent makes the peer's 200 OK answer omit telephone-event
	// even though the offer carried it, modelling a gateway that speaks G.711
	// only. It is the far-end half of §10.7's dtmf_send(rfc2833) =>
	// not_supported acceptance (Task 22): without it there is no way to reach
	// that arm through the real negotiation path. When it is NOT set the
	// peer's answer MIRRORS the offer's telephone-event PT, so every other
	// test exercises the negotiated path.
	StripTelephoneEvent bool

	// OmitRegisterExpires drops the Expires header from the 200 answering a
	// REGISTER, so responseExpires' fallback is observable (Task 24).
	OmitRegisterExpires bool

	// RegisterContactExpires is the RAW value of the `expires` PARAMETER the
	// peer puts on the Contact it echoes back in a 200 REGISTER; "" (the
	// default) omits the parameter, which is what every pre-existing caller
	// gets. RFC 3261 §10.2.4 makes this parameter the REQUIRED, authoritative
	// form of a registrar's grant while the Expires header is optional, so
	// combining this with OmitRegisterExpires models the real-registrar shape
	// a peer that always emits an Expires header can never produce.
	//
	// Raw string, not int, so a test can also drive the malformed and negative
	// values a UA must refuse to turn into a timer.
	RegisterContactExpires string

	// Reject423MinExpires, when non-zero, answers any REGISTER whose Expires is
	// BELOW this value with "423 Interval Too Brief" carrying a Min-Expires of
	// this value, and answers one that meets it normally — RFC 3261 §10.2.8's
	// registrar side, and the knob that makes the UAC's retry observable.
	//
	// SAME SHAPE AS Reject422MinSE (a floor the retry must raise itself to
	// meet), WITHOUT ITS Call-ID BOOKKEEPING, and the difference is deliberate.
	// Reject422MinSE rejects the first INVITE on a Call-ID UNCONDITIONALLY
	// because peer.Dial's caller does not control the Session-Expires the UA
	// under test opens with, so a value gate might never fire. A REGISTER's
	// Expires comes straight from Config.ExpiresS, which every test sets, so the
	// value gate always fires on the first attempt and — unlike an
	// unconditional-first gate — also proves the retry actually RAISED the value
	// rather than merely being the second message.
	//
	// Expires: 0 IS EXEMPT. That is a de-registration (Unregister), and RFC 3261
	// §10.2.8's floor applies to registrations, not to their removal; a registrar
	// that 423s an unregistration would strand the binding.
	Reject423MinExpires int

	// SuppressRegisterContactEcho stops the 200 REGISTER from echoing the UA's
	// OWN Contact back, so the response lists only ExtraRegisterContacts —
	// a registrar that rewrote the binding (NAT) or reports someone else's,
	// leaving nothing in the response that identifies our binding.
	SuppressRegisterContactEcho bool

	// ExtraRegisterContacts are additional Contact header VALUES (e.g.
	// "<sip:alice@10.0.0.9:5060>;expires=30") the 200 REGISTER carries AHEAD
	// of the UA's own echoed binding — other devices registered against the
	// same AOR, which a registrar MAY list in full. A UA that reads whichever
	// Contact comes first instead of matching its OWN binding picks these up.
	ExtraRegisterContacts []string

	// ExtraRegisterContactsAfter are the same thing listed AFTER the UA's own
	// echoed binding, so ours comes FIRST. Both orderings are needed: a test
	// using only ExtraRegisterContacts cannot fail against a UA that reads the
	// LAST Contact, only against one that reads the first.
	ExtraRegisterContactsAfter []string

	// Reject422MinSE, when non-zero, rejects the FIRST INVITE with
	// "422 Session Interval Too Small" carrying a Min-SE of this value,
	// UNCONDITIONALLY — even one that already carries a sufficient
	// Session-Expires — and only accepts a retry once its Session-Expires
	// meets that floor (Task 27).
	//
	// THE RETRY MUST REUSE THE SAME CALL-ID: this peer recognises "this is
	// the retry" (as opposed to a fresh, independent dial) by Call-ID, keyed
	// in reject422Sent. A retry that mints a fresh Call-ID — which
	// peer.Dial/DialWithHeaders always do — looks like a brand-new first
	// attempt to this peer and draws the SAME unconditional 422 again rather
	// than being accepted, which would hang a test waiting on a 200 that
	// never arrives. Drive both the first attempt and the retry over one raw
	// socket with the SAME Call-ID and an incremented CSeq (see peer_test.go's
	// TestReject422MinSEForcesARetryOnTheSameCallID for the exact shape) until
	// Task 27's own retry logic exists to do this for real.
	Reject422MinSE int

	// ProxyAuthInvite makes the digest gate on the INVITE path challenge as a
	// PROXY — 407 Proxy Authentication Required with a Proxy-Authenticate header,
	// and the credential read back from Proxy-Authorization — instead of as the
	// UAS (401 + WWW-Authenticate). It models a proxy sitting in front of the
	// callee, which is the ONLY shape under which a UA ever emits
	// Proxy-Authorization at all, and therefore the only shape in which
	// retry422's Proxy-Authorization strip is observable on the wire.
	//
	// REGISTRAR BEHAVIOUR IS UNTOUCHED: respondRegister keeps its 401, so one
	// Config can drive a 407 INVITE and a 401 REGISTER at the same time.
	ProxyAuthInvite bool

	// OneTimeRegisterNonce makes the registrar mint a FRESH nonce every time it
	// ACCEPTS a REGISTER, so the nonce a UA cached from its last challenge is
	// already dead by the next cycle. It is the only registrar shape in which a
	// preemptively-presented cached challenge is ever rejected, and therefore the
	// only way to exercise P4-D07's fallback path (challenge, retry ONCE,
	// re-cache — never a loop).
	//
	// It does NOT affect the INVITE path, which keeps the fixed testNonce.
	OneTimeRegisterNonce bool

	// AnswerSessionExpires is the exact Session-Expires value the peer's 200 OK
	// to an INVITE (or an in-dialog UPDATE/re-INVITE refresh) carries; ""
	// omits the header entirely (Tasks 27, 29, 30).
	AnswerSessionExpires string

	// RefreshSessionExpires makes this peer GRANT A DIFFERENT interval and/or
	// refresher role on each successive in-dialog refresh it answers, instead
	// of echoing AnswerSessionExpires forever.
	//
	// Each element is an exact Session-Expires header value —
	// "delta-seconds[;refresher=uac|uas]" per RFC 4028 §4 — so one entry
	// carries BOTH the granted interval and the granted role. The Nth refresh
	// this peer answers with a 200 gets element N-1; once the slice is
	// exhausted the LAST element is granted for every subsequent refresh. An
	// element of "" omits the header entirely on that refresh. Only refreshes
	// that draw a 200 consume an element: a swallowed (SwallowUpdate) or
	// rejected (RejectUpdateStatus) refresh grants nothing, so it advances
	// nothing.
	//
	// Nil/empty (the default) keeps the historical behaviour every pre-existing
	// caller gets: every refresh is answered with AnswerSessionExpires. That
	// behaviour is exactly the blindness this field exists to lift — with the
	// granted interval permanently equal to the current one, a UA's entire
	// session-timer re-base path can be deleted with every test still green.
	RefreshSessionExpires []string

	// AnswerAllow is the exact Allow value the peer's 200 OK carries, which is
	// what decides UPDATE-vs-re-INVITE refresh (Task 29).
	AnswerAllow string

	// RejectUpdateStatus, when non-zero, answers every in-dialog UPDATE, or an
	// in-dialog re-INVITE used as a session-timer refresh, with that status
	// instead of 200 (Task 29's rejected-refresh case).
	RejectUpdateStatus int

	// RejectUpdateMinSE, when non-zero, adds a Min-SE header with this value to the
	// RejectUpdateStatus response (a 422 to a session refresh, RFC 4028 6).
	RejectUpdateMinSE int

	// SwallowUpdate answers the INVITE and then silently DROPS every in-dialog
	// UPDATE and re-INVITE refresh, so the transaction runs its full budget
	// with no final response — §11.3.1 case 2 (Task 29). Same species of
	// switch as the existing SwallowBye.
	SwallowUpdate bool

	// RejectInfoStatus, when non-zero, answers an in-dialog INFO with that
	// status instead of 200 — Task 15's own regression coverage for
	// sendDTMFInfo's 405/501/415 => not_supported mapping (correction 7) and
	// its mid-sequence partial-send accounting. Same species of switch as
	// RejectStatus/RejectUpdateStatus.
	RejectInfoStatus int

	// EnforceNonceCountMonotonic makes this peer's REGISTER challenge behave
	// like a real registrar tracking RFC 7616 §3.4.3 nonce-count: an
	// Authorization whose `nc=` is not STRICTLY GREATER than the last one this
	// peer accepted is rejected as a replay (401, same challenge, same
	// never-rotated nonce) rather than accepted. It is what makes Phase 4 W1
	// M3's Inputs §1 acceptance criterion — a UA whose nc tracking is broken
	// (e.g. always sending 1) actually fails against this peer, rather than
	// merely being observed to send the wrong value.
	//
	// DEFAULT OFF, OPT IN PER TEST. The check tracks the last ACCEPTED nc
	// PER PEER INSTANCE, not per caller/credential — sufficient for this
	// project's one-peer-one-UA-under-test convention, but not a general
	// multi-client registrar model. Enforcing it unconditionally would fail
	// any test driving more than one UA against the same peer, which is not
	// this field's job to prevent. M7a inherits this default (off).
	EnforceNonceCountMonotonic bool

	// RejectRegisterCredentialAfterNAccepted makes this registrar turn hostile
	// to CREDENTIALED REGISTERs once it has ACCEPTED this many with a 200: any
	// FURTHER REGISTER carrying a non-empty Authorization header draws
	// "403 Forbidden" — no challenge, no acceptance — REGARDLESS of whether that
	// credential would otherwise verify. A REGISTER carrying NO Authorization
	// header is unaffected and still draws the ordinary 401 challenge (the
	// existing digest gate below already does this: credentialOK returns false
	// on a missing header). 0 (the default) disables the behaviour.
	//
	// IT MODELS A REGISTRAR THAT REJECTS AN IDENTITY OUTRIGHT (Rule 13 Cycle 3
	// finding I1) — a realistic example is an SBC/Kamailio nonce-replay guard —
	// rather than either accepting a credential or re-challenging it. It is the
	// only registrar shape that can exercise sendRegister's cache-invalidation
	// path (register.go's forgetChallenge): P4-D07's preemptive-credential cache
	// is written on 200 and, before that fix, was never cleared, so a registrar
	// answering the cached credential with anything other than 200/401/407 left
	// the cache presenting the same dead credential forever.
	RejectRegisterCredentialAfterNAccepted int

	// ReferStatus, when non-zero, answers an in-dialog REFER (call transfer,
	// RFC 3515) with that status — 202 to accept it, a 3xx-6xx to reject it.
	// With neither this nor SwallowRefer set, REFER keeps the pre-transfer
	// default: 405, like every other method this double does not implement.
	ReferStatus int

	// ReferReason, when non-empty, overrides ReferStatus's default
	// reasonPhrase text on the REFER response — for tests that need a
	// specific reason phrase (e.g. one long enough to exercise a length cap)
	// rather than the generic per-status-code default.
	ReferReason string

	// SwallowRefer answers nothing to an in-dialog REFER, so the UA's REFER
	// transaction runs its full budget with no final response. Same species of
	// switch as SwallowBye/SwallowUpdate.
	SwallowRefer bool
}

// AnswerWithBody returns an AnswerSDP hook that answers 200 OK carrying exactly
// body, ignoring the offer — the peer names whatever codec/profile body encodes,
// driving answer_codec_not_offered (an unoffered codec) or a downgraded RTP/AVP
// answer to an RTP/SAVP offer.
func AnswerWithBody(body []byte) func(offer []byte) []byte {
	return func([]byte) []byte { return body }
}

// AnswerNoBody returns an AnswerSDP hook that answers 200 OK with NO SDP body at
// all (sdp_absent). The nil return is the signal inviteFlow turns into a
// body-less 200 OK.
func AnswerNoBody() func(offer []byte) []byte {
	return func([]byte) []byte { return nil }
}

// AnswerRaw returns an AnswerSDP hook that answers 200 OK carrying garbage that
// is not parseable SDP (sdp_unparseable). Distinct from AnswerNoBody: the body
// is present (Content-Type application/sdp) but unparseable.
func AnswerRaw(garbage []byte) func(offer []byte) []byte {
	return func([]byte) []byte { return garbage }
}

// Config configures a stub Peer.
type Config struct {
	Addr           string // "127.0.0.1:0" for an ephemeral port; NEVER a wildcard
	Realm          string // digest realm; "" defaults to "sipclient-test"
	AuthUser       string
	AuthPass       string
	RegisterStatus int // final status after successful digest; 0 means 200
	RegisterReason string
	// RegisterExpires overrides the Expires the peer GRANTS in a 200
	// REGISTER response; 0 means echo the request's own Expires value
	// unchanged. Lets a test grant a different expiry than was requested, so
	// an assertion on the result must read the response rather than restate
	// a constant both sides happen to share.
	RegisterExpires int
	Behaviour       Behaviour
	// TLSCert, when set, additionally binds a TCP listener wrapped in TLS
	// serving this certificate (Phase 4 W1 M7a §2) — additive/opt-in: every
	// existing caller that leaves this nil takes a strictly
	// zero-behavior-change path (no TCP/TLS listener is bound at all), the
	// strongest available protection against regressing the 37 existing
	// importers that only ever use the UDP transport. Different tests set
	// different certificates (via internal/testutil/tlsca) to drive the
	// C1 acceptance matrix — matching, unrelated-CA, SAN-mismatch, expired,
	// not-yet-valid.
	TLSCert *tls.Certificate
}

// SetBehaviour installs b as the peer's call-side behaviour for subsequent
// requests (Task 15).
func (p *Peer) SetBehaviour(b Behaviour) {
	p.mu.Lock()
	p.cfg.Behaviour = b
	p.mu.Unlock()
}

// SetRegisterStatus changes the final status the peer returns for subsequent
// REGISTERs once any digest challenge is satisfied. It lets a single peer
// accept an initial REGISTER and then reject a later one (e.g. the
// Expires: 0 de-registration) — needed to test D122's contract that a
// non-2xx final response to Unregister's REGISTER surfaces as an error
// naming the code, distinct from a rejection of the initial registration.
func (p *Peer) SetRegisterStatus(status int, reason string) {
	p.mu.Lock()
	p.cfg.RegisterStatus = status
	p.cfg.RegisterReason = reason
	p.mu.Unlock()
}

// Peer is a minimal in-process SIP registrar and call peer.
type Peer struct {
	cfg         Config
	conn        net.PacketConn
	parser      *sip.Parser
	mu          sync.Mutex
	methods     []string
	expires     int
	via         string
	vias        []string
	unregisters int
	done        chan struct{}

	// codes, lastFinalStatus, lastFinalToTag and lastFinalBody track SIP
	// RESPONSES the peer receives — i.e. replies to requests THIS peer
	// originated (Dial). Requests the peer itself receives (REGISTER,
	// INVITE, BYE, ...) go through methods/record, a separate channel; a
	// peer that both dials and is dialled in the same test would otherwise
	// have no way to tell which direction a message belongs to.
	codes           []int
	lastFinalStatus int
	// lastFinalToTag and lastFinalBody are the wire-observed To-tag and body
	// of the last FINAL (>=200) response received, for Task 15's
	// Rule-10-cycle-1 regression coverage (F2: the Answer/Hangup To-tag race;
	// F4: SDP synthesis wiring) — captured off the actual bytes the peer
	// received, not off sipua's internal dialog state.
	lastFinalToTag string
	lastFinalBody  []byte

	// provToTags are the wire-observed To-tags of the provisional (101-199)
	// responses received, in arrival order: a 100 is always skipped and a
	// provisional without a To tag is dropped (see ProvisionalToTags).
	provToTags []string

	// lastByeToTag is the wire-observed To-tag of the last BYE the peer
	// received as a UAS (F2: compared against lastFinalToTag to prove the
	// BYE reuses the 200 OK's To-tag rather than a fabricated one).
	lastByeToTag string

	// lastBye is the last BYE the peer received as a UAS, kept in full (not
	// just its To-tag) so tests can inspect its From/To orientation directly
	// — D1's UAS-orientation regression coverage needs the actual From/To
	// headers, not one extracted tag.
	lastBye *sip.Request

	// lastByeCSeq and answeredInviteCSeq are the wire-observed CSeq sequence
	// numbers of, respectively, the last BYE the peer received and the INVITE
	// it last answered with a 200 OK — both read straight off the bytes on the
	// wire. §14.5's stale-BYE-CSeq regression compares them: a BYE ending a
	// digest-challenged (CSeq-advanced) dialog must carry a CSeq strictly
	// higher than the INVITE it ends (RFC 3261 §12.2.1.1), which a hardcoded
	// BYE CSeq cannot guarantee.
	lastByeCSeq        uint32
	answeredInviteCSeq uint32

	// lastInvite/lastOK/lastFrom remember the most recent call the peer
	// ACCEPTED AS UAS (an INVITE the UA under test sent it), so SendBye can
	// build a BYE via siptest.BuildByeFromInvite without a dialog ID the peer
	// never saw — the UA's dialog handle is sipua's own internal random hex,
	// and onBye on the UA side matches an incoming BYE by Call-ID, not by
	// handle.
	lastInvite *sip.Request
	lastOK     *sip.Response
	lastFrom   net.Addr

	// lastSentInvite is the INVITE the peer most recently sent as UAC
	// (Dial) — distinct from lastInvite, which is a call the peer accepted
	// AS UAS. Kept so inbound-flow tests (the UA under test is the callee)
	// can read back the identity/tag the peer put on its own From header:
	// siptest.BuildInvite mints a fresh random tag per call
	// (sip.GenerateTagN), so no test can hardcode it.
	lastSentInvite *sip.Request

	// lastSentInviteAddr is the wire destination Dial sent lastSentInvite to,
	// kept so SendCancel can address the CANCEL at the exact same socket
	// without re-deriving it from a URI a second time (D3).
	lastSentInviteAddr net.Addr

	// inboundInvites tracks every inbound INVITE the peer has received AS
	// UAS, keyed by its SIP Call-ID (unlike sipua's internal dialog handle,
	// the Call-ID is genuinely observable by the peer off the wire — see
	// SendFinal). Entries are added on arrival and never removed: a test
	// process is short-lived and this is a bounded per-test fixture, not a
	// long-lived server structure.
	inboundInvites map[string]*inboundInvite

	// lastInboundFinalStatus is the status of the last FINAL response THIS
	// PEER SENT for an inbound INVITE it received as UAS — distinct from
	// lastFinalStatus, which is a response this peer RECEIVED as UAC to its
	// own Dial.
	lastInboundFinalStatus int

	// inviteFinalCode/cancelFinalCode are the wire-observed status of the
	// last FINAL (>=200) response THIS PEER RECEIVED AS UAC to, respectively,
	// its own Dial INVITE and its own SendCancel — tracked SEPARATELY from
	// lastFinalStatus (D3): a CANCELled inbound call produces TWO distinct
	// final responses on the SAME Call-ID/dialog (487 on the INVITE
	// transaction, 200 on the CANCEL transaction), which a single
	// last-final-wins field cannot tell apart. recordResponse routes each
	// final by its CSeq method, the wire-level signal that distinguishes the
	// two transactions.
	inviteFinalCode int
	cancelFinalCode int

	// lastReqBody/lastReqHeader/lastResHeader/lastResStatus/reqCSeqs back the
	// P3 accessor surface (Task 15's ownership note): every request/response
	// method+status this peer has seen, so a later task can assert on the
	// EXACT body/header a specific method (and, for a response, status) drew
	// without adding a ninth ad hoc field of its own.
	lastReqBody    map[string]string
	lastReqHeader  map[string]string
	lastResHeader  map[string]string
	lastResStatus  map[string]int
	reqCSeqs       []MethodCSeq
	maxNonceCount  int
	crlfKeepalives int
	// lastAcceptedNc is the largest `nc=` value this peer has ACCEPTED,
	// tracked only when Behaviour.EnforceNonceCountMonotonic is set — unlike
	// maxNonceCount (which records every nc= seen, accepted or not), this
	// gates whether the NEXT one is accepted at all (see acceptNonceCount).
	lastAcceptedNc int
	// registerAccepts counts the REGISTERs this peer has ANSWERED WITH 200,
	// tracked unconditionally (same posture as maxNonceCount) but only READ
	// under Behaviour.RejectRegisterCredentialAfterNAccepted.
	registerAccepts int
	// regNonce is the nonce this peer's REGISTER challenges currently name, and
	// regNonceSeq is what makes each rotation distinct. Empty until first read;
	// registerNonce() seeds it with testNonce, so a peer without
	// Behaviour.OneTimeRegisterNonce behaves exactly as it always has.
	regNonce    string
	regNonceSeq int
	// pongCount counts inbound datagrams whose ENTIRE payload is a single
	// CRLF — D22's RFC 5626 §3.5.1 pong, sent by the UA under test in answer
	// to SendCRLFPing below.
	pongCount int
	stopOnce  sync.Once

	// callIDs is the Call-ID of EVERY request received, in arrival order, keyed
	// by method — the Call-ID counterpart of reqCSeqs. lastReqHeader keeps only
	// the most recent value per method, so it cannot express "all of these
	// carried the SAME Call-ID", which is what RFC 3261 §10.2 requires of one
	// registration's REGISTERs.
	callIDs map[string][]string

	// answeredToTag maps a Call-ID this peer has answered (as UAS) with a 200
	// OK to the To-tag it minted doing so. It is how inviteFlow tells an
	// in-dialog session-refresh re-INVITE (Task 29) — which carries this
	// SAME To-tag back — apart from a fresh dial, which never carries one.
	// Unlike inboundInvites, entries here are never overwritten by a later
	// INVITE on the same Call-ID: a re-INVITE that itself gets answered simply
	// reaffirms the same tag.
	answeredToTag map[string]string

	// reject422Sent marks, by Call-ID, that this peer has already sent the
	// MANDATORY first Reject422MinSE rejection for that dialog (Task 27) —
	// so a SECOND INVITE on the same Call-ID is recognised as the retry, not
	// re-rejected unconditionally.
	reject422Sent map[string]bool

	// toCallerCSeq is the per-dialog CSeq counter for in-dialog requests THIS
	// PEER ORIGINATES toward the caller, keyed on Call-ID. Shared by
	// SendUPDATEToCaller and SendReInviteToCaller (D23, Phase 4 W2) — one
	// counter, not one per helper, because RFC 3261 12.2.1.1 sequences a
	// dialog's requests as a single stream regardless of method: two
	// per-helper counters would let an UPDATE and a re-INVITE both claim the
	// same number.
	toCallerCSeq map[string]uint32

	// sentReInvites records the in-dialog INVITEs (with a body) this peer sent
	// through SendReInvite, SendReInviteToCaller and SendToCaller, keyed by
	// Call-ID and CSeq number, with the address each went to, so ackInvite2xx can
	// ACK their 2xx as any RFC UAC must (CF-208: the UA now retransmits an
	// un-ACKed 2xx to a re-INVITE). An offerless re-INVITE is not recorded: its
	// ACK must carry the answer, which is the test's job.
	sentReInvites map[string]sentReInvite

	// refreshesGranted counts the in-dialog refreshes this peer has ANSWERED
	// WITH A 200, and is the index into Behaviour.RefreshSessionExpires. It is
	// deliberately per-Peer rather than per-dialog: it walks the scripted
	// sequence in the order the peer granted the refreshes, which is what a
	// test scripting "grant 900, then 600, then 600 forever" means. It counts
	// across BOTH refresh arms (the UPDATE arm in respond and the in-dialog
	// re-INVITE arm in inviteFlow), since either method can carry the refresh.
	refreshesGranted int

	// tlsListener is the TCP listener wrapped in tls.NewListener, bound only
	// when Config.TLSCert is set (M7a §2 point 3). nil means no TLS listener
	// was ever bound — the UDP-only path every pre-existing caller takes.
	tlsListener net.Listener

	// streamMu guards streamConns. It is DELIBERATELY SEPARATE from p.mu:
	// several existing call sites (e.g. inviteFlow's 200 OK path) call
	// write()/send() while ALREADY HOLDING p.mu, and send() must be able to
	// look a stream connection up without re-entering p.mu (sync.Mutex is
	// not reentrant).
	streamMu sync.Mutex
	// streamConns maps a connected TCP/TLS peer's remote address (addr.String())
	// to the net.Conn accepted for it — the per-connection half of the write
	// seam (M7a §2 point 4): send() resolves "the connection for this peer
	// address" here first, falling back to p.conn.WriteTo (UDP) when no entry
	// exists, which is always true for every UDP-only test.
	streamConns map[string]net.Conn
}

// inboundInvite is one inbound INVITE the peer has received as UAS, kept so
// SendFinal can answer it later by Call-ID.
type inboundInvite struct {
	req  *sip.Request
	from net.Addr
}

// peerSDPBody is the fixed offer/answer body this test peer uses on both
// sides of a call it participates in (Dial's offer and inviteFlow's answer).
// It is a test fixture, not sipua's own SDP: sipua.FixedPCMUSDP is what a UA
// under test emits, parameterised on ITS bound address (D9d); this peer is
// the OTHER end of the wire and its own address is loopback by construction
// (Config.Addr is always "127.0.0.1:0" in every consumer), so a fixed
// loopback body here carries none of the concrete-bind concern
// sipua.FixedPCMUSDP exists to satisfy.
const peerSDPBody = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=peer\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
