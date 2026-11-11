package peer

// peer_observe.go — the READ-BACK SURFACE tests assert against: what did this
// peer receive, what did it answer, and the Wait* helpers that block until it
// has.
//
// Split out of peer.go by Phase 4 W2 (P4-W2-13); pure move. NOTHING HERE BUILDS
// OR SENDS A MESSAGE — every declaration takes p.mu, copies state out and
// returns it. That is the boundary: this file grows when a test needs a new
// question answered, and it can grow without touching a single line of protocol
// behaviour. It is also why the ~430 lines of one-line accessors are not padding
// one of the handler files.

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// AckBeforeBye reports whether the peer observed an ACK strictly before the BYE
// it received as UAS — the §11.2.1 ordering guarantee. serve() already records
// every inbound request method (record()) before dispatch, so ACK and BYE are
// both in Methods().
func (p *Peer) AckBeforeBye() bool {
	ms := p.Methods()
	ackAt, byeAt := -1, -1
	for i, m := range ms {
		if m == "ACK" && ackAt < 0 {
			ackAt = i
		}
		if m == "BYE" && byeAt < 0 {
			byeAt = i
		}
	}
	return ackAt >= 0 && byeAt >= 0 && ackAt < byeAt
}

// Methods reports request methods received, in arrival order.
func (p *Peer) Methods() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.methods))
	copy(out, p.methods)
	return out
}

// Count reports how many requests the peer received for method.
func (p *Peer) Count(method string) int {
	n := 0
	for _, m := range p.Methods() {
		if m == method {
			n++
		}
	}
	return n
}

// LastExpires is the Expires value of the last REGISTER received, or -1 if
// none has arrived yet.
func (p *Peer) LastExpires() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.expires
}

// LastVia is the Via sent-by of the last request received.
func (p *Peer) LastVia() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.via
}

// FirstVia is the Via sent-by of the FIRST request the peer received, or ""
// if none has arrived yet.
//
// D124: the Via is pinned in two independent places — engineConfig().
// LocalAddr (the FIRST REGISTER's Via, via siptest.BuildRegister) and Task
// 13's siptest.NewClient LocalAddr (the digest RETRY's Via, via
// ClientRequestAddVia). LastVia alone cannot catch a regression in the first
// place, because DoRequestWithDigest's retry always overwrites it — proven:
// mutating only engineConfig().LocalAddr still leaves LastVia() equal to
// BoundAddr(). Tests must assert both.
func (p *Peer) FirstVia() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.vias) == 0 {
		return ""
	}
	return p.vias[0]
}

// UnregisterCount counts REGISTERs carrying Expires: 0.
func (p *Peer) UnregisterCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unregisters
}

// LastRequestBody returns the body of the most recent request of the given
// method this peer received, or "" if it received none.
func (p *Peer) LastRequestBody(method string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastReqBody[method]
}

// LastRequestHeader returns the named header off the most recent request of the
// given method this peer received, or "".
func (p *Peer) LastRequestHeader(method, header string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastReqHeader[reqKey(method, header)]
}

// LastResponseHeader returns the named header off the most recent response this
// peer RECEIVED for the given request method with the given status code. A
// status of 0 means "the latest response to that method, whatever its code" —
// which is what a caller wants when only one response is possible. Both keys are
// needed because a 422 and a 200 can answer the same INVITE (Task 28).
//
// It only sees FINAL (status >= 200) responses, matching recordResponse's own
// gate (see LastFinalStatus's pre-existing field, which this mirrors) — a 100
// or 180's headers are never recorded here, so asking for one always returns
// "".
func (p *Peer) LastResponseHeader(method string, status int, header string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if status == 0 {
		status = p.lastResStatus[method]
	}
	return p.lastResHeader[resKey(method, status, header)]
}

// LastResponseStatus is the status code of the most recent FINAL (>= 200)
// response this peer received for the given request method, or 0 if it has
// seen none — a provisional like 180 never sets this (see LastResponseHeader).
func (p *Peer) LastResponseStatus(method string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastResStatus[method]
}

// MethodCSeq is one received request's method and CSeq sequence number.
type MethodCSeq struct {
	Method string
	CSeq   uint32
}

// RequestCSeqs returns every request this peer received, in ARRIVAL ORDER, with
// its CSeq. It is what lets a test assert RFC 3261 §12.2.1.1's
// strictly-increasing rule ACROSS methods on one dialog (INFO, then UPDATE, then
// BYE), which the per-method view below cannot see.
func (p *Peer) RequestCSeqs() []MethodCSeq {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]MethodCSeq(nil), p.reqCSeqs...)
}

// CSeqs returns the CSeq sequence numbers of every request of one method, in
// arrival order (Task 25's R10 assertion).
func (p *Peer) CSeqs(method string) []uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []uint32
	for _, mc := range p.reqCSeqs {
		if mc.Method == method {
			out = append(out, mc.CSeq)
		}
	}
	return out
}

// CallIDs returns the Call-ID of every request of one method the peer received,
// in ARRIVAL ORDER — the Call-ID counterpart of CSeqs.
//
// It exists because RFC 3261 §10.2 requires every REGISTER belonging to ONE
// registration to carry a SINGLE Call-ID, and no other accessor can express
// that: LastRequestHeader keeps only the most recent value per method, so a UA
// that minted a fresh Call-ID per refresh — which is what siptest.BuildRegister
// does unless the UA overrides it — is indistinguishable through it from one
// that reused a stable one.
func (p *Peer) CallIDs(method string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.callIDs[method]...)
}

// CSeqMonotonic reports whether one method's CSeqs strictly increased.
func (p *Peer) CSeqMonotonic(method string) bool {
	seqs := p.CSeqs(method)
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			return false
		}
	}
	return true
}

// MaxNonceCount is the largest `nc=` value seen on any Authorization header,
// decoded from its hex form — R10 requires it to increment across refresh
// cycles (Task 25).
func (p *Peer) MaxNonceCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxNonceCount
}

// CRLFKeepalives counts datagrams whose ENTIRE payload is a double CRLF, i.e.
// RFC 5626 §3.5.1 keep-alive pings rather than SIP messages (Task 26).
func (p *Peer) CRLFKeepalives() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.crlfKeepalives
}

// PongCount is the number of D22 single-CRLF pongs this peer has received in
// answer to SendCRLFPing.
func (p *Peer) PongCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pongCount
}

// ResponseCodes reports the status codes of every SIP response the peer has
// received, in arrival order (both provisional and final).
func (p *Peer) ResponseCodes() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]int, len(p.codes))
	copy(out, p.codes)
	return out
}

// LastFinalStatus is the status code of the last FINAL (>=200) response the
// peer received, or 0 if none has arrived yet.
func (p *Peer) LastFinalStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastFinalStatus
}

// LastFinalToTag is the To-tag of the last FINAL (>=200) response the peer
// received as a UAC, read directly off the wire message, or "" if none has
// arrived yet.
func (p *Peer) LastFinalToTag() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastFinalToTag
}

// ProvisionalToTags are the To-tags of the provisional (101-199) responses the
// peer received as a UAC, in arrival order, read off the wire message. A 100 is
// always skipped and a provisional without a To tag is dropped, so the slice is
// not index-aligned with ResponseCodes().
func (p *Peer) ProvisionalToTags() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.provToTags...)
}

// LastFinalResponseBody is the body of the last FINAL (>=200) response the
// peer received as a UAC, or nil if none has arrived yet.
func (p *Peer) LastFinalResponseBody() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastFinalBody
}

// LastByeToTag is the To-tag of the last BYE the peer received as a UAS,
// read directly off the wire message, or "" if none has arrived yet.
func (p *Peer) LastByeToTag() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastByeToTag
}

// LastByeCSeq is the CSeq sequence number of the last BYE the peer received as
// a UAS, read directly off the wire message, or 0 if none has arrived yet.
func (p *Peer) LastByeCSeq() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastByeCSeq
}

// LastBye is the last BYE the peer received as a UAS, read directly off the
// wire message, or nil if none has arrived yet.
func (p *Peer) LastBye() *sip.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastBye
}

// LastSentInvite is the INVITE the peer most recently sent via Dial, read
// back from what was actually built and written to the wire, or nil if it
// has not dialled yet.
func (p *Peer) LastSentInvite() *sip.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSentInvite
}

// AnsweredInviteCSeq is the CSeq sequence number of the INVITE the peer last
// answered with a 200 OK as a UAS, read directly off the wire message, or 0 if
// none has been answered yet.
func (p *Peer) AnsweredInviteCSeq() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.answeredInviteCSeq
}

// LastInviteBody is the body of the most recent INVITE the peer accepted as
// UAS (RejectStatus == 0), or nil if none has been accepted yet.
func (p *Peer) LastInviteBody() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastInvite == nil {
		return nil
	}
	return p.lastInvite.Body()
}

// InviteFinalCode is the status of the last FINAL (>=200) response this peer
// received AS UAC to its own Dial INVITE transaction specifically — 0 if none
// has arrived yet. See the inviteFinalCode field comment (D3).
func (p *Peer) InviteFinalCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inviteFinalCode
}

// CancelFinalCode is the status of the last FINAL (>=200) response this peer
// received AS UAC to its own SendCancel transaction specifically — 0 if none
// has arrived yet. See the cancelFinalCode field comment (D3).
func (p *Peer) CancelFinalCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cancelFinalCode
}

// WaitForInviteFinal blocks, polling with a bounded deadline, until the peer
// observes a final on the INVITE transaction it dialed (as opposed to a
// later CANCEL on the same dialog), returning its status code (D3).
func (p *Peer) WaitForInviteFinal(t *testing.T, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if code := p.InviteFinalCode(); code != 0 {
			return code
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer.WaitForInviteFinal: no INVITE-transaction final within %s; codes observed: %v", d, p.ResponseCodes())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// WaitForCancelFinal blocks, polling with a bounded deadline, until the peer
// observes a final on its own CANCEL transaction, returning its status code
// (D3).
func (p *Peer) WaitForCancelFinal(t *testing.T, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if code := p.CancelFinalCode(); code != 0 {
			return code
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer.WaitForCancelFinal: no CANCEL-transaction final within %s; codes observed: %v", d, p.ResponseCodes())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// WaitForFinalAfter blocks, polling with a bounded deadline, until the
// peer's count of FINAL (>=200) responses received as UAC exceeds before,
// then returns the status of the response that pushed the count past it.
// Needed by D2's re-INVITE test: the peer already holds an earlier INVITE
// final (the original 200 OK) by the time it sends the re-INVITE, so
// LastFinalStatus/InviteFinalCode alone cannot tell "still the old value"
// from "the re-INVITE's own response arrived and happens to match".
func (p *Peer) WaitForFinalAfter(t *testing.T, before int, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if p.FinalResponseCount() > before {
			return p.LastFinalStatus()
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer.WaitForFinalAfter: no new final response within %s; codes observed: %v", d, p.ResponseCodes())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// LastViaHostPort is the Via sent-by of the last request received, under the
// contract §2.10 name. It is a thin alias over LastVia (Rule 16/18: one
// implementation) — the two names exist because the interface contract
// settled on LastViaHostPort while the field-level accessor above predates
// it.
func (p *Peer) LastViaHostPort() string { return p.LastVia() }

// InviteCount reports how many INVITEs the peer has received as UAS.
func (p *Peer) InviteCount() int { return p.Count(string(sip.INVITE)) }

// ByeCount reports how many BYEs the peer has received as UAS.
func (p *Peer) ByeCount() int { return p.Count(string(sip.BYE)) }

// FinalResponseCount reports how many FINAL (>=200) responses the peer has
// received AS UAC, i.e. replies to requests this peer itself originated via
// Dial. Distinct from InviteCount/ByeCount, which count requests the peer
// received as UAS.
func (p *Peer) FinalResponseCount() int {
	n := 0
	for _, c := range p.ResponseCodes() {
		if c >= 200 {
			n++
		}
	}
	return n
}

// LastInboundFinalStatus is the status of the last FINAL response THIS PEER
// SENT for an inbound INVITE it received as UAS (a 200 OK it answered with,
// or a rejection status from Behaviour.RejectStatus / SendFinal) — 0 if the
// peer has not yet sent one. Distinct from LastFinalStatus, which is a
// response the peer RECEIVED as UAC to its own Dial.
func (p *Peer) LastInboundFinalStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastInboundFinalStatus
}

// WaitForBye blocks, polling with a bounded deadline, until the peer has
// received at least one BYE, or fails the test naming what it observed
// instead. It never blocks unboundedly: the Go test timeout is not the only
// backstop here, d is.
func (p *Peer) WaitForBye(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if p.ByeCount() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer.WaitForBye: no BYE received within %s; methods observed: %v", d, p.Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// AnsweredToTag returns the To-tag this peer minted answering (as UAS) the
// INVITE with the given Call-ID, or "" if it answered none. The attended
// call-transfer test needs it: RFC 3891's Replaces to-tag is THIS peer's tag on
// the consultation dialog, which only the peer knows.
func (p *Peer) AnsweredToTag(callID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.answeredToTag[callID]
}
