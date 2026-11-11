package peer

// peer_dialog.go — IN-DIALOG requests, both directions: UPDATE, re-INVITE and
// BYE.
//
// Split out of peer.go by Phase 4 W2 (P4-W2-13); pure move. Three things belong
// together here and nowhere else:
//
//  1. THE DIALOG MATCHER (toTagOf, inDialog, localDialogTag). respond()'s INFO
//     and UPDATE arms and inviteFlow's re-INVITE arm all match through it, so it
//     is neither REGISTER's nor INVITE's — it is what "in-dialog" means for this
//     double.
//  2. THE REFRESH-RESPONSE BUILDERS (sessionExpiresSeconds, buildRefreshResponse,
//     grantedSessionExpires), shared by the UPDATE arm and the re-INVITE arm for
//     exactly that reason.
//  3. EVERY IN-DIALOG REQUEST THIS PEER ORIGINATES toward the far end, which is
//     where the CSeq sequencing that RFC 3261 §12.2.1.1 makes per-dialog rather
//     than per-method lives (see Peer.toCallerCSeq).
//
// THE MEMBERSHIP TEST IS DIALOG STATE. Every request-originating helper here
// needs some: SendUPDATE fatals on an empty lastFinalToTag, sendBye needs
// lastOK (the 200 that confirmed the dialog), and the *ToCaller pair sequence
// their CSeq per dialog. The INVITE that ESTABLISHES a dialog is not here — that
// is peer_invite.go — and neither is CANCEL, which needs no dialog state at all
// and is matched by branch to a still-pending INVITE server transaction
// (RFC 3261 §9.1), so it lives with the INVITE transaction it terminates. This
// is the file that answers "what happens once the dialog exists".

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// SendUPDATE sends an in-dialog UPDATE carrying the given Session-Expires value
// on the call this peer most recently DIALED (via Dial/DialWithHeaders) —
// Task 28's inbound RFC 4028 negotiation. It mirrors SendReInvite's
// construction: the SAME Call-ID, the peer's own From (with its tag), the
// callee's To-tag (observed off the wire on the answer), an incremented CSeq,
// and a FRESH branch so sipgo's server transaction layer routes it as a new
// transaction rather than a retransmission.
func (p *Peer) SendUPDATE(t *testing.T, sessionExpires string, extra ...sip.Header) {
	t.Helper()
	p.mu.Lock()
	inv, addr, toTag := p.lastSentInvite, p.lastSentInviteAddr, p.lastFinalToTag
	p.mu.Unlock()
	if inv == nil {
		t.Fatalf("peer.SendUPDATE: no INVITE dialed yet")
	}
	if toTag == "" {
		t.Fatalf("peer.SendUPDATE: no To-tag observed yet (call not answered?)")
	}
	// D15 (P4-W2-08, W2): TYPED, and nothing asserts that it stays typed. This is
	// sip.MaxForwardsHeader(70), not sip.NewHeader("Max-Forwards", "70"), so it
	// serializes through the typed path — but no test reads it back through
	// req.MaxForwards() to confirm the receiving parser produced a typed header
	// rather than falling back to a generic one. A parser regression would be
	// invisible: the wire bytes are identical either way.
	//
	// Assertable with the existing accessors; not added here because it belongs to
	// whichever wave owns the parser, and W2 owns neither
	// third_party/sipgo/sip (G4-frozen) nor a parser change.

	upd := sip.NewRequest(sip.UPDATE, inv.Recipient)
	if v := inv.Via(); v != nil {
		nv := &sip.ViaHeader{
			ProtocolName:    v.ProtocolName,
			ProtocolVersion: v.ProtocolVersion,
			Transport:       v.Transport,
			Host:            v.Host,
			Port:            v.Port,
			Params:          sip.NewParams(),
		}
		nv.Params.Add("branch", sip.GenerateBranchN(10))
		nv.Params.Add("rport", "")
		upd.AppendHeader(nv)
	}
	if f := inv.From(); f != nil {
		upd.AppendHeader(sip.HeaderClone(f))
	}
	if to := inv.To(); to != nil {
		nt := &sip.ToHeader{DisplayName: to.DisplayName, Address: to.Address, Params: sip.NewParams()}
		nt.Params.Add("tag", toTag)
		upd.AppendHeader(nt)
	}
	if cid := inv.CallID(); cid != nil {
		upd.AppendHeader(sip.HeaderClone(cid))
	}
	seq := uint32(2)
	if cs := inv.CSeq(); cs != nil {
		seq = cs.SeqNo + 1
	}
	upd.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.UPDATE})
	mf := sip.MaxForwardsHeader(70)
	upd.AppendHeader(&mf)
	if c := inv.Contact(); c != nil {
		upd.AppendHeader(sip.HeaderClone(c))
	}
	if sessionExpires != "" {
		upd.AppendHeader(sip.NewHeader("Session-Expires", sessionExpires))
	}
	for _, h := range extra {
		upd.AppendHeader(h)
	}

	if _, err := p.send([]byte(upd.String()), addr); err != nil {
		t.Fatalf("peer.SendUPDATE write: %v", err)
	}
}

// toTagOf reads the "tag" param off a request's To header, or "" if the
// request carries none. A populated To-tag marks a request as IN-DIALOG
// (RFC 3261): a fresh dial's INVITE never carries one.
func toTagOf(req *sip.Request) string {
	to := req.To()
	if to == nil {
		return ""
	}
	tag, _ := to.Params.Get("tag")
	return tag
}

// inDialog reports whether req belongs to a dialog THIS PEER actually has: it
// carries a To-tag (a fresh, out-of-dialog request never does — RFC 3261) whose
// value is the peer's own local tag on req's Call-ID.
//
// It is the ONE dialog matcher in this file (Rule 18). The in-dialog re-INVITE
// arm (inviteFlow) and the in-dialog UPDATE/INFO arms (respond) all go through
// it, so a refresh or an INFO built on a wrong or dead dialog draws a 481
// instead of being answered as if it were valid — which is what lets a test on
// the far side of this peer fail when the UA under test gets the dialog wrong.
func (p *Peer) inDialog(req *sip.Request) bool {
	toTag := toTagOf(req)
	if toTag == "" {
		return false
	}
	cid := ""
	if c := req.CallID(); c != nil {
		cid = c.Value()
	}
	if cid == "" {
		return false
	}
	ourTag, known := p.localDialogTag(cid)
	return known && toTag == ourTag
}

// localDialogTag is the tag this peer carries as ITS OWN local tag on the
// dialog identified by cid, in either orientation: the tag it minted answering
// an INVITE as UAS (answeredToTag), or — for a dialog this peer itself DIALED —
// the From-tag it put on that INVITE. Both are needed: a UA under test refreshes
// into whichever dialog it has, and a peer that only recognised the calls it
// answered would 481 a perfectly valid refresh on a call it placed.
func (p *Peer) localDialogTag(cid string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if tag, ok := p.answeredToTag[cid]; ok {
		return tag, true
	}
	inv := p.lastSentInvite
	if inv == nil {
		return "", false
	}
	if c := inv.CallID(); c == nil || c.Value() != cid {
		return "", false
	}
	f := inv.From()
	if f == nil {
		return "", false
	}
	tag, ok := f.Params.Get("tag")
	return tag, ok
}

// sessionExpiresSeconds reads the leading delta-seconds integer off a
// request's Session-Expires header (format "delta-seconds[;refresher=...]"
// per RFC 4028 §4), or 0 if the request carries no such header or it does not
// parse. Used by Reject422MinSE to tell a retry's raised value apart from a
// still-too-low one.
func sessionExpiresSeconds(req *sip.Request) int {
	h := req.GetHeader("Session-Expires")
	if h == nil {
		return 0
	}
	v := h.Value()
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
}

// buildRefreshResponse builds this peer's response to an in-dialog session
// refresh — Task 29's UPDATE, or an in-dialog re-INVITE used as the refresh
// method instead. A nil return means SWALLOW: no response at all, modelling
// an unresponsive peer during a session-timer refresh (Behaviour.SwallowUpdate,
// the same species of switch as the existing SwallowBye). Otherwise it is
// Behaviour.RejectUpdateStatus when non-zero, else a 200 OK carrying
// AnswerSessionExpires/AnswerAllow when set. It is shared between the UPDATE
// arm (respond) and the in-dialog re-INVITE arm (inviteFlow) so a later task
// configures "respond with X"/"swallow it" ONCE, regardless of which method
// carries the refresh.
func (p *Peer) buildRefreshResponse(req *sip.Request, b Behaviour) *sip.Response {
	if b.SwallowUpdate {
		return nil
	}
	if b.RejectUpdateStatus != 0 {
		rej := sip.NewResponseFromRequest(req, sip.StatusCode(b.RejectUpdateStatus), reasonPhrase(b.RejectUpdateStatus), nil)
		if b.RejectUpdateMinSE != 0 {
			rej.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(b.RejectUpdateMinSE)))
		}
		return rej
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	if se := p.grantedSessionExpires(b); se != "" {
		res.AppendHeader(sip.NewHeader("Session-Expires", se))
	}
	if b.AnswerAllow != "" {
		res.AppendHeader(sip.NewHeader("Allow", b.AnswerAllow))
	}
	return res
}

// grantedSessionExpires is the Session-Expires value this peer grants on the
// refresh it is answering right now: AnswerSessionExpires unless
// RefreshSessionExpires scripts a per-refresh sequence, in which case the next
// unconsumed element (the last one, repeated, once exhausted). Called ONLY on
// the 200 path, so a swallowed or rejected refresh consumes nothing — see
// Behaviour.RefreshSessionExpires. Must be called with p.mu NOT held.
func (p *Peer) grantedSessionExpires(b Behaviour) string {
	if len(b.RefreshSessionExpires) == 0 {
		return b.AnswerSessionExpires
	}
	p.mu.Lock()
	i := p.refreshesGranted
	p.refreshesGranted++
	p.mu.Unlock()
	if i >= len(b.RefreshSessionExpires) {
		i = len(b.RefreshSessionExpires) - 1
	}
	return b.RefreshSessionExpires[i]
}

// SendReInvite sends an in-dialog re-INVITE for the call the peer most
// recently dialed via Dial: the SAME Call-ID, the peer's own original From
// (with its tag), the callee's own To-tag (read off the wire from the final
// response to the original INVITE), and an incremented CSeq — D2's positive
// case, modelling Asterisk's connected-line/codec-lock re-INVITE. A FRESH
// branch is required (unlike buildCancelFromInvite's shared branch, RFC
// 3261 §9.1's CANCEL-specific rule): reusing the original INVITE's branch on
// a second INVITE would let sipgo's server transaction layer treat this as a
// retransmission of the FIRST request rather than route it to onInvite
// again.
func (p *Peer) SendReInvite(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	inv, addr, toTag := p.lastSentInvite, p.lastSentInviteAddr, p.lastFinalToTag
	p.mu.Unlock()
	if inv == nil {
		t.Fatalf("peer.SendReInvite: no INVITE dialed yet")
	}
	if toTag == "" {
		t.Fatalf("peer.SendReInvite: no To-tag observed yet (call not answered?)")
	}

	reinv := sip.NewRequest(sip.INVITE, inv.Recipient)
	if v := inv.Via(); v != nil {
		nv := &sip.ViaHeader{
			ProtocolName:    v.ProtocolName,
			ProtocolVersion: v.ProtocolVersion,
			Transport:       v.Transport,
			Host:            v.Host,
			Port:            v.Port,
			Params:          sip.NewParams(),
		}
		nv.Params.Add("branch", sip.GenerateBranchN(10))
		nv.Params.Add("rport", "")
		reinv.AppendHeader(nv)
	}
	if f := inv.From(); f != nil {
		reinv.AppendHeader(sip.HeaderClone(f))
	}
	if to := inv.To(); to != nil {
		nt := &sip.ToHeader{DisplayName: to.DisplayName, Address: to.Address, Params: sip.NewParams()}
		nt.Params.Add("tag", toTag)
		reinv.AppendHeader(nt)
	}
	if cid := inv.CallID(); cid != nil {
		reinv.AppendHeader(sip.HeaderClone(cid))
	}
	seq := uint32(2)
	if cs := inv.CSeq(); cs != nil {
		seq = cs.SeqNo + 1
	}
	reinv.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	reinv.AppendHeader(&mf)
	if c := inv.Contact(); c != nil {
		reinv.AppendHeader(sip.HeaderClone(c))
	}
	ct := sip.ContentTypeHeader("application/sdp")
	reinv.AppendHeader(&ct)
	reinv.SetBody([]byte(peerSDPBody))

	p.recordReInvite(reinv, addr)
	if _, err := p.send([]byte(reinv.String()), addr); err != nil {
		t.Fatalf("peer.SendReInvite write: %v", err)
	}
}

// SendReInviteToCaller sends an in-dialog re-INVITE on the call this peer
// most recently ACCEPTED AS UAS (the UA under test dialed the peer via
// Dial/DialRequest and the peer answered) — Task 11's outbound-leg
// counterpart to SendReInvite. It models Asterisk's direct_media=yes
// re-INVITE-ing the CALLER leg after answer: same Call-ID, the CALLER's own
// local tag (observed on the inbound INVITE's From — the tag the caller
// generated as UAC) carried as this re-INVITE's To-tag, and this peer's own
// tag (the one it minted answering with the 200 OK) as the From-tag.
// A FRESH branch is required for the same reason SendReInvite needs one
// (§9.1 / sipgo's server-transaction routing): reusing the answered
// INVITE's branch would route as a retransmission rather than a new
// transaction into onInvite.
func (p *Peer) SendReInviteToCaller(t *testing.T, extra ...sip.Header) {
	t.Helper()
	p.mu.Lock()
	inv, ok, from := p.lastInvite, p.lastOK, p.lastFrom
	p.mu.Unlock()
	if inv == nil || ok == nil {
		t.Fatalf("peer.SendReInviteToCaller: no answered call accepted as UAS yet")
	}

	target := inv.From().Address
	if c := inv.Contact(); c != nil {
		target = c.Address
	}
	reinv := sip.NewRequest(sip.INVITE, target)

	host, portStr, err := net.SplitHostPort(p.Addr())
	if err != nil {
		t.Fatalf("peer.SendReInviteToCaller: bad peer addr %q: %v", p.Addr(), err)
	}
	port, _ := strconv.Atoi(portStr)
	via := &sip.ViaHeader{
		ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: host, Port: port, Params: sip.NewParams(),
	}
	via.Params.Add("branch", sip.GenerateBranchN(10))
	via.Params.Add("rport", "")
	reinv.AppendHeader(via)

	// From: THIS PEER's own identity, tagged with the tag it minted in the
	// 200 OK it sent as UAS — that tag is the peer's own local dialog
	// identity, unrelated to (and not to be confused with) the caller's tag.
	if okTo := ok.To(); okTo != nil {
		nf := &sip.FromHeader{DisplayName: okTo.DisplayName, Address: okTo.Address, Params: sip.NewParams()}
		if tag, tagOK := okTo.Params.Get("tag"); tagOK {
			nf.Params.Add("tag", tag)
		}
		reinv.AppendHeader(nf)
	}
	// To: the CALLER's identity, tagged with the tag IT generated on the
	// original INVITE's From — the exact value the D2 guard must recognize
	// as "our own local tag" for an outbound dialog.
	if invFrom := inv.From(); invFrom != nil {
		nt := &sip.ToHeader{DisplayName: invFrom.DisplayName, Address: invFrom.Address, Params: sip.NewParams()}
		if tag, tagOK := invFrom.Params.Get("tag"); tagOK {
			nt.Params.Add("tag", tag)
		}
		reinv.AppendHeader(nt)
	}
	cid := ""
	if c := inv.CallID(); c != nil {
		cid = c.Value()
		reinv.AppendHeader(sip.HeaderClone(c))
	}
	// D23 (Phase 4 W2): ADVANCES across repeated calls on the same dialog,
	// sharing toCallerCSeq with SendUPDATEToCaller. It was hardcoded to 1, which
	// made every re-INVITE after the first look like a retransmission and would
	// draw an RFC 3261 12.2.2 remote-sequence rejection from a real UA — the
	// same defect the UPDATE twin already had fixed, left asymmetric here.
	p.mu.Lock()
	seq := p.toCallerCSeq[cid] + 1
	p.toCallerCSeq[cid] = seq
	p.mu.Unlock()
	reinv.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	reinv.AppendHeader(&mf)
	reinv.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "bob", Host: host, Port: port}})
	for _, h := range extra {
		reinv.AppendHeader(h)
	}
	ct := sip.ContentTypeHeader("application/sdp")
	reinv.AppendHeader(&ct)
	reinv.SetBody([]byte(peerSDPBody))

	p.recordReInvite(reinv, from)
	if _, err := p.send([]byte(reinv.String()), from); err != nil {
		t.Fatalf("peer.SendReInviteToCaller write: %v", err)
	}
}

// SendUPDATEToCaller sends an in-dialog UPDATE carrying the given
// Session-Expires value on the call this peer most recently ACCEPTED AS UAS
// (the UA under test dialed the peer via Dial/DialRequest and the peer
// answered) — Task 30's own-refresher-role orientation, the OPPOSITE of
// SendUPDATE's (which needs the peer to have DIALED). It is SendToCaller with
// the UPDATE method and an optional Session-Expires header; the wire bytes are
// identical to this helper's pre-transfer hand-built form (same headers, same
// order, no body).
func (p *Peer) SendUPDATEToCaller(t *testing.T, sessionExpires string, extra ...sip.Header) {
	t.Helper()
	var hdrs []sip.Header
	if sessionExpires != "" {
		hdrs = append(hdrs, sip.NewHeader("Session-Expires", sessionExpires))
	}
	hdrs = append(hdrs, extra...)
	p.SendToCaller(t, sip.UPDATE, hdrs, nil)
}

// SendToCaller sends one in-dialog request of the given method, THIS PEER ->
// the caller, on the call this peer most recently ACCEPTED AS UAS. It is the
// ONE builder for that orientation (Rule 18): SendUPDATEToCaller delegates to
// it, and the call-transfer tests use it for NOTIFY and INFO. Construction:
// the SAME Call-ID, this peer's own From (tagged with the tag it minted in its
// 200 OK), the caller's To (tagged with the tag IT generated on the original
// INVITE's From), a fresh branch, and a CSeq from the per-dialog toCallerCSeq
// counter every *ToCaller helper shares. headers are appended after Contact,
// in order; a non-nil body is set with its Content-Length (the caller supplies
// Content-Type in headers).
func (p *Peer) SendToCaller(t *testing.T, method sip.RequestMethod, headers []sip.Header, body []byte) {
	t.Helper()
	req, from, err := p.buildToCaller(method, headers, body)
	if err != nil {
		t.Fatalf("peer.SendToCaller(%s): %v", method, err)
	}
	if method == sip.INVITE {
		p.recordReInvite(req, from)
	}
	if _, err := p.send([]byte(req.String()), from); err != nil {
		t.Fatalf("peer.SendToCaller(%s) write: %v", method, err)
	}
}

// buildToCaller builds the request SendToCaller and sendBye send, and the
// address to send it to.
func (p *Peer) buildToCaller(method sip.RequestMethod, headers []sip.Header, body []byte) (*sip.Request, net.Addr, error) {
	p.mu.Lock()
	inv, ok, from := p.lastInvite, p.lastOK, p.lastFrom
	p.mu.Unlock()
	if inv == nil || ok == nil {
		return nil, nil, fmt.Errorf("no answered call accepted as UAS yet")
	}
	target := inv.From().Address
	if c := inv.Contact(); c != nil {
		target = c.Address
	}
	req := sip.NewRequest(method, target)

	host, portStr, err := net.SplitHostPort(p.Addr())
	if err != nil {
		return nil, nil, fmt.Errorf("bad peer addr %q: %v", p.Addr(), err)
	}
	port, _ := strconv.Atoi(portStr)
	via := &sip.ViaHeader{
		ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: host, Port: port, Params: sip.NewParams(),
	}
	via.Params.Add("branch", sip.GenerateBranchN(10))
	via.Params.Add("rport", "")
	req.AppendHeader(via)

	// From: THIS PEER's own identity, tagged with the tag it minted in the
	// 200 OK it sent as UAS.
	if okTo := ok.To(); okTo != nil {
		nf := &sip.FromHeader{DisplayName: okTo.DisplayName, Address: okTo.Address, Params: sip.NewParams()}
		if tag, tagOK := okTo.Params.Get("tag"); tagOK {
			nf.Params.Add("tag", tag)
		}
		req.AppendHeader(nf)
	}
	// To: the CALLER's identity, tagged with the tag IT generated on the
	// original INVITE's From.
	if invFrom := inv.From(); invFrom != nil {
		nt := &sip.ToHeader{DisplayName: invFrom.DisplayName, Address: invFrom.Address, Params: sip.NewParams()}
		if tag, tagOK := invFrom.Params.Get("tag"); tagOK {
			nt.Params.Add("tag", tag)
		}
		req.AppendHeader(nt)
	}
	cid := ""
	if c := inv.CallID(); c != nil {
		cid = c.Value()
		req.AppendHeader(sip.HeaderClone(c))
	}
	// ADVANCES across repeated calls on the same dialog — see toCallerCSeq's
	// field comment. This peer has no "answered INVITE's CSeq" to offset from
	// on ITS OWN originated in-dialog requests, so the counter itself is the
	// CSeq.
	p.mu.Lock()
	seq := p.toCallerCSeq[cid] + 1
	p.toCallerCSeq[cid] = seq
	p.mu.Unlock()
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: method})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "bob", Host: host, Port: port}})
	for _, h := range headers {
		req.AppendHeader(h)
	}
	if body != nil {
		req.SetBody(body)
	}

	return req, from, nil
}

// SendBye ends the most recent call the peer accepted as UAS. It takes NO
// dialog argument (contract-divergent from the interface contract's
// SendBye(t, dialogID) by design — D128/C2, reaffirmed D305): the caller's
// dialog handle is sipua's own internal random hex, a value this peer never
// saw. onBye on the UA side matches an incoming BYE by Call-ID and both tags
// (CF-130), so the BYE is built in the callee orientation by buildToCaller:
// From is this peer's 200 tag, To is the caller's tag.
func (p *Peer) SendBye(t *testing.T) {
	t.Helper()
	if err := p.sendBye(); err != nil {
		t.Fatalf("peer.SendBye: %v", err)
	}
}

// SendByeErr is SendBye's error-returning twin (P1e's D305 correction to
// Harness.PeerSendBye): a caller resolving "the most recent answered call"
// from a non-test goroutine — Task 23's conflicting-pair racers share one
// func(*Harness, string) error shape — must not call t.Fatal, which calls
// runtime.Goexit and is a testing API violation off the test goroutine.
func (p *Peer) SendByeErr() error {
	return p.sendBye()
}

func (p *Peer) sendBye() error {
	bye, from, err := p.buildToCaller(sip.BYE, nil, nil)
	if err != nil {
		return fmt.Errorf("peer: no answered call to hang up: %w", err)
	}
	if _, err := p.send([]byte(bye.String()), from); err != nil {
		return fmt.Errorf("peer: write BYE: %w", err)
	}
	return nil
}
