package peer

// peer_invite.go — the INVITE TRANSACTION, in both directions: the multi-response
// flow this peer runs when it RECEIVES one (inviteFlow, plus the SDP-answer
// machinery it needs), the out-of-band final response SendFinal writes for a
// recorded inbound INVITE, the Dial family this peer uses to ORIGINATE one as a
// caller, and the CANCEL that terminates one still in progress.
//
// Split out of peer.go by Phase 4 W2 (P4-W2-13); pure move. SCOPED TO THE
// TRANSACTION, NOT THE DIALOG: an UPDATE, BYE or re-INVITE is not handled here
// even though the earliest draft of the split put them here — they need dialog
// state (a To-tag, a confirmed 200) and live in peer_dialog.go.
//
// CANCEL IS HERE, AND THAT IS NOT A NAMING ACCIDENT. RFC 3261 §9.1 gives the
// CANCEL the SAME top Via branch as the INVITE it cancels, because the UAS
// matches it to the still-PENDING INVITE server transaction — there is no
// confirmed dialog yet, and once there is one the CANCEL is too late. SendCancel
// reads lastSentInvite and nothing dialog-scoped: no To-tag, no final response.
// Filing it under peer_dialog.go (as an earlier draft did) would tell the next
// reader that CANCEL is dialog machinery, which is exactly backwards.
//
// inviteFlow itself stays whole at ~164 lines because its rejection knobs
// (Reject422MinSE, RingThenSilent, AnswerSDP, StripTelephoneEvent) are one
// cohesive decision tree; splitting mid-tree would cost more than the length
// saves.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// DialWithHeaders is Dial with arbitrary extra headers appended to the INVITE,
// which is how a test drives inbound RFC 4028 negotiation (Task 28).
func (p *Peer) DialWithHeaders(t *testing.T, target string, headers map[string]string) {
	t.Helper()
	p.dial(t, target, "", nil, headers)
}

// inviteFlow drives the peer's UAS side of an INVITE it received: 100 Trying
// and 180 Ringing immediately, then — after cfg.Behaviour.AnswerAfter — either
// a 200 OK (RejectStatus == 0, the contract §2.10 default: "0 = answer") or
// the configured rejection status. It runs on its own goroutine (see serve())
// so the delay cannot block the peer's single receive loop.
func (p *Peer) inviteFlow(req *sip.Request, from net.Addr) {
	p.mu.Lock()
	cfg := p.cfg
	b := cfg.Behaviour
	cid := ""
	if c := req.CallID(); c != nil {
		cid = c.Value()
	}
	p.mu.Unlock()

	// An INVITE carrying a To-tag that matches this peer's own local tag on
	// that Call-ID's dialog is an in-dialog session-refresh re-INVITE (Task
	// 29), never a fresh dial — a fresh dial's INVITE never carries a To-tag
	// (RFC 3261: only in-dialog requests do). It gets no ringing step (the call
	// is already answered) and is routed through the SAME refresh-response
	// logic as an in-dialog UPDATE, so a later task configures "respond with
	// X"/"swallow it" once regardless of which method carries the refresh.
	if p.inDialog(req) {
		res := p.buildRefreshResponse(req, b)
		if res != nil {
			p.write(res, from)
		}
		return
	}

	if b.HoldProvisionals != nil {
		select {
		case <-b.HoldProvisionals:
		case <-p.done:
			return
		}
	}

	// A digest-protected peer (AuthUser set) challenges an unauthenticated
	// INVITE with 401, exactly as it does REGISTER (respond()) — driving the
	// UA down its DoRequestWithDigest retry, which advances the INVITE's CSeq.
	// This is what makes §14.5's stale-BYE-CSeq defect reproducible in-process:
	// without a challenge the INVITE goes out at a low CSeq and a hardcoded BYE
	// CSeq happens to stay above it. Gated on AuthUser, so the many call tests
	// that start an unauthenticated peer are unaffected.
	if cfg.AuthUser != "" {
		// ProxyAuthInvite (Phase 4 W3): challenge as a PROXY rather than as the
		// UAS. 407 + Proxy-Authenticate makes the UA answer under
		// Proxy-Authorization (internal/sipua/digestauth.go's `case 407`), which
		// is the only way a Proxy-Authorization header ever reaches this wire —
		// and therefore the only way retry422's strip of it is observable.
		code, reason := 401, "Unauthorized"
		challengeHdr, credHdr := "WWW-Authenticate", "Authorization"
		if b.ProxyAuthInvite {
			code, reason = 407, "Proxy Authentication Required"
			challengeHdr, credHdr = "Proxy-Authenticate", "Proxy-Authorization"
		}
		if !p.credentialOK(req, cfg, credHdr, testNonce) {
			res := sip.NewResponseFromRequest(req, sip.StatusCode(code), reason, nil)
			res.AppendHeader(sip.NewHeader(challengeHdr,
				fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, cfg.Realm, testNonce)))
			p.write(res, from)
			return
		}
	}

	// Reject422MinSE (Task 27): the FIRST INVITE on a fresh Call-ID draws
	// "422 Session Interval Too Small" carrying Min-SE UNCONDITIONALLY —
	// modelling a peer whose minimum acceptable session interval is HIGHER
	// than whatever the caller opened with, regardless of what that first
	// attempt itself carried. Only a RETRY (the second-or-later INVITE on the
	// same Call-ID) that raises its own Session-Expires to meet that floor is
	// accepted; a retry that still falls short draws the same 422 again.
	//
	// Informational, pre-existing CLASS of risk (not a behaviour change
	// this task needs to make): if the FIRST INVITE's own Session-Expires
	// already met the floor, a UDP RETRANSMISSION of that same message
	// arriving AFTER alreadyRejectedOnce has flipped true would be evaluated
	// as if it were the genuine retry (its Session-Expires still meets the
	// floor) and answered 200 — a different final response than the
	// original 422 for what is nominally one retransmitted request. Low
	// probability on loopback and shared with every stateful-by-Call-ID
	// switch already in this file (Reject422MinSE is not special here); not
	// worth a dedup mechanism for a test double.
	if b.Reject422MinSE > 0 {
		p.mu.Lock()
		alreadyRejectedOnce := p.reject422Sent[cid]
		if !alreadyRejectedOnce {
			p.reject422Sent[cid] = true
		}
		p.mu.Unlock()
		if !alreadyRejectedOnce || sessionExpiresSeconds(req) < b.Reject422MinSE {
			res := sip.NewResponseFromRequest(req, 422, "Session Interval Too Small", nil)
			res.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(b.Reject422MinSE)))
			p.write(res, from)
			return
		}
		// A retry whose own Session-Expires meets the floor: falls through to
		// the normal ring+answer flow below.
	}

	p.write(sip.NewResponseFromRequest(req, 100, "Trying", nil), from)
	p.write(sip.NewResponseFromRequest(req, 180, "Ringing", nil), from)
	if b.RingThenSilent {
		// Rang, then vanished: no final ever. B1's reap test asserts the caller
		// times the dialog out at its finite post-ring budget rather than
		// parking on it.
		return
	}
	select {
	case <-time.After(b.AnswerAfter):
	case <-p.done:
		return
	}

	if b.RejectStatus == 0 {
		var ok *sip.Response
		if b.AnswerSDP != nil {
			// The test drives the exact answer: an unoffered codec, a downgraded
			// RTP/AVP profile, garbage (all non-nil bodies), or no SDP at all (nil).
			body := b.AnswerSDP(req.Body())
			if body == nil {
				ok = sip.NewResponseFromRequest(req, 200, "OK", nil) // sdp_absent
			} else {
				ok = sip.NewSDPResponseFromRequest(req, body)
			}
		} else {
			// StripTelephoneEvent/mirroring (Task 22): the default answer is no
			// longer the FIXED peerSDPBody verbatim — it mirrors the offer's
			// telephone-event payload type unless asked to omit it.
			ok = sip.NewSDPResponseFromRequest(req, buildDefaultAnswer(req.Body(), b.StripTelephoneEvent))
		}
		ok.AppendHeader(&sip.ContactHeader{Address: p.contactFor(req)})
		// Critical fix: EVERY downstream RFC 4028 consumer (Tasks 27/29/30)
		// needs Session-Expires/Allow on the INITIAL INVITE's 200, not only on
		// a later refresh response — Task 29's refreshMethodFor in particular
		// branches on whether THIS answer's own Allow lists UPDATE, and no
		// session timer is ever armed at all without Session-Expires here.
		// Same header names/values buildRefreshResponse already applies to a
		// refresh response, applied here to the answer that STARTS the timer.
		if b.AnswerSessionExpires != "" {
			ok.AppendHeader(sip.NewHeader("Session-Expires", b.AnswerSessionExpires))
		}
		if b.AnswerAllow != "" {
			ok.AppendHeader(sip.NewHeader("Allow", b.AnswerAllow))
		}
		// The answered-call state is recorded BEFORE the 200 reaches the wire,
		// and the write happens INSIDE the same critical section that publishes
		// it. Recording afterwards is a real race, not a flake: the moment the
		// 200 is on the wire the UA ACKs it and a test can be running an
		// in-dialog probe (SendUPDATEToCaller / SendReInviteToCaller, both of
		// which take p.mu and read these fields) against a peer that has not yet
		// remembered the call it just answered. A 5 ms deschedule between the
		// old write and the old record reproduced that as
		// "no answered call accepted as UAS yet" in all four answering-window
		// probes. Holding p.mu across the WriteTo also orders the 200 ahead of
		// any in-dialog request those helpers go on to send, which they cannot
		// even build until they have read these fields.
		p.mu.Lock()
		p.lastInvite, p.lastOK, p.lastFrom = req, ok, from
		p.lastInboundFinalStatus = 200
		if cs := req.CSeq(); cs != nil {
			p.answeredInviteCSeq = cs.SeqNo
		}
		// Remember the To-tag this 200 minted, keyed by Call-ID, so a LATER
		// in-dialog re-INVITE on the same dialog (Task 29's session-timer
		// refresh) is recognised as in-dialog rather than treated as a fresh
		// dial.
		if okTo := ok.To(); okTo != nil {
			if tag, tagOK := okTo.Params.Get("tag"); tagOK && cid != "" {
				p.answeredToTag[cid] = tag
			}
		}
		p.write(ok, from)
		p.mu.Unlock()
		return
	}
	p.write(sip.NewResponseFromRequest(req, sip.StatusCode(b.RejectStatus), reasonPhrase(b.RejectStatus), nil), from)
	p.mu.Lock()
	p.lastInboundFinalStatus = b.RejectStatus
	p.mu.Unlock()
}

// parseTelephoneEventRTPMap finds an "a=rtpmap:<pt> telephone-event/8000" line
// in offer and returns its payload type and the matching rtpmap line (plus a
// matching "a=fmtp:<pt> ..." line, if the offer carries one) verbatim, or
// found=false if the offer carries none. This is NOT a general SDP parser —
// just enough to locate this one line pattern (Rule 16: internal/testutil/peer
// deliberately does not import internal/media's production SDP parser, to
// stay a true black-box test double).
func parseTelephoneEventRTPMap(offer []byte) (pt int, rtpmapLine, fmtpLine string, found bool) {
	lines := strings.Split(string(offer), "\r\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "a=rtpmap:") {
			continue
		}
		fields := strings.SplitN(strings.TrimPrefix(line, "a=rtpmap:"), " ", 2)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "telephone-event/") {
			continue
		}
		v, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		pt, rtpmapLine, found = v, line+"\r\n", true
		break
	}
	if !found {
		return 0, "", "", false
	}
	prefix := fmt.Sprintf("a=fmtp:%d ", pt)
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			fmtpLine = line + "\r\n"
			break
		}
	}
	return pt, rtpmapLine, fmtpLine, true
}

// buildDefaultAnswer builds this peer's default SDP answer to offer: the same
// PCMU audio peerSDPBody has always carried, with the offer's
// telephone-event payload type MIRRORED IN — matching a real negotiation —
// unless strip (Behaviour.StripTelephoneEvent) asks to omit it entirely,
// modelling a gateway that speaks G.711 only (Task 22's far-end
// not_supported case). Used at the exact point AnswerSDP replaces; unlike
// AnswerSDP, this is the peer's UNCONFIGURED default, so every other test
// that never sets AnswerSDP or StripTelephoneEvent now negotiates
// telephone-event whenever the offer carried it, which it previously never
// did against this peer's old fixed-body answer.
func buildDefaultAnswer(offer []byte, strip bool) []byte {
	const header = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=peer\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
	pt, rtpmapLine, fmtpLine, found := parseTelephoneEventRTPMap(offer)
	if strip || !found {
		return []byte(header + "m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n")
	}
	body := header + fmt.Sprintf("m=audio 40002 RTP/AVP 0 %d\r\n", pt) +
		"a=rtpmap:0 PCMU/8000\r\n" + rtpmapLine + fmtpLine + "a=sendrecv\r\n"
	return []byte(body)
}

// Dial originates an INVITE at target from the peer's own socket, so a UA
// under test can be driven as a UAS. It is the contract §2.10 name (there is
// no peer.Invite) and is the reason siptest.RunUAS is not reused: RunUAS can
// only ANSWER, never ORIGINATE.
func (p *Peer) Dial(t *testing.T, target string) {
	t.Helper()
	p.dial(t, target, "", nil, nil)
}

// DialWithToTag originates an INVITE at target exactly as Dial does, but with
// an explicit To-tag — D2's negative case: an INVITE carrying a To-tag that
// matches no confirmed dialog on the UA under test (RFC 3261 §12.2.2's 481),
// as opposed to a genuinely new call, which carries none.
func (p *Peer) DialWithToTag(t *testing.T, target, toTag string) {
	t.Helper()
	p.dial(t, target, toTag, nil, nil)
}

// DialWithBody dials target sending an INVITE carrying an explicit SDP body,
// letting a test drive the exact offer the answering UA negotiates against
// (P2 W3 Task 8).
func (p *Peer) DialWithBody(t *testing.T, target string, body []byte) {
	t.Helper()
	p.dial(t, target, "", body, nil)
}

func (p *Peer) dial(t *testing.T, target, toTag string, body []byte, headers map[string]string) {
	t.Helper()
	user, hostport := splitTarget(target)
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("peer.Dial: unparseable target %q: %v", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("peer.Dial: bad port in target %q: %v", target, err)
	}
	if body == nil {
		body = []byte(peerSDPBody)
	}
	// A USERLESS TargetURI drives builders.go:52's IP-to-IP branch, the only
	// path that carries a port into the Request-URI (the same construction
	// sipua.Dial uses for the same reason — D127/C1).
	req := siptest.BuildInvite(config.Config{
		LocalAddr:  p.Addr(),
		TargetURI:  hostport,
		FromUser:   "bob",
		FromDomain: "peer.example",
		ToUser:     user,
		ToDomain:   host,
	}, "udp", body)
	if toTag != "" {
		if to := req.To(); to != nil {
			to.Params = sip.NewParams()
			to.Params.Add("tag", toTag)
		}
	}
	for k, v := range headers {
		req.AppendHeader(sip.NewHeader(k, v))
	}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		t.Fatalf("peer.Dial: %q is not an IP literal", host)
	}
	p.mu.Lock()
	p.lastSentInvite = req
	p.lastSentInviteAddr = addr
	p.mu.Unlock()
	if _, err := p.send([]byte(req.String()), addr); err != nil {
		t.Fatalf("peer.Dial write: %v", err)
	}
}

// splitTarget splits a "sip:"/"sips:" URI of the form user@host:port into its
// user and host:port halves.
func splitTarget(target string) (user, hostport string) {
	s := strings.TrimPrefix(strings.TrimPrefix(target, "sips:"), "sip:")
	if i := strings.IndexByte(s, '@'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// SendCancel CANCELs the most recent INVITE this peer dialed via Dial (D3),
// built per RFC 3261 §9.1 (buildCancelFromInvite) so it carries the
// SAME branch as that INVITE and the UAS matches it to the still-pending
// INVITE server transaction.
func (p *Peer) SendCancel(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	inv, addr := p.lastSentInvite, p.lastSentInviteAddr
	p.mu.Unlock()
	if inv == nil {
		t.Fatalf("peer.SendCancel: no INVITE dialed yet")
	}
	cancel := buildCancelFromInvite(inv)
	if _, err := p.send([]byte(cancel.String()), addr); err != nil {
		t.Fatalf("peer.SendCancel write: %v", err)
	}
}

// buildCancelFromInvite builds a CANCEL for a still-pending inv, per RFC 3261
// §9.1: the Request-URI, Call-ID, To, From (with tags) and the numeric CSeq
// all equal inv's, and the Via is the SAME top Via (same branch) as inv's —
// unlike siptest.BuildByeFromInvite's Via, which is fresh per in-dialog
// request, the UAS matches a CANCEL to the INVITE server transaction it must
// terminate by that shared branch, not by a new one. To comes from the
// REQUEST, never a provisional response's To-tag: §9.1 is explicit that the
// CANCEL's To must equal the cancelled request's own To field.
func buildCancelFromInvite(inv *sip.Request) *sip.Request {
	cancel := sip.NewRequest(sip.CANCEL, inv.Recipient)

	if v := inv.Via(); v != nil {
		cancel.AppendHeader(sip.HeaderClone(v))
	}
	if f := inv.From(); f != nil {
		cancel.AppendHeader(sip.HeaderClone(f))
	}
	if t := inv.To(); t != nil {
		cancel.AppendHeader(sip.HeaderClone(t))
	}
	if cid := inv.CallID(); cid != nil {
		cancel.AppendHeader(sip.HeaderClone(cid))
	}
	if cs := inv.CSeq(); cs != nil {
		cancel.AppendHeader(&sip.CSeqHeader{SeqNo: cs.SeqNo, MethodName: sip.CANCEL})
	}
	mf := sip.MaxForwardsHeader(70)
	cancel.AppendHeader(&mf)
	return cancel
}

// DialExpectingStatus dials toURI (as Dial does) and blocks, with a bounded
// deadline, until the peer observes a FINAL response to that INVITE,
// returning its status code. It fails the test if no final response arrives
// within the deadline.
func (p *Peer) DialExpectingStatus(t *testing.T, toURI string) int {
	t.Helper()
	before := p.FinalResponseCount()
	p.Dial(t, toURI)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p.FinalResponseCount() > before {
			return p.LastFinalStatus()
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer.DialExpectingStatus(%q): no final response within 5s; codes observed: %v",
				toURI, p.ResponseCodes())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// SendProvisional sends a provisional (100, 180 or 183) for the inbound INVITE
// with the given Call-ID, independently of inviteFlow — e.g. one arriving LATE,
// after the caller's CANCEL transaction has completed, or the ONLY provisional
// of an INVITE whose flow HoldProvisionals is holding.
func (p *Peer) SendProvisional(t *testing.T, callID string, status int) {
	t.Helper()
	p.mu.Lock()
	inv, ok := p.inboundInvites[callID]
	p.mu.Unlock()
	if !ok {
		t.Fatalf("peer.SendProvisional: no inbound INVITE known for Call-ID %q", callID)
	}
	reason := "Ringing"
	switch status {
	case 100:
		reason = "Trying"
	case 183:
		reason = "Session Progress"
	}
	p.write(sip.NewResponseFromRequest(inv.req, sip.StatusCode(status), reason, nil), inv.from)
}

// SendFinal sends a final response with the given status for the inbound
// INVITE identified by dialogID — the SIP Call-ID, which (unlike sipua's
// internal dialog handle) the peer genuinely observes off the wire, so
// dialogID here is real and load-bearing, not the same D128/D305 dead
// parameter SendBye's contract signature carries. status < 300 answers with
// a 200 OK carrying the peer's fixed SDP body; status >= 300 rejects.
func (p *Peer) SendFinal(t *testing.T, dialogID string, status int) {
	t.Helper()
	p.mu.Lock()
	inv, ok := p.inboundInvites[dialogID]
	p.mu.Unlock()
	if !ok {
		t.Fatalf("peer.SendFinal: no inbound INVITE known for Call-ID %q", dialogID)
	}

	var res *sip.Response
	if status < 300 {
		res = sip.NewSDPResponseFromRequest(inv.req, []byte(peerSDPBody))
		host, portStr, _ := net.SplitHostPort(p.Addr())
		port, _ := strconv.Atoi(portStr)
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "bob", Host: host, Port: port}})
	} else {
		res = sip.NewResponseFromRequest(inv.req, sip.StatusCode(status), reasonPhrase(status), nil)
	}
	p.write(res, inv.from)

	p.mu.Lock()
	p.lastInboundFinalStatus = status
	if status < 300 {
		p.lastInvite, p.lastOK, p.lastFrom = inv.req, res, inv.from
		// Same record inviteFlow's own 200 path makes, for the same reason:
		// inDialog resolves a later UPDATE/INFO/re-INVITE on this dialog by the
		// To-tag this answer minted, and a call answered through SendFinal is
		// just as much an answered call as one answered by inviteFlow.
		if resTo := res.To(); resTo != nil {
			if tag, tagOK := resTo.Params.Get("tag"); tagOK {
				p.answeredToTag[dialogID] = tag
			}
		}
	}
	p.mu.Unlock()
}

// contactFor is the Contact URI of this peer's 2xx to req: where the peer is
// reachable on the transport the INVITE arrived on. Over TLS that is the TLS
// listener (sips:), because the UA now addresses its 2xx ACK, and every later
// in-dialog request, by the dialog's remote target (CF-193), not by the INVITE's
// destination. Every other transport keeps the peer's UDP address.
func (p *Peer) contactFor(req *sip.Request) sip.Uri {
	if strings.EqualFold(req.Transport(), "tls") && p.tlsListener != nil {
		if host, portStr, err := net.SplitHostPort(p.TLSAddr()); err == nil {
			port, _ := strconv.Atoi(portStr)
			return sip.Uri{Scheme: "sips", User: "bob", Host: host, Port: port}
		}
	}
	host, portStr, _ := net.SplitHostPort(p.Addr())
	port, _ := strconv.Atoi(portStr)
	return sip.Uri{User: "bob", Host: host, Port: port}
}
