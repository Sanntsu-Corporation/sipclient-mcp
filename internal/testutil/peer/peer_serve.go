package peer

// peer_serve.go — this double's METHOD-AGNOSTIC SPINE: bring the socket up, read
// datagrams and stream frames off it, route one parsed message to a handler,
// write the answer back down, tear the socket down.
//
// Split out of peer.go by Phase 4 W2 (P4-W2-13) when that file reached 2346
// lines (1663 originally). THE SPLIT IS BY RESPONSIBILITY, not by which method
// happened to dominate a region of the old file. What earns a place here is
// serving EVERY method equally: dispatch's INVITE/ACK/default routing, respond's
// method switch, and record — which captures every request's observable state
// (the CSeq history, the header snapshots, the Via list, the maxNonceCount
// high-water mark) no matter what method carried it. A per-method payload
// belongs in that method's file: peer_register.go, peer_invite.go,
// peer_dialog.go.
//
// Every declaration here is a pure move — same name, same signature, same body.

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// Start launches the peer, listening on cfg.Addr, and registers its teardown
// with t.Cleanup.
func Start(t *testing.T, cfg Config) *Peer {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Realm == "" {
		cfg.Realm = "sipclient-test"
	}
	if cfg.RegisterStatus == 0 {
		cfg.RegisterStatus = 200
	}
	if cfg.RegisterReason == "" {
		cfg.RegisterReason = "OK"
	}
	conn, err := net.ListenPacket("udp", cfg.Addr)
	if err != nil {
		t.Fatalf("peer listen %s: %v", cfg.Addr, err)
	}
	p := &Peer{
		cfg: cfg, conn: conn, parser: sip.NewParser(), expires: -1, done: make(chan struct{}),
		lastReqBody: make(map[string]string), lastReqHeader: make(map[string]string),
		lastResHeader: make(map[string]string), lastResStatus: make(map[string]int),
		answeredToTag: make(map[string]string), reject422Sent: make(map[string]bool),
		toCallerCSeq: make(map[string]uint32), sentReInvites: make(map[string]sentReInvite), callIDs: make(map[string][]string),
		streamConns: make(map[string]net.Conn),
	}
	go p.serve()
	if cfg.TLSCert != nil {
		p.startTLS(t, cfg)
	}
	t.Cleanup(p.Close)
	return p
}

// startTLS binds a TCP listener on the same host as the UDP socket (an
// ephemeral port, never cfg.Addr's own port) and wraps it in tls.NewListener
// serving cfg.TLSCert (M7a §2 points 1 and 3). Only called when Config.TLSCert
// is set, so every existing UDP-only caller never runs this at all.
func (p *Peer) startTLS(t *testing.T, cfg Config) {
	t.Helper()
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		t.Fatalf("peer: TLS listen: bad addr %q: %v", cfg.Addr, err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("peer: TLS listen: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cfg.TLSCert},
		MinVersion:   tls.VersionTLS12,
	}
	p.tlsListener = tls.NewListener(ln, tlsCfg)
	go p.serveStream(p.tlsListener)
}

// Addr is the peer's concrete bound UDP host:port. NEVER repurposed to carry
// the TLS listener's address (M7a §2 point 4: changing its meaning would
// ripple into all 37 existing importers) — see TLSAddr for that.
func (p *Peer) Addr() string { return p.conn.LocalAddr().String() }

// TLSAddr is the peer's concrete bound TLS listener host:port, or "" if
// Config.TLSCert was never set (no TLS listener was bound).
func (p *Peer) TLSAddr() string {
	if p.tlsListener == nil {
		return ""
	}
	return p.tlsListener.Addr().String()
}

// Close shuts the peer's listener down. Safe to call more than once.
func (p *Peer) Close() {
	select {
	case <-p.done:
		return
	default:
	}
	close(p.done)
	_ = p.conn.Close()
	if p.tlsListener != nil {
		_ = p.tlsListener.Close()
	}
	p.streamMu.Lock()
	for _, c := range p.streamConns {
		_ = c.Close()
	}
	p.streamMu.Unlock()
}

// Stop closes the peer's socket EARLY, before t.Cleanup would, so a test can
// model the far end vanishing mid-run (Tasks 25 and 26). It is idempotent.
func (p *Peer) Stop() { p.stopOnce.Do(func() { _ = p.conn.Close() }) }

// SendCRLFPing writes RFC 5626 §3.5.1's double-CRLF ping AT target — the UA
// under test's OWN bound signalling address, the reverse direction of the
// crlfKeepalives counter above (which counts pings the UA sends TO this
// peer). This is D22's symmetric receive-and-verify half: it drives the
// UA-side pong-answer path (internal/sipua's readyConn.ReadFrom) end to end,
// and PongCount below reads the answer back.
func (p *Peer) SendCRLFPing(t *testing.T, target string) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatalf("peer.SendCRLFPing: resolve %q: %v", target, err)
	}
	if _, err := p.send([]byte("\r\n\r\n"), addr); err != nil {
		t.Fatalf("peer.SendCRLFPing write: %v", err)
	}
}

func reqKey(method, header string) string {
	return method + "|" + strings.ToLower(header)
}

func resKey(method string, status int, header string) string {
	return fmt.Sprintf("%s|%d|%s", method, status, strings.ToLower(header))
}

// ncParam parses the `nc=` parameter out of a raw Authorization header value,
// as hex (RFC 2617's nonce-count is 8 lowercase hex digits), returning 0 if
// the header carries none or it does not parse.
func ncParam(auth string) int {
	idx := strings.Index(auth, "nc=")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimLeft(auth[idx+len("nc="):], `"`)
	end := strings.IndexAny(rest, ", \"")
	if end < 0 {
		end = len(rest)
	}
	v, err := strconv.ParseInt(rest[:end], 16, 64)
	if err != nil {
		return 0
	}
	return int(v)
}

func (p *Peer) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		// RFC 5626 §3.5.1 keep-alive: a datagram whose ENTIRE payload is a
		// double CRLF is a NAT-binding ping, not a SIP message (Task 26) — it
		// must not reach the parser. This is a UDP-datagram-framing concept
		// (a whole datagram that IS the ping) with no TCP/TLS equivalent, so
		// it is deliberately NOT replicated in serveStreamConn below.
		if string(data) == "\r\n\r\n" {
			p.mu.Lock()
			p.crlfKeepalives++
			p.mu.Unlock()
			continue
		}
		// D22's pong: a single CRLF, the UA under test answering
		// SendCRLFPing. Also not a SIP message, so it must not reach the
		// parser either. Same UDP-only reasoning as above.
		if string(data) == "\r\n" {
			p.mu.Lock()
			p.pongCount++
			p.mu.Unlock()
			continue
		}
		msg, err := p.parser.ParseSIP(data)
		if err != nil {
			continue
		}
		p.dispatch(msg, from)
	}
}

// serveStream accepts connections off ln (the TLS listener startTLS bound)
// in a loop, registering each into streamConns and spawning a per-connection
// read goroutine (M7a §2 point 1). Returns once ln.Accept() errors, which
// Close's ln.Close() call causes.
func (p *Peer) serveStream(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.streamMu.Lock()
		p.streamConns[conn.RemoteAddr().String()] = conn
		p.streamMu.Unlock()
		go p.serveStreamConn(conn)
	}
}

// serveStreamConn reads off one accepted TCP/TLS connection, framing
// messages via sipgo's own sip.ParserStream (Rule 16 — M7a §2 point 2, not
// hand-rolled) and dispatching each through the SAME dispatch used by the
// UDP loop, so the challenge/registration/INVITE logic is reused completely
// unchanged. The first Read below is also what drives the server side of
// the TLS handshake itself (crypto/tls performs it lazily on first
// Read/Write), which is all C1's handshake-only acceptance tests require.
func (p *Peer) serveStreamConn(conn net.Conn) {
	from := conn.RemoteAddr()
	defer func() {
		p.streamMu.Lock()
		delete(p.streamConns, from.String())
		p.streamMu.Unlock()
		_ = conn.Close()
	}()
	// sip.NewParser().NewSIPStream(), NOT the zero-value var sp sip.ParserStream:
	// ParserStream.headersParsers is unexported and only populated by
	// NewSIPStream, so a zero-value stream's headersParsers is nil and every
	// header parsed through it silently degrades to a generic header (Rule 13
	// Cycle 3 finding — see TestServeStreamConnParsesTypedHeaders below).
	sp := sip.NewParser().NewSIPStream()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			msgs, perr := sp.ParseSIPStream(buf[:n])
			for _, msg := range msgs {
				p.dispatch(msg, from)
			}
			if perr != nil && perr != sip.ErrParseSipPartial {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// dispatch handles one parsed SIP message from either transport (from is the
// UDP peer address or the accepted stream connection's remote address) —
// the challenge/registration/INVITE logic factored out of serve() so the
// stream read path can reuse it unchanged (M7a §2 point 2).
func (p *Peer) dispatch(msg sip.Message, from net.Addr) {
	// A RESPONSE is a reply to something THIS peer sent (Dial); it needs
	// no reply of its own.
	if res, ok := msg.(*sip.Response); ok {
		p.recordResponse(res)
		p.ackInvite2xx(res)
		return
	}
	req, ok := msg.(*sip.Request)
	if !ok {
		return
	}
	p.record(req)
	switch req.Method {
	case sip.INVITE:
		// Recorded by Call-ID BEFORE inviteFlow runs, so SendFinal can
		// address this INVITE even while inviteFlow's own AnswerAfter
		// delay is still pending.
		if cid := req.CallID(); cid != nil {
			p.mu.Lock()
			if p.inboundInvites == nil {
				p.inboundInvites = make(map[string]*inboundInvite)
			}
			p.inboundInvites[cid.Value()] = &inboundInvite{req: req, from: from}
			p.mu.Unlock()
		}
		// The INVITE flow spans multiple responses over time (100, 180,
		// then a delayed final), which does not fit respond()'s
		// one-request-one-response shape; it runs on its own goroutine so
		// the caller's single receive loop is never blocked by AnswerAfter.
		go p.inviteFlow(req, from)
	case sip.ACK:
		// No response to an ACK.
	default:
		if res := p.respond(req); res != nil {
			_, _ = p.send([]byte(res.String()), from)
		}
	}
}

// send writes b to addr — the ONE write seam of this file (Rule 18),
// replacing every direct p.conn.WriteTo call (M7a §2 point 4). When addr is
// a live TCP/TLS connection this peer accepted, b is written to that
// connection; otherwise (every UDP-only caller, i.e. every pre-existing
// test) it falls straight through to p.conn.WriteTo exactly as before —
// this is what makes the refactor a zero-behavior-change path for UDP.
func (p *Peer) send(b []byte, addr net.Addr) (int, error) {
	if addr != nil {
		p.streamMu.Lock()
		conn := p.streamConns[addr.String()]
		p.streamMu.Unlock()
		if conn != nil {
			return conn.Write(b)
		}
	}
	return p.conn.WriteTo(b, addr)
}

// sentReInvite is an in-dialog INVITE this peer sent and the address it went to.
type sentReInvite struct {
	req  *sip.Request
	addr net.Addr
}

// recordReInvite remembers an in-dialog INVITE that carries a body so its 2xx is
// ACKed (see Peer.sentReInvites).
func (p *Peer) recordReInvite(req *sip.Request, addr net.Addr) {
	cid, cs := req.CallID(), req.CSeq()
	if cid == nil || cs == nil || len(req.Body()) == 0 {
		return
	}
	p.mu.Lock()
	p.sentReInvites[reInviteKey(cid.Value(), cs.SeqNo)] = sentReInvite{req, addr}
	p.mu.Unlock()
}

func reInviteKey(callID string, cseq uint32) string {
	return callID + "/" + strconv.FormatUint(uint64(cseq), 10)
}

// ackInvite2xx ACKs a 2xx to the INVITE this peer dialled, or to an in-dialog
// INVITE it sent with a body (recordReInvite), as any RFC UAC must, and every
// copy of it (RFC 3261 13.2.2.4): the UAS under test retransmits its 200 until it
// sees the ACK. The ACK is its own transaction, so it carries a fresh top Via
// branch (the shape SendReInvite builds).
func (p *Peer) ackInvite2xx(res *sip.Response) {
	if !res.IsSuccess() {
		return
	}
	cs, cid := res.CSeq(), res.CallID()
	if cs == nil || cid == nil || cs.MethodName != sip.INVITE {
		return
	}
	p.mu.Lock()
	inv, addr := p.lastSentInvite, p.lastSentInviteAddr
	if inv == nil || inv.CSeq() == nil || cs.SeqNo != inv.CSeq().SeqNo || inv.CallID() == nil || cid.Value() != inv.CallID().Value() {
		rec, ok := p.sentReInvites[reInviteKey(cid.Value(), cs.SeqNo)]
		inv, addr = rec.req, rec.addr
		if !ok {
			inv = nil
		}
	}
	p.mu.Unlock()
	if inv == nil {
		return
	}
	ack := sip.NewAckRequest(inv, res, nil)
	if v := inv.Via(); v != nil {
		nv := &sip.ViaHeader{ProtocolName: v.ProtocolName, ProtocolVersion: v.ProtocolVersion,
			Transport: v.Transport, Host: v.Host, Port: v.Port, Params: sip.NewParams()}
		nv.Params.Add("branch", sip.GenerateBranchN(10))
		ack.PrependHeader(nv)
	}
	_, _ = p.send([]byte(ack.String()), addr)
}

// recordResponse records a SIP response THIS peer received, in arrival order
// (ResponseCodes), and the most recent FINAL (>=200) one (LastFinalStatus).
func (p *Peer) recordResponse(res *sip.Response) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes = append(p.codes, int(res.StatusCode))
	if res.StatusCode > 100 && res.StatusCode < 200 {
		if to := res.To(); to != nil {
			if tag, _ := to.Params.Get("tag"); tag != "" {
				p.provToTags = append(p.provToTags, tag)
			}
		}
	}
	if res.StatusCode >= 200 {
		p.lastFinalStatus = int(res.StatusCode)
		p.lastFinalBody = res.Body()
		if to := res.To(); to != nil {
			tag, _ := to.Params.Get("tag")
			p.lastFinalToTag = tag
		}
		// D3: dispatch by CSeq method so a CANCEL's own 200 and the pending
		// INVITE's 487 — two finals on one Call-ID — are told apart.
		if cs := res.CSeq(); cs != nil {
			switch cs.MethodName {
			case sip.INVITE:
				p.inviteFinalCode = int(res.StatusCode)
			case sip.CANCEL:
				p.cancelFinalCode = int(res.StatusCode)
			}
			// Task 15's P3 helper surface: keyed by the METHOD the response
			// answers (not the response's own type), and by its status, so a
			// 422 and a 200 answering the same INVITE (Task 28) are both
			// addressable.
			method := string(cs.MethodName)
			p.lastResStatus[method] = int(res.StatusCode)
			for _, h := range res.Headers() {
				p.lastResHeader[resKey(method, int(res.StatusCode), h.Name())] = h.Value()
			}
		}
	}
}

// write serialises res and sends it to to. It is the shared send path for
// every response the peer originates as a UAS, whether from respond() or from
// inviteFlow's multi-response INVITE handling.
func (p *Peer) write(res *sip.Response, to net.Addr) {
	_, _ = p.send([]byte(res.String()), to)
}

// reasonPhrase is the RFC 3261 default reason phrase for the status codes
// this test peer's own callers reject with. It exists in place of a separate
// Behaviour.RejectReason knob (Rule 15/18): every status this peer is asked
// to reject with in this wave's tests has a fixed standard phrase, so a
// second field carrying the same information a second way is not needed.
func reasonPhrase(status int) string {
	switch status {
	case 202:
		return "Accepted"
	case 302:
		return "Moved Temporarily"
	case 404:
		return "Not Found"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 486:
		return "Busy Here"
	case 500:
		return "Server Internal Error"
	case 603:
		return "Decline"
	default:
		return "Rejected"
	}
}

func (p *Peer) record(req *sip.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	method := string(req.Method)
	p.methods = append(p.methods, method)
	if req.Method == sip.BYE {
		p.lastBye = req
		if to := req.To(); to != nil {
			tag, _ := to.Params.Get("tag")
			p.lastByeToTag = tag
		}
		if cs := req.CSeq(); cs != nil {
			p.lastByeCSeq = cs.SeqNo
		}
	}
	if h := req.GetHeader("Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil {
			p.expires = v
			if v == 0 {
				p.unregisters++
			}
		}
	}
	if v := req.Via(); v != nil {
		via := net.JoinHostPort(v.Host, strconv.Itoa(v.Port))
		p.via = via
		p.vias = append(p.vias, via)
	}

	// Task 15's P3 helper surface (see the field comments): every request's
	// body and headers, keyed by method, plus its CSeq in arrival order.
	p.lastReqBody[method] = string(req.Body())
	// F-M8 (D20, W2): TWO KNOWN FIDELITY LIMITS OF THIS RECORDING, stated here
	// because they bound what any test can assert through LastRequestHeader /
	// LastResponseHeader:
	//
	//  1. REPEATED HEADERS COLLAPSE. This map is keyed on method+header name, so
	//     the LAST occurrence wins. A test therefore CANNOT detect duplicate or
	//     conflicting headers on one message — e.g. two Contact headers, or a
	//     Via list. If you need that, assert on the serialized message instead.
	//  2. ncParam takes the FIRST "nc=" substring anywhere in the Authorization
	//     value, not a parsed parameter. A value that happened to contain "nc="
	//     inside another parameter's quoted string would mislead it.
	//
	// NOT FIXED HERE: a faithful multi-value recording changes the shape every
	// existing accessor returns, which is a redesign of this double's read
	// surface, not a cosmetic sweep item (Rule 19). Recorded so a test author
	// hits the limit knowingly.
	for _, h := range req.Headers() {
		p.lastReqHeader[reqKey(method, h.Name())] = h.Value()
	}
	if cs := req.CSeq(); cs != nil {
		p.reqCSeqs = append(p.reqCSeqs, MethodCSeq{Method: method, CSeq: cs.SeqNo})
	}
	if cid := req.CallID(); cid != nil {
		p.callIDs[method] = append(p.callIDs[method], cid.Value())
	}
	if a := req.GetHeader("Authorization"); a != nil {
		if nc := ncParam(a.Value()); nc > p.maxNonceCount {
			p.maxNonceCount = nc
		}
	}
}

// respond takes a snapshot of cfg under the lock before using it: SetBehaviour
// and SetRegisterStatus can run concurrently with serve()'s single goroutine,
// so every read of p.cfg here goes through this snapshot rather than the
// field directly.
func (p *Peer) respond(req *sip.Request) *sip.Response {
	p.mu.Lock()
	cfg := p.cfg
	p.mu.Unlock()

	switch req.Method {
	case sip.BYE:
		// SwallowBye exists SOLELY to make an in-dialog BYE not draw a 200 OK
		// (contract §2.10), which is what lets §11.4's shutdown-grace-period
		// wait actually elapse in the tests that need it — not exercised by
		// Task 15's own suite, but wired here since Behaviour already
		// declares the field.
		if cfg.Behaviour.SwallowBye {
			return nil
		}
		return sip.NewResponseFromRequest(req, 200, "OK", nil)
	case sip.CANCEL:
		return sip.NewResponseFromRequest(req, 200, "OK", nil)
	case sip.INFO:
		// Task 15: 200 any in-dialog INFO with no body, alongside the BYE this
		// peer already answers, so a UA under test sending DTMF-over-INFO gets
		// a final response rather than retransmitting for Timer J's ~32s.
		// RejectInfoStatus overrides this for the not_supported-mapping
		// regression coverage.
		//
		// Dialog-matched through the SAME inDialog matcher the in-dialog
		// re-INVITE arm uses: an INFO is an in-dialog request, and answering
		// one built on a wrong or dead dialog 200 OK would make that defect
		// unobservable to every test on the far side.
		if !p.inDialog(req) {
			return sip.NewResponseFromRequest(req, 481, reasonPhrase(481), nil)
		}
		if cfg.Behaviour.RejectInfoStatus != 0 {
			return sip.NewResponseFromRequest(req, sip.StatusCode(cfg.Behaviour.RejectInfoStatus), reasonPhrase(cfg.Behaviour.RejectInfoStatus), nil)
		}
		return sip.NewResponseFromRequest(req, 200, "OK", nil)
	case sip.UPDATE:
		// Task 29's session-timer refresh, delivered as UPDATE rather than a
		// re-INVITE — see buildRefreshResponse for the shared Behaviour knobs.
		// Dialog-matched exactly as the re-INVITE arm is (see INFO above).
		if !p.inDialog(req) {
			return sip.NewResponseFromRequest(req, 481, reasonPhrase(481), nil)
		}
		return p.buildRefreshResponse(req, cfg.Behaviour)
	case sip.REFER:
		// Call transfer (RFC 3515). With no REFER knob set this stays the
		// pre-transfer 405. With one set, dialog-matched through the same
		// inDialog matcher the INFO/UPDATE arms use, so a REFER built on a wrong
		// dialog draws 481 rather than being accepted.
		if cfg.Behaviour.ReferStatus == 0 && !cfg.Behaviour.SwallowRefer {
			return sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
		}
		if !p.inDialog(req) {
			return sip.NewResponseFromRequest(req, 481, reasonPhrase(481), nil)
		}
		if cfg.Behaviour.SwallowRefer {
			return nil
		}
		reason := cfg.Behaviour.ReferReason
		if reason == "" {
			reason = reasonPhrase(cfg.Behaviour.ReferStatus)
		}
		return sip.NewResponseFromRequest(req, sip.StatusCode(cfg.Behaviour.ReferStatus), reason, nil)
	case sip.REGISTER:
		// THE ROUTE, not the logic. The registrar half — the digest gate, RFC
		// 3261 §10.2.8's 423 floor and the 200's Contact/Expires construction —
		// lives in peer_register.go, so this switch stays a pure routing
		// decision and every arm reads the same way (P4-W2-13).
		return p.respondRegister(req, cfg)
	default:
		return sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	}
}
