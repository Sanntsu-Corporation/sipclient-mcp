// Package sipproxy provides a minimal REGISTER-recording SIP proxy used by
// integration tests.
package sipproxy

// proxy.go — minimal REGISTER-recording SIP proxy used by integration tests.
//
// Scope: this proxy exists to exercise the production routing model:
//
//  1. A UA (the probe) sends REGISTER. The proxy records the Contact
//     URI's host:port as the routable address for the registered user
//     (Contact -> bind) and replies 200 OK.
//  2. Any external UAC can then send INVITE to the proxy. The proxy
//     looks up the To-header user in its registrar table and forwards
//     the INVITE to the recorded Contact address via a stateful
//     Via-based path so that responses route back through the proxy.
//  3. Subsequent in-dialog requests (ACK, BYE) and responses are
//     forwarded by stripping our Via hop and using the next Via/addr.
//
// Explicit non-goals:
//   - Auth. W2-H6 is about routing, not authentication; the proxy
//     accepts any REGISTER payload.
//   - Record-Route or full B2BUA semantics. The proxy inserts its own
//     top Via on forwarded requests so responses return here, then
//     strips that hop before forwarding responses on.
//   - Production hardening. This is a test helper.
//
// The proxy implementation uses a raw UDP socket and the sipgo SIP
// parser rather than sipgo.Server because a correctly forwarding proxy
// needs full control over Via / Contact rewriting and of the source
// port used for each outbound leg.

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

// Proxy is a test helper SIP proxy. It listens on a UDP socket, records
// REGISTER Contacts, and forwards INVITE / in-dialog requests by the
// recorded Contact address. Call Close() to release the listener.
type Proxy struct {
	conn   net.PacketConn
	parser *sip.Parser
	t      *testing.T

	done chan struct{}

	mu sync.Mutex
	// contacts maps registered user -> UDP address (host:port) extracted
	// from the REGISTER Contact header.
	contacts map[string]string

	// digest is the opt-in challenge configuration (SetDigest). nil means
	// upstream behaviour exactly: the proxy accepts any REGISTER payload.
	digest *digestCreds
	// registers, challenges and unregisters are P1e Task 22 Step 7's wire
	// counters. registers counts every REGISTER received, on the wire;
	// challenges counts 401s issued; unregisters counts ACCEPTED REGISTERs
	// carrying Expires: 0.
	registers   map[string]int
	challenges  map[string]int
	unregisters map[string]int

	// observedAddr/observedSet are a test-only override (SetObservedAddr):
	// when set, REGISTER 200 OKs stamp received/rport with this FIXED
	// address instead of the packet's real source, so a test can prove a UA
	// learned (and later used) a server-observed address distinct from its
	// own bound socket. Guarded by mu like every other Proxy field.
	observedAddr netip.AddrPort
	observedSet  bool
}

// digestCreds is the opt-in challenge SetDigest installs. pass is carried as
// a policy.Secret and revealed only inside digestOK, at the point the
// expected response is computed.
type digestCreds struct {
	realm string
	user  string
	pass  policy.Secret
}

// SetDigest makes the proxy issue one 401 with a digest challenge per AOR
// before accepting, so tests can assert R1's REGISTER -> 401 -> REGISTER ->
// 200 ladder. Off by default: the proxy's stated non-goal is auth, and its
// routing tests depend on it accepting any REGISTER.
//
// pass is a policy.Secret AND IS STORED AS ONE. It is revealed only inside
// digestOK, at the point the expected response is computed — see the note
// there. Taking a plain string here would move the plaintext one frame
// earlier, into this argument list and into the caller's local, for no gain.
func (p *Proxy) SetDigest(realm, user string, pass policy.Secret) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.digest = &digestCreds{realm: realm, user: user, pass: pass}
}

// SetObservedAddr makes the proxy stamp received/rport on REGISTER 200 OK
// responses with a fixed address distinct from the packet source, so a test
// can prove the UA learned (and later used) the server-observed address
// rather than its own bound socket. The 200 is still sent to the real source.
func (p *Proxy) SetObservedAddr(ap netip.AddrPort) {
	p.mu.Lock()
	p.observedAddr, p.observedSet = ap, true
	p.mu.Unlock()
}

// RegisterCount is how many REGISTERs this AOR has sent, ON THE WIRE — the
// only way to distinguish "challenged then retried" from "accepted first
// time"; the response code alone cannot.
func (p *Proxy) RegisterCount(user string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registers[user]
}

// ChallengeCount is how many 401 digest challenges the proxy has issued to
// this AOR.
func (p *Proxy) ChallengeCount(user string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.challenges[user]
}

// UnregisterCount is how many REGISTERs with Expires: 0 this AOR has sent.
//
// IT IS THE REGISTRAR'S COUNTER AND TAKES A USER, and it is NOT
// peer.Peer.UnregisterCount(), which takes none and counts at the far-end
// UAS. Different object, different type: §12.7's "the far end observes one
// REGISTER Expires: 0" is observed at the REGISTRAR, because that is where a
// register-mode UA deregisters — the peer never sees it. Incremented on the
// ACCEPTED path only, so a challenged-and-retried deregistration counts
// once.
func (p *Proxy) UnregisterCount(user string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unregisters[user]
}

// digestOK verifies through internal/sipengine/digest — Rule 16, no
// hand-rolled MD5.
//
// A SANCTIONED TEST-ONLY .Reveal(), NOT COUNTED BY P1a's ASSERTION.
// TestRevealAppearsOnlyInProductionWiring is scoped to production code and
// excludes internal/testutil entirely, so this site contributes nothing to
// the one-production-reveal rule; that one is P1d's cmd/ wiring closure. The
// exclusion is sound only because TestDaemonDoesNotShipTestUtil proves the
// daemon cannot reach this package — the two are one control. A digest
// verifier cannot work without the plaintext — the whole scheme is
// MD5(HA1:nonce:HA2) where HA1 derives from the password — so this is
// irreducible, not an oversight. It is test-only, on a fixture password, in
// a package unreachable from the shipped daemon.
func (p *Proxy) digestOK(req *sip.Request, creds *digestCreds) bool {
	h := req.GetHeader("Authorization")
	if h == nil {
		return false
	}
	fields, err := digest.ParseAuthorization(h.Value())
	if err != nil {
		return false
	}
	if fields["username"] != creds.user {
		return false
	}
	return digest.VerifyMD5Auth(creds.user, creds.pass.Reveal(), string(req.Method), fields)
}

// nonceFor returns a per-user static nonce, stable enough for a test's single
// challenge/retry round trip.
func nonceFor(user string) string { return "sipproxy-nonce-" + user }

// digestChallenge builds the 401 response for req, carrying a WWW-Authenticate
// digest challenge in realm for nonce.
func digestChallenge(req *sip.Request, realm, nonce string) *sip.Response {
	res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
	res.AppendHeader(sip.NewHeader("WWW-Authenticate",
		fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, realm, nonce)))
	return res
}

// StartProxy binds a UDP socket on localIP (":0" — kernel picks the
// port), spins up the read loop, and returns a Proxy ready for use.
// The test is responsible for calling Close() via t.Cleanup or defer.
func StartProxy(t *testing.T, localIP string) *Proxy {
	t.Helper()
	conn, err := net.ListenPacket("udp", localIP+":0")
	if err != nil {
		t.Fatalf("siptest proxy: listen: %v", err)
	}
	p := &Proxy{
		conn:        conn,
		parser:      sip.NewParser(),
		t:           t,
		done:        make(chan struct{}),
		contacts:    make(map[string]string),
		registers:   make(map[string]int),
		challenges:  make(map[string]int),
		unregisters: make(map[string]int),
	}
	go p.readLoop()
	return p
}

// Addr returns the proxy's bound host:port (what to send REGISTER /
// INVITE to). Safe to call after StartProxy returns.
func (p *Proxy) Addr() string { return p.conn.LocalAddr().String() }

// Close stops the read loop and releases the listener. Safe to call
// more than once.
func (p *Proxy) Close() {
	_ = p.conn.Close()
	<-p.done
}

// LookupContact returns the most recent Contact address recorded for
// user, or ("", false) if no REGISTER has been seen for this user.
// Exposed so tests can assert the REGISTER leg landed correctly.
func (p *Proxy) LookupContact(user string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr, ok := p.contacts[user]
	return addr, ok
}

func (p *Proxy) readLoop() {
	defer close(p.done)
	buf := make([]byte, 8192)
	for {
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		msg, err := p.parser.ParseSIP(data)
		if err != nil {
			log.Printf("siptest proxy: parse: %v", err)
			continue
		}
		switch m := msg.(type) {
		case *sip.Request:
			p.handleRequest(m, from)
		case *sip.Response:
			p.handleResponse(m)
		}
	}
}

// handleRequest dispatches on method.
func (p *Proxy) handleRequest(req *sip.Request, from net.Addr) {
	switch req.Method {
	case sip.REGISTER:
		p.handleRegister(req, from)
	case sip.INVITE, sip.ACK, sip.BYE, sip.CANCEL:
		p.forwardRequest(req, from)
	default:
		// Unhandled methods: respond 200 to keep the UA happy if possible.
		if req.Method != sip.ACK {
			resp := sip.NewResponseFromRequest(req, 200, "OK", nil)
			p.writeTo(resp, from.String())
		}
	}
}

// handleRegister records the Contact URI host:port against the
// registering user and responds 200 OK to the source address.
func (p *Proxy) handleRegister(req *sip.Request, from net.Addr) {
	user := ""
	if to := req.To(); to != nil {
		user = to.Address.User
	}
	if user == "" {
		if f := req.From(); f != nil {
			user = f.Address.User
		}
	}

	// Opt-in digest challenge (SetDigest, Step 7). p.digest nil ⇒ upstream
	// behaviour exactly: accept any REGISTER payload.
	p.mu.Lock()
	p.registers[user]++
	creds := p.digest
	p.mu.Unlock()
	if creds != nil && !p.digestOK(req, creds) {
		p.mu.Lock()
		p.challenges[user]++
		p.mu.Unlock()
		p.writeTo(digestChallenge(req, creds.realm, nonceFor(user)), from.String())
		return
	}
	// ACCEPTED from here on. The Expires: 0 count is taken HERE, on the
	// accepted path only — not beside registers[user]++ above. The two
	// counters deliberately count different things: registers counts every
	// REGISTER ON THE WIRE (why the R1 ladder test expects 2 for one
	// challenged registration); unregisters counts ACCEPTED
	// DEREGISTRATIONS, so a challenged-and-retried deregistration still
	// counts once.
	//
	// An accepted Expires: 0 also CLEARS the routing entry (D11 point 4): a
	// deregistering REGISTER still carries a real Contact host:port (sipua's
	// Unregister reuses BuildRegister wholesale), so without this the block
	// below would just re-record the same now-stale contact and
	// forwardRequest would keep routing INVITEs to a closed socket instead
	// of reaching its explicit 404 branch.
	isUnregister := false
	if h := req.GetHeader("Expires"); h != nil && h.Value() == "0" {
		isUnregister = true
		p.mu.Lock()
		p.unregisters[user]++
		delete(p.contacts, user)
		p.mu.Unlock()
	}

	contactAddr := ""
	if !isUnregister {
		if c := req.Contact(); c != nil {
			host := c.Address.Host
			port := c.Address.Port
			if host != "" && port > 0 {
				// A real SIP server routes INVITEs by the Contact URI.
				// If the UA sent a Contact with no port (or port 0), the
				// binding is unroutable; we record nothing rather than
				// making up a fallback. W2-H6 depends on this strictness
				// so the red-first test sees a clear 404 symptom.
				contactAddr = net.JoinHostPort(host, fmt.Sprintf("%d", port))
			}
		}
	}
	if user != "" && contactAddr != "" {
		p.mu.Lock()
		p.contacts[user] = contactAddr
		p.mu.Unlock()
	}

	// Build 200 OK using rport/received so the reply goes to the actual
	// source UDP address rather than the Via-declared host:port.
	resp := sip.NewResponseFromRequest(req, 200, "OK", nil)

	// Reply to the source addr. For UDP over rport this is the right
	// destination because sipgo's UAC ClientRequestAddVia already sets
	// rport="".
	srcAddr := from.String()
	recvHost, rportVal := hostOf(srcAddr), portOf(srcAddr)
	p.mu.Lock()
	if p.observedSet {
		recvHost, rportVal = p.observedAddr.Addr().String(), strconv.Itoa(int(p.observedAddr.Port()))
	}
	p.mu.Unlock()
	if v := resp.Via(); v != nil {
		v.Params.Add("received", recvHost)
		v.Params.Add("rport", rportVal)
	}
	p.writeTo(resp, srcAddr)
}

// forwardRequest adds our Via (so responses come back here), populates
// received/rport on the caller's top Via (RFC 3261 §18.2.1 + RFC 3581)
// so our response-side forwarder knows where to send responses, and
// sends the request to the registered Contact for the To-user.
func (p *Proxy) forwardRequest(req *sip.Request, src net.Addr) {
	user := ""
	if to := req.To(); to != nil {
		user = to.Address.User
	}
	if user == "" {
		return
	}
	p.mu.Lock()
	contactAddr, ok := p.contacts[user]
	p.mu.Unlock()
	if !ok {
		// No registration: if it's an INVITE, reply 404 via the top Via.
		if req.Method == sip.INVITE {
			resp := sip.NewResponseFromRequest(req, 404, "Not Found", nil)
			if dst := topViaAddr(resp); dst != "" {
				p.writeTo(resp, dst)
			}
		}
		return
	}

	// Populate received/rport on the caller's top Via before we prepend
	// our own. rport may be present as a placeholder (empty value); per
	// RFC 3581 §4 the proxy fills it with the packet source port.
	if topVia := req.Via(); topVia != nil {
		srcHost := hostOf(src.String())
		srcPort := portOf(src.String())
		if topVia.Params == nil {
			topVia.Params = sip.NewParams()
		}
		if topVia.Host != srcHost {
			topVia.Params.Add("received", srcHost)
		}
		// If rport is present (empty or set), set it to the source port.
		if topVia.Params.Has("rport") {
			topVia.Params.Add("rport", srcPort)
		}
	}

	// Insert our own Via at the top so responses route back here.
	ourVia := &sip.ViaHeader{
		ProtocolName:    "SIP",
		ProtocolVersion: "2.0",
		Transport:       "UDP",
		Host:            hostOf(p.Addr()),
		Port:            intPort(portOf(p.Addr())),
		Params:          sip.NewParams(),
	}
	ourVia.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(ourVia)

	// Forward to the registered Contact address. For INVITE / ACK /
	// BYE / CANCEL we preserve the Request-URI so the UA receives a
	// recognizable dialog; only the transport-level destination is
	// the Contact addr.
	p.writeTo(req, contactAddr)
}

// handleResponse strips our Via hop and forwards the response to the
// next Via's address (received/rport if present, else host:port).
func (p *Proxy) handleResponse(resp *sip.Response) {
	// Remove our top Via. Responses must travel Via-by-Via back to the
	// originator per RFC 3261 §18.1.2.
	topVia := resp.Via()
	if topVia == nil {
		return
	}
	if topVia.Host != hostOf(p.Addr()) || topVia.Port != intPort(portOf(p.Addr())) {
		// Not our Via — drop silently; this shouldn't happen in normal
		// operation but we don't want to leak packets to arbitrary
		// destinations.
		return
	}
	resp.RemoveHeader("Via")

	// Next Via — route to received/rport if set, else host:port.
	next := resp.Via()
	if next == nil {
		return
	}
	dstHost := next.Host
	dstPort := next.Port
	if next.Params != nil {
		if rec, ok := next.Params.Get("received"); ok && rec != "" {
			dstHost = rec
		}
		if rp, ok := next.Params.Get("rport"); ok && rp != "" {
			// rport may be empty (request-side placeholder); in that
			// case the forwarded response has no better hint than the
			// sent-by port we already carry.
			var n int
			if _, err := fmt.Sscanf(rp, "%d", &n); err == nil && n > 0 {
				dstPort = n
			}
		}
	}
	if dstPort == 0 {
		return
	}
	dst := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))
	p.writeTo(resp, dst)
}

// writeTo serializes msg and writes it to dst over our PacketConn.
func (p *Proxy) writeTo(msg sip.Message, dst string) {
	udpAddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		log.Printf("siptest proxy: resolve %s: %v", dst, err)
		return
	}
	data := []byte(msg.String())
	if _, err := p.conn.WriteTo(data, udpAddr); err != nil {
		log.Printf("siptest proxy: write %s: %v", dst, err)
	}
}

// --- helpers ---

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "0"
	}
	return p
}

func intPort(s string) int {
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// topViaAddr returns the host:port of the top Via on a response (used
// for replying to the UA that sent us a request we couldn't forward).
func topViaAddr(resp *sip.Response) string {
	v := resp.Via()
	if v == nil {
		return ""
	}
	host := v.Host
	port := v.Port
	if v.Params != nil {
		if rec, ok := v.Params.Get("received"); ok && rec != "" {
			host = rec
		}
		if rp, ok := v.Params.Get("rport"); ok && rp != "" {
			var n int
			if _, err := fmt.Sscanf(rp, "%d", &n); err == nil && n > 0 {
				port = n
			}
		}
	}
	if host == "" || port == 0 {
		return ""
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
