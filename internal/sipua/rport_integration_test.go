package sipua_test

// rport_integration_test.go proves RFC 3581's learn-then-use flow end to end:
// the UA LEARNS its server-observed public address off the REGISTER 200 OK
// (received/rport on the top Via), then USES that learned address — not its
// own bound socket — as the Contact host/port on an inbound INVITE's 200 OK
// (Answer). sipproxy is the SOLE stimulus/injection oracle (Rule 6a-D1):
// every SIP message that reaches the UA under test arrives via
// internal/testutil/sipproxy or a raw UDP socket driving it directly;
// internal/testutil/peer is never used. Assertions read the UA's own
// outbound wire bytes off the ObservingConn tap (capturingTap, reused
// verbatim from observe_test.go), never sipgo's parsed objects.
//
// sipproxy's ordinary received/rport stamping mirrors the packet's real
// source address, which in a loopback test equals the UA's own bound
// socket — so "learned" and "bound" would be indistinguishable and a stub
// that never consulted the learned address would still pass. SetObservedAddr
// (added to sipproxy for this test) stamps a FIXED, distinct address instead,
// so the assertion below can tell learned-and-used apart from
// never-left-bound.

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/sipproxy"
)

// pcmuSDPOffer is a minimal SDP body offering PCMU, mirroring inviteRaw's
// body (observe_test.go) so the UA's onInvite sees OfferedCodecs as it
// would for a real peer.
const pcmuSDPOffer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=sipclient-mcp\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

// sendRawInvite dials dst over a fresh raw UDP socket and writes a hand-built
// INVITE addressed to toUser, targeting reqURIHost as the Request-URI host.
// This is the raw-wire injection technique proxy_test.go uses for REGISTER,
// applied to INVITE: no testutil/peer involved anywhere in this path.
func sendRawInvite(t *testing.T, dst, reqURIHost, toUser, callID string) {
	t.Helper()
	raw, err := net.Dial("udp", dst)
	if err != nil {
		t.Fatalf("dial %s: %v", dst, err)
	}
	defer func() { _ = raw.Close() }()

	req := "INVITE sip:" + toUser + "@" + reqURIHost + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + raw.LocalAddr().String() + ";branch=z9hG4bK-" + callID + ";rport\r\n" +
		"From: <sip:bob@example>;tag=t1\r\n" +
		"To: <sip:" + toUser + "@example>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Max-Forwards: 70\r\n" +
		"Contact: <sip:bob@" + raw.LocalAddr().String() + ">\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(pcmuSDPOffer)) + "\r\n\r\n" + pcmuSDPOffer
	if _, err := raw.Write([]byte(req)); err != nil {
		t.Fatalf("write INVITE: %v", err)
	}
}

// contactHostPort extracts the host:port out of a Contact header line found
// in raw wire bytes, e.g. "Contact: <sip:alice@198.51.100.9:40000>\r\n" ->
// ("198.51.100.9", 40000). Parsing the wire bytes directly (not a
// re-parsed sip.Message) keeps the assertion on the exact octets the UA
// sent, per Rule 6a-D1.
func contactHostPort(t *testing.T, raw []byte) (string, int) {
	t.Helper()
	for _, line := range strings.Split(string(raw), "\r\n") {
		if !strings.HasPrefix(line, "Contact:") {
			continue
		}
		open := strings.Index(line, "<")
		closeIdx := strings.Index(line, ">")
		if open < 0 || closeIdx < 0 || closeIdx < open {
			t.Fatalf("malformed Contact line: %q", line)
		}
		uri := line[open+1 : closeIdx]
		uri = strings.TrimPrefix(uri, "sip:")
		at := strings.LastIndex(uri, "@")
		if at < 0 {
			t.Fatalf("Contact URI has no @: %q", uri)
		}
		hostport := uri[at+1:]
		host, portStr, err := net.SplitHostPort(hostport)
		if err != nil {
			t.Fatalf("Contact host:port %q: %v", hostport, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("Contact port %q: %v", portStr, err)
		}
		return host, port
	}
	t.Fatalf("no Contact header found in:\n%s", raw)
	return "", 0
}

// find200Contact locates the UA's outbound 200 OK (the INVITE's final
// response — sipua also sends a 100 Trying, which is StatusCode 100, not
// matched here) and returns its Contact host/port.
func find200Contact(t *testing.T, tap *capturingTap) (string, int) {
	t.Helper()
	for _, rec := range tap.all() {
		if rec.Direction == session.Outbound && rec.StatusCode == 200 && rec.Method == "" {
			// A 200 OK to a REGISTER also matches this shape; disambiguate by
			// Contact presence — REGISTER's 200 as sipproxy builds it here
			// carries no Contact the UA generated, but robustly: only the
			// INVITE 200 carries CSeq method INVITE.
			if !strings.Contains(rec.CSeq, "INVITE") {
				continue
			}
			return contactHostPort(t, rec.Raw)
		}
	}
	t.Fatalf("no outbound 200 OK to INVITE found in tap; records: %+v", tap.all())
	return "", 0
}

// firstOutboundRegisterContact returns the host:port of the very FIRST
// outbound REGISTER request's Contact header — unambiguous regardless of
// how many messages a later exchange produces, since nothing precedes it.
// Unlike find200Contact (which reads a response), this reads a REQUEST off
// the tap — sipua stamps Method on a request record and leaves it "" on a
// response (SIPRecord's own doc comment), so filtering on Method ==
// "REGISTER" and Direction == Outbound unambiguously selects the request
// side.
func firstOutboundRegisterContact(t *testing.T, tap *capturingTap) (string, int) {
	t.Helper()
	for _, rec := range tap.all() {
		if rec.Direction != session.Outbound || rec.Method != "REGISTER" {
			continue
		}
		return contactHostPort(t, rec.Raw)
	}
	t.Fatal("no outbound REGISTER found in tap")
	return "", 0
}

// lastOutboundRegisterContact returns the host:port of the LAST outbound
// REGISTER request's Contact header seen in the tap so far — used for "the
// REGISTER a given Register() call most recently produced", which may not
// be at a fixed position (see this file's note above on why an index is
// not used).
func lastOutboundRegisterContact(t *testing.T, tap *capturingTap) (string, int) {
	t.Helper()
	var last *session.SIPRecord
	for _, rec := range tap.all() {
		if rec.Direction != session.Outbound || rec.Method != "REGISTER" {
			continue
		}
		r := rec
		last = &r
	}
	if last == nil {
		t.Fatal("no outbound REGISTER found in tap")
		return "", 0
	}
	return contactHostPort(t, last.Raw)
}

func TestRportIntegration_AnswerUsesLearnedAddress(t *testing.T) {
	p := sipproxy.StartProxy(t, "127.0.0.1")
	defer p.Close()
	p.SetDigest("sipclient-test", "alice", policy.NewSecret("s3cr3t"))
	observed := netip.MustParseAddrPort("198.51.100.9:40000")
	p.SetObservedAddr(observed)

	tap := &capturingTap{}
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.Addr(),
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  300,
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
		Clock:     clock.System(),
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return sipua.ObservingConn(pc, tap, session.TransportUDP, func() time.Time { return time.Unix(0, 0) }, "")
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	events := collect(t, ua)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !res.Registered || res.Code != 200 {
		t.Fatalf("Registered = %v, Code = %d, want true/200", res.Registered, res.Code)
	}

	// Deliver an inbound INVITE through sipproxy (the sole stimulus oracle):
	// sipproxy's forwardRequest relays it to the Contact this UA just
	// registered.
	sendRawInvite(t, p.Addr(), p.Addr(), "alice", "rport-integ-invite-1")

	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	host, port := find200Contact(t, tap)
	if host != observed.Addr().String() || port != int(observed.Port()) {
		t.Fatalf("200 OK Contact = %s:%d, want the LEARNED address %s (server-observed, RFC 3581)",
			host, port, observed)
	}
	if bound := ua.BoundAddr(); host == bound.IP.String() && port == bound.Port {
		t.Fatalf("200 OK Contact %s:%d equals the BOUND address; Answer did not use the learned address", host, port)
	}
}

// TestRportIntegration_ControlUnregisteredAnswersWithBoundContact is the
// negative control: a UA that never registered (so learnedPublic.known is
// always false) answers an inbound INVITE with its BOUND Contact, exactly as
// before this task. No sipproxy stimulus is needed for the control's own
// registration (there is none) — the INVITE is still delivered over a raw
// UDP socket, never testutil/peer.
func TestRportIntegration_ControlUnregisteredAnswersWithBoundContact(t *testing.T) {
	tap := &capturingTap{}
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "direct",
		AOR:       "sip:carol@example",
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
		Clock:     clock.System(),
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return sipua.ObservingConn(pc, tap, session.TransportUDP, func() time.Time { return time.Unix(0, 0) }, "")
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	events := collect(t, ua)

	sendRawInvite(t, ua.BoundAddr().String(), ua.BoundAddr().String(), "carol", "rport-integ-invite-ctrl")

	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	host, port := find200Contact(t, tap)
	bound := ua.BoundAddr()
	if host != bound.IP.String() || port != bound.Port {
		t.Fatalf("control's 200 OK Contact = %s:%d, want the BOUND address %s:%d (never registered, nothing learned)",
			host, port, bound.IP.String(), bound.Port)
	}
}

// TestRportIntegration_RegisterUsesLearnedAddressFromSecondRegisterOnward
// is the production-hardening spec's Task 4: REGISTER's own Contact must
// reflect the RFC 3581 learned public address once one is known, so a
// registrar with rewrite_contact=yes (this deployment's registrar) can
// match it against what it echoes back. buildRegister is the ONE place all
// four REGISTER call sites (Register, retryIntervalTooBrief, Unregister,
// refreshRegister) build their request, so calling Register() a second
// time exercises the identical code path a real refresh would use, without
// waiting on the refresher's internal timer.
//
// The FIRST REGISTER of a session necessarily still carries the bound
// address — learnedPublic can only be populated AFTER a REGISTER response
// comes back (RFC 3581's own chicken-and-egg) — so this test asserts BOTH
// halves: bound on the first REGISTER, learned from the second onward.
func TestRportIntegration_RegisterUsesLearnedAddressFromSecondRegisterOnward(t *testing.T) {
	p := sipproxy.StartProxy(t, "127.0.0.1")
	defer p.Close()
	p.SetDigest("sipclient-test", "alice", policy.NewSecret("s3cr3t"))
	observed := netip.MustParseAddrPort("198.51.100.9:40000")
	p.SetObservedAddr(observed)

	tap := &capturingTap{}
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.Addr(),
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  300,
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
		Clock:     clock.System(),
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return sipua.ObservingConn(pc, tap, session.TransportUDP, func() time.Time { return time.Unix(0, 0) }, "")
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	bound := ua.BoundAddr()

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if !res.Registered || res.Code != 200 {
		t.Fatalf("first Register: Registered = %v, Code = %d, want true/200", res.Registered, res.Code)
	}
	host, port := firstOutboundRegisterContact(t, tap)
	if host != bound.IP.String() || port != bound.Port {
		t.Fatalf("first REGISTER Contact = %s:%d, want the BOUND address %s:%d "+
			"(nothing learned yet at the time this REGISTER was built)",
			host, port, bound.IP.String(), bound.Port)
	}

	res2, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if !res2.Registered || res2.Code != 200 {
		t.Fatalf("second Register: Registered = %v, Code = %d, want true/200", res2.Registered, res2.Code)
	}
	host2, port2 := lastOutboundRegisterContact(t, tap)
	if host2 != observed.Addr().String() || port2 != int(observed.Port()) {
		t.Fatalf("second REGISTER Contact = %s:%d, want the LEARNED address %s (server-observed, RFC 3581)",
			host2, port2, observed)
	}
}
