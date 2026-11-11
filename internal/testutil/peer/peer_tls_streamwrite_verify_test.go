package peer

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

// TestVerifyStreamWriteSeamRoundTrip is a Rule 9 verification diagnostic (not
// part of the implementer's commit): it proves the write seam's stream
// branch — p.send resolving a live TCP/TLS net.Conn and writing back over
// it — actually works, by sending a real SIP BYE over the TLS connection
// after handshake and reading the fake's 200 OK response back on the wire.
func TestVerifyStreamWriteSeamRoundTrip(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	conn, err := tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	bye := "BYE sip:test@127.0.0.1 SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS 127.0.0.1:0;branch=z9hG4bK-verify\r\n" +
		"From: <sip:caller@test>;tag=abc\r\n" +
		"To: <sip:test@127.0.0.1>\r\n" +
		"Call-ID: verify-stream-write@test\r\n" +
		"CSeq: 1 BYE\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(bye)); err != nil {
		t.Fatalf("conn.Write(BYE): %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("conn.Read: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "SIP/2.0 200") {
		t.Fatalf("response over TLS stream = %q, want a 200 OK status line", got)
	}
}

// TestServeStreamConnParsesTypedHeaders is Rule 13 Cycle 3 finding 1's
// verification: it drives a real BYE through serveStreamConn's actual
// TLS/TCP read path (not a hand-rolled re-implementation of it) and asserts
// that p.LastBye()'s CSeq header comes back as the typed *sip.CSeqHeader,
// not sipgo's unexported generic header — the same
// h.(*sip.XHeader)-on-a-GetHeaders-result pattern register.go's
// matchingContact uses elsewhere in this codebase. Before the fix, this
// stream's zero-value sip.ParserStream left its unexported headersParsers
// map nil, so every header parsed through it silently degraded to generic
// regardless of whether a typed parser existed for it.
func TestServeStreamConnParsesTypedHeaders(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := Start(t, Config{Addr: "127.0.0.1:0", TLSCert: &leaf})

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	conn, err := tls.Dial("tcp", p.TLSAddr(), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	bye := "BYE sip:test@127.0.0.1 SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS 127.0.0.1:0;branch=z9hG4bK-typedhdr\r\n" +
		"From: <sip:caller@test>;tag=abc\r\n" +
		"To: <sip:test@127.0.0.1>\r\n" +
		"Call-ID: verify-typed-headers@test\r\n" +
		"CSeq: 1 BYE\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(bye)); err != nil {
		t.Fatalf("conn.Write(BYE): %v", err)
	}

	// Reading the 200 OK back guarantees dispatch (and the record() call
	// inside it that sets p.lastBye) has already run server-side — respond()
	// only writes it after record() returns.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("conn.Read: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "SIP/2.0 200") {
		t.Fatalf("response over TLS stream = %q, want a 200 OK status line", string(buf[:n]))
	}

	req := p.LastBye()
	if req == nil {
		t.Fatalf("LastBye() = nil, want the BYE just sent")
	}
	h := req.GetHeader("CSeq")
	if h == nil {
		t.Fatalf("BYE request has no CSeq header")
	}
	if _, ok := h.(*sip.CSeqHeader); !ok {
		t.Fatalf("CSeq header parsed as %T, want *sip.CSeqHeader (a zero-value "+
			"sip.ParserStream leaves headersParsers nil, degrading every header "+
			"parsed through it to a generic header)", h)
	}
}
