package sipua_test

// Lane C (rfc-sweep-c) pins for the C-SEC area (RFC 4028 section 11). Each passes
// today and must be inverted when its NEW-C finding is fixed. No test here calls t.Parallel
// (parallel_invariant_test.go).

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

// TestRFC4028_NEWC5_ContactIsSipsOverTLS: NEW-C-5 (C-SEC-03, RFC 4028 11.2:
// "A UA that inserts a Session-Expires header into a request or response
// SHOULD include a Contact URI that is a SIPS URI." rfc4028.txt:1044-1046) is
// fixed by CF-117 (D-117): over TLS the INVITE's Contact is sips: with no
// transport parameter (RFC 3261 26.2.2 deprecates transport=tls).
func TestRFC4028_NEWC5_ContactIsSipsOverTLS(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("tlsca.NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", TLSCert: &leaf})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:             "tls",
		Mode:                  "direct",
		AOR:                   "sip:alice@example",
		Timeout:               2 * time.Second,
		Clock:                 fakeclock.New(time.Unix(0, 0)),
		LocalAddr:             "127.0.0.1:0",
		SessionExpiresS:       90,
		MinSES:                90,
		TLSInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)
	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.TLSAddr()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if got := p.LastRequestHeader("INVITE", "Session-Expires"); got == "" {
		t.Fatal("the INVITE carried no Session-Expires (precondition: the sentence binds a UA that inserts one)")
	}
	contact := p.LastRequestHeader("INVITE", "Contact")
	if !strings.HasPrefix(contact, "<sips:") && !strings.HasPrefix(contact, "sips:") || strings.Contains(contact, "transport=") {
		t.Fatalf("INVITE Contact=%q, want a sips: URI with no transport parameter (CF-117)", contact)
	}
}
