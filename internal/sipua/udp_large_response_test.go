package sipua_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestRFC3261_CF168_LargeResponseToAUDPRequestIsSent: a response over 1300
// bytes to a UDP request is sent (RFC 3261 18.1.1: the 1300-byte rule binds
// requests; a response cannot change transport).
func TestRFC3261_CF168_LargeResponseToAUDPRequestIsSent(t *testing.T) {
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	const n = 20
	var extra strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&extra, "Record-Route: <sip:rr-%02d-%s.example;lr>\r\n", i, strings.Repeat("a", 60))
	}
	extra.WriteString("Content-Length: 0\r\n\r\n")
	resp := rawOptions(t, ua.BoundAddr().String(), "127.0.0.1:PORT", extra.String())
	if len(resp) <= 1300 {
		t.Fatalf("response is %d bytes, want more than 1300", len(resp))
	}
	for i := 0; i < n; i++ {
		if !strings.Contains(resp, fmt.Sprintf("rr-%02d-", i)) {
			t.Fatalf("response lacks Record-Route %d", i)
		}
	}
}
