package sipua_test

// Lane D (rfc-sweep-d) pins for wire deviations in RFC 4566 rows (6a D11). Each
// passes today and must be inverted when its NEW-D finding is fixed. No test here calls t.Parallel
// (parallel_invariant_test.go).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestSipuaOfferCarriesSDESWheneverSRTPIsRequired_GuardIsAtUACreate pins NEW-D-3 (D-SSEC-06,
// RFC 4566 7: "SDP MUST NOT be used to convey key material, unless it can be
// guaranteed that the channel over which the SDP is delivered is both private
// and authenticated." rfc4566.txt:1780-1782). Evidence:
// evidence/rg-srtp/excerpt.txt frame 4 (our INVITE over UDP SIP, m=audio ...
// RTP/SAVP with a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<key>). Locus:
// internal/media/sdp.go:BuildOffer (GenerateCryptoAttr), bytes emitted via the
// INVITE body in internal/sipua/call.go. Design: the documented limitation of
// the design spec, line 96 (WARN 18.7).
//
// CF-134 / D-134: the guard is at session.UACreate, which refuses srtp over a
// non-TLS transport unless allow_cleartext_sdes (compliance test:
// TestRFC4566_NEWD3_UACreateRefusesSDESOverNonTLS in internal/session). The
// sipua layer stays permissive by design: this test builds the UA below
// UACreate and pins that the offer carries SDES whenever SRTP is required.
func TestSipuaOfferCarriesSDESWheneverSRTPIsRequired_GuardIsAtUACreate(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
	// The peer answers plain RTP/AVP, so Dial's outcome is not the assertion:
	// the INVITE the peer received is.
	_, _ = ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	waitForCond(t, func() bool { return p.Count("INVITE") > 0 })
	body := string(p.LastInviteBody())
	if !strings.Contains(body, "a=crypto:") {
		t.Fatalf("UDP INVITE body %q carries no a=crypto: line: the sipua layer no longer offers SDES", body)
	}
	if !strings.Contains(body, "RTP/SAVP") {
		t.Fatalf("UDP INVITE body %q is not RTP/SAVP (control: SRTP required must offer SAVP)", body)
	}
}
