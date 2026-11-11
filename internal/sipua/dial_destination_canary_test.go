package sipua

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestDialInviteDestinationMatchesTheDialledTarget is HIGH-1's regression
// canary (locked decision: destination pinning via req.SetDestination is OUT
// OF SCOPE for sipua.Dial). session.validateHeaders
// (internal/session/input.go) now rejects every Route/Record-Route/Via/...
// header before CallDial ever calls into this package, so no production path
// can build an outbound INVITE whose Route header overrides sipgo's own
// next-hop resolution (sip/request.go's Request.Destination(), consumed by
// sip/transport_layer.go). Once no Route header can be constructed, sipgo's
// own Request-URI resolution is ALREADY CORRECT, and pinning the destination
// here (SetDestination) would replace that resolution — port defaulting,
// future SRV/TLS handling — with a reimplementation: a behaviour-change risk
// for no additional security benefit.
//
// THIS TEST DOES NOT EXERCISE session's validation AT ALL (that is
// input_test.go's and toolservice_test.go's job, and the whole point of the
// fix living in session, not here — Rule 18). It pins the INVARIANT
// directly at this layer instead: an ordinary Dial produces an INVITE whose
// resolved Destination() is exactly the dialled host:port, with no Route (or
// anything else) able to steer it elsewhere. Any FUTURE change to this
// package — a new header injected here, a Route added for some load-
// balancing feature, anything — that reopens the hole trips this test at
// zero behaviour risk to the shipped Dial path.
func TestDialInviteDestinationMatchesTheDialledTarget(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	ua, err := New(context.Background(), Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              fakeclock.New(time.Unix(0, 0)),
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	final := make(chan session.UAEvent, 4)
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventFinal {
			final <- ev
		}
	})

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// d.invite is set once, at dialog creation, before Dial returns — reading
	// it here (via the same u.lookup other in-package tests use, e.g.
	// call_answerclaim_test.go) races with nothing: runDial's goroutine never
	// mutates it.
	d, err := ua.lookup(res.DialogID)
	if err != nil {
		t.Fatalf("lookup(%q): %v", res.DialogID, err)
	}
	if got := d.invite.Destination(); got != p.Addr() {
		t.Errorf("outbound INVITE Destination() = %q, want %q (the dialled host:port) — "+
			"a mismatch means something can once again steer the real next hop away from "+
			"the address to_uri/policy.CheckDestination approved", got, p.Addr())
	}

	// Let the transaction actually settle before Cleanup tears the UA down,
	// so no goroutine outlives the test.
	select {
	case <-final:
	case <-time.After(3 * time.Second):
		t.Fatal("no final event; the peer's response never reached the UA")
	}
}
