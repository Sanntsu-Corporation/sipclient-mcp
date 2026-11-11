package sipua_test

// Lane A (rfc-sweep-a) pins for the A-REG area. Each passes today and must be
// inverted when its NEW-A finding is fixed.
// No test here calls t.Parallel (parallel_invariant_test.go).

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestRFC3261Pin_NEWA13_ChallengedInviteCredentialsAreNotReused pins NEW-A-13
// (A-REG-21, RFC 3261 22.2: "UAs SHOULD cache the credentials for a given value
// of the To header field and "realm" and attempt to re-use these values on the
// next request for that destination." rfc3261.txt:10939-10943). Evidence:
// evidence/corpus-udp/queries.txt R-REG-6 and evidence/corpus-udp/02/excerpt.txt
// frame 1-4. Two calls to one destination draw one 401 each: the peer sees four
// INVITEs. A compliant UA sends three (the second call's first INVITE already
// carries the cached credentials).
//
// PIN OF A DEVIATION: invert this assertion when NEW-A-13 is fixed.
func TestRFC3261Pin_NEWA13_ChallengedInviteCredentialsAreNotReused(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "register",
		AOR:                "sip:alice@example",
		Registrar:          "sip:" + p.Addr(),
		AuthUser:           "alice",
		AuthPass:           "s3cr3t",
		ExpiresS:           60,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              fakeclock.New(time.Unix(0, 0)),
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	events := collect(t, ua)
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for call := 1; call <= 2; call++ {
		if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
			t.Fatalf("Dial %d: %v", call, err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for finals200(events()) < call && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if finals200(events()) < call {
			t.Fatalf("call %d never drew a 200", call)
		}
	}
	n := p.Count("INVITE")
	t.Logf("peer saw %d INVITEs for two calls", n)
	if n < 4 {
		t.Errorf("peer saw %d INVITEs for two calls, fewer than one 401 round trip each: NEW-A-13 is fixed, invert this pin", n)
	}
}

func finals200(evs []session.UAEvent) int {
	n := 0
	for _, ev := range evs {
		if ev.Kind == session.UAEventFinal && ev.Code == 200 {
			n++
		}
	}
	return n
}
