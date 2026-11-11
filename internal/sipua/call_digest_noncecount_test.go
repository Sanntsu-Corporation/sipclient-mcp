package sipua_test

// P4-D06: ONE nonce-counter, keyed on the nonce, spanning REGISTER and INVITE.
//
// Before this wave the two legs ran through two structurally different digest
// engines: internal/sipua's own doRequestWithDigest/nonceCounter (digestauth.go)
// for REGISTER, and github.com/icholy/digest via
// third_party/sipgo/client.go:438-454's digestAuthApply for INVITE, whose
// digest.Options never sets Count — so the INVITE leg always sent nc=1
// (digest.Options.Count's zero value), regardless of how many requests this UA
// had already authenticated against that nonce.
//
// WHY ONE COUNTER AND NOT TWO (design §3's gate decision). RFC 7616 §3.4.3
// counts nc as a property of the NONCE, not of the method. internal/testutil/peer
// issues ONE nonce (its testNonce) for every method, which is exactly the peer
// class this feature exists for. Two independent counters would each send nc=1
// on that one nonce, and a registrar enforcing monotonicity per nonce rejects
// the second as a replay — the very failure the fix removes.
//
// THE DISCRIMINATOR IS peer.MaxNonceCount(). With one shared counter the
// REGISTER sends nc=1 and the challenged INVITE sends nc=2, so the peer's
// high-water mark is 2. With two counters (or with sipgo's hardcoded zero
// value) it is 1. The assertion cannot pass on the pre-fix code.

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func TestChallengedInviteContinuesTheRegisterNonceCount(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 60,
	})
	clk := fakeclock.New(time.Unix(0, 0))

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
		Clock:              clk,
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
	// The REGISTER leg drew the peer's 401 and answered it with nc=1.
	if got := p.MaxNonceCount(); got != 1 {
		t.Fatalf("after REGISTER, peer saw max nc=%d, want 1 — the shared counter must start at 1", got)
	}

	if _, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	// THE ASSERTION: the INVITE's own 401 was answered with nc=2, continuing the
	// REGISTER leg's count on the SAME nonce.
	if got := p.MaxNonceCount(); got != 2 {
		t.Fatalf("after a challenged INVITE, peer saw max nc=%d, want 2 — the INVITE leg must "+
			"continue the REGISTER leg's nonce-count on this peer's single nonce (RFC 7616 §3.4.3), "+
			"not restart at 1", got)
	}
}
