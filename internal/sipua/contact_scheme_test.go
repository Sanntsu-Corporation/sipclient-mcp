package sipua

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// TestContactSchemeByTransport pins contactAddr, the one helper both Contact
// sites use (CF-117, RFC 4028 11.2 and RFC 3261 26.2.2): a TLS UA advertises a
// sips: URI with no transport parameter; udp and tcp are unchanged.
func TestContactSchemeByTransport(t *testing.T) {
	tests := []struct{ transport, want string }{
		{"udp", "sip:bob@10.0.0.1:5060"},
		{"tcp", "sip:bob@10.0.0.1:5060;transport=tcp"},
		{"tls", "sips:bob@10.0.0.1:5060"},
	}
	for _, tt := range tests {
		got := contactAddr(sip.Uri{User: "bob", Host: "10.0.0.1", Port: 5060}, tt.transport)
		if s := got.String(); s != tt.want {
			t.Errorf("%s: Contact URI = %q, want %q", tt.transport, s, tt.want)
		}
	}
}

// TestRFC4028_AnswerContactIsSipsOverTLS: a TLS UA answering an inbound TLS
// INVITE puts a sips: Contact (no transport parameter) on its 200.
func TestRFC4028_AnswerContactIsSipsOverTLS(t *testing.T) {
	ctx := context.Background()
	callee, err := New(ctx, Config{
		Transport: "tls", Mode: "direct", AOR: "sip:bob@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: clock.System(), Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("New(callee): %v", err)
	}
	defer func() { _ = callee.Close(ctx) }()
	caller, err := New(ctx, Config{
		Transport: "tls", Mode: "direct", AOR: "sip:alice@example", LocalAddr: "127.0.0.1:0",
		Timeout: 2 * time.Second, Clock: clock.System(), Logger: testLogger(),
		TLSInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New(caller): %v", err)
	}
	defer func() { _ = caller.Close(ctx) }()

	inbound := make(chan session.UAEvent, 1)
	callee.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})
	callerEvents := make(chan session.UAEvent, 8)
	caller.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) { callerEvents <- ev })
	if _, err := caller.Dial(ctx, session.DialRequest{ToURI: "sip:bob@" + callee.LocalAddr().String()}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var in session.UAEvent
	select {
	case in = <-inbound:
	case <-time.After(3 * time.Second):
		t.Fatal("callee never observed an inbound INVITE")
	}
	d, err := callee.lookup(in.DialogID)
	if err != nil {
		t.Fatalf("callee.lookup: %v", err)
	}
	spy := &contactCaptureSpy{}
	callee.calls.mu.Lock()
	spy.ServerTransaction = d.serverTx
	d.serverTx = spy
	callee.calls.mu.Unlock()
	if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	res := spy.captured()
	if res == nil || res.GetHeader("Contact") == nil {
		t.Fatal("Answer's 200 OK carries no Contact header")
	}
	got := strings.ToLower(res.GetHeader("Contact").Value())
	if !strings.HasPrefix(got, "<sips:") && !strings.HasPrefix(got, "sips:") || strings.Contains(got, "transport=") {
		t.Errorf("Answer 200 Contact = %q, want a sips: URI with no transport parameter", got)
	}
	// Drain the caller's 200 before the deferred Closes, as
	// TestAnswerContactCarriesTransportParam does: the caller emits it only
	// after its media loop is published, so Close then stops that loop. Closing
	// while the caller is still answering leaves the loop running for the rest
	// of the package run, where it fails TestStopAllMediaLoops... and sends
	// stray RTP to reused ports.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case cev := <-callerEvents:
			if cev.Kind == session.UAEventFinal && cev.Code == 200 {
				return
			}
		case <-deadline:
			t.Fatal("caller never observed a 200 OK")
		}
	}
}
