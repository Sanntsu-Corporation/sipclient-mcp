package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func TestNewHTTPServerSetsPreAuthTimeouts(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())

	if srv.Addr != "127.0.0.1:0" {
		t.Errorf("Addr = %q, want %q", srv.Addr, "127.0.0.1:0")
	}
	if srv.Handler == nil {
		t.Error("Handler is nil, want the passed handler")
	}
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", srv.ReadTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", srv.IdleTimeout)
	}
	// WriteTimeout MUST stay unset: call_wait/media_play legitimately hold a
	// response open past any fixed write deadline (spec Non-goals).
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want 0 (unset)", srv.WriteTimeout)
	}
	if srv.BaseContext == nil {
		t.Fatal("BaseContext is nil, want the Background-based func")
	}
	// A cancelable base context here would race in-flight §6.3 waiters
	// ahead of the terminal broadcast that is supposed to wake them — must
	// be context.Background(), never one derived from the daemon context.
	if ctx := srv.BaseContext(nil); ctx == nil || ctx.Done() != nil {
		t.Error("BaseContext() must return context.Background()")
	}
}

// CF-190: a udp UA's stream traffic is tapped and labelled tcp (the pcap
// encoder frames a record as TCP only for tcp/tls); tcp and tls keep theirs.
func TestStreamTapTransportLabelsAUDPUAsStreamTrafficTCP(t *testing.T) {
	for _, c := range []struct{ in, want session.Transport }{
		{session.TransportUDP, session.TransportTCP},
		{session.TransportTCP, session.TransportTCP},
		{session.TransportTLS, session.TransportTLS},
	} {
		if got := streamTapTransport(c.in); got != c.want {
			t.Errorf("streamTapTransport(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
