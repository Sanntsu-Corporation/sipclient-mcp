package sipua

// Internal (package sipua) unit test for keepaliveTarget — Task 26
// correction 8. keepaliveTarget only reads u.cfg, so a bare *UA literal is
// enough; no network bind is needed and binding port 5060 in the sandbox
// would be unreliable.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

func TestKeepaliveTargetDefaultsThePort(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "portless sip registrar defaults to 5060",
			cfg:  Config{Mode: "register", Registrar: "sip:pbx.example.com"},
			want: "pbx.example.com:5060",
		},
		{
			name: "portless sips registrar defaults to 5061",
			cfg:  Config{Mode: "register", Registrar: "sips:pbx.example.com"},
			want: "pbx.example.com:5061",
		},
		{
			name: "an explicit port is left alone",
			cfg:  Config{Mode: "register", Registrar: "sip:pbx.example.com:5070"},
			want: "pbx.example.com:5070",
		},
		{
			name: "direct mode has no target",
			cfg:  Config{Mode: "direct", Registrar: ""},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &UA{cfg: tc.cfg}
			if got := u.keepaliveTarget(); got != tc.want {
				t.Fatalf("keepaliveTarget() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCrlfUnsupportedRecognisesAWrappedSentinel is D20 D-M5's acceptance
// criterion: the crlf->OPTIONS fallback used to compare a Do error against
// errCRLFUnsupported with `==`, safe today only because sendCRLFKeepalive's
// own `return errCRLFUnsupported` is unwrapped — but sibling error returns in
// this file already wrap with %w, and a comparison that only survives the
// unwrapped case is one signature change away from silently breaking the
// fallback. A double standing in for a wrapped return (one level of %w) is
// deliberately NOT == the sentinel, so it proves crlfUnsupported (errors.Is)
// recognises what `==` would have missed, not merely that today's unwrapped
// case still works.
func TestCrlfUnsupportedRecognisesAWrappedSentinel(t *testing.T) {
	wrapped := fmt.Errorf("keepalive: crlf: %w", errCRLFUnsupported)

	if wrapped == errCRLFUnsupported {
		t.Fatal("test double must NOT be == the sentinel — otherwise this proves nothing " +
			"about errors.Is over ==")
	}
	if !crlfUnsupported(wrapped) {
		t.Fatal("crlfUnsupported must recognise a wrapped errCRLFUnsupported via errors.Is")
	}
	if !errors.Is(wrapped, errCRLFUnsupported) {
		t.Fatal("sanity: errors.Is must itself recognise the wrap")
	}
}

// TestKeepaliveSenderResolvesExactlyTheImplementedModes is Cycle 5's
// acceptance criterion: keepaliveSender is now the ONE function
// startKeepalive's arming gate and sendKeepalive's dispatch both resolve
// through, so this pins its contract directly rather than only through the
// two callers. "" and "none" are included to record that keepaliveSender
// itself treats them like any other unimplemented string (nil) — it is
// startKeepalive's OWN separate early return, not keepaliveSender's
// nil-ness, that gives them their special "do not arm" (rather than "not
// implemented") meaning.
func TestKeepaliveSenderResolvesExactlyTheImplementedModes(t *testing.T) {
	u := &UA{}
	if u.keepaliveSender("crlf") == nil {
		t.Fatal(`keepaliveSender("crlf") = nil, want non-nil`)
	}
	if u.keepaliveSender("options") == nil {
		t.Fatal(`keepaliveSender("options") = nil, want non-nil`)
	}
	if u.keepaliveSender("bogus") != nil {
		t.Fatal(`keepaliveSender("bogus") = non-nil, want nil`)
	}
	if u.keepaliveSender("") != nil {
		t.Fatal(`keepaliveSender("") = non-nil, want nil (see doc comment)`)
	}
	if u.keepaliveSender("none") != nil {
		t.Fatal(`keepaliveSender("none") = non-nil, want nil (see doc comment)`)
	}
}

// CF-188: the CRLF keepalive follows the destination the last answered
// REGISTER was sent to, and falls back to keepaliveTarget() before any.
func TestCRLFKeepaliveFollowsTheLatestRegisterDestination(t *testing.T) {
	u, err := New(context.Background(), Config{
		Transport: "udp", Mode: "register", AOR: "sip:alice@example", Registrar: "sip:127.0.0.1:1",
		Keepalive: "crlf", Timeout: time.Second, Clock: clock.System(), LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = u.Close(context.Background()) }()
	listen := func() net.PacketConn {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		return pc
	}
	got := func(pc net.PacketConn) bool {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 16)
		n, _, err := pc.ReadFrom(buf)
		return err == nil && string(buf[:n]) == "\r\n\r\n"
	}
	setDest := func(d string) {
		u.reg.mu.Lock()
		u.reg.dest = d
		u.reg.mu.Unlock()
	}
	a, b := listen(), listen()
	for name, pc := range map[string]net.PacketConn{"A": a, "B": b} {
		setDest(pc.LocalAddr().String())
		if err := u.sendCRLFKeepalive(); err != nil {
			t.Fatalf("send to %s: %v", name, err)
		}
		if !got(pc) {
			t.Fatalf("the CRLF did not reach %s (%s)", name, pc.LocalAddr())
		}
	}
	setDest("")
	if err := u.sendCRLFKeepalive(); err != nil {
		t.Fatalf("send with no destination: %v", err)
	}
	if got(a) || got(b) {
		t.Fatal("with no recorded destination the CRLF went to a previously recorded one")
	}
}

func TestKeepaliveOptionsURIIsTheRegistrarAsConfigured(t *testing.T) {
	for registrar, want := range map[string]string{
		"sip:reg.test":               "sip:reg.test",
		"SIPS:reg.test:5061":         "sips:reg.test:5061",
		"Sip:[::1]":                  "sip:[::1]",
		"reg.test":                   "sip:reg.test",
		"sip:alice@reg.test":         "sip:reg.test",
		"sip:reg.test;transport=tcp": "sip:reg.test",
	} {
		u := &UA{cfg: Config{Registrar: registrar}}
		uri, err := u.keepaliveOptionsURI()
		if err != nil {
			t.Errorf("%q: %v", registrar, err)
			continue
		}
		if got := uri.String(); got != want {
			t.Errorf("keepaliveOptionsURI(%q) = %q, want %q", registrar, got, want)
		}
	}
}
