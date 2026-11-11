package sipua

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// CF-046 (D-C): runDial answers an INVITE digest challenge only when the INVITE
// target host is the account's registrar/AOR host, or the UA has AuthAnyHost.

const guardPass = "s3cr3t-guard-pw"

const guardReason = "credentials withheld: 127.0.0.1 is not this account's registrar or AOR host (ua_create auth_any_host allows it)"

// lockedBuf is a bytes.Buffer safe for a logger written from UA goroutines.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// guardHarness is a challenging peer plus a UA built from cfg, with its events
// and its log captured.
type guardHarness struct {
	peer   *sippeer.Peer
	ua     *UA
	log    *lockedBuf
	mu     sync.Mutex
	events []session.UAEvent
}

func newGuardHarness(t *testing.T, proxyAuth bool, mutate func(cfg *Config, p *sippeer.Peer)) *guardHarness {
	t.Helper()
	h := &guardHarness{log: &lockedBuf{}}
	h.peer = sippeer.Start(t, sippeer.Config{
		Addr: "127.0.0.1:0", AuthUser: "bob", AuthPass: guardPass,
		Behaviour: sippeer.Behaviour{ProxyAuthInvite: proxyAuth},
	})
	cfg := Config{
		Transport: "udp", Mode: "direct", AuthUser: "bob", AuthPass: guardPass, ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		MediaPortRange: [2]int{16384, 32767},
		Logger:         slog.New(slog.NewTextHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	mutate(&cfg, h.peer)
	ua, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.ua = ua
	t.Cleanup(func() {
		_ = ua.Close(context.Background())
		deadline := time.Now().Add(5 * time.Second)
		for ua.RegisteredDialogCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	})
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		h.mu.Lock()
		h.events = append(h.events, ev)
		h.mu.Unlock()
	})
	return h
}

// dial dials the peer and returns the first UAEventFinal.
func (h *guardHarness) dial(t *testing.T) session.UAEvent {
	t.Helper()
	return h.dialTo(t, "sip:bob@"+h.peer.Addr())
}

// dialTo dials toURI and returns the first UAEventFinal.
func (h *guardHarness) dialTo(t *testing.T, toURI string) session.UAEvent {
	t.Helper()
	if _, err := h.ua.Dial(context.Background(), session.DialRequest{ToURI: toURI}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var fin session.UAEvent
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, ev := range h.events {
			if ev.Kind == session.UAEventFinal {
				fin = ev
				return true
			}
		}
		return false
	})
	return fin
}

func (h *guardHarness) finals() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, ev := range h.events {
		if ev.Kind == session.UAEventFinal {
			n++
		}
	}
	return n
}

// requireRefused asserts the peer's view and the UA's view of a withheld challenge.
func (h *guardHarness) requireRefused(t *testing.T, fin session.UAEvent, wantCode int) {
	t.Helper()
	if fin.Code != wantCode {
		t.Errorf("final Code = %d, want %d", fin.Code, wantCode)
	}
	if fin.Reason != guardReason {
		t.Errorf("final Reason = %q, want %q", fin.Reason, guardReason)
	}
	if n := h.peer.Count("INVITE"); n != 1 {
		t.Errorf("peer received %d INVITEs, want exactly 1 (no authenticated retry)", n)
	}
	for _, hdr := range []string{"Authorization", "Proxy-Authorization"} {
		if v := h.peer.LastRequestHeader("INVITE", hdr); v != "" {
			t.Errorf("peer saw %s = %q on an INVITE, want none", hdr, v)
		}
	}
	if n := h.finals(); n != 1 {
		t.Errorf("%d UAEventFinal events, want exactly 1", n)
	}
	logs := h.log.String()
	if strings.Contains(logs, guardPass) || strings.Contains(logs, "response=") {
		t.Errorf("UA log leaks the password or a digest response:\n%s", logs)
	}
	if !strings.Contains(logs, "digest challenge not answered") {
		t.Errorf("UA log has no Warn for the refused challenge:\n%s", logs)
	}
}

// requireAnswered asserts the retried INVITE carried credentials and the call was answered.
func (h *guardHarness) requireAnswered(t *testing.T, fin session.UAEvent) {
	t.Helper()
	if fin.Code != 200 {
		t.Fatalf("final Code = %d (%q), want 200", fin.Code, fin.Reason)
	}
	if h.peer.LastRequestHeader("INVITE", "Authorization") == "" &&
		h.peer.LastRequestHeader("INVITE", "Proxy-Authorization") == "" {
		t.Error("the answered INVITE carried no credentials")
	}
}

func registerAt(registrar string) func(*Config, *sippeer.Peer) {
	return func(cfg *Config, _ *sippeer.Peer) {
		cfg.Mode = "register"
		cfg.AOR = "sip:bob@example"
		cfg.Registrar = registrar
	}
}

func TestChallengeFromANonAnchorHostIsNotAnswered(t *testing.T) {
	for _, tc := range []struct {
		name      string
		proxyAuth bool
		code      int
	}{{"401", false, 401}, {"407", true, 407}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGuardHarness(t, tc.proxyAuth, registerAt("sip:192.0.2.1:5060"))
			h.requireRefused(t, h.dial(t), tc.code)
		})
	}
}

func TestRefusedChallengeConsumesNoNonceCount(t *testing.T) {
	h := newGuardHarness(t, false, registerAt("sip:192.0.2.1:5060"))
	h.requireRefused(t, h.dial(t), 401)
	c := &h.ua.nonceCounter
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.registrar.count != 0 {
		t.Errorf("registrar slot = %+v after a refused challenge, want unused", c.registrar)
	}
	for i, s := range c.invites {
		if s.count != 0 {
			t.Errorf("invite slot %d = %+v after a refused challenge, want unused", i, s)
		}
	}
}

func TestChallengeFromTheRegistrarHostIsAnswered(t *testing.T) {
	h := newGuardHarness(t, false, func(cfg *Config, p *sippeer.Peer) {
		registerAt("sip:"+p.Addr())(cfg, p)
	})
	// The registrar is the peer itself: register first so the UA is a real
	// register-mode account, then dial it.
	if _, err := h.ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h.requireAnswered(t, h.dial(t))
}

func TestAuthAnyHostAnswersAnyChallenge(t *testing.T) {
	h := newGuardHarness(t, false, func(cfg *Config, p *sippeer.Peer) {
		registerAt("sip:192.0.2.1:5060")(cfg, p)
		cfg.AuthAnyHost = true
	})
	h.requireAnswered(t, h.dial(t))
}

// TestDirectModeCallerAORIsAnAnchor pins direct-daemon behaviour (D-C1 (2),
// D-C3): a caller-supplied AOR host is an anchor and a caller-supplied
// AuthAnyHost is honoured; the port is ignored (D-C5).
func TestDirectModeCallerAORIsAnAnchor(t *testing.T) {
	t.Run("AOR host is the target host", func(t *testing.T) {
		h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "sip:u@127.0.0.1" })
		h.requireAnswered(t, h.dial(t))
	})
	t.Run("caller override honoured", func(t *testing.T) {
		h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) {
			cfg.AOR = "sip:u@192.0.2.1"
			cfg.AuthAnyHost = true
		})
		h.requireAnswered(t, h.dial(t))
	})
	t.Run("other AOR host without override is refused", func(t *testing.T) {
		h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "sip:u@192.0.2.1" })
		h.requireRefused(t, h.dial(t), 401)
	})
}

// TestDirectAccountShapeWithoutAORWithholdsCredentials uses exactly the fields
// the proxy's Inject forwards for a direct account (no aor, no registrar): it
// has no anchor, so it answers nothing unless auth_any_host is set (D-C2).
func TestDirectAccountShapeWithoutAORWithholdsCredentials(t *testing.T) {
	shape := func(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "" }
	t.Run("no override", func(t *testing.T) {
		h := newGuardHarness(t, false, shape)
		h.requireRefused(t, h.dial(t), 401)
	})
	t.Run("with auth_any_host", func(t *testing.T) {
		h := newGuardHarness(t, false, func(cfg *Config, p *sippeer.Peer) {
			shape(cfg, p)
			cfg.AuthAnyHost = true
		})
		h.requireAnswered(t, h.dial(t))
	})
}
