package sipua

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/tlsca"
)

// CF-054: an INVITE digest challenge is answered only when its SOURCE address is
// one of the addresses the anchor host resolved to, pinned per UA.

// setAnchorLookup installs the anchorLookup seam; t.Cleanup is registered before
// the UA is built by the test (round-one Cycle 3 N1/N2).
func setAnchorLookup(t *testing.T, fn func(ctx context.Context, host string) ([]net.IPAddr, error)) {
	t.Helper()
	old := anchorLookup
	anchorLookup = fn
	t.Cleanup(func() { anchorLookup = old })
	// CF-180: pinsFor also asks DNS for SRV records; answer hermetically so an
	// offline runner does not wait on the host resolver.
	useFakeDNS(t, map[string][]string{"localhost/A": {"127.0.0.1"}})
}

func ipAddrs(ips ...string) []net.IPAddr {
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func localhostAOR(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "sip:u@localhost" }

func peerPort(p *sippeer.Peer) string {
	_, port, _ := net.SplitHostPort(p.Addr())
	return port
}

// finalN waits for the nth UAEventFinal and returns it.
func (h *guardHarness) finalN(t *testing.T, n int) session.UAEvent {
	t.Helper()
	var fin session.UAEvent
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		seen := 0
		for _, ev := range h.events {
			if ev.Kind == session.UAEventFinal {
				seen++
				if seen == n {
					fin = ev
					return true
				}
			}
		}
		return false
	})
	return fin
}

// requireWithheld asserts a withheld challenge with the given reason prefix:
// one INVITE on the wire, no credentials, no secret in the log.
func (h *guardHarness) requireWithheld(t *testing.T, fin session.UAEvent, wantCode int, reasonPrefix string) {
	t.Helper()
	if fin.Code != wantCode {
		t.Errorf("final Code = %d, want %d", fin.Code, wantCode)
	}
	if !strings.HasPrefix(fin.Reason, reasonPrefix) {
		t.Errorf("final Reason = %q, want prefix %q", fin.Reason, reasonPrefix)
	}
	if n := h.peer.Count("INVITE"); n != 1 {
		t.Errorf("peer received %d INVITEs, want exactly 1", n)
	}
	for _, hdr := range []string{"Authorization", "Proxy-Authorization"} {
		if v := h.peer.LastRequestHeader("INVITE", hdr); v != "" {
			t.Errorf("peer saw %s = %q, want none", hdr, v)
		}
	}
	logs := h.log.String()
	if strings.Contains(logs, guardPass) || strings.Contains(logs, "response=") {
		t.Errorf("UA log leaks the password or a digest response:\n%s", logs)
	}
	if !strings.Contains(logs, "digest challenge not answered") {
		t.Errorf("UA log has no Warn for the withheld challenge:\n%s", logs)
	}
}

func TestPinnedAnchorAnswersAChallengeFromTheResolvedAddress(t *testing.T) {
	h := newGuardHarness(t, false, localhostAOR) // anchorLookup nil: the real resolver
	h.requireAnswered(t, h.dialTo(t, "sip:bob@localhost:"+peerPort(h.peer)))
}

func TestChallengeFromAnUnpinnedSourceIsNotAnswered(t *testing.T) {
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) { return ipAddrs("127.0.0.2"), nil })
	h := newGuardHarness(t, false, localhostAOR)
	fin := h.dialTo(t, "sip:bob@localhost:"+peerPort(h.peer))
	h.requireWithheld(t, fin, 401, "credentials withheld: the challenge came from 127.0.0.1")
}

// spoofChallenger is a raw UDP responder on 127.0.0.1 that answers every INVITE
// with a 401 sent from a socket bound to 127.0.0.2 (UDP responses are matched to
// the transaction by branch from ANY source address).
func spoofChallenger(t *testing.T) (addr string, invites chan struct{}) {
	t.Helper()
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = rx.Close() })
	tx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatalf("127.0.0.2 is not bindable here (the spoof tests need it): %v", err)
	}
	t.Cleanup(func() { _ = tx.Close() })

	invites = make(chan struct{}, 4)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := rx.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, perr := sip.ParseMessage(append([]byte(nil), buf[:n]...))
			req, ok := msg.(*sip.Request)
			if perr != nil || !ok || req.Method != sip.INVITE {
				continue
			}
			invites <- struct{}{}
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="x", nonce="abc", algorithm=MD5`))
			_, _ = tx.WriteToUDP([]byte(res.String()), from)
		}
	}()
	return rx.LocalAddr().String(), invites
}

func TestChallengeFromADifferentSourceThanTheAnchorIsNotAnswered(t *testing.T) {
	h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "sip:u@127.0.0.1" })
	addr, invites := spoofChallenger(t)

	fin := h.dialTo(t, "sip:bob@"+addr)
	if fin.Code != 401 || !strings.HasPrefix(fin.Reason, "credentials withheld: the challenge came from 127.0.0.2") {
		t.Fatalf("final = %d %q, want 401 withheld from 127.0.0.2", fin.Code, fin.Reason)
	}
	time.Sleep(300 * time.Millisecond) // bounded window for a (forbidden) second INVITE
	if n := len(invites); n != 1 {
		t.Errorf("responder saw %d INVITEs, want exactly 1", n)
	}
}

// The digest goes to the INVITE's destination, so that destination must be a
// pinned address too: a challenge whose source is forged as a pinned address
// must not make the UA answer an INVITE that went somewhere else (the name now
// resolves to a different address than the one pinned).
func TestAChallengeForgedFromAPinnedSourceDoesNotUnlockAnUnpinnedDestination(t *testing.T) {
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) { return ipAddrs("127.0.0.2"), nil })
	h := newGuardHarness(t, false, localhostAOR)
	addr, invites := spoofChallenger(t) // the INVITE goes to 127.0.0.1; the 401 claims 127.0.0.2
	_, port, _ := net.SplitHostPort(addr)

	fin := h.dialTo(t, "sip:bob@localhost:"+port)
	if fin.Code != 401 || !strings.HasPrefix(fin.Reason, "credentials withheld: the INVITE was sent to 127.0.0.1") {
		t.Fatalf("final = %d %q, want 401 withheld because the INVITE went to 127.0.0.1", fin.Code, fin.Reason)
	}
	time.Sleep(300 * time.Millisecond) // bounded window for a (forbidden) second INVITE
	if n := len(invites); n != 1 {
		t.Errorf("responder saw %d INVITEs, want exactly 1 (no authenticated retry to the unpinned address)", n)
	}
}

func TestIPLiteralAnchorIsPinnedWithoutDNS(t *testing.T) {
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("anchorLookup called for an IP-literal anchor")
		return nil, errors.New("must not be called")
	})
	h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "sip:u@127.0.0.1" })
	h.requireAnswered(t, h.dial(t))
}

func TestAnchorResolutionFailureWithholdsCredentials(t *testing.T) {
	var calls atomic.Int32
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("injected resolver failure")
		}
		return ipAddrs("127.0.0.1"), nil
	})
	h := newGuardHarness(t, false, localhostAOR)
	to := "sip:bob@localhost:" + peerPort(h.peer)
	h.requireWithheld(t, h.dialTo(t, to), 401, "credentials withheld: localhost could not be resolved to pin the challenge source")
	if _, err := h.ua.Dial(context.Background(), session.DialRequest{ToURI: to}); err != nil {
		t.Fatalf("Dial 2: %v", err)
	}
	if fin := h.finalN(t, 2); fin.Code != 200 {
		t.Fatalf("dial 2 final = %d %q, want 200 (the failure must not be cached)", fin.Code, fin.Reason)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("anchorLookup called %d times, want 2", n)
	}
}

func TestAnchorIsResolvedOncePerUA(t *testing.T) {
	var calls atomic.Int32
	var answer atomic.Value
	answer.Store("127.0.0.1")
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
		calls.Add(1)
		return ipAddrs(answer.Load().(string)), nil
	})
	h := newGuardHarness(t, false, localhostAOR)
	to := "sip:bob@localhost:" + peerPort(h.peer)
	h.requireAnswered(t, h.dialTo(t, to))
	answer.Store("127.0.0.2") // DNS changes after the pin
	if _, err := h.ua.Dial(context.Background(), session.DialRequest{ToURI: to}); err != nil {
		t.Fatalf("Dial 2: %v", err)
	}
	if fin := h.finalN(t, 2); fin.Code != 200 {
		t.Fatalf("dial 2 final = %d %q, want 200 (the pin holds)", fin.Code, fin.Reason)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("anchorLookup called %d times, want exactly 1", n)
	}
}

func TestEveryResolvedAddressIsPinned(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []string
	}{
		{"source is the last record", []string{"::1", "127.0.0.2", "127.0.0.1"}},
		{"IPv4-mapped form", []string{"::ffff:127.0.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) { return ipAddrs(tc.ips...), nil })
			h := newGuardHarness(t, false, localhostAOR)
			h.requireAnswered(t, h.dialTo(t, "sip:bob@localhost:"+peerPort(h.peer)))
		})
	}
}

func TestAuthAnyHostSkipsThePin(t *testing.T) {
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("anchorLookup called with auth_any_host set")
		return nil, errors.New("must not be called")
	})
	h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) {
		cfg.AOR = "sip:u@localhost"
		cfg.AuthAnyHost = true
	})
	h.requireAnswered(t, h.dialTo(t, "sip:bob@localhost:"+peerPort(h.peer)))
}

func TestTwoSimultaneousFirstChallengesAreBothAnswered(t *testing.T) {
	var calls atomic.Int32
	both := make(chan struct{})
	var once sync.Once
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
		if calls.Add(1) == 2 {
			once.Do(func() { close(both) })
		}
		select {
		case <-both:
		case <-time.After(time.Second):
		}
		return ipAddrs("127.0.0.1"), nil
	})
	h := newGuardHarness(t, false, localhostAOR)
	to := "sip:bob@localhost:" + peerPort(h.peer)
	for i := 0; i < 2; i++ {
		if _, err := h.ua.Dial(context.Background(), session.DialRequest{ToURI: to}); err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
	}
	for n := 1; n <= 2; n++ {
		if fin := h.finalN(t, n); fin.Code != 200 {
			t.Fatalf("final %d = %d %q, want 200", n, fin.Code, fin.Reason)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("anchorLookup called %d times, want 2 (both first challenges inside the lookup)", n)
	}
	if _, err := h.ua.Dial(context.Background(), session.DialRequest{ToURI: to}); err != nil {
		t.Fatalf("Dial 3: %v", err)
	}
	if fin := h.finalN(t, 3); fin.Code != 200 {
		t.Fatalf("final 3 = %d %q, want 200", fin.Code, fin.Reason)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("anchorLookup called %d times after a third dial, want still 2 (the stored pin is read)", n)
	}
}

func TestAnchorOnAnotherPortIsAnswered(t *testing.T) {
	h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) { cfg.AOR = "sip:u@127.0.0.1:1" })
	h.requireAnswered(t, h.dial(t))
}

func TestPinnedSourceMatching(t *testing.T) {
	ip := net.ParseIP
	for _, tc := range []struct {
		name      string
		pins      []net.IP
		source    string
		wantShown string
		wantOK    bool
	}{
		{"IPv6 source, IPv6 pin", []net.IP{ip("::1")}, "[::1]:5060", "::1", true},
		{"IPv6 source, IPv4 pin", []net.IP{ip("127.0.0.1")}, "[::1]:5060", "::1", false},
		{"IPv4 source, IPv4-mapped pin", []net.IP{ip("::ffff:127.0.0.1")}, "127.0.0.1:5060", "127.0.0.1", true},
		{"zoned source fails closed", []net.IP{ip("fe80::1")}, "[fe80::1%eth0]:5060", "fe80::1%eth0", false},
		{"unparsable source fails closed", []net.IP{ip("127.0.0.1")}, "not-an-address", "not-an-address", false},
		{"empty pins", nil, "127.0.0.1:5060", "127.0.0.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shown, ok := pinnedSource(tc.pins, tc.source)
			if shown != tc.wantShown || ok != tc.wantOK {
				t.Fatalf("pinnedSource(%v, %q) = (%q, %v), want (%q, %v)", tc.pins, tc.source, shown, ok, tc.wantShown, tc.wantOK)
			}
		})
	}
}

// TLS inherits TCP's parse path; the connection's remote address is the source.
func TestPinnedAnchorOverTLS(t *testing.T) {
	ca, err := tlsca.NewCA()
	if err != nil {
		t.Fatalf("tlsca.NewCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(tlsca.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", AuthUser: "bob", AuthPass: guardPass, TLSCert: &leaf})
	h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) {
		cfg.Transport = "tls"
		cfg.AOR = "sip:u@127.0.0.1"
		cfg.TLSInsecureSkipVerify = true
	})
	fin := h.dialTo(t, "sip:bob@"+p.TLSAddr())
	if fin.Code != 200 {
		t.Fatalf("final = %d %q, want 200 (challenge from the pinned address over TLS)", fin.Code, fin.Reason)
	}
	if p.LastRequestHeader("INVITE", "Authorization") == "" && p.LastRequestHeader("INVITE", "Proxy-Authorization") == "" {
		t.Error("the answered INVITE carried no credentials")
	}
}
