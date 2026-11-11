package sipua

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakedns"
)

// CF-180: the digest anchor pins include the A/AAAA addresses of the host's SRV
// targets (RFC 3263 4.2), so an INVITE routed to an SRV target is not withheld.

// useFakeDNS installs a fake DNS zone as the resolver of UAs built afterwards;
// the restore is registered before the UA is built.
func useFakeDNS(t *testing.T, zone map[string][]string) func() []string {
	t.Helper()
	r, queries := fakedns.Start(t, zone)
	old := dnsResolverOverride
	dnsResolverOverride = r
	t.Cleanup(func() { dnsResolverOverride = old })
	return queries
}

func TestSRVTargetAddressIsPinned(t *testing.T) {
	h := newGuardHarness(t, false, func(cfg *Config, p *sippeer.Peer) {
		cfg.AOR = "sip:u@pbx.test"
		useFakeDNS(t, map[string][]string{
			"pbx.test/A":             {"127.0.0.3"},
			"_sip._udp.pbx.test/SRV": {"0 0 " + peerPort(p) + " sip1.pbx.test."},
			"sip1.pbx.test/A":        {"127.0.0.1"},
		})
	})
	h.requireAnswered(t, h.dialTo(t, "sip:bob@pbx.test"))
}

func TestSRVTargetPinsDoNotAdmitAnotherSource(t *testing.T) {
	addr, invites := spoofChallenger(t) // receives on 127.0.0.1, answers from 127.0.0.2
	_, port, _ := net.SplitHostPort(addr)
	h := newGuardHarness(t, false, func(cfg *Config, _ *sippeer.Peer) {
		cfg.AOR = "sip:u@pbx.test"
		useFakeDNS(t, map[string][]string{
			"pbx.test/A":             {"127.0.0.3"},
			"_sip._udp.pbx.test/SRV": {"0 0 " + port + " sip1.pbx.test."},
			"sip1.pbx.test/A":        {"127.0.0.1"},
		})
	})
	fin := h.dialTo(t, "sip:bob@pbx.test")
	if fin.Code != 401 || !strings.HasPrefix(fin.Reason, "credentials withheld: the challenge came from 127.0.0.2") {
		t.Fatalf("final = %d %q, want 401 withheld from 127.0.0.2", fin.Code, fin.Reason)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(invites); n != 1 {
		t.Errorf("responder saw %d INVITEs, want exactly 1", n)
	}
}

func pinStrings(pins []net.IP) []string {
	out := make([]string, len(pins))
	for i, p := range pins {
		out[i] = p.String()
	}
	slices.Sort(out)
	return out
}

func countQueries(log []string, name string) int {
	n := 0
	for _, q := range log {
		if strings.HasPrefix(q, name+"/") {
			n++
		}
	}
	return n
}

func TestPinsForUsesTheHostsSRVTargets(t *testing.T) {
	z := func() map[string][]string {
		return map[string][]string{
			"h.test/A":                 {"10.0.0.1"},
			"_sip._udp.h.test/SRV":     {"0 0 5060 u1.h.test."},
			"u1.h.test/A":              {"10.0.0.2"},
			"_sip._tcp.h.test/SRV":     {"0 0 5060 t1.h.test."},
			"t1.h.test/A":              {"10.0.0.3"},
			"_sips._tcp.h.test/SRV":    {"0 0 5061 s1.h.test."},
			"s1.h.test/A":              {"10.0.0.4"},
			"other.test/A":             {"10.0.0.9"},
			"_sip._udp.other.test/SRV": {"0 0 5060 o1.other.test."},
			"o1.other.test/A":          {"10.0.0.8"},
		}
	}
	type tc struct {
		name      string
		transport string
		zone      func() map[string][]string
		anchor    string
		want      []string // nil: not ok
	}
	zone := func(mod func(m map[string][]string)) func() map[string][]string {
		return func() map[string][]string { m := z(); mod(m); return m }
	}
	cases := []tc{
		{"udp pins the host, udp and tcp targets", "udp", z, "h.test", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"tcp", "tcp", z, "h.test", []string{"10.0.0.1", "10.0.0.3"}},
		{"tls", "tls", z, "h.test", []string{"10.0.0.1", "10.0.0.4"}},
		{"never wider: other.test's target is not h.test's", "udp", z, "other.test", []string{"10.0.0.8", "10.0.0.9"}},
		{"only an A record", "udp", z, "a.test", nil},
		{"no transport service", "", z, "h.test", []string{"10.0.0.1"}},
		{"srv without an A record", "udp", zone(func(m map[string][]string) { delete(m, "h.test/A") }), "h.test", []string{"10.0.0.2", "10.0.0.3"}},
		{"a target without an address, another with one", "udp", zone(func(m map[string][]string) {
			m["_sip._udp.h.test/SRV"] = []string{"0 0 5060 gone.h.test.", "1 0 5060 u1.h.test."}
		}), "h.test", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"dot target alongside a real one", "udp", zone(func(m map[string][]string) {
			m["_sip._udp.h.test/SRV"] = []string{"0 0 0 .", "1 0 5060 u1.h.test."}
		}), "h.test", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"SERVFAIL on one service still yields the rest", "udp", zone(func(m map[string][]string) {
			m["_sip._udp.h.test/SRV"] = []string{"!SERVFAIL"}
		}), "h.test", []string{"10.0.0.1", "10.0.0.3"}},
	}
	// the "only an A record" row needs a host with just an A record
	cases[4].zone = zone(func(m map[string][]string) { m["a.test/A"] = []string{"10.0.0.5"} })
	cases[4].want = []string{"10.0.0.5"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := fakedns.Start(t, c.zone())
			u := &UA{cfg: Config{Transport: c.transport, Timeout: 2 * time.Second}, resolver: r}
			pins, ok := u.pinsFor(context.Background(), c.anchor)
			if !ok {
				t.Fatalf("pinsFor(%s) not ok", c.anchor)
			}
			if got := pinStrings(pins); !slices.Equal(got, c.want) {
				t.Fatalf("pins = %v, want %v", got, c.want)
			}
		})
	}

	t.Run("a host with neither is not ok and not cached", func(t *testing.T) {
		r, queries := fakedns.Start(t, z())
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		if _, ok := u.pinsFor(context.Background(), "nowhere.test"); ok {
			t.Fatal("pinsFor(nowhere.test) ok")
		}
		first := countQueries(queries(), "nowhere.test")
		_, _ = u.pinsFor(context.Background(), "nowhere.test")
		if second := countQueries(queries(), "nowhere.test"); second <= first {
			t.Fatalf("second call did not query again (%d then %d): an empty result was cached", first, second)
		}
	})

	t.Run("a definitive answer is cached", func(t *testing.T) {
		r, queries := fakedns.Start(t, z())
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		_, _ = u.pinsFor(context.Background(), "h.test")
		n := len(queries())
		pins, ok := u.pinsFor(context.Background(), "h.test")
		if !ok || len(pins) != 3 || len(queries()) != n {
			t.Fatalf("second call: ok=%v pins=%v, queries %d -> %d; want the cached set and no query", ok, pins, n, len(queries()))
		}
	})

	t.Run("a transient failure is not cached", func(t *testing.T) {
		m := z()
		m["_sip._udp.h.test/SRV"] = []string{"!SERVFAIL"}
		r, queries := fakedns.Start(t, m)
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		_, _ = u.pinsFor(context.Background(), "h.test")
		first := countQueries(queries(), "_sip._udp.h.test")
		_, _ = u.pinsFor(context.Background(), "h.test")
		if second := countQueries(queries(), "_sip._udp.h.test"); second <= first {
			t.Fatalf("SRV not asked again after a SERVFAIL (%d then %d)", first, second)
		}
	})

	t.Run("at most 16 targets are resolved", func(t *testing.T) {
		m := map[string][]string{"big.test/A": {"10.9.0.1"}}
		var recs []string
		for i := 0; i < 20; i++ {
			name := fmt.Sprintf("t%02d.big.test", i)
			recs = append(recs, fmt.Sprintf("0 0 5060 %s.", name))
			m[name+"/A"] = []string{fmt.Sprintf("10.1.0.%d", i)}
		}
		m["_sip._udp.big.test/SRV"] = recs
		r, queries := fakedns.Start(t, m)
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		pins, ok := u.pinsFor(context.Background(), "big.test")
		if !ok {
			t.Fatal("not ok")
		}
		seen := map[string]bool{}
		for _, q := range queries() {
			if strings.Contains(q, ".big.test/") && strings.HasPrefix(q, "t") {
				seen[q[:strings.Index(q, "/")]] = true
			}
		}
		if len(seen) != maxAnchorSRVTargets {
			t.Fatalf("%d distinct targets resolved, want exactly %d", len(seen), maxAnchorSRVTargets)
		}
		if len(pins) != maxAnchorSRVTargets+1 {
			t.Fatalf("%d pins, want %d (the anchor's A plus %d targets)", len(pins), maxAnchorSRVTargets+1, maxAnchorSRVTargets)
		}
	})

	t.Run("two records naming one target cost one lookup", func(t *testing.T) {
		m := z()
		m["_sip._udp.h.test/SRV"] = []string{"0 0 5060 u1.h.test.", "1 0 5060 U1.H.TEST"}
		r, queries := fakedns.Start(t, m)
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		if _, ok := u.pinsFor(context.Background(), "h.test"); !ok {
			t.Fatal("not ok")
		}
		if n := countQueries(queries(), "u1.h.test"); n != 2 { // one A and one AAAA lookup
			t.Fatalf("%d queries for u1.h.test, want 2 (one lookup = A + AAAA)", n)
		}
	})

	t.Run("an IP literal needs no DNS", func(t *testing.T) {
		r, queries := fakedns.Start(t, z())
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		pins, ok := u.pinsFor(context.Background(), "192.0.2.7")
		if !ok || len(pins) != 1 || len(queries()) != 0 {
			t.Fatalf("pins=%v ok=%v queries=%v", pins, ok, queries())
		}
	})

	t.Run("SRV targets are looked up absolute, as the record names them", func(t *testing.T) {
		r, _ := fakedns.Start(t, z())
		var hosts []string
		setAnchorLookup(t, func(_ context.Context, host string) ([]net.IPAddr, error) {
			hosts = append(hosts, host)
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}, nil
		})
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		if _, ok := u.pinsFor(context.Background(), "h.test"); !ok {
			t.Fatal("not ok")
		}
		for _, want := range []string{"u1.h.test.", "t1.h.test."} {
			if !slices.Contains(hosts, want) {
				t.Errorf("address lookups %v lack the absolute name %q", hosts, want)
			}
		}
	})

	t.Run("an address shared by several targets is pinned once", func(t *testing.T) {
		m := z()
		m["t1.h.test/A"] = []string{"10.0.0.2"} // same as u1.h.test
		r, _ := fakedns.Start(t, m)
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: r}
		pins, _ := u.pinsFor(context.Background(), "h.test")
		if got := pinStrings(pins); !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2"}) {
			t.Fatalf("pins = %v, want 10.0.0.1 and 10.0.0.2 once each", got)
		}
	})

	t.Run("an expired deadline stops the collection", func(t *testing.T) {
		setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}, nil
		})
		u := &UA{cfg: Config{Transport: "udp", Timeout: 2 * time.Second}, resolver: net.DefaultResolver}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if pins, ok := u.pinsFor(ctx, "h.test"); ok {
			t.Fatalf("pinsFor with a dead context returned %v, want not ok", pins)
		}
	})
}
