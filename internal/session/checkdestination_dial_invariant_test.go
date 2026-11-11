package session

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// recordingDialAgent is a nopAgent whose Dial records the EXACT ToURI it
// received onto dialCh, so the test can inspect the string that actually
// reached the wire without importing sipgo into this package's test binary.
// internal/importguard forbids that (contract:122: internal/session's tests
// must run entirely on fakes, engine imports are the engine layer's alone) —
// an earlier attempt at this test that parsed URIs with sipgo tripped that
// gate. A recording fake sidesteps it entirely.
type recordingDialAgent struct {
	nopAgent
	dialCh chan string
}

func (a *recordingDialAgent) Dial(_ context.Context, req DialRequest) (DialResult, error) {
	a.dialCh <- req.ToURI
	return DialResult{DialogID: "dlg-invariant", CallID: "cid-invariant"}, nil
}

// wrapBracket optionally wraps uri in a single angle-bracket name-addr pair —
// never nested, since a nested pair is one of the five axes and is expected
// to be rejected before CheckDestination ever runs.
func wrapBracket(uri string, bracket bool) string {
	if !bracket {
		return uri
	}
	return "<" + uri + ">"
}

// generateInvariantHosts returns 54 host forms — plain, mixed-case, IPv4,
// IPv4:port, IPv6-literal, IPv6-literal:port and multi-label domains — so
// policy.Normalise's host case-fold and scheme-prepend are both exercised
// across many shapes, not just the handful §10.3's examples name.
func generateInvariantHosts() []string {
	hosts := make([]string, 0, 54)
	for i := 0; i < 40; i++ {
		h := fmt.Sprintf("host%03d.example", i)
		switch {
		case i%3 == 0:
			h = strings.ToUpper(h)
		case i%5 == 0:
			h = strings.ToUpper(h[:4]) + h[4:]
		}
		hosts = append(hosts, h)
	}
	hosts = append(hosts,
		"192.0.2.10", "192.0.2.10:5060", "203.0.113.5:8080",
		"[2001:db8::1]", "[2001:db8::1]:5060", "[2001:db8::42]:5061",
		"LAB.internal", "Lab.Internal", "lab.internal",
		"sub.domain.example", "a.b.c.example:9999",
		"deep.sub.domain.example.org", "UPPER.EXAMPLE.ORG", "MiXeD.CaSe.example.net",
	)
	return hosts
}

// buildInvariantCorpus assembles the corpus Task 11d's charter requires: all
// five to_uri bypass axes (D72 rounds 1-4, copied literally from the same
// literal strings toolservice_test.go's four axis tests use, so this test
// exercises the exact evasions that were proved live, not a paraphrase of
// them), every §10.3-permitted form (from TestCallDialRound2ToURIEvasions's
// "permitted" table), a sample of Unicode whitespace runes and
// length-changing-lowercase runes at extra positions, and a broad
// combinatorial set over scheme x user x host x bracket-depth.
func buildInvariantCorpus() []string {
	var corpus []string

	// The five axis inputs (D72 rounds 1-4), copied verbatim from
	// TestCallDialClosesTheSipsSchemeBypass, TestCallDialRound2ToURIEvasions,
	// TestCallDialRound3SemicolonQuestionMarkEvasions and
	// TestCallDialRound4UnicodeCaseFoldEvasions.
	corpus = append(corpus,
		"sips:19005550123@example.net",
		"SIPS:19005550123@example.net",
		"sip:x@lab.internal\r\nINVITE sip:evil@a.b SIP/2.0",
		"<sips:19005550123@example.net>",
		"<sips:lab.internal>",
		"<<sips:19005550123.example.net>>",
		"\u00a0sips:19005550123.example.net",
		"< sips:19005550123.example.net>",
		"\u0085sips:19005550123.example.net",
		"\u2000sips:19005550123.example.net",
		"\u3000sips:19005550123.example.net",
		"\u1680sips:19005550123.example.net",
		"\u00a0<sips:19005550123.example.net>",
		";evil.example",
		"?evil.example",
		";sips:evil.example",
		";sip:evil.example",
		"s\u0130p:19005550123@example.net",
		"s\u0130p:lab.internal",
		"s\u0130p:",
		"s\u0130p:lab%2Einternal",
	)

	// Every §10.3-permitted form.
	corpus = append(corpus,
		"sip:lab.internal",
		"<sip:lab.internal>",
		"sip:alice@lab.internal:5060",
		"192.0.2.10:5060",
		"sip:sips@h",
		"sip:x@sips.example",
		"sip:[2001:db8::1]:5060",
		"SIP:lab.internal",
	)

	// A broader sample of whitespace-rune and length-changing-lowercase-rune
	// positions than the literal axis inputs above cover (mid-host and
	// trailing, not just leading/scheme position). All expected rejected by
	// validateToURI today; included so the corpus, and the invariant, cover
	// them too rather than only the scheme-prefix position.
	for _, r := range []string{"\u00a0", "\u2028", "\u3000"} {
		corpus = append(corpus,
			"sip:x@lab"+r+".internal",
			"sip:x@lab.internal"+r,
		)
	}
	for _, r := range []string{"\u0130", "\u023a", "\u023e"} {
		corpus = append(corpus,
			"sip:x@lab"+r+".internal",
			"sip:"+r+"@lab.internal",
		)
	}

	// The combinatorial core: scheme x user x host x bracket-depth. None of
	// these matches the deny-only fixture's `^sip:\+?1900` pattern (no user
	// or host below starts with "1900"), so absent a regression every one is
	// expected to be ACCEPTED — this is what clears the coverage floor
	// below (D91: a corpus that silently truncates to the §12.2.2 default
	// per-session cap of 50 said nothing about 1,000+ intended inputs).
	schemes := []string{"", "sip:", "SIP:", "Sip:"}
	users := []string{"", "alice@", "bob.smith@", "user.name@"}
	hosts := generateInvariantHosts()
	for _, scheme := range schemes {
		for _, bracket := range []bool{false, true} {
			if scheme == "" {
				// The bare host:port form has no scheme and no user part
				// (input.go); only host varies here.
				for _, host := range hosts {
					corpus = append(corpus, wrapBracket(host, bracket))
				}
				continue
			}
			for _, user := range users {
				for _, host := range hosts {
					corpus = append(corpus, wrapBracket(scheme+user+host, bracket))
				}
			}
		}
	}
	return corpus
}

// TestCallDialInvariant_DialledURIIsCheckDestinationsOutput is Task 11d's
// acceptance test (D85-D91): the redesign's point is that the string
// policy.CheckDestination evaluated and the string that reaches Dial can
// never differ, STRUCTURALLY, rather than by validateToURI's five
// hand-maintained rules staying in lockstep with policy.Normalise — an
// alignment that failed five separate times before this task.
//
// TWO CLAUSES:
//   - Clause 1 (byte identity): for every input CallDial ACCEPTS, the ToURI
//     the fake agent's Dial received is byte-identical to the dialURI
//     policy.CheckDestination returned for that same raw input, on an
//     independent call against the same policy snapshot.
//   - Clause 2 (re-check stability, axis-agnostic): re-running
//     CheckDestination on the string that was ACTUALLY dialled must still
//     PERMIT it, under a DENY-ONLY fixture — so a spurious re-normalisation
//     drift would surface as a fresh denial. This clause names no specific
//     evasion mechanism, unlike the five axis regression tests it
//     complements.
//
// A RECORDING FAKE AGENT is used, never a real sipgo-backed one:
// internal/importguard enforces that internal/session's tests run entirely
// on fakes (contract:122); an agent that parses URIs with sipgo here would
// break that gate.
//
// EACH ACCEPTED CALL IS HUNG UP INSIDE THE LOOP, and a coverage floor is
// asserted (D91): the §12.2.2 default max_concurrent_calls_per_session is
// 50, and an earlier draft of this analysis that never freed a slot
// silently truncated its corpus to 50 accepted inputs — 4% of intended
// coverage — and reported nothing wrong. TestTerminationFreesSlotsImmediately
// already proves a slot is freed synchronously at CallHangup, no janitor
// pass required, which is what lets the full corpus run here.
func TestCallDialInvariant_DialledURIIsCheckDestinationsOutput(t *testing.T) {
	const denyPattern = `^sip:\+?1900`
	const coverageFloor = 1000

	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	store := denyOnlyStore(t, fc, denyPattern)
	p := store.Current()

	// Non-vacuity guard: policy.Defaults() ships neither an allow nor a deny
	// list and permits everything, so it could never observe this invariant
	// failing (CheckDestination returns permit unconditionally whenever
	// len(p.allowRE) == 0). Prove the deny-only fixture actually denies
	// something before relying on it for clause 2.
	if _, _, err := p.CheckDestination("sip:19005550123@example.net"); err == nil {
		t.Fatal("deny-only fixture did not deny sip:19005550123@example.net; " +
			"the fixture proves nothing")
	}

	agent := &recordingDialAgent{dialCh: make(chan string, 1)}
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc, Policy: store, Logger: testLogger(),
		NewUA: func(context.Context, UAConfig) (UserAgent, error) { return agent, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ts := NewToolService(m)
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, "s1", UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}

	corpus := buildInvariantCorpus()
	accepted := 0
	for _, raw := range corpus {
		out, err := ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: raw})
		if err != nil {
			// Not accepted — either validateToURI or CheckDestination itself
			// refused it. Nothing to check for this input; move on.
			continue
		}
		accepted++

		res, ok := out.(map[string]any)
		if !ok {
			t.Fatalf("CallDial(%q) result = %#v, want map[string]any", raw, out)
		}
		callHandle, _ := res["call_handle"].(string)
		if callHandle == "" {
			t.Fatalf("CallDial(%q) result carries no call_handle: %#v", raw, res)
		}

		var gotDialed string
		select {
		case gotDialed = <-agent.dialCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("CallDial(%q) was accepted but its goroutine never called Dial", raw)
		}

		// Clause 1: byte identity against an INDEPENDENT CheckDestination
		// call on the same raw input and the same policy snapshot CallDial
		// used internally.
		wantDialURI, _, cderr := p.CheckDestination(raw)
		if cderr != nil {
			t.Fatalf("CallDial(%q) accepted the call but a fresh CheckDestination(%q) "+
				"now errors: %v — the two disagree on whether this input is permitted",
				raw, raw, cderr)
		}
		if gotDialed != wantDialURI {
			t.Errorf("CallDial(%q): Dial received %q, want %q (CheckDestination's own "+
				"return) — the evaluated and dialled strings diverged", raw, gotDialed, wantDialURI)
		}

		// Clause 2: re-check stability. Re-running CheckDestination on what
		// was ACTUALLY dialled must still permit it under the deny-only
		// fixture.
		if _, _, err := p.CheckDestination(gotDialed); err != nil {
			t.Errorf("CallDial(%q): re-checking the actually-dialled string %q now "+
				"DENIES it: %v — the invariant must hold on re-evaluation, not just once",
				raw, gotDialed, err)
		}

		if _, err := ts.CallHangup(ctx, "s1", CallHangupInput{Call: callHandle}); err != nil {
			t.Fatalf("CallHangup(%q) after CallDial(%q): %v — a leaked slot here would "+
				"silently truncate every later iteration's corpus (D91)", callHandle, raw, err)
		}
	}

	t.Logf("invariant held over %d accepted inputs out of %d corpus entries", accepted, len(corpus))
	if accepted < coverageFloor {
		t.Fatalf("only %d accepted inputs (corpus size %d), want >= %d — a coverage-floor "+
			"regression (e.g. a re-truncation to the §12.2.2 default cap of 50) would "+
			"silently pass without this floor", accepted, len(corpus), coverageFloor)
	}
}
