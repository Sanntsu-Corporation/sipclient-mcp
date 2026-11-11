package sipua_test

// parallel_invariant_test.go — C-M5's enforcement (D20, P4-W2-01, Phase 4 W2).
//
// internal/sipua carries four test-only seams on production surface
// (ringBudgetOverride, mediaTeardownHook, dialAnsweringHook in call.go; seq0 in
// medialoop.go). None is synchronised, so their correctness rests entirely on an
// invariant nothing checked: NO TEST IN THIS PACKAGE CALLS t.Parallel().
//
// The Cycle 3 review flagged the trend and proposed no fix; the deferral's
// bounded action was to make the invariant explicit rather than remove the seams.
// A comment saying "tests here don't run in parallel" is not that — the first
// person to add t.Parallel() to a new table-driven test would not read it. This
// is.
//
// SOURCE SCAN, NOT A RUNTIME PROBE. There is no way to observe "no test in this
// package used t.Parallel" from inside one test, so this parses the package's own
// test files. It is deliberately a plain string scan over parsed source rather
// than a type-checked one: the check must stay cheap and dependency-free, and a
// t.Parallel() call is unambiguous in the text.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoTestInThisPackageCallsTParallel(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			// stripQuoted drops double-quoted string contents before matching:
			// this very file's own failure message and its Contains() pattern
			// argument below both spell out ".Parallel()" as DATA, and a scan
			// that did not exclude quoted text would flag its own source on
			// every run — checked here, once, so the fix isn't rediscovered.
			if strings.Contains(stripQuoted(trimmed), ".Parallel()") {
				offenders = append(offenders, fmt.Sprintf("%s:%d: %s", name, i+1, trimmed))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("t.Parallel() found in internal/sipua's tests:\n  %s\n\n"+
			"THIS PACKAGE'S TEST-ONLY PRODUCTION SEAMS ARE UNSYNCHRONISED — ringBudgetOverride, "+
			"mediaTeardownHook and dialAnsweringHook (call.go) and seq0 (medialoop.go) are plain "+
			"globals. Two tests mutating them concurrently interleave, producing a failure that "+
			"reproduces once in twenty runs and blames the wrong code. Either drop the t.Parallel() "+
			"call, or make the seam it races on safe first (C-M5, D20).",
			strings.Join(offenders, "\n  "))
	}
}

// stripQuoted removes the contents of double-quoted string literals from a
// single line of Go source (a `"` not preceded by `\` toggles in/out of a
// string). It is a per-line heuristic, not a full lexer — sufficient here
// because every string literal this package's test files construct opens and
// closes on the line it starts on.
func stripQuoted(line string) string {
	var b strings.Builder
	inString := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' && (i == 0 || line[i-1] != '\\') {
			inString = !inString
			continue
		}
		if !inString {
			b.WriteByte(c)
		}
	}
	return b.String()
}
