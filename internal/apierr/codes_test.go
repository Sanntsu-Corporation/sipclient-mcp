package apierr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestAllCodesMatchesSpecTable pins AllCodes() to spec §11.2's table, which the
// spec declares exhaustive: "no code value appears anywhere else in this document
// that is not listed here". The assertion runs in both directions, so neither a
// code added without a spec change nor a code dropped from the enum can pass.
func TestAllCodesMatchesSpecTable(t *testing.T) {
	// Transcribed from spec §11.2, in table order.
	want := []string{
		"denied",
		"not_found",
		"gone",
		"invalid_argument",
		"precondition_failed",
		"not_supported",
		"media_negotiation",
		"tls_failure",
		"resource_limit",
		"cancelled",
		"internal",
	}

	got := make([]string, 0, len(AllCodes()))
	for _, c := range AllCodes() {
		got = append(got, string(c))
	}

	if len(got) != len(want) {
		t.Fatalf("AllCodes() has %d entries, spec §11.2 lists %d: got %v, want %v",
			len(got), len(want), got, want)
	}

	sortedGot := append([]string(nil), got...)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedGot)
	sort.Strings(sortedWant)

	for i := range sortedWant {
		if sortedGot[i] != sortedWant[i] {
			t.Errorf("code set mismatch: got %v, want %v", sortedGot, sortedWant)
			break
		}
	}

	seen := make(map[string]bool, len(got))
	for _, c := range got {
		if seen[c] {
			t.Errorf("AllCodes() lists %q more than once", c)
		}
		seen[c] = true
	}
}

// TestNoStringLiteralErrorCodesOutsideApierr walks every production .go file in
// the repository and fails if a string literal equals one of §11.2's codes.
// Callers must use the Code constants; a literal makes the exhaustiveness test
// above a fiction, because a code could then exist that AllCodes() never lists.
//
// Scope, and why: _test.go files are exempt (a test may legitimately write the
// wire value it expects), internal/sipengine is exempt (vendored, and locked
// decision 14 excludes it from all tooling), and this package is exempt (it
// defines the constants).
func TestNoStringLiteralErrorCodesOutsideApierr(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	codes := make(map[string]Code, len(AllCodes()))
	for _, c := range AllCodes() {
		codes[string(c)] = c
	}

	apierrDir := filepath.Join(root, "internal", "apierr")
	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "testdata", "sipengine":
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Dir(path) == apierrDir {
			return nil
		}

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}

		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if _, isCode := codes[v]; isCode {
				t.Errorf("%s: string literal %q duplicates a §11.2 error code; use the apierr constant instead",
					fset.Position(lit.Pos()), v)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
}
