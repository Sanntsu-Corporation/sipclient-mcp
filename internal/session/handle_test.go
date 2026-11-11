package session

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestNewHandleFormat(t *testing.T) {
	tests := []struct {
		name string
		gen  func() Handle
		re   *regexp.Regexp
	}{
		{"ua", newUAHandle, regexp.MustCompile(`^ua_[0-9a-f]{16}$`)},
		{"call", newCallHandle, regexp.MustCompile(`^call_[0-9a-f]{16}$`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[Handle]struct{}, 10000)
			for i := 0; i < 10000; i++ {
				h := tc.gen()
				if !tc.re.MatchString(string(h)) {
					t.Fatalf("handle %q does not match %s", h, tc.re)
				}
				if _, dup := seen[h]; dup {
					t.Fatalf("handle %q issued twice", h)
				}
				seen[h] = struct{}{}
			}
		})
	}
}

// TestPrefixNeverParsedForAuthorization is the source-level half of locked
// decision 12. The behavioural half is TestResolveIgnoresHandlePrefix.
func TestPrefixNeverParsedForAuthorization(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	banned := map[string]bool{
		"HasPrefix": true, "TrimPrefix": true, "Cut": true,
		"Split": true, "SplitN": true,
	}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || id.Name != "strings" || !banned[sel.Sel.Name] {
					return true
				}
				for _, arg := range call.Args {
					lit, ok := arg.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if strings.Contains(lit.Value, "ua_") || strings.Contains(lit.Value, "call_") {
						t.Errorf("%s: strings.%s on a handle prefix literal %s — the prefix "+
							"MUST NEVER be parsed (locked decision 12)",
							fset.Position(call.Pos()), sel.Sel.Name, lit.Value)
					}
				}
				return true
			})
		}
	}
}
