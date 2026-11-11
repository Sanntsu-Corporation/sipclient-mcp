package policy

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// ConstantTimeEqual takes []byte (U6): transport/mcp holds the presented
// token as bytes off the wire, and the []byte form avoids materialising a
// second copy of secret material on the heap.
func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{name: "equal", a: []byte("s3cr3t"), b: []byte("s3cr3t"), want: true},
		{name: "different value same length", a: []byte("s3cr3t"), b: []byte("s3cr3T")},
		{name: "prefix", a: []byte("s3cr3t"), b: []byte("s3cr3")},
		{name: "longer", a: []byte("s3cr3t"), b: []byte("s3cr3tt")},
		{name: "both empty", a: []byte(""), b: []byte(""), want: true},
		{name: "one empty", a: []byte("s3cr3t"), b: []byte("")},
		{name: "nil equals empty", a: nil, b: []byte(""), want: true},
		{name: "both nil", a: nil, b: nil, want: true},
		// U6's whole point: a length mismatch must not short-circuit. Both
		// inputs are SHA-256'd to a fixed 32 bytes first, so the comparison
		// is over equal-length digests whatever the inputs' lengths were.
		{name: "wildly different lengths", a: []byte("a"), b: []byte(strings.Repeat("b", 4096))},
		// Already-hashed digests are a legitimate input: identityStore
		// (Task 17) passes two 32-byte SHA-256 digests.
		{name: "equal digests", a: digestOf("tok"), b: digestOf("tok"), want: true},
		{name: "unequal digests", a: digestOf("tok"), b: digestOf("tok2")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConstantTimeEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("ConstantTimeEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func digestOf(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

func TestTokenMatchingAndAdminPlaneSwitch(t *testing.T) {
	bearer := writeFile(t, "bearer", "bearer-token-value\n")
	admin := writeFile(t, "admin", "admin-token-value\n")

	t.Run("admin_token_file unset means the plane is not registered", func(t *testing.T) {
		body := fmt.Sprintf("auth:\n  bearer_token_file: %s\n", bearer)
		p, err := Load(writePolicy(t, body))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if p.Auth.AdminTokenFile != "" {
			t.Errorf("admin_token_file = %q, want \"\"", p.Auth.AdminTokenFile)
		}
		if p.AdminEnabled() {
			t.Error("AdminEnabled() = true, want false: an unset admin_token_file means /admin/* is NOT REGISTERED AT ALL (§12.7)")
		}
		if p.MatchesAdminToken([]byte("admin-token-value")) {
			t.Error("MatchesAdminToken must be false when no admin token is configured")
		}
		if !p.MatchesBearerToken([]byte("bearer-token-value")) {
			t.Error("MatchesBearerToken must accept the configured bearer token")
		}
		if p.MatchesBearerToken([]byte("wrong-token")) {
			t.Error("MatchesBearerToken must reject a token that was not configured")
		}
	})

	t.Run("admin_token_file set enables a SEPARATE token", func(t *testing.T) {
		body := fmt.Sprintf("auth:\n  bearer_token_file: %s\n  admin_token_file: %s\n", bearer, admin)
		p, err := Load(writePolicy(t, body))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if !p.AdminEnabled() {
			t.Fatal("AdminEnabled() = false, want true")
		}
		if !p.MatchesAdminToken([]byte("admin-token-value")) {
			t.Error("MatchesAdminToken must accept the admin token")
		}
		// §12.7: the MCP bearer token must NEVER open the admin plane, and
		// the admin token must never be accepted as an MCP bearer token.
		if p.MatchesAdminToken([]byte("bearer-token-value")) {
			t.Error("the MCP bearer token must not be accepted by the admin plane")
		}
		if p.MatchesBearerToken([]byte("admin-token-value")) {
			t.Error("the admin token must not be accepted as an MCP bearer token")
		}
	})
}

// TestMultipleBearerTokens covers the one-token-per-line bearer_token_file
// format: multiple machines can each hold their own token, revocable
// independently by deleting its line and reloading, with no identity
// tracking beyond an optional human-readable "#<remark>" the operator can
// append per line for their own bookkeeping.
func TestMultipleBearerTokens(t *testing.T) {
	bearer := writeFile(t, "bearer", ""+
		"tokenA #laptop\n"+
		"\n"+
		"# a full-line comment, e.g. a header the operator added\n"+
		"tokenB # office-desktop\n"+
		"tokenC\n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\n", bearer)
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, tok := range []string{"tokenA", "tokenB", "tokenC"} {
		if !p.MatchesBearerToken([]byte(tok)) {
			t.Errorf("MatchesBearerToken(%q) = false, want true", tok)
		}
	}
	if p.MatchesBearerToken([]byte("tokenD")) {
		t.Error("MatchesBearerToken(\"tokenD\") = true, want false: not a configured token")
	}
	// The remark is bookkeeping only -- it must never itself authenticate.
	if p.MatchesBearerToken([]byte("laptop")) {
		t.Error("a remark must not be usable as a token")
	}
}

func TestBearerTokenFileEmptyOrCommentsOnlyIsRejected(t *testing.T) {
	bearer := writeFile(t, "bearer", "\n# just a comment\n   \n")
	body := fmt.Sprintf("auth:\n  bearer_token_file: %s\n", bearer)
	_, err := Load(writePolicy(t, body))
	if err == nil {
		t.Fatal("Load succeeded, want an error: no real token in the file")
	}
	if !strings.Contains(err.Error(), "auth.bearer_token_file") {
		t.Errorf("error = %q, want it to name auth.bearer_token_file", err)
	}
}
