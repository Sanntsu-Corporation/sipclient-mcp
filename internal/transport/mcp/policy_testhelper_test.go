package mcp

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

const (
	testToken  = "mcp-token"
	adminToken = "admin-token"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// testPolicyStore writes a real policy file whose auth.bearer_token_file (and,
// when admin != "", auth.admin_token_file) name real files on disk, then loads
// it through the real policy.NewStore. Passing admin == "" leaves
// auth.admin_token_file unset, which is what makes AdminEnabled() false and the
// §12.7 plane unregistered.
//
// It returns the store AND its path, so a test can rewrite a token file and
// call store.Reload() to exercise SIGHUP rotation.
func testPolicyStore(t *testing.T, clk clock.Clock, bearer, admin string) (*policy.Store, string) {
	t.Helper()
	return testPolicyStoreWithLimits(t, clk, bearer, admin, "")
}

// testPolicyStoreWithLimits is the same, plus an extra `limits:` block — for the
// tests that need a specific max_uas_total or shutdown_grace_period. limitsYAML
// is the block's BODY, already indented two spaces, e.g. "  max_uas_total: 2\n".
func testPolicyStoreWithLimits(t *testing.T, clk clock.Clock, bearer, admin, limitsYAML string) (*policy.Store, string) {
	t.Helper()
	dir := t.TempDir()

	bearerFile := filepath.Join(dir, "bearer.token")
	if err := os.WriteFile(bearerFile, []byte(bearer), 0o600); err != nil {
		t.Fatalf("write bearer token file: %v", err)
	}
	yaml := "auth:\n  bearer_token_file: " + bearerFile + "\n"

	if admin != "" {
		adminFile := filepath.Join(dir, "admin.token")
		if err := os.WriteFile(adminFile, []byte(admin), 0o600); err != nil {
			t.Fatalf("write admin token file: %v", err)
		}
		yaml += "  admin_token_file: " + adminFile + "\n"
	}
	if limitsYAML != "" {
		yaml += "limits:\n" + limitsYAML
	}
	yaml += "artifact:\n  dir: " + dir + "\n"

	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	store, err := policy.NewStore(path, clk, discardLogger())
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}
	return store, path
}
