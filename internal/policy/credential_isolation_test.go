package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestNoCredentialEverEscapesPolicy is spec §5 N5's acceptance and §14.2's
// Policy row, asserted structurally: every rendering path a credential could
// reach is exercised against a loaded policy, and none may contain the bearer
// token or the admin token.
//
// IT IS THE RESTORED HALF OF A TEST THAT WAS DELETED WHOLESALE. Phase 1 removed
// policy.Profile, which took profiles[i].auth_pass — one of the three secrets
// the original asserted on — with it. The bearer/admin half did NOT become
// obsolete: Policy still carries bearerDigests and adminDigest, resolve() still
// reads both token FILES, and this wave added new secret-adjacent surfaces
// (config_get, which marshals policy-derived values, and admin_token_rotate,
// which returns a plaintext token in its own response). Deleting the file left
// those with no structural assertion at all, so only the profile-specific
// assertions are gone here; everything else is the original's shape.
//
// The Store is exercised alongside the Policy because it is what production
// code actually holds and logs -- a leak through the wrapper counts the same
// as one through the value.
func TestNoCredentialEverEscapesPolicy(t *testing.T) {
	const (
		bearerTok = "bearer-token-value-9f2a"
		adminTok  = "admin-token-value-4b71"
	)
	bearerPath := writeFile(t, "bearer", bearerTok+"\n")
	adminPath := writeFile(t, "admin", adminTok+"\n")

	path := writePolicy(t, fmt.Sprintf(`
auth:
  bearer_token_file: %s
  admin_token_file: %s
`, bearerPath, adminPath))

	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s, err := NewStore(path, fakeclock.New(epoch), discardLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Both digests really were resolved from the token files -- otherwise the
	// whole assertion runs against a Policy that never held a credential.
	if !p.MatchesBearerToken([]byte(bearerTok)) {
		t.Fatal("precondition: the loaded policy does not recognise the bearer token it was given")
	}
	if !p.MatchesAdminToken([]byte(adminTok)) {
		t.Fatal("precondition: the loaded policy does not recognise the admin token it was given")
	}

	// The full log, as N5's grep would see it: every value that could
	// plausibly be logged, through the JSONHandler of locked decision 5.
	var log bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&log, nil))
	lg.Info("policy_loaded", slog.Any("policy", p))
	lg.Info("policy_auth", slog.Any("auth", p.Auth))
	lg.Info("store_built", slog.Any("store", s), slog.Any("current", s.Current()))
	lg.Error("policy_reload_failed", slog.Any("policy", p))

	// Every tool-response shape: policy values reach a response only by being
	// marshalled, so marshalling is the whole surface.
	policyJSON, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	authJSON, err := json.Marshal(p.Auth)
	if err != nil {
		t.Fatalf("marshal auth: %v", err)
	}
	currentJSON, err := json.Marshal(s.Current())
	if err != nil {
		t.Fatalf("marshal store.Current(): %v", err)
	}

	renders := map[string]string{
		"log":             log.String(),
		"json(policy)":    string(policyJSON),
		"json(auth)":      string(authJSON),
		"json(current)":   string(currentJSON),
		"fmt %v policy":   fmt.Sprintf("%v", p),
		"fmt %+v policy":  fmt.Sprintf("%+v", p),
		"fmt %#v policy":  fmt.Sprintf("%#v", p),
		"fmt %+v auth":    fmt.Sprintf("%+v", p.Auth),
		"fmt %#v auth":    fmt.Sprintf("%#v", p.Auth),
		"fmt %v store":    fmt.Sprintf("%v", s),
		"fmt %+v store":   fmt.Sprintf("%+v", s),
		"fmt %#v store":   fmt.Sprintf("%#v", s),
		"fmt %+v current": fmt.Sprintf("%+v", s.Current()),
		"fmt %#v current": fmt.Sprintf("%#v", s.Current()),
	}
	secrets := map[string]string{
		"bearer token": bearerTok,
		"admin token":  adminTok,
	}

	for renderName, rendered := range renders {
		for secretName, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Errorf("%s leaked the %s:\n%s", renderName, secretName, rendered)
			}
		}
	}

	// Guard against a vacuous pass: the renderings must be non-trivial and
	// must actually contain the policy, or the assertion above proves
	// nothing. bearer_token_file is a PATH and is expected in the output --
	// its presence is what shows the renderer walked the auth section at all
	// and simply had no plaintext to print.
	if !strings.Contains(log.String(), "policy_loaded") ||
		!strings.Contains(string(policyJSON), bearerPath) ||
		!strings.Contains(fmt.Sprintf("%+v", p.Auth), adminPath) {
		t.Fatal("renderings are vacuous; the isolation assertion would be meaningless")
	}
}
