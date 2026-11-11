package session

import (
	"context"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// TestDirectModeWiresInlineCredentials pins the §14.5 fix, carried forward
// into Phase 1's inline-account model: a direct-mode UA created WITH inline
// credentials receives them (and the From identity) so a 401/407 challenge on
// the INVITE can be answered, while a direct-mode UA created WITHOUT them
// stays unauthenticated (IP-to-IP).
//
// The credential defect the Asterisk interop gate originally found was that
// the "direct" branch of ToolService.UACreate wired only Keepalive — it never
// carried AuthUser/AuthPass through, so a challenged INVITE went out with no
// Authorization. Phase 1 (session-scoped UA lifecycle, owner-locked decision)
// replaced the policy.yaml profile lookup this test used to drive with
// ua_create's own inline aor/auth_user/auth_pass fields (D6); the property
// being pinned — direct mode wires credentials when given, and stays
// unauthenticated when not — is unchanged.
//
// THIS UNIT TEST DOES NOT CLOSE THE BLOCKER. The loopback peer never
// challenges an INVITE, so it cannot prove the authenticated call actually
// completes; only the §14.5 re-run against Asterisk does. This test pins the
// wiring at the session boundary — that the credentials leave UACreate on the
// UAConfig — and nothing more.
func TestDirectModeWiresInlineCredentials(t *testing.T) {
	const (
		aor       = "sip:e2e-uac-direct@192.168.1.117"
		authUser  = "e2e-uac-direct"
		authPass  = "s3cr3t-direct"
		registrar = "sip:192.168.1.117:5060" // must NOT be wired in direct mode
	)

	cases := []struct {
		name string
		in   UACreateInput
		// wanted UAConfig fields
		wantAuthUser string
		wantAuthPass bool // whether AuthPass should be non-empty
		wantAOR      string
		// CF-046 (D-C3): a direct-daemon caller's own aor/auth_any_host reach
		// UAConfig unchanged; the sipua guard honours both as given.
		wantAuthAnyHost bool
	}{
		{
			name: "with inline credentials authenticates",
			in: UACreateInput{
				Mode: "direct", Transport: string(TransportUDP),
				AOR: aor, AuthUser: authUser, AuthPass: authPass,
			},
			wantAuthUser: authUser,
			wantAuthPass: true,
			wantAOR:      aor,
		},
		{
			name:         "without credentials stays unauthenticated",
			in:           UACreateInput{Mode: "direct", Transport: string(TransportUDP)},
			wantAuthUser: "",
			wantAuthPass: false,
			wantAOR:      "",
		},
		{
			name: "caller-supplied aor and auth_any_host true reach UAConfig",
			in: UACreateInput{
				Mode: "direct", Transport: string(TransportUDP),
				AOR: "sip:u@192.0.2.1", AuthUser: authUser, AuthPass: authPass, AuthAnyHost: true,
			},
			wantAuthUser:    authUser,
			wantAuthPass:    true,
			wantAOR:         "sip:u@192.0.2.1",
			wantAuthAnyHost: true,
		},
		{
			name: "explicit auth_any_host false stays false",
			in: UACreateInput{
				Mode: "direct", Transport: string(TransportUDP),
				AOR: aor, AuthUser: authUser, AuthPass: authPass, AuthAnyHost: false,
			},
			wantAuthUser: authUser,
			wantAuthPass: true,
			wantAOR:      aor,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeClock()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			var got UAConfig
			m, err := NewManager(ManagerConfig{
				Ctx: ctx, Clock: fc,
				Policy: policy.NewStaticStore(policy.Defaults(), fc, testLogger()),
				Logger: testLogger(),
				NewUA: func(_ context.Context, cfg UAConfig) (UserAgent, error) {
					got = cfg
					return nopAgent{}, nil
				},
			})
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			if err := m.Open(ctx, "s1"); err != nil {
				t.Fatalf("Open: %v", err)
			}
			ts := NewToolService(m)

			if _, err := ts.UACreate(ctx, "s1", tc.in); err != nil {
				t.Fatalf("ua_create(direct): %v", err)
			}

			if got.AuthUser != tc.wantAuthUser {
				t.Errorf("AuthUser = %q, want %q", got.AuthUser, tc.wantAuthUser)
			}
			// Compare against the zero Secret rather than revealing the plaintext
			// (D5): a non-empty AuthPass differs from policy.Secret{}.
			gotPass := got.AuthPass != policy.Secret{}
			if gotPass != tc.wantAuthPass {
				t.Errorf("AuthPass non-empty = %v, want %v", gotPass, tc.wantAuthPass)
			}
			if got.AOR != tc.wantAOR {
				t.Errorf("AOR = %q, want %q", got.AOR, tc.wantAOR)
			}
			if got.AuthAnyHost != tc.wantAuthAnyHost {
				t.Errorf("AuthAnyHost = %v, want %v", got.AuthAnyHost, tc.wantAuthAnyHost)
			}
			// Direct mode sends the INVITE to the literal to_uri, never via a
			// registrar (§7): registrar must NOT be wired even though this
			// case never sets one — UAConfig.Registrar must simply stay empty.
			if got.Registrar != "" {
				t.Errorf("Registrar = %q, want empty (direct mode never uses a registrar)", got.Registrar)
			}
		})
	}
}
