package session

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// ---- §2 Phase 2: MCP-managed config (admin-scoped) -------------------------
//
// ConfigGet, ConfigSet and AdminTokenRotate are ADMIN-SCOPED (Phase 2 §2.4):
// the admin/bearer distinction is decided and enforced entirely in
// internal/transport/mcp (identityStore.isAdmin, wired at registration in
// tools.go's adminGate) rather than here. session must not import
// transport/mcp (§6.2's layering), and these three methods have no way to
// see WHICH token authenticated the caller — sess is just this tool's
// existing session id string, exactly like every other Tools method. Rule
// 18: one place decides "is this caller an admin", not two.

// ConfigGet is config_get (Phase 2, admin-scoped): the current policy,
// rendered as plain JSON-able values. It carries no revealed secret because
// Policy itself never carries one -- auth.bearer_token_file and
// auth.admin_token_file are FILE PATHS, not the token contents, and the
// resolved digests are unexported fields Load never round-trips through
// JSON or YAML.
func (t *ToolService) ConfigGet(_ context.Context, _ string, _ ConfigGetInput) (any, error) {
	p := t.m.policy.Current()
	return map[string]any{
		"auth": map[string]any{
			"bearer_token_file": p.Auth.BearerTokenFile,
			"admin_token_file":  p.Auth.AdminTokenFile,
		},
		"limits": map[string]any{
			"max_uas_total":                    p.Limits.MaxUAsTotal,
			"max_uas_per_session":              p.Limits.MaxUAsPerSession,
			"max_sessions_total":               p.Limits.MaxSessionsTotal,
			"max_redirects":                    p.Limits.MaxRedirects,
			"max_concurrent_calls_total":       p.Limits.MaxConcurrentCallsTotal,
			"max_concurrent_calls_per_session": p.Limits.MaxConcurrentCallsPerSession,
			"shutdown_grace_period":            p.Limits.ShutdownGracePeriod.Duration().String(),
			// CF-002: these two now have an observable effect (Tasks 3-5),
			// so they are worth reporting instead of only accepting/validating.
			"session_ttl":           p.Limits.SessionTTL.Duration().String(),
			"session_resume_window": p.Limits.SessionResumeWindow.Duration().String(),
			"registry_retention":    p.Limits.RegistryRetention.Duration().String(),
		},
		"destinations": map[string]any{
			"allow": p.Destinations.Allow,
			"deny":  p.Destinations.Deny,
		},
		"artifact": map[string]any{
			"dir":       p.Artifact.Dir,
			"max_bytes": p.Artifact.MaxBytes,
			"retention": p.Artifact.Retention.Duration().String(),
		},
		"tls": map[string]any{
			"insecure_skip_verify": p.TLS.InsecureSkipVerify,
		},
	}, nil
}

// ConfigSet is config_set (Phase 2, admin-scoped): apply a single dotted
// key/value pair through policy.Store.Mutate (§2.3a), the ONE serialised
// mutation path config_set shares with admin_token_rotate and the SIGHUP
// goroutine (Rule 18) -- it does NOT call policy.WriteFile or Store.Reload
// itself.
func (t *ToolService) ConfigSet(_ context.Context, _ string, in ConfigSetInput) (any, error) {
	if in.Key == "" {
		return nil, apierr.InvalidArgument("key is required")
	}
	err := t.m.policy.Mutate(func(cur *policy.Policy) error {
		return applyConfigKey(cur, in.Key, in.Value)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "key": in.Key}, nil
}

// AdminTokenRotate is admin_token_rotate (Phase 2, admin-scoped, §2.2 item
// 5): mint a fresh admin token, write it to the CONFIGURED admin token file
// atomically, and reload -- so the digest bearerAuth compares against is
// recomputed from the new value. The whole sequence runs through
// Store.MutateWithCommit, which is what serialises it against a concurrent
// config_set or SIGHUP reload (§2.3a): without that, a rotation racing a
// reload could have its file write observed mid-write by a Load that started
// a moment earlier.
//
// THE TOKEN FILE IS WRITTEN IN TWO STEPS, AND THAT IS THE FIX FOR SEC-1. The
// write used to happen inside the closure Mutate runs -- i.e. BEFORE Mutate's
// own validate / state-file write / reload -- so any failure in those three
// steps returned an error and discarded newToken while the token FILE on disk
// already held it. The in-memory digest still matched the OLD token, so the
// daemon kept authenticating normally and diverged silently until the next
// reload or restart, at which point it read a token nothing had ever returned
// to anyone and the admin plane was permanently locked out with no shell-free
// way back in. Now the value is STAGED to a temp file beside the real one
// (reversible), and the rename is handed to MutateWithCommit's commit hook,
// which runs only after validate and the state file's own staging have
// succeeded -- and still before the reload, because the reload is what
// recomputes the digest from this file. A failure before the commit leaves the
// token file byte-identical; a failure of the reload after it is rolled back by the
// closure the commit hook hands back, so every error path this function can
// return leaves the file exactly as it was, matching Mutate's own "abandoned
// wholesale" guarantee.
//
// THE STAGING AND THE ROLLBACK BOTH LIVE INSIDE THE COMMIT HOOK, AND THAT IS
// THE FIX FOR SEC-3. They used to sit OUTSIDE MutateWithCommit -- the
// snapshot of the old token was captured before the call and the rollback ran
// after it returned, both with reloadMu released -- which let two concurrent
// rotations, or a rotation racing a config_set/SIGHUP, act on a snapshot some
// other caller had already invalidated: the loser's rollback could revive a
// token the winner had just revoked, or restore old bytes after another
// reload had already recomputed the live digest from the new ones. Staging
// inside the hook means the "previous" bytes are read under reloadMu, at the
// instant of the rename; returning the undo to MutateWithCommit means it runs
// under that same lock hold. No other writer can slip between the three
// steps, so no rollback can ever write back a snapshot that is no longer the
// value this call itself replaced. See Store.MutateWithCommit's own contract.
//
// The new token is returned ONCE, in this call's own response -- nowhere
// else prints or stores the plaintext (the token FILE holds it, at 0600;
// the Policy struct never does, per policy.Secret's whole posture).
//
// reinitialize_required (SEC-2) travels in the response beside it: see
// internal/transport/mcp's registerTools, where the rotate tool re-binds the
// CALLING session to the new token so this same session keeps working.
func (t *ToolService) AdminTokenRotate(_ context.Context, _ string, _ AdminTokenRotateInput) (any, error) {
	p := t.m.policy.Current()
	if p.Auth.AdminTokenFile == "" {
		return nil, apierr.InvalidArgument(
			"no admin token is configured (auth.admin_token_file is unset); there is nothing to rotate")
	}

	newToken, err := policy.GenerateToken()
	if err != nil {
		return nil, apierr.Internal("", "generate token: "+err.Error())
	}

	if err := t.m.policy.MutateWithCommit(
		// The rotation changes no POLICY field at all -- auth.admin_token_file
		// is a path, and the path is unchanged. The mutation exists so the
		// reload underneath it recomputes the digest from the file the commit
		// hook below just replaced.
		func(*policy.Policy) error { return nil },
		func() (func() error, error) {
			// Read the path back under reloadMu rather than reusing the
			// snapshot taken above: this hook runs serialised, so this is the
			// value in force at the moment the rename actually happens.
			path := t.m.policy.Current().Auth.AdminTokenFile
			staged, err := policy.StageSecretFile(path, newToken)
			if err != nil {
				return nil, apierr.Internal("", "stage admin token file: "+err.Error())
			}
			// A no-op once Commit has run; this only reclaims the temp file on
			// the path where the rename never happened.
			defer staged.Discard()
			if err := staged.Commit(); err != nil {
				return nil, apierr.Internal("", "install admin token file: "+err.Error())
			}
			// The undo MutateWithCommit runs -- still holding reloadMu -- if
			// the reload after this commit fails. The rename landed but the
			// digest was never recomputed, so the file holds a token this call
			// is about to refuse to return; put the previous one back, or the
			// next restart reads a token nobody has.
			return func() error {
				if rbErr := staged.Rollback(); rbErr != nil {
					return apierr.Internal("", fmt.Sprintf(
						"the admin token file at %s could not be restored (%v) and may now hold a "+
							"value that was never returned -- restore it by hand before restarting "+
							"the daemon", path, rbErr))
				}
				return nil
			}, nil
		},
	); err != nil {
		return nil, err
	}

	return map[string]any{"admin_token": newToken}, nil
}

// configurableKeys is the closed, curated set of dotted policy keys
// config_set accepts (Rule 15): a small hand-written switch, not a
// reflection-based generic patcher that would silently expose every field
// of *policy.Policy — including auth.* and the unexported digests a generic
// walker could still reach via its exported wrapper fields — to whichever
// caller holds the admin token.
//
// artifact.dir is the one PERMANENTLY DENIED key (Phase 2 design §2.6): the
// artifact store, its janitor and every in-flight capture resolve the
// directory ONCE, at process construction (cmd/sipclient-mcpd/run.go), so a
// live change would silently split writes across two directories with no
// defined answer for a capture that already holds an open file handle in
// the old one. Making it settable would cost FOUR separate changes (a live
// indirection inside the artifact store, per-write directory resolution,
// a janitor that sweeps both the old and new directory, and a defined
// answer for an in-flight capture's open handle) for a key a single-user
// local dev daemon's operator sets once and restarts for. This entry is not
// a general extension point: it exists for this one key, for this one
// reason; deleting it requires actually doing those four things first.
func applyConfigKey(p *policy.Policy, key string, value any) error {
	switch key {
	case "artifact.dir":
		return apierr.InvalidArgument(
			"artifact.dir cannot be changed while the daemon is running (the artifact store, its " +
				"janitor and every in-flight capture resolve it once at startup); set it in the state " +
				"file and restart the daemon for it to take effect")
	case "limits.max_uas_total":
		v, err := configPositiveInt(key, value)
		if err != nil {
			return err
		}
		p.Limits.MaxUAsTotal = v
	case "limits.max_sessions_total":
		// No floor here: policy.validate() already rejects a non-positive
		// max_sessions_total (and anything above 100000), and Mutate runs it
		// on every config_set, so a second copy of the bound would be two
		// places to keep in step for no extra coverage (Rule 18).
		v, err := configInt(value)
		if err != nil {
			return err
		}
		p.Limits.MaxSessionsTotal = v
	case "limits.max_redirects":
		// Checked here as well as in policy.validate(): a validate() failure
		// inside Store.Mutate comes back without an apierr code.
		v, err := configInt(value)
		if err != nil {
			return err
		}
		if v < 0 || v > policy.MaxRedirectsCeiling {
			return apierr.InvalidArgument(fmt.Sprintf(
				"limits.max_redirects must be between 0 and %d, got %d", policy.MaxRedirectsCeiling, v))
		}
		p.Limits.MaxRedirects = v
	case "limits.max_concurrent_calls_total":
		v, err := configPositiveInt(key, value)
		if err != nil {
			return err
		}
		p.Limits.MaxConcurrentCallsTotal = v
	case "limits.max_concurrent_calls_per_session":
		v, err := configPositiveInt(key, value)
		if err != nil {
			return err
		}
		p.Limits.MaxConcurrentCallsPerSession = v
	case "limits.shutdown_grace_period":
		// Bounded by policy.validate() as well -- see max_sessions_total above.
		d, err := configDuration(value)
		if err != nil {
			return err
		}
		p.Limits.ShutdownGracePeriod = d
	case "artifact.max_bytes":
		v, err := configPositiveInt64(key, value)
		if err != nil {
			return err
		}
		p.Artifact.MaxBytes = v
	case "artifact.retention":
		d, err := configPositiveDuration(key, value)
		if err != nil {
			return err
		}
		p.Artifact.Retention = d
	case "destinations.allow":
		v, err := configStringSlice(key, value)
		if err != nil {
			return err
		}
		p.Destinations.Allow = v
	case "destinations.deny":
		v, err := configStringSlice(key, value)
		if err != nil {
			return err
		}
		p.Destinations.Deny = v
	case "tls.insecure_skip_verify":
		v, ok := value.(bool)
		if !ok {
			return apierr.InvalidArgument("tls.insecure_skip_verify must be a boolean")
		}
		p.TLS.InsecureSkipVerify = v
	default:
		return apierr.InvalidArgument(fmt.Sprintf("unknown or unsettable config key %q", key))
	}
	return nil
}

// configInt/configInt64/configDuration/configStringSlice decode a
// ConfigSetInput.Value (an `any` off the JSON wire: float64, string, bool or
// []any) into the Go type the named field actually holds. JSON has no
// integer type distinct from float64, so an int field checks Trunc rather
// than accepting any float silently.

// configPositiveInt/configPositiveInt64/configPositiveDuration are the decoders
// above PLUS the range floor every curated key that cannot mean anything at or
// below zero gets.
//
// WHY THEY EXIST — the decoders alone check the TYPE and nothing else, so
// `config_set limits.max_uas_total 0`, `-1`, or `artifact.max_bytes -5`
// returned nil, took effect live AND landed in the state file, surviving the
// restart that would otherwise have cleared it. max_uas_total=0 in particular
// wedges the daemon outright: every ua_create then fails with resource_limit
// and the only way back is to edit the state file by hand. The bound is the
// same posture policy.validate() already takes for max_sessions_total,
// event_log_size, max_ladders and shutdown_grace_period -- a degenerate limit
// is a config mistake to refuse at the boundary, not a setting to honour.
//
// The keys policy.validate() ALREADY bounds do not get a second copy here; see
// the switch above.
func configPositiveInt(key string, v any) (int, error) {
	n, err := configInt(v)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, apierr.InvalidArgument(fmt.Sprintf("%s must be positive, got %d", key, n))
	}
	return n, nil
}

func configPositiveInt64(key string, v any) (int64, error) {
	n, err := configInt64(v)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, apierr.InvalidArgument(fmt.Sprintf("%s must be positive, got %d", key, n))
	}
	return n, nil
}

func configPositiveDuration(key string, v any) (policy.Duration, error) {
	d, err := configDuration(v)
	if err != nil {
		return 0, err
	}
	if d.Duration() <= 0 {
		return 0, apierr.InvalidArgument(fmt.Sprintf("%s must be positive, got %v", key, d.Duration()))
	}
	return d, nil
}

func configInt(v any) (int, error) {
	f, ok := v.(float64)
	if !ok {
		return 0, apierr.InvalidArgument("value must be a number")
	}
	if f != math.Trunc(f) {
		return 0, apierr.InvalidArgument("value must be an integer")
	}
	return int(f), nil
}

func configInt64(v any) (int64, error) {
	f, ok := v.(float64)
	if !ok {
		return 0, apierr.InvalidArgument("value must be a number")
	}
	if f != math.Trunc(f) {
		return 0, apierr.InvalidArgument("value must be an integer")
	}
	return int64(f), nil
}

func configDuration(v any) (policy.Duration, error) {
	s, ok := v.(string)
	if !ok {
		return 0, apierr.InvalidArgument(`value must be a duration string such as "10s"`)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, apierr.InvalidArgument("invalid duration: " + err.Error())
	}
	return policy.Duration(d), nil
}

// configStringSlice NAMES THE KEY in its refusals, unlike the scalar decoders
// above and like the configPositive* range checks. Its two callers are
// destinations.allow and destinations.deny — the most security-weighted keys in
// the curated set, and the only list-shaped ones — so an operator who gets a
// refusal back needs to know which of the two lists was rejected, not merely
// that "value" was the wrong shape.
func configStringSlice(key string, v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, apierr.InvalidArgument(fmt.Sprintf("%s must be an array of strings", key))
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, apierr.InvalidArgument(fmt.Sprintf("%s must be an array of strings", key))
		}
		out = append(out, s)
	}
	return out, nil
}
