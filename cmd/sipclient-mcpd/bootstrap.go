package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// bearerTokenFileName and adminTokenFileName are the two minted credential
// files P2-T1 writes into the state directory, alongside the state.yaml
// itself. Named constants because P2-T2's --print-tokens and P2-T3a/T4's
// bootstrap both need the SAME two paths, and Rule 18 says that pairing is
// written once.
const (
	bearerTokenFileName = "bearer.token"
	adminTokenFileName  = "admin.token"
)

// defaultStatePath resolves --state's default (§2.2 item 1):
// $XDG_STATE_HOME/sipclient-mcp/state.yaml, falling back to
// ~/.local/state/sipclient-mcp/state.yaml when XDG_STATE_HOME is unset —
// the same fallback the XDG base directory spec itself defines, so this
// matches what every other XDG-aware tool on the box already does.
func defaultStatePath() (string, error) {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "sipclient-mcp", "state.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve --state default: %w", err)
	}
	return filepath.Join(home, ".local", "state", "sipclient-mcp", "state.yaml"), nil
}

// mintTokensIfAbsent is §2.2 items 1-2: create the state directory (0700),
// and, ONLY if the two token files are not already there, generate two
// 256-bit CSPRNG tokens (policy.GenerateToken — the SAME generator
// admin_token_rotate uses, Rule 16/18) and write them to bearerTokenFileName
// / adminTokenFileName at 0600.
//
// IT MUST ONLY BE CALLED ON A TRUE FIRST RUN — i.e. when the state file does
// not exist (run.go's own os.Stat, the single condition the two bootstrap
// functions below are already gated on). Its internal idempotency check keys
// on the two token files' own presence under stateDir, which is NOT the same
// question: a daemon whose existing state.yaml points auth.bearer_token_file /
// auth.admin_token_file at some OTHER location has no file at either stateDir
// path, so calling this unconditionally minted two fresh tokens that
// authenticate nothing and printed the FIRST RUN banner over them. The stat
// belongs to the caller, not here, because the caller is also what decides
// which bootstrap follows; keying this function on the files it itself owns
// keeps it self-contained and independently testable, per P2-T1's own success
// criteria.
//
// On a genuine first run it also PRINTS the two values to stdout, once,
// behind an unmistakable banner, and logs an INFO line — the only time
// either value is ever shown. A second start neither re-mints nor
// re-prints.
func mintTokensIfAbsent(stateDir string, stdout io.Writer, logger *slog.Logger) (bearerPath, adminPath string, err error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create state directory %s: %w", stateDir, err)
	}
	bearerPath = filepath.Join(stateDir, bearerTokenFileName)
	adminPath = filepath.Join(stateDir, adminTokenFileName)

	_, bErr := os.Stat(bearerPath)
	_, aErr := os.Stat(adminPath)
	if bErr == nil && aErr == nil {
		// Already minted (a second start, or a --state pointed at a
		// directory another process already bootstrapped). Nothing to do,
		// and CRITICALLY nothing to print: the values are already known
		// only to whoever read them the first time.
		return bearerPath, adminPath, nil
	}
	// A partially-minted directory (one file present, one missing) is not a
	// state this bootstrap sequence can produce on its own — mintTokensIfAbsent
	// is the only writer of either file at these paths — but an operator
	// could still construct it by hand. Treat it as "mint both fresh": the
	// alternative, trying to salvage the one that exists, would print a
	// banner claiming a token the operator may have already seen printed
	// once before under a different value.
	bearerTok, err := policy.GenerateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate bearer token: %w", err)
	}
	adminTok, err := policy.GenerateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate admin token: %w", err)
	}
	if err := policy.WriteSecretFile(bearerPath, bearerTok); err != nil {
		return "", "", fmt.Errorf("write bearer token file: %w", err)
	}
	if err := policy.WriteSecretFile(adminPath, adminTok); err != nil {
		return "", "", fmt.Errorf("write admin token file: %w", err)
	}

	banner := "================================================================\n" +
		"sipclient-mcpd: FIRST RUN — generated credentials (shown ONCE)\n" +
		"  bearer token:  " + bearerTok + "\n" +
		"  admin token:   " + adminTok + "\n" +
		"  saved to:      " + bearerPath + " and " + adminPath + "\n" +
		"  recover them later with: sipclient-mcpd --print-tokens --state <path>\n" +
		"================================================================\n"
	if _, err := io.WriteString(stdout, banner); err != nil {
		return "", "", fmt.Errorf("print first-run banner: %w", err)
	}
	logger.Info("first_run_credentials_minted",
		slog.String("bearer_token_file", bearerPath),
		slog.String("admin_token_file", adminPath))

	return bearerPath, adminPath, nil
}

// printTokens is --print-tokens (§2.2 item 4): read the two token files
// this same bootstrap sequence mints and print them, without starting a
// listener. It reads the files directly rather than going through
// policy.Load, so it works even when the state YAML itself is absent or
// unreadable — the two token files are the only thing it needs.
func printTokens(stateDir string, stdout io.Writer) error {
	bearerPath := filepath.Join(stateDir, bearerTokenFileName)
	adminPath := filepath.Join(stateDir, adminTokenFileName)

	bearer, err := os.ReadFile(bearerPath)
	if err != nil {
		return fmt.Errorf("read bearer token file %s: %w", bearerPath, err)
	}
	admin, err := os.ReadFile(adminPath)
	if err != nil {
		return fmt.Errorf("read admin token file %s: %w", adminPath, err)
	}
	if _, err := io.WriteString(stdout, string(bearer)+"\n"+string(admin)+"\n"); err != nil {
		return fmt.Errorf("print tokens: %w", err)
	}
	return nil
}

// bootstrapDefaultState is P2-T3a, §2.2a: the TRUE first-run path (no
// --state file, no --policy). It builds a complete, validate()-passing
// Policy from policy.Defaults() — which supplies Limits, Media, Capture and
// Artifact.Retention/MaxBytes and NOTHING ELSE (policy.go's own doc comment
// on Defaults says so) — points Auth at the two files mintTokensIfAbsent
// just wrote, gives Artifact a real writable directory (Defaults leaves
// this empty, and an empty artifact.dir is a daemon that authenticates
// fine and answers /readyz 503 forever — the loopback harness's own D294),
// writes it, and immediately loads it back through policy.NewStore.
//
// Ordering is load-bearing: mint (mintTokensIfAbsent, already done by the
// time this is called) -> write -> load back, never reversed. The
// load-back is not a formality — it is the actual proof that the writer
// and the decoder agree; an in-memory struct check would prove nothing
// about what a RESTART reads back.
func bootstrapDefaultState(statePath, bearerPath, adminPath string) error {
	artifactDir, err := defaultArtifactDir(statePath)
	if err != nil {
		return err
	}

	p := policy.Defaults()
	p.Auth.BearerTokenFile = bearerPath
	p.Auth.AdminTokenFile = adminPath
	p.Artifact.Dir = artifactDir

	if err := policy.WriteFile(statePath, p); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	// The round-trip through the REAL decoder is the assertion, not a
	// belt-and-braces extra: a bootstrap file WriteFile can produce but
	// Load rejects would otherwise surface only as a confusing failure on
	// the NEXT start, with no hint that this run's own bootstrap wrote it.
	if _, err := policy.Load(statePath); err != nil {
		return fmt.Errorf("state file this daemon just wrote failed to load back: %w", err)
	}
	return nil
}

// defaultArtifactDir creates and returns the artifact directory a bootstrap
// falls back to: "artifacts" beside the state file, at 0700.
//
// AN EMPTY artifact.dir IS NOT A COSMETIC GAP — it is a daemon that
// authenticates fine and answers /readyz 503 FOREVER (the loopback harness's
// own D294). bootstrapDefaultState has always defaulted it for that reason;
// this is that same line, extracted so bootstrapSeedFromPolicy can reuse it
// (Rule 16/18) rather than hold a second copy of the same fallback — a
// --policy seed with no `artifact:` section produced exactly the
// permanently-unready daemon the default path was written to prevent.
func defaultArtifactDir(statePath string) (string, error) {
	dir := filepath.Join(filepath.Dir(statePath), "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create artifact directory %s: %w", dir, err)
	}
	return dir, nil
}

// bootstrapSeedFromPolicy is P2-T4, §2.5: the one-shot --policy seed. It
// loads the operator-supplied policy file UNCHANGED (so --policy's own
// existing requirements — most concretely, its own auth.bearer_token_file
// must exist and be readable — are exactly what Load already enforces),
// overwrites ONLY the decoded Auth paths with the two minted token files,
// and persists the rest of the seed VERBATIM. It then round-trips the
// result through Load exactly as bootstrapDefaultState does.
//
// Why overwrite Auth rather than keep the seed's own tokens: the operator
// was just shown the minted tokens (mintTokensIfAbsent's banner) and told
// those are the credentials that work. Persisting the seed's DIFFERENT
// tokens instead would make that banner's promise false the moment this
// function returns — the single most trust-critical output this daemon
// produces would be wrong on exactly the run where an operator is watching
// it for the first time.
func bootstrapSeedFromPolicy(statePath, policyFlagPath, bearerPath, adminPath string, logger *slog.Logger) error {
	seed, err := policy.Load(policyFlagPath)
	if err != nil {
		return fmt.Errorf("load --policy seed %s: %w", policyFlagPath, err)
	}

	seedBearer, seedAdmin := seed.Auth.BearerTokenFile, seed.Auth.AdminTokenFile
	seed.Auth.BearerTokenFile = bearerPath
	seed.Auth.AdminTokenFile = adminPath

	// AUTH IS NOT THE ONLY FIELD THE SEED CANNOT BE TRUSTED TO CARRY. A seed
	// that omits `artifact:` leaves Artifact.Dir empty, and policy.Load does
	// not reject that — it produces a daemon that starts, authenticates, and
	// answers /readyz 503 forever (D294), with nothing in the log naming the
	// cause. bootstrapDefaultState has always defaulted this; a seeded state
	// file has exactly the same requirement, so it gets exactly the same
	// fallback rather than silently inheriting the hole. An artifact.dir the
	// seed DID supply is left alone: that is the operator's own choice, and
	// overriding it would be the Auth override's rationale applied where it
	// does not hold.
	if seed.Artifact.Dir == "" {
		dir, derr := defaultArtifactDir(statePath)
		if derr != nil {
			return derr
		}
		seed.Artifact.Dir = dir
		logger.Warn("policy_seed_artifact_dir_defaulted",
			slog.String("policy_path", policyFlagPath),
			slog.String("artifact_dir", dir),
			slog.String("note", "the --policy seed carried no artifact.dir; an empty one would make "+
				"/readyz answer 503 for the life of the daemon, so it was defaulted beside the state file"))
	}

	if err := policy.WriteFile(statePath, seed); err != nil {
		return fmt.Errorf("write state file seeded from %s: %w", policyFlagPath, err)
	}
	if _, err := policy.Load(statePath); err != nil {
		return fmt.Errorf("state file seeded from %s failed to load back: %w", policyFlagPath, err)
	}

	logger.Warn("policy_seed_auth_overridden",
		slog.String("policy_path", policyFlagPath),
		slog.String("seed_bearer_token_file", seedBearer),
		slog.String("seed_admin_token_file", seedAdmin),
		slog.String("bearer_token_file", bearerPath),
		slog.String("admin_token_file", adminPath),
		slog.String("note", "the seed's own auth.bearer_token_file/auth.admin_token_file were NOT "+
			"adopted; the minted tokens shown at first run are authoritative -- recover them with "+
			"--print-tokens; --policy is now vestigial and is ignored on every later start"))
	return nil
}
