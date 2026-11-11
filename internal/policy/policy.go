// Package policy loads and enforces the server-side policy file (spec §12.3).
// It is a DECISION component (spec §6.1): it answers questions, holds no
// sockets, and never dials.
package policy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration decoded from a YAML string such as "1h".
// yaml.v3 has no native time.Duration support: it would decode a bare
// integer as nanoseconds, silently turning "registry_retention: 3600" into
// 3.6 microseconds. Requiring a string makes that mistake a load error.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a quoted or bare string such as \"1h\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// MarshalYAML implements yaml.Marshaler, the write-side counterpart of
// UnmarshalYAML above (Phase 2 §2.3: WriteFile round-trips a Policy through
// the SAME yaml: tags Load reads). Without this, yaml.v3's default encoding
// of a Duration -- an unexported-alias int64 -- would emit the raw
// nanosecond count as a bare integer, which UnmarshalYAML above deliberately
// REJECTS ("duration must be a quoted or bare string") to close the exact
// footgun this type exists to prevent. Emitting the same "1h"-style string
// UnmarshalYAML accepts is what makes WriteFile-then-Load idempotent rather
// than a load-time failure on the daemon's own output.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Policy is the parsed, validated and resolved policy file of spec §12.3.
// A *Policy is IMMUTABLE once returned by Load. Task 6's Store swaps whole
// *Policy values on SIGHUP; nothing ever mutates one in place, which is what
// makes §12.2.1's "a call continues under the policy in force when it
// started" a matter of holding a pointer rather than of copying fields.
type Policy struct {
	Auth Auth `yaml:"auth"`
	// Profiles WAS a []Profile registry of SIP accounts, resolved by name
	// (Phase 1a-3). DELETED in Phase 1 of the session-scoped UA lifecycle
	// wave (owner-locked decision): ua_create now takes an account INLINE on
	// the request, so there is no shared registry left to hold. A policy
	// file that still carries a `profiles:` key is rejected wholesale by
	// Load's strict decoder (KnownFields(true)) with a clear unknown-key
	// error, exactly like any other removed key.
	Destinations Destinations `yaml:"destinations"`
	Limits       Limits       `yaml:"limits"`
	Media        Media        `yaml:"media"`
	TLS          TLS          `yaml:"tls"`
	Capture      Capture      `yaml:"capture"`
	Artifact     Artifact     `yaml:"artifact"`
	Prompts      []Prompt     `yaml:"prompts"`

	// resolved at load; never carries a plaintext credential (see Step 10)
	allowRE       []*regexp.Regexp
	denyRE        []*regexp.Regexp
	bearerDigests [][32]byte
	adminDigest   [32]byte
	adminEnabled  bool
	tlsRootCAs    *x509.CertPool
}

// Auth holds the policy file's authentication material.
type Auth struct {
	BearerTokenFile string `yaml:"bearer_token_file"`
	// AdminTokenFile is the SEPARATE operator token of spec §12.7. Empty
	// (the default) means the /admin/* plane is NOT REGISTERED AT ALL — not
	// "registered and always 401". See AdminEnabled.
	AdminTokenFile string `yaml:"admin_token_file"`
}

// DefaultSessionExpiresS is the RFC 4028 Session-Expires a profile offers when
// it names none. It is declared here because validate() has to know it: the
// min_se_s / session_expires_s consistency check is meaningless without the
// value the omitted field resolves to.
//
// sipua.(*UA).sessionExpiresS applies the same default at send time and still
// spells it as a literal; that copy is outside this section's ownership and is
// reported rather than changed. The two must not diverge.
const DefaultSessionExpiresS = 1800

// Destinations holds the dial allow/deny pattern lists.
type Destinations struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// MaxRedirectsCeiling is the upper bound of limits.max_redirects, shared by
// validate() and config_set (Rule 18).
const MaxRedirectsCeiling = 10

// Limits holds the resource caps of spec §12.3.
type Limits struct {
	// Two INDEPENDENT concurrency caps, both checked, per-session first
	// (spec §12.2.2, locked decision U3). They are separate keys and a
	// denial names which one bound.
	MaxConcurrentCallsPerSession int `yaml:"max_concurrent_calls_per_session"`
	MaxConcurrentCallsTotal      int `yaml:"max_concurrent_calls_total"`

	// MaxRedirects bounds how many new INVITEs one call_dial may send to
	// 3xx redirect targets (RFC 3261 8.1.3.4, CF-090). 0 disables following.
	// The ceiling MaxRedirectsCeiling keeps one dial from fanning out into an
	// unbounded INVITE sequence. Daemon-wide: the destination policy each
	// target must pass is too, and an MCP client must not raise it.
	MaxRedirects int `yaml:"max_redirects"`

	MaxCallDurationS    int `yaml:"max_call_duration_s"`
	MaxUAsPerSession    int `yaml:"max_uas_per_session"`
	MaxUAsTotal         int `yaml:"max_uas_total"`
	InboundRingTimeoutS int `yaml:"inbound_ring_timeout_s"`

	// SessionTTL is a live MCP session's fixed lifetime while it owns at
	// least one live UA — the multi-UA-per-session wave's replacement for
	// the old hardcoded `sessionTTL` constant in internal/session/registry.go.
	// Renewed by exactly the same three call sites that constant's
	// renewTTLLocked already had (Open, CreateUA, SessionKeepalive). An
	// EMPTY session (zero live UAs) is governed by SessionResumeWindow
	// instead — see JanitorSweep's existing "§12.6 Lifetime rule" comment,
	// which this wave makes reachable for the first time.
	SessionTTL Duration `yaml:"session_ttl"`

	// MaxSessionsTotal bounds the number of DISTINCT logical sessions
	// (spec §12.6) the registry may hold at once. Compounds a
	// bearer-token-compromise blast radius into a bounded, not unbounded,
	// amount of server-side resource growth (production-hardening spec
	// Task 3). Checked in Manager.Open, live (not cached), same convention
	// as every other limit read at the top of a mutating call.
	MaxSessionsTotal int `yaml:"max_sessions_total"`

	// MaxStepDurationS is Phase 4 W1 M2's new §4 key (Inputs §4, RN-1): the
	// ceiling on any ONE media-plan step's declared or derived maximum length
	// (a wait/record's duration_ms, a wait_dtmf's timeout_ms, or a dtmf step's
	// derived len(digits) x (duration_ms + gap_ms) total). UNLIKE
	// max_call_duration_s, 0 is NOT a legal "uncapped" sentinel here —
	// decision 8's "0 is legal" ruling is scoped to max_call_duration_s only,
	// and extending it to this key would reopen the exact overflow hole this
	// ceiling exists to close (see validate()). Default 180s, chosen well
	// below the 300s DTMF render ceiling (mediaplan_validate.go's
	// dtmfRenderCeilingMs) so a default-policy plan step never has this bound
	// as its FIRST limiting factor for DTMF surfaces, while still being tight
	// enough to catch a runaway wait/record duration typo.
	MaxStepDurationS int `yaml:"max_step_duration_s"`

	// RegistryRetention is §N3's terminated-handle clock: how long a
	// terminated call or destroyed UA handle keeps answering `gone` rather
	// than `not_found`.
	//
	// KNOWN, ACCEPTED LIMITATION UNDER PHASE 1's FIXED SESSION TTL. Its
	// default is 1h, but no session can now outlive roughly 5.5 minutes
	// (internal/session's hardcoded 5-minute sessionTTL plus one 30s reaper
	// interval), and a session's death deletes every handle it retained —
	// destroySessionAndDelete evicts the whole retention set outright. On top
	// of that, the only clock-driven consumer of this value is the hourly
	// JanitorSweep, whose ticker cannot realistically fire inside a
	// five-minute session at all. SO THIS VALUE IS PRACTICALLY CAPPED AT THE
	// SESSION TTL and, for most configurations, has NO OBSERVABLE EFFECT
	// WHATSOEVER: the handle's `gone` window ends when its session does. The
	// agent-facing ua_destroy shortens it further, to zero — see UADestroy in
	// internal/session/destroy.go.
	//
	// WHAT STILL WORKS: MaxTerminatedCallsPerSession and
	// MaxTerminatedUAsPerSession below, which are enforced IMMEDIATELY on
	// every termination rather than on a ticker, and the admin DELETE path
	// (§12.7), which leaves its terminated entry inside a session that
	// survives it.
	//
	// The key is deliberately still accepted, validated and reported by
	// config_get unchanged: it is documented as limited, not removed.
	RegistryRetention            Duration `yaml:"registry_retention"`
	MaxTerminatedCallsPerSession int      `yaml:"max_terminated_calls_per_session"`
	MaxTerminatedUAsPerSession   int      `yaml:"max_terminated_uas_per_session"`

	// SessionResumeWindow is §12.6's idle window for an EMPTY session record
	// (no live UA, no live call, nothing retained) before JanitorSweep ages
	// it out.
	//
	// KNOWN, ACCEPTED LIMITATION UNDER PHASE 1's FIXED SESSION TTL, and it is
	// BROADER than RegistryRetention's: this one binds on NO session, not
	// merely on sessions that have owned a UA. The TTL reaper
	// (internal/session/reaper.go) deletes EVERY session past its 5-minute
	// deadline, empty or not, on a 30s tick — so an empty idle session is
	// gone long before a 1h resume window could apply, and the hourly
	// JanitorSweep that reads this value could only ever win the race if the
	// window were configured well below the TTL *and* its hourly tick
	// happened to land in the gap. In practice this value has no observable
	// effect on any session.
	//
	// Like RegistryRetention, the key is deliberately still accepted,
	// validated and reported by config_get unchanged.
	SessionResumeWindow Duration `yaml:"session_resume_window"`

	MaxWaitTimeoutMS     int `yaml:"max_wait_timeout_ms"`
	MaxWaitersPerCall    int `yaml:"max_waiters_per_call"`
	MaxWaitersPerSession int `yaml:"max_waiters_per_session"`

	// ShutdownGracePeriod is U12: §11.4 requires "a configurable grace period
	// (default 10 s)" and §12.7's admin DELETE depends on the same value, but
	// §12.3 defines NO key for it. ONE key, ONE default, read by both. This is a
	// POLICY KEY NOT IN §12.3 and MUST be recorded in the P1 closeout as a spec
	// amendment.
	ShutdownGracePeriod Duration `yaml:"shutdown_grace_period"` // 10s

	// EventLogSize is §N3's per-call event-log bound. §N3 states the default
	// 1024 in prose and §12.3 defines no key for it either; same closeout
	// treatment as ShutdownGracePeriod.
	EventLogSize int `yaml:"event_log_size"` // 1024

	// MaxLadders is U15: the bound on the NUMBER of ladder rings the trace sink
	// holds. DefaultLadderSize bounds each ring's DEPTH; without this key
	// nothing bounds how many rings exist.
	//
	// AS AMENDED BY U18, IT BOUNDS THE UNRETAINED RINGS ONLY. A ring retained by
	// session.Tap.Retain for a LIVE call is excluded from this count and is never
	// an LRU eviction candidate; Tap.Evict releases the retention at REGISTRY
	// EVICTION, not at terminal bookkeeping (U21). The total the store may hold is
	// therefore max_ladders plus one retained ring per registry-resident call —
	// max_concurrent_calls_total live, plus max_terminated_calls_per_session per
	// session inside the §N3 retention window — all policy-bounded, so §N3 still
	// holds. Without the exclusion the LRU evicts LIVE calls' ladders in
	// preference to dead keepalive rings — a P1 call writes nothing to its ladder
	// between the ACK and the BYE, so a held call's ring is by construction the
	// least-recently-written object, while `keepalive: "options"` refreshes its
	// own recency continuously. See session.Tap.Retain for the full argument.
	//
	// Why depth alone is insufficient: Tap.Evict only ever reaches Call-IDs the
	// session registry knows about. REGISTER, OPTIONS keepalives, failed dials
	// and inbound INVITEs rejected before a Call record exists all produce a
	// ladder that NOTHING evicts — unbounded growth on precisely the
	// long-lived-daemon workload §N3 was written for.
	//
	// Default 512, derived: 200 max_uas_total UAs each producing a REGISTER and
	// an OPTIONS Call-ID = 400, plus 50 max_concurrent_calls_total dialogs,
	// plus headroom. Consumed by trace.New(size, maxLadders) in P1c Task 16.
	// A policy key not in §12.3; same closeout treatment as the two above.
	MaxLadders int `yaml:"max_ladders"` // 512
}

// Media holds the RTP media configuration.
type Media struct {
	LocalIP        string `yaml:"local_ip"`
	PortRange      [2]int `yaml:"port_range"`
	JitterBufferMS int    `yaml:"jitter_buffer_ms"`
}

// TLS holds the mutual-TLS client certificate configuration (spec §12.5).
type TLS struct {
	CABundle           string `yaml:"ca_bundle"`
	ClientCert         string `yaml:"client_cert"`
	ClientKey          string `yaml:"client_key"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Capture holds the RTP capture configuration.
type Capture struct {
	MaxBytesPerCall int64 `yaml:"max_bytes_per_call"`
}

// Artifact holds the recorded-call artifact retention configuration.
type Artifact struct {
	Dir       string   `yaml:"dir"`
	Retention Duration `yaml:"retention"`
	MaxBytes  int64    `yaml:"max_bytes"`
}

// Prompt names a named prompt file playable during a call.
type Prompt struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// Prompt resolves a policy-registered prompt name to its file path (§12.3,
// §10.9). It is the ONLY way a prompt name becomes a path: media_play never
// accepts an arbitrary path, closing the path-traversal / arbitrary-file-read
// vector. ok is false for any unregistered name, including the empty string.
func (p *Policy) Prompt(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	for _, pr := range p.Prompts {
		if pr.Name == name {
			return pr.Path, true
		}
	}
	return "", false
}

// TLSRootCAs returns the resolved trust anchor for outbound TLS dials
// (Phase 4 M7b, §7.1), resolved once at Load from tls.ca_bundle. nil means
// "use the host roots" — either because ca_bundle is unset, or because p was
// built by Defaults()/NewStaticStore, which resolve no files. When non-nil,
// this pool REPLACES the host roots; it is never merged with
// x509.SystemCertPool() (owner-approved decision, §12.5 case 2).
func (p *Policy) TLSRootCAs() *x509.CertPool {
	return p.tlsRootCAs
}

// removedPolicyKeys are the top-level keys Phase 4 W1 deleted as dead
// config (commit 594902a). A small, explicit
// list — not a general "did you mean" fuzzy matcher for arbitrary policy
// keys (production-hardening spec Non-goals).
var removedPolicyKeys = []string{"webhooks", "quality"}

// wrapRemovedKeyHint appends a pointer to the release notes when a strict
// yaml.v3 decode error names one of removedPolicyKeys, so an operator
// upgrading an existing config can tell "this key was intentionally
// removed" apart from "I made a typo". The underlying reject-the-whole-file
// behavior (locked decision 4) is unchanged — this only improves the
// message. yaml.v3's *TypeError carries one string per unknown field,
// formatted "line N: field <name> not found in type <type>".
func wrapRemovedKeyHint(err error) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return err
	}
	for _, line := range typeErr.Errors {
		for _, key := range removedPolicyKeys {
			if strings.Contains(line, "field "+key+" not found") {
				return fmt.Errorf("%w (webhooks: and quality: were removed as dead config -- "+
					"delete the whole block from your policy file; see CHANGELOG.md)", err)
			}
		}
	}
	return err
}

// Load reads, decodes, validates and resolves a policy file.
//
// Decoding is STRICT (KnownFields(true), locked decision 4). Do not relax
// this. A misspelled key such as "destinations.deny_all" would otherwise
// load quietly with an EMPTY deny list — a policy BYPASS, not a typo — and
// §12.2.1 requires that an invalid file be rejected wholesale.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("policy: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	p := defaults()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy: %s: %w", path, wrapRemovedKeyHint(err))
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	if err := p.resolve(); err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return &p, nil
}

// defaults returns the §12.3 default policy. Load decodes ON TOP of this
// value, so an absent key keeps its default and only a PRESENT key
// overrides. This is why a default lives here and not in a getter: the
// decoded *Policy is the single source of truth for every consumer.
func defaults() Policy {
	return Policy{
		Limits: Limits{
			MaxConcurrentCallsPerSession: 50,
			MaxConcurrentCallsTotal:      50,
			MaxRedirects:                 3,
			// 7200s (Phase 4 W1 M2, Inputs §3): raised from 300s, which was too
			// tight for anything but a short probe call. See validate()'s 86400s
			// load-time ceiling, added in the same change.
			MaxCallDurationS: 7200,
			// MaxUAsPerSession defaults to 8 (multi-UA-per-session wave):
			// enough for a caller+callee+consult scenario plus headroom,
			// while staying well under max_uas_total's own default of 200.
			// Unlike Phase 1's pin, this key has no validate() bound of its
			// own — same convention as its sibling max_uas_total below, which
			// has never had one.
			MaxUAsPerSession:             8,
			SessionTTL:                   Duration(5 * time.Minute),
			MaxUAsTotal:                  200,
			InboundRingTimeoutS:          60,
			MaxSessionsTotal:             1000,
			RegistryRetention:            Duration(time.Hour),
			MaxTerminatedCallsPerSession: 500,
			MaxTerminatedUAsPerSession:   100,
			SessionResumeWindow:          Duration(time.Hour),
			MaxWaitTimeoutMS:             300000,
			MaxWaitersPerCall:            8,
			MaxWaitersPerSession:         64,
			// 180s (Phase 4 W1 M2, Inputs §4): the new per-step ceiling. See
			// validate()'s "0 is illegal here" check, added in the same change.
			MaxStepDurationS: 180,
			// U12 and §N3: two keys §12.3 does not define. Recorded in the
			// P1 closeout as spec amendments.
			ShutdownGracePeriod: Duration(10 * time.Second),
			EventLogSize:        1024,
			// U15: 200 UAs x (REGISTER + OPTIONS) = 400, plus 50 concurrent
			// dialogs, plus headroom. See the field's comment.
			MaxLadders: 512,
		},
		Media: Media{
			PortRange:      [2]int{16384, 32767},
			JitterBufferMS: 60,
		},
		Capture: Capture{
			MaxBytesPerCall: 52428800,
		},
		Artifact: Artifact{
			Retention: Duration(24 * time.Hour),
			MaxBytes:  10737418240,
		},
	}
}

// Defaults returns §12.3's documented defaults with NO auth material
// resolved. internal/session and the loopback harness use it, together with
// NewStaticStore (Task 6), to construct a Policy without a file on disk —
// which is what lets session read limits from the ONE canonical
// policy.Limits type rather than declaring a duplicate (U9, Rule 18).
//
// It deliberately shares defaults() with Load, so the two can never drift.
// It resolves no token files, so the returned Policy authenticates nothing
// and AdminEnabled() is false; the daemon must always go through Load.
func Defaults() *Policy {
	p := defaults()
	return &p
}

// validate performs every structural check, and compiles the destination
// patterns. It touches no files: validation must be able to reject a policy
// that names paths which do not exist, so that the ERROR §12.2.1 requires
// names the offending KEY rather than a missing file.
func (p *Policy) validate() error {
	if p.Auth.BearerTokenFile == "" {
		return fmt.Errorf("auth.bearer_token_file is required")
	}

	seenPrompt := make(map[string]struct{}, len(p.Prompts))
	for i, pr := range p.Prompts {
		if pr.Name == "" {
			return fmt.Errorf("prompts[%d].name is required", i)
		}
		if pr.Path == "" {
			return fmt.Errorf("prompts[%d].path is required (prompt %q)", i, pr.Name)
		}
		if _, dup := seenPrompt[pr.Name]; dup {
			return fmt.Errorf("prompts[%d].name %q is duplicated", i, pr.Name)
		}
		seenPrompt[pr.Name] = struct{}{}
	}

	var err error
	if p.allowRE, err = compilePatterns("destinations.allow", p.Destinations.Allow); err != nil {
		return err
	}
	if p.denyRE, err = compilePatterns("destinations.deny", p.Destinations.Deny); err != nil {
		return err
	}

	// §12.5: the mutual-TLS pair is all-or-nothing, checked at load rather
	// than at first connection, so a half-configured trunk is a startup or
	// reload failure and not a call that mysteriously fails hours later.
	switch {
	case p.TLS.ClientCert != "" && p.TLS.ClientKey == "":
		return fmt.Errorf("tls.client_cert is set but tls.client_key is not; both are required for mutual TLS")
	case p.TLS.ClientKey != "" && p.TLS.ClientCert == "":
		return fmt.Errorf("tls.client_key is set but tls.client_cert is not; both are required for mutual TLS")
	}

	// U12 and §N3: both keys default to a positive value, so a zero here
	// means the operator wrote one explicitly. Reject it rather than treat
	// it as "disabled" — a zero grace period makes §11.4's BYE wait and
	// §12.7's admin DELETE return before any peer can answer, and a zero
	// event-log bound silently discards every §10.5 event.
	if p.Limits.ShutdownGracePeriod.Duration() <= 0 {
		return fmt.Errorf("limits.shutdown_grace_period must be positive, got %v",
			p.Limits.ShutdownGracePeriod.Duration())
	}
	if p.Limits.SessionTTL.Duration() <= 0 {
		return fmt.Errorf("limits.session_ttl must be positive, got %s",
			p.Limits.SessionTTL.Duration())
	}
	if p.Limits.EventLogSize <= 0 {
		return fmt.Errorf("limits.event_log_size must be positive, got %d", p.Limits.EventLogSize)
	}
	// U15: zero would mean the ladder store holds nothing, so call_ladder
	// would return an empty ladder for every call while D9a promises the
	// ladder is unconditional.
	if p.Limits.MaxLadders <= 0 {
		return fmt.Errorf("limits.max_ladders must be positive, got %d", p.Limits.MaxLadders)
	}

	// production-hardening spec Task 3: zero or negative would mean the
	// registry accepts no sessions at all, silently wedging every
	// session_open call rather than surfacing a config mistake.
	if p.Limits.MaxSessionsTotal <= 0 {
		return fmt.Errorf("limits.max_sessions_total must be positive, got %d", p.Limits.MaxSessionsTotal)
	}
	// Rule 13 Cycle 6 (finding F3): an upper bound too. Manager.Open's
	// pressure-triggered eviction (registry.go) does a linear scan of
	// m.sessions WHILE HOLDING m.mu, the registry's global mutex, so an
	// operator misconfiguration setting this absurdly high turns every Open
	// call under cap pressure into a self-inflicted lock-contention
	// amplifier. 100000 is comfortably above any realistic legitimate
	// deployment (the default is 1000) and well below where that scan
	// becomes a real contention risk.
	if p.Limits.MaxSessionsTotal > 100000 {
		return fmt.Errorf("limits.max_sessions_total must not exceed 100000, got %d", p.Limits.MaxSessionsTotal)
	}

	// Phase 4 W1 M2, Inputs §3: max_call_duration_s's LOAD-TIME ceiling. 0
	// stays legal and means "uncapped" (decision 8) — CallDeadline and
	// ClampDuration (duration.go) both test that raw value BEFORE any
	// multiplication, never inferring "uncapped" from overflowed arithmetic.
	// Every OTHER value is bounded to one day (86400s) for the same reason
	// session_expires_s and expires_s are bounded above, in this same
	// function: an unreasonably large cap reaches those two functions' int
	// seconds x time.Second multiplication, which overflows into a negative
	// time.Duration once the configured value exceeds roughly 9.2e9 seconds.
	// Bounding the value here removes that multiplication's ability to
	// overflow at all for anything Load ever produces — 86400 x 1e9 is
	// trivially representable.
	if p.Limits.MaxCallDurationS < 0 || p.Limits.MaxCallDurationS > 86400 {
		return fmt.Errorf("limits.max_call_duration_s must be 0 (uncapped) or between 1 and 86400, got %d",
			p.Limits.MaxCallDurationS)
	}
	// Phase 4 W1 M2, Inputs §4 (RN-1): max_step_duration_s has NO uncapped
	// sentinel — decision 9 scopes decision 8's "0 is legal" ruling to
	// max_call_duration_s alone, and letting 0 mean "uncapped" here would
	// reopen the exact per-step overflow hole this ceiling exists to close
	// (a media-plan wait/record/wait_dtmf field reaching sipua's
	// time.Duration(ms)*time.Millisecond unbounded). The upper ceiling is the
	// same 86400s outer bound as max_call_duration_s, for the same overflow
	// reason and because there is no argument for a single media-plan step
	// needing to run longer than the longest call this daemon will hold open.
	if p.Limits.MaxRedirects < 0 || p.Limits.MaxRedirects > MaxRedirectsCeiling {
		return fmt.Errorf("limits.max_redirects must be between 0 and %d, got %d",
			MaxRedirectsCeiling, p.Limits.MaxRedirects)
	}
	if p.Limits.MaxStepDurationS <= 0 || p.Limits.MaxStepDurationS > 86400 {
		return fmt.Errorf("limits.max_step_duration_s must be between 1 and 86400, got %d",
			p.Limits.MaxStepDurationS)
	}

	// capture.max_bytes_per_call: 0 means UNBOUNDED (the capture engine treats
	// <=0 as no cap); a positive value must fit at least the pcap global
	// header (24 bytes), else the per-call truncation math underflows. Reject
	// a sub-header positive value (and any negative) at LOAD, so a bad policy
	// fails at startup rather than on every capture.
	if b := p.Capture.MaxBytesPerCall; b < 0 || (b > 0 && b < 24) {
		return fmt.Errorf("capture.max_bytes_per_call must be 0 (unbounded) or at least 24 "+
			"(the pcap header size), got %d", b)
	}

	return nil
}

// ValidKeepaliveMode reports whether mode is a keepalive value sendKeepalive
// (internal/sipua) actually implements: "none", "crlf", "options", or "" —
// which means "not supplied" and falls through to the profile's value and
// then the per-mode default, so it is valid here and is NOT the same thing as
// "none".
//
// This is the one place the set is written FOR THE TWO VALIDATION BOUNDARIES.
// The earlier version of this sentence claimed it was the ONE place the set is
// written, full stop, and that was false at the time: the set existed in THREE
// places — here, startKeepalive's arming switch, and sendKeepalive's dispatch
// switch (both internal/sipua/keepalive.go). Phase 4 W1 M3's Cycle 5 fix
// collapsed those two into ONE function, keepaliveSender, so the set is now
// written in exactly TWO places: here, and keepaliveSender itself. Only the
// two boundaries below are this function's to own.
//
// Those two are independent and cannot see each other's input: this package's
// own profile validation below, and internal/session's ua_create input
// validation, where a caller can name a mode the loaded profile never did.
// Both must call this rather than repeat the enum, or one can drift out of
// sync with keepaliveSender while the other still accepts (or rejects) it.
//
// SIPUA'S keepaliveSender IS PINNED AGAINST THIS FUNCTION BY TEST, NOT BY
// IMPORT. keepalive_test.go's TestSipuaKeepaliveModesAgreeWithPolicyValidKeepaliveMode
// (formerly the cross-package half of TestKeepaliveArmsExactlyTheModesSendKeepaliveImplements,
// renamed once the arming-vs-dispatch half it also drove went tautological
// under the Cycle 5 consolidation) fails if this function accepts a mode
// sipua will not arm, or rejects one it implements. It is a test rather than
// a shared constant because internal/sipua deliberately has no edge to this
// package — the SIP stack stays off the YAML schema — so the coupling is
// stated where it can fail loudly instead of being hidden behind an import.
func ValidKeepaliveMode(mode string) bool {
	switch mode {
	case "", "none", "crlf", "options":
		return true
	default:
		return false
	}
}

func compilePatterns(key string, pats []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(pats))
	for i, pat := range pats {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: invalid regex %q: %w", key, i, pat, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// resolve performs the load's file I/O: token digests and the mutual-TLS
// pair. It runs after validate, so every path it touches has already been
// structurally checked.
func (p *Policy) resolve() error {
	toks, err := readBearerTokens(p.Auth.BearerTokenFile)
	if err != nil {
		return fmt.Errorf("auth.bearer_token_file: %w", err)
	}
	p.bearerDigests = make([][32]byte, len(toks))
	for i, tok := range toks {
		p.bearerDigests[i] = sha256.Sum256([]byte(tok))
	}

	if p.Auth.AdminTokenFile != "" {
		adm, err := readTokenFile(p.Auth.AdminTokenFile)
		if err != nil {
			return fmt.Errorf("auth.admin_token_file: %w", err)
		}
		p.adminDigest = sha256.Sum256([]byte(adm))
		p.adminEnabled = true
	}

	// §12.5: the pair must PARSE AND MATCH at load, not at first connection.
	// crypto/tls is used here ONLY for LoadX509KeyPair, which reads two files
	// from disk and never opens a socket; internal/policy must never open one
	// (spec §6.1, this package is a DECISION component).
	if p.TLS.ClientCert != "" {
		if _, err := tls.LoadX509KeyPair(p.TLS.ClientCert, p.TLS.ClientKey); err != nil {
			return fmt.Errorf("tls.client_cert/tls.client_key do not form a usable pair: %w", err)
		}
	}

	// Phase 4 M7b, §7.1: tls.ca_bundle resolves to a *x509.CertPool at load,
	// same all-or-nothing shape as the mTLS pair above — missing, unreadable
	// or unparseable is a whole-file load rejection (Load's caller already
	// abandons wholesale on any resolve() error), not a lazily-discovered
	// dial-time failure. The resulting pool REPLACES the host roots rather
	// than adding to them (owner-approved decision): it is never seeded from
	// x509.SystemCertPool().
	if p.TLS.CABundle != "" {
		b, err := os.ReadFile(p.TLS.CABundle)
		if err != nil {
			return fmt.Errorf("tls.ca_bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return fmt.Errorf("tls.ca_bundle %s contains no PEM certificate", p.TLS.CABundle)
		}
		p.tlsRootCAs = pool
	}
	return nil
}

// readTokenFile reads a credential file and trims surrounding whitespace, so
// that a trailing newline left by an editor does not change the token. The
// contents are returned to the caller and NEVER retained on the Policy.
func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("file %s is empty", path)
	}
	return v, nil
}

// readBearerTokens reads auth.bearer_token_file as one token per line, so a
// separate token can be handed to each machine/agent and revoked
// independently (delete its line, reload) without touching anyone else's.
// A line may carry a trailing "#<remark>" the operator appends purely for
// their own bookkeeping -- e.g. which machine a line belongs to; the remark
// is discarded here and never hashed, stored, or reported back anywhere. A
// line that is blank, or entirely a comment, is skipped. At least one real
// token is required, matching readTokenFile's "must not be empty" posture.
func readBearerTokens(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var toks []string
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		toks = append(toks, line)
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("file %s is empty", path)
	}
	return toks, nil
}
