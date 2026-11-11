package sipua

// Task 26: NAT keepalive — crlf and options.
//
// Landmine (spec §7), historical: an earlier release plumbed
// policy.Profile.Keepalive all the way to sipua.Config.Keepalive but READ IT
// NOWHERE — ua_status advertised a mode that never fired. This is where it
// starts firing. policy.Profile itself is deleted as of the session-scoped UA
// lifecycle wave (Phase 1): Keepalive's value now arrives via ua_create's
// inline `keepalive` field (session.ToolService.UACreate), threaded through
// the SAME UAConfig.Keepalive -> sipua.Config.Keepalive path this comment
// describes.
//
// crlf writes RFC 5626 §3.5.1's double-CRLF ping on the signalling socket
// toward the registrar. options sends an out-of-dialog OPTIONS — new code,
// since the engine has always ANSWERED OPTIONS (srv.OnOptions) and never sent
// one. Both modes log and continue on failure; the keepalive never terminates
// anything (spec §2.4's table) — the policy below carries no Retry and no
// OnGiveUp, and Do swallows the send error rather than returning it, so no
// error ever reaches the refresher at all.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

// log is the UA's logger, never nil. Config.Logger is optional and is nil
// throughout this package's own test suite; an slog method on a nil *Logger
// panics (SIGSEGV in log/slog.(*Logger).Handler), and it would panic on the
// refresher's goroutine, killing the process rather than failing a test.
// newRefresher already nil-normalises its own copy; these call sites do not
// go through it.
func (u *UA) log() *slog.Logger {
	return logOrDefault(u.cfg.Logger)
}

// logOrDefault is the nil-safe logger idiom (C6): an slog method on a nil
// *Logger panics (SIGSEGV in log/slog.(*Logger).Handler), so any call site
// without a *UA to read (*UA).log() through — such as newTLSConfigs, which
// runs before a UA exists — normalises through this instead of inventing a
// fourth idiom.
func logOrDefault(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

// startKeepalive arms the NAT keepalive refresher when Config.Keepalive names
// a mode other than "none". It is armed at CONSTRUCTION, not at Register: a
// direct-mode UA has no registrar and arms nothing (keepaliveTarget is ""),
// and a register-mode UA's binding needs keeping open from the moment it
// binds, including across a REGISTER that has not succeeded yet.
//
// AN UNRECOGNISED MODE ARMS NOTHING, AND THAT IS THE POINT OF THE GATE BELOW.
// This used to arm for any non-empty non-"none" string, so a one-character typo
// ("crfl") armed a refresher whose every tick was a no-op: sendKeepalive's
// default: returned `unknown mode "crfl"`, the Do closure below swallowed it
// into a Warn and returned nil — every interval, forever, with nothing ever
// sent — while ua_status went on reporting the mode as configured. That is
// exactly the "advertised mode that never fires" defect this file exists to end,
// restored by a typo, and under NAT its consequence is inbound calls quietly
// stopping once the pinhole times out. It is refused ONCE, at Error, instead.
//
// The accepted set here and sendKeepalive's dispatch switch are the SAME
// FUNCTION now (keepaliveSender, Phase 4 W1 M3 Cycle 5), not two switches kept
// in sync by hand — a mode accepted here but not implemented there is no
// longer constructible. keepalive_test.go's TestSipuaKeepaliveModesAgreeWithPolicyValidKeepaliveMode
// still pins the one divergence this consolidation cannot see: whether this
// package's implemented set agrees with policy.ValidKeepaliveMode
// (internal/policy), a cross-package fact no shared function can express
// (internal/sipua has no import edge to internal/policy and must not grow
// one).
func (u *UA) startKeepalive() {
	mode := u.cfg.Keepalive
	switch mode {
	case "", "none":
		// Explicit "do not arm", distinct from a mode this package simply does
		// not implement — keepaliveSender returning nil means the latter.
		return
	}
	if u.keepaliveSender(mode) == nil {
		u.log().Error("keepalive: unrecognised mode; not arming (nothing would ever be sent)",
			"mode", mode, "supported", "none, crlf, options")
		return
	}
	if u.keepaliveTarget() == "" {
		// D-M3 (D20, W2): "NO REGISTRAR" IS THE WHOLE CONDITION. The old wording said
		// "No registrar and no outbound proxy", which promised an outbound-proxy next hop
		// keepaliveTarget has never consulted — it reads registrarHostPort(u.cfg) and
		// nothing else. A direct-mode UA has no registrar, so it has no keepalive target,
		// full stop. If an outbound proxy ever becomes a configurable next hop, THIS is
		// the function that must learn about it, and this comment is the marker.
		u.log().Debug("keepalive: no target; not arming", "mode", mode)
		return
	}
	r := newRefresher(u.cfg.Clock, u.log(), refreshPolicy{
		Name:     "keepalive",
		Fraction: 1.0, // a fixed period, not a fraction of an expiry
		Initial:  time.Duration(u.keepaliveIntervalS()) * time.Second,
		Do: func(ctx context.Context) (int, error) {
			if err := u.sendKeepalive(ctx, mode); err != nil {
				// Logged, NOT returned: returning an error would consume the
				// refresher's attempt budget and eventually reach OnGiveUp, and
				// a keepalive must never escalate.
				u.log().Warn("keepalive send failed",
					"mode", mode, "target", u.keepaliveDestination(), "err", err)
			}
			return 0, nil // interval unchanged
		},
	})
	ctx, cancel := u.refresherCtx()
	u.reg.mu.Lock()
	u.reg.keepalive, u.reg.keepaliveCancel = r, cancel
	u.reg.mu.Unlock()
	r.Start(ctx)
}

// keepaliveTarget is the "host:port" the keepalive is aimed at: the registrar
// in register mode, "" in direct mode (no NAT binding to maintain).
//
// THE DEFAULT PORT IS LOAD-BEARING. A registrar configured without one
// ("sip:pbx.example.com") is legal — policy validates nothing on the field and
// routeLookup falls through to §6.5.3 rule 4 — but net.ResolveUDPAddr then
// returns "missing port in address" and the crlf keepalive silently never
// fires, which is precisely the defect this task exists to fix. Since CF-188 it
// serves the arm gate, the CRLF fallback before the first answered REGISTER
// (keepaliveDestination) and the Warn's target; the CRLF otherwise goes where
// REGISTER went, and the OPTIONS URI carries no injected port.
func (u *UA) keepaliveTarget() string {
	hp := registrarHostPort(u.cfg)
	if hp == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(hp); err != nil {
		port := "5060"
		if strings.HasPrefix(strings.ToLower(u.cfg.Registrar), "sips:") {
			port = "5061"
		}
		hp = net.JoinHostPort(hp, port) // brackets an IPv6 literal correctly
	}
	return hp
}

// keepaliveSendTimeout bounds ONE keepalive attempt at min(interval,
// cfg.Timeout): a keepalive has no reason to outlive its own period, because
// the interval IS the retry.
//
// IT IS NOT THE SHUTDOWN BOUND, AND THE COMMENT THAT SAID IT WAS WAS WRONG.
// That claim ("a 32s transaction timeout makes ua_destroy and daemon shutdown
// hang, so min() fixes it") does not hold at any configuration an operator can
// reach: policy.Validate floors keepalive_interval_s at 5 and cfg.Timeout
// defaults to 32s, so at production defaults min(30, 32) is 30 SECONDS — the
// value the bound was supposed to avoid, and exactly the duration Close was
// measured blocking for. The only test that appeared to prove otherwise ran at
// keepalive_interval_s=1, which policy rejects.
//
// What actually bounds shutdown is stopRefresher (register.go): it cancels the
// refresher's attempt context before joining the goroutine, which aborts the
// in-flight transaction regardless of what this returns.
func (u *UA) keepaliveSendTimeout() time.Duration {
	d := time.Duration(u.keepaliveIntervalS()) * time.Second
	if u.cfg.Timeout > 0 && u.cfg.Timeout < d {
		d = u.cfg.Timeout
	}
	return d
}

// keepaliveSender returns the function that sends ONE keepalive in mode, or
// nil when this package does not implement mode (Cycle 5). startKeepalive's
// arming gate and sendKeepalive's dispatch below both resolve through this
// SAME function, so an arm-gate/dispatch-switch divergence — two hand-written
// switches drifting apart, the defect the retired half of
// TestKeepaliveArmsExactlyTheModesSendKeepaliveImplements used to catch — is
// no longer constructible: there is only one place left to drift.
func (u *UA) keepaliveSender(mode string) func(context.Context) error {
	switch mode {
	case "crlf":
		return func(ctx context.Context) error {
			err := u.sendCRLFKeepalive()
			if crlfUnsupported(err) {
				u.log().Debug("keepalive: crlf unavailable on this transport; sending OPTIONS instead",
					"transport", u.Transport())
				return u.sendOPTIONSKeepalive(ctx)
			}
			return err
		}
	case "options":
		return u.sendOPTIONSKeepalive
	default:
		return nil
	}
}

// sendKeepalive dispatches one keepalive in the configured mode.
func (u *UA) sendKeepalive(ctx context.Context, mode string) error {
	send := u.keepaliveSender(mode)
	if send == nil {
		return fmt.Errorf("keepalive: unknown mode %q", mode)
	}
	return send(ctx)
}

// errCRLFUnsupported marks the stream-transport case sendKeepalive turns into
// an OPTIONS.
var errCRLFUnsupported = fmt.Errorf("keepalive: crlf is not available on a stream transport")

// crlfUnsupported reports whether err means "crlf keepalive is not available
// on this transport" (D20 D-M5). errors.Is, NOT ==: sendCRLFKeepalive's own
// `return errCRLFUnsupported` is unwrapped today, which is the only reason `==`
// was ever safe here, but sibling error returns in this file already wrap
// with %w — a comparison that only survives the unwrapped case is one
// signature change away from silently breaking the crlf->OPTIONS fallback.
func crlfUnsupported(err error) bool {
	return errors.Is(err, errCRLFUnsupported)
}

// keepaliveDestination is where the CRLF ping goes: the last answered
// REGISTER's destination, else keepaliveTarget().
func (u *UA) keepaliveDestination() string {
	if d := u.registerDestination(); d != "" {
		return d
	}
	return u.keepaliveTarget()
}

// sendCRLFKeepalive writes RFC 5626 §3.5.1's double-CRLF ping on the
// signalling socket, toward the registrar.
//
// THE DESTINATION IS WHERE THE LAST ANSWERED REGISTER WENT (CF-188, D6C-3): the
// fork resolved the registrar SRV-first (RFC 3263 4.2) and the ping must refresh
// that flow's NAT binding, so it reuses that result instead of resolving again
// (a second LookupSRV randomises by weight and can pick another target). Before
// any REGISTER was answered it falls back to keepaliveTarget().
//
// UDP ONLY, AND THE FALLBACK IS DELIBERATE. On tcp/tls the connection is owned
// by sipgo's transport pool and sipua holds no net.Conn to write to, so there
// is nothing to write the CRLF on. Falling back to an OPTIONS keeps the
// binding open there instead of silently doing nothing — a silent no-op would
// reproduce exactly the "advertised mode that never fires" defect this task
// exists to fix.
func (u *UA) sendCRLFKeepalive() error {
	if u.conn == nil {
		return errCRLFUnsupported
	}
	target := u.keepaliveDestination()
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("keepalive: resolve %q: %w", target, err)
	}
	if _, err := u.conn.WriteTo([]byte("\r\n\r\n"), addr); err != nil {
		return fmt.Errorf("keepalive: write crlf: %w", err)
	}
	return nil
}

// keepaliveOptionsURI is the OPTIONS Request-URI: the registrar as configured
// (scheme lower-cased, host and port as given, no user, parameters or headers).
// It deliberately carries NO injected default port, so the fork resolves it
// exactly as it resolves REGISTER's Request-URI, SRV first when portless
// (CF-188, D6C-4). The scheme comes from the parsed registrar: engineConfig()'s
// TargetURI keeps a sips: registrar's scheme verbatim, and a hardcoded "sip:"
// would downgrade it.
func (u *UA) keepaliveOptionsURI() (sip.Uri, error) {
	reg, err := parseSIPURI(u.cfg.Registrar)
	if err != nil {
		return sip.Uri{}, err
	}
	return sip.Uri{Scheme: strings.ToLower(reg.Scheme), Host: reg.Host, Port: reg.Port}, nil
}

// sendOPTIONSKeepalive sends an OUT-OF-DIALOG OPTIONS to the registrar. It is
// new code: the engine has always ANSWERED OPTIONS (srv.OnOptions) and has
// never sent one, so there is no builder to reuse — this is the minimum
// request RFC 3261 §11 requires, built from the same engineConfig() every
// other outbound request is built from so the From identity agrees with them.
//
// Any final response counts as success, including a 405: the point is proof
// that the path is open, not that the far end implements OPTIONS.
func (u *UA) sendOPTIONSKeepalive(ctx context.Context) error {
	uri, err := u.keepaliveOptionsURI()
	if err != nil {
		return fmt.Errorf("keepalive: parse registrar %q: %w", u.cfg.Registrar, err)
	}
	req := sip.NewRequest(sip.OPTIONS, uri)
	ecfg := u.engineConfig()
	from := &sip.FromHeader{
		Address: sip.Uri{User: ecfg.FromUser, Host: ecfg.FromDomain},
		Params:  sip.NewParams(),
	}
	from.Params.Add("tag", sip.GenerateTagN(10))
	// The To carries NO tag: this is an out-of-dialog request.
	to := &sip.ToHeader{Address: uri}
	req.AppendHeader(from)
	req.AppendHeader(to)
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	if t := u.Transport(); !strings.EqualFold(t, "udp") {
		req.Recipient.UriParams = sip.NewParams()
		req.Recipient.UriParams.Add("transport", strings.ToLower(t))
	}
	ensureSupportedTimer(req) // RFC 4028 7.1 (CF-113)
	if _, err := u.Client().RawTransaction(ctx, req, u.keepaliveSendTimeout()); err != nil {
		return fmt.Errorf("keepalive: OPTIONS: %w", err)
	}
	return nil
}
