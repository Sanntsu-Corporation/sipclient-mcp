// internal/sipua/sessiontimer_m4_test.go
//
// Phase 4 W1 module M4: F4(b) (item 1), C3 (item 2), C2 (item 3) and A-M5
// (item 6). C9/A-M6 (item 4) and C-M1 (item 7) live in sessiontimer_test.go
// (package sipua) since they need unexported state a black-box test cannot
// reach; A-M4 (item 5) is comment-only and has no test. See the M4 brief for
// the full item list.
package sipua_test

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newSessionTimerUAWithLogger is newSessionTimerUAFull (sessiontimer_refresh_test.go)
// with an explicit Config.Logger, which that family of constructors has no
// parameter for. Built standalone rather than widening
// newSessionTimerUAFull's four existing call sites (Rule 19): this file is
// the only caller that needs to assert on log content.
func newSessionTimerUAWithLogger(t *testing.T, clk *fakeclock.Clock, ses, minSE int, logger *slog.Logger) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport:          "udp",
		Mode:               "direct",
		AOR:                "sip:alice@example",
		ExpiresS:           300,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              clk,
		LocalAddr:          "127.0.0.1:0",
		SessionExpiresS:    ses,
		MinSES:             minSE,
		Logger:             logger,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

// TestARefreshResponseNamingThePeerHandsOverTheRefresherRole (CF-115; rewritten
// from F4(b)'s TestARefreshResponseCannotFlipTheRefresherRole, the owner-approved
// rejection the locked CF-115 decision reverses): a peer's 200 to OUR refresh that
// names the peer as refresher (RFC 4028 7.2, rfc4028.txt:521-523) hands the role
// over: SessionTimerView reports it, we stop refreshing, and no "would flip" WARN
// is logged (the rejection it described no longer exists).
func TestARefreshResponseNamingThePeerHandsOverTheRefresherRole(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires:  "90;refresher=uac",
			RefreshSessionExpires: []string{"90;refresher=uas"},
			AnswerAllow:           "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	logBuf := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newSessionTimerUAWithLogger(t, clk, 1800, 60, logger)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if v, ok := ua.SessionTimerView(res.DialogID); !ok || v.Refresher != "uac" {
		t.Fatalf("view=%+v ok=%v want the negotiated uac before any refresh", v, ok)
	}

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // RFC 4028 §10: interval/2 = 45s
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	waitFor(t, events, session.UAEventSessionRefresh, 0)

	waitForCond(t, func() bool {
		v, ok := ua.SessionTimerView(res.DialogID)
		return ok && v.Refresher == "uas" && v.Armed && v.NextRefreshMs > 89_000 && v.NextRefreshMs <= 90_000
	})

	// We are no longer the one refreshing: a further half-interval produces no
	// second UPDATE (a refresher dialog would have sent one).
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if n := p.Count("UPDATE"); n != 1 {
		t.Fatalf("UPDATE count=%d, want 1: we kept refreshing after the peer took the role", n)
	}
	if logged := logBuf.String(); strings.Contains(logged, "would flip") {
		t.Fatalf("the removed F4(b) rejection WARN was logged: %s", logged)
	}
}

// TestAnIntentionalWatchdogExpiryLogsDebugNotWarn is C3's (item 2) acceptance
// test. refreshPolicy for the watchdog sets no Retry, so attempts=1 and
// (pre-fix) every intentional expiry hit attempt()'s n==attempts unclassified
// path and logged "refresh gave up" at WARN — 100% reproduction, and exactly
// what real monitoring log-greps for WARN would false-alarm on. After the
// fix, expireSessionTimer's Do wraps errRefresherStopped, so refresher.go's
// Start loop classifies it as an intentional stop and logs "refresher
// stopping" at DEBUG instead.
//
// Reuses TestSuppressedPeerRefreshExpiresTheSessionWithCause408's fixture
// shape (sessiontimer_watchdog_test.go) — same peer behaviour, same
// assertions on the BYE/cause — plus the log-content check this item adds.
//
// Mutation-tested: reverting the Do's `return 0, fmt.Errorf("%w: %v",
// errRefresherStopped, errSessionExpired)` to the bare `return 0,
// errSessionExpired` reddens the Debug-not-Warn assertion below — see the
// implementer's mutation-proof log.
func TestAnIntentionalWatchdogExpiryLogsDebugNotWarn(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr:      "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSessionExpires: "90;refresher=uas"},
	})
	logBuf := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newSessionTimerUAWithLogger(t, clk, 1800, 90, logger)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(91 * time.Second) // past the full interval: the watchdog fires
	p.WaitForBye(t, 5*time.Second)

	ended := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseSessionTimerExpired || ended.DialogID != res.DialogID {
		t.Fatalf("cause=%q dialog_id=%q want session_timer_expired on %q — unchanged by this item",
			ended.Cause, ended.DialogID, res.DialogID)
	}

	// The refresher goroutine logs "refresher stopping"/"refresh gave up" from
	// its own Start() loop as it exits; give it a moment past the BYE to land.
	deadline := time.Now().Add(3 * time.Second)
	var logged string
	for time.Now().Before(deadline) {
		logged = logBuf.String()
		if strings.Contains(logged, "refresher stopping") || strings.Contains(logged, "refresh gave up") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Contains(logged, "level=WARN") && strings.Contains(logged, "refresh gave up") {
		t.Fatalf("intentional expiry logged the misleading \"refresh gave up\" WARN: %s", logged)
	}
	if !strings.Contains(logged, "level=DEBUG") || !strings.Contains(logged, "refresher stopping") {
		t.Fatalf("no DEBUG \"refresher stopping\" line found for the intentional expiry; log=%s", logged)
	}
}

// updateSwallowConn is a net.PacketConn decorator that drops the FIRST
// outbound UPDATE write (returning success without ever putting it on the
// wire) so RawTransaction blocks inside Timer B/F — the in-flight window
// TestUADestroyMidRefreshProducesNoRetryingWARN needs to close the UA while a
// refresh is still outstanding. It reuses firstLine (countingconn_test.go,
// same sipua_test package), the same seam updateFailConn
// (sessiontimer_refresh_test.go) already uses.
type updateSwallowConn struct {
	net.PacketConn
	swallowed atomic.Bool
}

func (c *updateSwallowConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.swallowed.Load() && strings.HasPrefix(firstLine(b), "UPDATE ") {
		c.swallowed.Store(true)
		return len(b), nil // report success; the write never actually reaches the peer
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestUADestroyMidRefreshProducesNoRetryingWARN is C2's (item 3) acceptance
// test. refreshSession's ctxErr branch (the outer `if err != nil { if ctxErr
// := ctx.Err(); ctxErr != nil {...} }`) used to return the bare ctx.Err()
// when the UA's own lifetime ended mid-refresh. On attempt()'s FIRST attempt
// this bare error is not yet exhausted (n=1 of Attempts=2), so (pre-fix) it
// fell into the ordinary "refresh attempt failed; retrying" WARN path before
// the retry-wait's own select happened to reclassify it as
// errRefresherStopped one line later — a spurious, misleading WARN for an
// intentional shutdown. After the fix, attempt()'s C4-precedent short-circuit
// (errors.Is(err, errRefresherStopped) at refresher.go:284) fires
// immediately on the wrapped error, before that log statement is ever
// reached, and the retry budget is never spent chasing a UA that is already
// gone.
//
// Mutation-tested: reverting the ctxErr wrap to the bare `return 0, ctxErr`
// reddens the no-WARN assertion below — see the implementer's mutation-proof
// log.
func TestUADestroyMidRefreshProducesNoRetryingWARN(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
		},
	})
	logBuf := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clk := fakeclock.New(time.Unix(0, 0))
	var sc *updateSwallowConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example",
		ExpiresS: 300, Timeout: 5 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: clk, LocalAddr: "127.0.0.1:0",
		SessionExpiresS: 1800, MinSES: 60, Logger: logger,
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			sc = &updateSwallowConn{PacketConn: pc}
			return sc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // fires the refresh; its UPDATE write is swallowed
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !sc.swallowed.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	if !sc.swallowed.Load() {
		t.Fatal("the refresh's UPDATE was never sent — nothing was in flight to cancel")
	}

	// The UA's own lifetime ends while the refresh is still parked in Timer
	// B/F, with no response ever coming: exactly "UA destroy mid-refresh".
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Give the refresher goroutine a moment to observe ctx.Done() and exit.
	time.Sleep(300 * time.Millisecond)

	logged := logBuf.String()
	if strings.Contains(logged, "refresh attempt failed; retrying") {
		t.Fatalf("UA-destroy-mid-refresh logged the misleading \"retrying\" WARN: %s", logged)
	}
	if strings.Contains(logged, "refresh gave up") {
		t.Fatalf("UA-destroy-mid-refresh logged the misleading \"gave up\" WARN: %s", logged)
	}
	_ = res
}

// a422RefreshStub is a small, purpose-built fake peer for A-M5 (item 6): it
// answers the initial INVITE normally, then answers the FIRST session-timer
// refresh UPDATE with "422 Session Interval Too Small" carrying a
// caller-supplied Min-SE, and every later UPDATE with 200. Not
// internal/testutil/peer: that package's only 422 support
// (Behaviour.Reject422MinSE) is scoped to the INITIAL INVITE, not an
// in-dialog refresh, and extending it is out of this task's file list — this
// mirrors sessiontimer_refresh_test.go's own precedent for a scenario the
// shared peer fake does not cover (reInviteRingThenSilentStub, updateFailConn).
type a422RefreshStub struct {
	conn    net.PacketConn
	parser  *sip.Parser
	min422  int
	mu      sync.Mutex
	dialogs map[string]bool
	updates map[string]int
	lastSE  string // the retry UPDATE's own Session-Expires header value
	lastMin string // the retry UPDATE's own Min-SE header value
}

func startA422RefreshStub(t *testing.T, min422 int) *a422RefreshStub {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &a422RefreshStub{
		conn: c, parser: sip.NewParser(), min422: min422,
		dialogs: map[string]bool{}, updates: map[string]int{},
	}
	t.Cleanup(func() { _ = c.Close() })
	go s.serve()
	return s
}

func (s *a422RefreshStub) Addr() string { return s.conn.LocalAddr().String() }

func (s *a422RefreshStub) UpdateCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, c := range s.updates {
		n += c
	}
	return n
}

func (s *a422RefreshStub) LastUpdateSessionExpires() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSE
}

func (s *a422RefreshStub) LastUpdateMinSE() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastMin
}

func (s *a422RefreshStub) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		d := make([]byte, n)
		copy(d, buf[:n])
		m, err := s.parser.ParseSIP(d)
		if err != nil {
			continue
		}
		req, ok := m.(*sip.Request)
		if !ok {
			continue
		}
		callID := ""
		if h := req.CallID(); h != nil {
			callID = h.Value()
		}
		switch req.Method {
		case sip.INVITE:
			if s.dialogs[callID] {
				continue // a re-INVITE refresh is not exercised by this test
			}
			s.dialogs[callID] = true
			res := sip.NewSDPResponseFromRequest(req, []byte(reInviteRingThenSilentSDP))
			host, portS, _ := net.SplitHostPort(s.Addr())
			port, _ := strconv.Atoi(portS)
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "stub", Host: host, Port: port}})
			res.AppendHeader(sip.NewHeader("Session-Expires", "90;refresher=uac"))
			res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, BYE, CANCEL, UPDATE"))
			s.write(res, from)
		case sip.ACK:
		case sip.UPDATE:
			s.mu.Lock()
			s.updates[callID]++
			count := s.updates[callID]
			if count >= 2 {
				if h := req.GetHeader("Session-Expires"); h != nil {
					s.lastSE = h.Value()
				}
				if h := req.GetHeader("Min-SE"); h != nil {
					s.lastMin = h.Value()
				}
			}
			s.mu.Unlock()
			if count == 1 {
				res := sip.NewResponseFromRequest(req, 422, "Session Interval Too Small", nil)
				res.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(s.min422)))
				s.write(res, from)
				continue
			}
			res := sip.NewResponseFromRequest(req, 200, "OK", nil)
			res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, BYE, CANCEL, UPDATE"))
			s.write(res, from)
		default:
			s.write(sip.NewResponseFromRequest(req, 200, "OK", nil), from)
		}
	}
}

func (s *a422RefreshStub) write(res *sip.Response, to net.Addr) {
	_, _ = s.conn.WriteTo([]byte(res.String()), to)
}

// TestA422RefreshRebasesTheRetryInterval is A-M5's (item 6) positive case: a
// 422 on a session-timer refresh, with a Min-SE inside our bounds, must
// re-base st.IntervalS BEFORE returning the error, so the refresher's own
// retry (Attempts: 2, Base: 2s) carries the raised interval rather than
// repeating the identical one the peer just rejected.
//
// Mutation-tested: removing the rebase call in refreshSession's
// !res.IsSuccess() branch reddens the "120;refresher=uac" assertion below
// (the retry keeps sending the original 90) — see the implementer's
// mutation-proof log.
func TestA422RefreshRebasesTheRetryInterval(t *testing.T) {
	s := startA422RefreshStub(t, 120)
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the refresh fires and draws the 422
	waitForCond(t, func() bool { return s.UpdateCount() >= 1 })

	// The 422 is a REAL Do failure (not a quiet stop), so attempt()'s own
	// backoff wait (Base: 2s) runs on the fake clock before the retry.
	clk.BlockUntil(1)
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return s.UpdateCount() >= 2 })

	if got := s.LastUpdateSessionExpires(); got != "120;refresher=uac" {
		t.Fatalf("retry UPDATE Session-Expires=%q want 120;refresher=uac (rebased off the 422's Min-SE)", got)
	}
	_ = res
}

// TestA422RefreshOutsideBoundsLeavesTheIntervalUnchanged is A-M5's negative
// case: retryIntervalFor422 already refuses a Min-SE outside our own bounds
// (below 90, or above maxAcceptableSessionIntervalS) by returning 0, and this
// item's fix must honour that refusal rather than rebasing onto an
// out-of-bounds value.
func TestA422RefreshOutsideBoundsLeavesTheIntervalUnchanged(t *testing.T) {
	s := startA422RefreshStub(t, 5) // below RFC 4028's own 90s floor
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	waitForCond(t, func() bool { return s.UpdateCount() >= 1 })

	clk.BlockUntil(1)
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return s.UpdateCount() >= 2 })

	if got := s.LastUpdateSessionExpires(); got != "90;refresher=uac" {
		t.Fatalf("retry UPDATE Session-Expires=%q want 90;refresher=uac (unchanged: the 422's "+
			"Min-SE of 5 is outside our bounds)", got)
	}
	_ = res
}

// a422RetryHeaders drives a 422 (Min-SE min422) on the first refresh of a 90 s
// outbound dialog and returns the retry's Session-Expires and Min-SE and the
// view's interval.
func a422RetryHeaders(t *testing.T, min422 int) (se, minSE string, intervalS int) {
	t.Helper()
	s := startA422RefreshStub(t, min422)
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + s.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // the refresh fires and draws the 422
	waitForCond(t, func() bool { return s.UpdateCount() >= 1 })
	clk.BlockUntil(1)
	clk.Advance(2 * time.Second)
	waitForCond(t, func() bool { return s.UpdateCount() >= 2 })
	v, ok := ua.SessionTimerView(res.DialogID)
	if !ok {
		t.Fatal("no session timer after the 422 retry")
	}
	return s.LastUpdateSessionExpires(), s.LastUpdateMinSE(), v.IntervalS
}

// TestA422RefreshRaisesTheRetryMinSE (CF-121, the 422 source): our retry's Min-SE is
// the largest returned in a 422 on the dialog (rfc4028.txt:600-603).
func TestA422RefreshRaisesTheRetryMinSE(t *testing.T) {
	_, minSE, _ := a422RetryHeaders(t, 120)
	if minSE != "120" {
		t.Fatalf("retry Min-SE=%q want 120", minSE)
	}
}

// TestA422AboveTheGrantCeilingStillRaisesTheRetryMinSE (K6, K6b): a 422 Min-SE above
// the 7200 s grant ceiling cannot re-base the interval (retryIntervalFor422 refuses
// it) but is still the dialog's Min-SE, so the retry carries it with a
// Session-Expires at least as large (LB-D9). Above 86400 nothing is recorded
// (LB-D14).
func TestA422AboveTheGrantCeilingStillRaisesTheRetryMinSE(t *testing.T) {
	t.Run("8000", func(t *testing.T) {
		se, minSE, intervalS := a422RetryHeaders(t, 8000)
		if se != "8000;refresher=uac" || minSE != "8000" {
			t.Fatalf("retry Session-Expires=%q Min-SE=%q want 8000;refresher=uac and 8000", se, minSE)
		}
		if intervalS != 90 {
			t.Fatalf("view IntervalS=%d want 90 (a Min-SE above the grant ceiling must not re-base)", intervalS)
		}
	})
	t.Run("AboveTheCeiling", func(t *testing.T) {
		se, minSE, _ := a422RetryHeaders(t, 86401)
		if se != "90;refresher=uac" || minSE != "90" {
			t.Fatalf("retry Session-Expires=%q Min-SE=%q want 90;refresher=uac and 90 (86401 is not recorded)", se, minSE)
		}
	})
}
