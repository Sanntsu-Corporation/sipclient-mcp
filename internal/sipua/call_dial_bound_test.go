package sipua

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// CF-038 (D-B): Dial refuses once the UA holds CallLimit + lingeringDialHeadroom
// registered dialogs. With CallLimit 1 the bound is 1 + 32 = 33.
const boundForLimit1 = 1 + lingeringDialHeadroom

// newBoundUA is a direct-mode UA against a peer that never answers, so a held
// dial stays in the registry until the test ends. The fake clock does NOT make
// the dial timeout inert: runDial's transaction timer is a real one, so a held
// dial's own timeout (5 s here) is real time.
func newBoundUA(t *testing.T) *UA {
	t.Helper()
	ua, err := New(context.Background(), Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 5 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		MediaPortRange: [2]int{16384, 32767}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		_ = ua.Close(context.Background())
		// Close cancels every held dial; wait for their runDial goroutines to
		// release their dialogs, so none is still running (and reading the
		// package-level post-CANCEL seam) when the next test sets it.
		deadline := time.Now().Add(5 * time.Second)
		for ua.RegisteredDialogCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	})
	return ua
}

// holdPeer is a peer that answers nothing until the test ends, so every dial to
// it stays `dialing`.
func holdPeer(t *testing.T) *sippeer.Peer {
	t.Helper()
	hold := make(chan struct{})
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", Behaviour: sippeer.Behaviour{HoldProvisionals: hold}})
	t.Cleanup(func() { close(hold) })
	return p
}

// assertLiveDialogDenial fails unless err is the ua_live_dialogs denial with the
// given limit and current.
func assertLiveDialogDenial(t *testing.T, err error, limit, current int) {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) || apierr.CodeOf(err) != apierr.CodeDenied {
		t.Fatalf("Dial err = %v, want a denied *apierr.Error", err)
	}
	if ae.Rule != "ua_live_dialogs" {
		t.Errorf("Rule = %q, want ua_live_dialogs", ae.Rule)
	}
	if ae.Limit == nil || *ae.Limit != limit {
		t.Errorf("Limit = %v, want %d", ae.Limit, limit)
	}
	if ae.Current == nil || *ae.Current != current {
		t.Errorf("Current = %v, want %d", ae.Current, current)
	}
}

func dialBound(ua *UA, p *sippeer.Peer, limit int) (session.DialResult, error) {
	return ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr(), CallLimit: limit})
}

func TestDialRefusedAtTheLiveDialogBound(t *testing.T) {
	p := holdPeer(t)
	ua := newBoundUA(t)
	for i := 0; i < boundForLimit1; i++ {
		if _, err := dialBound(ua, p, 1); err != nil {
			t.Fatalf("dial %d of %d: %v", i+1, boundForLimit1, err)
		}
	}
	var bound atomic.Bool
	_, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + p.Addr(), CallLimit: 1,
		OnDialogBound: func(string, string) { bound.Store(true) },
	})
	assertLiveDialogDenial(t, err, boundForLimit1, boundForLimit1)
	if n := ua.RegisteredDialogCount(); n != boundForLimit1 {
		t.Errorf("RegisteredDialogCount = %d, want %d (the refused dial must not register)", n, boundForLimit1)
	}
	if bound.Load() {
		t.Error("OnDialogBound was called for a refused dial")
	}
}

func TestLiveDialogBoundCountsHungUpLingeringDials(t *testing.T) {
	// Registered BEFORE newBoundUA so it runs AFTER that UA's drain: a `defer`
	// would restore the global while a leftover dial goroutine may still read it.
	t.Cleanup(SetPostCancelWait(3 * time.Second))
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", Behaviour: sippeer.Behaviour{RingThenSilent: true}})
	ua := newBoundUA(t)
	var mu sync.Mutex
	rang := map[string]bool{}
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventProvisional && ev.Code == 180 {
			mu.Lock()
			rang[ev.DialogID] = true
			mu.Unlock()
		}
	})
	waitRang := func(id string) {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			ok := rang[id]
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatalf("dialog %s never saw a 180", id)
	}

	for i := 0; i < boundForLimit1; i++ {
		res, err := dialBound(ua, p, 1)
		if err != nil {
			t.Fatalf("dial %d: %v", i+1, err)
		}
		waitRang(res.DialogID)
		if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
			t.Fatalf("Hangup %d: %v", i+1, err)
		}
	}
	// All hung up, none finalised: they linger in the registry and still count.
	_, err := dialBound(ua, p, 1)
	assertLiveDialogDenial(t, err, boundForLimit1, boundForLimit1)

	deadline := time.Now().Add(15 * time.Second)
	for ua.RegisteredDialogCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d dialogs still registered after the post-CANCEL wait", ua.RegisteredDialogCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := dialBound(ua, p, 1); err != nil {
		t.Fatalf("dial after the lingering dials drained: %v", err)
	}
}

func TestLiveDialogBoundDoesNotWrapForHugeCallLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
	}{
		{"MaxInt", math.MaxInt},
		{"MaxInt-31", math.MaxInt - 31},
		{"MaxInt-32", math.MaxInt - 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := holdPeer(t)
			ua := newBoundUA(t)
			if _, err := dialBound(ua, p, tc.limit); err != nil {
				t.Fatalf("first Dial with CallLimit %d: %v (the bound must saturate, never wrap negative)", tc.limit, err)
			}
			if n := ua.RegisteredDialogCount(); n != 1 {
				t.Errorf("RegisteredDialogCount = %d, want 1", n)
			}
		})
	}
}

func TestConcurrentDialsNeverExceedTheLiveDialogBound(t *testing.T) {
	const dials = 50
	p := holdPeer(t)
	ua := newBoundUA(t)

	var maxSeen atomic.Int64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int64(ua.RegisteredDialogCount()); n > maxSeen.Load() {
				maxSeen.Store(n)
			}
		}
	}()

	var ok, denied, other atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < dials; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := dialBound(ua, p, 1)
			switch {
			case err == nil:
				ok.Add(1)
			case apierr.CodeOf(err) == apierr.CodeDenied:
				denied.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(stop)
	<-sampled

	if ok.Load() != boundForLimit1 || denied.Load() != dials-boundForLimit1 || other.Load() != 0 {
		t.Errorf("ok=%d denied=%d other=%d, want ok=%d denied=%d other=0",
			ok.Load(), denied.Load(), other.Load(), boundForLimit1, dials-boundForLimit1)
	}
	if maxSeen.Load() > boundForLimit1 {
		t.Errorf("registry peaked at %d dialogs, bound is %d", maxSeen.Load(), boundForLimit1)
	}
}

func TestInboundDialogsCountTowardButAreNeverRefusedByTheBound(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	ua := newBoundUA(t)
	for i := 0; i < boundForLimit1; i++ {
		ua.register(&dialog{id: fmt.Sprintf("inbound-%d", i), direction: session.Inbound, phase: phaseRinging})
	}
	t.Cleanup(func() { // the stubs have no runner to release them; newBoundUA's drain wait needs an empty registry
		ua.calls.mu.Lock()
		defer ua.calls.mu.Unlock()
		for i := 0; i < boundForLimit1; i++ {
			delete(ua.calls.byID, fmt.Sprintf("inbound-%d", i))
		}
	})

	// One more inbound INVITE, past the bound, is still accepted (180 rings).
	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	deadline := time.Now().Add(3 * time.Second)
	for ua.RegisteredDialogCount() != boundForLimit1+1 || !hasCode(p.ResponseCodes(), 180) {
		if time.Now().After(deadline) {
			t.Fatalf("inbound INVITE past the bound not accepted: count=%d codes=%v",
				ua.RegisteredDialogCount(), p.ResponseCodes())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// ...but the inbound dialogs consumed the outbound headroom.
	_, err := dialBound(ua, p, 1)
	assertLiveDialogDenial(t, err, boundForLimit1, boundForLimit1+1)
}

func hasCode(codes []int, want int) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestDialWithoutCallLimitIsUnbounded(t *testing.T) {
	p := holdPeer(t)
	ua := newBoundUA(t)
	for i := 0; i < 40; i++ {
		if _, err := dialBound(ua, p, 0); err != nil {
			t.Fatalf("dial %d with CallLimit 0: %v", i+1, err)
		}
	}
	if n := ua.RegisteredDialogCount(); n != 40 {
		t.Errorf("RegisteredDialogCount = %d, want 40", n)
	}
}
