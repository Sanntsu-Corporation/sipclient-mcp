package sipua_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestDialBindHookRunsBeforeAnyEvent is the sipua half of the lost-event-race
// gate. Its session half is
// session.TestInstantlyAnsweredDialReachesAnswered.
//
// THE ASSERTION IS AN ORDERING, NOT A TIMING. `Dial` spawns `go u.runDial(d)`
// before it returns, so a caller that binds the dialog id only on Dial's
// RETURN loses every event runDial emits in between — on loopback against an
// instantly-answering peer that is the whole INVITE/200/ACK exchange. The
// hook exists to make the bind happen while nothing can yet emit, and this
// test asserts exactly that: the hook fired, and no event was delivered
// before it.
//
// Deterministic, and it stays deterministic: `AnswerAfter: 0` only widens the
// window the assertion would catch, it is not what the assertion depends on.
func TestDialBindHookRunsBeforeAnyEvent(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{AnswerAfter: 0}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))

	var bound atomic.Bool
	var mu sync.Mutex
	var early []session.UAEvent // events delivered BEFORE the hook ran
	var seen int

	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		mu.Lock()
		defer mu.Unlock()
		seen++
		if !bound.Load() {
			early = append(early, ev)
		}
	})

	var hookDialogID, hookCallID string
	var hookCalls int
	res, err := ua.Dial(context.Background(), session.DialRequest{
		ToURI: "sip:bob@" + p.Addr(),
		OnDialogBound: func(dialogID, callID string) {
			hookCalls++
			hookDialogID, hookCallID = dialogID, callID
			bound.Store(true)
		},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if hookCalls != 1 {
		t.Fatalf("OnDialogBound fired %d time(s), want exactly 1 — without it "+
			"the caller cannot bind the dialog before runDial starts emitting",
			hookCalls)
	}
	if hookDialogID != res.DialogID {
		t.Errorf("hook dialog id = %q, DialResult.DialogID = %q; they must be "+
			"the same dialog", hookDialogID, res.DialogID)
	}
	if hookCallID != res.CallID {
		t.Errorf("hook call id = %q, DialResult.CallID = %q; they must be the "+
			"same dialog", hookCallID, res.CallID)
	}
	if hookCallID == "" {
		t.Error("hook call id is empty — it is the Tap's ladder key (U18)")
	}

	// Wait for the exchange to actually produce events, so the ordering
	// assertion below is not vacuous: with no event delivered at all, an
	// empty `early` would prove nothing.
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := seen
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no UA event within 3s; the peer answers immediately, so the " +
				"ordering assertion would be vacuous")
		}
		time.Sleep(time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(early) > 0 {
		t.Errorf("%d event(s) delivered before OnDialogBound ran (first: %s/%d) — "+
			"runDial must not be able to emit before the caller has bound the "+
			"dialog", len(early), early[0].Kind, early[0].Code)
	}
}
