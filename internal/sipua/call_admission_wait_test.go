package sipua_test

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// admissionHold is an inbound dialog held in phaseAdmitting by the UA's own
// OnAdmit callback (no production seam): the callback reports the dialog id and
// blocks until open.
type admissionHold struct {
	p       *peer.Peer
	ua      *sipua.UA
	events  func() []session.UAEvent
	id      string
	release chan struct{}
	once    sync.Once
}

func holdAdmission(t *testing.T) *admissionHold {
	t.Helper()
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	h := &admissionHold{p: p, ua: ua, events: collect(t, ua), release: make(chan struct{})}
	// Registered after newDirectUA's cleanup, so it runs first: a blocked admit
	// callback is released before the UA is closed.
	t.Cleanup(h.open)
	admitted := make(chan string, 1)
	ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		select {
		case admitted <- ev.DialogID:
		default:
		}
		<-h.release
		return session.AdmitAccept()
	})
	p.Dial(t, "sip:alice@"+ua.BoundAddr().String())
	select {
	case h.id = <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("admit handler never ran")
	}
	return h
}

// open lets the admission finish (the 180 is written, the dialog rings).
func (h *admissionHold) open() { h.once.Do(func() { close(h.release) }) }

func (h *admissionHold) goAnswer(ctx context.Context) <-chan error {
	res := make(chan error, 1)
	go func() { res <- h.ua.Answer(ctx, session.AnswerRequest{DialogID: h.id}) }()
	return res
}

func (h *admissionHold) goReject(ctx context.Context, status int, reason string) <-chan error {
	res := make(chan error, 1)
	go func() { res <- h.ua.Reject(ctx, h.id, status, reason) }()
	return res
}

// requireStillWaiting fails if the call returned within 200 ms: while the
// dialog is held in admission it must be waiting, not failing.
func (h *admissionHold) requireStillWaiting(t *testing.T, res <-chan error) {
	t.Helper()
	select {
	case err := <-res:
		t.Fatalf("returned within 200ms while the dialog was still being admitted (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func (h *admissionHold) await(t *testing.T, res <-chan error) error {
	t.Helper()
	select {
	case err := <-res:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("did not return within 2s")
		return nil
	}
}

// waitCodes waits until the peer has seen exactly these response codes.
func (h *admissionHold) waitCodes(t *testing.T, want ...int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.p.ResponseCodes()
		if reflect.DeepEqual(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("response codes = %v, want %v", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func requireCode(t *testing.T, err error, want apierr.Code) {
	t.Helper()
	if !isCode(err, want) {
		t.Fatalf("err = %v, want code %s", err, want)
	}
}

func TestRejectDuringAdmittingWaitsAndRejectsAfterThe180(t *testing.T) {
	h := holdAdmission(t)

	res := h.goReject(context.Background(), 486, "Busy Here")
	h.requireStillWaiting(t, res)

	h.open()
	if err := h.await(t, res); err != nil {
		t.Fatalf("Reject after the admission finished = %v, want nil", err)
	}
	h.waitCodes(t, 100, 180, 486)
}

// A CANCEL during admission wins over a waiting Answer: the waiter, once woken,
// meets the claimed dialog and does not answer.
func TestAnswerWaitingOnAdmissionLosesToACancel(t *testing.T) {
	h := holdAdmission(t)

	res := h.goAnswer(context.Background())
	h.requireStillWaiting(t, res)

	h.p.SendCancel(t)
	ended := waitFor(t, h.events, session.UAEventDialogEnded, 0)
	if ended.Cause != session.UACauseCancelled {
		t.Fatalf("cause=%q want cancelled", ended.Cause)
	}
	h.open()
	requireCode(t, h.await(t, res), apierr.CodePreconditionFailed)
	if got := h.p.WaitForInviteFinal(t, 2*time.Second); got != 487 {
		t.Fatalf("INVITE final = %d, want 487", got)
	}
	for _, c := range h.p.ResponseCodes() {
		if c == 180 {
			t.Fatalf("a 180 was sent after the CANCEL: %v", h.p.ResponseCodes())
		}
	}
}

// A waiting Answer gives up on its own context and claims nothing: the dialog
// rings as normal afterwards and a second Answer succeeds.
func TestAnswerWaitingOnAdmissionReturnsWhenItsContextEnds(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		code apierr.Code
		msg  string
	}{
		{"cancel", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(300*time.Millisecond, cancel)
			return ctx, cancel
		}, apierr.CodeCancelled, ""},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 300*time.Millisecond)
		}, apierr.CodeInternal, "call_answer: context deadline exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := holdAdmission(t)
			ctx, cancel := tc.ctx()
			defer cancel()
			start := time.Now()
			res := h.goAnswer(ctx)
			err := h.await(t, res)
			requireCode(t, err, tc.code)
			if tc.msg != "" && !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.msg)
			}
			if d := time.Since(start); d < 250*time.Millisecond {
				t.Fatalf("returned after %v, want it to wait for the context (about 300ms)", d)
			}

			h.open()
			h.waitCodes(t, 100, 180)
			if err := h.await(t, h.goAnswer(context.Background())); err != nil {
				t.Fatalf("second Answer = %v, want nil", err)
			}
			h.waitCodes(t, 100, 180, 200)
		})
	}
}

// UA.Close releases a waiter even if admission never finishes.
func TestUAClosedWhileAnAnswerWaitsOnAdmissionReleasesIt(t *testing.T) {
	h := holdAdmission(t)

	res := h.goAnswer(context.Background())
	h.requireStillWaiting(t, res)

	closed := make(chan error, 1)
	go func() { closed <- h.ua.Close(context.Background()) }()

	err := h.await(t, res)
	requireCode(t, err, apierr.CodePreconditionFailed)
	if !strings.Contains(err.Error(), "the user agent closed while the call was being admitted") {
		t.Fatalf("err = %v", err)
	}
	select {
	case cerr := <-closed:
		if cerr != nil {
			t.Fatalf("Close = %v, want nil", cerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within 5s")
	}
}

// A hangup during admission declines with one 603; the waiting Answer, once
// woken, meets the claimed dialog.
func TestHangupWhileAnAnswerWaitsOnAdmissionDeclinesOnce(t *testing.T) {
	h := holdAdmission(t)

	res := h.goAnswer(context.Background())
	h.requireStillWaiting(t, res)

	if err := h.ua.Hangup(context.Background(), h.id, ""); err != nil {
		t.Fatalf("Hangup = %v, want nil", err)
	}
	h.open()
	requireCode(t, h.await(t, res), apierr.CodePreconditionFailed)
	h.waitCodes(t, 100, 603)
}
