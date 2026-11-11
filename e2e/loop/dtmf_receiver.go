package main

// dtmf_receiver.go — Task 33's DTMF acceptance detector.
//
// This receiver proves our RX decode path. It is NOT a substitute for the
// rig: scenarioDTMFRFC2833Rig dials Asterisk's ext 602 and proves the other
// direction, that our TX encoding is understood by an independent
// implementation. Both ends here are ours, so a shared misunderstanding of
// the protocol would go unseen — which is exactly the bug class §14.5's
// interop gate exists to catch. Neither scenario replaces the other.
//
// (History: this receiver was introduced when ext 602 appeared broken —
// Read() returning instantly with zero digits — under a rig freeze that
// forbade fixing it. Both the freeze and the defect are gone as of
// 2026-07-28; see e2e/asterisk/USAGE.md's Troubleshooting section for the
// mechanism. The receiver stays on its own merits, not the freeze's.)
//
// The three local-receiver DTMF scenarios dial a SECOND real sipua.UA this
// binary hosts directly — the exact production DTMF detection path
// (RFC 4733 telephone-event decode, Goertzel inband detection, SIP INFO)
// internal/sipua/p3_acceptance_test.go's TestR2DTMFDetectedByASecondUA
// already proves in isolation, reused here (Rule 16) rather than
// reimplemented against raw sockets. This is a bare, unregistered UA, not a
// test double — sipua.New needs no *testing.T, only its exported Config.
import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

type dtmfReceiverUA struct {
	ua *sipua.UA

	mu  sync.Mutex
	evs []session.UAEvent
}

// startDTMFReceiverUA binds a direct-mode UA on localIP (the gate's own address: a LAN-bound UA refuses a loopback c=, CF-201) with dtmfMode as
// its DTMFMode default — inband detection is gated on this (see
// UA.inbandDetectionEnabled); rfc2833/info detection is unconditional once
// negotiated/received.
func startDTMFReceiverUA(ctx context.Context, dtmfMode, localIP string) (*dtmfReceiverUA, error) {
	r := &dtmfReceiverUA{}
	ua, err := sipua.New(ctx, sipua.Config{
		Transport: "udp",
		Mode:      "direct",
		// AOR user "alice" matches the SIPTarget below and
		// internal/sipua/p3_acceptance_test.go's own TestR2DTMFDetectedByASecondUA:
		// direct mode validates the inbound Request-URI user against this AOR
		// and 404s otherwise.
		AOR:                "sip:alice@" + localIP,
		Timeout:            2 * time.Second,
		InboundRingTimeout: 5 * time.Second,
		Clock:              clock.System(),
		LocalAddr:          localIP + ":0",
		DTMFMode:           dtmfMode,
		MediaPortRange:     [2]int{20100, 20300},
	})
	if err != nil {
		return nil, fmt.Errorf("sipua.New: %w", err)
	}
	r.ua = ua
	ua.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
		if !ev.AdmitProbe { // an OPTIONS capacity probe is not an inbound call
			r.record(ev)
		}
		return session.AdmitAccept()
	})
	ua.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) {
		r.record(ev)
	})
	return r, nil
}

func (r *dtmfReceiverUA) record(ev session.UAEvent) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *dtmfReceiverUA) events() []session.UAEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]session.UAEvent, len(r.evs))
	copy(out, r.evs)
	return out
}

func (r *dtmfReceiverUA) Addr() *net.UDPAddr { return r.ua.BoundAddr() }
func (r *dtmfReceiverUA) SIPTarget() string  { return "sip:alice@" + r.Addr().String() }

// AnswerWhenRinging polls for the inbound admission event and answers it —
// mirroring internal/sipua's own collect()/waitFor test pattern rather than
// answering from inside the OnEvent/OnAdmit callback itself.
//
// UAEventInbound is recorded synchronously from inside sipua's admit() call,
// which runs WHILE the dialog is still phaseAdmitting — the 180 write and the
// phaseAdmitting -> phaseRinging flip happen afterwards, back in onInvite, on
// sipua's own goroutine. sipua exposes no further event for that later
// transition (UAEventProvisional only fires for the OUTBOUND 180/183 case),
// so nothing outside internal/sipua can observe "now ringing" directly. A
// poller that answers the instant it sees UAEventInbound can therefore race
// the flip and land on call_answer's own phase check, which fails
// deterministically with a precondition_failed naming the ringing
// requirement: retry on exactly that message until it clears (or the overall
// timeout expires) rather than guessing a fixed extra delay. Any other error
// — including the OTHER precondition_failed call_answer can return, the
// Min-SE-too-small 422 case — is a real failure and is returned immediately,
// not retried.
func (r *dtmfReceiverUA) AnswerWhenRinging(ctx context.Context, timeout time.Duration) error {
	// C12: this literal is pinned by
	// internal/sipua.TestAnswerOnANonRingingDialogNamesTheRingingRequirement, so
	// a reword in call.go fails a unit test before it silently breaks this retry
	// loop. Keep the two in sync.
	const notRinging = "requires a ringing inbound dialog"
	deadline := time.Now().Add(timeout)
	seenInbound, dialogID := false, ""
	for time.Now().Before(deadline) {
		if !seenInbound {
			for _, ev := range r.events() {
				if ev.Kind == session.UAEventInbound {
					seenInbound, dialogID = true, ev.DialogID
					break
				}
			}
		}
		if seenInbound {
			err := r.ua.Answer(ctx, session.AnswerRequest{DialogID: dialogID})
			if err == nil {
				return nil
			}
			if apierr.CodeOf(err) != apierr.CodePreconditionFailed || !strings.Contains(err.Error(), notRinging) {
				return err
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seenInbound {
		return fmt.Errorf("no inbound call observed within %s", timeout)
	}
	return fmt.Errorf("dialog never reached phaseRinging within %s", timeout)
}

// Digits concatenates every UAEventDTMF digit observed so far, in order.
func (r *dtmfReceiverUA) Digits() string {
	var b strings.Builder
	for _, ev := range r.events() {
		if ev.Kind == session.UAEventDTMF {
			b.WriteString(ev.Digit)
		}
	}
	return b.String()
}

func (r *dtmfReceiverUA) Close() { _ = r.ua.Close(context.Background()) }
