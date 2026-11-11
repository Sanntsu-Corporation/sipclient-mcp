package sipua

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// contactCaptureSpy wraps the dialog's real sip.ServerTransaction and records
// the 200 OK actually put on the wire, so the test can inspect the Contact
// header sipua sent rather than reconstructing it independently. Embedding —
// not reimplementation — means every other method (and the 200 itself) behave
// exactly as they would without the spy; only Respond is observed. Modeled on
// call_answerclaim_test.go's respondSpy.
type contactCaptureSpy struct {
	sip.ServerTransaction
	mu   sync.Mutex
	last *sip.Response
}

func (s *contactCaptureSpy) Respond(res *sip.Response) error {
	if res.StatusCode == 200 {
		s.mu.Lock()
		s.last = res
		s.mu.Unlock()
	}
	return s.ServerTransaction.Respond(res)
}

func (s *contactCaptureSpy) captured() *sip.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// TestAnswerContactCarriesTransportParam is T4's exit gate: a stream-transport
// UA's Answer 200 OK Contact and its outbound INVITE Request-URI must carry
// ;transport=<t>, while udp (the RFC 3261 default) must carry neither. Built
// on ua_tcp_test.go's two-production-UA loopback pattern (this repo's TCP test
// harness — the shared testutil/peer harness is UDP-only) with
// call_answerclaim_test.go's ServerTransaction-spy pattern layered in to
// observe the actual 200 sent on the wire.
func TestAnswerContactCarriesTransportParam(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		wantParam string // "" means the transport param must be absent
	}{
		{name: "tcp", transport: "tcp", wantParam: ";transport=tcp"},
		{name: "udp_control", transport: "udp", wantParam: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			callee, err := New(ctx, Config{
				Transport:          tt.transport,
				Mode:               "direct",
				AOR:                "sip:bob@example",
				LocalAddr:          "127.0.0.1:0",
				Timeout:            2 * time.Second,
				InboundRingTimeout: 2 * time.Second,
				Clock:              clock.System(),
				Logger:             testLogger(),
			})
			if err != nil {
				t.Fatalf("New(callee): %v", err)
			}
			defer func() { _ = callee.Close(ctx) }()

			caller, err := New(ctx, Config{
				Transport: tt.transport,
				Mode:      "direct",
				AOR:       "sip:alice@example",
				LocalAddr: "127.0.0.1:0",
				Timeout:   2 * time.Second,
				Clock:     clock.System(),
				Logger:    testLogger(),
			})
			if err != nil {
				t.Fatalf("New(caller): %v", err)
			}
			defer func() { _ = caller.Close(ctx) }()

			inbound := make(chan session.UAEvent, 1)
			callee.OnAdmit(ctx, func(_ context.Context, ev session.UAEvent) session.Admission {
				inbound <- ev
				return session.AdmitAccept()
			})

			callerEvents := make(chan session.UAEvent, 8)
			caller.OnEvent(ctx, func(_ context.Context, ev session.UAEvent) {
				callerEvents <- ev
			})

			dr, err := caller.Dial(ctx, session.DialRequest{
				ToURI: "sip:bob@" + callee.LocalAddr().String(),
			})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}

			// The outbound INVITE Request-URI, captured from the caller's own
			// dialog record (in-package: this test IS package sipua).
			cd, err := caller.lookup(dr.DialogID)
			if err != nil {
				t.Fatalf("caller.lookup: %v", err)
			}
			gotRURI := cd.invite.Recipient.String()
			if tt.wantParam == "" {
				if strings.Contains(strings.ToLower(gotRURI), "transport=") {
					t.Errorf("outbound INVITE Request-URI = %q, want NO transport param for udp", gotRURI)
				}
			} else if !strings.Contains(strings.ToLower(gotRURI), tt.wantParam) {
				t.Errorf("outbound INVITE Request-URI = %q, want it to carry %q", gotRURI, tt.wantParam)
			}

			// The callee's inbound admission event.
			var in session.UAEvent
			select {
			case in = <-inbound:
			case <-time.After(3 * time.Second):
				t.Fatal("callee never observed an inbound INVITE")
			}

			// Install the capture spy in place of the callee dialog's real
			// server transaction, exactly as call_answerclaim_test.go does,
			// so Answer's real 200 OK can be inspected after it goes out.
			d, err := callee.lookup(in.DialogID)
			if err != nil {
				t.Fatalf("callee.lookup: %v", err)
			}
			spy := &contactCaptureSpy{}
			callee.calls.mu.Lock()
			spy.ServerTransaction = d.serverTx
			d.serverTx = spy
			callee.calls.mu.Unlock()

			if err := callee.AnswerEventually(ctx, session.AnswerRequest{DialogID: in.DialogID}); err != nil {
				t.Fatalf("Answer: %v", err)
			}

			res := spy.captured()
			if res == nil {
				t.Fatal("Answer's 200 OK was never observed on the server transaction")
			}
			contact := res.GetHeader("Contact")
			if contact == nil {
				t.Fatal("Answer's 200 OK carries no Contact header")
			}
			gotContact := contact.Value()
			if tt.wantParam == "" {
				if strings.Contains(strings.ToLower(gotContact), "transport=") {
					t.Errorf("Answer 200 Contact = %q, want NO transport param for udp", gotContact)
				}
			} else if !strings.Contains(strings.ToLower(gotContact), tt.wantParam) {
				t.Errorf("Answer 200 Contact = %q, want it to carry %q", gotContact, tt.wantParam)
			}

			// Drain the caller's 200 so the call completes cleanly.
			deadline := time.After(3 * time.Second)
			for {
				select {
				case cev := <-callerEvents:
					if cev.Kind == session.UAEventFinal && cev.Code == 200 {
						return
					}
				case <-deadline:
					t.Fatal("caller never observed a 200 OK")
				}
			}
		})
	}
}
