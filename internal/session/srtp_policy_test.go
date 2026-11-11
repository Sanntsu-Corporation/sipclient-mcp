package session

// CF-134 / D-134: ua_create validates srtp and keeps SDES keys off a
// transport that does not protect the SDP body unless allow_cleartext_sdes is
// set. Uses the NewManager NewUA capture seam of rfc4733_pin_test.go.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
)

// newSRTPPolicyService returns a ToolService whose NewUA seam appends every
// UAConfig to *got, plus the buffer its logger writes to.
func newSRTPPolicyService(t *testing.T, got *[]UAConfig) (*ToolService, context.Context, *syncBuffer) {
	t.Helper()
	fc := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lg, buf := captureLogger()
	m, err := NewManager(ManagerConfig{
		Ctx: ctx, Clock: fc,
		Policy: policy.NewStaticStore(policy.Defaults(), fc, lg),
		Logger: lg,
		NewUA: func(_ context.Context, cfg UAConfig) (UserAgent, error) {
			*got = append(*got, cfg)
			return nopAgent{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Open(ctx, "s1"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	return NewToolService(m), ctx, buf
}

// TestRFC4566_NEWD3_UACreateRefusesSDESOverNonTLS is the compliance test of
// CF-134 (RFC 4566 7, rfc4566.txt:1780-1782).
func TestRFC4566_NEWD3_UACreateRefusesSDESOverNonTLS(t *testing.T) {
	for _, tr := range []string{"udp", "tcp", ""} {
		for _, srtp := range []string{"optional", "required"} {
			t.Run(tr+"/"+srtp, func(t *testing.T) {
				var got []UAConfig
				ts, ctx, _ := newSRTPPolicyService(t, &got)
				_, err := ts.UACreate(ctx, "s1", UACreateInput{Mode: "direct", Transport: tr, SRTP: srtp})
				var ae *apierr.Error
				if !errors.As(err, &ae) || ae.Code != apierr.CodeInvalidArgument {
					t.Fatalf("UACreate err = %v, want invalid_argument", err)
				}
				want := `srtp "` + srtp + `" needs transport "tls": SRTP keys are offered in the SDP body (SDES, RFC 4566 section 7), which this transport does not protect; set allow_cleartext_sdes to accept that risk`
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %q, want it to contain %q", err.Error(), want)
				}
				if len(got) != 0 {
					t.Fatalf("NewUA was called %d times for a refused request", len(got))
				}
			})
		}
	}
	for _, c := range []struct{ tr, srtp string }{{"tls", "required"}, {"udp", "disabled"}} {
		var got []UAConfig
		ts, ctx, _ := newSRTPPolicyService(t, &got)
		if _, err := ts.UACreate(ctx, "s1", UACreateInput{Mode: "direct", Transport: c.tr, SRTP: c.srtp}); err != nil {
			t.Fatalf("%s + %s: %v", c.tr, c.srtp, err)
		}
	}
}

func TestUACreateRejectsUnknownSRTP(t *testing.T) {
	var got []UAConfig
	ts, ctx, _ := newSRTPPolicyService(t, &got)
	_, err := ts.UACreate(ctx, "s1", UACreateInput{Mode: "direct", Transport: "tls", SRTP: "requried"})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.CodeInvalidArgument || !strings.Contains(err.Error(), "srtp") {
		t.Fatalf("UACreate err = %v, want invalid_argument naming srtp", err)
	}
	if len(got) != 0 {
		t.Fatalf("NewUA was called for an unknown srtp value")
	}
}

func TestUACreateAllowsCleartextSDESOnlyWhenAsked(t *testing.T) {
	var got []UAConfig
	ts, ctx, buf := newSRTPPolicyService(t, &got)
	if _, err := ts.UACreate(ctx, "s1", UACreateInput{
		Mode: "direct", Transport: "udp", SRTP: "required", AllowCleartextSDES: true,
	}); err != nil {
		t.Fatalf("UACreate with allow_cleartext_sdes: %v", err)
	}
	if len(got) != 1 || got[0].SRTP != "required" {
		t.Fatalf("UAConfig = %+v, want one UA with SRTP required", got)
	}
	if n := strings.Count(buf.String(), `"level":"WARN"`); n != 1 {
		t.Fatalf("Warn lines = %d, want 1; log: %s", n, buf.String())
	}
}

// srtpRecorder records the per-call srtp that reaches the UA.
type srtpRecorder struct {
	nopAgent
	mu      sync.Mutex
	dials   []DialRequest
	answers []AnswerRequest
}

func (a *srtpRecorder) Dial(_ context.Context, r DialRequest) (DialResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dials = append(a.dials, r)
	return DialResult{}, nil
}

func (a *srtpRecorder) Answer(_ context.Context, r AnswerRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.answers = append(a.answers, r)
	return nil
}

// TestPerCallSRTPCannotLoosenTheUAPolicy is CF-170: call_dial and call_answer
// accept srtp as an override that may only tighten the UA's policy.
func TestPerCallSRTPCannotLoosenTheUAPolicy(t *testing.T) {
	cases := []struct {
		name     string
		cfg      UAConfig
		perCall  string
		wantErr  string // substring; "" = accepted
		wantSRTP string // the SRTP the UA receives when accepted
	}{
		{"required UA loosened to optional", UAConfig{SRTP: "required", Transport: TransportTLS}, "optional", "would loosen", ""},
		{"disabled UA, udp, optional", UAConfig{SRTP: "disabled", Transport: TransportUDP}, "optional", "needs transport", ""},
		{"disabled UA, udp, allowed, required", UAConfig{SRTP: "disabled", Transport: TransportUDP, AllowCleartextSDES: true}, "required", "", "required"},
		{"optional UA on tls, no override", UAConfig{SRTP: "optional", Transport: TransportTLS}, "", "", ""},
		{"bogus value", UAConfig{SRTP: "disabled", Transport: TransportTLS}, "bogus", "must be disabled, optional or required", ""},
		{"disabled override on a disabled UA", UAConfig{SRTP: "disabled", Transport: TransportUDP}, "disabled", "", "disabled"},
	}
	for _, c := range cases {
		for _, op := range []string{"dial", "answer"} {
			t.Run(c.name+"/"+op, func(t *testing.T) {
				fc := newFakeClock()
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				rec := &srtpRecorder{}
				m, err := NewManager(ManagerConfig{
					Ctx: ctx, Clock: fc, Policy: newTestStore(t, fc, nil), Logger: testLogger(),
					NewUA: func(context.Context, UAConfig) (UserAgent, error) { return rec, nil },
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := m.Open(ctx, "s1"); err != nil {
					t.Fatal(err)
				}
				c.cfg.Mode = "direct"
				ua, err := m.CreateUA(ctx, "s1", c.cfg)
				if err != nil {
					t.Fatal(err)
				}
				ts := NewToolService(m)
				var callErr error
				var call *Call
				if op == "dial" {
					_, callErr = ts.CallDial(ctx, "s1", CallDialInput{UA: string(ua.Handle()), ToURI: "sip:bob@example.net", SRTP: c.perCall})
				} else {
					call, err = m.CreateCall(ctx, "s1", ua.Handle(), Inbound, StateRinging)
					if err != nil {
						t.Fatal(err)
					}
					_, callErr = ts.CallAnswer(ctx, "s1", CallAnswerInput{Call: string(call.Handle()), SRTP: c.perCall})
				}
				if c.wantErr != "" {
					var ae *apierr.Error
					if !errors.As(callErr, &ae) || ae.Code != apierr.CodeInvalidArgument || !strings.Contains(callErr.Error(), c.wantErr) {
						t.Fatalf("err = %v, want invalid_argument containing %q", callErr, c.wantErr)
					}
					if op == "dial" && len(m.sessionCalls("s1")) != 0 {
						t.Fatal("a refused call_dial created a call")
					}
					if op == "answer" && call.State() != StateRinging {
						t.Fatalf("a refused call_answer left the call %s, want ringing", call.State())
					}
					return
				}
				if callErr != nil {
					t.Fatal(callErr)
				}
				waitUntil(t, func() bool {
					rec.mu.Lock()
					defer rec.mu.Unlock()
					if op == "dial" {
						return len(rec.dials) == 1 && rec.dials[0].SRTP == c.wantSRTP
					}
					return len(rec.answers) == 1 && rec.answers[0].SRTP == c.wantSRTP
				})
			})
		}
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(ciScaled(2 * time.Second)); time.Now().Before(deadline); {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached within 2 s")
}
