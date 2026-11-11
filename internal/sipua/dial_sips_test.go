package sipua

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func newSipsTestUA(t *testing.T, transport string, mutate func(*Config)) *UA {
	t.Helper()
	cfg := Config{
		Transport: transport, Mode: "direct", AOR: "sip:alice@example",
		LocalAddr: "127.0.0.1:0", Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: clock.System(), Logger: testLogger(), TLSInsecureSkipVerify: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	ua, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(%s): %v", transport, err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua
}

func TestDialRequestURIKeepsSipsOnATLSUA(t *testing.T) {
	ua := newSipsTestUA(t, "tls", nil)
	for _, tc := range []struct {
		target, want string
		transport    bool
	}{
		{"sips:bob@127.0.0.1:5071", "sips:bob@127.0.0.1:5071", false},
		{"SIPS:bob@h", "sips:bob@h", false},
		{"sip:bob@h:5071", "sip:bob@h:5071;transport=tls", true},
	} {
		got, err := ua.dialRequestURI(tc.target)
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if got.String() != tc.want {
			t.Errorf("%s -> %q, want %q", tc.target, got.String(), tc.want)
		}
		if _, has := got.UriParams.Get("transport"); got.UriParams != nil && has != tc.transport {
			t.Errorf("%s: transport param present = %v, want %v", tc.target, has, tc.transport)
		}
	}
}

func TestDialRequestURIRefusesSipsOnANonTLSUA(t *testing.T) {
	for _, tr := range []string{"udp", "tcp"} {
		ua := newSipsTestUA(t, tr, nil)
		_, err := ua.dialRequestURI("sips:bob@h")
		if err == nil || !strings.Contains(err.Error(), "sips") || !strings.Contains(err.Error(), `"`+tr+`"`) {
			t.Errorf("%s UA: err = %v, want a sips refusal naming the transport", tr, err)
		}
	}
}

func TestDialRequestURIForSipTargets(t *testing.T) {
	udp := newSipsTestUA(t, "udp", nil)
	tcp := newSipsTestUA(t, "tcp", nil)
	for _, tc := range []struct {
		ua           *UA
		target, want string
	}{
		{udp, "sip:bob@h:5070", "sip:bob@h:5070"},
		{udp, "h:5070", "sip:h:5070"},
		{tcp, "sip:bob@h:5070", "sip:bob@h:5070;transport=tcp"},
	} {
		got, err := tc.ua.dialRequestURI(tc.target)
		if err != nil || got.String() != tc.want {
			t.Errorf("%s -> %q, %v; want %q", tc.target, got.String(), err, tc.want)
		}
	}
	if _, err := udp.dialRequestURI("sip:[::1]:5060"); err == nil {
		t.Error("an IPv6 literal must be refused, as validSIPURI does")
	}
}

func TestDialSipsOnAUDPUAIsRefusedBeforeAnyResource(t *testing.T) {
	ua := newSipsTestUA(t, "udp", nil)
	events := make(chan session.UAEvent, 4)
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) { events <- ev })
	_, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sips:bob@127.0.0.1:5999"})
	if err == nil {
		t.Fatal("a sips: target on a UDP UA must be refused")
	}
	ua.calls.mu.Lock()
	n := len(ua.calls.byID)
	ua.calls.mu.Unlock()
	if n != 0 {
		t.Errorf("%d dialogs registered after a refused dial", n)
	}
	select {
	case ev := <-events:
		t.Errorf("event %s emitted for a refused dial", ev.Kind)
	case <-time.After(200 * time.Millisecond):
	}
}

// sipsTLSPair returns a caller and a callee TLS UA; every inbound INVITE of
// the callee is delivered on the returned channel.
func sipsTLSPair(t *testing.T, calleeMutate func(*Config)) (caller, callee *UA, inbound, callerEvents, calleeEvents chan session.UAEvent) {
	t.Helper()
	callee = newSipsTestUA(t, "tls", func(c *Config) {
		c.AOR = "sip:bob@example"
		if calleeMutate != nil {
			calleeMutate(c)
		}
	})
	caller = newSipsTestUA(t, "tls", nil)
	inbound = make(chan session.UAEvent, 8)
	callee.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
		inbound <- ev
		return session.AdmitAccept()
	})
	calleeEvents = make(chan session.UAEvent, 32)
	callee.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) { calleeEvents <- ev })
	callerEvents = make(chan session.UAEvent, 32)
	caller.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) { callerEvents <- ev })
	return
}

func awaitEvent(t *testing.T, ch chan session.UAEvent, d time.Duration, what string, match func(session.UAEvent) bool) session.UAEvent {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-ch:
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func dialogInvite(ua *UA, id string) *sip.Request {
	ua.calls.mu.Lock()
	defer ua.calls.mu.Unlock()
	if d, ok := ua.calls.byID[id]; ok {
		return d.invite
	}
	return nil
}

func TestDialSipsTargetOverTLSCompletes(t *testing.T) {
	caller, callee, inbound, callerEvents, calleeEvents := sipsTLSPair(t, nil)
	res, err := caller.Dial(context.Background(), session.DialRequest{ToURI: "sips:bob@" + callee.LocalAddr().String()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	ev := awaitEvent(t, inbound, 3*time.Second, "the callee's inbound INVITE", func(session.UAEvent) bool { return true })
	if err := callee.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: ev.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	awaitEvent(t, callerEvents, 3*time.Second, "the caller's 200", func(e session.UAEvent) bool {
		return e.Kind == session.UAEventFinal && e.Code == 200
	})
	inv := dialogInvite(caller, res.DialogID)
	if inv == nil || inv.Recipient.Scheme != "sips" {
		t.Fatalf("the dialog's INVITE Request-URI = %v, want scheme sips", inv)
	}
	if _, has := inv.Recipient.UriParams.Get("transport"); inv.Recipient.UriParams != nil && has {
		t.Error("a sips: Request-URI must carry no transport parameter")
	}
	if err := caller.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	// The BYE is built without a Via; it must leave over TLS (fork default).
	awaitEvent(t, calleeEvents, 3*time.Second, "the callee's BYE over TLS", func(e session.UAEvent) bool {
		return e.Kind == session.UAEventDialogEnded && e.Cause == session.UACausePeerBYE
	})
}

func TestDialSipsRetryAfter422StaysOnTLS(t *testing.T) {
	caller, callee, inbound, callerEvents, _ := sipsTLSPair(t, func(c *Config) { c.MinSES = 2000 })
	res, err := caller.Dial(context.Background(), session.DialRequest{ToURI: "sips:bob@" + callee.LocalAddr().String()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := awaitEvent(t, inbound, 3*time.Second, "the first inbound INVITE", func(session.UAEvent) bool { return true })
	if err := callee.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: first.DialogID}); err == nil {
		t.Fatal("the first INVITE (Session-Expires below our Min-SE) must be refused with 422")
	}
	second := awaitEvent(t, inbound, 3*time.Second, "the 422 retry over TLS", func(session.UAEvent) bool { return true })
	if err := callee.AnswerEventually(context.Background(), session.AnswerRequest{DialogID: second.DialogID}); err != nil {
		t.Fatalf("Answer of the retry: %v", err)
	}
	awaitEvent(t, callerEvents, 3*time.Second, "the caller's 200", func(e session.UAEvent) bool {
		return e.Kind == session.UAEventFinal && e.Code == 200
	})
	if inv := dialogInvite(caller, res.DialogID); inv == nil || inv.Recipient.Scheme != "sips" {
		t.Errorf("after the retry the Request-URI = %v, want scheme sips", inv)
	}
}
