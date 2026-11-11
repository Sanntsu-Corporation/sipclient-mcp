package sipua

// CF-109/110/122 internals of sendInDialog: the outcome classifier, the
// synchronous single claim of endDialogInDialogTimeout, and the pinned
// destination of a credentialed retry.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func TestInDialogEndCauseTable(t *testing.T) {
	timeoutErr := fmt.Errorf("tx done: %v", sip.ErrTransactionTimeout)
	res := func(code int) *sip.Response { return sip.NewResponse(sip.StatusCode(code), "x") }
	cases := []struct {
		name   string
		method sip.RequestMethod
		ctxErr error
		res    *sip.Response
		err    error
		want   string
	}{
		{"BYE 481", sip.BYE, nil, res(481), nil, ""},
		{"BYE 408", sip.BYE, nil, res(408), nil, ""},
		{"BYE timeout", sip.BYE, nil, nil, timeoutErr, ""},
		{"ctx cancelled", sip.INFO, context.Canceled, nil, context.Canceled, ""},
		{"timeout text", sip.REFER, nil, nil, timeoutErr, "in_dialog_timeout"},
		{"deadline", sip.INFO, nil, nil, context.DeadlineExceeded, "in_dialog_timeout"},
		{"plain send error", sip.INFO, nil, nil, errors.New("boom"), ""},
		{"not dispatched, blocked to the deadline", sip.INFO, nil, nil, &noTransactionError{context.DeadlineExceeded}, ""},
		{"481", sip.REFER, nil, res(481), nil, "in_dialog_481"},
		{"408", sip.UPDATE, nil, res(408), nil, "in_dialog_408"},
		{"200", sip.INFO, nil, res(200), nil, ""},
		{"401", sip.INFO, nil, res(401), nil, ""},
		{"486", sip.INFO, nil, res(486), nil, ""},
	}
	for _, c := range cases {
		if got := inDialogEndCause(c.method, c.ctxErr, c.res, c.err); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestEndDialogInDialogTimeoutClaimsSynchronouslyAndOnce(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	events := teardownEventCollector(t, u)
	d, _ := newNotifyTestDialog(u, "cid-end-once")

	u.endDialogInDialogTimeout(d, "INFO", errors.New("x"), "in_dialog_481")
	u.calls.mu.Lock()
	phase, _, found := d.phase, 0, u.calls.byID[d.id] != nil
	u.calls.mu.Unlock()
	if phase != phaseDone || found {
		t.Fatalf("after the first call phase=%v registered=%v, want done and forgotten", phase, found)
	}
	u.endDialogInDialogTimeout(d, "REFER", errors.New("y"), "in_dialog_timeout") // a racing second claim

	deadline := time.After(3 * time.Second)
	for len(events()) < 1 {
		select {
		case <-deadline:
			t.Fatal("no dialog-ended event")
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(100 * time.Millisecond)
	n := 0
	for _, ev := range events() {
		if ev.Kind == session.UAEventDialogEnded {
			n++
			if ev.Detail["cause"] != "in_dialog_481" || ev.Detail["method"] != "INFO" {
				t.Errorf("event detail %v, want the first claimant's", ev.Detail)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d dialog-ended events, want exactly 1", n)
	}
}

// pinRequester answers attempt 1 with a 401 after resolving a destination on
// the request (the way the transport layer does) and records attempt 2's.
type pinRequester struct {
	mu    sync.Mutex
	n     int
	dests []string
}

func (r *pinRequester) Request(_ context.Context, req *sip.Request) (sip.ClientTransaction, error) {
	r.mu.Lock()
	r.n++
	n := r.n
	r.dests = append(r.dests, req.Destination())
	r.mu.Unlock()
	if n == 1 {
		req.SetDestination("203.0.113.9:5060") // as the transport layer stores the resolved address
		res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
		res.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="r",nonce="0123456789abcdef0123456789abcdef",qop="auth",algorithm=MD5`))
		return newStubClientTx(res), nil
	}
	return newStubClientTx(sip.NewResponseFromRequest(req, 200, "OK", nil)), nil
}

func TestInDialogDigestRetryKeepsThePinnedDestination(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	u.cfg.AuthUser, u.cfg.AuthPass, u.cfg.AuthAnyHost = "alice", "pw", true
	d := newWireOrderDialog()
	r := &pinRequester{}
	u.client.Raw().TxRequester = r

	_, res, err := u.sendInDialog(context.Background(), d, sip.INFO, nil)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("sendInDialog = %v, %v; want the credentialed retry's 200", res, err)
	}
	if len(r.dests) != 2 || r.dests[1] != "203.0.113.9:5060" {
		t.Fatalf("destinations %v: attempt 2 must go to attempt 1's resolved address", r.dests)
	}
}

// TestInDialogDigestWithheldForAForeignRequestTarget (Cycle 5 B1): the next hop is
// the account's registrar (a record-routing proxy) but the Request-URI, the
// peer's Contact, is a foreign host: the peer could replay the response, so a
// 401 relayed by the proxy is not answered.
func TestInDialogDigestWithheldForAForeignRequestTarget(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	u.cfg.AuthUser, u.cfg.AuthPass = "alice", "pw"
	u.cfg.Mode, u.cfg.Registrar = "register", "sip:proxy.example.com"
	req := sip.NewRequest(sip.INFO, sip.Uri{User: "+1900", Host: "attacker.example.net"})
	res := sip.NewResponse(401, "Unauthorized")
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="r",nonce="0123456789abcdef0123456789abcdef"`))
	d := newWireOrderDialog()
	if u.inDialogCanRetry(context.Background(), d, req, sip.Uri{Host: "proxy.example.com"}, res) {
		t.Fatal("credentials would be built for a Request-URI on a foreign host")
	}
}

// TestInDialogDigestWithheldForAForeignTargetBehindAStrictRouter (Cycle 4 round
// 1): the first route is the account's proxy WITHOUT lr, so the Request-URI is
// rewritten to the proxy and the foreign Contact moves to the end of Route. The
// retry must still be refused.
func TestInDialogDigestWithheldForAForeignTargetBehindAStrictRouter(t *testing.T) {
	setAnchorLookup(t, func(context.Context, string) ([]net.IPAddr, error) { return ipAddrs("203.0.113.9"), nil })
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	u.cfg.AuthUser, u.cfg.AuthPass = "alice", "pw"
	u.cfg.Mode, u.cfg.Registrar = "register", "sip:proxy.example.com"
	d := newWireOrderDialog()
	d.invite.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "+1900", Host: "attacker.example.net"}})
	d.invite.AppendHeader(&sip.RecordRouteHeader{Address: sip.Uri{Host: "proxy.example.com"}}) // no lr: strict
	req, hop, err := u.buildInDialogRequest(d, sip.INFO)
	if err != nil {
		t.Fatal(err)
	}
	if req.Recipient.Host != "proxy.example.com" || hop.Host != "proxy.example.com" {
		t.Fatalf("precondition: Request-URI %q and hop %q should both be the strict router", req.Recipient.Host, hop.Host)
	}
	req.SetDestination("203.0.113.9:5060") // pinned, as the transport layer stores it
	res := sip.NewResponse(401, "Unauthorized")
	res.SetSource("203.0.113.9:5060") // from the pinned proxy
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="r",nonce="0123456789abcdef0123456789abcdef"`))
	if u.inDialogCanRetry(context.Background(), d, req, hop, res) {
		t.Fatal("credentials would be sent through a strict router to a foreign remote target")
	}
}
