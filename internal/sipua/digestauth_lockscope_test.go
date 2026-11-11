package sipua

// Rule 13 Cycle 5 (architecture review) regression test for digestRetryMu's
// SCOPE.
//
// THE DEFECT THIS PINS. digestRetryMu is UA-GLOBAL: it does not distinguish
// (realm, nonce) identities, and both digest legs take it — REGISTER through
// doRequestWithDigest, the challenged outbound INVITE through
// digestAuthTransaction. It used to be held across BOTH the reservation
// (applyDigest) and the dispatch (TransactionRequest), and TransactionRequest
// synchronously DIALS when the destination has no live connection (TCP connect,
// and for tls the full handshake). So a slow or unreachable callee could park
// the INVITE leg inside its dispatch while still holding the lock, and a
// perfectly healthy registrar's refresh — a completely unrelated identity —
// would stall on u.digestRetryMu.Lock(). Mutex.Lock takes no context, so the
// waiter could not even honour its own deadline: unrelated call-path network
// trouble became registration failure.
//
// WHAT THE TEST DOES. It parks the INVITE leg's dispatch (identity
// calls.example/nonce-A) inside TransactionRequest and holds it there, then
// runs a full REGISTER digest exchange (identity registrar.example/nonce-R)
// and requires it to COMPLETE while the INVITE is still parked. Under the old
// wider critical section the REGISTER blocks on the lock and the test times
// out; the assertion cannot pass on the pre-fix code.
//
// HOW THE DISPATCH IS PARKED, without inventing test infrastructure: sipgo's
// Client exposes TxRequester ("useful only for testing", third_party/sipgo/
// client.go:30-34), the single funnel every transaction on this client goes
// through (requestTransaction, :163-168) — including siptest's own doTx, so one
// stub serves both legs. That is a far more precise seam than trying to make a
// real socket dial slowly, and it makes the test hermetic: no listener, no
// timing tolerance beyond the deadline that defines the failure.
//
// It does NOT assert wire ORDER. Narrowing the lock deliberately gave that up
// (see digestRetryMu's field comment in ua.go): reservation order stays
// guaranteed, wire order is best-effort exactly as the network already made it.
// The nonce-count assertions below check the guarantee that survived.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

// stubClientTx is a sip.ClientTransaction pre-loaded with one response.
type stubClientTx struct {
	responses chan *sip.Response
	done      chan struct{}
	once      sync.Once
}

func newStubClientTx(res *sip.Response) *stubClientTx {
	tx := &stubClientTx{responses: make(chan *sip.Response, 1), done: make(chan struct{})}
	tx.responses <- res
	return tx
}

func (tx *stubClientTx) Terminate()                      { tx.once.Do(func() { close(tx.done) }) }
func (tx *stubClientTx) Done() <-chan struct{}           { return tx.done }
func (tx *stubClientTx) Err() error                      { return nil }
func (tx *stubClientTx) Responses() <-chan *sip.Response { return tx.responses }

// gatedRequester answers every transaction request from memory, and parks the
// FIRST request matching gate until release is closed — the stand-in for a
// dispatch stuck in a TCP connect or TLS handshake.
type gatedRequester struct {
	gate    func(*sip.Request) bool
	reply   func(*sip.Request) *sip.Response
	entered chan struct{}
	release chan struct{}

	enteredOnce sync.Once
}

func (g *gatedRequester) Request(_ context.Context, req *sip.Request) (sip.ClientTransaction, error) {
	if g.gate(req) {
		g.enteredOnce.Do(func() { close(g.entered) })
		<-g.release
	}
	return newStubClientTx(g.reply(req)), nil
}

// newLockScopeUA builds the smallest UA that can run both digest legs: a
// siptest client (whose sipgo client carries the TxRequester seam) plus the
// credentials and timeout applyDigest and doRequestWithDigest read off cfg.
// New() is deliberately NOT used — it binds sockets and starts refreshers this
// test has no use for, and every transaction is intercepted before it can reach
// a socket anyway.
func newLockScopeUA(t *testing.T) *UA {
	t.Helper()
	agent, err := sipgo.NewUA(sipgo.WithUserAgentHostname("127.0.0.1"))
	if err != nil {
		t.Fatalf("sipgo.NewUA: %v", err)
	}
	client, err := siptest.NewClient(config.Config{
		LocalAddr: "127.0.0.1:0",
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		Timeout:   2 * time.Second,
	}, agent)
	if err != nil {
		t.Fatalf("siptest.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return &UA{
		client: client,
		cfg: Config{
			AuthUser:  "alice",
			AuthPass:  "s3cr3t",
			Timeout:   2 * time.Second,
			Registrar: "sip:registrar.example",
		},
	}
}

func lockScopeURI(t *testing.T, s string) sip.Uri {
	t.Helper()
	var u sip.Uri
	if err := sip.ParseUri(s, &u); err != nil {
		t.Fatalf("ParseUri(%q): %v", s, err)
	}
	return u
}

// challenge401 builds the 401 whose WWW-Authenticate names (realm, nonce).
// NewResponse, not NewResponseFromRequest: applyDigest reads only StatusCode
// and this one header, and the dialog-shaped copy would need a From/To/Call-ID
// on requests this test has no reason to give them.
func challenge401(realm, nonce string) *sip.Response {
	res := sip.NewResponse(401, "Unauthorized")
	res.AppendHeader(sip.NewHeader("WWW-Authenticate",
		fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5`, realm, nonce)))
	return res
}

func TestDigestRetryLockDoesNotBlockAnotherLegOnASlowDispatch(t *testing.T) {
	u := newLockScopeUA(t)

	g := &gatedRequester{
		// Park the INVITE leg's retry — and only it. The REGISTER leg's two
		// dispatches must sail through.
		gate:    func(req *sip.Request) bool { return req.Method == sip.INVITE },
		entered: make(chan struct{}),
		release: make(chan struct{}),
		reply: func(req *sip.Request) *sip.Response {
			// An unauthenticated REGISTER draws the registrar's challenge; the
			// authenticated retry (and the parked INVITE) get a 200.
			if req.Method == sip.REGISTER && req.GetHeader("Authorization") == nil {
				return challenge401("registrar.example", "nonce-R")
			}
			return sip.NewResponse(200, "OK")
		},
	}
	u.client.Raw().TxRequester = g

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(g.release) }) }
	defer release()

	// Both requests are built on the test goroutine: lockScopeURI can t.Fatalf,
	// which is only legal here.
	inviteReq := sip.NewRequest(sip.INVITE, lockScopeURI(t, "sip:bob@callee.example"))
	inviteReq.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	registerReq := sip.NewRequest(sip.REGISTER, lockScopeURI(t, "sip:registrar.example"))

	// LEG 1 (INVITE, identity calls.example/nonce-A): reserve nc, then park
	// inside TransactionRequest for as long as the test wants.
	inviteErr := make(chan error, 1)
	go func() {
		_, err := u.digestAuthTransaction(context.Background(), inviteReq, challenge401("calls.example", "nonce-A"))
		inviteErr <- err
	}()

	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the INVITE leg never reached its dispatch")
	}

	// LEG 2 (REGISTER, identity registrar.example/nonce-R): a DIFFERENT
	// (realm, nonce) entirely. THE ASSERTION: it completes while leg 1's
	// dispatch is still parked. Held across dispatch, digestRetryMu would make
	// this wait for leg 1's network I/O — which in production never has to
	// finish at all.
	regErr := make(chan error, 1)
	go func() {
		_, _, err := u.doRequestWithDigest(context.Background(), registerReq)
		regErr <- err
	}()

	select {
	case err := <-regErr:
		if err != nil {
			t.Fatalf("REGISTER leg: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the REGISTER leg did not complete while an unrelated INVITE's dispatch was " +
			"parked — digestRetryMu is being held across network I/O again")
	}

	// The reservation guarantee that narrowing the lock KEPT: each leg counted
	// in its own slot, both starting at 1.
	u.nonceCounter.mu.Lock()
	registrar := u.nonceCounter.registrar
	pooled := u.nonceCounter.invites[0]
	u.nonceCounter.mu.Unlock()
	if registrar.realm != "registrar.example" || registrar.nonce != "nonce-R" || registrar.count != 1 {
		t.Fatalf("registrar slot = %+v, want realm=registrar.example nonce=nonce-R count=1", registrar)
	}
	if pooled.realm != "calls.example" || pooled.nonce != "nonce-A" || pooled.count != 1 {
		t.Fatalf("pool head = %+v, want realm=calls.example nonce=nonce-A count=1", pooled)
	}

	release()
	select {
	case err := <-inviteErr:
		if err != nil {
			t.Fatalf("INVITE leg: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the INVITE leg did not finish after its dispatch was released")
	}
}
