// internal/sipua/indialog_test.go — D12's regression tests for sendInDialog.
package sipua

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// wireOrderRequester answers every transaction from memory and records each
// request's CSeq at the moment it is "written" — i.e. when it LEAVES Request,
// which runs inside sipgo's TransactionRequest AFTER the CSeq bump and is where
// the real ClientTx.Init writes. The FIRST request whose method is parkMethod is
// held inside Request — its CSeq already reserved, not yet written — until
// release is closed. Every other request reports its method on entered.
type wireOrderRequester struct {
	parkMethod sip.RequestMethod
	parked     chan struct{}
	release    chan struct{}
	entered    chan sip.RequestMethod

	mu         sync.Mutex
	parkedOnce bool
	wire       []uint32
}

func (r *wireOrderRequester) Request(_ context.Context, req *sip.Request) (sip.ClientTransaction, error) {
	r.mu.Lock()
	park := !r.parkedOnce && req.Method == r.parkMethod
	if park {
		r.parkedOnce = true
	}
	r.mu.Unlock()
	if park {
		close(r.parked)
		<-r.release
	} else {
		r.entered <- req.Method
	}
	r.mu.Lock()
	r.wire = append(r.wire, req.CSeq().SeqNo)
	r.mu.Unlock()
	return newStubClientTx(sip.NewResponseFromRequest(req, 200, "OK", nil)), nil
}

// newWireOrderDialog is an answered inbound dialog carrying everything
// buildInDialogRequest needs (an INVITE with a CSeq, and our 200).
func newWireOrderDialog() *dialog {
	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader("call-wire-order")
	inv.AppendHeader(&cid)
	from := &sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()}
	from.Params.Add("tag", "peer-tag")
	inv.AppendHeader(from)
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	return &dialog{id: "d-wire", direction: session.Inbound, phase: phaseAnswered, callID: "call-wire-order",
		invite: inv, ok: sip.NewResponseFromRequest(inv, 200, "OK", nil), localCSeq: 1}
}

// TestALaterInDialogRequestCannotOvertakeAnEarlierOneOnTheWire is D12 (Cycle C
// finding 1). A REFER is parked INSIDE its dispatch, after its CSeq was
// reserved. A second in-dialog request is then started. Its outcome is observed
// positively either way: it either reaches the wire first, which is the defect,
// or it reports that it found the dialog's send-order token held and waited.
// Neither outcome depends on goroutine scheduling or a sleep. Once the REFER is
// released, the wire order must equal the CSeq order.
func TestALaterInDialogRequestCannotOvertakeAnEarlierOneOnTheWire(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d := newWireOrderDialog()
	r := &wireOrderRequester{parkMethod: sip.REFER, parked: make(chan struct{}),
		release: make(chan struct{}), entered: make(chan sip.RequestMethod, 4)}
	u.client.Raw().TxRequester = r
	var releaseOnce sync.Once
	releaseRefer := func() { releaseOnce.Do(func() { close(r.release) }) }
	defer releaseRefer()

	contended := make(chan sip.RequestMethod, 4)
	inDialogSendContendedHook = func(m sip.RequestMethod) { contended <- m }
	t.Cleanup(func() { inDialogSendContendedHook = nil })

	ctx := context.Background()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, _, err := u.sendInDialog(ctx, d, sip.REFER, nil); first <- err }()
	select {
	case <-r.parked:
	case <-time.After(3 * time.Second):
		t.Fatal("the REFER never reached its dispatch")
	}

	go func() { _, _, err := u.sendInDialog(ctx, d, sip.UPDATE, nil); second <- err }()
	select {
	case m := <-r.entered:
		t.Fatalf("%s reached the wire while the REFER, which reserved a LOWER CSeq, was still "+
			"parked in its dispatch — RFC 3261 §12.2.1.1 (CSeq increases in SEND order) violated", m)
	case m := <-contended:
		if m != sip.UPDATE {
			t.Fatalf("contended send was %s, want UPDATE", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the UPDATE neither overtook the REFER nor waited for the send-order token")
	}

	releaseRefer()
	for i, ch := range []chan error{first, second} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("send %d never completed", i)
		}
	}
	r.mu.Lock()
	wire := append([]uint32(nil), r.wire...)
	r.mu.Unlock()
	if len(wire) != 2 || wire[1] != wire[0]+1 {
		t.Fatalf("wire CSeqs in send order = %v, want two consecutive, strictly increasing values", wire)
	}
}

// TestACancelledWaitForTheSendOrderTokenSendsNothing: a sender whose ctx ends
// while another request holds the token returns ctx's error, a nil request, and
// consumes no CSeq.
func TestACancelledWaitForTheSendOrderTokenSendsNothing(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d := newWireOrderDialog()
	r := &wireOrderRequester{parkMethod: sip.REFER, parked: make(chan struct{}),
		release: make(chan struct{}), entered: make(chan sip.RequestMethod, 4)}
	u.client.Raw().TxRequester = r
	defer close(r.release)

	go func() { _, _, _ = u.sendInDialog(context.Background(), d, sip.REFER, nil) }()
	<-r.parked
	u.calls.mu.Lock()
	before := d.localCSeq
	u.calls.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, res, err := u.sendInDialog(ctx, d, sip.UPDATE, func(*sip.Request) {
		t.Error("prepare ran for a send that never got its turn")
	})
	if req != nil || res != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got (%v, %v, %v), want (nil, nil, context.Canceled)", req, res, err)
	}
	u.calls.mu.Lock()
	after := d.localCSeq
	u.calls.mu.Unlock()
	if after != before {
		t.Fatalf("localCSeq %d -> %d: a send that never got its turn consumed a CSeq", before, after)
	}
}

// TestABYEStillWaitsForTheSendOrderTokenAfterItsCallerGaveUp is Cycle C round
// 2's non-blocking finding 1. Every BYE sender has ALREADY set phaseDone and
// forgotten the dialog, so a BYE whose caller's ctx is cancelled while another
// request holds the token must still go out once the token frees. Otherwise
// the call ends locally with nothing on the wire. The contended hook fires
// BEFORE the wait in both the fixed and the unfixed code, so the discriminating
// assertion is the second one: a request was built and reached the wire.
func TestABYEStillWaitsForTheSendOrderTokenAfterItsCallerGaveUp(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d := newWireOrderDialog()
	r := &wireOrderRequester{parkMethod: sip.REFER, parked: make(chan struct{}),
		release: make(chan struct{}), entered: make(chan sip.RequestMethod, 4)}
	u.client.Raw().TxRequester = r
	var releaseOnce sync.Once
	releaseRefer := func() { releaseOnce.Do(func() { close(r.release) }) }
	defer releaseRefer()
	contended := make(chan sip.RequestMethod, 4)
	inDialogSendContendedHook = func(m sip.RequestMethod) { contended <- m }
	t.Cleanup(func() { inDialogSendContendedHook = nil })

	go func() { _, _, _ = u.sendInDialog(context.Background(), d, sip.REFER, nil) }()
	<-r.parked
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the hangup's caller has already given up
	bye := make(chan *sip.Request, 1)
	go func() { req, _, _ := u.sendInDialog(ctx, d, sip.BYE, nil); bye <- req }()
	select {
	case m := <-contended:
		if m != sip.BYE {
			t.Fatalf("contended send was %s, want BYE", m)
		}
	case req := <-bye:
		t.Fatalf("the BYE returned (req=%v) without waiting for the send-order token", req)
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE never reached the send-order token")
	}

	releaseRefer()
	select {
	case req := <-bye:
		if req == nil {
			t.Fatal("the BYE was never built: a cancelled caller ctx abandoned it while waiting " +
				"for its turn, so the dialog ended locally with no BYE on the wire")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE never completed")
	}
	r.mu.Lock()
	n := len(r.wire)
	r.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d requests on the wire, want 2 (the REFER, then the BYE)", n)
	}
}

// TestEveryInDialogRequestIsSentThroughSendInDialog pins D12's widening: the
// seam only orders the wire if EVERY in-dialog sender uses it. A call site
// that builds its own request with buildInDialogRequest and dispatches it
// directly reintroduces the allocate-unlock-send race.
func TestEveryInDialogRequestIsSentThroughSendInDialog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sites []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "u.buildInDialogRequest(") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				sites = append(sites, f+":"+strconv.Itoa(i+1))
			}
		}
	}
	if len(sites) != 1 || !strings.HasPrefix(sites[0], "indialog.go:") {
		t.Fatalf("buildInDialogRequest call sites = %v, want exactly one, in indialog.go's sendInDialog", sites)
	}
}

// TestNoTransactionErrUnwrapsToTheOriginalError is CF-009's Cycle C fix:
// noTransactionError must support errors.Is/errors.As traversal into the
// wrapped error, not just Error() pass-through — embedding the error
// interface alone satisfies Error() but gives errors.Is/As no path through
// without an explicit Unwrap() method.
func TestNoTransactionErrUnwrapsToTheOriginalError(t *testing.T) {
	sentinel := errors.New("sentinel transport failure")
	wrapped := error(&noTransactionError{sentinel})

	if !noTransactionErr(wrapped) {
		t.Fatal("noTransactionErr(wrapped) = false, want true")
	}
	if !errors.Is(wrapped, sentinel) {
		t.Fatal("errors.Is(wrapped, sentinel) = false: noTransactionError.Unwrap() is missing or broken")
	}
	if got := errors.Unwrap(wrapped); got != sentinel {
		t.Fatalf("errors.Unwrap(wrapped) = %v, want the sentinel error", got)
	}
}

// TestNoNonBYERequestFollowsOurOwnBYEOnTheWire is CF-018. A non-BYE sender is
// blocked on the dialog's send-order token, already PAST any caller-side
// liveness check. The dialog is then torn down exactly as hangupWithReason does
// it (phaseDone first, then its BYE through the seam, which queues behind the
// same token). Once the token frees, the non-BYE request must be refused, the
// BYE must still go out, and the refusal must consume no CSeq.
func TestNoNonBYERequestFollowsOurOwnBYEOnTheWire(t *testing.T) {
	// INVITE is refreshSession's re-INVITE fallback (refreshMethodFor).
	for _, method := range []sip.RequestMethod{sip.REFER, sip.INFO, sip.UPDATE, sip.INVITE} {
		t.Run(string(method), func(t *testing.T) {
			u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
			d := newWireOrderDialog()
			// parkMethod left empty: nothing parks, every write reports on entered.
			r := &wireOrderRequester{entered: make(chan sip.RequestMethod, 4)}
			u.client.Raw().TxRequester = r
			contended := make(chan sip.RequestMethod, 4)
			inDialogSendContendedHook = func(m sip.RequestMethod) { contended <- m }
			t.Cleanup(func() { inDialogSendContendedHook = nil })

			u.calls.mu.Lock()
			tok := sendOrderTokLocked(d)
			u.calls.mu.Unlock()
			tok <- struct{}{}

			type result struct {
				req *sip.Request
				err error
			}
			awaitContended := func(want sip.RequestMethod) {
				t.Helper()
				select {
				case m := <-contended:
					if m != want {
						t.Fatalf("contended send was %s, want %s", m, want)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("%s never reached the send-order token", want)
				}
			}
			recv := func(ch chan result, what string) result {
				t.Helper()
				select {
				case got := <-ch:
					return got
				case <-time.After(3 * time.Second):
					t.Fatalf("%s never completed", what)
					return result{}
				}
			}

			sent := make(chan result, 1)
			go func() {
				req, _, err := u.sendInDialog(context.Background(), d, method, nil)
				sent <- result{req, err}
			}()
			awaitContended(method)

			u.calls.mu.Lock()
			d.phase = phaseDone
			before := d.localCSeq
			u.calls.mu.Unlock()
			bye := make(chan result, 1)
			go func() {
				req, _, err := u.sendInDialog(context.Background(), d, sip.BYE, nil)
				bye <- result{req, err}
			}()
			awaitContended(sip.BYE)

			<-tok
			got, b := recv(sent, string(method)), recv(bye, "BYE")

			if got.req != nil || apierr.CodeOf(got.err) != apierr.CodePreconditionFailed {
				t.Fatalf("%s on a torn-down dialog: req=%v err=%v, want nil and precondition_failed",
					method, got.req, got.err)
			}
			if b.req == nil || b.err != nil {
				t.Fatalf("our own BYE after phaseDone: req=%v err=%v, want it built and sent (BYE is exempt)",
					b.req, b.err)
			}
			var wire []sip.RequestMethod
			for len(r.entered) > 0 {
				wire = append(wire, <-r.entered)
			}
			if len(wire) != 1 || wire[0] != sip.BYE {
				t.Fatalf("wire carried %v, want exactly [BYE]", wire)
			}
			u.calls.mu.Lock()
			after := d.localCSeq
			u.calls.mu.Unlock()
			if after != before+1 {
				t.Fatalf("localCSeq %d -> %d, want +1 (the BYE only): the refused %s burned a CSeq",
					before, after, method)
			}
		})
	}
}
