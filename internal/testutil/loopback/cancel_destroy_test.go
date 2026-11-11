package loopback_test

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// Ending a call that has not been answered yet, end to end through the real
// session.Manager: call_hangup and ua_destroy used to leave a ringing outbound
// call ringing at the far end (the INVITE was never CANCELled) and a ringing
// inbound call unanswered, while recording both terminated locally.

// wireLog records, IN ORDER, the start line of every datagram the UA's
// signalling socket writes and the socket's Close, so a test can pin the
// relative order of messages that go to DIFFERENT far ends (the call peer and
// the registrar).
type wireLog struct {
	mu  sync.Mutex
	seq []string
}

func (w *wireLog) add(s string) {
	w.mu.Lock()
	w.seq = append(w.seq, s)
	w.mu.Unlock()
}

func (w *wireLog) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.seq...)
}

type wireLogConn struct {
	net.PacketConn
	log *wireLog
	// cancelDelay, when set, holds every CANCEL write this long BEFORE it is
	// logged and sent. A caller released before its CANCEL is actually written
	// then deterministically logs its NEXT write (the REGISTER Expires: 0)
	// first, instead of only when the scheduler happens to interleave them.
	// sipgo's UDP write path takes no lock, so other writes are not held up.
	cancelDelay time.Duration
}

func (c *wireLogConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	line, _, _ := strings.Cut(string(b), "\r\n")
	if c.cancelDelay > 0 && strings.HasPrefix(line, "CANCEL ") {
		time.Sleep(c.cancelDelay)
	}
	c.log.add(line)
	return c.PacketConn.WriteTo(b, addr)
}

func (c *wireLogConn) Close() error {
	c.log.add("CLOSE")
	return c.PacketConn.Close()
}

// indexFrom is the index of the first entry at or after from that starts with
// prefix, or -1.
func indexFrom(seq []string, from int, prefix string) int {
	for i := from; i < len(seq); i++ {
		if strings.HasPrefix(seq[i], prefix) {
			return i
		}
	}
	return -1
}

// Criterion F: ua_destroy on a registered UA holding one RINGING outbound call
// and one ANSWERED call puts the CANCEL and the BYE on the wire BEFORE the
// REGISTER Expires: 0 and before the transport closes, and reports both calls
// terminated.
func TestUADestroyCancelsARingingCallAndByesAnAnsweredOneBeforeUnregistering(t *testing.T) {
	wl := &wireLog{}
	h := loopback.New(t,
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")),
		loopback.WithConn(func(c net.PacketConn) net.PacketConn { return &wireLogConn{PacketConn: c, log: wl} }))
	defer h.Close()

	ua := h.MustCreateUAWithAccount(t, "carrier-a")
	answered := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, answered, "answered", 5000)

	h.Peer().SetBehaviour(loopback.PeerBehaviour{RingThenSilent: true})
	ringing := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, ringing, "ringing", 5000)

	from := len(wl.snapshot())
	res := h.MustCallTool(t, "ua_destroy", map[string]any{"ua": ua})
	if n, _ := res["calls_terminated"].(float64); n != 2 {
		t.Fatalf("calls_terminated = %v, want 2 (%+v)", res["calls_terminated"], res)
	}

	seq := wl.snapshot()
	cancelAt, byeAt := indexFrom(seq, from, "CANCEL "), indexFrom(seq, from, "BYE ")
	unregAt, closeAt := indexFrom(seq, from, "REGISTER "), indexFrom(seq, from, "CLOSE")
	if cancelAt < 0 || byeAt < 0 || unregAt < 0 || closeAt < 0 {
		t.Fatalf("teardown wire sequence %q: want a CANCEL, a BYE, a REGISTER Expires:0 and a close", seq[from:])
	}
	if cancelAt > unregAt || byeAt > unregAt || unregAt > closeAt {
		t.Fatalf("teardown wire sequence %q: want CANCEL and BYE before the REGISTER Expires:0, "+
			"and all of them before the transport closes", seq[from:])
	}
	waitForPeerCancel(t, h)
	if n := h.Peer().ByeCount(); n != 1 {
		t.Fatalf("peer received %d BYE, want exactly 1 (the answered call only)", n)
	}
}

// Criterion G: ua_destroy on a UA holding a RINGING inbound call declines it
// 603 at the caller; the call's termination_reason stays local_hangup.
func TestUADestroyDeclinesARingingInboundCall603(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	c := setupInboundRinging(t, h, ua)

	res := h.MustCallTool(t, "ua_destroy", map[string]any{"ua": ua})
	if n, _ := res["calls_terminated"].(float64); n != 1 {
		t.Fatalf("calls_terminated = %v, want 1 (%+v)", res["calls_terminated"], res)
	}
	if code := h.Peer().WaitForInviteFinal(t, 3*time.Second); code != 603 {
		t.Fatalf("caller received final %d, want 603 Decline", code)
	}
	if m, ok := h.CallLogLineFor(t, c); !ok || m["termination_reason"] != "local_hangup" {
		t.Fatalf("call log line %v (found %v): want termination_reason local_hangup", m, ok)
	}
}

// call_hangup (the tool, not ua_destroy) on a RINGING inbound call declines it
// 603 at the caller, records local_hangup, and puts exactly one final on the
// wire.
func TestCallHangupDeclinesARingingInboundCall603(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	c := setupInboundRinging(t, h, ua)

	if err := h.Hangup(c); err != nil {
		t.Fatalf("call_hangup on a ringing inbound call = %v, want success", err)
	}
	if code := h.Peer().WaitForInviteFinal(t, 3*time.Second); code != 603 {
		t.Fatalf("caller received final %d, want 603 Decline", code)
	}
	if m, ok := h.CallLogLineFor(t, c); !ok || m["termination_reason"] != "local_hangup" {
		t.Fatalf("call log line %v (found %v): want termination_reason local_hangup", m, ok)
	}
	time.Sleep(200 * time.Millisecond) // a second, stray final would land here
	if n := h.Peer().FinalResponseCount(); n != 1 {
		t.Fatalf("caller received %d finals, want exactly 1", n)
	}
}

// Criterion H: call_hangup on a ringing outbound call succeeds (it used to
// return precondition_failed after the session had already recorded the call
// terminated) and CANCELs the INVITE.
func TestCallHangupOnARingingOutboundCallSucceedsAndCancels(t *testing.T) {
	h := loopback.New(t, loopback.WithPeerBehaviour(loopback.PeerBehaviour{RingThenSilent: true}))
	defer h.Close()

	c := h.MustDialRinging(t)
	if err := h.Hangup(c); err != nil {
		t.Fatalf("call_hangup on a ringing outbound call = %v, want success", err)
	}
	if st := h.MustCallStatus(t, c); st.State != "terminated" {
		t.Fatalf("call state = %q, want terminated", st.State)
	}
	waitForPeerCancel(t, h)
}

// waitForPeerCancel polls until the far end has received a CANCEL, then
// requires it to be exactly one.
func waitForPeerCancel(t *testing.T, h *loopback.Harness) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.Peer().Count("CANCEL") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := h.Peer().Count("CANCEL"); n != 1 {
		t.Fatalf("peer received %d CANCEL, want exactly 1", n)
	}
}

// ua_destroy on a call still DIALING (no provisional yet) whose far end rings
// ~300ms later: the teardown must wait for that first provisional and put the
// CANCEL on the wire BEFORE the REGISTER Expires: 0 and the transport close —
// not close the socket first and leave the phone ringing with nobody to
// CANCEL it. The CANCEL's write is held 100ms (cancelDelay), so a Hangup that
// returned before the CANCEL was WRITTEN — not merely scheduled — fails here
// every time.
func TestUADestroyWaitsForTheFirstProvisionalToCancelADialingCall(t *testing.T) {
	wl := &wireLog{}
	h := loopback.New(t,
		loopback.WithAccounts(loopback.TestAccount("carrier-a", "s3cr3t-auth-pass")),
		loopback.WithConn(func(c net.PacketConn) net.PacketConn {
			return &wireLogConn{PacketConn: c, log: wl, cancelDelay: 100 * time.Millisecond}
		}))
	defer h.Close()

	ua := h.MustCreateUAWithAccount(t, "carrier-a")
	hold := make(chan struct{})
	h.Peer().SetBehaviour(loopback.PeerBehaviour{RingThenSilent: true, HoldProvisionals: hold})
	before := h.Peer().Count("INVITE")
	c := h.MustDial(t, ua, h.PeerURI())
	deadline := time.Now().Add(3 * time.Second)
	for h.Peer().Count("INVITE") == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := h.MustCallStatus(t, c); st.State != "dialing" {
		t.Fatalf("call state = %q, want dialing (no provisional yet)", st.State)
	}

	from := len(wl.snapshot())
	time.AfterFunc(300*time.Millisecond, func() { close(hold) })
	res := h.MustCallTool(t, "ua_destroy", map[string]any{"ua": ua})
	if n, _ := res["calls_terminated"].(float64); n != 1 {
		t.Fatalf("calls_terminated = %v, want 1 (%+v)", res["calls_terminated"], res)
	}

	seq := wl.snapshot()
	cancelAt := indexFrom(seq, from, "CANCEL ")
	unregAt, closeAt := indexFrom(seq, from, "REGISTER "), indexFrom(seq, from, "CLOSE")
	if cancelAt < 0 || unregAt < 0 || closeAt < 0 || cancelAt > unregAt || unregAt > closeAt {
		t.Fatalf("teardown wire sequence %q: want the CANCEL before the REGISTER Expires:0, "+
			"and both before the transport closes", seq[from:])
	}
	waitForPeerCancel(t, h)
}
