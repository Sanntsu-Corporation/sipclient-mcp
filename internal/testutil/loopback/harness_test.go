package loopback

import (
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Locked decision 13: five functional options. WithConn and WithPeerBehaviour
// are forward-looking and are designed at P1 so P2 does not reshape the
// constructor.
func TestFunctionalOptionsApply(t *testing.T) {
	var wrapped atomic.Int64
	wrap := func(c net.PacketConn) net.PacketConn { wrapped.Add(1); return c }

	o := newOptions()
	for _, opt := range []Option{
		WithTransport("udp"),
		WithConn(wrap),
		WithPeerBehaviour(PeerBehaviour{RejectStatus: 486}),
		WithAdminToken("admin-secret"),
		WithPolicyOverride("limits.shutdown_grace_period", "3s"),
	} {
		opt(&o)
	}
	if o.transport != "udp" {
		t.Fatalf("transport = %q, want %q", o.transport, "udp")
	}
	if o.wrapConn == nil {
		t.Fatal("WithConn did not install a wrapper; it is P2's netfault substitution seam")
	}
	if o.peer.RejectStatus != 486 {
		t.Fatalf("peer.RejectStatus = %d, want 486", o.peer.RejectStatus)
	}
	if o.adminToken != "admin-secret" {
		t.Fatalf("adminToken = %q, want %q", o.adminToken, "admin-secret")
	}
	if got := o.overrides["limits.shutdown_grace_period"]; got != "3s" {
		t.Fatalf("override = %v, want %q", got, "3s")
	}
}

func TestDefaultConnWrapperIsIdentity(t *testing.T) {
	o := newOptions()
	if o.wrapConn == nil {
		t.Fatal("newOptions must install the identity wrapper by default, not nil")
	}
}

// The seam must be genuinely load-bearing at P1, not dead code: the harness
// routes the UA's signalling PacketConn through it on the ordinary path.
func TestConnWrapperIsInvokedOnTheP1Path(t *testing.T) {
	var wrapped atomic.Int64
	h := New(t, WithConn(func(c net.PacketConn) net.PacketConn {
		wrapped.Add(1)
		return c
	}))
	defer h.Close()

	h.MustCreateUA(t, "direct")
	if got := wrapped.Load(); got != 1 {
		t.Fatalf("WithConn wrapper invoked %d times creating one UA, want 1 — if it is "+
			"never invoked, P2 inherits an unexercised seam", got)
	}
}

// §3d's concrete-bind trap: a wildcard bind makes sipgo silently open a
// second, untapped socket on the first outbound REGISTER or INVITE, because
// the transport pool is keyed by conn.LocalAddr().String() and no routable Via
// can ever match "0.0.0.0:5060". The harness therefore NEVER produces a
// wildcard.
//
// BOTH halves are load-bearing: a pinned Via is necessary but not sufficient.
func TestHarnessUABindsConcreteLoopbackAddressWithPinnedVia(t *testing.T) {
	h := New(t)
	defer h.Close()

	ua := h.MustCreateUA(t, "direct")
	st := h.MustUAStatus(t, ua)

	host, port, err := net.SplitHostPort(st.LocalAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", st.LocalAddr, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("UA bound host = %q, want %q — the harness must never bind a wildcard",
			host, "127.0.0.1")
	}
	if port == "0" || port == "" {
		t.Fatalf("UA bound port = %q, want a concrete kernel-assigned port", port)
	}

	// Drive one outbound INVITE, then assert the Via pinned the same post-bind
	// address.
	c := h.MustDial(t, ua, h.PeerURI())
	h.MustWait(t, c, "answered", 2000)
	if got := h.Peer().LastViaHostPort(); got != st.LocalAddr {
		t.Fatalf("Via pinned %q but the UA bound %q; an unpinned Via takes the same "+
			"untapped fall-through as a wildcard bind (§3d, D9d)", got, st.LocalAddr)
	}
}

func TestRegisterModeDigestLadder(t *testing.T) {
	h := New(t, WithAccounts(TestAccount("carrier-a", "s3cr3t-auth-pass")))
	defer h.Close()

	res := h.MustCallTool(t, "ua_create", h.UACreateArgsForAccount(t, "carrier-a"))
	if res["registered"] != true {
		t.Fatalf("ua_create registered = %v, want true", res["registered"])
	}
	if code, _ := res["register_code"].(float64); int(code) != 200 {
		t.Fatalf("register_code = %v, want 200", res["register_code"])
	}
	if _, ok := h.Registrar().LookupContact("testuser"); !ok {
		t.Fatal("registrar recorded no Contact for testuser")
	}
	// The in-process registrar challenges once, so the wire ladder is
	// REGISTER -> 401 -> REGISTER -> 200.
	if got := h.Registrar().RegisterCount("testuser"); got != 2 {
		t.Fatalf("registrar saw %d REGISTERs, want 2 (401 challenge then digest retry)", got)
	}
	if got := h.Registrar().ChallengeCount("testuser"); got != 1 {
		t.Fatalf("registrar issued %d challenges, want 1", got)
	}
}

func TestHarnessSupportsEveryP1Capability(t *testing.T) {
	h := New(t)
	defer h.Close()
	ua := h.MustCreateUA(t, "direct")

	t.Run("dial and hangup", func(t *testing.T) {
		c := h.MustDial(t, ua, h.PeerURI())
		h.MustWait(t, c, "answered", 2000)
		h.MustHangup(t, c)
		h.Peer().WaitForBye(t, time.Second)
	})

	t.Run("call_wait gates on ringing before answered", func(t *testing.T) {
		h.Peer().SetBehaviour(PeerBehaviour{AnswerAfter: 300 * time.Millisecond})
		c := h.MustDial(t, ua, h.PeerURI())
		res := h.CallWait(c, "ringing", 2000)
		if res.TimedOut || res.Event == nil || string(res.Event.Type) != "ringing" {
			t.Fatalf("call_wait(ringing) = %+v, want the ringing event", res)
		}
		if st := h.MustCallStatus(t, c).State; st == "answered" {
			t.Fatal("call_wait(ringing) returned only after answer; it must gate on ringing")
		}
		h.MustWait(t, c, "answered", 2000)
		h.MustHangup(t, c)
		h.Peer().SetBehaviour(PeerBehaviour{AnswerAfter: 0})
	})

	t.Run("inbound answer", func(t *testing.T) {
		h.Peer().Dial(t, h.UAContactURI(t, ua))
		c := h.MustWaitForInboundCall(t, 2*time.Second)
		h.MustCallTool(t, "call_answer", map[string]any{"call": c})
		st := h.MustCallStatus(t, c)
		if st.State != "answered" || st.Direction != "inbound" {
			t.Fatalf("inbound call = %+v, want answered/inbound", st)
		}
		h.MustHangup(t, c)
	})

	t.Run("inbound reject with a chosen status", func(t *testing.T) {
		// The PEER dials the UA here (Dial), so the peer is UAC and the 603
		// it observes is a response it RECEIVED — LastFinalStatus(), not
		// LastInboundFinalStatus() (which tracks a status the peer itself
		// SENT, for the reverse direction: an INVITE inbound TO the peer).
		h.Peer().Dial(t, h.UAContactURI(t, ua))
		c := h.MustWaitForInboundCall(t, 2*time.Second)
		before := h.Peer().FinalResponseCount()
		res := h.MustCallTool(t, "call_reject", map[string]any{"call": c, "status": 603})
		if code, _ := res["sip_code"].(float64); int(code) != 603 {
			t.Fatalf("call_reject sip_code = %v, want 603", res["sip_code"])
		}
		// D319: MustCallTool returns once the DAEMON has issued the reject; the
		// peer's LastFinalStatus only updates once the 603 ARRIVES over UDP and
		// recordResponse runs on the peer's own read goroutine — a read here
		// with no wait is a STALE read (it can pass vacuously on a value a
		// PRIOR subtest left behind). Poll, bounded, until the peer's own
		// final-response count has actually advanced, exactly as
		// peer.DialExpectingStatus does, before trusting the status.
		deadline := time.Now().Add(2 * time.Second)
		for h.Peer().FinalResponseCount() <= before {
			if time.Now().After(deadline) {
				t.Fatalf("peer did not observe a final response to the reject within 2s; "+
					"codes observed: %v", h.Peer().ResponseCodes())
			}
			time.Sleep(5 * time.Millisecond)
		}
		if got := h.Peer().LastFinalStatus(); got != 603 {
			t.Fatalf("peer observed final status %d, want 603", got)
		}
	})

	t.Run("ladder renders in all three formats", func(t *testing.T) {
		c := h.MustDial(t, ua, h.PeerURI())
		h.MustWait(t, c, "answered", 2000)
		h.MustHangup(t, c)

		text := h.Ladder(t, c, "text")
		for _, want := range []string{"INVITE", "200 OK", "BYE", "►", "◄"} {
			if !strings.Contains(text, want) {
				t.Fatalf("text ladder missing %q:\n%s", want, text)
			}
		}
		if mm := h.Ladder(t, c, "mermaid"); !strings.Contains(mm, "sequenceDiagram") {
			t.Fatalf("mermaid ladder missing sequenceDiagram:\n%s", mm)
		}
		var msgs []struct {
			Method     string `json:"method"`
			Serialized string `json:"serialized"`
			Fidelity   string `json:"fidelity"`
		}
		if err := json.Unmarshal([]byte(h.Ladder(t, c, "json")), &msgs); err != nil {
			t.Fatalf("json ladder does not parse: %v", err)
		}
		if len(msgs) == 0 {
			t.Fatal("json ladder is empty")
		}
		for _, m := range msgs {
			// U1 REVERSES the earlier D9d conclusion: UDP is byte_exact.
			if m.Fidelity != "byte_exact" {
				t.Fatalf("UDP message fidelity = %q, want %q (U1, D9d)", m.Fidelity, "byte_exact")
			}
			if m.Serialized == "" {
				t.Fatal("json ladder message carries no serialized bytes")
			}
		}
	})
}
