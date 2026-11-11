package loopback_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/loopback"
)

// §12.6's WIRE half. Task 17 asserts the same identity rules at the transport
// layer against a FAKE registry, because §6.2 forbids transport/mcp from
// importing sipua and it therefore cannot originate a real INVITE. This half
// asserts the rules hold with a real UA, a real dialog and D11's real inbound
// routing. NEITHER HALF ALONE DISCHARGES §12.6's ACCEPTANCE.
func TestUnknownIDRuleBothHalvesOverTheWire(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	s1 := h.NewSession(t)
	ua := s1.MustCreateUA(t, "direct")
	call := s1.MustDial(t, ua, h.PeerURI())
	s1.MustWait(t, call, "answered", 2000)

	tests := []struct {
		name              string
		id                func() string
		token             string
		wantInitStatus    int
		wantNonInitStatus int // 0 = success path, no failure asserted
	}{
		{"same id same token", func() string { return s1.ID() }, loopback.TestBearer(), 200, 0},
		// bearerAuth wraps ALL of /mcp (auth.go) and rejects a wrong bearer
		// token with 401 UNCONDITIONALLY, before any session-id logic runs
		// — confirmed empirically (a naive 200-init/404-non-init
		// expectation for this row failed outright). loopback.OtherBearer
		// is "never configured against any harness" by its own doc, so
		// presenting a VALID id alongside it still 401s on both requests:
		// a stolen/guessed session id grants nothing without its own
		// token.
		{"valid id different token", func() string { return s1.ID() }, loopback.OtherBearer(), 401, 401},
		{"fabricated id", func() string { return "00000000000000000000000000000000" },
			loopback.TestBearer(), 200, 404},
		{"absent id", func() string { return "" }, loopback.TestBearer(), 200, 404},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/initialize", func(t *testing.T) {
			got := h.Initialize(t, tt.id(), tt.token)
			if got.Status != tt.wantInitStatus {
				t.Fatalf("initialize status = %d, want %d", got.Status, tt.wantInitStatus)
			}
			if tt.wantInitStatus != 200 {
				return
			}
			if got.SessionID == "" {
				t.Fatal("initialize returned no Mcp-Session-Id")
			}
			if tt.name != "same id same token" && got.SessionID == tt.id() {
				t.Fatal("initialize echoed the presented id; it must issue a FRESH one")
			}
			if list := h.CallListFor(t, got.SessionID, tt.token); len(list) != 0 {
				t.Fatalf("fresh session call_list = %v, want empty", list)
			}
		})
		t.Run(tt.name+"/non-initialize", func(t *testing.T) {
			status, body := h.RawToolCallAs(t, tt.id(), tt.token, "call_status",
				map[string]any{"call": call})
			if tt.wantNonInitStatus == 0 {
				return
			}
			if status != tt.wantNonInitStatus {
				t.Fatalf("non-initialize with %s = %d, want %d", tt.name, status, tt.wantNonInitStatus)
			}
			if strings.Contains(body, call) || strings.Contains(body, ua) {
				t.Fatalf("%d body discloses a handle: %s", status, body)
			}
		})
	}
}

// D11 + §12.6 over the wire: an INVITE is answered on a UA whose owning session
// has no connection attached; its events are readable by THAT session when it
// reconnects with the same id and token, and not_found from any other session.
func TestInboundInviteResolvesOnlyForTheOwningSessionAfterReconnect(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	s1 := h.NewSession(t)
	// "direct" mode, not "register": this harness carries no profile
	// (loopback.New(t) with no options), and ua_create rejects
	// mode="register" with no profile as invalid_argument. The test needs
	// only an inbound INVITE routable to the UA's own bound address via
	// UAContactURI, which "direct" mode UAs already serve — the same
	// pattern setupInboundRinging (Step 0) and Step 1's table rows use.
	ua := s1.MustCreateUA(t, "direct")
	s1.CloseConnection(t)

	h.Peer().Dial(t, h.UAContactURI(t, ua))

	s1.Reconnect(t) // same id, same token
	call := s1.MustWaitForInboundCall(t, 2*time.Second)
	s1.MustCallTool(t, "call_answer", map[string]any{"call": call})
	if st := s1.MustCallStatus(t, call); st.State != "answered" {
		t.Fatalf("inbound call state = %q, want answered", st.State)
	}
	if len(s1.MustCallEvents(t, call, 0)) == 0 {
		t.Fatal("owning session sees no events for its own inbound call")
	}

	other := h.NewSession(t)
	if _, err := other.CallTool("call_status", map[string]any{"call": call}); loopback.ErrorCode(err) != "not_found" {
		t.Fatalf("foreign session got %q, want not_found (R11, §12.6)", loopback.ErrorCode(err))
	}

	// D11 point 4 ("an INVITE with no live UA matching gets 404 Not Found")
	// is NOT asserted here (Rule 6c blocker, reported to the wave owner):
	// destroyUA (session/destroy.go step 3) synchronously closes the UA's
	// UDP socket as part of ua_destroy's own teardown, and UAContactURI
	// addresses that same now-closed private port directly — dialing it
	// after destroy gets NO response at all (confirmed empirically: 0 final
	// responses in 5s), not a 404, because nothing is listening to answer
	// one. A raw direct-mode UA's own socket has no intermediary able to
	// answer 404 on its behalf; see admin_wire_test.go's identical finding
	// for the registrar-routed case.
	s1.MustCallTool(t, "ua_destroy", map[string]any{"ua": ua})
}

// §12.6's -race criterion, driven over the wire: 20 goroutines reconnecting
// under one identity while a 21st drives real inbound INVITEs at that
// session's UA.
func TestConcurrentReconnectionAndInboundInvitesLeakNoHandles(t *testing.T) {
	h := loopback.New(t)
	defer h.Close()

	owner := h.NewSession(t)
	// "direct" mode: same reasoning as above — this harness carries no
	// profile, and only inbound routing to the UA's own bound address is
	// exercised here.
	ua := owner.MustCreateUA(t, "direct")
	foreign := h.NewSession(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Error-returning forms, not Reconnect(t)/MustCallList(t):
				// a t.Fatal from this goroutine would Goexit it alone and
				// leave the other 19 running. The foreign-read check below
				// already uses t.Errorf + return; these two now match it.
				if err := owner.ReconnectErr(); err != nil {
					t.Errorf("owner reconnect: %v", err)
					return
				}
				list, err := owner.CallList()
				if err != nil {
					t.Errorf("owner call_list: %v", err)
					return
				}
				for _, c := range list {
					if _, err := foreign.CallTool("call_status", map[string]any{"call": c.CallHandle}); loopback.ErrorCode(err) != "not_found" {
						t.Errorf("foreign session observed handle %q (code %q); no handle "+
							"may ever be observed from a foreign session id",
							c.CallHandle, loopback.ErrorCode(err))
						return
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			h.Peer().Dial(t, h.UAContactURI(t, ua))
			time.Sleep(10 * time.Millisecond)
		}
		close(stop)
	}()
	wg.Wait()
}
