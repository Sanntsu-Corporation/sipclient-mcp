package sipua_test

// Lane B (rfc-sweep-b) pin for the B-REF area. It passes today and must be
// inverted when its NEW-B finding is fixed.
// No test here calls t.Parallel (parallel_invariant_test.go). It reuses Lane A's
// raw-UDP UAS stub (startUACStub, stubResponse, stubHeaders, dialStub, newStubUA
// in rfc3261_pin_uac_test.go).

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// TestRFC3515_NEWB1_ReferFollowsTheRouteSet is NEW-B-1 / CF-108, fixed: RFC 3515
// 2: "REFERs occurring inside an existing dialog MUST follow the Route/Record-
// Route logic of that dialog." rfc3515.txt:136-138. The REFER carries the two
// Route values in reverse order and goes to the 200's Contact. Was
// the old RFC3515 pin NEWB1_ReferIgnoresRouteSet.
func TestRFC3515_NEWB1_ReferFollowsTheRouteSet(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
				"Contact: <sip:stub@" + s.addr() + ">",
				"Record-Route: <sip:" + s.addr() + ";lr;rr=1>",
				"Record-Route: <sip:" + s.addr() + ";lr;rr=2>",
			}, stubSDP))
		case "REFER":
			s.send(from, stubResponse(raw, 202, "Accepted", "", []string{"Contact: <sip:stub@" + s.addr() + ">"}, ""))
		}
	})
	ua := newStubUA(t)
	id := dialStub(t, ua, s)
	if r := stubHeaders(s.requests("ACK")[0], "Route"); len(r) != 2 {
		t.Fatalf("the ACK carries %d Route headers, want 2 (the pin's precondition): %v", len(r), r)
	}
	out, err := ua.Transfer(context.Background(), session.TransferRequest{
		DialogID: id, Mode: session.TransferBlind, Target: "sip:carol@example.com"})
	if err != nil || !out.Accepted {
		t.Fatalf("Transfer: %+v, %v", out, err)
	}
	if !stubWait(func() bool { return len(s.requests("REFER")) > 0 }, 3*time.Second) {
		t.Fatal("the stub never saw a REFER")
	}
	refer := s.requests("REFER")[0]
	r := stubHeaders(refer, "Route")
	if len(r) != 2 || !strings.Contains(r[0], "rr=2") || !strings.Contains(r[1], "rr=1") {
		t.Errorf("REFER Route = %v, want rr=2 then rr=1", r)
	}
	if got, want := stubRequestURI(refer), "sip:stub@"+s.addr(); got != want {
		t.Errorf("REFER Request-URI %q, want the Contact %q", got, want)
	}
}
