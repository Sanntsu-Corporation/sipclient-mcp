package sipua_test

// CF-113: RFC 4028 7.1 "A UAC that supports the session timer extension ...
// MUST include a Supported header field in each request (except ACK), listing
// the option tag 'timer'". The in-dialog half is in indialog_route_test.go.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

func hasTimer(v string) bool { return strings.Contains(strings.ToLower(v), "timer") }

func TestCancelCarriesSupportedTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RingThenSilent: true}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventProvisional, 180)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	waitPeerCount(t, p, "CANCEL", 1)
	if got := p.LastRequestHeader("CANCEL", "Supported"); !hasTimer(got) {
		t.Errorf("CANCEL Supported = %q, want timer", got)
	}
}

func TestRegisterAndItsRetriesCarrySupportedTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, cc := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if cc.Sent("REGISTER") != 2 {
		t.Fatalf("want the challenge and its digest retry, sent %d", cc.Sent("REGISTER"))
	}
	if got := p.LastRequestHeader("REGISTER", "Supported"); !hasTimer(got) {
		t.Errorf("digest-retry REGISTER Supported = %q, want timer", got)
	}
	if err := ua.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if p.LastExpires() != 0 {
		t.Fatalf("last REGISTER Expires = %d, want the de-registration", p.LastExpires())
	}
	if got := p.LastRequestHeader("REGISTER", "Supported"); !hasTimer(got) {
		t.Errorf("de-registration Supported = %q, want timer", got)
	}
}

func TestKeepaliveOptionsCarriesSupportedTimer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	clk := fakeclock.New(time.Unix(0, 0))
	ua := newKeepaliveUA(t, p, clk, "options", 30)
	defer func() { _ = ua.Close(context.Background()) }()
	clk.BlockUntil(1)
	clk.Advance(31 * time.Second)
	waitForCond(t, func() bool { return p.Count("OPTIONS") >= 1 })
	if got := p.LastRequestHeader("OPTIONS", "Supported"); !hasTimer(got) {
		t.Errorf("OPTIONS Supported = %q, want timer", got)
	}
}

func TestForkByeCarriesSupportedTimer(t *testing.T) {
	s := forkStub(t, nil, "forkB")
	ua := newStubUA(t)
	dialStub(t, ua, s)
	settle(s, 2, 1)
	byes := s.requests("BYE")
	if len(byes) != 1 {
		t.Fatalf("%d fork BYEs, want 1", len(byes))
	}
	if n := timerCount(stubHeaders(byes[0], "Supported")); n != 1 {
		t.Errorf("fork BYE Supported = %v, want timer exactly once", stubHeaders(byes[0], "Supported"))
	}
	for _, a := range s.requests("ACK") {
		if h := stubHeaders(a, "Supported"); len(h) != 0 {
			t.Errorf("an ACK carries Supported %v", h)
		}
	}
}

func TestAckNeverCarriesSupported(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	dialStub(t, ua, s)
	acks := s.requests("ACK")
	if len(acks) == 0 {
		t.Fatal("no ACK")
	}
	if h := stubHeaders(acks[0], "Supported"); len(h) != 0 {
		t.Errorf("ACK carries Supported %v", h)
	}
}
