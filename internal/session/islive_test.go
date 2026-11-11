package session

import (
	"context"
	"testing"
)

func TestManagerIsLive(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	sid := "s1"

	if err := m.Open(ctx, sid); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ua, err := m.CreateUA(ctx, sid, UAConfig{Mode: "direct", Transport: TransportUDP})
	if err != nil {
		t.Fatalf("CreateUA: %v", err)
	}
	c, err := m.CreateCall(ctx, sid, ua.Handle(), Outbound, StateAnswered)
	if err != nil {
		t.Fatalf("CreateCall: %v", err)
	}

	if !m.IsLive(string(c.Handle())) {
		t.Fatal("answered call not reported live")
	}
	if err := c.TryHangup(m.clk.Now(), "local_hangup"); err != nil {
		t.Fatalf("TryHangup: %v", err)
	}
	m.RecordTermination(c)
	if m.IsLive(string(c.Handle())) {
		t.Fatal("terminated call still reported live")
	}
	if m.IsLive("call-never-issued") {
		t.Fatal("unknown handle reported live")
	}
}
