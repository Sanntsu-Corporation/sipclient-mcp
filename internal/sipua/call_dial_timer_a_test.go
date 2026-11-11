package sipua_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

// A dial timeout equal to a sipgo Timer A instant (500, 1500, 3500 ms ...) used
// to panic the vendored FSM (CF-050: actInviteResend reset a timer_a that
// terminate had already cleared). Five concurrent dials make five
// timer-vs-terminate coincidences per run; a panic kills the test binary.
// Deliberately sits ON a Timer A instant, unlike every other dial test here.
func TestDialTimeoutOnATimerAInstantDoesNotPanic(t *testing.T) {
	ua, _ := newLoggedUA(t, func(c *sipua.Config) { c.Timeout = 1500 * time.Millisecond })
	events := collect(t, ua)

	const dials = 5
	ids := make([]string, 0, dials)
	for i := 0; i < dials; i++ {
		res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + closedUDPAddr(t)})
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		ids = append(ids, res.DialogID)
	}
	for _, id := range ids {
		waitForDialog(t, events, id, session.UAEventDialogEnded, 0)
	}
	waitFor := time.Now().Add(3 * time.Second)
	for ua.RegisteredDialogCount() != 0 && time.Now().Before(waitFor) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := ua.RegisteredDialogCount(); n != 0 {
		t.Fatalf("RegisteredDialogCount = %d, want 0", n)
	}
}
