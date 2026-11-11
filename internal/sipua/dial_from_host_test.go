package sipua

import (
	"context"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestDirectModeInviteCarriesBoundFromHost pins the §14.5 Asterisk interop
// blocker. A direct-mode UA has NO AOR — session/toolservice.go's "direct"
// case never sets one — so engineConfig's aorParts("") yields an empty From
// host and the outbound INVITE rendered `From: <sip:>` (or `<sip:user@>` with
// from_user set). A loopback peer accepts that malformed From; Asterisk
// (RFC 3261-correct) silently drops it, so every direct-mode call against a
// real peer stuck in `dialing`. The From host MUST fall back to the UA's
// BOUND LOCAL IP so the INVITE carries a routable From.
//
// The AOR here is DELIBERATELY EMPTY, exactly as production direct mode builds
// it. The other outbound tests set AOR "sip:alice@example", whose bogus
// "example" host MASKED this defect — the whole reason a green loopback suite
// never caught it.
//
// Contact is asserted alongside From: it is where the far end sends ACK and
// BYE, so a hostless Contact would break the dialog on answer even if From
// were fixed. (Contact already derives from the bound LocalAddr, so this arm
// is a guard against a regression, not the driver of the red.)
func TestDirectModeInviteCarriesBoundFromHost(t *testing.T) {
	p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0"})
	ua, err := New(context.Background(), Config{
		Transport:          "udp",
		Mode:               "direct",
		Timeout:            2 * time.Second,
		InboundRingTimeout: 2 * time.Second,
		Clock:              fakeclock.New(time.Unix(0, 0)),
		LocalAddr:          "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	final := make(chan session.UAEvent, 4)
	ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventFinal {
			final <- ev
		}
	})

	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// d.invite is set once, at dialog creation, before Dial returns; runDial's
	// goroutine never mutates it, so reading it here races with nothing.
	d, err := ua.lookup(res.DialogID)
	if err != nil {
		t.Fatalf("lookup(%q): %v", res.DialogID, err)
	}

	wantHost := ua.BoundAddr().IP.String()

	from := d.invite.From()
	if from == nil {
		t.Fatal("outbound INVITE has no From header")
	}
	if from.Address.Host != wantHost {
		t.Errorf("outbound INVITE From host = %q, want %q (the UA's bound local IP) — "+
			"an empty From host renders `From: <sip:>`, which RFC 3261 peers such as "+
			"Asterisk silently drop (§14.5)", from.Address.Host, wantHost)
	}

	contact := d.invite.Contact()
	if contact == nil {
		t.Fatal("outbound INVITE has no Contact header")
	}
	if contact.Address.Host != wantHost {
		t.Errorf("outbound INVITE Contact host = %q, want %q (the UA's bound local IP) — "+
			"Contact is where the far end sends ACK and BYE and must be routable",
			contact.Address.Host, wantHost)
	}

	select {
	case <-final:
	case <-time.After(3 * time.Second):
		t.Fatal("no final event; the peer's response never reached the UA")
	}
}
