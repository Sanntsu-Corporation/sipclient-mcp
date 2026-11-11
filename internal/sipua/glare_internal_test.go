package sipua

import (
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestOnNotifyRequiresThePeerTag (CF-176, RFC 3261 12.2.2): a refer NOTIFY
// carrying our To tag but a foreign From tag matches no dialog (481) and
// settles nothing; with the peer's tag it is routed.
func TestOnNotifyRequiresThePeerTag(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, ours := newNotifyTestDialog(u, "cid-notify-peertag")
	w := newReferWaiter(7, session.TransferBlind)
	u.calls.mu.Lock()
	d.referWaiter = w
	u.calls.mu.Unlock()

	tx := &stubServerTx{}
	u.onNotify(referNotifyReq("cid-notify-peertag", "intruder", ours, "refer;id=7", "SIP/2.0 200 OK"), tx)
	if got := tx.last().StatusCode; got != 481 || settled(w) {
		t.Fatalf("foreign From tag: code %d, settled %v; want 481 and not settled", got, settled(w))
	}
	tx = &stubServerTx{}
	u.onNotify(referNotifyReq("cid-notify-peertag", "peer-tag", ours, "refer;id=7", "SIP/2.0 200 OK"), tx)
	if got := tx.last().StatusCode; got != 200 || !settled(w) {
		t.Fatalf("peer tag: code %d, settled %v; want 200 and settled", got, settled(w))
	}
}
