package sipua

import (
	"context"
	"errors"
	"testing"

	"github.com/emiago/sipgo/sip"

	sippeer "github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// CF-208 P5/P9/P10: onAck routes an ACK to the exchange it acknowledges.
func TestOnAckMatchesTheRightExchange(t *testing.T) {
	setup := func(t *testing.T) (*UA, *dialog, string) {
		u, d, _ := reofferDialog(t)
		u.calls.mu.Lock()
		tag := ourReInviteTagLocked(d)
		d.answerTag = tag
		u.calls.mu.Unlock()
		return u, d, tag
	}
	t.Run("the initial INVITE's ACK", func(t *testing.T) {
		u, d, _ := setup(t)
		u.calls.mu.Lock()
		d.peerReinvite = &peerReinviteState{cseq: 7}
		u.calls.mu.Unlock()
		u.onAck(peerRequest(d, u, sip.ACK, 1, ""), nil)
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if !d.acked || d.peerReinvite.acked {
			t.Errorf("acked=%v peerReinvite.acked=%v, want true / false", d.acked, d.peerReinvite.acked)
		}
	})
	t.Run("a re-INVITE's ACK", func(t *testing.T) {
		u, d, _ := setup(t)
		u.calls.mu.Lock()
		d.acked = true
		d.peerReinvite = &peerReinviteState{cseq: 7}
		u.calls.mu.Unlock()
		u.onAck(peerRequest(d, u, sip.ACK, 7, ""), nil)
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if !d.peerReinvite.acked {
			t.Error("the re-INVITE's ACK was not recorded")
		}
	})
	t.Run("a foreign CSeq", func(t *testing.T) {
		u, d, _ := setup(t)
		u.calls.mu.Lock()
		d.acked = true
		d.peerReinvite = &peerReinviteState{cseq: 7}
		u.calls.mu.Unlock()
		u.onAck(peerRequest(d, u, sip.ACK, 99, ""), nil)
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if d.peerReinvite.acked {
			t.Error("an ACK with a foreign CSeq was recorded")
		}
	})
	t.Run("no answerTag (an outbound dialog), the INVITE's CSeq, nothing pending", func(t *testing.T) {
		u, d, _ := setup(t)
		u.calls.mu.Lock()
		d.answerTag = "" // only Answer sets it, so an outbound dialog never has one
		u.calls.mu.Unlock()
		u.onAck(peerRequest(d, u, sip.ACK, 1, ""), nil)
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if d.acked {
			t.Error("an ACK with our INVITE's CSeq was recorded on a dialog with no answerTag")
		}
	})
}

// B-D14 (RFC 3261 14.1, P13): our refresh re-INVITE waits while the peer's INVITE
// exchange is not confirmed; an UPDATE refresh is not held.
func TestOurRefreshReInviteWaitsForThePeerReInvitesAck(t *testing.T) {
	invitePeer := func() *sippeer.Peer {
		return sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", Behaviour: sippeer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac", AnswerAllow: "INVITE, ACK, BYE, CANCEL"}})
	}
	for _, tc := range []struct {
		name     string
		setup    func(d *dialog)
		wantSent bool
	}{
		{"peer re-INVITE un-ACKed", func(d *dialog) { d.peerReinvite = &peerReinviteState{cseq: 7} }, false},
		{"peer offer pending", func(d *dialog) { d.peerOfferPending = true }, false},
		{"peer re-INVITE ACKed, our offer unanswered", func(d *dialog) { d.peerReinvite = &peerReinviteState{cseq: 7, acked: true, answerPending: true} }, false},
		{"peer re-INVITE ACKed", func(d *dialog) { d.peerReinvite = &peerReinviteState{cseq: 7, acked: true} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := invitePeer()
			u, d, st := dialedRefreshingDialog(t, p)
			u.calls.mu.Lock()
			tc.setup(d)
			gen := st.armGen
			u.calls.mu.Unlock()
			before := p.Count("INVITE")
			_, err := u.refreshSession(context.Background(), d, st, gen)
			if tc.wantSent {
				if err != nil || p.Count("INVITE") != before+1 {
					t.Fatalf("refresh err=%v, INVITEs %d -> %d, want a refresh re-INVITE sent", err, before, p.Count("INVITE"))
				}
				return
			}
			if err == nil || errors.Is(err, errRefresherStopped) {
				t.Fatalf("refresh err=%v, want a retryable error", err)
			}
			if p.Count("INVITE") != before {
				t.Fatalf("a re-INVITE went out although the peer's exchange is unconfirmed")
			}
		})
	}
	t.Run("an UPDATE refresh is not held", func(t *testing.T) {
		p := sippeer.Start(t, sippeer.Config{Addr: "127.0.0.1:0", Behaviour: sippeer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac", AnswerAllow: "INVITE, ACK, BYE, CANCEL, UPDATE"}})
		u, d, st := dialedRefreshingDialog(t, p)
		u.calls.mu.Lock()
		d.peerReinvite = &peerReinviteState{cseq: 7}
		gen := st.armGen
		u.calls.mu.Unlock()
		if _, err := u.refreshSession(context.Background(), d, st, gen); err != nil {
			t.Fatalf("UPDATE refresh err=%v", err)
		}
		if p.Count("UPDATE") != 1 {
			t.Fatalf("%d UPDATEs sent, want 1", p.Count("UPDATE"))
		}
	})
}

// failingFinalTx fails the write of a final response.
type failingFinalTx struct{ stubServerTx }

func (f *failingFinalTx) Respond(r *sip.Response) error {
	f.res = append(f.res, r)
	if r.StatusCode >= 200 {
		return errors.New("write failed")
	}
	return nil
}

// A re-INVITE whose 2xx cannot be written leaves nothing behind: no pending
// exchange (it would block every refresh re-INVITE, B-D14) and no refreshed target.
func TestReInviteWhose2xxWriteFailsLeavesNoExchangeAndNoRefresh(t *testing.T) {
	u, d, _ := reofferDialog(t)
	req := peerRequest(d, u, sip.INVITE, 11, reofferA)
	req.AppendHeader(sip.NewHeader("Contact", "<sip:moved@127.0.0.1:5999>"))
	u.onInvite(req, &failingFinalTx{})
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.peerReinvite != nil {
		t.Errorf("a failed 2xx write left d.peerReinvite = %+v", d.peerReinvite)
	}
	if d.remoteTarget != nil {
		t.Errorf("a failed 2xx write refreshed the remote target to %v", d.remoteTarget)
	}
}
