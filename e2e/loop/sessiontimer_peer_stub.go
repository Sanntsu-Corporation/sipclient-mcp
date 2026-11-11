package main

// sessiontimer_peer_stub.go — Task 33's scenario4 peer-refresher half
// (RULING 2): a stub that DIALS INTO the daemon's fixed-address UA
// (sessiontimerPeerFixedAddr) proposing itself as the session-timer
// refresher (Session-Expires: 90;refresher=uac in its OWN INVITE — the
// UAC's proposal). Per Task 28's rule ("claim uas unless the peer asked
// uac"), the daemon — UAS here — honours the peer's explicit uac claim and
// arms its watchdog instead of refreshing itself, which is the "peer
// refreshes, our watchdog is armed" half the original brief's scenario 4
// wanted, retargeted off the shared rig per RULING 2.
//
// Unlike sessiontimer_silent_stub.go and keepalive_stub.go, this stub is the
// CALLER, so it needs a real outbound-dialog client, not just a
// request/response responder — built on sipgo's own DialogClientCache
// (already an existing dependency; internal/sipua's own UA is built on the
// same library, just through a vendored construction wrapper this package
// main binary has no access to and no need of).
import (
	"context"
	"fmt"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// sessionTimerPeerSDP offers PCMU, matching the daemon's own default codec
// preference, so the call reaches `answered` and the fault under test stays
// isolated to the session-timer role negotiation.
const sessionTimerPeerSDP = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\nm=audio 20006 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

type sessionTimerPeerUAC struct {
	client *sipgo.Client
	cache  *sipgo.DialogClientCache
	dlg    *sipgo.DialogClientSession
}

func newSessionTimerPeerUAC(localIP string) (*sessionTimerPeerUAC, error) {
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("e2e-loop-peer-refresher-stub"))
	if err != nil {
		return nil, fmt.Errorf("sipgo.NewUA: %w", err)
	}
	client, err := sipgo.NewClient(ua, sipgo.WithClientHostname(localIP))
	if err != nil {
		return nil, fmt.Errorf("sipgo.NewClient: %w", err)
	}
	cache := sipgo.NewDialogClientCache(client, sip.ContactHeader{
		Address: sip.Uri{User: "stub", Host: localIP},
		Params:  sip.NewParams(),
	})
	return &sessionTimerPeerUAC{client: client, cache: cache}, nil
}

// Dial sends the INVITE proposing itself as refresher, then completes the
// handshake.
func (s *sessionTimerPeerUAC) Dial(ctx context.Context, toURI string) error {
	var recipient sip.Uri
	if err := sip.ParseUri(toURI, &recipient); err != nil {
		return fmt.Errorf("parse %q: %w", toURI, err)
	}
	dlg, err := s.cache.Invite(ctx, recipient, []byte(sessionTimerPeerSDP),
		sip.NewHeader("Content-Type", "application/sdp"),
		sip.NewHeader("Session-Expires", "90;refresher=uac"),
		sip.NewHeader("Supported", "timer"),
	)
	if err != nil {
		return fmt.Errorf("INVITE: %w", err)
	}
	if err := dlg.WaitAnswer(ctx, sipgo.AnswerOptions{}); err != nil {
		return fmt.Errorf("WaitAnswer: %w", err)
	}
	if err := dlg.Ack(ctx); err != nil {
		return fmt.Errorf("ack: %w", err)
	}
	s.dlg = dlg
	return nil
}

// Refresh sends one in-dialog UPDATE carrying the same Session-Expires,
// proving the daemon's watchdog REARMS on an inbound refresh rather than
// merely tolerating a call that happens not to reach the full interval
// (mirrors sessiontimer_watchdog_test.go's TestAnInboundRefreshRearmsTheWatchdog,
// exercised live).
func (s *sessionTimerPeerUAC) Refresh(ctx context.Context) error {
	recipient := s.dlg.InviteRequest.Recipient
	if cont := s.dlg.InviteResponse.Contact(); cont != nil {
		recipient = cont.Address
	}
	req := sip.NewRequest(sip.UPDATE, recipient)
	req.AppendHeader(sip.NewHeader("Session-Expires", "90;refresher=uac"))
	// RFC 4028 7.1: a timer-capable UAC MUST list timer in Supported on every
	// request, which also keeps the daemon's Table 2 answer on the "Y" row.
	req.AppendHeader(sip.NewHeader("Supported", "timer"))
	tx, err := s.dlg.TransactionRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("UPDATE: %w", err)
	}
	defer tx.Terminate()
	select {
	case res := <-tx.Responses():
		if res.StatusCode != 200 {
			return fmt.Errorf("UPDATE got %d %s", res.StatusCode, res.Reason)
		}
		return nil
	case <-tx.Done():
		return fmt.Errorf("UPDATE transaction died: %w", tx.Err())
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *sessionTimerPeerUAC) Close() {
	_ = s.client.Close()
}
