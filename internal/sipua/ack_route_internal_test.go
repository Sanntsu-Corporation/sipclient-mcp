package sipua

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func TestNewAckFor2xxRefusesASipsTargetOnANonTLSUA(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	inv := routeTestInvite(t)
	ack, err := u.newAckFor2xx(inv, routeTestOK(t), sip.Uri{Scheme: "sips", User: "x", Host: "h"}, nil)
	if err == nil || ack != nil {
		t.Fatalf("got (%v, %v), want an error and no ACK", ack, err)
	}
}

func TestAddressInDialogClearsACopiedDestination(t *testing.T) {
	req := sip.NewRequest(sip.ACK, sip.Uri{Scheme: "sip", User: "x", Host: "10.9.9.9"})
	req.SetDestination("10.9.9.9:5060")
	target := sip.Uri{Scheme: "sip", User: "x", Host: "127.0.0.1", Port: 5999}
	addressInDialog(req, target, nil, "UDP")
	if got := req.Destination(); got != "127.0.0.1:5999" {
		t.Fatalf("Destination = %q, want the remote target", got)
	}
}

func TestNewAckFor2xxKeepsTheAckShape(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	inv := routeTestInvite(t)
	res := routeTestOK(t)
	target := sip.Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: 5070}
	ack, err := u.newAckFor2xx(inv, res, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ack.CSeq().SeqNo != inv.CSeq().SeqNo || string(ack.CSeq().MethodName) != "ACK" {
		t.Errorf("CSeq %v", ack.CSeq())
	}
	if ack.From().Params == nil || ack.CallID().Value() != inv.CallID().Value() {
		t.Error("From or Call-ID not carried")
	}
	if tag, _ := ack.From().Params.Get("tag"); tag != "ft" {
		t.Errorf("From tag %q", tag)
	}
	if ack.To() == nil || ack.MaxForwards() == nil {
		t.Error("To or Max-Forwards missing")
	}
	if ack.Via() != nil {
		t.Error("an ACK built here carries no Via: the transport adds it")
	}
	if ack.Recipient.Host != "127.0.0.1" || ack.Recipient.Port != 5070 {
		t.Errorf("Request-URI %s, want the remote target", ack.Recipient.String())
	}
}
