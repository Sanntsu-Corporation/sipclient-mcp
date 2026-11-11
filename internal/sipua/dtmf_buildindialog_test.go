// internal/sipua/dtmf_buildindialog_test.go — D19 and B-M8's regression tests
// for buildInDialogRequest (dtmf.go). Package sipua (whitebox): both bugs are
// only observable through unexported state (d.localCSeq, buildInDialogRequest
// itself).
package sipua

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// TestBuildInDialogRequestClonesFromToInsteadOfAliasing is D19's regression
// test. buildInDialogRequest's inbound branch used to assign
// reqFrom.Params/reqTo.Params and reqFrom.Address/reqTo.Address straight from
// ok.To()/inv.From() — sip.HeaderParams is a Go map (header_params.go) and
// Address is a sip.Uri value carrying two MORE maps of its own (UriParams,
// Headers — uri.go), so that assignment aliased the dialog's OWN stored
// d.ok/d.invite headers two levels deep. Mutating the built request's Params
// or Address.UriParams after the fix must never reach the dialog's stored
// headers.
func TestBuildInDialogRequestClonesFromToInsteadOfAliasing(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))

	invFrom := &sip.FromHeader{
		Address: sip.Uri{User: "bob", Host: "peer", UriParams: sip.NewParams()},
		Params:  sip.NewParams(),
	}
	invFrom.Address.UriParams.Add("orig", "invite-from")
	invFrom.Params.Add("tag", "peer-tag")

	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader("call-alias")
	inv.AppendHeader(&cid)
	inv.AppendHeader(invFrom)
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})

	ok := sip.NewResponseFromRequest(inv, 200, "OK", nil)
	okTo := ok.To()
	okTo.Params.Add("tag", "our-tag")
	okTo.Address.UriParams = sip.NewParams()
	okTo.Address.UriParams.Add("orig", "ok-to")

	d := &dialog{id: "d1", direction: session.Inbound, phase: phaseAnswered, invite: inv, ok: ok, localCSeq: 1}

	req, _, err := u.buildInDialogRequest(d, sip.INFO)
	if err != nil {
		t.Fatalf("buildInDialogRequest: %v", err)
	}
	reqFrom, reqTo := req.From(), req.To()
	if reqFrom == nil || reqTo == nil {
		t.Fatal("built request carries no From/To")
	}

	// Mutate the BUILT request's own Params/Address.UriParams.
	reqFrom.Params.Add("mutated", "yes")
	reqFrom.Address.UriParams.Add("mutated", "yes")
	reqTo.Params.Add("mutated", "yes")
	reqTo.Address.UriParams.Add("mutated", "yes")

	if _, has := okTo.Params.Get("mutated"); has {
		t.Fatal("mutating the built request's To Params corrupted the dialog's stored d.ok.To().Params — Params was aliased, not cloned")
	}
	if _, has := okTo.Address.UriParams.Get("mutated"); has {
		t.Fatal("mutating the built request's To Address.UriParams corrupted d.ok.To().Address.UriParams — Address was aliased, not cloned")
	}
	if _, has := invFrom.Params.Get("mutated"); has {
		t.Fatal("mutating the built request's From Params corrupted the dialog's stored d.invite.From().Params — Params was aliased, not cloned")
	}
	if _, has := invFrom.Address.UriParams.Get("mutated"); has {
		t.Fatal("mutating the built request's From Address.UriParams corrupted d.invite.From().Address.UriParams — Address was aliased, not cloned")
	}
}

// TestBuildInDialogRequestNilInviteReturnsErrorWithoutBurningCSeq is B-M8's
// first regression: the nil check must come BEFORE d.localCSeq is
// incremented, or a failed build (no dialog to build from) silently burns a
// sequence number.
func TestBuildInDialogRequestNilInviteReturnsErrorWithoutBurningCSeq(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d := &dialog{id: "d1", phase: phaseAnswered, localCSeq: 5}

	if _, _, err := u.buildInDialogRequest(d, sip.INFO); err == nil {
		t.Fatal("buildInDialogRequest with a nil invite must return an error")
	}
	if d.localCSeq != 5 {
		t.Fatalf("d.localCSeq=%d want unchanged at 5 — a failed build must not burn a sequence number", d.localCSeq)
	}
}

// TestBuildInDialogRequestNilCSeqReturnsErrorNotTheHardcodedFallback is B-M8's
// second regression: BuildByeFromInvite always sets its own CSeq:2 as a
// placeholder (siptest/builders.go), and buildInDialogRequest used to leave
// that hardcoded value in place — silently — whenever ok.CSeq()/req.CSeq()
// came back nil, rather than reporting the unexpected state as an error. A
// CSeq-less invite (no CSeqHeader appended) makes both ok and inv carry no
// CSeq (sip.NewResponseFromRequest only copies a CSeq that exists).
func TestBuildInDialogRequestNilCSeqReturnsErrorNotTheHardcodedFallback(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))

	inv := sip.NewRequest(sip.INVITE, sip.Uri{User: "alice", Host: "here"})
	cid := sip.CallIDHeader("call-nocseq")
	inv.AppendHeader(&cid)
	inv.AppendHeader(&sip.FromHeader{Address: sip.Uri{User: "bob", Host: "peer"}, Params: sip.NewParams()})
	inv.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "alice", Host: "here"}, Params: sip.NewParams()})
	// Deliberately NO CSeqHeader appended.

	ok := sip.NewResponseFromRequest(inv, 200, "OK", nil)
	if ok.CSeq() != nil {
		t.Fatal("test setup invalid: NewResponseFromRequest must not have copied a CSeq that was never appended")
	}

	d := &dialog{id: "d1", direction: session.Inbound, phase: phaseAnswered, invite: inv, ok: ok, localCSeq: 1}

	req, _, err := u.buildInDialogRequest(d, sip.INFO)
	if err == nil {
		t.Fatalf("buildInDialogRequest with no CSeq on the answered INVITE must return an error, not "+
			"the vendored builder's hardcoded CSeq:2 fallback (got req=%+v)", req)
	}
}
