package sipua_test

// CF-170: srtp "optional" offers SDES and falls back to plain RTP; an RTP/SAVP
// offer is answered RTP/SAVP; a per-call srtp tightens the UA's policy.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// srtpPair places a call from caller to callee, answers it and returns both
// dialog ids once the caller has seen the 200.
func srtpPair(t *testing.T, callerSRTP, calleeSRTP string) (caller, callee *sipua.UA, callerDlg, calleeDlg string) {
	t.Helper()
	caller, _ = newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, callerSRTP)
	callee, _ = newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, calleeSRTP)
	cEvents, eEvents := collect(t, caller), collect(t, callee)
	res, err := caller.Dial(context.Background(), session.DialRequest{ToURI: "sip:alice@" + callee.BoundAddr().String()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	in := waitFor(t, eEvents, session.UAEventInbound, 0)
	if err := callee.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitFor(t, cEvents, session.UAEventFinal, 200)
	return caller, callee, res.DialogID, in.DialogID
}

func packetsReceived(u *sipua.UA, dlg string) int64 {
	q, _ := u.QualityView(dlg)
	return q.PacketsReceived
}

func TestOptionalUAsNegotiateSRTP(t *testing.T) {
	caller, callee, cd, ed := srtpPair(t, "optional", "optional")
	waitForCond(t, func() bool {
		mv1, _ := caller.MediaView(cd)
		mv2, _ := callee.MediaView(ed)
		return mv1.SRTP && mv2.SRTP
	})
	waitForCond(t, func() bool { return packetsReceived(caller, cd) > 0 && packetsReceived(callee, ed) > 0 })
	if q, _ := caller.QualityView(cd); q.SRTPAuthFailures != 0 {
		t.Fatalf("srtp auth failures: %d", q.SRTPAuthFailures)
	}
}

func TestOptionalOffererFallsBackToPlainAgainstADisabledAnswerer(t *testing.T) {
	caller, callee, cd, ed := srtpPair(t, "optional", "disabled")
	waitForCond(t, func() bool { return packetsReceived(caller, cd) > 0 && packetsReceived(callee, ed) > 0 })
	for _, x := range []struct {
		u   *sipua.UA
		dlg string
	}{{caller, cd}, {callee, ed}} {
		if mv, _ := x.u.MediaView(x.dlg); mv.SRTP {
			t.Fatal("SRTP reported on a call that fell back to plain RTP")
		}
	}
	// The optional UA's INVITE carries a key (the offer shape).
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	u, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "optional")
	if _, err := u.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()}); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, func() bool { return len(p.LastInviteBody()) > 0 })
	body := string(p.LastInviteBody())
	if !strings.Contains(body, "a=crypto:") || !strings.Contains(body, "RTP/AVP") {
		t.Fatalf("optional INVITE body:\n%s", body)
	}
}

func TestMediaViewReportsSRTPOnlyWhenBothKeysExist(t *testing.T) {
	caller, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "optional")
	callee, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "optional")
	cEvents, eEvents := collect(t, caller), collect(t, callee)
	res, err := caller.Dial(context.Background(), session.DialRequest{ToURI: "sip:alice@" + callee.BoundAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	in := waitFor(t, eEvents, session.UAEventInbound, 0)
	if mv, ok := caller.MediaView(res.DialogID); !ok || mv.SRTP {
		t.Fatalf("before the answer: MediaView %+v ok=%v, want SRTP false (our key only)", mv, ok)
	}
	if err := callee.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, cEvents, session.UAEventFinal, 200)
	waitForCond(t, func() bool { mv, _ := caller.MediaView(res.DialogID); return mv.SRTP })
}

func TestDisabledAnswererRefusesAnSAVPOffer(t *testing.T) {
	caller, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
	callee, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	cEvents, eEvents := collect(t, caller), collect(t, callee)
	if _, err := caller.Dial(context.Background(), session.DialRequest{ToURI: "sip:alice@" + callee.BoundAddr().String()}); err != nil {
		t.Fatal(err)
	}
	in := waitFor(t, eEvents, session.UAEventInbound, 0)
	err := callee.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID})
	var ae *apierr.Error
	if !asAPIErr(err, &ae) || !strings.Contains(err.Error(), "srtp_offered_but_disabled") && !strings.Contains(detailKind(ae), "srtp_offered_but_disabled") {
		t.Fatalf("Answer err = %v, want media_negotiation srtp_offered_but_disabled", err)
	}
	waitFor(t, cEvents, session.UAEventFinal, 488)
}

func detailKind(ae *apierr.Error) string {
	if k, ok := ae.Detail["kind"].(string); ok {
		return k
	}
	return ""
}

func TestPerCallSRTPOverrideReachesTheOffer(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	u, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	if _, err := u.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr(), SRTP: "required"}); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, func() bool { return len(p.LastInviteBody()) > 0 })
	body := string(p.LastInviteBody())
	if !strings.Contains(body, "RTP/SAVP") || !strings.Contains(body, "a=crypto:") {
		t.Fatalf("per-call srtp=required INVITE body:\n%s", body)
	}
}

func TestPerCallSRTPOverrideReachesTheAnswer(t *testing.T) {
	plainOffer := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	_, crypto, err := media.GenerateCryptoAttr()
	if err != nil {
		t.Fatal(err)
	}
	savpOffer := strings.Replace(plainOffer, "RTP/AVP", "RTP/SAVP", 1) + crypto + "\r\n"

	t.Run("plain offer refused", func(t *testing.T) {
		ua, events, r, ruri := optionalUAS(t)
		r.send(r.request("INVITE", ruri, "cf170a@127.0.0.1", "z9hG4bKcf170a", 1, "", "", plainOffer))
		in := waitFor(t, events, session.UAEventInbound, 0)
		if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID, SRTP: "required"}); err == nil {
			t.Fatal("Answer must fail for srtp=required against an RTP/AVP offer")
		}
		if !stubWait(func() bool { return r.hasCode("INVITE", 488) }, 3*time.Second) {
			t.Fatal("no 488")
		}
	})
	t.Run("savp offer answered savp with the tightened policy", func(t *testing.T) {
		ua, events, r, ruri := optionalUAS(t)
		r.send(r.request("INVITE", ruri, "cf170b@127.0.0.1", "z9hG4bKcf170b", 1, "", "", savpOffer))
		in := waitFor(t, events, session.UAEventInbound, 0)
		if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID, SRTP: "required"}); err != nil {
			t.Fatal(err)
		}
		code, msg := laneDWaitFinal(t, r)
		if code != 200 || !strings.Contains(msg, "RTP/SAVP") {
			t.Fatalf("answer %d:\n%s", code, msg)
		}
		if s := sipua.MediaSessionForTest(ua, in.DialogID); s == nil || s.SRTPPolicy() != media.SRTPRequired {
			t.Fatalf("session policy = %v, want required", s)
		}
	})
	t.Run("offerless invite", func(t *testing.T) {
		ua, events, r, ruri := optionalUAS(t)
		r.send(r.request("INVITE", ruri, "cf170c@127.0.0.1", "z9hG4bKcf170c", 1, "", "", ""))
		in := waitFor(t, events, session.UAEventInbound, 0)
		if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID, SRTP: "required"}); err != nil {
			t.Fatal(err)
		}
		code, msg := laneDWaitFinal(t, r)
		if code != 200 || !strings.Contains(msg, "RTP/SAVP") {
			t.Fatalf("offer %d:\n%s", code, msg)
		}
	})
}

// optionalUAS is a UA with srtp optional plus its event collector and raw caller.
func optionalUAS(t *testing.T) (*sipua.UA, func() []session.UAEvent, *rawUAC, string) {
	t.Helper()
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "optional")
	return ua, collect(t, ua), newRawUAC(t, ua), "sip:alice@" + ua.BoundAddr().String()
}
