package sipua_test

// CF-109/110/122/169: the in-dialog send seam's outcome rules (indialog.go,
// sendInDialog): 481/408/no response end the dialog locally, a 401/407 is
// answered once with credentials, and a re-INVITE's 2xx is re-ACKed. Raw stub
// from rfc3261_pin_uac_test.go; internal peer where it can script the case.

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// assertDialogEnded waits for the single dialog-ended event and checks its
// transport_failure detail.
func assertDialogEnded(t *testing.T, events func() []session.UAEvent, cause, method string) {
	t.Helper()
	ev := waitFor(t, events, session.UAEventDialogEnded, 0)
	if ev.Cause != session.UACauseTransportFailure || ev.Detail["kind"] != "transport_failure" ||
		ev.Detail["cause"] != cause || ev.Detail["method"] != method {
		t.Errorf("dialog-ended event cause=%v detail=%v, want transport_failure/%s/%s", ev.Cause, ev.Detail, cause, method)
	}
	time.Sleep(100 * time.Millisecond)
	if n := countKind(events(), session.UAEventDialogEnded); n != 1 {
		t.Errorf("%d dialog-ended events, want exactly 1", n)
	}
}

func assertHangupNotFound(t *testing.T, ua *sipua.UA, id string) {
	t.Helper()
	err := ua.Hangup(context.Background(), id, "")
	if err == nil || apierr.CodeOf(err) != apierr.CodeNotFound {
		t.Errorf("Hangup after the dialog ended = %v, want not_found", err)
	}
}

func stubSawNoBye(t *testing.T, s *uacStub) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if n := len(s.requests("BYE")); n != 0 {
		t.Errorf("the stub saw %d BYE(s), want none (the dialog is released locally)", n)
	}
}

// TestRFC3261_NEWB2_DialogEndsAfter481ToRefer is NEW-B-2 / CF-109, fixed (RFC
// 3261 12.2.1.2). Was the RFC3261 pin NEWB2_DialogKeptAfter481ToRefer.
func TestRFC3261_NEWB2_DialogEndsAfter481ToRefer(t *testing.T) {
	s := referStub(t, func(s *uacStub, raw string, from net.Addr) {
		s.send(from, stubResponse(raw, 481, "Call/Transaction Does Not Exist", "", nil, ""))
	})
	ua := newStubUA(t)
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	if out := blindTransfer(t, ua, id); out.Accepted || out.StatusCode != 481 {
		t.Fatalf("result=%+v, want a 481 refusal", out)
	}
	assertHangupNotFound(t, ua, id) // immediately: the claim precedes Transfer's return
	assertDialogEnded(t, events, "in_dialog_481", "REFER")
	stubSawNoBye(t, s)
}

// TestRFC3261_NEWB3_DialogEndsWhenReferDrawsNoResponse is NEW-B-3 / CF-110,
// fixed. Was the RFC3261 pin NEWB3_DialogKeptWhenReferDrawsNoResponse.
func TestRFC3261_NEWB3_DialogEndsWhenReferDrawsNoResponse(t *testing.T) {
	s := referStub(t, nil)
	ua := newStubUA(t)
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	if out := blindTransfer(t, ua, id); out.Accepted || out.StatusCode != 0 || out.Reason != "REFER drew no final response" {
		t.Fatalf("result=%+v, want the no-response result", out)
	}
	assertHangupNotFound(t, ua, id)
	assertDialogEnded(t, events, "in_dialog_timeout", "REFER")
	stubSawNoBye(t, s)
}

// TestRFC3261_ReobsCF109_InfoRejected481EndsDialog is CF-109 on the DTMF INFO
// path, fixed. Was ..._InfoRejected481KeepsDialog.
func TestRFC3261_ReobsCF109_InfoRejected481EndsDialog(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RejectInfoStatus: 481}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if _, _, err := ua.SendDTMF(context.Background(), res.DialogID, "5", session.DTMFModeInfo, 100, 0); err == nil {
		t.Fatal("SendDTMF in INFO mode succeeded against a 481")
	}
	assertHangupNotFound(t, ua, res.DialogID)
	assertDialogEnded(t, events, "in_dialog_481", "INFO")
	time.Sleep(300 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Errorf("peer saw %d BYE(s), want none", n)
	}
}

// TestRFC3261_ReobsCF110_InfoTimeoutEndsDialog is CF-110 on the DTMF INFO path,
// fixed. Was ..._InfoTimeoutKeepsDialog. The stub drops every INFO; the UA's 2 s
// test Timeout stands for Timer F.
func TestRFC3261_ReobsCF110_InfoTimeoutEndsDialog(t *testing.T) {
	s := startUACStub(t, answer200())
	ua := newStubUA(t)
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	if _, _, err := ua.SendDTMF(context.Background(), id, "5", session.DTMFModeInfo, 100, 0); err == nil {
		t.Fatal("SendDTMF in INFO mode succeeded against a stub that drops INFO")
	}
	assertHangupNotFound(t, ua, id)
	assertDialogEnded(t, events, "in_dialog_timeout", "INFO")
	stubSawNoBye(t, s)
}

// TestRFC3261_ReobsCF109_RefreshRejected481EndsDialog is CF-109 on the session
// refresh path, fixed. Was ..._RefreshRejected481KeepsDialog.
func TestRFC3261_ReobsCF109_RefreshRejected481EndsDialog(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{
			AnswerSessionExpires: "90;refresher=uac",
			AnswerAllow:          "INVITE, ACK, BYE, CANCEL, UPDATE",
			RejectUpdateStatus:   481,
		},
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 90, 90)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // our UPDATE refresh, answered 481
	waitForCond(t, func() bool { return p.Count("UPDATE") >= 1 })
	assertDialogEnded(t, events, "in_dialog_481", "UPDATE")
	assertHangupNotFound(t, ua, res.DialogID)
	time.Sleep(300 * time.Millisecond)
	if n := p.ByeCount(); n != 0 {
		t.Errorf("peer saw %d BYE(s), want none", n)
	}
}

// TestInDialog408EndsTheDialog: an INFO answered 408 ends the dialog.
func TestInDialog408EndsTheDialog(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RejectInfoStatus: 408}})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	_, _, _ = ua.SendDTMF(context.Background(), res.DialogID, "5", session.DTMFModeInfo, 100, 0)
	assertDialogEnded(t, events, "in_dialog_408", "INFO")
	assertHangupNotFound(t, ua, res.DialogID)
}

// TestInDialogOtherRejectionKeepsTheDialog guards S13: 486 and 500 to an INFO
// keep the dialog.
func TestInDialogOtherRejectionKeepsTheDialog(t *testing.T) {
	for _, code := range []int{486, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{RejectInfoStatus: code}})
			ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
			events := collect(t, ua)
			res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
			if err != nil {
				t.Fatal(err)
			}
			waitFor(t, events, session.UAEventFinal, 200)
			_, _, _ = ua.SendDTMF(context.Background(), res.DialogID, "5", session.DTMFModeInfo, 100, 0)
			if err := ua.Hangup(context.Background(), res.DialogID, ""); err != nil {
				t.Fatalf("Hangup after a %d to the INFO: %v", code, err)
			}
			waitForCond(t, func() bool { return p.ByeCount() == 1 })
		})
	}
}

// TestByeDrawing481EndsWithOneTerminalEvent guards S10: a BYE answered 481
// causes no in-dialog teardown of its own (startUACStub answers every BYE 200
// itself, so this uses a small stub of its own).
func TestByeDrawing481EndsWithOneTerminalEvent(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			raw := string(buf[:n])
			switch stubMethod(raw) {
			case "INVITE":
				_, _ = pc.WriteTo([]byte(stubResponse(raw, 200, "OK", "stubtag",
					[]string{"Contact: <sip:stub@" + pc.LocalAddr().String() + ">"}, stubSDP)), from)
			case "BYE":
				_, _ = pc.WriteTo([]byte(stubResponse(raw, 481, "Call/Transaction Does Not Exist", "", nil, "")), from)
			}
		}
	}()
	ua := newStubUA(t)
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + pc.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if err := ua.Hangup(context.Background(), res.DialogID, ""); err == nil {
		t.Fatal("Hangup succeeded against a BYE answered 481")
	}
	time.Sleep(300 * time.Millisecond)
	if n := countKind(events(), session.UAEventDialogEnded); n > 1 {
		t.Errorf("%d dialog-ended events, want at most one", n)
	}
	for _, e := range events() {
		if e.Kind == session.UAEventDialogEnded && e.Detail["cause"] == "in_dialog_481" {
			t.Errorf("a BYE answered 481 raised the in-dialog teardown: %+v", e)
		}
	}
}

// ---- CF-122: a 401/407 to an in-dialog request is answered once with credentials ----

// bareStub is a raw UDP peer that, unlike startUACStub, hands EVERY datagram
// (BYE included) to onMsg. It is created answering INVITE with a 200.
func bareStub(t *testing.T, onMsg func(s *uacStub, raw string, from net.Addr)) *uacStub {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &uacStub{pc: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			raw := string(buf[:n])
			s.mu.Lock()
			s.got = append(s.got, raw)
			s.mu.Unlock()
			if stubMethod(raw) == "INVITE" {
				answer200()(s, raw, from)
				continue
			}
			onMsg(s, raw, from)
		}
	}()
	return s
}

const digestChallenge = `Digest realm="cf5c",nonce="fedcba9876543210fedcba9876543210",qop="auth",algorithm=MD5`

func challenge(s *uacStub, raw string, from net.Addr, code int) {
	hdr := "WWW-Authenticate"
	reason := "Unauthorized"
	if code == 407 {
		hdr, reason = "Proxy-Authenticate", "Proxy Authentication Required"
	}
	s.send(from, stubResponse(raw, code, reason, "", []string{hdr + ": " + digestChallenge}, ""))
}

// authUA is a direct UA with an account. anyHost false pins credentials to the
// AOR host, which a loopback stub is not.
func authUA(t *testing.T, anyHost bool, user string) *sipua.UA {
	t.Helper()
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: fakeclock.New(time.Unix(0, 0)), LocalAddr: "127.0.0.1:0",
		AuthUser: user, AuthPass: map[bool]string{true: "s3cr3t", false: ""}[user != ""], AuthAnyHost: anyHost,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = collect(t, ua)
	return ua
}

func infoStub(t *testing.T, code int) *uacStub {
	return startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			answer200()(s, raw, from)
		case "INFO":
			challenge(s, raw, from, code)
		}
	})
}

// TestInDialogDigestRetryIsSentOnce: every INFO is answered 401: exactly 2
// INFOs (the original and one credentialed retry), the retry's CSeq is +1.
func TestInDialogDigestRetryIsSentOnce(t *testing.T) {
	s := infoStub(t, 401)
	ua := authUA(t, true, "alice")
	id := dialStub(t, ua, s)
	_, _, err := ua.SendDTMF(context.Background(), id, "5", session.DTMFModeInfo, 100, 0)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("SendDTMF err = %v, want one naming 401", err)
	}
	infos := s.requests("INFO")
	if len(infos) != 2 {
		t.Fatalf("%d INFOs, want 2", len(infos))
	}
	if len(stubHeaders(infos[0], "Authorization")) != 0 || len(stubHeaders(infos[1], "Authorization")) != 1 {
		t.Errorf("Authorization on the original %v / retry %v", stubHeaders(infos[0], "Authorization"), stubHeaders(infos[1], "Authorization"))
	}
	if stubCSeq(infos[1]) != stubCSeq(infos[0])+1 {
		t.Errorf("retry CSeq %d, want %d", stubCSeq(infos[1]), stubCSeq(infos[0])+1)
	}
}

func TestInDialogDigest407UsesProxyAuthorization(t *testing.T) {
	s := infoStub(t, 407)
	ua := authUA(t, true, "alice")
	id := dialStub(t, ua, s)
	_, _, _ = ua.SendDTMF(context.Background(), id, "5", session.DTMFModeInfo, 100, 0)
	infos := s.requests("INFO")
	if len(infos) != 2 {
		t.Fatalf("%d INFOs, want 2", len(infos))
	}
	if len(stubHeaders(infos[1], "Proxy-Authorization")) != 1 || len(stubHeaders(infos[1], "Authorization")) != 0 {
		t.Errorf("retry Proxy-Authorization %v Authorization %v", stubHeaders(infos[1], "Proxy-Authorization"), stubHeaders(infos[1], "Authorization"))
	}
}

// TestInDialogDigestWithheldForAForeignHost: the next hop (127.0.0.1) is not the
// AOR host (example) and AuthAnyHost is off: no credentials leave (CF-046).
func TestInDialogDigestWithheldForAForeignHost(t *testing.T) {
	s := infoStub(t, 401)
	ua := authUA(t, false, "alice")
	id := dialStub(t, ua, s)
	_, _, _ = ua.SendDTMF(context.Background(), id, "5", session.DTMFModeInfo, 100, 0)
	infos := s.requests("INFO")
	if len(infos) != 1 {
		t.Fatalf("%d INFOs, want exactly 1", len(infos))
	}
	if h := stubHeaders(infos[0], "Authorization"); len(h) != 0 {
		t.Errorf("credentials sent to a foreign host: %v", h)
	}
}

func TestInDialogDigestWithoutCredentials(t *testing.T) {
	s := infoStub(t, 401)
	ua := authUA(t, true, "")
	id := dialStub(t, ua, s)
	_, _, _ = ua.SendDTMF(context.Background(), id, "5", session.DTMFModeInfo, 100, 0)
	if n := len(s.requests("INFO")); n != 1 {
		t.Fatalf("%d INFOs, want exactly 1", n)
	}
}

// TestByeDigestRetry: the first BYE is answered 401, the second (CSeq + 1, with
// Authorization) 200, and Hangup returns nil.
func TestByeDigestRetry(t *testing.T) {
	s := bareStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "BYE" {
			return
		}
		if len(stubHeaders(raw, "Authorization")) == 0 {
			challenge(s, raw, from, 401)
			return
		}
		s.send(from, stubResponse(raw, 200, "OK", "", nil, ""))
	})
	ua := authUA(t, true, "alice")
	id := dialStub(t, ua, s)
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup: %v", err)
	}
	byes := s.requests("BYE")
	if len(byes) != 2 || stubCSeq(byes[1]) != stubCSeq(byes[0])+1 || len(stubHeaders(byes[1], "Authorization")) != 1 {
		t.Fatalf("BYEs %d, CSeqs %v", len(byes), []int{stubCSeq(byes[0]), stubCSeq(byes[len(byes)-1])})
	}
}

// TestReferDigestRetryRoutesTheNotifyById: REFER 401, retry 202, then a final
// NOTIFY carrying the retried REFER's wire CSeq as its Event id settles the
// transfer with that NOTIFY's status.
func TestReferDigestRetryRoutesTheNotifyById(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			answer200()(s, raw, from)
		case "REFER":
			if len(stubHeaders(raw, "Authorization")) == 0 {
				challenge(s, raw, from, 401)
				return
			}
			s.send(from, stubResponse(raw, 202, "Accepted", "", []string{"Contact: <sip:stub@" + s.addr() + ">"}, ""))
		}
	})
	ua := authUA(t, true, "alice")
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	if out := blindTransfer(t, ua, id); !out.Accepted {
		t.Fatalf("Transfer: %+v", out)
	}
	refers := s.requests("REFER")
	if len(refers) != 2 {
		t.Fatalf("%d REFERs, want 2", len(refers))
	}
	stubNotifyEvent(t, s, s.requests("INVITE")[0], 50, fmt.Sprintf("refer;id=%d", stubCSeq(refers[1])),
		"SIP/2.0 200 OK", "terminated;reason=noresource")
	ev := waitFor(t, events, session.UAEventTransfer, 0)
	if ev.Detail["final"] != true || ev.Detail["status_code"] != 200 {
		t.Errorf("transfer event detail: %+v, want final with status_code 200", ev.Detail)
	}
	if !stubWait(func() bool { return stubResponseCode(s, "50 NOTIFY") == 200 }, 3*time.Second) {
		t.Fatal("the NOTIFY was not answered 200")
	}
}

// TestChallengedInDialogRequestThatThenDrawsNoResponseEndsTheDialog (S3a).
func TestChallengedInDialogRequestThatThenDrawsNoResponseEndsTheDialog(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			answer200()(s, raw, from)
		case "INFO":
			if len(stubHeaders(raw, "Authorization")) == 0 {
				challenge(s, raw, from, 401)
			}
		}
	})
	ua := authUA(t, true, "alice")
	events := collect(t, ua)
	id := dialStub(t, ua, s)
	_, _, _ = ua.SendDTMF(context.Background(), id, "5", session.DTMFModeInfo, 100, 0)
	assertDialogEnded(t, events, "in_dialog_timeout", "INFO")
}

// TestRFC4028_NEWC10_RefreshRetryAfter401CarriesCredentials is NEW-C-10 / CF-122,
// fixed: the 401 to our UPDATE refresh is answered at once (sendInDialog's
// retry, not the refresher's backoff) with credentials, CSeq + 1. Was
// the old RFC4028 pin NEWC10_RefreshRetryAfter401CarriesNoCredentials.
func TestRFC4028_NEWC10_RefreshRetryAfter401CarriesCredentials(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		switch stubMethod(raw) {
		case "INVITE":
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{
				"Contact: <sip:stub@" + s.addr() + ">",
				"Allow: INVITE, ACK, BYE, CANCEL, UPDATE",
				"Supported: timer", "Require: timer", "Session-Expires: 90;refresher=uac",
			}, stubSDP))
		case "UPDATE":
			if len(stubHeaders(raw, "Authorization")) == 0 {
				s.send(from, stubResponse(raw, 401, "Unauthorized", "", []string{
					`WWW-Authenticate: Digest realm="rfcsweep-c",nonce="0123456789abcdef0123456789abcdef",qop="auth",algorithm=MD5`,
				}, ""))
				return
			}
			s.send(from, stubResponse(raw, 200, "OK", "", []string{"Session-Expires: 90;refresher=uac"}, ""))
		}
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp", Mode: "direct", AOR: "sip:alice@example", ExpiresS: 300,
		Timeout: 2 * time.Second, InboundRingTimeout: 2 * time.Second,
		Clock: clk, LocalAddr: "127.0.0.1:0",
		AuthUser: "alice", AuthPass: "s3cr3t", AuthAnyHost: true,
		SessionExpiresS: 90, MinSES: 90,
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	_ = collect(t, ua)
	dialStub(t, ua, s)

	clk.BlockUntil(1)
	clk.Advance(46 * time.Second) // our refresh at interval/2; NO further clock advance
	if !stubWait(func() bool { return len(s.requests("UPDATE")) >= 2 }, 3*time.Second) {
		t.Fatalf("%d UPDATEs, want the refresh and its credentialed retry", len(s.requests("UPDATE")))
	}
	ups := s.requests("UPDATE")
	a := stubHeaders(ups[1], "Authorization")
	if len(a) != 1 || !strings.Contains(a[0], `username="alice"`) || !strings.Contains(a[0], `realm="rfcsweep-c"`) ||
		!strings.Contains(a[0], `uri="`+stubRequestURI(ups[1])+`"`) {
		t.Errorf("retry Authorization = %v", a)
	}
	if stubCSeq(ups[1]) != stubCSeq(ups[0])+1 {
		t.Errorf("retry CSeq %d, want %d", stubCSeq(ups[1]), stubCSeq(ups[0])+1)
	}
}

// ---- CF-169: a re-INVITE's retransmitted 2xx is re-ACKed ----

func reInviteStub(t *testing.T, extra ...string) *uacStub {
	return startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if tag := stubHeaders(raw, "To")[0]; !strings.Contains(tag, "tag=") { // initial INVITE
			hdr := append([]string{"Contact: <sip:stub@" + s.addr() + ">", "Allow: INVITE, ACK, BYE, CANCEL",
				"Session-Expires: 90;refresher=uac", "Require: timer"}, extra...)
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", hdr, stubSDP))
			return
		}
		res := stubResponse(raw, 200, "OK", "", []string{"Contact: <sip:stub@" + s.addr() + ">", "Session-Expires: 90;refresher=uac"}, stubSDP)
		s.send(from, res)
		s.send(from, res) // a retransmitted 2xx
	})
}

func TestReInviteRetransmittedTwoxxIsReAcked(t *testing.T) {
	s := reInviteStub(t)
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	dialStub(t, ua, s)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	if !stubWait(func() bool { return len(s.requests("INVITE")) >= 2 }, 3*time.Second) {
		t.Fatal("no re-INVITE refresh")
	}
	re := s.requests("INVITE")[1]
	if !stubWait(func() bool { return len(withCSeq(s.requests("ACK"), stubCSeq(re))) >= 2 }, 3*time.Second) {
		t.Fatalf("%d ACK(s) for the re-INVITE, want 2 (one per 2xx)", len(withCSeq(s.requests("ACK"), stubCSeq(re))))
	}
	acks := withCSeq(s.requests("ACK"), stubCSeq(re))
	if !sameAck(acks[0], acks[1]) {
		t.Errorf("the re-sent ACK differs:\n%s\n---\n%s", acks[0], acks[1])
	}
}

func TestReInviteAckFollowsTheRouteSet(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		rr := []string{"Record-Route: <sip:" + s.addr() + ";lr;rr=1>", "Record-Route: <sip:" + s.addr() + ";lr;rr=2>"}
		hdr := append([]string{"Contact: <sip:stub@" + s.addr() + ">", "Allow: INVITE, ACK, BYE, CANCEL",
			"Session-Expires: 90;refresher=uac", "Require: timer"}, rr...)
		tag := ""
		if !strings.Contains(stubHeaders(raw, "To")[0], "tag=") {
			tag = "stubtag"
		}
		s.send(from, stubResponse(raw, 200, "OK", tag, hdr, stubSDP))
	})
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	dialStub(t, ua, s)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	if !stubWait(func() bool { return len(s.requests("INVITE")) >= 2 }, 3*time.Second) {
		t.Fatal("no re-INVITE refresh")
	}
	re := s.requests("INVITE")[1]
	if !stubWait(func() bool { return len(withCSeq(s.requests("ACK"), stubCSeq(re))) >= 1 }, 3*time.Second) {
		t.Fatal("no ACK for the re-INVITE")
	}
	for name, raw := range map[string]string{"re-INVITE": re, "ACK": withCSeq(s.requests("ACK"), stubCSeq(re))[0]} {
		r := stubHeaders(raw, "Route")
		if len(r) != 2 || !strings.Contains(r[0], "rr=2") || !strings.Contains(r[1], "rr=1") {
			t.Errorf("%s Route = %v, want rr=2 then rr=1", name, r)
		}
	}
}

// absorberCount is the number of goroutines inside absorbInvite2xx.
func absorberCount() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	cnt := 0
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "absorbInvite2xx") {
			cnt++
		}
	}
	return cnt
}

// TestReInviteAbsorberExitsOnUAClose: the re-INVITE's own absorber (one more
// than the initial INVITE's) is running after its 2xx and is gone after Close.
func TestReInviteAbsorberExitsOnUAClose(t *testing.T) {
	s := reInviteStub(t)
	clk := fakeclock.New(time.Unix(0, 0))
	ua, _ := newSessionTimerUA(t, clk, 1800, 60)
	dialStub(t, ua, s)
	clk.BlockUntil(1)
	clk.Advance(46 * time.Second)
	if !stubWait(func() bool { return len(s.requests("INVITE")) >= 2 && len(s.requests("ACK")) >= 2 }, 3*time.Second) {
		t.Fatal("no re-INVITE refresh and ACK")
	}
	if !stubWait(func() bool { return absorberCount() >= 2 }, 2*time.Second) {
		t.Fatalf("%d absorber(s) after the re-INVITE's 2xx, want the initial INVITE's and the re-INVITE's", absorberCount())
	}
	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !stubWait(func() bool { return absorberCount() == 0 }, 2*time.Second) {
		t.Fatalf("%d absorbInvite2xx goroutine(s) still running 2 s after UA.Close", absorberCount())
	}
}

// TestCancelledInDialogRequestKeepsTheDialog (S11): an INFO whose context is
// cancelled while the peer withholds its response learned nothing about the
// dialog, so it is kept: Hangup still sends its BYE.
func TestCancelledInDialogRequestKeepsTheDialog(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			answer200()(s, raw, from)
		} // an INFO is never answered
	})
	ua := authUA(t, true, "")
	id := dialStub(t, ua, s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = ua.SendDTMF(ctx, id, "5", session.DTMFModeInfo, 100, 0)
	}()
	if !stubWait(func() bool { return len(s.requests("INFO")) > 0 }, 3*time.Second) {
		t.Fatal("the INFO never reached the stub")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SendDTMF did not return after its context was cancelled")
	}
	if err := ua.Hangup(context.Background(), id, ""); err != nil {
		t.Fatalf("Hangup after a cancelled INFO: %v (the dialog was ended)", err)
	}
	if n := len(s.requests("BYE")); n != 1 {
		t.Fatalf("%d BYE(s), want 1", n)
	}
}
