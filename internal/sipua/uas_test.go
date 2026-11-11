package sipua_test

// Lane D (cf5-d) Task 1: UAS request screening (RFC 3261 8.2), OPTIONS (11)
// and the 405 with Allow (8.2.1). No test calls t.Parallel.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

const wantAllow = "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, UPDATE, NOTIFY"

// uasFinal sends msg and waits for a response with the given code to method.
func uasFinal(t *testing.T, r *rawUAC, method string, code int, msg string) string {
	t.Helper()
	r.send(msg)
	if !stubWait(func() bool { return r.hasCode(method, code) }, 3*time.Second) {
		codes, _ := r.responses(method)
		t.Fatalf("no %d to %s (got %v)", code, method, codes)
	}
	_, msgs := r.responses(method)
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 "+itoa(code)) {
			return m
		}
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }

// asText swaps the request's Content-Type for text/plain.
func asText(m string) string {
	return strings.Replace(m, "Content-Type: application/sdp", "Content-Type: text/plain", 1)
}

// toNobody addresses the request's To header to a user this UA does not own.
func toNobody(m string) string {
	return strings.Replace(m, "To: <sip:alice@example>", "To: <sip:nobody@example>", 1)
}

func noInbound(t *testing.T, events func() []session.UAEvent) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if n := countInbound(events()); n != 0 {
		t.Errorf("%d inbound events, want 0 (a refused request must not reach the handler)", n)
	}
}

func TestRFC3261_NEWA26_TelRequestURIDraws416(t *testing.T) {
	_, events, r, _ := uasUA(t)
	uasFinal(t, r, "INVITE", 416, r.invite("tel:+81012345678", "cf5d-tel@127.0.0.1", "z9hG4bKcf5dTEL", 1, ""))
	noInbound(t, events)
}

func TestScreenAcceptsSipsAndUpperCaseScheme(t *testing.T) {
	ua, events, r, _ := uasUA(t)
	r.send(r.invite("SIP:alice@"+ua.BoundAddr().String(), "cf5d-sch@127.0.0.1", "z9hG4bKcf5dSCH", 1, ""))
	waitFor(t, events, session.UAEventInbound, 0)
	if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 2*time.Second) {
		t.Fatal("no 180 for the upper-case scheme")
	}
}

func TestScreenSchemeIsCheckedBeforeTarget(t *testing.T) {
	_, _, r, _ := uasUA(t)
	uasFinal(t, r, "INVITE", 416, r.invite("tel:+1", "cf5d-sbt@127.0.0.1", "z9hG4bKcf5dSBT", 1, ""))
	if r.hasCode("INVITE", 404) {
		t.Error("404 sent: the scheme check must come first")
	}
}

func TestScreenUnknownTargetStillDraws404(t *testing.T) {
	ua, events, r, _ := uasUA(t)
	uasFinal(t, r, "INVITE", 404, toNobody(r.invite("sip:nobody@"+ua.BoundAddr().String(), "cf5d-404@127.0.0.1", "z9hG4bKcf5d404", 1, "")))
	noInbound(t, events)
}

func TestRFC3261_NEWA29_UnknownRequireDraws420(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	m := uasFinal(t, r, "INVITE", 420, r.invite(ruri, "cf5d-req@127.0.0.1", "z9hG4bKcf5dREQ", 1, "Require: rfcsweep-a-unknown\r\n"))
	if u := stubHeaders(m, "Unsupported"); len(u) != 1 || u[0] != "rfcsweep-a-unknown" {
		t.Errorf("Unsupported = %q, want rfcsweep-a-unknown", u)
	}
	noInbound(t, events)
}

func TestScreenRequireTimerIsUnderstood(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	r.send(r.invite(ruri, "cf5d-rt@127.0.0.1", "z9hG4bKcf5dRT", 1, "Require: Timer\r\nSupported: timer\r\nSession-Expires: 1800\r\n"))
	waitFor(t, events, session.UAEventInbound, 0)
	if !stubWait(func() bool { return r.hasCode("INVITE", 180) }, 2*time.Second) {
		t.Fatal("no 180")
	}
}

func TestScreenRequireListsOnlyUnknownTags(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	m := uasFinal(t, r, "INVITE", 420, r.invite(ruri, "cf5d-rl@127.0.0.1", "z9hG4bKcf5dRL", 1, "Require: timer, foo\r\nRequire: bar\r\n"))
	if u := stubHeaders(m, "Unsupported"); len(u) != 1 || u[0] != "foo, bar" {
		t.Errorf("Unsupported = %q, want \"foo, bar\"", u)
	}
}

func TestScreenRequireOnInDialogRequests(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5d-rid@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	for i, m := range []string{"BYE", "INFO", "UPDATE", "NOTIFY", "OPTIONS"} {
		before, _ := r.responses(m)
		r.send(r.request(m, ruri, cid, "z9hG4bKcf5dRID"+m, 20+i, tag, "Require: x-unknown\r\n", ""))
		if !stubWait(func() bool { c, _ := r.responses(m); return len(c) > len(before) }, 2*time.Second) {
			t.Fatalf("no response to %s", m)
		}
		if !r.hasCode(m, 420) {
			c, _ := r.responses(m)
			t.Errorf("%s with Require x-unknown answered %v, want 420", m, c)
		}
	}
	for _, e := range events() {
		if e.Kind == session.UAEventDialogEnded {
			t.Fatal("the refused BYE ended the call")
		}
	}
	uasFinal(t, r, "INFO", 200, r.request("INFO", ruri, cid, "z9hG4bKcf5dRIDok", 30, tag, "", ""))
}

func TestRFC3261_NEWD15_TextPlainBodyDraws415(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	m := uasFinal(t, r, "INVITE", 415, asText(r.invite(ruri, "cf5d-ct@127.0.0.1", "z9hG4bKcf5dCT", 1, "")))
	if a := stubHeaders(m, "Accept"); len(a) != 1 || a[0] != "application/sdp" {
		t.Errorf("Accept = %q", a)
	}
	noInbound(t, events)
}

func TestRFC3261_NEWD16_GzipLabelledBodyDraws415(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	m := uasFinal(t, r, "INVITE", 415, r.invite(ruri, "cf5d-ce@127.0.0.1", "z9hG4bKcf5dCE", 1, "Content-Encoding: gzip\r\n"))
	if a := stubHeaders(m, "Accept-Encoding"); len(a) != 1 || a[0] != "identity" {
		t.Errorf("Accept-Encoding = %q", a)
	}
	noInbound(t, events)
}

func TestScreenCompactContentEncodingDraws415(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	uasFinal(t, r, "INVITE", 415, r.invite(ruri, "cf5d-ceh@127.0.0.1", "z9hG4bKcf5dCEH", 1, "e: gzip\r\n"))
}

func TestScreenSdpWithParamsAndIdentityIsAccepted(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	msg := r.invite(ruri, "cf5d-ok@127.0.0.1", "z9hG4bKcf5dOK", 1, "Content-Encoding: identity\r\n")
	msg = strings.Replace(msg, "Content-Type: application/sdp", "Content-Type: Application/SDP;charset=utf-8", 1)
	r.send(msg)
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
}

func TestScreenBodyWithoutContentTypeDraws415(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	msg := r.invite(ruri, "cf5d-nct@127.0.0.1", "z9hG4bKcf5dNCT", 1, "")
	msg = strings.Replace(msg, "Content-Type: application/sdp\r\n", "", 1)
	m := uasFinal(t, r, "INVITE", 415, msg)
	if a := stubHeaders(m, "Accept"); len(a) != 1 || a[0] != "application/sdp" {
		t.Errorf("Accept = %q", a)
	}
}

func TestScreenOptionalNonSdpBodyIsIgnored(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	msg := r.invite(ruri, "cf5d-opt@127.0.0.1", "z9hG4bKcf5dOPT", 1, "Content-Disposition: render;handling=optional\r\n")
	msg = strings.Replace(msg, "Content-Type: application/sdp", "Content-Type: text/plain", 1)
	r.send(msg)
	in := waitFor(t, events, session.UAEventInbound, 0)
	if len(in.OfferedCodecs) != 0 {
		t.Errorf("OfferedCodecs = %v, want none", in.OfferedCodecs)
	}
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	ok := uasFinal(t, r, "INVITE", 200, "")
	if !strings.Contains(ok, "m=audio") {
		t.Errorf("200 carries no offer of ours:\n%s", ok)
	}
}

// RFC 3261 20.11: an application/sdp body whose Content-Disposition is not
// "session" is not a session offer. Optional: ignored (offerless INVITE).
// Required (the default handling) : 415. "session" and an absent header: offer.
func TestScreenSdpWithUnknownDisposition(t *testing.T) {
	t.Run("required draws 415", func(t *testing.T) {
		_, _, r, ruri := uasUA(t)
		m := uasFinal(t, r, "INVITE", 415, r.invite(ruri, "cf5d-dr@127.0.0.1", "z9hG4bKcf5dDR", 1, "Content-Disposition: render\r\n"))
		if got := stubHeaders(m, "Accept"); len(got) != 1 || got[0] != "application/sdp" {
			t.Errorf("Accept = %q", got)
		}
	})
	t.Run("explicit handling=required draws 415", func(t *testing.T) {
		_, _, r, ruri := uasUA(t)
		uasFinal(t, r, "INVITE", 415, r.invite(ruri, "cf5d-dq@127.0.0.1", "z9hG4bKcf5dDQ", 1, "Content-Disposition: icon;handling=required\r\n"))
	})
	t.Run("optional is ignored", func(t *testing.T) {
		ua, events, r, ruri := uasUA(t)
		r.send(r.invite(ruri, "cf5d-do@127.0.0.1", "z9hG4bKcf5dDO", 1, "Content-Disposition: render;handling=optional\r\n"))
		in := waitFor(t, events, session.UAEventInbound, 0)
		if len(in.OfferedCodecs) != 0 {
			t.Errorf("OfferedCodecs = %v, want none (the body was ignored)", in.OfferedCodecs)
		}
		if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		uasFinal(t, r, "INVITE", 200, "")
	})
	t.Run("session is the offer", func(t *testing.T) {
		_, events, r, ruri := uasUA(t)
		r.send(r.invite(ruri, "cf5d-ds@127.0.0.1", "z9hG4bKcf5dDS", 1, "Content-Disposition: session\r\n"))
		in := waitFor(t, events, session.UAEventInbound, 0)
		if len(in.OfferedCodecs) == 0 {
			t.Error("a session disposition lost the offer")
		}
	})
}

func TestScreenInDialogBodiesDraw415(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5d-idb@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	uasFinal(t, r, "INVITE", 415, asText(r.request("INVITE", ruri, cid, "z9hG4bKcf5dIDB1", 21, tag, "", stubSDP)))
	uasFinal(t, r, "UPDATE", 415, r.request("UPDATE", ruri, cid, "z9hG4bKcf5dIDB2", 22, tag, "Content-Encoding: gzip\r\n", stubSDP))
	uasFinal(t, r, "INFO", 200, r.request("INFO", ruri, cid, "z9hG4bKcf5dIDB3", 23, tag, "", ""))
}

func TestRFC3261_NEWA4_AllowListsNotify(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	ok := answered(t, ua, events, r, ruri, "cf5d-allow@127.0.0.1", 1)
	if a := stubHeaders(ok, "Allow"); len(a) != 1 || a[0] != wantAllow {
		t.Errorf("Allow = %q, want %q", a, wantAllow)
	}
}

func TestRFC3261_NEWA24_UnsupportedMethod405HasAllow(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	m := uasFinal(t, r, "SUBSCRIBE", 405, r.request("SUBSCRIBE", ruri, "cf5d-sub@127.0.0.1", "z9hG4bKcf5dSUB", 1, "", "Event: presence\r\n", ""))
	if a := stubHeaders(m, "Allow"); len(a) != 1 || a[0] != wantAllow {
		t.Errorf("Allow = %q, want %q", a, wantAllow)
	}
}

func TestNoRouteAnswersAnyUnhandledMethod405WithAllow(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	for _, meth := range []string{"MESSAGE", "FOO"} {
		m := uasFinal(t, r, meth, 405, r.request(meth, ruri, "cf5d-nr"+meth+"@127.0.0.1", "z9hG4bKcf5dNR"+meth, 1, "", "", ""))
		if a := stubHeaders(m, "Allow"); len(a) != 1 || a[0] != wantAllow {
			t.Errorf("%s: Allow = %q", meth, a)
		}
	}
}

func checkOptions200(t *testing.T, m string) {
	t.Helper()
	for h, want := range map[string]string{"Allow": wantAllow, "Accept": "application/sdp", "Accept-Encoding": "identity",
		"Accept-Language": "en", "Supported": "timer", "Content-Length": "0"} {
		if v := stubHeaders(m, h); len(v) != 1 || v[0] != want {
			t.Errorf("%s = %q, want %q", h, v, want)
		}
	}
}

func TestRFC3261_NEWA25_OptionsIsAnswered200(t *testing.T) {
	_, events, r, ruri := uasUA(t)
	m := uasFinal(t, r, "OPTIONS", 200, r.request("OPTIONS", ruri, "cf5d-opt200@127.0.0.1", "z9hG4bKcf5dO200", 1, "", "Accept: application/sdp\r\n", ""))
	checkOptions200(t, m)
	noInbound(t, events)
	for _, e := range events() {
		t.Errorf("OPTIONS produced a UA event %v", e.Kind)
	}
}

func TestOptionsToAnotherUserDraws404(t *testing.T) {
	ua, _, r, _ := uasUA(t)
	uasFinal(t, r, "OPTIONS", 404, toNobody(r.request("OPTIONS", "sip:nobody@"+ua.BoundAddr().String(), "cf5d-o404@127.0.0.1", "z9hG4bKcf5dO404", 1, "", "", "")))
}

func TestOptionsWithTelURIDraws416(t *testing.T) {
	_, _, r, _ := uasUA(t)
	uasFinal(t, r, "OPTIONS", 416, r.request("OPTIONS", "tel:+1", "cf5d-o416@127.0.0.1", "z9hG4bKcf5dO416", 1, "", "", ""))
}

func TestInDialogOptionsIsAnswered200(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf5d-ido@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	m := uasFinal(t, r, "OPTIONS", 200, r.request("OPTIONS", ruri, cid, "z9hG4bKcf5dIDO", 21, tag, "", ""))
	checkOptions200(t, m)
}

// D-3 (owner amendment): a busy UA answers OPTIONS with the status an INVITE
// would get, through a probe that admits nothing.
func TestOptionsOnABusyUAGetsTheInviteStatus(t *testing.T) {
	for _, tc := range []struct {
		name         string
		verdict      session.Admission
		wantCode     int
		wantReason   string
		wantProbeSet bool
	}{
		{"busy", session.AdmitReject(486, "Busy Here"), 486, "Busy Here", true},
		{"shutdown", session.AdmitReject(503, "Service Unavailable"), 503, "Service Unavailable", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ua, events, r, ruri := uasUA(t)
			var probes, calls int
			var mu = make(chan struct{}, 1)
			mu <- struct{}{}
			ua.OnAdmit(context.Background(), func(_ context.Context, ev session.UAEvent) session.Admission {
				<-mu
				defer func() { mu <- struct{}{} }()
				if ev.AdmitProbe {
					probes++
					return tc.verdict
				}
				calls++
				return session.AdmitAccept()
			})
			m := uasFinal(t, r, "OPTIONS", tc.wantCode, r.request("OPTIONS", ruri, "cf5d-obusy"+tc.name+"@127.0.0.1", "z9hG4bKcf5dOB"+tc.name, 1, "", "", ""))
			if !strings.HasPrefix(m, "SIP/2.0 "+itoa(tc.wantCode)+" "+tc.wantReason) {
				t.Errorf("status line: %q", strings.SplitN(m, "\r\n", 2)[0])
			}
			<-mu
			defer func() { mu <- struct{}{} }()
			if probes != 1 || calls != 0 {
				t.Errorf("probes=%d admissions=%d, want 1 and 0", probes, calls)
			}
			if len(events()) != 0 {
				t.Errorf("events recorded: %v", events())
			}
		})
	}
}

var _ = sipua.Config{}
