package sipua_test

// CF-186 (Lane B Task 5): an unchanged re-offer is answered from the live
// negotiated Session when our previous SDP was an offer (RFC 3264 8).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// TestUnchangedReOfferOnAnOutboundDialogIsAnsweredFromTheLiveSession replaces
// TestReInviteUnchangedOriginIsANoOp: the 200 is a valid answer, not our original
// offer (which listed codecs the peer's SDP lacks).
func TestUnchangedReOfferOnAnOutboundDialogIsAnsweredFromTheLiveSession(t *testing.T) {
	r := newReofferRig(t)
	st, body := r.reoffer(t, laneDSDP(1, r.aPort)) // the peer's own SDP again, same o=
	if st != 200 {
		t.Fatalf("unchanged re-offer: %d", st)
	}
	if body == r.ours {
		t.Fatalf("the 200 is our original offer, not an answer:\n%s", body)
	}
	if n := strings.Count(body, "m=audio"); n != 1 {
		t.Fatalf("%d m=audio lines, want 1:\n%s", n, body)
	}
	if f := strings.Fields(sdpField(body, "m=audio")); len(f) != 5 || f[3] != "0" || f[4] != "101" {
		t.Errorf("m=audio %q, want the live codec 0 and event PT 101 only", f)
	}
	want := strings.Fields(sdpField(r.ours, "o="))
	got := strings.Fields(sdpField(body, "o="))
	if len(got) < 3 || got[1] != want[1] || got[2] != "2" {
		t.Errorf("answer o= %q, want our session id %q and version 2", got, want)
	}
	if strings.Contains(body, "a=crypto") {
		t.Error("the answer carries a key the peer never accepted")
	}
	if pt := rtpWithin(r.a, time.Second); pt != 0 {
		t.Errorf("RTP stopped at A after an unchanged re-offer (PT %d)", pt)
	}
}

// The live codec is listed first, so a no-op re-offer never switches codec.
func TestUnchangedReOfferKeepsTheLiveCodec(t *testing.T) {
	a, aPort := laneDMediaSocket(t)
	answer := strings.Replace(laneDSDP(1, aPort), "RTP/AVP 0 101", "RTP/AVP 8 0 101", 1)
	answer = strings.Replace(answer, "a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000", 1)
	r := newReofferRigWith(t, a, aPort, answer, 8)
	st, body := r.reoffer(t, answer)
	if st != 200 {
		t.Fatalf("unchanged re-offer: %d", st)
	}
	if f := strings.Fields(sdpField(body, "m=audio")); len(f) < 4 || f[3] != "8" {
		t.Fatalf("m=audio %q, want the live codec 8 first\n%s", f, body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rtpWithin(a, 200*time.Millisecond) == 8 {
			return
		}
	}
	t.Fatal("RTP is no longer PT 8 after the unchanged re-offer")
}

// An inbound dialog whose INVITE had no offer sent its own offer in the 200; the
// caller then answered PCMA in the ACK. An unchanged re-offer is answered from the
// settled session, not with our offer (0 8 101).
func TestUnchangedReOfferOnAnOfferlessInboundDialogAnswersTheSettledCodec(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf186-offerless@127.0.0.1"
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKcf186I", 1, "", "", ""))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	_, tag := toTagOfResponse(t, r, "INVITE", 200)
	pcma := strings.Replace(laneDSDP(1, 40000), "RTP/AVP 0 101", "RTP/AVP 8 101", 1)
	pcma = strings.Replace(pcma, "a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000", 1)
	r.send(r.request("ACK", ruri, cid, "z9hG4bKcf186A", 1, tag, "", pcma))
	time.Sleep(300 * time.Millisecond)
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKcf186R", 2, tag, "", pcma))
	if !stubWait(func() bool { return countCode(r, "INVITE", 200) == 2 }, 3*time.Second) {
		t.Fatal("no 200 to the re-INVITE")
	}
	_, msgs := r.responses("INVITE")
	body := msgs[len(msgs)-1][strings.Index(msgs[len(msgs)-1], "\r\n\r\n")+4:]
	f := strings.Fields(sdpField(body, "m=audio"))
	if len(f) != 5 || f[3] != "8" || f[4] != "101" {
		t.Fatalf("m=audio %q, want 8 and 101 only\n%s", f, body)
	}
}
