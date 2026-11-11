package sipua_test

// Lane D (cf5-d) Task 7 (CF-163, CF-164): a peer's re-INVITE or UPDATE offer is
// applied to the live session and answered (RFC 3261 14.2, RFC 3311 5.2). The
// peer is internal/testutil/peer answering our dial with an SDP naming test
// socket A; each test then re-offers. No test calls t.Parallel.

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

type reofferRig struct {
	p      *peer.Peer
	ua     *sipua.UA
	events func() []session.UAEvent
	a      *net.UDPConn
	aPort  int
	dlg    string
	ours   string // our offer, which describes our media for the whole call
}

// newReofferRig dials a peer whose answer names socket A and waits for our RTP
// to reach A. Codecs are PCMU and PCMA so a re-offer can switch.
func newReofferRig(t *testing.T) *reofferRig {
	t.Helper()
	a, aPort := laneDMediaSocket(t)
	return newReofferRigWith(t, a, aPort, laneDSDP(1, aPort), 0)
}

// newReofferRigWith is newReofferRig with a chosen peer answer (naming socket a)
// and the payload type our RTP is expected to start with.
func newReofferRigWith(t *testing.T, a *net.UDPConn, aPort int, answer string, wantPT int) *reofferRig {
	t.Helper()
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0",
		Behaviour: peer.Behaviour{AnswerSDP: peer.AnswerWithBody([]byte(answer))}})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU", "PCMA"}, "disabled")
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	if pt := rtpWithin(a, 2*time.Second); pt != wantPT {
		t.Fatalf("control: RTP payload type %d at the answer's port before the re-offer, want %d", pt, wantPT)
	}
	return &reofferRig{p: p, ua: ua, events: events, a: a, aPort: aPort, dlg: res.DialogID, ours: string(p.LastInviteBody())}
}

// reoffer sends a re-INVITE with body and returns the status and body of our
// final response to it.
func (r *reofferRig) reoffer(t *testing.T, body string) (int, string) {
	t.Helper()
	n := len(r.p.ResponseCodes())
	r.p.SendToCaller(t, sip.INVITE, laneDSDPHeader(), []byte(body))
	return r.finalAfter(t, n)
}

// finalAfter waits for a final response recorded after the first n responses.
func (r *reofferRig) finalAfter(t *testing.T, n int) (int, string) {
	t.Helper()
	st := 0
	if !stubWait(func() bool {
		codes := r.p.ResponseCodes()
		for i := n; i < len(codes); i++ {
			if codes[i] >= 200 {
				st = codes[i]
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no final response to the re-offer")
	}
	return st, string(r.p.LastFinalResponseBody())
}

func sdpField(sdp, prefix string) string {
	for _, l := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

var audioPortRE = regexp.MustCompile(`m=audio (\d+) `)

// quiet discards datagrams sock holds, then reports whether any arrives in d.
func quiet(sock *net.UDPConn, d time.Duration) bool {
	for drained := rtpWithin(sock, 30*time.Millisecond); drained != -1; drained = rtpWithin(sock, 30*time.Millisecond) {
		_ = drained
	}
	return rtpWithin(sock, d) == -1
}

func TestRFC3261_NEWD32_ReInviteOfferIsApplied(t *testing.T) {
	r := newReofferRig(t)
	b, bPort := laneDMediaSocket(t)
	st, body := r.reoffer(t, laneDSDP(2, bPort))
	if st != 200 {
		t.Fatalf("re-INVITE answered %d, want 200", st)
	}
	if pt := rtpWithin(b, time.Second); pt != 0 {
		t.Fatalf("RTP payload type %d at the re-offered port, want 0 within 1 s", pt)
	}
	if m := audioPortRE.FindStringSubmatch(body); m == nil || m[1] != audioPortRE.FindStringSubmatch(r.ours)[1] {
		t.Errorf("answer m=audio port is not our original port:\n%s", body)
	}
	want := strings.Fields(sdpField(r.ours, "o="))
	got := strings.Fields(sdpField(body, "o="))
	if len(want) < 3 || len(got) < 3 || got[1] != want[1] || got[2] != "2" {
		t.Errorf("answer o= %q, want our session id %q and version 2", got, want)
	}
}

func TestRFC3311_NEWD33_UpdateOfferIsAnswered(t *testing.T) {
	r := newReofferRig(t)
	b, bPort := laneDMediaSocket(t)
	n := len(r.p.ResponseCodes())
	r.p.SendToCaller(t, sip.UPDATE, laneDSDPHeader(), []byte(laneDSDP(2, bPort)))
	st, body := r.finalAfter(t, n)
	if st != 200 || !strings.Contains(body, "m=audio") {
		t.Fatalf("UPDATE offer answered %d with body %q, want 200 with an SDP answer", st, body)
	}
	if ct := r.p.LastResponseHeader("UPDATE", 200, "Content-Type"); ct != "application/sdp" {
		t.Errorf("Content-Type %q", ct)
	}
	if pt := rtpWithin(b, time.Second); pt != 0 {
		t.Errorf("RTP payload type %d at the offered port, want 0", pt)
	}
}

func TestReInviteCodecChangeIsApplied(t *testing.T) {
	r := newReofferRig(t)
	offer := strings.Replace(laneDSDP(2, r.aPort), "RTP/AVP 0 101", "RTP/AVP 8 101", 1)
	offer = strings.Replace(offer, "a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000", 1)
	st, body := r.reoffer(t, offer)
	if st != 200 || !strings.Contains(sdpField(body, "m=audio"), " 8") {
		t.Fatalf("PCMA re-offer: %d\n%s", st, body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rtpWithin(r.a, 100*time.Millisecond) == 8 {
			return
		}
	}
	t.Fatal("our RTP never switched to payload type 8")
}

func TestReInviteHoldAndResume(t *testing.T) {
	r := newReofferRig(t)
	st, body := r.reoffer(t, strings.Replace(laneDSDP(2, r.aPort), "a=sendrecv", "a=sendonly", 1))
	if st != 200 || !strings.Contains(body, "a=recvonly") {
		t.Fatalf("hold: %d\n%s", st, body)
	}
	if !quiet(r.a, 500*time.Millisecond) {
		t.Fatal("RTP of ours continued during hold")
	}
	st, _ = r.reoffer(t, laneDSDP(3, r.aPort))
	if st != 200 {
		t.Fatalf("resume answered %d", st)
	}
	if pt := rtpWithin(r.a, 2*time.Second); pt != 0 {
		t.Errorf("RTP did not resume after the resume re-offer (PT %d)", pt)
	}
}

func TestReInviteZeroConnectionAddress(t *testing.T) {
	r := newReofferRig(t)
	st, body := r.reoffer(t, strings.Replace(laneDSDP(2, r.aPort), "c=IN IP4 127.0.0.1", "c=IN IP4 0.0.0.0", 1))
	if st != 200 || !strings.Contains(body, "a=inactive") {
		t.Fatalf("0.0.0.0 re-offer: %d\n%s", st, body)
	}
	if !quiet(r.a, 500*time.Millisecond) {
		t.Fatal("RTP continued to an unspecified address")
	}
}

func TestReInviteAddedVideoStream(t *testing.T) {
	r := newReofferRig(t)
	offer := laneDSDP(2, r.aPort) + "m=video 15290 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
	st, body := r.reoffer(t, offer)
	if st != 200 || strings.Count(body, "m=") != 2 {
		t.Fatalf("audio+video re-offer: %d\n%s", st, body)
	}
	if !strings.Contains(body, "m=video 0 ") {
		t.Errorf("the video stream is not rejected with port 0:\n%s", body)
	}
	if pt := rtpWithin(r.a, time.Second); pt != 0 {
		t.Errorf("audio stopped (PT %d)", pt)
	}
}

func TestReInviteUnacceptableOfferDraws488(t *testing.T) {
	r := newReofferRig(t)
	unsupported := strings.Replace(strings.Replace(laneDSDP(2, r.aPort), "RTP/AVP 0 101", "RTP/AVP 111", 1), "a=rtpmap:0 PCMU/8000", "a=rtpmap:111 opus/48000/2", 1)
	unsupported = strings.Replace(unsupported, "a=rtpmap:101 telephone-event/8000\r\n", "", 1)
	if st, _ := r.reoffer(t, unsupported); st != 488 {
		t.Fatalf("codec 18 only answered %d, want 488", st)
	}
	if pt := rtpWithin(r.a, time.Second); pt != 0 {
		t.Errorf("RTP changed after a refused re-offer (PT %d)", pt)
	}
	st, body := r.reoffer(t, laneDSDP(3, r.aPort))
	if st != 200 {
		t.Fatalf("a later acceptable re-offer answered %d", st)
	}
	if f := strings.Fields(sdpField(body, "o=")); len(f) < 3 || f[2] != "2" {
		t.Errorf("the answer after a refusal has o= %q, want version 2 (the refusal consumed none)", f)
	}
}

func TestReInviteDTMFUsesTheRenumberedEventPT(t *testing.T) {
	r := newReofferRig(t)
	offer := strings.ReplaceAll(laneDSDP(2, r.aPort), "101", "96")
	if st, _ := r.reoffer(t, offer); st != 200 {
		t.Fatalf("renumbering re-offer answered %d", st)
	}
	go func() {
		_, _, _ = r.ua.SendDTMF(context.Background(), r.dlg, "5", session.DTMFModeRFC2833, 100, 50)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		switch rtpWithin(r.a, 100*time.Millisecond) {
		case 96:
			return
		case 101:
			t.Fatal("an event packet used the old PT 101")
		}
	}
	t.Fatal("no telephone-event packet with PT 96")
}

// I10: a re-offer that lands between startMediaLoop's build and its publish is
// not lost: the launched loop carries it, and the discarded one sent nothing.
func TestReOfferDuringMediaStartIsNotLost(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	a, aPort := laneDMediaSocket(t)
	b, bPort := laneDMediaSocket(t)
	const cid = "cf5d-ms@127.0.0.1"
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKcf5dMS", 1, "", "", laneDSDP(1, aPort)))
	in := waitFor(t, events, session.UAEventInbound, 0)
	hooked := false
	sipua.SetMediaLoopBuiltHook(func() {
		if hooked {
			return
		}
		hooked = true
		if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
			t.Error("the 200 never reached the caller")
			return
		}
		_, msgs := r.responses("INVITE")
		tag := ""
		for _, m := range msgs {
			if strings.HasPrefix(m, "SIP/2.0 200") {
				tag = tagOf(stubHeaders(m, "To")[0])
			}
		}
		r.send(r.request("INVITE", ruri, cid, "z9hG4bKcf5dMS2", 2, tag, "", laneDSDP(2, bPort)))
		if !stubWait(func() bool {
			_, ms := r.responses("INVITE")
			for _, m := range ms {
				if strings.HasPrefix(m, "SIP/2.0 200") && strings.HasPrefix(stubHeaders(m, "CSeq")[0], "2 ") {
					return true
				}
			}
			return false
		}, 3*time.Second) {
			codes, _ := r.responses("INVITE")
			t.Errorf("the mid-start re-INVITE drew no 200 (INVITE responses %v)", codes)
		}
	})
	t.Cleanup(func() { sipua.SetMediaLoopBuiltHook(nil) })
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	sipua.SetMediaLoopBuiltHook(nil)
	if pt := rtpWithin(b, 2*time.Second); pt != 0 {
		t.Fatalf("RTP payload type %d at the re-offered port, want 0", pt)
	}
	if !quiet(a, 300*time.Millisecond) {
		t.Error("RTP reached the old address after the re-offer")
	}
}
