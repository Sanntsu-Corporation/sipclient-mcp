package sipua_test

// CF-207 / CF-165 (Lane B Task 7): the 2xx to an offerless re-INVITE carries a
// fresh offer, our offer is outstanding until its ACK, and the answer in that ACK
// is applied to the live media session (RFC 3261 14.2, 13.2.2.4; RFC 3264 4).
// No test calls t.Parallel.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// pcmaAnswer is the caller's answer in the ACK: PCMA at the given port.
func pcmaAnswer(version, port int) string {
	s := strings.Replace(laneDSDP(version, port), "RTP/AVP 0 101", "RTP/AVP 8 101", 1)
	return strings.Replace(s, "a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000", 1)
}

// offeredDialog is an answered, ACKed inbound dialog whose INVITE offered laneDSDP
// naming the media socket A.
type offeredDialog struct {
	ua     *sipua.UA
	events func() []session.UAEvent
	r      *rawUAC
	ruri   string
	cid    string
	tag    string
	a      *net.UDPConn
	aPort  int
}

func newOfferedDialog(t *testing.T, cid string) *offeredDialog {
	t.Helper()
	ua, events, r, ruri := uasUA(t)
	answerBye(t, r)
	a, aPort := laneDMediaSocket(t)
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKcf207I", 10, "", "", laneDSDP(1, aPort)))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { return r.hasCode("INVITE", 200) }, 3*time.Second) {
		t.Fatal("no 200")
	}
	_, tag := toTagOfResponse(t, r, "INVITE", 200)
	r.send(r.request("ACK", ruri, cid, "z9hG4bKcf207IA", 10, tag, "", ""))
	if pt := rtpWithin(a, 2*time.Second); pt != 0 {
		t.Fatalf("control: RTP payload type %d at A, want 0", pt)
	}
	return &offeredDialog{ua: ua, events: events, r: r, ruri: ruri, cid: cid, tag: tag, a: a, aPort: aPort}
}

// offerlessReInvite sends an offerless re-INVITE and returns the body of our 200.
func (g *offeredDialog) offerlessReInvite(t *testing.T, cseq int, branch string) string {
	t.Helper()
	g.r.send(g.r.request("INVITE", g.ruri, g.cid, branch, cseq, g.tag, "", ""))
	var body string
	if !stubWait(func() bool {
		_, msgs := g.r.responses("INVITE")
		for _, m := range msgs {
			if strings.HasPrefix(m, "SIP/2.0 200") && strings.HasPrefix(stubHeaders(m, "CSeq")[0], strconv.Itoa(cseq)+" ") {
				_, body, _ = strings.Cut(m, "\r\n\r\n")
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no 200 to the offerless re-INVITE")
	}
	return body
}

func (g *offeredDialog) ack(cseq int, branch, body string) {
	g.r.send(g.r.request("ACK", g.ruri, g.cid, branch, cseq, g.tag, "", body))
}

func (g *offeredDialog) ended() bool {
	for _, e := range g.events() {
		if e.Kind == session.UAEventDialogEnded {
			return true
		}
	}
	return false
}

func audioCodecs(body string) []string {
	for _, l := range strings.Split(body, "\r\n") {
		if strings.HasPrefix(l, "m=audio ") {
			f := strings.Fields(l)
			return f[3:]
		}
	}
	return nil
}

func TestRFC3261_CF207_AckAnswerToOurReOfferIsApplied(t *testing.T) {
	g := newOfferedDialog(t, "cf207-ack@127.0.0.1")
	body := g.offerlessReInvite(t, 11, "z9hG4bKcf207R")
	if got := audioCodecs(body); len(got) != 3 || got[0] != "0" || got[1] != "8" || got[2] != "101" {
		t.Fatalf("our offer lists %v, want 0 8 101\n%s", got, body)
	}
	b, bPort := laneDMediaSocket(t)
	g.ack(11, "z9hG4bKcf207RA", pcmaAnswer(2, bPort))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rtpWithin(b, 100*time.Millisecond) == 8 {
			if !quiet(g.a, 500*time.Millisecond) {
				t.Error("RTP still reaches A after the ACK's answer moved the stream to B")
			}
			return
		}
	}
	t.Fatal("our RTP never reached B with PT 8 after the ACK's answer")
}

// The flipped NEWD34 pin (CF-165): the offer lists more than one codec and keeps
// our session id with the version incremented.
func TestRFC3261_NEWD34_OfferlessReInviteGetsAFreshOffer(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "rfcsweepd-nosdp@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	r.send(r.request("INVITE", ruri, cid, "z9hG4bKrfcsweepdR11", 11, tag, "", ""))
	var body string
	if !stubWait(func() bool {
		_, msgs := r.responses("INVITE")
		for _, m := range msgs {
			if strings.HasPrefix(m, "SIP/2.0 200") && strings.HasPrefix(stubHeaders(m, "CSeq")[0], "11 ") {
				_, body, _ = strings.Cut(m, "\r\n\r\n")
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no 200 to the offerless re-INVITE")
	}
	codecs := 0
	for _, pt := range audioCodecs(body) {
		if pt != "101" {
			codecs++
		}
	}
	if codecs < 2 {
		t.Fatalf("the offer in the 200 lists %d audio codecs, want at least 2:\n%s", codecs, body)
	}
	_, msgs := r.responses("INVITE")
	ours := ""
	for _, m := range msgs {
		if strings.HasPrefix(m, "SIP/2.0 200") && strings.HasPrefix(stubHeaders(m, "CSeq")[0], "10 ") {
			_, ours, _ = strings.Cut(m, "\r\n\r\n")
		}
	}
	was, now := strings.Fields(sdpField(ours, "o=")), strings.Fields(sdpField(body, "o="))
	if len(was) < 3 || len(now) < 3 || was[1] != now[1] || now[2] != "2" {
		t.Errorf("o= %q after %q: want the same session id and version 2", now, was)
	}
}

func TestPeerUpdateOfferWhileOurReOfferIsOutstandingDraws491(t *testing.T) {
	g := newOfferedDialog(t, "cf207-upd491@127.0.0.1")
	g.offerlessReInvite(t, 11, "z9hG4bKcf207U")
	first491(t, g, "UPDATE", 12)
	b, bPort := laneDMediaSocket(t)
	_ = b
	g.ack(11, "z9hG4bKcf207UA", pcmaAnswer(2, bPort))
	time.Sleep(200 * time.Millisecond)
	g.r.send(g.r.request("UPDATE", g.ruri, g.cid, "z9hG4bKcf207UX", 20, g.tag, "", laneDSDP(3, g.aPort)))
	if !stubWait(func() bool { c, _ := g.r.responses("UPDATE"); return len(c) >= 2 }, 2*time.Second) {
		t.Fatal("no answer to the UPDATE after the ACK")
	}
	codes, _ := g.r.responses("UPDATE")
	if codes[len(codes)-1] != 200 {
		t.Errorf("UPDATE after the ACK drew %v, want 200", codes)
	}
}

func TestPeerReInviteWhileOurReOfferIsOutstandingDraws491(t *testing.T) {
	g := newOfferedDialog(t, "cf207-inv491@127.0.0.1")
	g.offerlessReInvite(t, 11, "z9hG4bKcf207V")
	first491(t, g, "INVITE", 12)
}

// first491 sends the peer's offer-carrying request until the first answer that is
// not the legal 500 of the instant before our offer is marked outstanding (B-D13),
// and requires that answer to be 491.
func first491(t *testing.T, g *offeredDialog, method string, cseq int) {
	t.Helper()
	for i := 0; i < 5; i++ {
		before, _ := g.r.responses(method)
		g.r.send(g.r.request(method, g.ruri, g.cid, "z9hG4bKcf207X"+method+strconv.Itoa(i), cseq+i, g.tag, "", laneDSDP(3, g.aPort)))
		n := len(before) + 1
		// an INVITE draws provisionals too: wait for a final answer
		if !stubWait(func() bool {
			codes, _ := g.r.responses(method)
			return len(codes) >= n && codes[len(codes)-1] >= 200
		}, 2*time.Second) {
			t.Fatal("no final answer to the peer's offer")
		}
		codes, _ := g.r.responses(method)
		last := codes[len(codes)-1]
		if last == 500 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if last != 491 {
			t.Fatalf("%s with an offer while our offer is outstanding drew %d, want 491 (answers %v)", method, last, codes)
		}
		return
	}
	t.Fatal("still 500 after 5 attempts")
}

func TestPeerOfferBetweenTheReAnswerSectionsDraws491(t *testing.T) {
	g := newOfferedDialog(t, "cf207-sect@127.0.0.1")
	g.offerlessReInvite(t, 11, "z9hG4bKcf207S")
	b, bPort := laneDMediaSocket(t)
	_ = b
	var got atomic.Int32
	restore := sipua.SetReAnswerParsedHook(func() {
		g.r.send(g.r.request("UPDATE", g.ruri, g.cid, "z9hG4bKcf207SU", 30, g.tag, "", laneDSDP(3, g.aPort)))
		if stubWait(func() bool { c, _ := g.r.responses("UPDATE"); return len(c) >= 1 }, 2*time.Second) {
			c, _ := g.r.responses("UPDATE")
			got.Store(int32(c[0]))
		}
	})
	defer restore()
	g.ack(11, "z9hG4bKcf207SA", pcmaAnswer(2, bPort))
	if !stubWait(func() bool { return got.Load() != 0 }, 4*time.Second) {
		t.Fatal("the hook never saw an answer")
	}
	if got.Load() != 491 {
		t.Errorf("a peer offer between the re-answer sections drew %d, want 491", got.Load())
	}
}

func TestUnusableAckAnswerToOurReOfferEndsTheCall(t *testing.T) {
	for name, body := range map[string]string{
		"no body":     "",
		"unoffered":   strings.Replace(laneDSDP(2, 40000), "RTP/AVP 0 101", "RTP/AVP 18 101", 1),
		"unparseable": "this is not sdp\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			g := newOfferedDialog(t, "cf207-bad-"+strings.ReplaceAll(name, " ", "")+"@127.0.0.1")
			g.offerlessReInvite(t, 11, "z9hG4bKcf207B")
			g.ack(11, "z9hG4bKcf207BA", body)
			if !stubWait(func() bool { return rawGotRequest(g.r, "BYE") }, 3*time.Second) {
				t.Fatal("no BYE after an unusable ACK answer")
			}
			g.r.mu.Lock()
			var bye string
			for _, m := range g.r.got {
				if stubMethod(m) == "BYE" {
					bye = m
					break
				}
			}
			g.r.mu.Unlock()
			if r := stubHeaders(bye, "Reason"); len(r) != 1 || !strings.Contains(r[0], "cause=488") {
				t.Errorf("BYE Reason %v, want SIP;cause=488", r)
			}
			if !stubWait(g.ended, 2*time.Second) {
				t.Fatal("no dialog_ended event")
			}
			for _, e := range g.events() {
				if e.Kind == session.UAEventDialogEnded && e.Cause != session.UACauseMediaNegotiationFailed {
					t.Errorf("dialog_ended cause %q, want media_negotiation_failed", e.Cause)
				}
			}
		})
	}
}

func TestUnchangedReOfferAfterOurReOfferIsAnsweredFromTheLiveSession(t *testing.T) {
	g := newOfferedDialog(t, "cf207-unch@127.0.0.1")
	g.offerlessReInvite(t, 11, "z9hG4bKcf207N")
	_, bPort := laneDMediaSocket(t)
	answer := pcmaAnswer(2, bPort)
	g.ack(11, "z9hG4bKcf207NA", answer)
	time.Sleep(300 * time.Millisecond)
	g.r.send(g.r.request("INVITE", g.ruri, g.cid, "z9hG4bKcf207NR", 12, g.tag, "", answer))
	var body string
	if !stubWait(func() bool {
		_, msgs := g.r.responses("INVITE")
		for _, m := range msgs {
			if strings.HasPrefix(m, "SIP/2.0 200") && strings.HasPrefix(stubHeaders(m, "CSeq")[0], "12 ") {
				_, body, _ = strings.Cut(m, "\r\n\r\n")
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no 200 to the unchanged re-INVITE")
	}
	if got := audioCodecs(body); len(got) != 2 || got[0] != "8" || got[1] != "101" {
		t.Errorf("answer lists %v, want 8 101 only\n%s", got, body)
	}
}

// Outbound dialog: the stub sends an offerless re-INVITE and ACKs our offer with B.
func TestAckAnswerToOurReOfferOnAnOutboundDialog(t *testing.T) {
	t.Cleanup(sipua.SetAck2xxT1(time.Hour))
	a, aPort := laneDMediaSocket(t)
	b, bPort := laneDMediaSocket(t)
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) == "INVITE" {
			s.send(from, stubResponse(raw, 200, "OK", "stubtag", []string{"Contact: <sip:stub@" + s.addr() + ">"}, laneDSDP(1, aPort)))
		}
	})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU", "PCMA"}, "disabled")
	_ = collect(t, ua)
	dialStub(t, ua, s)
	if pt := rtpWithin(a, 2*time.Second); pt != 0 {
		t.Fatalf("control: RTP payload type %d at A", pt)
	}
	inv := s.requests("INVITE")[0]
	dst, _ := net.ResolveUDPAddr("udp", ua.BoundAddr().String())
	hdrs := "Via: SIP/2.0/UDP " + s.addr() + ";branch=z9hG4bKcf207O\r\n" +
		"From: <sip:bob@" + s.addr() + ">;tag=stubtag\r\nTo: " + stubHeaders(inv, "From")[0] + "\r\n" +
		"Call-ID: " + stubHeaders(inv, "Call-ID")[0] + "\r\n"
	s.send(dst, "INVITE sip:alice@"+ua.BoundAddr().String()+" SIP/2.0\r\n"+hdrs+"CSeq: 7 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:stub@"+s.addr()+">\r\nContent-Length: 0\r\n\r\n")
	var ok string
	if !stubWait(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, m := range s.got {
			if strings.HasPrefix(m, "SIP/2.0 200") && strings.Contains(m, "CSeq: 7 INVITE") {
				ok = m
				return true
			}
		}
		return false
	}, 3*time.Second) {
		t.Fatal("no 200 with an offer to the offerless re-INVITE")
	}
	_, offer, _ := strings.Cut(ok, "\r\n\r\n")
	if len(audioCodecs(offer)) < 3 {
		t.Fatalf("our offer lists %v", audioCodecs(offer))
	}
	ans := pcmaAnswer(2, bPort)
	s.send(dst, "ACK sip:alice@"+ua.BoundAddr().String()+" SIP/2.0\r\nVia: SIP/2.0/UDP "+s.addr()+";branch=z9hG4bKcf207OA\r\n"+
		"From: <sip:bob@"+s.addr()+">;tag=stubtag\r\nTo: "+stubHeaders(inv, "From")[0]+"\r\nCall-ID: "+stubHeaders(inv, "Call-ID")[0]+
		"\r\nCSeq: 7 ACK\r\nMax-Forwards: 70\r\nContent-Type: application/sdp\r\nContent-Length: "+strconv.Itoa(len(ans))+"\r\n\r\n"+ans)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rtpWithin(b, 100*time.Millisecond) == 8 {
			return
		}
	}
	t.Fatal("our RTP never reached B with PT 8")
}
