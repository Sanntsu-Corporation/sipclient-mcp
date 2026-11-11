package sipua_test

// Lane D (rfc-sweep-d) pins for media-loop deviations seen as the answerer of a
// crafted offer (6a D11). A test-owned UDP socket is the offer's media port and
// reads our RTP. Each pin passes today and must be inverted when its finding is
// fixed. No t.Parallel.

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtp"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// laneDAnswered dials the UA with an offer built around the socket's port,
// answers it, and returns the UA, the dialog and a channel of every RTP packet
// that reaches the socket. Offer lines: the session part, then mAndAttrs(port).
func laneDAnswered(t *testing.T, connLine, sessionExtra, mAndAttrs string) (*sipua.UA, string, chan *rtp.Packet) {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("media socket: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	port := strconv.Itoa(sock.LocalAddr().(*net.UDPAddr).Port)
	offer := "v=0\r\no=probe 1 1 IN IP4 127.0.0.1\r\ns=-\r\n" + connLine + "\r\n" + sessionExtra + "t=0 0\r\n" +
		strings.ReplaceAll(mAndAttrs, "PORT", port)
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)
	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(), []byte(offer))
	in := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)
	pkts := make(chan *rtp.Packet, 256)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, rerr := sock.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			pkt := &rtp.Packet{}
			if pkt.Unmarshal(buf[:n]) == nil {
				pkts <- pkt
			}
		}
	}()
	return ua, in.DialogID, pkts
}

// nextRTP returns the next packet of payload type pt, failing after 2 s.
func nextRTP(t *testing.T, pkts chan *rtp.Packet, pt uint8) *rtp.Packet {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case p := <-pkts:
			if p.PayloadType == pt {
				return p
			}
		case <-deadline:
			t.Fatalf("no RTP packet of PT %d reached the offer's media socket", pt)
		}
	}
}

const laneDAudio = "m=audio PORT RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n"

// TestRFC3264Pin_NEWD8_PtimeOfOfferIsIgnored pins NEW-D-8 (L7, D-ANS-29, RFC
// 3264 6.1: "When sending media, it SHOULD use a packetization interval equal to
// the value of the ptime attribute in the offer, if any was present."
// rfc3264.txt:608-610). Evidence: evidence/s-ptime/rtp.txt (offer a=ptime:30;
// every timestamp step of ours is 160, a 20 ms interval). Locus:
// internal/sipua/medialoop.go:runTX (fixed 20 ms tick) and
// internal/media/sdp.go:parseSDP (reads no ptime).
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-8 is fixed.
func TestRFC3264Pin_NEWD8_PtimeOfOfferIsIgnored(t *testing.T) {
	_, _, pkts := laneDAnswered(t, "c=IN IP4 127.0.0.1", "", laneDAudio+"a=ptime:30\r\n")
	a := nextRTP(t, pkts, 0)
	b := nextRTP(t, pkts, 0)
	if step := b.Timestamp - a.Timestamp; step != 160 {
		t.Fatalf("timestamp step %d: NEW-D-8 is fixed, invert this pin (240 is a 30 ms interval)", step)
	}
}

// TestRFC3264Pin_NEWD9_BandwidthOfOfferIsIgnored pins NEW-D-9 (L8, D-ANS-30,
// RFC 3264 6.1: "It SHOULD send media using a bandwidth no higher than the value
// of the bandwidth attribute in the offer, if any was present." rfc3264.txt:
// 610-612). Evidence: evidence/s-ptime/rtp.txt (offer b=AS:16; our payload is
// 160 bytes per 20 ms, 64 kbit/s). Locus: internal/media/sdp.go:parseSDP
// (reads no b= line) and medialoop.go:runTX.
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-9 is fixed.
func TestRFC3264Pin_NEWD9_BandwidthOfOfferIsIgnored(t *testing.T) {
	_, _, pkts := laneDAnswered(t, "c=IN IP4 127.0.0.1", "b=AS:16\r\n", laneDAudio)
	a := nextRTP(t, pkts, 0)
	b := nextRTP(t, pkts, 0)
	if len(a.Payload) != 160 || b.Timestamp-a.Timestamp != 160 {
		t.Fatalf("payload %d bytes, step %d: NEW-D-9 is fixed, invert this pin (160 bytes per 20 ms is 64 kbit/s, above b=AS:16)", len(a.Payload), b.Timestamp-a.Timestamp)
	}
}

// noRTP fails when any RTP packet reaches pkts within d.
func noRTP(t *testing.T, pkts chan *rtp.Packet, d time.Duration) {
	t.Helper()
	select {
	case p := <-pkts:
		t.Fatalf("RTP of PT %d was sent although the negotiated stream does not send", p.PayloadType)
	case <-time.After(d):
	}
}

// TestRFC3264_NEWD11_NoMediaIsSentToAZeroAddress (CF-142, was the NEW-D-11 pin;
// RFC 3264 8.4, rfc3264.txt:973-975). Control: the call is answered and
// MediaView reports the remote 0.0.0.0:<port>.
func TestRFC3264_NEWD11_NoMediaIsSentToAZeroAddress(t *testing.T) {
	ua, dlg, pkts := laneDAnswered(t, "c=IN IP4 0.0.0.0", "", laneDAudio)
	noRTP(t, pkts, time.Second)
	mv, ok := ua.MediaView(dlg)
	if !ok || !strings.HasPrefix(mv.RemoteMediaAddr, "0.0.0.0:") {
		t.Fatalf("MediaView = %+v, %v; want remote 0.0.0.0:<port>", mv, ok)
	}
}

// TestNoMediaIsSentWhenOurDirectionDoesNotSend (CF-137 TX half).
func TestNoMediaIsSentWhenOurDirectionDoesNotSend(t *testing.T) {
	for _, c := range []struct {
		dir  string
		send bool
	}{{"a=sendonly", false}, {"a=inactive", false}, {"a=recvonly", true}, {"a=sendrecv", true}} {
		t.Run(c.dir, func(t *testing.T) {
			_, _, pkts := laneDAnswered(t, "c=IN IP4 127.0.0.1", "",
				"m=audio PORT RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"+c.dir+"\r\n")
			if c.send {
				nextRTP(t, pkts, 0)
			} else {
				noRTP(t, pkts, time.Second)
			}
		})
	}
}

// TestRFC3264_NEWD19_AnswererSendsAtTheOfferedPT (CF-150, was the NEW-D-19 pin;
// RFC 3264 6.1, rfc3264.txt:623-624). Control: SendDTMF's events arrive at the
// offered telephone-event PT 97.
func TestRFC3264_NEWD19_AnswererSendsAtTheOfferedPT(t *testing.T) {
	ua, dlg, pkts := laneDAnswered(t, "c=IN IP4 127.0.0.1", "",
		"m=audio PORT RTP/AVP 96 97\r\na=rtpmap:96 PCMU/8000\r\na=rtpmap:97 telephone-event/8000\r\na=sendrecv\r\n")
	if _, _, err := ua.SendDTMF(context.Background(), dlg, "5", session.DTMFModeRFC2833, 100, 0); err != nil {
		t.Fatalf("SendDTMF: %v", err)
	}
	nextRTP(t, pkts, 97) // control: events use the offered PT
	nextRTP(t, pkts, 96) // audio is at the offered PT 96, not the static 0
}

// laneDCall is an outbound call whose 200 carries a crafted answer. peerSock is
// the answer's media socket (it also reads our RTP into pkts); uaMedia is the
// address our offer named, where the test sends its RTP.
type laneDCall struct {
	ua       *sipua.UA
	dlg      string
	events   func() []session.UAEvent
	peerSock *net.UDPConn
	uaMedia  *net.UDPAddr
	pkts     chan *rtp.Packet
}

// laneDOutbound dials a peer double whose 200 answers with the SDP lines in
// answer (PORT is replaced by the media socket's port) and waits for the 200.
func laneDOutbound(t *testing.T, codecs []string, answer string) *laneDCall {
	t.Helper()
	return laneDOutboundOpts(t, codecs, answer, true)
}

// laneDOutboundOpts is laneDOutbound; expectMedia false skips the wait for our
// first RTP packet (answers under which we send nothing).
func laneDOutboundOpts(t *testing.T, codecs []string, answer string, expectMedia bool) *laneDCall {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("media socket: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	port := strconv.Itoa(sock.LocalAddr().(*net.UDPAddr).Port)
	body := "v=0\r\no=probe 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" + strings.ReplaceAll(answer, "PORT", port)
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", Behaviour: peer.Behaviour{AnswerSDP: peer.AnswerWithBody([]byte(body))}})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), codecs, "disabled")
	events := collect(t, ua)
	res, err := ua.Dial(context.Background(), session.DialRequest{ToURI: "sip:bob@" + p.Addr()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, events, session.UAEventFinal, 200)
	offer := string(p.LastInviteBody())
	m := regexp.MustCompile(`(?m)^m=audio (\d+) `).FindStringSubmatch(offer)
	if m == nil {
		t.Fatalf("our offer has no m=audio line:\n%s", offer)
	}
	uaPort, _ := strconv.Atoi(m[1])
	pkts := make(chan *rtp.Packet, 4096)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, rerr := sock.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			pkt := &rtp.Packet{}
			if pkt.Unmarshal(append([]byte(nil), buf[:n]...)) == nil { // a copy: Payload aliases its input
				pkts <- pkt
			}
		}
	}()
	// Our first RTP packet shows the media loop is running, so the packets a pin
	// sends next are not lost to a loop that has not started.
	if expectMedia {
		select {
		case <-pkts:
		case <-time.After(2 * time.Second):
			t.Fatal("the media loop sent no RTP within 2 s of the 200")
		}
	}
	return &laneDCall{ua: ua, dlg: res.DialogID, events: events, peerSock: sock, pkts: pkts,
		uaMedia: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: uaPort}}
}

// sendFrom writes one RTP packet from src to our media port.
func (c *laneDCall) sendFrom(t *testing.T, src *net.UDPConn, pt uint8, marker bool, seq uint16, ts uint32, ssrc uint32, payload []byte) {
	t.Helper()
	raw, err := (&rtp.Packet{Header: rtp.Header{Version: 2, Marker: marker, PayloadType: pt, SequenceNumber: seq, Timestamp: ts, SSRC: ssrc}, Payload: payload}).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := src.WriteToUDP(raw, c.uaMedia); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// send writes from the answer's media socket, the signalled source.
func (c *laneDCall) send(t *testing.T, pt uint8, marker bool, seq uint16, ts uint32, payload []byte) {
	t.Helper()
	c.sendFrom(t, c.peerSock, pt, marker, seq, ts, 0x01020304, payload)
}

// event is an RFC 4733 payload: code, E, R, volume 10, duration.
func laneDEvent(code byte, end, reserved bool, dur uint16) []byte {
	b := byte(10)
	if end {
		b |= 0x80
	}
	if reserved {
		b |= 0x40
	}
	return []byte{code, b, byte(dur >> 8), byte(dur)}
}

const laneDULaw = "a=rtpmap:0 PCMU/8000\r\n"

// dtmfReports returns the digits our UA has reported so far, in order.
func (c *laneDCall) dtmfReports() []session.UAEvent {
	var out []session.UAEvent
	for _, ev := range c.events() {
		if ev.Kind == session.UAEventDTMF {
			out = append(out, ev)
		}
	}
	return out
}

func (c *laneDCall) reported(digit string) int {
	n := 0
	for _, ev := range c.dtmfReports() {
		if ev.Digit == digit {
			n++
		}
	}
	return n
}

// TestRFC3264_NEWD23_EventAtOfferedPTIsAcceptedWhenAnswerRemaps (CF-154, was
// the NEW-D-23 pin; rfc3264.txt:432-436). Control: the digit at the answer's
// PT 96 is reported.
func TestRFC3264_NEWD23_EventAtOfferedPTIsAcceptedWhenAnswerRemaps(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, "m=audio PORT RTP/AVP 0 96\r\n"+laneDULaw+"a=rtpmap:96 telephone-event/8000\r\na=fmtp:96 0-15\r\na=sendrecv\r\n")
	for i := 0; i < 3; i++ {
		c.send(t, 96, i == 0, uint16(1+i), 1000, laneDEvent(6, true, false, 480))
	}
	waitForCond(t, func() bool { return c.reported("6") == 1 })
	for i := 0; i < 3; i++ {
		c.send(t, 101, i == 0, uint16(4+i), 2000, laneDEvent(4, true, false, 480))
	}
	waitForCond(t, func() bool { return c.reported("4") == 1 })
}

// TestRFC3264_NEWD24_SecondAnsweredCodecIsReceived (CF-155, was the NEW-D-24
// pin; rfc3264.txt:432-436): PCMA then PCMU packets are all counted.
func TestRFC3264_NEWD24_SecondAnsweredCodecIsReceived(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU", "PCMA"}, "m=audio PORT RTP/AVP 8 0 101\r\na=rtpmap:8 PCMA/8000\r\n"+laneDULaw+"a=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n")
	received := func() int64 {
		q, _ := c.ua.QualityView(c.dlg)
		return q.PacketsReceived
	}
	for i := 0; i < 5; i++ {
		c.send(t, 8, false, uint16(1+i), uint32(160*i), make([]byte, 160))
	}
	waitForCond(t, func() bool { return received() == 5 })
	for i := 5; i < 10; i++ {
		c.send(t, 0, false, uint16(1+i), uint32(160*i), make([]byte, 160))
	}
	waitForCond(t, func() bool { return received() == 10 })
}

// TestOffererSendsAtTheAnswersPT (CF-150): an answer that lists PCMU at 96
// makes our audio go out at 96.
func TestOffererSendsAtTheAnswersPT(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, "m=audio PORT RTP/AVP 96 101\r\na=rtpmap:96 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n")
	nextRTP(t, c.pkts, 96)
}

// TestOffererSendsNothingWhenTheAnswerIsSendonly (CF-137 TX half, offerer side).
func TestOffererSendsNothingWhenTheAnswerIsSendonly(t *testing.T) {
	c := laneDOutboundOpts(t, []string{"PCMU"}, "m=audio PORT RTP/AVP 0\r\n"+laneDULaw+"a=sendonly\r\n", false)
	noRTP(t, c.pkts, time.Second)
}
