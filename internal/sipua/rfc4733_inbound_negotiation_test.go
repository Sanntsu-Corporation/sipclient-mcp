// internal/sipua/rfc4733_inbound_negotiation_test.go — Lane D (rfc-sweep-d)
// positive test, 6a D20: the one non-pin test of the lane.
//
// The earlier D8 test (rfc2833_inbound_offer_test.go) offers PT 101, which is
// our own offer constant, so it cannot tell "mirror the offered PT" from "use
// the default PT", and it covers the transmit direction only. This test offers
// telephone-event at PT 96 and checks both directions on one dialog.
// Rows: D-ANS-18 (answer keeps the offered PT), D-ANS-32 (we send with the
// offered PT), D-RX-* (an event at the offered PT is reported as the digit).
package sipua_test

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
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestInboundTelephoneEventOfferAtANonDefaultPTIsUsedInBothDirections: an
// inbound offer `0 96` with `a=rtpmap:96 telephone-event/8000` is answered with
// 96, an RFC 4733 packet of PT 96 sent to the answer's port is reported as the
// digit, and SendDTMF in RFC 2833 mode puts PT 96 event packets on the wire.
func TestInboundTelephoneEventOfferAtANonDefaultPTIsUsedInBothDirections(t *testing.T) {
	peerMedia, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("peer media socket: %v", err)
	}
	t.Cleanup(func() { _ = peerMedia.Close() })
	peerPort := peerMedia.LocalAddr().(*net.UDPAddr).Port

	const offerTEPT = 96
	pt := strconv.Itoa(offerTEPT)
	offer := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=peer\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio " + strconv.Itoa(peerPort) + " RTP/AVP 0 " + pt + "\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:" + pt + " telephone-event/8000\r\n" +
		"a=sendrecv\r\n")

	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "disabled")
	events := collect(t, ua)

	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(), offer)
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)

	// The answer lists the offered PT with a telephone-event rtpmap.
	answerSDP := string(p.LastFinalResponseBody())
	m := regexp.MustCompile(`(?m)^m=audio (\d+) \S+ ([^\r\n]*)`).FindStringSubmatch(answerSDP)
	if m == nil || !strings.Contains(" "+m[2]+" ", " "+pt+" ") ||
		!strings.Contains(answerSDP, "a=rtpmap:"+pt+" telephone-event/8000") {
		t.Fatalf("answer does not list PT %s with a telephone-event rtpmap:\n%s", pt, answerSDP)
	}
	answerPort, _ := strconv.Atoi(m[1])

	// Receive direction: an end-of-event packet at the offered PT is reported.
	// Payload: event 5, E=1, volume 10, duration 800.
	evPkt := &rtp.Packet{
		Header:  rtp.Header{Version: 2, Marker: true, PayloadType: offerTEPT, SequenceNumber: 1, Timestamp: 1000, SSRC: 0x01020304},
		Payload: []byte{5, 0x80 | 10, 0x03, 0x20},
	}
	raw, err := evPkt.Marshal()
	if err != nil {
		t.Fatalf("marshal event packet: %v", err)
	}
	if _, err := peerMedia.WriteToUDP(raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answerPort}); err != nil {
		t.Fatalf("send event packet: %v", err)
	}
	waitForCond(t, func() bool {
		for _, ev := range events() {
			if ev.Kind == session.UAEventDTMF && ev.Digit == "5" {
				return true
			}
		}
		return false
	})

	// Transmit direction: SendDTMF in RFC 2833 mode uses the offered PT.
	pktCh := make(chan *rtp.Packet, 64)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, rerr := peerMedia.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			pkt := &rtp.Packet{}
			if uerr := pkt.Unmarshal(buf[:n]); uerr == nil {
				pktCh <- pkt
			}
		}
	}()
	if sent, _, err := ua.SendDTMF(context.Background(), incoming.DialogID, "7", session.DTMFModeRFC2833, 100, 0); err != nil || sent != 1 {
		t.Fatalf("SendDTMF(rfc2833): sent=%d err=%v", sent, err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-pktCh:
			if pkt.PayloadType == offerTEPT {
				return
			}
		case <-deadline:
			t.Fatalf("no event packet with PT %d reached the peer's media socket", offerTEPT)
		}
	}
}
