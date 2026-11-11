// internal/sipua/rfc2833_inbound_offer_test.go — D8's integration coverage.
//
// The Phase 3 known-limitations record (§4/M6) records the gap this closes: zero
// test drove an inbound INVITE carrying a telephone-event offer through
// BuildAnswer and then actually sent/received rfc2833 on that dialog.
// internal/media/sdp_answer_test.go already unit-tests BuildAnswer's
// PT-mirroring in isolation; this test drives the real production entry
// points around it — a real UA, a real inbound INVITE, a real Answer(), and a
// real mediaLoop putting an RFC 4733 packet on the wire — so a regression in
// how onInvite/Answer WIRES UP the negotiated PT (as opposed to how
// BuildAnswer computes it) would be caught here even though the unit tests
// stay green.
package sipua_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtp"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// TestInboundTelephoneEventOfferNegotiatesAndSendsRFC2833OnTheWire is D8's
// integration test. peerMedia stands in for the far end's own media socket —
// its address is embedded directly in the crafted offer, independent of the
// peer.Peer signalling double's own socket — so the RFC 4733 packet our UA's
// real mediaLoop actually sends can be read back and its payload type
// checked against the negotiated (mirrored) one.
func TestInboundTelephoneEventOfferNegotiatesAndSendsRFC2833OnTheWire(t *testing.T) {
	peerMedia, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("peer media socket: %v", err)
	}
	t.Cleanup(func() { _ = peerMedia.Close() })
	peerPort := peerMedia.LocalAddr().(*net.UDPAddr).Port

	const offerTEPT = 101
	offer := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=peer\r\nc=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\nm=audio " + strconv.Itoa(peerPort) + " RTP/AVP 0 " + strconv.Itoa(offerTEPT) + "\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:" + strconv.Itoa(offerTEPT) + " telephone-event/8000\r\n" +
		"a=sendrecv\r\n")

	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0"})
	ua, _ := newDirectUA(t, fakeclock.New(time.Unix(0, 0)))
	events := collect(t, ua)

	p.DialWithBody(t, "sip:alice@"+ua.BoundAddr().String(), offer)
	incoming := waitFor(t, events, session.UAEventInbound, 0)
	if err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: incoming.DialogID}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	waitForCode(t, p, 200)

	// Confirm the negotiated PT is non-zero: our own 200 OK must mirror the
	// offered telephone-event PT back verbatim (BuildAnswer, sdp.go).
	answerSDP := string(p.LastFinalResponseBody())
	if !strings.Contains(answerSDP, "a=rtpmap:"+strconv.Itoa(offerTEPT)+" telephone-event/8000") {
		t.Fatalf("our 200 OK did not mirror the offered telephone-event PT %d:\n%s", offerTEPT, answerSDP)
	}

	pktCh := make(chan *rtp.Packet, 32)
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

	sent, _, err := ua.SendDTMF(context.Background(), incoming.DialogID, "5", session.DTMFModeRFC2833, 100, 0)
	if err != nil {
		t.Fatalf("SendDTMF(rfc2833): %v", err)
	}
	if sent != 1 {
		t.Fatalf("digits_sent=%d want 1", sent)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-pktCh:
			if pkt.PayloadType == offerTEPT {
				return // the negotiated (mirrored) PT reached the wire
			}
		case <-deadline:
			t.Fatalf("no RFC 4733 packet with PT %d arrived at the peer's media socket", offerTEPT)
		}
	}
}
