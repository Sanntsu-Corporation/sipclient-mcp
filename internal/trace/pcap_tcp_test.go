package trace

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// TestPcapFrameTCPUsesProtocol6 (plan T5 Step 1/base test, name kept per the
// plan): a tcp-transport record renders IP protocol 6, not the UDP-hardcoded
// 17. Routed through streamSeqEncoder.frame, NOT PcapFrame directly: Rule 6a
// D1 locks PcapFrame as the stateless UDP/single-frame primitive the encoder
// delegates to for the UDP arm — the TCP arm lives in the encoder, so
// PcapFrame itself never branches on transport (its behavior/signature are
// unchanged by T5).
func TestPcapFrameTCPUsesProtocol6(t *testing.T) {
	rec := session.SIPRecord{
		Transport:  session.TransportTCP,
		Direction:  session.Outbound,
		At:         time.Unix(1_700_000_000, 0),
		LocalAddr:  "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5062",
		Serialized: "INVITE sip:x SIP/2.0\r\n\r\n",
	}
	enc := newStreamSeqEncoder()
	frame, err := enc.frame(rec)
	if err != nil {
		t.Fatalf("frame(tcp): %v", err)
	}
	// LINKTYPE_RAW: frame starts at the IPv4 header; byte 9 is the protocol.
	ip := frame[16:] // skip the 16-byte pcap record header
	if ip[9] != 6 {
		t.Fatalf("IP protocol = %d, want 6 (TCP)", ip[9])
	}
}

// TestPcapFrameUnchangedForUDP confirms PcapFrame's own behavior/signature
// are untouched by T5 (Rule 6a D1): calling it directly with a tcp-transport
// record still renders protocol 17 — PcapFrame does not know about transport
// at all, it is the pre-T5 UDP-only primitive the encoder delegates to.
func TestPcapFrameUnchangedForUDP(t *testing.T) {
	rec := session.SIPRecord{
		Transport:  session.TransportTCP,
		Direction:  session.Outbound,
		At:         time.Unix(1_700_000_000, 0),
		LocalAddr:  "127.0.0.1:5060",
		RemoteAddr: "127.0.0.1:5062",
		Serialized: "INVITE sip:x SIP/2.0\r\n\r\n",
	}
	frame, err := PcapFrame(rec)
	if err != nil {
		t.Fatalf("PcapFrame: %v", err)
	}
	ip := frame[16:]
	if ip[9] != 17 {
		t.Fatalf("IP protocol = %d, want 17 (PcapFrame stays UDP-only per D1)", ip[9])
	}
}

// tcpSeqAck pulls the seq (bytes 4:8) and ack (bytes 8:12) fields out of a
// synthesised frame's 20-byte TCP header, which starts at offset 16 (pcap
// record header) + 20 (IPv4 header).
func tcpSeqAck(t *testing.T, frame []byte) (seq, ack uint32) {
	t.Helper()
	const tcpOff = 16 + 20
	if len(frame) < tcpOff+20 {
		t.Fatalf("frame too short (%d) to hold a TCP header at offset %d", len(frame), tcpOff)
	}
	tcp := frame[tcpOff : tcpOff+20]
	return binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12])
}

// TestPcapTCPSeqMonotonic (Rule 6a D1 / Cycle B item 2): two same-direction
// tcp segments on the same flow must carry a running seq — the second
// segment's seq equals the first seq plus the first segment's payload length.
func TestPcapTCPSeqMonotonic(t *testing.T) {
	payload1 := []byte("INVITE sip:x SIP/2.0\r\n\r\n")
	payload2 := []byte("ACK sip:x SIP/2.0\r\n\r\n")
	recs := []session.SIPRecord{
		{
			Transport: session.TransportTCP, Direction: session.Outbound,
			At:        time.Unix(1_700_000_000, 0),
			LocalAddr: "127.0.0.1:5060", RemoteAddr: "127.0.0.1:5062",
			Raw: payload1,
		},
		{
			Transport: session.TransportTCP, Direction: session.Outbound,
			At:        time.Unix(1_700_000_001, 0),
			LocalAddr: "127.0.0.1:5060", RemoteAddr: "127.0.0.1:5062",
			Raw: payload2,
		},
	}
	enc := newStreamSeqEncoder()
	frame1, err := enc.frame(recs[0])
	if err != nil {
		t.Fatalf("frame 1: %v", err)
	}
	frame2, err := enc.frame(recs[1])
	if err != nil {
		t.Fatalf("frame 2: %v", err)
	}
	seq1, _ := tcpSeqAck(t, frame1)
	seq2, _ := tcpSeqAck(t, frame2)
	if want := seq1 + uint32(len(payload1)); seq2 != want {
		t.Fatalf("seq2 = %d, want %d (seq1=%d + len(payload1)=%d)", seq2, want, seq1, len(payload1))
	}
}

// TestPcapTCPCrossDirectionAck (Rule 6a D1 / Cycle B item 2): a reverse
// direction segment's ACK equals the forward direction's running seq (the
// seq value the forward direction would use for its NEXT segment).
func TestPcapTCPCrossDirectionAck(t *testing.T) {
	fwdPayload := []byte("INVITE sip:x SIP/2.0\r\n\r\n")
	recs := []session.SIPRecord{
		{
			Transport: session.TransportTCP, Direction: session.Outbound,
			At:        time.Unix(1_700_000_000, 0),
			LocalAddr: "127.0.0.1:5060", RemoteAddr: "127.0.0.1:5062",
			Raw: fwdPayload,
		},
		{
			Transport: session.TransportTCP, Direction: session.Inbound,
			At:        time.Unix(1_700_000_001, 0),
			LocalAddr: "127.0.0.1:5060", RemoteAddr: "127.0.0.1:5062",
			Raw: []byte("SIP/2.0 100 Trying\r\n\r\n"),
		},
	}
	enc := newStreamSeqEncoder()
	fwdFrame, err := enc.frame(recs[0])
	if err != nil {
		t.Fatalf("forward frame: %v", err)
	}
	revFrame, err := enc.frame(recs[1])
	if err != nil {
		t.Fatalf("reverse frame: %v", err)
	}
	fwdSeq, _ := tcpSeqAck(t, fwdFrame)
	_, revAck := tcpSeqAck(t, revFrame)
	wantAck := fwdSeq + uint32(len(fwdPayload)) // the forward dir's running seq after its 1st segment
	if revAck != wantAck {
		t.Fatalf("reverse ACK = %d, want %d (forward running seq)", revAck, wantAck)
	}
}
