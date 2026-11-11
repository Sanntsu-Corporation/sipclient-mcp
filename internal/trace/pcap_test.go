package trace

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func TestPcapWriterRawElseSerialized(t *testing.T) {
	rawBytes := []byte("OPTIONS sip:peer@127.0.0.1 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5060\r\nCSeq: 1 OPTIONS\r\n\r\n")
	serialized := "REGISTER sip:reg@127.0.0.1 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5061\r\nCSeq: 2 REGISTER\r\n\r\n"
	recs := []session.SIPRecord{
		{At: time.Unix(1_700_000_000, 0), Direction: session.Outbound,
			LocalAddr: "127.0.0.1:5060", RemoteAddr: "127.0.0.1:5062",
			Method: "OPTIONS", Serialized: "IGNORED-WHEN-RAW-SET", Raw: rawBytes},
		{At: time.Unix(1_700_000_001, 0), Direction: session.Inbound,
			LocalAddr: "127.0.0.1:5061", RemoteAddr: "127.0.0.1:5063",
			Method: "REGISTER", Serialized: serialized, Raw: nil},
	}
	blob, err := Pcap(recs)
	if err != nil {
		t.Fatalf("Pcap: %v", err)
	}
	// (a) Raw-set record: payload is byte-exact rawBytes.
	if !bytes.Contains(blob, rawBytes) {
		t.Fatal("Raw-set record: emitted payload is not the observed Raw octets")
	}
	// (b) Raw==nil record: payload byte-equals Serialized (canonical fallback).
	if !bytes.Contains(blob, []byte(serialized)) {
		t.Fatal("Raw==nil record: emitted payload is not byte-equal to Serialized")
	}
	// (c) Every emitted SIP frame re-parses as SIP.
	for _, want := range [][]byte{rawBytes, []byte(serialized)} {
		if _, err := sip.ParseMessage(want); err != nil {
			t.Fatalf("emitted frame does not re-parse as SIP: %v", err)
		}
	}
	// (d) Classic-pcap magic present at offset 0.
	if len(blob) < 24 || !bytes.Equal(blob[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}) {
		t.Fatal("missing classic-pcap global header magic")
	}
}

// TestPcapIPv4HeaderChecksumIsValid (M1) verifies the synthesised IPv4 header
// checksum §18.1 requires is not just present but ARITHMETICALLY CORRECT:
// computed independently here (the standard one's-complement fold over the full
// 20-byte header, checksum field included, must equal 0xffff), rather than by
// reusing the production ipChecksum. A single-record Pcap places the IPv4 header
// at offset 24 (global header) + 16 (record header).
func TestPcapIPv4HeaderChecksumIsValid(t *testing.T) {
	blob, err := Pcap([]session.SIPRecord{{
		At: time.Unix(1_700_000_000, 0), Direction: session.Outbound,
		LocalAddr: "127.0.0.1:5060", RemoteAddr: "192.0.2.10:5062",
		Method: "OPTIONS", Raw: []byte("OPTIONS sip:p SIP/2.0\r\n\r\n"),
	}})
	if err != nil {
		t.Fatalf("Pcap: %v", err)
	}
	const ipOff = 24 + 16
	if len(blob) < ipOff+20 {
		t.Fatalf("blob too short (%d) to hold a 20-byte IPv4 header at offset %d", len(blob), ipOff)
	}
	ipHdr := blob[ipOff : ipOff+20]

	// Independent verification: the one's-complement sum over the full header
	// (checksum field INCLUDED) folds to 0xffff for a valid checksum.
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(ipHdr[i])<<8 | uint32(ipHdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Fatalf("IPv4 header checksum invalid: full-header one's-complement fold = %#04x, want 0xffff", uint16(sum))
	}
	// And it is actually populated, not left zero — §18.1 requires it computed.
	if binary.BigEndian.Uint16(ipHdr[10:12]) == 0 {
		t.Fatal("IPv4 header checksum field is zero; §18.1 requires it computed over the synthesised header")
	}
}

// TestPcapRejectsNonIPv4 (B3) is the pcap IPv4-only error path: a record whose
// LocalAddr/RemoteAddr is not IPv4 returns a non-nil error rather than a corrupt
// frame, at BOTH the single-frame (PcapFrame) and batch (Pcap) entry points.
func TestPcapRejectsNonIPv4(t *testing.T) {
	rec := session.SIPRecord{
		At: time.Unix(1_700_000_000, 0), Direction: session.Outbound,
		LocalAddr: "[::1]:5060", RemoteAddr: "[::1]:5062",
		Method: "OPTIONS", Raw: []byte("OPTIONS sip:p SIP/2.0\r\n\r\n"),
	}
	if _, err := PcapFrame(rec); err == nil {
		t.Error("PcapFrame on a non-IPv4 5-tuple returned nil error, want a synth failure")
	}
	if _, err := Pcap([]session.SIPRecord{rec}); err == nil {
		t.Error("Pcap on a non-IPv4 5-tuple returned nil error, want a synth failure")
	}
}
