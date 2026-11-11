package trace

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// Synthesised pcap (§18.1, D9c): a reconstruction from tap records, not a wire
// capture. Classic pcap, LINKTYPE_RAW (101) so each frame begins at the IPv4
// header — no fabricated link layer. IPv4/UDP headers are synthesised from the
// recorded 5-tuple. §18.1 states checksums are COMPUTED over the synthesised
// content, so the IPv4 header checksum is computed (ipChecksum below); the UDP
// checksum is left 0, which IPv4 defines as "checksum not computed" (RFC 768) —
// a legal value, not an invalid one, so tshark dissects cleanly. This file
// imports NEITHER sipgo NOR sipua NOR internal/artifact — it is a pure renderer
// over session.SIPRecord, the sibling of render.go.
const linktypeRaw = 101

// PcapFileHeader is the 24-byte classic-pcap global header. All classic-pcap
// framing fields (here and in each record header in PcapFrame) are written
// BigEndian, consistently: the magic must be byte-exact a1 b2 c3 d4 (verified
// by TestPcapWriterRawElseSerialized assertion (d)), and a mixed-endian file
// would misdissect in tshark, since a reader fixes one byte order for the
// whole file from the magic's byte pattern. This is a valid, standards-legal
// classic-pcap byte-order variant, distinct from the IP/UDP header fields in
// PcapFrame below, which are ALWAYS BigEndian (network byte order) regardless
// of the pcap file's own byte order.
func PcapFileHeader() []byte {
	h := make([]byte, 24)
	binary.BigEndian.PutUint32(h[0:], 0xa1b2c3d4) // magic
	binary.BigEndian.PutUint16(h[4:], 2)          // version major
	binary.BigEndian.PutUint16(h[6:], 4)          // version minor
	// h[8:16] thiszone + sigfigs = 0
	binary.BigEndian.PutUint32(h[16:], 262144)      // snaplen
	binary.BigEndian.PutUint32(h[20:], linktypeRaw) // network
	return h
}

// PcapFrame renders one tap record: pcap record header + synthesised IPv4 +
// UDP + payload. Payload is rec.Raw when non-nil, else rec.Serialized (D9d
// fallback). It is the STATELESS UDP/single-frame primitive (Rule 6a D1):
// tcp/tls records need a stateful running seq/ack, which streamSeqEncoder
// (below) owns — PcapFrame's own behaviour and signature are unchanged by T5,
// so every pre-existing byte-for-byte UDP assertion still holds.
func PcapFrame(rec session.SIPRecord) ([]byte, error) {
	payload := pcapPayload(rec)
	srcStr, dstStr := pcapEndpoints(rec)
	srcIP, srcPort, err := ipv4Port(srcStr, "udp")
	if err != nil {
		return nil, fmt.Errorf("pcap: src %q: %w", srcStr, err)
	}
	dstIP, dstPort, err := ipv4Port(dstStr, "udp")
	if err != nil {
		return nil, fmt.Errorf("pcap: dst %q: %w", dstStr, err)
	}

	udpLen := 8 + len(payload)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	// udp[6:8] checksum = 0 — RFC 768 "checksum not computed"; a legal value.

	ip := pcapIPHeader(17, udpLen, srcIP, dstIP) // protocol UDP

	body := make([]byte, 0, len(ip)+len(udp)+len(payload))
	body = append(body, ip...)
	body = append(body, udp...)
	body = append(body, payload...)

	return append(pcapRecordHeader(rec, len(body)), body...), nil
}

// Pcap renders a whole capture: file header followed by one frame per record,
// all through a single streamSeqEncoder for the batch (Rule 6a D1) — so a
// tcp/tls flow's synthesised seq/ack is internally consistent across the
// whole recorded call. The streaming capture engine (sink.go) carries the
// same encoder type across calls, so batch and stream share one framing
// (Rule 18).
func Pcap(recs []session.SIPRecord) ([]byte, error) {
	out := PcapFileHeader()
	enc := newStreamSeqEncoder()
	for i := range recs {
		f, err := enc.frame(recs[i])
		if err != nil {
			return nil, err
		}
		out = append(out, f...)
	}
	return out, nil
}

// pcapPayload picks the frame payload: rec.Raw when non-nil, else
// rec.Serialized (D9d fallback). Shared by PcapFrame and streamSeqEncoder so
// the two frame arms (UDP, tcp/tls) never diverge on this choice.
func pcapPayload(rec session.SIPRecord) []byte {
	if rec.Raw != nil {
		return rec.Raw
	}
	return []byte(rec.Serialized)
}

// pcapEndpoints returns (src, dst) as "host:port" from THIS UA's perspective:
// outbound src=Local dst=Remote; inbound src=Remote dst=Local.
func pcapEndpoints(rec session.SIPRecord) (srcStr, dstStr string) {
	srcStr, dstStr = rec.LocalAddr, rec.RemoteAddr
	if rec.Direction == session.Inbound {
		srcStr, dstStr = rec.RemoteAddr, rec.LocalAddr
	}
	return srcStr, dstStr
}

// pcapIPHeader synthesises the 20-byte IPv4 header shared by both frame arms,
// with the checksum COMPUTED over it (§18.1).
func pcapIPHeader(protocol byte, l4Len int, srcIP, dstIP net.IP) []byte {
	totalLen := 20 + l4Len
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(totalLen))
	ip[8] = 64 // TTL (nominal, §18.1)
	ip[9] = protocol
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)
	// §18.1: the IPv4 header checksum is COMPUTED over the synthesised header.
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))
	return ip
}

// pcapRecordHeader is the 16-byte classic-pcap per-record header.
func pcapRecordHeader(rec session.SIPRecord, bodyLen int) []byte {
	rechdr := make([]byte, 16)
	binary.BigEndian.PutUint32(rechdr[0:], uint32(rec.At.Unix()))
	binary.BigEndian.PutUint32(rechdr[4:], uint32(rec.At.Nanosecond()/1000))
	binary.BigEndian.PutUint32(rechdr[8:], uint32(bodyLen))  // incl_len
	binary.BigEndian.PutUint32(rechdr[12:], uint32(bodyLen)) // orig_len
	return rechdr
}

// ipv4Port splits "host:port" and returns the 4-byte IPv4 address. An IPv6
// address returns an error rather than a mis-framed packet — P2 UDP traffic is
// IPv4 (loopback and the §14.5 rig), so IPv6 is unreachable here (Rule 15).
// network is passed to net.LookupPort transport-correctly (L6: "udp" for the
// UDP arm, "tcp" for tcp/tls — TLS resolves port names the same way TCP does).
func ipv4Port(hostPort, network string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	v4 := ip.To4()
	if v4 == nil {
		return nil, 0, fmt.Errorf("not an IPv4 address")
	}
	p, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, 0, err
	}
	return v4, uint16(p), nil
}

// flowKey identifies a tcp/tls flow direction-independently (Rule 6a D1):
// sorted endpoints + transport. Sorting means the same flow is found
// regardless of which direction's record arrives first.
type flowKey struct {
	transport session.Transport
	epA, epB  string
}

func newFlowKey(transport session.Transport, ep1, ep2 string) flowKey {
	if ep1 > ep2 {
		ep1, ep2 = ep2, ep1
	}
	return flowKey{transport: transport, epA: ep1, epB: ep2}
}

// streamSeqEncoder is the stateful pcap framer (Rule 6a D1). UDP records
// (Transport != tcp/tls, including the zero-value "") are a pure passthrough
// to the stateless PcapFrame, byte-for-byte identical to pre-T5 output. Each
// tcp/tls flow gets one running per-direction sequence number, keyed by
// flowKey; the peer direction's current running seq is this direction's ACK.
// Not safe for concurrent use — callers (Pcap for a batch, capture for a
// stream) already serialize their own frame calls.
type streamSeqEncoder struct {
	flows map[flowKey]map[session.Direction]uint32
}

func newStreamSeqEncoder() *streamSeqEncoder {
	return &streamSeqEncoder{flows: map[flowKey]map[session.Direction]uint32{}}
}

// frame renders one record. UDP (and any transport other than tcp/tls, incl.
// "") delegates unchanged to PcapFrame. tcp/tls synthesises IP protocol 6 +
// a 20-byte TCP header: this direction's running seq (init 0, += the previous
// segment's payload length for this direction), ACK = the peer direction's
// current running seq, flags PSH+ACK, window 65535, checksum left 0 (matching
// the file's existing UDP-checksum-0 precedent; Wireshark's default "validate
// checksum" is off).
func (e *streamSeqEncoder) frame(rec session.SIPRecord) ([]byte, error) {
	if rec.Transport != session.TransportTCP && rec.Transport != session.TransportTLS {
		return PcapFrame(rec)
	}

	payload := pcapPayload(rec)
	srcStr, dstStr := pcapEndpoints(rec)
	srcIP, srcPort, err := ipv4Port(srcStr, "tcp")
	if err != nil {
		return nil, fmt.Errorf("pcap: src %q: %w", srcStr, err)
	}
	dstIP, dstPort, err := ipv4Port(dstStr, "tcp")
	if err != nil {
		return nil, fmt.Errorf("pcap: dst %q: %w", dstStr, err)
	}

	key := newFlowKey(rec.Transport, rec.LocalAddr, rec.RemoteAddr)
	dirs, ok := e.flows[key]
	if !ok {
		dirs = map[session.Direction]uint32{}
		e.flows[key] = dirs
	}
	peerDir := session.Inbound
	if rec.Direction == session.Inbound {
		peerDir = session.Outbound
	}
	seq := dirs[rec.Direction] // 0 for a direction's first segment
	ack := dirs[peerDir]       // 0 until the peer direction has sent anything

	tcpLen := 20 + len(payload)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4                            // data offset: 5 32-bit words (20 bytes), no options
	tcp[13] = 0x18                              // flags: PSH+ACK
	binary.BigEndian.PutUint16(tcp[14:], 65535) // window
	// tcp[16:18] checksum = 0, tcp[18:20] urgent pointer = 0 (unused, PSH+ACK
	// carries no urgent data) — left zero, matching the UDP arm's precedent.

	ip := pcapIPHeader(6, tcpLen, srcIP, dstIP) // protocol TCP

	body := make([]byte, 0, len(ip)+len(tcp)+len(payload))
	body = append(body, ip...)
	body = append(body, tcp...)
	body = append(body, payload...)

	dirs[rec.Direction] = seq + uint32(len(payload)) // advance for the next segment

	return append(pcapRecordHeader(rec, len(body)), body...), nil
}

// ipChecksum is the standard 16-bit one's-complement sum over the 20-byte IPv4
// header, with the checksum field (bytes 10:12) held zero during the sum. §18.1
// requires the checksum be computed over the synthesised header.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 { // skip the checksum field itself (assumed zero here)
			continue
		}
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
