package main

// noncompliant_uas.go — a minimal, standalone SIP UAS stub used only by
// scenario488AckThenBye (P2 Wave 3, spec §11.2.1) to drive the offering-side
// 488/ACK-then-BYE path: a peer that answers 200 OK with an SDP offering a
// codec the daemon never offered (opus, payload type 111), which the daemon must react to
// entirely locally — ACK the 200 OK, then internally BYE — never emitting a
// SIP error of its own back to the peer.
//
// This deliberately duplicates a small slice of internal/testutil/peer's UAS
// wire-handling in miniature rather than reusing that package directly:
// peer.Start and every method on peer.Peer take/require a *testing.T and call
// t.Fatalf/t.Helper on it (internal/testutil/peer/peer.go), which e2e/loop —
// a live-rig-facing `package main` binary with no testing.T in scope — has no
// way to satisfy. This stub intentionally does not replicate REGISTER/digest,
// re-INVITE, CANCEL, or any of peer's other surface — only the INVITE/ACK/BYE
// slice this one scenario needs.

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/emiago/sipgo/sip"
)

// nonCompliantUnsupportedSDP is the SDP body the stub answers every INVITE with: a
// codec (opus, dynamic payload type 111) the daemon's own offer never included —
// exactly what the daemon's media.ParseAnswer must reject as
// answer_codec_not_offered.
func nonCompliantUnsupportedSDP(ip string) string {
	return "v=0\r\no=- 1 1 IN IP4 " + ip + "\r\ns=x\r\nc=IN IP4 " + ip + "\r\n" +
		"t=0 0\r\nm=audio 20000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n"
}

// nonCompliantUAS is a standalone UDP SIP peer that answers every INVITE it
// receives with a 200 OK carrying nonCompliantUnsupportedSDP, then tracks whether it
// observed the resulting ACK strictly before a BYE, and how many INVITEs it
// saw (no retransmit is the expected count-1 case).
type nonCompliantUAS struct {
	conn   net.PacketConn
	ip     string // the address it binds and advertises in its SDP
	parser *sip.Parser
	done   chan struct{}

	mu          sync.Mutex
	inviteCount int
	methods     []string // arrival order, for SawAckBeforeBye
}

// startNonCompliantUAS binds a UDP socket on localIP (the gate's own address:
// a LAN-bound UA refuses a loopback c=, CF-201) on an ephemeral port and
// starts serving.
func startNonCompliantUAS(localIP string) (*nonCompliantUAS, error) {
	conn, err := net.ListenPacket("udp", localIP+":0")
	if err != nil {
		return nil, fmt.Errorf("noncompliant UAS listen: %w", err)
	}
	u := &nonCompliantUAS{conn: conn, ip: localIP, parser: sip.NewParser(), done: make(chan struct{})}
	go u.serve()
	return u, nil
}

// Addr is the stub's concrete bound host:port.
func (u *nonCompliantUAS) Addr() string { return u.conn.LocalAddr().String() }

// SIPTarget is the sip: URI a dial helper passes to call_dial's to_uri to
// reach this stub directly (any Request-URI user part reaches it — the stub
// does not route on it).
func (u *nonCompliantUAS) SIPTarget() string { return "sip:stub@" + u.Addr() }

// Close shuts the stub's listener down, unblocking serve()'s read loop. Safe
// to call more than once.
func (u *nonCompliantUAS) Close() {
	select {
	case <-u.done:
		return
	default:
	}
	close(u.done)
	_ = u.conn.Close()
}

// InviteCount reports how many INVITEs the stub has received.
func (u *nonCompliantUAS) InviteCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.inviteCount
}

// SawAckBeforeBye reports whether the stub observed an ACK strictly before a
// BYE — the §11.2.1 ordering guarantee scenario488AckThenBye asserts.
func (u *nonCompliantUAS) SawAckBeforeBye() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	ackAt, byeAt := -1, -1
	for i, m := range u.methods {
		if m == "ACK" && ackAt < 0 {
			ackAt = i
		}
		if m == "BYE" && byeAt < 0 {
			byeAt = i
		}
	}
	return ackAt >= 0 && byeAt >= 0 && ackAt < byeAt
}

// serve is the stub's single receive loop: parse each inbound datagram as a
// SIP request and dispatch it. It returns once conn is closed.
func (u *nonCompliantUAS) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := u.conn.ReadFrom(buf)
		if err != nil {
			return // Close() -> conn.Close() unblocks ReadFrom with an error
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		msg, err := u.parser.ParseSIP(data)
		if err != nil {
			continue
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			continue // ignore stray responses
		}
		u.record(req)
		switch req.Method {
		case sip.INVITE:
			res := sip.NewSDPResponseFromRequest(req, []byte(nonCompliantUnsupportedSDP(u.ip)))
			host, portStr, _ := net.SplitHostPort(u.Addr())
			port, _ := strconv.Atoi(portStr)
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "stub", Host: host, Port: port}})
			u.write(res, from)
		case sip.ACK:
			// No response to an ACK; record() above already logged it.
		case sip.BYE:
			u.write(sip.NewResponseFromRequest(req, 200, "OK", nil), from)
		default:
			u.write(sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil), from)
		}
	}
}

func (u *nonCompliantUAS) record(req *sip.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.methods = append(u.methods, string(req.Method))
	if req.Method == sip.INVITE {
		u.inviteCount++
	}
}

func (u *nonCompliantUAS) write(res *sip.Response, to net.Addr) {
	_, _ = u.conn.WriteTo([]byte(res.String()), to)
}
