package main

// sessiontimer_silent_stub.go — a minimal, standalone SIP UAS stub used only
// by scenarioSessionTimerInDialogTimeout (Task 33, §11.3.1 case 2, RULING 2):
// it answers the daemon's INVITE claiming Session-Expires: 90;refresher=uac
// (WE refresh), ACKs are recorded, and then it goes SILENT on the very next
// in-dialog request it receives — the refresh UPDATE Task 29's refresher
// sends at interval/2 — so the daemon's own client transaction runs out its
// real Timer F (~32s, ua.go's 32s default) with no response ever arriving.
//
// This follows noncompliant_uas.go's precedent exactly (see its own doc
// comment for why testutil/peer, which needs a *testing.T, cannot be reused
// from this package main binary) rather than modifying the shared lab rig,
// per RULING 2: no pjsip.conf/extensions.conf change, no root, no iptables.
import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/emiago/sipgo/sip"
)

// sessionTimerSilentSDP offers a PCMU codec — the same one the daemon's own
// direct-mode UAs negotiate by default — so the call reaches `answered`
// cleanly and the fault under test is the in-dialog timeout, not a media
// negotiation mismatch.
func sessionTimerSilentSDP(ip string) string {
	return "v=0\r\no=- 1 1 IN IP4 " + ip + "\r\ns=x\r\nc=IN IP4 " + ip + "\r\n" +
		"t=0 0\r\nm=audio 20002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
}

// sessionTimerSilentStub answers exactly the FIRST INVITE of a dialog (a new
// Call-ID) with Session-Expires: 90;refresher=uac and
// Allow: INVITE, ACK, BYE, UPDATE (biasing the daemon's Task 28
// UPDATE-when-allowed choice, matching sessiontimer_refresh_test.go's own
// proven AnswerAllow/SwallowUpdate mechanism), then drops every subsequent
// in-dialog request on the SAME Call-ID — UPDATE, or a re-INVITE refresh if
// the daemon ever chose that instead — on the floor. No response at all.
//
// A bare `case sip.INVITE: always answer` would be wrong here: RFC 4028's
// refresh IS an in-dialog request, and for the UPDATE-vs-re-INVITE fallback
// it can legally be a re-INVITE — answering that unconditionally would
// silently REFRESH the session instead of drawing no response, defeating the
// fault this stub exists to inject (found empirically: without the Call-ID
// check, the first live run's "in-dialog timeout" scenario stayed answered
// past 90s because the stub had already 200'd the refresh re-INVITE).
type sessionTimerSilentStub struct {
	conn   net.PacketConn
	ip     string // the address it binds and advertises in its SDP
	parser *sip.Parser
	done   chan struct{}

	mu sync.Mutex
	// refreshSeen counts the in-dialog session refreshes this stub RECEIVED AND
	// DROPPED — an UPDATE, or a re-INVITE on a dialog it has already answered.
	// It is the scenario's proof that the fault under test was actually
	// injected: without it, "terminated / transport_failure /
	// in_dialog_timeout" is reached identically by a daemon that never sent a
	// refresh at all and died of something else, and the scenario passes for
	// the wrong reason.
	//
	// Only those two methods count. A stray OPTIONS or anything else the daemon
	// might put on this socket is NOT a refresh, and counting it would restore
	// exactly the vacuity this observable exists to close.
	refreshSeen int
	dialogs     map[string]bool
}

// startSessionTimerSilentStub binds on localIP, the gate's own address (a
// LAN-bound UA refuses a loopback c=, CF-201).
func startSessionTimerSilentStub(localIP string) (*sessionTimerSilentStub, error) {
	conn, err := net.ListenPacket("udp", localIP+":0")
	if err != nil {
		return nil, fmt.Errorf("sessionTimerSilentStub listen: %w", err)
	}
	u := &sessionTimerSilentStub{conn: conn, ip: localIP, parser: sip.NewParser(), done: make(chan struct{}), dialogs: map[string]bool{}}
	go u.serve()
	return u, nil
}

func (u *sessionTimerSilentStub) Addr() string      { return u.conn.LocalAddr().String() }
func (u *sessionTimerSilentStub) SIPTarget() string { return "sip:stub@" + u.Addr() }
func (u *sessionTimerSilentStub) RefreshesSeen() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.refreshSeen
}

func (u *sessionTimerSilentStub) Close() {
	select {
	case <-u.done:
		return
	default:
	}
	close(u.done)
	_ = u.conn.Close()
}

func (u *sessionTimerSilentStub) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := u.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		msg, err := u.parser.ParseSIP(data)
		if err != nil {
			continue
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			continue
		}
		callID := ""
		if h := req.CallID(); h != nil {
			callID = h.Value()
		}
		switch req.Method {
		case sip.INVITE:
			u.mu.Lock()
			isFirst := !u.dialogs[callID]
			if isFirst {
				u.dialogs[callID] = true
			} else {
				u.refreshSeen++
			}
			u.mu.Unlock()
			if !isFirst {
				continue // a re-INVITE refresh on an existing dialog: SILENCE.
			}
			res := sip.NewSDPResponseFromRequest(req, []byte(sessionTimerSilentSDP(u.ip)))
			host, portStr, _ := net.SplitHostPort(u.Addr())
			port, _ := strconv.Atoi(portStr)
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "stub", Host: host, Port: port}})
			res.AppendHeader(sip.NewHeader("Session-Expires", "90;refresher=uac"))
			res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, BYE, UPDATE"))
			u.write(res, from)
		case sip.ACK:
			// Dialog established; nothing to send back.
		case sip.BYE:
			// Not expected under §11.3.1 case 2 (no BYE reaches the wire), but
			// answered defensively so a stray one never wedges the daemon.
			u.write(sip.NewResponseFromRequest(req, 200, "OK", nil), from)
		case sip.UPDATE:
			// The expected refresh: SILENCE, on purpose — this is the fault
			// under test. Counted only on a dialog this stub actually answered,
			// so RefreshesSeen means "a refresh was dropped", nothing looser.
			u.mu.Lock()
			if u.dialogs[callID] {
				u.refreshSeen++
			}
			u.mu.Unlock()
		default:
			// Anything else: silence, and NOT counted as a refresh.
		}
	}
}

func (u *sessionTimerSilentStub) write(res *sip.Response, to net.Addr) {
	_, _ = u.conn.WriteTo([]byte(res.String()), to)
}
