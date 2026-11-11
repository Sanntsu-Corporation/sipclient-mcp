package main

// keepalive_stub.go — a minimal, standalone SIP registrar/OPTIONS-responder
// stub used only by scenarioKeepaliveObservable (Task 33, C8). Keepalive
// OPTIONS are out-of-dialog and the tool surface has no UA-scoped ladder or
// capture (design spec §4/§10), so the only way to OBSERVE that the daemon's
// keepalive refresher actually fires is to point its registrar at something
// we control and count what arrives. Same noncompliant_uas.go precedent as
// sessiontimer_silent_stub.go: no rig change, no shared-fixture reuse (peer.go
// needs a *testing.T this package main binary has no way to supply).
//
// It binds a FIXED port (keepaliveStubAddr), not an ephemeral one: policy.yaml
// is a static file loaded at daemon startup, before this stub exists, so the
// e2e-uac-keepalive profile's registrar must name an address known in advance.
import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/emiago/sipgo/sip"
)

// keepaliveStubAddr matches e2e-uac-keepalive's `registrar` in policy.yaml.
const keepaliveStubAddr = "127.0.0.1:39310"

// keepaliveStub answers every REGISTER with 200 OK (accepting whatever Expires
// was requested — this stub never challenges) and every OPTIONS with 200 OK,
// counting the OPTIONS it observes.
type keepaliveStub struct {
	conn   net.PacketConn
	parser *sip.Parser
	done   chan struct{}

	mu      sync.Mutex
	options int
}

func startKeepaliveStub() (*keepaliveStub, error) {
	conn, err := net.ListenPacket("udp", keepaliveStubAddr)
	if err != nil {
		return nil, fmt.Errorf("keepaliveStub listen %s: %w", keepaliveStubAddr, err)
	}
	u := &keepaliveStub{conn: conn, parser: sip.NewParser(), done: make(chan struct{})}
	go u.serve()
	return u, nil
}

func (u *keepaliveStub) OptionsCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.options
}

func (u *keepaliveStub) Close() {
	select {
	case <-u.done:
		return
	default:
	}
	close(u.done)
	_ = u.conn.Close()
}

func (u *keepaliveStub) serve() {
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
		switch req.Method {
		case sip.REGISTER:
			res := sip.NewResponseFromRequest(req, 200, "OK", nil)
			expires := "60"
			if h := req.GetHeader("Expires"); h != nil {
				expires = h.Value()
			}
			host, portStr, _ := net.SplitHostPort(u.conn.LocalAddr().String())
			port, _ := strconv.Atoi(portStr)
			res.AppendHeader(&sip.ContactHeader{
				Address: sip.Uri{User: "e2e-uac-keepalive", Host: host, Port: port},
				Params:  sip.NewParams(),
			})
			res.AppendHeader(sip.NewHeader("Expires", expires))
			u.write(res, from)
		case sip.OPTIONS:
			u.mu.Lock()
			u.options++
			u.mu.Unlock()
			u.write(sip.NewResponseFromRequest(req, 200, "OK", nil), from)
		default:
			u.write(sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil), from)
		}
	}
}

func (u *keepaliveStub) write(res *sip.Response, to net.Addr) {
	_, _ = u.conn.WriteTo([]byte(res.String()), to)
}
