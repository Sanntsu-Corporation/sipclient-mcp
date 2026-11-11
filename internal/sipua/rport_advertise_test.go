package sipua_test

// rport_advertise_test.go is Task 2's regression: a digest-challenged
// REGISTER's retry Via must carry ;rport, not just the initial Via's. Before
// the fix (internal/sipengine/siptest/client.go's WithClientNAT()), sipgo
// only adds ;rport to a Via it REGENERATES itself — the digest retry's path
// (Via removed and rebuilt) — so the retry Via silently drops it while the
// initial Via (built once by the frozen builders.go and sent verbatim)
// keeps it. sipproxy is the sole oracle (Rule 6a-D1): assertions run off the
// ObservingConn tap's exact wire bytes, not sipgo's parsed Request objects.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/policy"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/sipproxy"
)

func TestChallengedRegisterAdvertisesRport(t *testing.T) {
	p := sipproxy.StartProxy(t, "127.0.0.1")
	defer p.Close()
	p.SetDigest("sipclient-test", "alice", policy.NewSecret("s3cr3t"))

	tap := &capturingTap{}
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.Addr(),
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  300,
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			return sipua.ObservingConn(pc, tap, session.TransportUDP, func() time.Time { return time.Unix(0, 0) }, "")
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !res.Registered || res.Code != 200 {
		t.Fatalf("Registered = %v, Code = %d, want true/200 (sipproxy accepts after the digest retry)", res.Registered, res.Code)
	}
	if got := p.ChallengeCount("alice"); got != 1 {
		t.Errorf("ChallengeCount(alice) = %d, want 1 (the challenge path must have been exercised)", got)
	}

	var registers []session.SIPRecord
	for _, rec := range tap.all() {
		if rec.Direction == session.Outbound && rec.Method == "REGISTER" {
			registers = append(registers, rec)
		}
	}
	if len(registers) != 2 {
		t.Fatalf("tap saw %d outbound REGISTERs, want exactly 2 (initial + digest retry)", len(registers))
	}

	assertViaHasRport := func(t *testing.T, raw []byte, label string) {
		t.Helper()
		via := ""
		for _, line := range strings.Split(string(raw), "\r\n") {
			if strings.HasPrefix(line, "Via:") {
				via = line
				break
			}
		}
		if via == "" {
			t.Fatalf("%s: no Via header found in:\n%s", label, raw)
		}
		if !strings.Contains(via, "rport") {
			t.Errorf("%s: Via %q lacks rport param", label, via)
		}
	}

	assertViaHasRport(t, registers[0].Raw, "initial REGISTER Via")
	assertViaHasRport(t, registers[1].Raw, "digest-retry REGISTER Via")
}
