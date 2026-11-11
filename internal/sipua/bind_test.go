package sipua

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

func TestBindPacket_FallsBackToEphemeralWhenDefaultTaken(t *testing.T) {
	squatter, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	taken := squatter.LocalAddr().(*net.UDPAddr).Port
	addr := fmt.Sprintf("127.0.0.1:%d", taken)

	conn, err := bindPacket("udp", addr, false /*portExplicit*/, slog.Default())
	if err != nil {
		t.Fatalf("expected fallback bind, got err: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := conn.LocalAddr().(*net.UDPAddr).Port; got == taken {
		t.Errorf("bound the taken port %d; expected ephemeral fallback", taken)
	}
}

func TestBindPacket_ExplicitPinErrorsWhenTaken(t *testing.T) {
	squatter, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	taken := squatter.LocalAddr().(*net.UDPAddr).Port
	addr := fmt.Sprintf("127.0.0.1:%d", taken)

	_, err = bindPacket("udp", addr, true /*portExplicit*/, slog.Default())
	if err == nil {
		t.Fatal("expected invalid_argument for a taken explicit pinned port")
	}
	// apierr has NO classifier predicate (verified: internal/apierr exposes only
	// *apierr.Error{Code, Message} + constructors, Code const at apierr.go:22).
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) || apiErr.Code != apierr.CodeInvalidArgument {
		t.Errorf("err = %v; want *apierr.Error invalid_argument", err)
	}
}
