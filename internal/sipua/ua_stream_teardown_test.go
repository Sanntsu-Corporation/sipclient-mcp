package sipua

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestTCPTeardownClosesAcceptedConns is P2 W2c T6 (Task 6, Step 1): it proves
// UA.Close drains the sipgo transport pool so an ALREADY-ACCEPTED stream conn
// actually closes — not merely that the listener stops accepting new ones. A
// rebind check alone cannot see this (spec §8): the listener and the accepted
// conn are two different sockets, and closing only the former would leave the
// latter (and its peer) hanging forever. This asserts both, in the order the
// plan's Task 6 documents: (a) the accepted server-side conn closes (the
// client's Read unblocks with an error/EOF within a short deadline), and (b)
// the port is rebindable afterward (proving the listener itself also closed).
//
// Per the T2 closer (ua.go's newUAStream: listener.Close() -> <-serveDone ->
// agent.Close(), sync.Once-guarded — L8), this is expected to PASS with no
// production change: agent.Close() drains the sipgo pool, and the pool holds
// the accepted conn at ref-count 2 from accept time (initConnection), so
// pool.Clear() closes it without any SIP traffic ever having to flow.
func TestTCPTeardownClosesAcceptedConns(t *testing.T) {
	ua, err := New(context.Background(), Config{
		Transport: "tcp",
		LocalAddr: "127.0.0.1:0", // ephemeral to avoid port conflicts in CI
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("New(tcp): %v", err)
	}

	cli, err := net.Dial("tcp", ua.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial UA: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// initConnection runs synchronously in the accept loop right after
	// Accept() returns, so by the time Dial has returned successfully on the
	// client side, the TCP handshake completed and the server side is either
	// already accepted or about to be within microseconds. A brief settle
	// (rather than a fixed sleep guessing at that window) is sufficient here;
	// there is no application-level ready signal on this path (T2 deliberately
	// drops the udp readyConn barrier for streams, see newUAStream's comment).
	time.Sleep(50 * time.Millisecond)

	if err := ua.Close(context.Background()); err != nil {
		t.Fatalf("ua.Close: %v", err)
	}

	// A conn that was NEVER closed would also make cli.Read return a non-nil
	// error here — just a deadline-exceeded timeout, 2s later — so "err !=
	// nil" alone cannot distinguish a real close from a hang that merely
	// outlasts the deadline. The three checks below rule that false-pass out:
	// the error must not be a timeout, it must positively signal closure
	// (EOF or a closed/reset-style error), and it must arrive fast.
	start := time.Now()
	_ = cli.SetReadDeadline(start.Add(2 * time.Second))
	_, err = cli.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("accepted conn still open after Close — pool not drained")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("read timed out after %s — connection was never actually closed (teardown broken)", elapsed)
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("Read returned %v (elapsed %s), want io.EOF or a closed/reset error", err, elapsed)
	}
	// Teardown that actually drains the pool closes the accepted conn within
	// microseconds of ua.Close returning; a pass that took anywhere near the
	// 2s deadline would itself be suspicious evidence of a slow/racy path.
	if elapsed > time.Second {
		t.Fatalf("close took %s, want well under the 2s deadline", elapsed)
	}

	// Rebind proves the listener also closed (not just the accepted conn).
	ln, err := net.Listen("tcp", ua.LocalAddr().String())
	if err != nil {
		t.Fatalf("port not rebindable after Close: %v", err)
	}
	_ = ln.Close()
}
