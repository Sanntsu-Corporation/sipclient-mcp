package sipua

// Phase 4 M1 B1 gap fix: parserhardening_test.go's tests build a
// sip.ParserStream through newHardenedSIPParser directly and never touch
// ua.go's newUA/newUAStream construction path — they cannot see a ua.go that
// silently dropped the sipgo.WithUserAgentParser call, and the Rule 9
// verifier proved exactly that by removing both call sites and finding
// every existing test still green. This file closes that gap: it builds a
// real *UA the same way New()/newUAStream does, drives a message with an
// oversized Content-Length through it over a real TCP socket exactly as a
// peer would, and proves the vulnerable allocation
// (third_party/sipgo/sip/parser_stream.go:135's
// `body := make([]byte, contentLength)`) never happens.

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// wiringMaliciousContentLength is comfortably over maxBodyLen (1 MiB) — a
// correctly-wired parser must reject it — and comfortably small enough to be
// a SAFE allocation for this test process to actually perform if the wiring
// turns out to be missing. This deliberately does NOT reuse
// parserhardening_test.go's 4294967295 edge value: that value is already
// mutation-proven in isolation (TestHardenedParserRejectsOversizedContentLength),
// and actually reaching parser_stream.go's make() call with it here — which
// is exactly what happens in this test's own mutation-proof run, see below
// — would attempt a ~4 GiB allocation. This test's job is narrower (prove
// the wiring reaches real UA construction), and any over-the-bound value
// proves that equally well.
const wiringMaliciousContentLength = 64 * 1024 * 1024 // 64 MiB

// wiringGrowthBudget is the heap-growth ceiling for "the malicious
// Content-Length was rejected before any body allocation". p3_r8_test.go's
// heapAfterGC (double-GC, reused below rather than reimplemented — Rule 16)
// documents a measured noise floor of a few KB on this package's test
// binary; 8 MiB is a >100x margin over that noise while still an order of
// magnitude below wiringMaliciousContentLength, so a real, unbounded
// make([]byte, wiringMaliciousContentLength) cannot land under it by
// accident.
const wiringGrowthBudget = 8 * 1024 * 1024 // 8 MiB

// TestHardenedParserWiredIntoRealUA is the B1 wiring-level mutation proof.
// It sends a well-formed SIP message declaring Content-Length:
// wiringMaliciousContentLength with NO body bytes attached, over a real TCP
// connection into a real *UA. A correctly-wired hardened parser rejects the
// header during parseMsgHeader, before parser_stream.go ever reaches
// stateContent's make([]byte, contentLength) — declared length or not, no
// body bytes need to actually arrive for that allocation to fire once the
// header is (wrongly) accepted, which is exactly the hazard B1 closes.
func TestHardenedParserWiredIntoRealUA(t *testing.T) {
	ua, err := New(context.Background(), Config{
		Transport: "tcp",
		LocalAddr: "127.0.0.1:0",
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("New(tcp): %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	cli, err := net.Dial("tcp", ua.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial UA: %v", err)
	}
	defer func() { _ = cli.Close() }()

	before := heapAfterGC()

	msg := sipMessageWithContentLength(strconv.Itoa(wiringMaliciousContentLength))
	if _, err := cli.Write(msg); err != nil {
		t.Fatalf("write malicious message: %v", err)
	}

	// The allocation this proves the ABSENCE of is a single, synchronous,
	// CPU-only make() call with no I/O wait on the server's read goroutine —
	// 500ms is a large margin over that, not a tight timing race.
	time.Sleep(500 * time.Millisecond)

	after := heapAfterGC()
	grew := after - before
	if grew > wiringGrowthBudget {
		t.Fatalf("heap grew by %d bytes (budget %d) after sending Content-Length: %d with no body — "+
			"the real UA's transport allocated the declared length instead of rejecting it, meaning "+
			"newUAStream is NOT wiring the hardened parser into real UA construction",
			grew, wiringGrowthBudget, wiringMaliciousContentLength)
	}
}
