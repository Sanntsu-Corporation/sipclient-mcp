package sipua

// Internal (package sipua) unit tests for the B1 (Phase 4 M1) hardened
// Content-Length parser — mirrors keepalive_internal_test.go's convention of
// a white-box test file for internals export_test.go does not need to expose
// to sipua_test.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// newHardenedTestStream builds a ParserStream through newHardenedSIPParser,
// the exact constructor ua.go's newUA/newUAStream wire in via
// sipgo.WithUserAgentParser, so criterion 1's test genuinely depends on that
// wiring (see mutation proof A).
func newHardenedTestStream() *sip.ParserStream {
	return newHardenedSIPParser().NewSIPStream()
}

// sipMessageWithContentLength builds a minimal well-formed SIP response
// carrying the given Content-Length value, with no body bytes appended. This
// is enough to observe the header-parse rejection: boundedContentLengthParser
// runs while headers are still being parsed (parser_stream.go's stateHeader),
// strictly before the framer would ever read or allocate a body.
func sipMessageWithContentLength(contentLength string) []byte {
	return []byte(strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.0.2.7:5060;branch=z9hG4bK.parserhardening",
		"From: <sip:alice@example.com>;tag=1928301774",
		"To: <sip:alice@example.com>;tag=registrar",
		"Call-ID: parserhardening-test",
		"CSeq: 1 REGISTER",
		"Content-Length: " + contentLength,
		"",
		"",
	}, "\r\n"))
}

// TestHardenedParserRejectsOversizedContentLength is B1 acceptance criterion
// 1: a stream built from the hardened parser rejects a peer-supplied
// Content-Length of 4294967295 (2^32-1, the max value upstream's
// strconv.ParseUint(..., 32) would otherwise accept) with a non-nil error
// naming both the observed value and the bound, before any body allocation.
func TestHardenedParserRejectsOversizedContentLength(t *testing.T) {
	stream := newHardenedTestStream()
	_, err := stream.ParseSIPStream(sipMessageWithContentLength("4294967295"))
	if err == nil {
		t.Fatal("expected an error rejecting an oversized Content-Length, got nil")
	}
	if !strings.Contains(err.Error(), "4294967295") {
		t.Fatalf("error %q does not name the observed value 4294967295", err.Error())
	}
	if !strings.Contains(err.Error(), strconv.Itoa(maxBodyLen)) {
		t.Fatalf("error %q does not name the bound %d", err.Error(), maxBodyLen)
	}
}

// wantMaxBodyLen is the boundary this test expects, pinned to a literal
// number rather than reading the maxBodyLen identifier on purpose (mutation
// proof B): if boundedContentLengthParser ever hardcoded its own "1 MiB"
// literal instead of reading maxBodyLen, this test's fixed expectation would
// stay put while the const moved, and the drift would show up as a failure
// here. Reading maxBodyLen dynamically for both the test input and the
// production bound would make this test blind to exactly that bug — it
// would silently track any duplicate literal. Keep this number equal to
// maxBodyLen's current value (1 * 1024 * 1024, observestream.go) whenever
// that const legitimately changes.
const wantMaxBodyLen = 1 * 1024 * 1024

// TestHardenedParserBoundary is B1 acceptance criterion 2: exactly
// maxBodyLen (1 MiB) is accepted (with a real, matching body read all the
// way through) and maxBodyLen+1 is rejected. It is also mutation proof B's
// target test (brief §Mutation proof B): flipping maxBodyLen in
// observestream.go must redden this test, or a duplicate literal is hiding
// somewhere instead of a single canonical bound.
func TestHardenedParserBoundary(t *testing.T) {
	t.Run("exactly maxBodyLen is accepted", func(t *testing.T) {
		stream := newHardenedTestStream()
		body := make([]byte, wantMaxBodyLen)
		for i := range body {
			body[i] = 'a'
		}
		full := append(sipMessageWithContentLength(strconv.Itoa(wantMaxBodyLen)), body...)

		msgs, err := stream.ParseSIPStream(full)
		if err != nil {
			t.Fatalf("expected Content-Length == maxBodyLen (%d) to be accepted, got error: %v", wantMaxBodyLen, err)
		}
		if len(msgs) != 1 {
			t.Fatalf("expected exactly 1 parsed message, got %d", len(msgs))
		}
		if len(msgs[0].Body()) != wantMaxBodyLen {
			t.Fatalf("expected body of length %d, got %d", wantMaxBodyLen, len(msgs[0].Body()))
		}
	})

	t.Run("maxBodyLen+1 is rejected", func(t *testing.T) {
		stream := newHardenedTestStream()
		_, err := stream.ParseSIPStream(sipMessageWithContentLength(strconv.Itoa(wantMaxBodyLen + 1)))
		if err == nil {
			t.Fatalf("expected Content-Length == maxBodyLen+1 (%d) to be rejected", wantMaxBodyLen+1)
		}
		// err != nil alone is not enough: no body bytes were sent, so if the
		// header parser wrongly ACCEPTED the value, ParseSIPStream would
		// still return a non-nil error (ErrParseSipPartial, from trying and
		// failing to read the not-sent body) — a false pass that would mask
		// the bound check never having fired at all. Pin the value AND the
		// bound in the message to prove it was the header-parse rejection,
		// not incomplete-body partial-parse, that produced this error.
		if err == sip.ErrParseSipPartial {
			t.Fatalf("got ErrParseSipPartial: Content-Length %d was ACCEPTED at header-parse time "+
				"(then failed on the absent body) instead of being rejected for exceeding the bound",
				wantMaxBodyLen+1)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(wantMaxBodyLen+1)) {
			t.Fatalf("error %q does not name the observed value %d", err.Error(), wantMaxBodyLen+1)
		}
	})
}

// TestHardenedParserDoesNotMutateGlobalDefaultHeadersParser is B1 acceptance
// criterion 3: constructing the hardened parser must not mutate the
// package-level default sip.DefaultHeadersParser() map. If it did, the
// global "content-length" entry would start rejecting values it used to
// accept (or vice versa), corrupting every other *sip.Parser in the process
// (including internal/sipengine's) and racing concurrent NewParser/NewUA
// calls.
func TestHardenedParserDoesNotMutateGlobalDefaultHeadersParser(t *testing.T) {
	_ = newHardenedHeadersParsers()

	parser, ok := sip.DefaultHeadersParser()["content-length"]
	if !ok {
		t.Fatal("content-length parser missing from sip.DefaultHeadersParser()")
	}
	if _, err := parser("content-length", "2000000"); err != nil {
		t.Fatalf("global content-length parser should still accept 2000000 (> maxBodyLen) unbounded, got: %v", err)
	}
}
