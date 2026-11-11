package sipua

import (
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// newHardenedSIPParser returns a *sip.Parser whose Content-Length ("l")
// header parser rejects any value over maxBodyLen. Both newUA (udp) and
// newUAStream (tcp/tls) wire it in via sipgo.WithUserAgentParser so that
// ParserStream.ParseSIPStream (third_party/sipgo/sip/parser_stream.go:135)
// never sizes its `make([]byte, contentLength)` body allocation off an
// unbounded peer-supplied Content-Length (Phase 4 M1, B1).
//
// This relies on the 7th VENDOR.md divergence (parseMsgHeader's receiver-
// shadow fix in third_party/sipgo/sip/parse_header.go): without it,
// WithHeadersParsers/WithUserAgentParser's custom map is never consulted, so
// this constructor alone would provide no protection.
func newHardenedSIPParser() *sip.Parser {
	return sip.NewParser(sip.WithHeadersParsers(newHardenedHeadersParsers()))
}

// newHardenedHeadersParsers copies sip.DefaultHeadersParser() into a fresh
// map and overwrites the content-length/l entries with
// boundedContentLengthParser.
//
// DefaultHeadersParser (third_party/sipgo/sip/parse_header.go:65-67) returns
// the package-level headersParsers map itself, not a copy, and
// WithHeadersParsers assigns whatever map it is given straight onto the
// *Parser. Writing the bounded entries directly into the returned map would
// therefore mutate global sipgo state shared by every Parser in the process
// (including internal/sipengine's) and race any concurrent NewParser/NewUA.
// Copying into a fresh map first keeps the default global untouched.
func newHardenedHeadersParsers() map[string]sip.HeaderParser {
	defaults := sip.DefaultHeadersParser()
	m := make(map[string]sip.HeaderParser, len(defaults))
	maps.Copy(m, defaults)
	m["content-length"] = boundedContentLengthParser
	m["l"] = boundedContentLengthParser
	return m
}

// boundedContentLengthParser is a sip.HeaderParser for the "content-length"/
// "l" header. It parses the value exactly as upstream's
// headerParserContentLength does (strconv.ParseUint, bitSize 32) but then
// rejects any value exceeding maxBodyLen (observestream.go) — the same bound
// internal/sipua's stream framer already applies to the identical hazard, per
// Rule 16/18 (reuse the canonical bound, do not duplicate the literal).
func boundedContentLengthParser(_, headerText string) (sip.Header, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(headerText), 10, 32)
	if err != nil {
		return nil, err
	}
	if value > maxBodyLen {
		return nil, fmt.Errorf("content-length %d exceeds maximum %d", value, maxBodyLen)
	}
	h := sip.ContentLengthHeader(value)
	return &h, nil
}
