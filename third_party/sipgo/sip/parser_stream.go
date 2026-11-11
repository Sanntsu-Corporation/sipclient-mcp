package sip

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

const (
	stateStartLine = 0
	stateHeader    = 1
	stateContent   = 2
	// stateParsed = 1
)

// ErrParseHeaderTooLarge is returned when a stream connection accumulates more
// than maxStreamHeaderBuf bytes without completing a message's start-line and
// header block.
//
// SIPCLIENT-MCP DIVERGENCE (Phase 4 W3, P4-W1-N05) — see VENDOR.md. It is a
// DISTINCT sentinel rather than a reuse of ErrParseSipPartial on purpose:
// "partial" means "send me more of this message", and after this error there is
// no message left to be partial about — the parser state has been dropped.
// transportTCP.parseStream (transport_tcp.go:222-236) special-cases only
// ErrParseSipPartial and otherwise iterates an empty msgs slice, so this error
// is handled exactly as every other non-partial parse error already is: the
// connection is left open and the next chunk starts a fresh message.
var ErrParseHeaderTooLarge = errors.New("SIP stream header accumulation exceeded the limit")

// maxStreamHeaderBuf bounds how many bytes a ParserStream will hold while it is
// still looking for the end of a message's start-line and headers.
//
// SIPCLIENT-MCP DIVERGENCE (Phase 4 W3, P4-W1-N05) — see VENDOR.md. Upstream
// v0.24.1 has no bound here at all: ParseSIPStream appends every chunk to
// p.reader, and when a header line has no CRLF yet it writes the whole unparsed
// remainder back and waits for more — so a peer that completes a TCP/TLS
// handshake and drip-feeds bytes containing no CRLF grows this buffer without
// limit (measured live: 32MB fed in, 32MB retained). Reachable unauthenticated
// on transport: tcp, and on transport: tls too, since the server config sets no
// ClientAuth.
//
// 64KB IS NOT A NEW NUMBER, AND MUST NOT DRIFT. It is the SAME bound this
// repository already chose for the identical hazard on its observation path —
// internal/sipua/observestream.go's maxHeaderBuf. It is restated here as a
// literal rather than imported because third_party/sipgo is a SEPARATE Go module
// (its own go.mod) and an internal/... package is unimportable from it in any
// case. If one of the two moves, move the other.
//
// It also sits just above transportBufferSize (65535, transport.go:38), the
// largest single read the TCP/TLS/UDP transports ever hand to ParseSIPStream, so
// no single legitimate read can trip it on its own.
const maxStreamHeaderBuf = 64 * 1024

var streamBufReader = sync.Pool{
	New: func() interface{} {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation:
		return new(bytes.Buffer)
	},
}

type ParserStream struct {
	// HeadersParsers uses default list of headers to be parsed. Smaller list parser will be faster
	headersParsers mapHeadersParser

	// runtime values
	reader            *bytes.Buffer
	msg               Message
	readContentLength int
	state             int
}

func (p *ParserStream) reset() {
	p.state = stateStartLine
	p.reader = nil
	p.msg = nil
	p.readContentLength = 0
}

// ParseSIPStream parsing messages comming in stream
// It has slight overhead vs parsing full message
func (p *ParserStream) ParseSIPStream(data []byte) (msgs []Message, err error) {
	if p.reader == nil {
		p.reader = streamBufReader.Get().(*bytes.Buffer)
		p.reader.Reset()
	}

	reader := p.reader
	reader.Write(data) // This should append to our already buffer

	unparsed := reader.Bytes() // TODO find a better way as we only want to move our offset

	parseSingle := func(reader *bytes.Buffer) (msg Message, err error) {

		// TODO change this with functions and store last function state
		switch p.state {
		case stateStartLine:
			startLine, err := nextLine(reader)

			if err != nil {
				if err == io.EOF {
					return nil, ErrParseLineNoCRLF
				}
				return nil, err
			}

			msg, err = parseLine(startLine)
			if err != nil {
				return nil, err
			}

			p.state = stateHeader
			p.msg = msg
			fallthrough
		case stateHeader:
			msg := p.msg
			for {
				line, err := nextLine(reader)

				if err != nil {
					if err == io.EOF {
						// No more to read
						return nil, ErrParseLineNoCRLF
					}
					return nil, err
				}

				if len(line) == 0 {
					// We've hit second CRLF
					break
				}

				err = p.headersParsers.parseMsgHeader(msg, line)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", err.Error(), ErrParseEOF)
					// log.Info().Err(err).Str("line", line).Msg("skip header due to error")
				}
				unparsed = reader.Bytes()
			}
			unparsed = reader.Bytes()

			// Grab content length header
			// TODO: Maybe this is not best approach
			hdrs := msg.GetHeaders("Content-Length")
			if len(hdrs) == 0 {
				// No body then
				return msg, nil
			}

			h := hdrs[0]

			// TODO: Have fast reference instead casting
			var contentLength int
			if clh, ok := h.(*ContentLengthHeader); ok {
				contentLength = int(*clh)
			} else {
				n, err := strconv.Atoi(h.Value())
				if err != nil {
					return nil, fmt.Errorf("fail to parse content length: %w", err)
				}
				contentLength = n
			}

			if contentLength <= 0 {
				return msg, nil
			}

			body := make([]byte, contentLength)
			msg.SetBody(body)

			p.state = stateContent
			fallthrough
		case stateContent:
			msg := p.msg
			body := msg.Body()
			contentLength := len(body)

			n, err := reader.Read(body[p.readContentLength:])
			unparsed = reader.Bytes()
			if err != nil {
				return nil, fmt.Errorf("read message body failed: %w", err)
			}
			p.readContentLength += n

			if p.readContentLength < contentLength {
				return nil, ErrParseReadBodyIncomplete
			}

			p.state = -1 // Clear state
			return msg, nil
		default:
			return nil, fmt.Errorf("Parser is in unknown state")
		}
	}

	for {
		msg, err := parseSingle(reader)
		switch err {
		case ErrParseLineNoCRLF, ErrParseReadBodyIncomplete:
			// SIPCLIENT-MCP DIVERGENCE (Phase 4 W3, P4-W1-N05): bound the header
			// accumulator. Checked HERE, on the partial-parse path, rather than
			// before parseSingle runs — p.state and unparsed must reflect what
			// THIS call's parse attempt actually consumed, not what stood before
			// it. A single call carrying a complete header block plus a large
			// legitimate body (a normal single-TCP-segment delivery, exercised by
			// internal/sipua's TestHardenedParserBoundary) reaches stateContent
			// and returns successfully inside parseSingle without ever taking
			// this switch arm at all, so it is never subject to the cap — a
			// pre-parse check computed on the raw, not-yet-parsed buffer length
			// could not tell that case apart from a genuine unbounded
			// no-CRLF header, because both start with p.state at its zero value
			// and a large reader.Len(). Below stateContent the buffer IS
			// un-drained (nextLine only consumes a line once its CRLF has
			// arrived, and this arm restores the whole unparsed remainder below,
			// unread, for the next call) — so a peer that never sends a CRLF
			// grows it forever unless this check stops it.
			//
			// unparsed, NOT reader.Len(). By this point nextLine's ReadString
			// scan has already partially drained reader looking for a '\r' that
			// never arrived, so reader.Len() no longer reflects how much data is
			// actually pending; unparsed is the exact snapshot that is about to
			// be written back below and carried into the next call, which is
			// the quantity that must be bounded.
			//
			// RESET, DON'T WEDGE. Parser state is dropped so the next chunk
			// starts a fresh message, and the oversized buffer is deliberately
			// NOT returned to streamBufReader: pooling an array a hostile peer
			// talked us into allocating would keep it alive for the life of the
			// process. p.reset() nils p.reader, so it becomes garbage
			// immediately.
			if p.state != stateContent && len(unparsed) > maxStreamHeaderBuf {
				p.reset()
				return nil, ErrParseHeaderTooLarge
			}
			reader.Reset()
			reader.Write(unparsed)
			return nil, ErrParseSipPartial
		}

		if err != nil {
			return nil, err
		}

		msgs = append(msgs, msg)
		if len(unparsed) == 0 {
			// Maybe we need to check did empty spaces left
			break
		}

		p.reset()
		reader.Reset()
		reader.Write(unparsed)
		p.reader = reader
	}

	// IN all other cases do reset
	streamBufReader.Put(reader)
	p.reset()

	return
}
