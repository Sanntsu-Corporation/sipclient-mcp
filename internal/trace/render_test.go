package trace_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/trace"
)

const (
	tryingRaw = "SIP/2.0 100 Trying\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>\r\n" +
		"Call-ID: c-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"

	ringingRaw = "SIP/2.0 180 Ringing\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>;tag=t2\r\n" +
		"Call-ID: c-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"

	okRaw = "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-1;rport\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>;tag=t2\r\n" +
		"Call-ID: c-1\r\nCSeq: 1 INVITE\r\n" +
		"Contact: <sip:bob@192.0.2.10:5060>\r\n" +
		"Content-Type: application/sdp\r\nContent-Length: 136\r\n\r\n" +
		"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=peer\r\nc=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\nm=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

	ackRaw = "ACK sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-2;rport\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>;tag=t2\r\n" +
		"Call-ID: c-1\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"

	byeRaw = "BYE sip:bob@192.0.2.10:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-3;rport\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>;tag=t2\r\n" +
		"Call-ID: c-1\r\nCSeq: 2 BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"

	byeOKRaw = "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-3;rport\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>;tag=t2\r\n" +
		"Call-ID: c-1\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
)

var fixtureRaws = []string{inviteRaw, tryingRaw, ringingRaw, okRaw, ackRaw, byeRaw, byeOKRaw}

// fixture builds the seven-record ladder every renderer test shares: a
// complete outbound call, INVITE through BYE. The offsets are §10.13's, so
// the goldens are directly comparable to its worked example.
//
// EVERY FIELD IS SET BY HAND. Nothing here parses SIP, because the renderer
// never sees a sip.Message — sipua's ObservingConn extracts these scalars at
// the socket seam and the renderer's whole input is this struct. That is the
// property that makes the canonical-fallback case below expressible at all.
func fixture(t *testing.T) *trace.Sink {
	t.Helper()
	s := trace.New(0, 0)
	base := time.Unix(1000, 0)

	type spec struct {
		dir    session.Direction
		method string // "" on a response
		code   int    // 0 on a request
		reason string
		cseq   string
		codecs []string
	}
	specs := []spec{
		{session.Outbound, "INVITE", 0, "", "1 INVITE", []string{"PCMU"}},
		{session.Inbound, "", 100, "Trying", "1 INVITE", nil},
		{session.Inbound, "", 180, "Ringing", "1 INVITE", nil},
		{session.Inbound, "", 200, "OK", "1 INVITE", []string{"PCMU"}},
		{session.Outbound, "ACK", 0, "", "1 ACK", nil},
		{session.Outbound, "BYE", 0, "", "2 BYE", nil},
		{session.Inbound, "", 200, "OK", "2 BYE", nil},
	}
	offsets := []int64{0, 4, 812, 3104, 3106, 33210, 33255}
	ctx := context.Background()
	for i, raw := range fixtureRaws {
		s.SIPMessage(ctx, session.SIPRecord{
			At:        base.Add(time.Duration(offsets[i]) * time.Millisecond),
			Direction: specs[i].dir, Transport: session.TransportUDP,
			LocalAddr: "127.0.0.1:5066", RemoteAddr: "192.0.2.10:5060",
			CallID: "c-1", CSeq: specs[i].cseq,
			Method: specs[i].method, StatusCode: specs[i].code, Reason: specs[i].reason,
			FromURI: "sip:alice@example", ToURI: "sip:bob@example",
			SDPCodecs:  specs[i].codecs,
			Serialized: raw, Raw: []byte(raw), Fidelity: "byte_exact",
		})
	}
	return s
}

type jsonMsg struct {
	OffsetMs   int64    `json:"offset_ms"`
	Direction  string   `json:"direction"`
	Method     string   `json:"method"`
	Code       int      `json:"code"`
	Reason     string   `json:"reason"`
	Remote     string   `json:"remote"`
	Codecs     []string `json:"sdp_codecs"`
	Serialized string   `json:"serialized"`
	Fidelity   string   `json:"fidelity"`
}

func jsonLadder(t *testing.T, s *trace.Sink) []jsonMsg {
	t.Helper()
	got, err := s.Ladder(context.Background(), "", "c-1", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	var msgs []jsonMsg
	if err := json.Unmarshal([]byte(got.Rendered), &msgs); err != nil {
		t.Fatalf("json ladder does not parse: %v\n%s", err, got.Rendered)
	}
	return msgs
}

func TestJSONLadderSerializedAndFidelity(t *testing.T) {
	msgs := jsonLadder(t, fixture(t))
	if len(msgs) != 7 {
		t.Fatalf("got %d messages, want 7", len(msgs))
	}
	// §10.13: offsets are milliseconds FROM THE FIRST MESSAGE.
	if msgs[0].OffsetMs != 0 {
		t.Errorf("first offset = %d, want 0", msgs[0].OffsetMs)
	}
	if msgs[3].OffsetMs != 3104 {
		t.Errorf("fourth offset = %d, want 3104", msgs[3].OffsetMs)
	}
	if msgs[6].OffsetMs != 33255 {
		t.Errorf("last offset = %d, want 33255", msgs[6].OffsetMs)
	}
	for i, m := range msgs {
		// D9d is NORMATIVE: on UDP, `serialized` holds the OBSERVED WIRE BYTES
		// and fidelity is byte_exact. The roadmap's "(D9d canonical form)"
		// note is wrong; this is the assertion that pins the correction.
		if m.Fidelity != "byte_exact" {
			t.Errorf("message %d: fidelity = %q, want \"byte_exact\" on UDP", i, m.Fidelity)
		}
		if m.Serialized != fixtureRaws[i] {
			t.Errorf("message %d: serialized is not the observed octets", i)
		}
	}
	if msgs[0].Method != "INVITE" || msgs[0].Code != 0 {
		t.Errorf("request rendered as method=%q code=%d, want INVITE/0", msgs[0].Method, msgs[0].Code)
	}
	if msgs[1].Code != 100 || msgs[1].Reason != "Trying" || msgs[1].Method != "" {
		t.Errorf("response rendered as method=%q code=%d reason=%q, want \"\"/100/Trying", msgs[1].Method, msgs[1].Code, msgs[1].Reason)
	}
	if msgs[0].Direction != "outbound" || msgs[1].Direction != "inbound" {
		t.Errorf("directions = %q/%q, want outbound/inbound", msgs[0].Direction, msgs[1].Direction)
	}
	// SDP codec lists are carried on the offer and the answer, and nowhere else.
	if !reflect.DeepEqual(msgs[0].Codecs, []string{"PCMU"}) {
		t.Errorf("offer codecs = %v, want [PCMU]", msgs[0].Codecs)
	}
	if !reflect.DeepEqual(msgs[3].Codecs, []string{"PCMU"}) {
		t.Errorf("answer codecs = %v, want [PCMU]", msgs[3].Codecs)
	}
	if len(msgs[1].Codecs) != 0 {
		t.Errorf("100 Trying carries codecs %v, want none", msgs[1].Codecs)
	}
}

// R12's acceptance: on EITHER fidelity, re-parsing `serialized` yields a
// message SEMANTICALLY EQUAL to the one exchanged — same method or code,
// header values, SDP. THAT is what an assertion may ALWAYS rely on. A
// byte-level assertion is valid ONLY where fidelity is byte_exact, which is
// why the byte-equality check below is gated on that field.
func TestLadderSerializedReparsesSemanticallyEqual(t *testing.T) {
	msgs := jsonLadder(t, fixture(t))
	// The re-parse is done with the STDLIB, not sipgo: internal/trace must not
	// import sipgo (importguard asserts it), and a textproto read is enough to
	// establish that `serialized` is a well-formed SIP message whose start line
	// and headers survived the round trip. R12's acceptance is SEMANTIC
	// equality, and that is what this checks.
	for i, m := range msgs {
		start, headers, body := splitSIPMessage(t, m.Serialized)
		wantStart, wantHeaders, wantBody := splitSIPMessage(t, fixtureRaws[i])

		if start != wantStart {
			t.Errorf("message %d: start line %q, want %q", i, start, wantStart)
		}
		for _, h := range []string{"Via", "From", "To", "Call-ID", "CSeq", "Contact", "Content-Type"} {
			g, gok := headers[strings.ToLower(h)]
			w, wok := wantHeaders[strings.ToLower(h)]
			if gok != wok {
				t.Errorf("message %d: header %s presence differs", i, h)
				continue
			}
			if gok && g != w {
				t.Errorf("message %d: header %s = %q, want %q", i, h, g, w)
			}
		}
		if body != wantBody {
			t.Errorf("message %d: SDP body differs\n--- got ---\n%s\n--- want ---\n%s", i, body, wantBody)
		}
		// The projected scalars must agree with the message they claim to
		// describe — the renderer's own consistency, which matters more now
		// that nothing downstream re-parses to check it.
		if m.Method != "" && !strings.HasPrefix(start, m.Method+" ") {
			t.Errorf("message %d: method %q does not match start line %q", i, m.Method, start)
		}
		if m.Code != 0 && !strings.HasPrefix(start, "SIP/2.0 "+strconv.Itoa(m.Code)+" ") {
			t.Errorf("message %d: code %d does not match start line %q", i, m.Code, start)
		}
		// Byte-level assertion, sound ONLY where fidelity is byte_exact — and
		// a test making one must assert that field FIRST, which it does here.
		if m.Fidelity == "byte_exact" && m.Serialized != fixtureRaws[i] {
			t.Errorf("message %d: byte_exact serialized differs from the observed octets", i)
		}
	}
}

// splitSIPMessage is a deliberately minimal SIP splitter: start line, a
// lower-cased header map, and the body. It exists so this package can assert
// on message structure WITHOUT importing sipgo (contract Part 1.3).
func splitSIPMessage(t *testing.T, raw string) (start string, headers map[string]string, body string) {
	t.Helper()
	head, body, found := strings.Cut(raw, "\r\n\r\n")
	if !found {
		t.Fatalf("message has no header/body separator:\n%q", raw)
	}
	lines := strings.Split(head, "\r\n")
	headers = map[string]string{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}
	return lines[0], headers, body
}

// The canonical branch is not reachable through any P1 integration path (UDP
// always sets Raw), so it is driven directly here with a HAND-BUILT record.
//
// This test is the clearest payoff of moving ObservingConn to internal/sipua:
// when `serialized` had to come from a parsed sip.Message, constructing "a
// record with no Raw but a valid canonical rendering" meant parsing a fixture
// just to re-serialise it. Now it is three scalar fields.
func TestLadderCanonicalFallbackWhenRawIsAbsent(t *testing.T) {
	s := trace.New(0, 0)
	s.SIPMessage(context.Background(), session.SIPRecord{
		At: time.Unix(0, 0), Direction: session.Outbound, Transport: session.TransportTCP,
		CallID: "c-1", Method: "INVITE", CSeq: "1 INVITE",
		FromURI: "sip:alice@example", ToURI: "sip:bob@example",
		Serialized: inviteRaw, Raw: nil, Fidelity: "canonical",
	})
	msgs := jsonLadder(t, s)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Fidelity != "canonical" {
		t.Errorf("fidelity = %q, want \"canonical\" when Raw is nil", msgs[0].Fidelity)
	}
	if msgs[0].Serialized != inviteRaw {
		t.Error("canonical serialized does not carry the record's Serialized field")
	}
	// D9d's per-transport table: canonical fidelity arises only where no socket
	// seam exists — dialled TCP and TLS. It must NEVER appear on UDP, which is
	// P1's only transport, and the fixture above asserts that for all seven.
}

func TestTextLadderMatchesGolden(t *testing.T) {
	ctx := context.Background()
	got, err := fixture(t).Ladder(ctx, "", "c-1", session.LadderText)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "ladder_text.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got.Rendered != string(want) {
		t.Errorf("text ladder differs from golden\n--- got ---\n%s\n--- want ---\n%s", got.Rendered, want)
	}
}

// §10.13 names the properties an assertion may rely on. They are asserted
// SEPARATELY from the golden so a deliberate spacing change cannot silently
// drop one of them.
func TestTextLadderProperties(t *testing.T) {
	ctx := context.Background()
	got, err := fixture(t).Ladder(ctx, "", "c-1", session.LadderText)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	body := got.Rendered
	for _, want := range []string{
		"0ms",     // offsets are ms from the FIRST message...
		"33255ms", // ...and therefore relative, not absolute
		"►",       // -> outbound
		"◄",       // <- inbound
		"INVITE",
		"200 OK",
		"UA(alice)",
		"192.0.2.10:5060",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("text ladder missing %q\n%s", want, body)
		}
	}
	// SDP codec lists are annotated on the OFFER and the ANSWER — exactly two.
	if n := strings.Count(body, "sdp: PCMU"); n != 2 {
		t.Errorf("want exactly 2 sdp annotations (offer and answer), got %d\n%s", n, body)
	}
	// P1 has NO media session and sends NO RTP (§15's R14 split), so a P1 call
	// renders NO media band. A band reading "0 pkt tx / 0 rx" would be read as
	// a MEASURED zero rather than an ABSENT measurement — precisely the
	// assertion P1's exit criterion says it must never invite.
	for _, forbidden := range []string{"media", "pkt", "═"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("P1 ladder contains %q; P1 has no media session and renders no media band\n%s", forbidden, body)
		}
	}
	// Two lanes at P1: the UA and the one remote it exchanged messages with.
	header := strings.SplitN(body, "\n", 2)[0]
	if strings.Count(header, ":") != 1 {
		t.Errorf("header names %d remotes, want exactly 1 (P1 draws two lanes): %q", strings.Count(header, ":"), header)
	}
}

// "Parses cleanly as a sequenceDiagram" is asserted STRUCTURALLY rather than
// by running a Mermaid parser: there is no Go Mermaid parser in the tree and
// adding one is a Rule 17 dependency gate this task does not open. The
// assertion is that the first line is the diagram directive and that EVERY
// subsequent line matches one of the two grammatical forms Mermaid accepts
// here — a participant declaration or a message arrow — with no stray text
// and no character Mermaid would mis-tokenise.
func TestMermaidLadderIsAWellFormedSequenceDiagram(t *testing.T) {
	ctx := context.Background()
	got, err := fixture(t).Ladder(ctx, "", "c-1", session.LadderMermaid)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	lines := strings.Split(strings.TrimRight(got.Rendered, "\n"), "\n")
	if len(lines) == 0 || lines[0] != "sequenceDiagram" {
		t.Fatalf("first line = %q, want \"sequenceDiagram\"", lines[0])
	}
	participant := regexp.MustCompile(`^    participant [A-Za-z0-9_]+ as .+$`)
	message := regexp.MustCompile(`^    [A-Za-z0-9_]+(->>|-->>)[A-Za-z0-9_]+: .+$`)
	participants, messages := 0, 0
	for i, line := range lines[1:] {
		switch {
		case participant.MatchString(line):
			participants++
		case message.MatchString(line):
			messages++
		default:
			t.Errorf("line %d is neither a participant nor a message: %q", i+2, line)
		}
	}
	if participants != 2 {
		t.Errorf("participants = %d, want 2 (the UA and its one remote)", participants)
	}
	if messages != 7 {
		t.Errorf("messages = %d, want 7", messages)
	}
	for _, line := range lines {
		if strings.ContainsAny(line, ";\r") {
			t.Errorf("line contains a character Mermaid would mis-tokenise: %q", line)
		}
	}
	// The offsets and the SDP annotation survive into the mermaid form.
	if !strings.Contains(got.Rendered, "0ms INVITE") {
		t.Errorf("mermaid ladder lost the offset/label pairing:\n%s", got.Rendered)
	}
	if n := strings.Count(got.Rendered, "sdp: PCMU"); n != 2 {
		t.Errorf("mermaid sdp annotations = %d, want 2\n%s", n, got.Rendered)
	}
}

func TestMermaidLadderEscapesAHostileReasonPhrase(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0)
	// A reason phrase is FREE TEXT and may legally contain a semicolon. The
	// record is hand-built, so the hostile value goes straight into the field
	// the renderer reads — no fixture parsing in between to sanitise it by
	// accident, which is a strictly stronger test than the parsed version.
	const hostile = "SIP/2.0 486 Busy; here\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-9\r\n" +
		"From: <sip:alice@example>;tag=t1\r\nTo: <sip:bob@example>;tag=t2\r\n" +
		"Call-ID: c-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	s.SIPMessage(ctx, session.SIPRecord{
		At: time.Unix(0, 0), Direction: session.Inbound, Transport: session.TransportUDP,
		RemoteAddr: "192.0.2.10:5060", CallID: "c-1", CSeq: "1 INVITE",
		StatusCode: 486, Reason: "Busy; here",
		FromURI: "sip:alice@example", ToURI: "sip:bob@example",
		Serialized: hostile, Raw: []byte(hostile), Fidelity: "byte_exact",
	})
	got, err := s.Ladder(ctx, "", "c-1", session.LadderMermaid)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	if strings.Contains(got.Rendered, ";") {
		t.Errorf("a semicolon from a SIP reason phrase reached the mermaid output:\n%s", got.Rendered)
	}
}

func TestLadderFormatValidation(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	for _, f := range []session.LadderFormat{session.LadderText, session.LadderMermaid, session.LadderJSON, ""} {
		if _, err := s.Ladder(ctx, "", "c-1", f); err != nil {
			t.Errorf("Ladder(format=%q) = %v, want nil (\"\" defaults to text)", f, err)
		}
	}
	for _, f := range []session.LadderFormat{"TEXT", "Text", "html", "pcap", "json "} {
		if _, err := s.Ladder(ctx, "", "c-1", f); err == nil {
			t.Errorf("Ladder(format=%q) succeeded; want invalid_argument", f)
		}
	}
	if _, err := s.Ladder(ctx, "", "no-such-call", session.LadderText); err == nil {
		t.Error("Ladder on an unknown call succeeded; want not_found")
	}
}

// D9a: THE LADDER IS UNCONDITIONAL — always on, no arming, no enable flag, no
// policy key. This asserts THE PROPERTY, not the absence of a method name: a
// brand-new Sink that has never been armed by anything records the very first
// message it is handed and renders it.
//
// The method-name check this replaces could not survive session.Tap requiring
// ArmCapture/DisarmCapture — but the property it protected is real, so it is
// asserted directly instead of dropped.
func TestLadderRecordsWithoutArming(t *testing.T) {
	ctx := context.Background()
	s := trace.New(0, 0) // nothing is armed, enabled or started on this Sink

	s.SIPMessage(ctx, rec(time.Unix(0, 0), session.Outbound, "c-9", "INVITE", inviteRaw))

	got, err := s.Ladder(ctx, "", "c-9", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder on a never-armed Sink: %v — D9a makes the ladder unconditional", err)
	}
	if got.Messages != 1 {
		t.Errorf("Messages = %d, want 1; the first message must be recorded with no prior arming", got.Messages)
	}
	// And it stays unconditional AFTER an arming attempt — a SUCCESSFUL
	// ArmCapture must equally not gate the ladder: the two switches are
	// independent in both directions.
	_ = s.ArmCapture(ctx, "", "c-9", nopWC{}, session.CaptureConfig{})
	s.SIPMessage(ctx, rec(time.Unix(0, 1), session.Inbound, "c-9", "", tryingRaw))
	got, err = s.Ladder(ctx, "", "c-9", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder after ArmCapture: %v", err)
	}
	if got.Messages != 2 {
		t.Errorf("Messages = %d, want 2; a successful ArmCapture must not gate the ladder", got.Messages)
	}
}

// nopWC is a package-local no-op io.WriteCloser for tests that need to arm a
// capture without asserting on its written bytes.
type nopWC struct{}

func (nopWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopWC) Close() error                { return nil }

// TestArmCaptureRejectsUnsupportedModes is the complementary assertion, and
// the one that actually protects D9b: W2 captures signaling/plaintext only
// (TestCaptureStreamsPerCallScoped in sink_test.go covers the success path),
// so scope="media"/"both" and payload_mode="ciphertext" must still report
// not_supported. THEY MUST NOT RETURN A SILENT NIL — a silent no-op is
// indistinguishable from a working capture, and a caller that believed it had
// armed one would get an empty file with no error to explain it.
func TestArmCaptureRejectsUnsupportedModes(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)

	var ae *apierr.Error
	err := s.ArmCapture(ctx, "", "c-1", nopWC{}, session.CaptureConfig{Scope: "media"})
	if !errors.As(err, &ae) || ae.Code != apierr.CodeNotSupported {
		t.Errorf("ArmCapture(scope=media) = %v, want *apierr.Error with code not_supported (never a silent nil)", err)
	}
	err = s.ArmCapture(ctx, "", "c-2", nopWC{}, session.CaptureConfig{Scope: "signaling", PayloadMode: "ciphertext"})
	if !errors.As(err, &ae) || ae.Code != apierr.CodeNotSupported {
		t.Errorf("ArmCapture(payload_mode=ciphertext) = %v, want *apierr.Error with code not_supported", err)
	}
}

// R1's acceptance: the ladder shows EXACTLY REGISTER -> 401 -> REGISTER ->
// 200. Task 14 asserted that sequence AT THE SOCKET; this asserts the
// RENDERING of it, which is what an agent consumes. The two halves together
// discharge R1's registration clause.
func TestLadderRendersRegisterChallengeRetry(t *testing.T) {
	const (
		registerRaw = "REGISTER sip:registrar.example SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-r1;rport\r\n" +
			"From: <sip:alice@example>;tag=t1\r\nTo: <sip:alice@example>\r\n" +
			"Call-ID: r-1\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 70\r\n" +
			"Contact: <sip:alice@127.0.0.1:5066>\r\nExpires: 300\r\nContent-Length: 0\r\n\r\n"

		unauthorizedRaw = "SIP/2.0 401 Unauthorized\r\n" +
			"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-r1;rport\r\n" +
			"From: <sip:alice@example>;tag=t1\r\nTo: <sip:alice@example>;tag=s1\r\n" +
			"Call-ID: r-1\r\nCSeq: 1 REGISTER\r\n" +
			"WWW-Authenticate: Digest realm=\"sipclient-test\", nonce=\"n1\", algorithm=MD5, qop=\"auth\"\r\n" +
			"Content-Length: 0\r\n\r\n"

		registerAuthRaw = "REGISTER sip:registrar.example SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-r2;rport\r\n" +
			"From: <sip:alice@example>;tag=t1\r\nTo: <sip:alice@example>\r\n" +
			"Call-ID: r-1\r\nCSeq: 2 REGISTER\r\nMax-Forwards: 70\r\n" +
			"Authorization: Digest username=\"alice\", realm=\"sipclient-test\", nonce=\"n1\", " +
			"uri=\"sip:registrar.example\", response=\"deadbeefdeadbeefdeadbeefdeadbeef\", algorithm=MD5\r\n" +
			"Contact: <sip:alice@127.0.0.1:5066>\r\nExpires: 300\r\nContent-Length: 0\r\n\r\n"

		registerOKRaw = "SIP/2.0 200 OK\r\n" +
			"Via: SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-r2;rport\r\n" +
			"From: <sip:alice@example>;tag=t1\r\nTo: <sip:alice@example>;tag=s1\r\n" +
			"Call-ID: r-1\r\nCSeq: 2 REGISTER\r\n" +
			"Contact: <sip:alice@127.0.0.1:5066>\r\nExpires: 300\r\nContent-Length: 0\r\n\r\n"
	)

	s := trace.New(0, 0)
	base := time.Unix(0, 0)
	raws := []string{registerRaw, unauthorizedRaw, registerAuthRaw, registerOKRaw}
	dirs := []session.Direction{session.Outbound, session.Inbound, session.Outbound, session.Inbound}
	methods := []string{"REGISTER", "", "REGISTER", ""}
	codes := []int{0, 401, 0, 200}
	reasons := []string{"", "Unauthorized", "", "OK"}
	ctx := context.Background()
	for i, raw := range raws {
		s.SIPMessage(ctx, session.SIPRecord{
			At: base.Add(time.Duration(i*3) * time.Millisecond), Direction: dirs[i],
			Transport: session.TransportUDP,
			LocalAddr: "127.0.0.1:5066", RemoteAddr: "192.0.2.10:5060",
			CallID: "r-1", CSeq: "1 REGISTER",
			Method: methods[i], StatusCode: codes[i], Reason: reasons[i],
			FromURI: "sip:alice@example", ToURI: "sip:alice@example",
			Serialized: raw, Raw: []byte(raw), Fidelity: "byte_exact",
		})
	}

	got, err := s.Ladder(ctx, "", "r-1", session.LadderJSON)
	if err != nil {
		t.Fatalf("Ladder: %v", err)
	}
	var msgs []jsonMsg
	if err := json.Unmarshal([]byte(got.Rendered), &msgs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"REGISTER", "401", "REGISTER", "200"}
	if len(msgs) != len(want) {
		t.Fatalf("ladder has %d messages, want EXACTLY %d (REGISTER -> 401 -> REGISTER -> 200)", len(msgs), len(want))
	}
	for i, w := range want {
		label := msgs[i].Method
		if label == "" {
			label = strconv.Itoa(msgs[i].Code)
		}
		if label != w {
			t.Errorf("ladder[%d] = %q, want %q", i, label, w)
		}
	}
	// The text form shows the same four messages and no others.
	text, err := s.Ladder(ctx, "", "r-1", session.LadderText)
	if err != nil {
		t.Fatalf("Ladder(text): %v", err)
	}
	if n := strings.Count(text.Rendered, "REGISTER"); n != 2 {
		t.Errorf("text ladder shows %d REGISTERs, want 2\n%s", n, text.Rendered)
	}
	if !strings.Contains(text.Rendered, "401 Unauthorized") || !strings.Contains(text.Rendered, "200 OK") {
		t.Errorf("text ladder is missing the 401 or the 200\n%s", text.Rendered)
	}
	// D6: the digest RESPONSE is a hash and the password appears nowhere.
	for _, forbidden := range []string{"s3cr3t", "password"} {
		if strings.Contains(got.Rendered, forbidden) || strings.Contains(text.Rendered, forbidden) {
			t.Errorf("ladder leaks %q (D6)", forbidden)
		}
	}
}
