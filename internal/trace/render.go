package trace

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// NOTE THE ABSENCE OF sipgo. This file reads SCALARS off session.SIPRecord and
// renders them; it parses nothing. sipua's ObservingConn extracted every field
// below at the socket seam, which is why session.SIPRecord can be a plain
// struct — and why `session`, and therefore transport/mcp, stays free of sipgo
// (§14.2's transport-boundary test).

// view is the renderer-neutral projection of a tap record. All three
// renderers read it, so "what a message is called" is decided once.
type view struct {
	OffsetMs   int64
	Direction  session.Direction
	Label      string // "INVITE" or "200 OK"
	Method     string
	Code       int
	Reason     string
	Remote     string
	Serialized string
	Fidelity   string
	Codecs     []string
	FromUser   string
	ToUser     string
}

func project(recs []session.SIPRecord) []view {
	out := make([]view, 0, len(recs))
	if len(recs) == 0 {
		return out
	}
	first := recs[0].At
	for _, rec := range recs {
		v := view{
			OffsetMs:   rec.At.Sub(first).Milliseconds(),
			Direction:  rec.Direction,
			Method:     rec.Method,
			Code:       rec.StatusCode,
			Reason:     rec.Reason,
			Remote:     rec.RemoteAddr,
			Serialized: rec.Serialized,
			Fidelity:   rec.Fidelity,
			Codecs:     rec.SDPCodecs,
			// FromURI/ToURI carry the RAW header value — e.g.
			// "<sip:alice@example>;tag=t1" — not a bare URI (D168): the
			// producer at the socket seam extracts the header verbatim, and
			// uriUser below is the only consumer, so stripping the name-addr
			// wrapper here would be speculative work for a field nothing
			// else reads (Rule 15).
			FromUser: uriUser(rec.FromURI),
			ToUser:   uriUser(rec.ToURI),
		}
		// SIPRecord.Serialized is ALWAYS SET by the producer, and Fidelity
		// records how. D9d: on the seam-backed paths it holds the OBSERVED WIRE
		// BYTES and Fidelity is "byte_exact". P2 W2c's byte-preserving stream
		// framer extends the same seam to tcp/tls, so their capture is
		// OBSERVED (byte_exact) too, same as UDP — not the re-serialised
		// "canonical" form once expected here.
		//
		// The two defaults below cover a producer that set Raw but left
		// Serialized or Fidelity empty. The renderer NEVER invents the bytes: it
		// has no parser and no message to re-serialise, which is precisely the
		// point of moving extraction to the socket seam.
		if v.Serialized == "" && len(rec.Raw) > 0 {
			v.Serialized = string(rec.Raw)
		}
		if v.Fidelity == "" {
			if len(rec.Raw) > 0 {
				v.Fidelity = "byte_exact"
			} else {
				v.Fidelity = "canonical"
			}
		}
		// Request or response is decided by WHICH SCALAR the producer set:
		// Method is "" on a response, StatusCode is 0 on a request.
		if rec.Method != "" {
			v.Label = rec.Method
		} else {
			v.Label = fmt.Sprintf("%d %s", rec.StatusCode, rec.Reason)
		}
		out = append(out, v)
	}
	return out
}

// uriUser pulls the user part out of a SIP URI for the lane labels. It is
// string handling, not SIP parsing — the URIs arrive already extracted, and
// the codec list arrives as SIPRecord.SDPCodecs rather than being re-derived
// from a body this package no longer sees. FromURI/ToURI carry the raw
// header value (D168), so this cuts on "sip:" then "@" and survives both a
// bare URI and a full name-addr like "<sip:alice@example>;tag=t1".
func uriUser(uri string) string {
	_, rest, ok := strings.Cut(uri, "sip:")
	if !ok {
		return ""
	}
	user, _, ok := strings.Cut(rest, "@")
	if !ok {
		return ""
	}
	return user
}

// render dispatches on session.LadderFormat — NOT trace.Format/trace.Rendered,
// which are DELETED (Rule 18: the format enum lives in session, once, because
// session.Tap names both LadderFormat and Ladder and a local duplicate would
// stop Sink satisfying it).
func render(recs []session.SIPRecord, f session.LadderFormat) (string, error) {
	vs := project(recs)
	switch f {
	case session.LadderJSON:
		return renderJSON(vs)
	case session.LadderMermaid:
		return renderMermaid(vs), nil
	case session.LadderText, "":
		return renderText(vs), nil
	default:
		return "", apierr.InvalidArgument(
			fmt.Sprintf("unknown ladder format %q; want text, mermaid or json", f))
	}
}

type jsonMessage struct {
	OffsetMs   int64    `json:"offset_ms"`
	Direction  string   `json:"direction"`
	Method     string   `json:"method,omitempty"`
	Code       int      `json:"code,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Remote     string   `json:"remote"`
	Codecs     []string `json:"sdp_codecs,omitempty"`
	Serialized string   `json:"serialized"`
	Fidelity   string   `json:"fidelity"`
}

func renderJSON(vs []view) (string, error) {
	out := make([]jsonMessage, 0, len(vs))
	for _, v := range vs {
		out = append(out, jsonMessage{
			OffsetMs: v.OffsetMs, Direction: string(v.Direction),
			Method: v.Method, Code: v.Code, Reason: v.Reason,
			Remote: v.Remote, Codecs: v.Codecs,
			Serialized: v.Serialized, Fidelity: v.Fidelity,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("marshal ladder: %w", err)
	}
	return string(b), nil
}

// arrowWidth is the lane between the local column and the remote column.
//
// §10.13's worked example is ILLUSTRATIVE in its exact spacing — its own
// columns do not align to a single rule. This fixes a deterministic rule that
// reproduces its style and every property §10.13 says an assertion may rely
// on: millisecond offsets from the first message, U+25BA outbound and U+25C4
// inbound, and SDP codec lists annotated on offer and answer.
//
// P1 draws TWO lanes: the UA and the one remote it exchanged messages with.
// At P1 a call's records carry exactly one remote address per dialog, so
// §10.13's three-lane proxy example cannot arise and building for it would be
// a speculative abstraction (Rule 15).
const arrowWidth = 26

func renderText(vs []view) string {
	if len(vs) == 0 {
		return ""
	}
	var b strings.Builder

	b.WriteString(strings.Repeat(" ", 7))
	b.WriteString(padRunes("UA("+localUser(vs)+")", arrowWidth))
	b.WriteString(remoteLabel(vs))
	b.WriteByte('\n')

	for _, v := range vs {
		fmt.Fprintf(&b, "%6s ", fmt.Sprintf("%dms", v.OffsetMs))
		b.WriteString(arrowCell(v))
		if len(v.Codecs) > 0 {
			b.WriteString("  sdp: ")
			b.WriteString(strings.Join(v.Codecs, ","))
		}
		b.WriteByte('\n')
	}

	// NO media band: P1 has no media session and sends no RTP (§15's R14
	// split). P2 adds the band once the record set carries media frames.
	return b.String()
}

func arrowCell(v view) string {
	dashes := arrowWidth - len([]rune(v.Label)) - 2
	if dashes < 1 {
		dashes = 1
	}
	if v.Direction == session.Outbound {
		return v.Label + " " + strings.Repeat("─", dashes) + "►"
	}
	return "◄" + strings.Repeat("─", dashes) + " " + v.Label
}

func padRunes(s string, w int) string {
	n := len([]rune(s))
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func remoteLabel(vs []view) string {
	for _, v := range vs {
		if v.Remote != "" {
			return v.Remote
		}
	}
	return "peer"
}

// localUser labels the UA lane with this UA's own identity: the From user of
// the first outbound message, or the To user of the first inbound one.
func localUser(vs []view) string {
	for _, v := range vs {
		if v.Direction == session.Outbound && v.FromUser != "" {
			return v.FromUser
		}
		if v.Direction == session.Inbound && v.ToUser != "" {
			return v.ToUser
		}
	}
	return "local"
}

func renderMermaid(vs []view) string {
	var b strings.Builder
	b.WriteString("sequenceDiagram\n")
	if len(vs) == 0 {
		return b.String()
	}
	b.WriteString("    participant UA as " + mermaidSafe("UA("+localUser(vs)+")") + "\n")
	b.WriteString("    participant PEER as " + mermaidSafe(remoteLabel(vs)) + "\n")
	for _, v := range vs {
		arrow, from, to := "->>", "UA", "PEER"
		if v.Direction == session.Inbound {
			arrow, from, to = "-->>", "PEER", "UA"
		}
		label := fmt.Sprintf("%dms %s", v.OffsetMs, v.Label)
		if len(v.Codecs) > 0 {
			label += " (sdp: " + strings.Join(v.Codecs, ",") + ")"
		}
		b.WriteString("    " + from + arrow + to + ": " + mermaidSafe(label) + "\n")
	}
	return b.String()
}

// mermaidSafe strips the characters Mermaid mis-tokenises inside a label. SIP
// reason phrases are free text and can legally contain all three.
func mermaidSafe(s string) string {
	return strings.NewReplacer(";", ",", "\r", "", "\n", " ").Replace(s)
}
