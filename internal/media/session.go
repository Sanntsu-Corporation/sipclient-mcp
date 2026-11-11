// Package media owns a call's SDP offer/answer negotiation and the SRTP-in-SDP
// seam. It performs NO RTP I/O (M3): the negotiated *Session is a data record
// internal/sipua stores on its dialog. W4 attaches RTP behind this same type.
package media

import (
	"net"
	"strconv"
	"strings"
)

// State is the media session lifecycle (M3). It is intentionally minimal at W3:
// no RTP ever moves it past StateNegotiated.
type State int

// State values enumerate a media session's lifecycle.
const (
	StateNegotiating State = iota
	StateNegotiated
	StateClosed
)

// CodecPrefs is an ordered codec preference list, e.g. ["PCMU","PCMA"]. The
// order is load-bearing on the ANSWER side (§10.3 rule 3): among the codecs a
// peer offered, our first preference wins.
type CodecPrefs []string

// SRTPPolicy is the SDES-SRTP policy one negotiation runs under (CF-170).
type SRTPPolicy string

// SRTPPolicy values: the UA's configured policy, or a per-call tightening of it.
const (
	SRTPDisabled SRTPPolicy = "disabled"
	SRTPOptional SRTPPolicy = "optional"
	SRTPRequired SRTPPolicy = "required"
)

// Direction is an SDP media direction attribute (RFC 3264 6.1).
type Direction string

// Direction values.
const (
	DirSendRecv Direction = "sendrecv"
	DirSendOnly Direction = "sendonly"
	DirRecvOnly Direction = "recvonly"
	DirInactive Direction = "inactive"
)

// Sends reports whether a stream with this (our) direction may carry our RTP.
// The zero value counts as sendrecv (the SDP default).
func (d Direction) Sends() bool { return d != DirRecvOnly && d != DirInactive }

// Origin is our own o= identity, kept so a later SDP of ours in the same
// dialog can reuse the session id and increment the version (RFC 3264 8).
type Origin struct {
	SessID  uint64
	Version uint64
}

// Stream is one m= line of a negotiation, in SDP order. An answer's Streams
// has exactly as many entries as the offer's m= lines.
type Stream struct {
	Media      string    // m= media type as offered ("audio", "video", ...)
	Proto      string    // m= transport protocol as written in OUR SDP for it
	RemoteAddr string    // the peer's host:port: its media-level c= over the session c=, its m= port
	LocalPort  int       // our m= port for it; 0 = rejected in our SDP
	Direction  Direction // OUR negotiated direction for it; DirInactive when rejected
}

// AnswerOptions are BuildAnswer's inputs other than the offer body.
type AnswerOptions struct {
	Prefs     CodecPrefs
	LocalAddr string // our host:port for the live stream
	SRTP      SRTPPolicy
	// Prev, when set, makes this an answer to a re-offer in an established
	// dialog: the o= line keeps Prev's session id and increments its version by
	// one (RFC 3264 8), and the SDES key we already use (Prev.LocalCrypto) is
	// kept rather than minted anew, so a published Session's LocalCrypto always
	// equals the live SRTP transform's key.
	Prev *Session
}

// Session is the outcome of a negotiation. LocalAddr/RemoteAddr are "host:port"
// SDP c=/m= addresses; Codec is the single selected codec ("" until answered).
// LocalCrypto is the SDES key WE generated and put in our own SDP (what the peer
// needs to decrypt what we send); RemoteCrypto is the key we parsed from the
// PEER's a=crypto line (what we need to decrypt what they send). Both are non-nil
// only when SRTP was negotiated; W4 feeds both into pion/srtp.
type Session struct {
	LocalAddr    string
	RemoteAddr   string
	Codec        string
	LocalCrypto  *CryptoParams
	RemoteCrypto *CryptoParams
	// TelephoneEventPT is the NEGOTIATED RFC 4733 telephone-event payload type,
	// or 0 when telephone-event was not negotiated on this dialog. On the
	// offering side BuildOffer proposes telephoneEventOfferPT and ParseAnswer
	// OVERWRITES this with what the peer actually accepted — 0 if it accepted
	// nothing, which is precisely what makes dtmf_send(mode="rfc2833") report
	// not_supported instead of silently downgrading (§10.8).
	TelephoneEventPT int

	Streams   []Stream  // every m= line, in order (an offerer's Session has exactly 1)
	Live      int       // index in Streams of the one live audio stream
	Direction Direction // == Streams[Live].Direction (DirInactive for a held or rejected stream)
	Origin    Origin    // our o= identity

	SendPT       int              // the PT we send Codec at (offer's number as answerer, answer's as offerer)
	RecvPTs      map[uint8]string // every audio PT we accept -> its codec name (PTs are 0-127 by construction)
	RecvEventPTs map[uint8]bool   // every telephone-event PT we accept (1-127)
	PeerEvents   map[uint8]bool   // event codes the peer accepts (its fmtp events list; nil = absent = 0-15)

	state   State
	srtp    SRTPPolicy
	offered CodecPrefs // what BuildOffer put on the wire; ParseAnswer reads it
}

// State reports the lifecycle state.
func (s *Session) State() State { return s.state }

// SRTPPolicy reports the policy this negotiation ran under (recorded by
// BuildOffer and BuildAnswer, kept by ParseAnswer). A later SDP of ours in the
// same dialog must use it, never the UA default, so a per-call tightening is
// never lost.
func (s *Session) SRTPPolicy() SRTPPolicy { return s.srtp }

// SendsMedia reports whether our RTP may go to the peer on the live stream:
// Direction.Sends(), and RemoteAddr has a specified IP and a non-zero port
// (RFC 3264 6 and 8.4). RemoteAddr is an IPv4 literal or unspecified (parseSDP
// refuses anything else).
func (s *Session) SendsMedia() bool {
	if !s.Direction.Sends() {
		return false
	}
	host, port, err := net.SplitHostPort(s.RemoteAddr)
	if err != nil || port == "" || port == "0" {
		return false
	}
	switch host {
	case "", "0.0.0.0", "::":
		return false
	}
	return true
}

// PeerAcceptsEvent reports whether the peer accepts event code. RFC 4733
// 2.5.1.1: with no events list the sender assumes 0-15 and nothing else.
func (s *Session) PeerAcceptsEvent(code uint8) bool {
	if s.PeerEvents == nil {
		return code <= 15
	}
	return s.PeerEvents[code]
}

// PeerEventsText renders the peer's accepted event codes for error messages,
// such as "0-11" or "0-3,7".
func (s *Session) PeerEventsText() string {
	var out []string
	for lo := 0; lo < 256; lo++ {
		if !s.PeerAcceptsEvent(uint8(lo)) {
			continue
		}
		hi := lo
		for hi+1 < 256 && s.PeerAcceptsEvent(uint8(hi+1)) {
			hi++
		}
		if hi == lo {
			out = append(out, strconv.Itoa(lo))
		} else {
			out = append(out, strconv.Itoa(lo)+"-"+strconv.Itoa(hi))
		}
		lo = hi
	}
	return strings.Join(out, ",")
}
