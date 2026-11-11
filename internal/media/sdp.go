package media

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Static payload-type table. This harness speaks only the two G.711 codecs; a
// static PT lets us map a peer's m= line even when it omits a=rtpmap for a
// static type. Any other static type is treated as an unknown payload type.
var codecToPT = map[string]int{"PCMU": 0, "PCMA": 8}
var ptToCodec = map[int]string{0: "PCMU", 8: "PCMA"}

func payloadType(codec string) (int, bool) { pt, ok := codecToPT[codec]; return pt, ok }
func codecForPT(pt int) (string, bool)     { c, ok := ptToCodec[pt]; return c, ok }

// telephoneEventOfferPT is the dynamic payload type BuildOffer PROPOSES for
// RFC 4733 telephone-event. It mirrors codec.DTMFPayloadType; the constant is
// restated here rather than imported because internal/media deliberately does
// not depend on internal/media/codec (this file speaks SDP text, not audio).
// TestTelephoneEventOfferPTMatchesCodecConstant pins the two constants equal
// so a future change to either one is caught immediately instead of silently
// diverging.
const telephoneEventOfferPT = 101

func profileFor(srtp bool) string {
	if srtp {
		return "RTP/SAVP"
	}
	return "RTP/AVP"
}

func splitHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("media addr %q is not host:port: %w", addr, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("media addr %q has a non-numeric port: %w", addr, err)
	}
	return h, port, nil
}

// BuildOffer renders an outbound SDP offer advertising every codec in prefs (in
// order), from localAddr's host:port, in RTP/AVP or (under SRTPRequired) RTP/SAVP
// with a fresh a=crypto. The returned Session records the local address, the
// offered codec list (ParseAnswer validates against it), any crypto and the
// SRTP policy the negotiation runs under.
func BuildOffer(prefs CodecPrefs, localAddr string, srtp SRTPPolicy) ([]byte, *Session, error) {
	// required offers RTP/SAVP; optional offers RTP/AVP plus an a=crypto line,
	// the one shape that lets a peer answer plain RTP without a transport
	// mismatch (A-6).
	srtpRequired := srtp == SRTPRequired
	offerCrypto := srtp != SRTPDisabled && srtp != ""
	if len(prefs) == 0 {
		return nil, nil, fmt.Errorf("BuildOffer: empty codec prefs")
	}
	host, port, err := splitHostPort(localAddr)
	if err != nil {
		return nil, nil, err
	}
	pts := make([]string, 0, len(prefs))
	rtpmaps := make([]string, 0, len(prefs))
	for _, c := range prefs {
		pt, ok := payloadType(c)
		if !ok {
			return nil, nil, fmt.Errorf("BuildOffer: unsupported codec %q", c)
		}
		pts = append(pts, strconv.Itoa(pt))
		rtpmaps = append(rtpmaps, fmt.Sprintf("a=rtpmap:%d %s/8000\r\n", pt, c))
	}
	// telephone-event is offered UNCONDITIONALLY: this UA always wants RFC 2833
	// available, and a peer that declines it simply omits it from the answer
	// (ParseAnswer then zeroes Session.TelephoneEventPT). Offering it costs one
	// payload type and two attribute lines.
	pts = append(pts, strconv.Itoa(telephoneEventOfferPT))
	rtpmaps = append(rtpmaps,
		fmt.Sprintf("a=rtpmap:%d telephone-event/8000\r\n", telephoneEventOfferPT),
		fmt.Sprintf("a=fmtp:%d 0-15\r\n", telephoneEventOfferPT))
	sess := &Session{LocalAddr: localAddr, state: StateNegotiating, offered: append(CodecPrefs{}, prefs...), TelephoneEventPT: telephoneEventOfferPT, srtp: srtp,
		Direction: DirSendRecv, Origin: Origin{SessID: 1, Version: 1}}
	sess.Streams = []Stream{{Media: "audio", Proto: profileFor(srtpRequired), LocalPort: port, Direction: DirSendRecv}}

	var b strings.Builder
	b.WriteString("v=0\r\n")
	fmt.Fprintf(&b, "o=- 1 1 IN IP4 %s\r\n", host)
	b.WriteString("s=sipclient-mcp\r\n")
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", host)
	b.WriteString("t=0 0\r\n")
	fmt.Fprintf(&b, "m=audio %d %s %s\r\n", port, profileFor(srtpRequired), strings.Join(pts, " "))
	for _, r := range rtpmaps {
		b.WriteString(r)
	}
	if offerCrypto {
		cp, line, err := GenerateCryptoAttr()
		if err != nil {
			return nil, nil, err
		}
		sess.LocalCrypto = &cp
		b.WriteString(line + "\r\n")
	}
	b.WriteString("a=sendrecv\r\n")
	return []byte(b.String()), sess, nil
}

// sdpStream is one m= line of an SDP body with the attributes that follow it.
type sdpStream struct {
	media   string   // "audio", "video", ...
	port    int      // the m= port (the "/<n>" port-count suffix is dropped)
	proto   string   // "RTP/AVP" | "RTP/SAVP" | ...
	fmts    []string // the raw format fields of the m= line, in order
	host    string   // its own c= address, else the session's (RFC 4566 5.7)
	dir     Direction
	codecs  []string       // resolved codec names of the numeric formats, in m= order
	ptOf    map[string]int // the stream's first payload type for each codec name
	ptName  map[int]string // every audio payload type of the m= line and its codec name
	fmtp    map[int]string // a=fmtp value (text after "<pt> ") per payload type
	cryptos []string       // every a=crypto line of the stream, in order
	// teEventPT is the stream's telephone-event/8000 payload type listed on its
	// m= line, 0 when absent.
	teEventPT int
}

// sdpDesc is a parsed SDP body: the first t= line verbatim and every stream.
type sdpDesc struct {
	timeLine string // first t= line without CRLF, "" when there is none
	streams  []sdpStream
}

// firstAudio returns the first audio stream (CF-153: a later m=audio never
// replaces it) or nil.
func (d *sdpDesc) firstAudio() *sdpStream {
	for i := range d.streams {
		if d.streams[i].media == "audio" {
			return &d.streams[i]
		}
	}
	return nil
}

// sdpTypeLetters is RFC 4566 5's complete set of type letters.
const sdpTypeLetters = "vosiuepcbzkatrm"

// parseSDP parses an SDP body per stream (RFC 4566): c=, a=rtpmap, a=crypto and
// the direction attribute belong to the m= line they follow, and a stream's own
// c= overrides the session's. A line whose type letter is not one of the 15 of
// RFC 4566 5 makes the whole description unusable (CF-148). It returns an
// error for a malformed m= line, an unknown type letter, or a body with no m=.
// It also refuses (CF-201) a c=IN IP4 host that is not a usable IPv4 literal
// (see peerAddrError; local is our media host:port) and an m= port that is not
// 1 to 5 digits with value 0..65535; every line is checked, including those of
// a stream we would reject, and one bad line makes the whole SDP invalid.
func parseSDP(body []byte, local string) (sdpDesc, error) {
	var d sdpDesc
	var sessHost string
	sessDir := DirSendRecv
	var cur *sdpStream
	var curDir Direction
	var curHost string
	var rtpmap map[int]string
	var teEventPTs map[int]bool // every telephone-event PT of the stream, at ANY clock rate
	var te8000 int              // first telephone-event/8000 PT in 1..127
	finish := func() {
		if cur == nil {
			return
		}
		if curHost != "" {
			cur.host = curHost
		} else {
			cur.host = sessHost
		}
		cur.dir = curDir
		cur.ptOf = map[string]int{}
		cur.ptName = map[int]string{}
		if cur.dir == "" {
			cur.dir = sessDir
		}
		// A telephone-event rtpmap only counts if its PT is on this stream's
		// own m= line; a leftover rtpmap with no matching format is not an offer.
		for _, f := range cur.fmts {
			pt, err := strconv.Atoi(f)
			if err != nil || pt < 0 || pt > 127 {
				continue // a PT outside 0..127 would wrap in uint8
			}
			if pt == te8000 {
				cur.teEventPT = pt
			}
			if teEventPTs[pt] {
				continue // not an audio codec, at any clock rate
			}
			name, ok := rtpmap[pt]
			if !ok {
				if name, ok = codecForPT(pt); !ok {
					continue
				}
			}
			cur.codecs = append(cur.codecs, name)
			cur.ptName[pt] = name
			if _, seen := cur.ptOf[name]; !seen {
				cur.ptOf[name] = pt
			}
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		// RFC 4566 5: a line is text ending in CRLF. A bare CR or a control byte
		// would be echoed into our answer (t= and rejected m= lines are mirrored).
		if strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
			return sdpDesc{}, fmt.Errorf("SDP line with a control character: %q", line)
		}
		if len(line) < 2 || line[1] != '=' || !strings.ContainsRune(sdpTypeLetters, rune(line[0])) {
			return sdpDesc{}, fmt.Errorf("SDP line with an unknown type letter: %q", line)
		}
		val := line[2:]
		switch line[0] {
		case 't':
			if d.timeLine == "" {
				d.timeLine = line
			}
		case 'c':
			if h, ok := strings.CutPrefix(line, "c=IN IP4 "); ok {
				h = strings.TrimSpace(h)
				if err := peerAddrError(h, local); err != nil {
					return sdpDesc{}, err
				}
				if cur == nil {
					sessHost = h
				} else {
					curHost = h
				}
			}
		case 'm':
			finish()
			f := strings.Fields(val)
			if len(f) < 3 {
				return sdpDesc{}, fmt.Errorf("malformed m= line: %q", line)
			}
			portStr, _, _ := strings.Cut(f[1], "/") // RFC 4566 5.14 port-count suffix
			p, err := parseSDPPort(portStr)
			if err != nil {
				return sdpDesc{}, fmt.Errorf("m= port invalid: %q", line)
			}
			d.streams = append(d.streams, sdpStream{media: f[0], port: p, proto: f[2], fmts: f[3:], fmtp: map[int]string{}})
			cur = &d.streams[len(d.streams)-1]
			curDir, curHost, rtpmap, teEventPTs, te8000 = "", "", map[int]string{}, map[int]bool{}, 0
		case 'a':
			attr := val
			switch attr {
			case "sendrecv", "sendonly", "recvonly", "inactive":
				if cur == nil {
					sessDir = Direction(attr)
				} else {
					curDir = Direction(attr)
				}
				continue
			}
			if cur == nil {
				continue // a=rtpmap before any m= belongs to no stream
			}
			if rest, ok := strings.CutPrefix(attr, "rtpmap:"); ok {
				f := strings.Fields(rest)
				if len(f) < 2 {
					continue
				}
				pt, err := strconv.Atoi(f[0])
				if err != nil {
					continue
				}
				name, rateStr, ok := strings.Cut(f[1], "/")
				if !ok {
					continue
				}
				rtpmap[pt] = name
				if strings.EqualFold(name, "telephone-event") {
					teEventPTs[pt] = true
					// Only an 8000 Hz entry within the valid RTP payload-type
					// range is negotiable: the DTMF machinery (codec.dtmfSampleRate)
					// is hardcoded to 8kHz, and the 1-127 bound rejects a
					// peer-supplied PT before it is echoed into our own SDP.
					if rate, err := strconv.Atoi(rateStr); err == nil && rate == 8000 && pt >= 1 && pt <= 127 && te8000 == 0 {
						te8000 = pt
					}
				}
			} else if rest, ok := strings.CutPrefix(attr, "fmtp:"); ok {
				ptStr, value, _ := strings.Cut(rest, " ")
				if pt, err := strconv.Atoi(ptStr); err == nil {
					cur.fmtp[pt] = strings.TrimSpace(value)
				}
			} else if strings.HasPrefix(attr, "crypto:") {
				cur.cryptos = append(cur.cryptos, line)
			}
		}
	}
	finish()
	if len(d.streams) == 0 {
		return sdpDesc{}, fmt.Errorf("no m= line in SDP")
	}
	return d, nil
}

// parseSDPPort accepts a port only as 1 to 5 ASCII digits with value 0..65535
// (RFC 4566 9: port = 1*DIGIT; a sign is not part of the grammar).
func parseSDPPort(s string) (int, error) {
	if len(s) > 5 || !isDigits(s) {
		return 0, fmt.Errorf("port %q is not 1 to 5 digits", s)
	}
	p, _ := strconv.Atoi(s)
	if p > 65535 {
		return 0, fmt.Errorf("port %d is out of range", p)
	}
	return p, nil
}

// peerAddrError reports why host, the token after "c=IN IP4 ", cannot be a
// peer's media address, or nil. local is our media host:port: a loopback host
// is accepted only when it is loopback too (CF-201/210, LA-1). 0.0.0.0 stays
// valid as hold (RFC 3264 8.4).
func peerAddrError(host, local string) error {
	a, err := netip.ParseAddr(host)
	if err != nil || !a.Is4() {
		return fmt.Errorf("c= address %q is not an IPv4 literal", host)
	}
	if a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("c= address %q is multicast or broadcast", host)
	}
	if a.IsLoopback() {
		lh, _, _ := net.SplitHostPort(local)
		if la, lerr := netip.ParseAddr(lh); lerr != nil || !la.IsLoopback() {
			return fmt.Errorf("c= address %q is loopback and our media address %q is not", host, local)
		}
	}
	return nil
}

// BuildAnswer answers the peer's offer stream by stream (RFC 3264 6): the first
// audio stream with a non-zero port that passes the SRTP rule and shares a codec
// with us is the live one, and OUR preference order picks its codec (§10.3 rule
// 3); every other m= line is answered with port 0. On failure it returns a
// *NegotiationError whose Detail() names 488 as the response the caller must
// put on the wire.
func BuildAnswer(offer []byte, opts AnswerOptions) ([]byte, *Session, error) {
	prefs, localAddr := opts.Prefs, opts.LocalAddr
	desc, err := parseSDP(offer, localAddr)
	if err != nil || desc.firstAudio() == nil {
		// An answer-side unparseable/absent offer is not in W3's answer-side
		// taxonomy (§11.2 lists only no_common_codec / srtp_required_but_peer_
		// offered_avp there); a malformed inbound offer with no common codec
		// collapses to no_common_codec with an empty offered set.
		return nil, nil, NoCommonCodec(nil, []string(prefs))
	}

	live, chosen := -1, ""
	srtpRefused, disabledRefused := false, false
	refusedProto := ""
	var offeredCodecs []string
	for i := range desc.streams {
		st := &desc.streams[i]
		if st.media != "audio" || st.port == 0 {
			continue
		}
		for _, c := range st.codecs { // distinct: the list reaches the 488 detail
			if !slices.Contains(offeredCodecs, c) {
				offeredCodecs = append(offeredCodecs, c)
			}
		}
		// SRTP policy (decision table, A-5/A-6): checked before the codec match.
		switch usable := answerSRTPUsable(opts.SRTP, st); usable {
		case srtpRefusedNoKeys:
			srtpRefused, refusedProto = true, st.proto
			continue
		case srtpRefusedDisabled:
			disabledRefused = true
			continue
		}
		for _, c := range prefs {
			if _, ok := st.ptOf[c]; ok {
				live, chosen = i, c
				break
			}
		}
		if live >= 0 {
			break
		}
	}
	if live < 0 {
		if srtpRefused {
			return nil, nil, SRTPPeerOfferedAVP(opts.SRTP, refusedProto)
		}
		if disabledRefused {
			return nil, nil, SRTPOfferedButDisabled()
		}
		return nil, nil, NoCommonCodec(offeredCodecs, []string(prefs))
	}
	info := &desc.streams[live]

	host, port, err := splitHostPort(localAddr)
	if err != nil {
		return nil, nil, err
	}
	origin := Origin{Version: 1}
	if opts.Prev != nil {
		origin = Origin{SessID: opts.Prev.Origin.SessID, Version: opts.Prev.Origin.Version + 1}
	} else {
		sessID, err := randomSessionID()
		if err != nil {
			return nil, nil, err
		}
		origin.SessID = sessID
	}
	pt := info.ptOf[chosen]
	ansDir := ourDirection(info)
	sess := &Session{
		LocalAddr:        localAddr,
		RemoteAddr:       net.JoinHostPort(info.host, strconv.Itoa(info.port)),
		Codec:            chosen,
		srtp:             opts.SRTP,
		state:            StateNegotiated,
		TelephoneEventPT: info.teEventPT,
		Live:             live,
		Direction:        ansDir,
		Origin:           origin,
		// We send at the OFFER's number (RFC 3264 6.1) and accept only it.
		SendPT:       pt,
		RecvPTs:      map[uint8]string{uint8(pt): chosen},
		RecvEventPTs: map[uint8]bool{},
	}
	if info.teEventPT != 0 {
		sess.RecvEventPTs[uint8(info.teEventPT)] = true
		sess.PeerEvents = parseEvents(info.fmtp[info.teEventPT])
	}

	var b strings.Builder
	b.WriteString("v=0\r\n")
	fmt.Fprintf(&b, "o=- %d %d IN IP4 %s\r\n", origin.SessID, origin.Version, host)
	b.WriteString("s=sipclient-mcp\r\n")
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", host)
	if desc.timeLine != "" {
		b.WriteString(desc.timeLine + "\r\n")
	} else {
		b.WriteString("t=0 0\r\n")
	}
	for i := range desc.streams {
		st := &desc.streams[i]
		remote := net.JoinHostPort(st.host, strconv.Itoa(st.port))
		if i != live {
			// A rejected stream: port 0, the offered proto and formats (RFC 3264 6).
			fmts := strings.Join(st.fmts, " ")
			if fmts == "" {
				fmts = "0"
			}
			fmt.Fprintf(&b, "m=%s 0 %s %s\r\n", st.media, st.proto, fmts)
			sess.Streams = append(sess.Streams, Stream{Media: st.media, Proto: st.proto, RemoteAddr: remote, Direction: DirInactive})
			continue
		}
		proto := profileFor(info.proto == "RTP/SAVP")
		sess.Streams = append(sess.Streams, Stream{Media: "audio", Proto: proto, RemoteAddr: remote, LocalPort: port, Direction: ansDir})
		if info.teEventPT != 0 {
			fmt.Fprintf(&b, "m=audio %d %s %d %d\r\n", port, proto, pt, info.teEventPT)
		} else {
			fmt.Fprintf(&b, "m=audio %d %s %d\r\n", port, proto, pt)
		}
		fmt.Fprintf(&b, "a=rtpmap:%d %s/8000\r\n", pt, chosen)
		if info.teEventPT != 0 {
			// Mirror the OFFERER's payload type rather than imposing our own: RFC
			// 4733 leaves the number to negotiation and a peer that offered 96 will
			// send and expect 96.
			fmt.Fprintf(&b, "a=rtpmap:%d telephone-event/8000\r\n", info.teEventPT)
			fmt.Fprintf(&b, "a=fmtp:%d 0-15\r\n", info.teEventPT)
		}
		if rcp, tag, ok := answerPeerCrypto(opts.SRTP, info); ok {
			// Retain the peer's actual key material (RemoteCrypto) — W4 needs it to
			// decrypt what the peer sends. answerSRTPUsable guaranteed it parses
			// whenever the policy needs it.
			sess.RemoteCrypto = &rcp
			var cp CryptoParams
			var line string
			if opts.Prev != nil && opts.Prev.LocalCrypto != nil {
				cp = *opts.Prev.LocalCrypto // the key the live transform already uses
			} else {
				var err error
				if cp, _, err = GenerateCryptoAttr(); err != nil {
					return nil, nil, err
				}
			}
			line = cp.attrLine(tag) // echo the accepted line's tag
			sess.LocalCrypto = &cp
			b.WriteString(line + "\r\n")
		}
		fmt.Fprintf(&b, "a=%s\r\n", ansDir)
	}
	return []byte(b.String()), sess, nil
}

type srtpVerdict int

const (
	srtpUsable          srtpVerdict = iota
	srtpRefusedNoKeys               // policy needs SRTP and the stream offers no usable crypto
	srtpRefusedDisabled             // policy disabled and the stream is RTP/SAVP
)

// answerSRTPUsable applies the BuildAnswer rows of the SRTP decision table to
// one offered audio stream.
func answerSRTPUsable(policy SRTPPolicy, st *sdpStream) srtpVerdict {
	_, _, haveKeys := pickCrypto(st.cryptos, "")
	savp := st.proto == "RTP/SAVP"
	switch policy {
	case SRTPRequired:
		if !savp || !haveKeys {
			return srtpRefusedNoKeys
		}
	case SRTPOptional:
		if savp && !haveKeys {
			return srtpRefusedNoKeys
		}
	default: // disabled
		if savp {
			return srtpRefusedDisabled
		}
	}
	return srtpUsable
}

// answerPeerCrypto returns the peer's key and the tag of its line when this
// negotiation runs SRTP on st: required, or optional with a usable a=crypto
// line (RTP/SAVP or RTP/AVP).
func answerPeerCrypto(policy SRTPPolicy, st *sdpStream) (CryptoParams, string, bool) {
	if policy != SRTPRequired && policy != SRTPOptional {
		return CryptoParams{}, "", false
	}
	return pickCrypto(st.cryptos, "")
}

// pickCrypto returns the first of lines that parseCryptoLine accepts and, when
// tag is not empty, whose tag equals it (RFC 4568 5.1.2: the answerer takes the
// first supported line; 5.1.3: the offerer checks the tag it offered).
func pickCrypto(lines []string, tag string) (cp CryptoParams, gotTag string, ok bool) {
	for _, l := range lines {
		t, c, err := parseCryptoLine(l)
		if err == nil && (tag == "" || t == tag) {
			return c, t, true
		}
	}
	return CryptoParams{}, "", false
}

// randomSessionID returns a crypto-random o= session id below 2^63 (some
// parsers read it as an int64), so an answer's origin differs from the offer's
// (RFC 3264 6, CF-143).
func randomSessionID() (uint64, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("session id: %w", err)
	}
	return binary.BigEndian.Uint64(raw[:]) &^ (1 << 63), nil
}

// mirrorDirection is the RFC 3264 6.1 matrix: our direction for a stream the
// peer describes with d (sendonly <-> recvonly; sendrecv and inactive map to
// themselves).
func mirrorDirection(d Direction) Direction {
	switch d {
	case DirSendOnly:
		return DirRecvOnly
	case DirRecvOnly:
		return DirSendOnly
	}
	return d
}

// ourDirection is our direction for the stream st of a peer SDP: inactive when
// the peer's connection address is 0.0.0.0 (RFC 3264 8.4, A-8), else the
// mirror of its direction.
func ourDirection(st *sdpStream) Direction {
	if st.host == "0.0.0.0" {
		return DirInactive
	}
	return mirrorDirection(st.dir)
}

// ParseAnswer validates a peer's 200 OK SDP against the offer we sent
// (offerSess), per §11.2.1. It returns a *NegotiationError — whose Detail()
// carries action:"ack_then_bye" and sip_response_sent:null — when the body is
// absent, unparseable, answers a codec we did not offer, rejects our only audio
// stream (port 0, answer_rejected_audio), or downgrades an SRTP offer to plain
// RTP/AVP. On success it fills
// offerSess.Codec/RemoteAddr and advances it to StateNegotiated.
func ParseAnswer(offerSess *Session, answerBody []byte) (*Session, error) {
	srtpRequired := offerSess.srtp == SRTPRequired
	srtpOptional := offerSess.srtp == SRTPOptional
	if len(answerBody) == 0 {
		return nil, SDPAbsent()
	}
	desc, err := parseSDP(answerBody, offerSess.LocalAddr)
	if err != nil {
		return nil, SDPUnparseable()
	}
	// The answer's stream at the live index answers our live stream (RFC 3264 6:
	// one m= line per offered stream; the live index is 0 for an initial offer).
	live := offerSess.Live
	if live < 0 || live >= len(desc.streams) {
		return nil, SDPUnparseable()
	}
	// RFC 3264 6: the answer has the same number of m= lines as the offer, in the
	// same order; one that omits trailing streams is malformed. Extra streams are
	// ignored (locked policy).
	if len(desc.streams) < len(offerSess.Streams) {
		return nil, SDPUnparseable()
	}
	info := &desc.streams[live]
	if info.media != "audio" {
		return nil, SDPUnparseable()
	}
	if info.port == 0 {
		// Rejected: any formats on the line are ignored (RFC 3264 6), so this
		// is checked before the SRTP and codec rules.
		return nil, AnswerRejectedAudio()
	}
	// SRTP downgrade check.
	if srtpRequired && (info.proto != "RTP/SAVP" || len(info.cryptos) == 0) {
		return nil, SRTPPeerAnsweredAVP()
	}
	// optional: an answer with a=crypto means SRTP, so the line must parse (the
	// peer will encrypt; plain RTP would be undecipherable, A-6).
	// An RTP/SAVP answer without a key is not plain RTP either: the peer believes
	// the stream is secure, so it is refused rather than run in the clear.
	if srtpOptional && info.proto == "RTP/SAVP" && len(info.cryptos) == 0 {
		return nil, SDPUnparseable()
	}
	var peerKey *CryptoParams
	if srtpRequired || srtpOptional && len(info.cryptos) > 0 {
		// RFC 4568 5.1.3: the answer must echo the tag we offered.
		rcp, _, ok := pickCrypto(info.cryptos, offerCryptoTag)
		if !ok {
			if srtpRequired {
				return nil, SRTPPeerAnsweredAVP()
			}
			return nil, SDPUnparseable()
		}
		peerKey = &rcp
	}
	offered := map[string]bool{}
	for _, c := range offerSess.offered {
		offered[c] = true
	}
	var chosen string
	for _, c := range info.codecs {
		if offered[c] {
			chosen = c
			break
		}
	}
	if chosen == "" {
		return nil, AnswerCodecNotOffered([]string(offerSess.offered), info.codecs)
	}
	offerSess.Codec = chosen
	offerSess.RemoteAddr = net.JoinHostPort(info.host, strconv.Itoa(info.port))
	// New slices, never a write into the ones offerSess came with: the
	// applyAckAnswer value copy shares them with the dialog's session.
	proto, localPort := info.proto, 0
	if live < len(offerSess.Streams) {
		proto, localPort = offerSess.Streams[live].Proto, offerSess.Streams[live].LocalPort
	}
	// RFC 3264 5.1: we send at the answer's numbers but must be ready to receive
	// at both ours and the answer's for every codec the answer lists (CF-155),
	// and likewise for telephone-event (CF-154).
	recvPTs := map[uint8]string{}
	// Our offer's numbers first, so a collision with an answer alias resolves the
	// same way on every run (RFC 3264: the peer sends at the offer's numbers).
	for _, c := range info.codecs {
		if !offered[c] {
			continue
		}
		if opt, ok := payloadType(c); ok {
			recvPTs[uint8(opt)] = c
		}
	}
	for _, f := range info.fmts { // every alias the answer maps, in m= order
		pt, err := strconv.Atoi(f)
		c, ok := info.ptName[pt]
		if err != nil || !ok || !offered[c] {
			continue
		}
		if _, taken := recvPTs[uint8(pt)]; !taken {
			recvPTs[uint8(pt)] = c
		}
	}
	recvEventPTs := map[uint8]bool{}
	if info.teEventPT != 0 {
		recvEventPTs[uint8(info.teEventPT)] = true
		// The payload type we offered telephone-event at (a re-offer reuses the
		// live one, RFC 3264 5.1); 101 for a Session that does not record it.
		offeredEventPT := telephoneEventOfferPT
		if offerSess.TelephoneEventPT != 0 {
			offeredEventPT = offerSess.TelephoneEventPT
		}
		recvEventPTs[uint8(offeredEventPT)] = true
		// An audio codec the answer maps to an event PT stays audio.
		for pt := range recvPTs {
			delete(recvEventPTs, pt)
		}
	}
	offerSess.SendPT, offerSess.RecvPTs, offerSess.RecvEventPTs = info.ptOf[chosen], recvPTs, recvEventPTs
	offerSess.PeerEvents = nil
	if info.teEventPT != 0 {
		offerSess.PeerEvents = parseEvents(info.fmtp[info.teEventPT])
	}
	offerSess.Direction = ourDirection(info)
	// Every offered stream is kept, only the live one replaced (a re-offer may have
	// rejected streams at other indexes); a one-stream offer yields one stream.
	streams := append([]Stream(nil), offerSess.Streams...)
	liveStream := Stream{Media: "audio", Proto: proto, RemoteAddr: offerSess.RemoteAddr, LocalPort: localPort, Direction: offerSess.Direction}
	if live < len(streams) {
		streams[live] = liveStream
	} else {
		streams, offerSess.Live = []Stream{liveStream}, 0
	}
	offerSess.Streams = streams
	// Retain the peer's parsed key material (RemoteCrypto), parsed with the SAME
	// ParseCryptoAttr as the answer side. offerSess.LocalCrypto was set by
	// BuildOffer. An optional offer answered without a=crypto falls back to
	// plain RTP: the local key is dropped so nothing reports SRTP.
	offerSess.RemoteCrypto = peerKey
	if peerKey == nil && srtpOptional {
		offerSess.LocalCrypto = nil
	}
	// The peer's answer is authoritative: it either accepted telephone-event
	// (at its own PT) or it did not, and BuildOffer's proposal must not survive
	// a refusal.
	offerSess.TelephoneEventPT = info.teEventPT
	offerSess.state = StateNegotiated
	return offerSess, nil
}

// parseEvents reads an RFC 4733 events list such as "0-15,66,70-73".
// Malformed tokens are skipped; nil means no valid token (the 0-15 default).
func parseEvents(list string) map[uint8]bool {
	var set map[uint8]bool
	for _, tok := range strings.Split(list, ",") {
		loStr, hiStr, isRange := strings.Cut(strings.TrimSpace(tok), "-")
		lo, err := strconv.Atoi(loStr)
		if err != nil || lo < 0 || lo > 255 {
			continue
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(hiStr); err != nil || hi < lo || hi > 255 {
				continue
			}
		}
		if set == nil {
			set = map[uint8]bool{}
		}
		for c := lo; c <= hi; c++ {
			set[uint8(c)] = true
		}
	}
	return set
}
