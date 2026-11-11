package media

import (
	"fmt"
	"strconv"
	"strings"
)

// BuildReOffer renders our offer for an established session (RFC 3261 14.2: the
// 2xx to an offerless re-INVITE carries an offer "as if the UAS were making a
// brand new call", constrained to update the existing session). Unlike BuildOffer
// (a fresh call: new origin, one stream, a new SRTP key) it keeps what the session
// already has: the session id with the version incremented (RFC 3264 8), every
// m= line of prev in order (rejected ones at port 0), the live stream's port,
// transport profile and SRTP key (the SRTP transform is built once, D-10), and the
// live event payload type (RFC 3264 8: a payload type mapping must not change).
// The live codec is listed first, then every other configured codec, so a peer
// that picks its first supported codec does not switch codec on every refresh.
//
// The returned Session is the offer-side state to hand to ParseAnswer with the
// answer carried in the ACK. Errors are local faults, never a negotiation result.
func BuildReOffer(prev *Session, prefs CodecPrefs) ([]byte, *Session, error) {
	if prev == nil {
		return nil, nil, fmt.Errorf("BuildReOffer: no session")
	}
	if len(prev.Streams) == 0 || prev.Live < 0 || prev.Live >= len(prev.Streams) {
		return nil, nil, fmt.Errorf("BuildReOffer: session has no live stream")
	}
	if len(prefs) == 0 {
		return nil, nil, fmt.Errorf("BuildReOffer: empty codec prefs")
	}
	host, _, err := splitHostPort(prev.LocalAddr)
	if err != nil {
		return nil, nil, err
	}
	codecs := CodecPrefs{}
	if prev.Codec != "" {
		codecs = append(codecs, prev.Codec)
	}
	for _, c := range prefs {
		if c != prev.Codec {
			codecs = append(codecs, c)
		}
	}
	eventPT := prev.TelephoneEventPT
	if eventPT == 0 {
		eventPT = telephoneEventOfferPT
	}
	pts := make([]string, 0, len(codecs)+1)
	var attrs strings.Builder
	for _, c := range codecs {
		pt, ok := payloadType(c)
		if !ok {
			return nil, nil, fmt.Errorf("BuildReOffer: unsupported codec %q", c)
		}
		pts = append(pts, strconv.Itoa(pt))
		fmt.Fprintf(&attrs, "a=rtpmap:%d %s/8000\r\n", pt, c)
	}
	pts = append(pts, strconv.Itoa(eventPT))
	fmt.Fprintf(&attrs, "a=rtpmap:%d telephone-event/8000\r\na=fmtp:%d 0-15\r\n", eventPT, eventPT)

	origin := Origin{SessID: prev.Origin.SessID, Version: prev.Origin.Version + 1}
	var b strings.Builder
	b.WriteString("v=0\r\n")
	fmt.Fprintf(&b, "o=- %d %d IN IP4 %s\r\n", origin.SessID, origin.Version, host)
	b.WriteString("s=sipclient-mcp\r\n")
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", host)
	b.WriteString("t=0 0\r\n")
	streams := append([]Stream(nil), prev.Streams...)
	for i, st := range streams {
		if i != prev.Live {
			fmt.Fprintf(&b, "m=%s 0 %s 0\r\n", st.Media, st.Proto)
			continue
		}
		fmt.Fprintf(&b, "m=audio %d %s %s\r\n", st.LocalPort, st.Proto, strings.Join(pts, " "))
		b.WriteString(attrs.String())
		if prev.LocalCrypto != nil {
			b.WriteString(prev.LocalCrypto.AttrLine() + "\r\n")
		}
		b.WriteString("a=sendrecv\r\n")
		streams[i].Direction = DirSendRecv
	}
	sess := &Session{
		LocalAddr: prev.LocalAddr, TelephoneEventPT: eventPT, state: StateNegotiating,
		offered: append(CodecPrefs{}, codecs...), srtp: prev.srtp,
		Streams: streams, Live: prev.Live, Direction: DirSendRecv, Origin: origin,
	}
	if prev.LocalCrypto != nil {
		cp := *prev.LocalCrypto
		sess.LocalCrypto = &cp
	}
	return []byte(b.String()), sess, nil
}
