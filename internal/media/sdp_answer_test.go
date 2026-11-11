package media

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func offerBody(t *testing.T, srtp bool, codecs ...string) []byte {
	t.Helper()
	b, _, err := BuildOffer(codecs, "198.51.100.1:20000", srtpPolicy(srtp))
	if err != nil {
		t.Fatalf("offerBody: %v", err)
	}
	return b
}

func TestBuildAnswerSelectsOurPrefOrder(t *testing.T) {
	// Peer offers [PCMU,PCMA]; our pref is [PCMA,PCMU] -> PCMA wins (§10.3 r3).
	offer := offerBody(t, false, "PCMU", "PCMA")
	sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMA", "PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.Codec != "PCMA" {
		t.Fatalf("selected codec=%q want PCMA", sess.Codec)
	}
	if !strings.Contains(string(sdp), "m=audio 16384 RTP/AVP 8 101\r\n") {
		t.Fatalf("answer m= must list only PT 8:\n%s", sdp)
	}
	if sess.RemoteAddr != "198.51.100.1:20000" {
		t.Fatalf("remote addr not parsed: %q", sess.RemoteAddr)
	}
	if sess.State() != StateNegotiated {
		t.Fatalf("state=%v", sess.State())
	}
}

func TestBuildAnswerNoCommonCodec(t *testing.T) {
	offer := offerBody(t, false, "PCMA")
	_, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPDisabled})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindNoCommonCodec {
		t.Fatalf("want no_common_codec, got %v", err)
	}
	d := ne.Detail()
	if d["sip_response_sent"] != 488 {
		t.Fatalf("answer-side must send 488: %#v", d)
	}
}

func TestBuildAnswerSRTPRequiredButPeerOfferedAVP(t *testing.T) {
	offer := offerBody(t, false, "PCMU") // plain RTP/AVP, no a=crypto
	_, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSRTPRequiredPeerOfferedAVP {
		t.Fatalf("want srtp_required_but_peer_offered_avp, got %v", err)
	}
}

func TestBuildAnswerSRTPHappyPath(t *testing.T) {
	offer := offerBody(t, true, "PCMU") // RTP/SAVP + a=crypto
	sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	if err != nil {
		t.Fatalf("BuildAnswer(srtp): %v", err)
	}
	if !strings.Contains(string(sdp), "RTP/SAVP") || !strings.Contains(string(sdp), "a=crypto:1 ") {
		t.Fatalf("SRTP answer missing profile/crypto:\n%s", sdp)
	}
	if sess.LocalCrypto == nil {
		t.Fatal("answer session local crypto not set")
	}
	if sess.RemoteCrypto == nil {
		t.Fatal("answer session must retain the peer's parsed crypto (RemoteCrypto)")
	}
}

func TestBuildAnswerStaticPTFallbackNoRTPMap(t *testing.T) {
	// Peer's m=audio line names PT 0 (PCMU) but omits a=rtpmap entirely; parseSDP
	// must resolve it via the static codecForPT table, not via a=rtpmap.
	offer := []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.5\r\n" +
		"t=0 0\r\n" +
		"m=audio 40000 RTP/AVP 0\r\n" +
		"a=sendrecv\r\n")
	_, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.Codec != "PCMU" {
		t.Fatalf("codec=%q want PCMU (resolved via static PT table, no a=rtpmap present)", sess.Codec)
	}
}

func TestBuildAnswerMirrorsThePeersTelephoneEventPT(t *testing.T) {
	offer := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0 96\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:96 telephone-event/8000\r\na=fmtp:96 0-15\r\na=sendrecv\r\n")
	body, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 96 {
		t.Fatalf("TelephoneEventPT=%d want 96 (the peer's PT, mirrored)", sess.TelephoneEventPT)
	}
	s := string(body)
	if !strings.Contains(s, "m=audio 20002 RTP/AVP 0 96") ||
		!strings.Contains(s, "a=rtpmap:96 telephone-event/8000") ||
		!strings.Contains(s, "a=fmtp:96 0-15") {
		t.Fatalf("answer does not mirror PT 96:\n%s", s)
	}
}

func TestBuildAnswerOmitsTelephoneEventWhenThePeerDidNotOfferIt(t *testing.T) {
	offer := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n")
	body, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 0 {
		t.Fatalf("TelephoneEventPT=%d want 0 (not negotiated)", sess.TelephoneEventPT)
	}
	if strings.Contains(string(body), "telephone-event") {
		t.Fatalf("answer must not offer telephone-event unilaterally:\n%s", body)
	}
}

// TestBuildAnswerPicksThe8kHzTelephoneEventAmongMultipleRates is the regression
// test for the multi-rate interop bug found in review: a peer (a real-world
// Asterisk/SBC pattern) can offer BOTH telephone-event/8000 and
// telephone-event/16000. This UA's DTMF machinery is hardcoded to 8kHz
// (codec.dtmfSampleRate), so only the 8000 Hz entry may ever be selected —
// picking whichever rtpmap line happens to parse last would be wrong, and
// mirroring back a PT at the wrong rate would violate RFC 3264.
//
// THE 16000 LINE COMES FIRST, AND THAT ORDER IS THE WHOLE TEST. With the 8000
// entry listed first this test could not fail: parseSDP takes the first
// telephone-event it accepts, so 101 was selected by position whether or not
// the `rate == 8000` gate existed at all, and relaxing that gate to `rate > 0`
// left internal/media green. Offering 16000 first is equally realistic, and it
// is the only order under which the rate gate is what decides the answer.
func TestBuildAnswerPicksThe8kHzTelephoneEventAmongMultipleRates(t *testing.T) {
	offer := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0 111 101\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:111 telephone-event/16000\r\na=rtpmap:101 telephone-event/8000\r\n" +
		"a=sendrecv\r\n")
	body, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 101 {
		t.Fatalf("TelephoneEventPT=%d want 101 (the 8kHz entry, not 111/16000)", sess.TelephoneEventPT)
	}
	s := string(body)
	// Lines other than o= only: the random o= sess-id may contain "111".
	for _, ln := range strings.Split(s, "\r\n") {
		if strings.HasPrefix(ln, "o=") {
			continue
		}
		if strings.Contains(ln, "111") {
			t.Fatalf("answer must not reference the 16kHz telephone-event PT at all:\n%s", s)
		}
	}
	if !strings.Contains(s, "a=rtpmap:101 telephone-event/8000") {
		t.Fatalf("answer must mirror the 8kHz telephone-event PT:\n%s", s)
	}
}

// TestBuildAnswerIgnoresStaleTelephoneEventRtpmapNotInMLine is the regression
// test for the "declined but rtpmap survives" bug found in review: a stale
// a=rtpmap:101 telephone-event/8000 line alongside an m=audio line that does
// NOT list 101 means the peer actually declined telephone-event for this
// call, and it must read as not-negotiated — same as if the rtpmap line were
// entirely absent.
func TestBuildAnswerIgnoresStaleTelephoneEventRtpmapNotInMLine(t *testing.T) {
	offer := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n")
	body, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 0 {
		t.Fatalf("TelephoneEventPT=%d want 0 — 101 is not in the m=audio PT list", sess.TelephoneEventPT)
	}
	if strings.Contains(string(body), "telephone-event") {
		t.Fatalf("answer must not offer telephone-event when the offer's m= line declined it:\n%s", body)
	}
	if !strings.Contains(string(body), "PCMU") {
		t.Fatalf("the stale telephone-event rtpmap must not have swayed codec selection:\n%s", body)
	}
}

// TestBuildAnswerRejectsOutOfRangeTelephoneEventPT is the regression test for
// security review finding F4: parseSDP's a=rtpmap PT is read with strconv.Atoi
// (any int, unbounded), and BuildAnswer echoes info.teEventPT straight into
// our own m=audio line and a=rtpmap:/a=fmtp: attributes. A peer offering
// a=rtpmap:99999999 telephone-event/8000 — with 99999999 also listed in its
// own m=audio PT list, so the "declined" path does not apply — must not reach
// the echo. Out of range must read exactly like "not negotiated" (PT 0), the
// same normalization parseSDP already applies for a stale/non-m= rtpmap.
func TestBuildAnswerRejectsOutOfRangeTelephoneEventPT(t *testing.T) {
	offer := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0 99999999\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:99999999 telephone-event/8000\r\na=sendrecv\r\n")
	body, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 0 {
		t.Fatalf("TelephoneEventPT=%d want 0 — 99999999 is out of the valid RTP payload-type range (1-127)", sess.TelephoneEventPT)
	}
	if strings.Contains(string(body), "telephone-event") || strings.Contains(sansOrigin(string(body)), "99999999") {
		t.Fatalf("answer must not echo an out-of-range telephone-event PT:\n%s", body)
	}
	if !strings.Contains(string(body), "PCMU") {
		t.Fatalf("the out-of-range telephone-event rtpmap must not have swayed codec selection:\n%s", body)
	}
}

func TestBuildAnswerMalformedOfferCollapsesToNoCommonCodec(t *testing.T) {
	// No m=audio line at all: parseSDP fails, and BuildAnswer collapses that
	// failure to no_common_codec with an empty offered set rather than a
	// distinct error kind.
	offer := []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 203.0.113.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.5\r\n" +
		"t=0 0\r\n")
	_, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPDisabled})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindNoCommonCodec {
		t.Fatalf("want no_common_codec, got %v", err)
	}
}

// TestBuildAnswerMatchesTelephoneEventCaseInsensitively pins parseSDP's
// deliberate strings.EqualFold. Every telephone-event fixture in the package
// spells the encoding name in lowercase, so EqualFold could be narrowed to a
// plain == with internal/media green.
//
// The failure it guards is silent and total: a peer spelling the registered
// name TELEPHONE-EVENT would have its payload type read as an ordinary audio
// codec and telephone-event seen as NOT negotiated, so RFC 2833 DTMF is simply
// off for that call while everything else about it succeeds.
func TestBuildAnswerMatchesTelephoneEventCaseInsensitively(t *testing.T) {
	offer := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:101 TELEPHONE-EVENT/8000\r\na=sendrecv\r\n")
	body, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 101 {
		t.Fatalf("TelephoneEventPT=%d want 101 — an uppercase encoding name must still "+
			"negotiate telephone-event, or RFC 2833 DTMF is silently off for the call", sess.TelephoneEventPT)
	}
	if !strings.Contains(string(body), "a=rtpmap:101 telephone-event/8000") {
		t.Fatalf("answer must mirror the peer's PT back:\n%s", body)
	}
}

// srtpPolicy maps the old boolean test argument onto the policy type.
func srtpPolicy(required bool) SRTPPolicy {
	if required {
		return SRTPRequired
	}
	return SRTPDisabled
}

func TestBuildAnswerZeroConnectionAddressIsAnsweredInactive(t *testing.T) {
	offer := sdpOf("v=0", "o=- 1 1 IN IP4 0.0.0.0", "s=-", "c=IN IP4 0.0.0.0", "t=0 0", "m=audio 15282 RTP/AVP 0", "a=sendrecv")
	sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sdp), "a=inactive\r\n") || sess.Direction != DirInactive || sess.RemoteAddr != "0.0.0.0:15282" {
		t.Fatalf("Direction %s RemoteAddr %s:\n%s", sess.Direction, sess.RemoteAddr, sdp)
	}
}

func TestBuildAnswerNoUsableStreamListsTheOfferedCodecs(t *testing.T) {
	offer := sdpOf("v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0",
		"m=audio 15282 RTP/AVP 111", "a=rtpmap:111 opus/48000/2", "m=audio 0 RTP/AVP 0")
	_, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002"})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindNoCommonCodec || !reflect.DeepEqual(ne.Offered, []string{"opus"}) {
		t.Fatalf("err %v", err)
	}
}

func TestBuildAnswerWithNoTimeLineAnswersZeroZero(t *testing.T) {
	offer := sdpOf("v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "m=audio 15282 RTP/AVP 0")
	sdp, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002"})
	if err != nil || !strings.Contains(string(sdp), "\r\nt=0 0\r\n") {
		t.Fatalf("err %v:\n%s", err, sdp)
	}
}

func TestSessionSendsMedia(t *testing.T) {
	for _, c := range []struct {
		dir  Direction
		addr string
		want bool
	}{
		{DirSendRecv, "127.0.0.1:4000", true}, {"", "127.0.0.1:4000", true},
		{DirRecvOnly, "127.0.0.1:4000", false}, {DirInactive, "127.0.0.1:4000", false},
		{DirSendRecv, "0.0.0.0:4000", false}, {DirSendRecv, "127.0.0.1:0", false},
		{DirSendRecv, ":4000", false}, {DirSendRecv, "host.example:4000", true},
		{DirSendOnly, "127.0.0.1:4000", true},
	} {
		if got := (&Session{Direction: c.dir, RemoteAddr: c.addr}).SendsMedia(); got != c.want {
			t.Errorf("%q %q: %v, want %v", c.dir, c.addr, got, c.want)
		}
	}
}

func TestBuildAnswerSRTPPolicyTable(t *testing.T) {
	_, crypto, err := GenerateCryptoAttr()
	if err != nil {
		t.Fatal(err)
	}
	offer := func(proto string, withCrypto bool, cryptoLine string) []byte {
		l := []string{"v=0", "o=- 1 1 IN IP4 198.51.100.1", "s=-", "c=IN IP4 198.51.100.1", "t=0 0", "m=audio 20000 " + proto + " 0", "a=rtpmap:0 PCMU/8000"}
		if withCrypto {
			l = append(l, cryptoLine)
		}
		return sdpOf(l...)
	}
	cases := []struct {
		name       string
		policy     SRTPPolicy
		body       []byte
		wantKind   string
		wantProto  string
		wantCrypto bool
	}{
		{"disabled SAVP", SRTPDisabled, offer("RTP/SAVP", true, crypto), KindSRTPOfferedButDisabled, "", false},
		{"disabled AVP", SRTPDisabled, offer("RTP/AVP", false, ""), "", "RTP/AVP", false},
		{"disabled AVP+crypto", SRTPDisabled, offer("RTP/AVP", true, crypto), "", "RTP/AVP", false},
		{"optional SAVP+crypto", SRTPOptional, offer("RTP/SAVP", true, crypto), "", "RTP/SAVP", true},
		{"optional SAVP no crypto", SRTPOptional, offer("RTP/SAVP", false, ""), KindSRTPRequiredPeerOfferedAVP, "", false},
		{"optional AVP+crypto", SRTPOptional, offer("RTP/AVP", true, crypto), "", "RTP/AVP", true},
		{"optional AVP", SRTPOptional, offer("RTP/AVP", false, ""), "", "RTP/AVP", false},
		{"optional AVP bad crypto", SRTPOptional, offer("RTP/AVP", true, "a=crypto:1 garbage"), "", "RTP/AVP", false},
		{"required AVP", SRTPRequired, offer("RTP/AVP", true, crypto), KindSRTPRequiredPeerOfferedAVP, "", false},
		{"required SAVP+crypto", SRTPRequired, offer("RTP/SAVP", true, crypto), "", "RTP/SAVP", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sdp, sess, err := BuildAnswer(c.body, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: c.policy})
			if c.wantKind != "" {
				var ne *NegotiationError
				if !errors.As(err, &ne) || ne.Kind != c.wantKind || ne.Detail()["sip_response_sent"] != 488 {
					t.Fatalf("err %v, want kind %s with 488", err, c.wantKind)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body := string(sdp)
			if !strings.Contains(body, "m=audio 16384 "+c.wantProto+" 0") || strings.Contains(body, "a=crypto:") != c.wantCrypto ||
				(sess.LocalCrypto != nil) != c.wantCrypto || (sess.RemoteCrypto != nil) != c.wantCrypto {
				t.Fatalf("answer wrong (Local %v Remote %v):\n%s", sess.LocalCrypto, sess.RemoteCrypto, body)
			}
		})
	}
}

// sansOrigin drops the o= line, whose sess-id is random.
func sansOrigin(sdp string) string {
	var keep []string
	for _, ln := range strings.Split(sdp, "\r\n") {
		if !strings.HasPrefix(ln, "o=") {
			keep = append(keep, ln)
		}
	}
	return strings.Join(keep, "\r\n")
}

// The 488 for an optional UA that cannot use an SAVP offer names the profile
// the peer really offered and the policy, not "srtp=required ... RTP/AVP".
func TestBuildAnswerOptionalSAVPRefusalNamesTheRealProfile(t *testing.T) {
	offer := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	_, _, err := BuildAnswer([]byte(offer), AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPOptional})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Detail()["offered_profile"] != "RTP/SAVP" || !strings.Contains(ne.Error(), "srtp=optional") {
		t.Fatalf("err=%v detail=%v, want offered_profile RTP/SAVP and srtp=optional", err, ne.Detail())
	}
}

// A static payload type outside the table (18, with no a=rtpmap) is an unknown
// payload type: the offer is refused exactly like any other unsupported one,
// and no codec name is invented for it.
func TestBuildAnswerUnmappedStaticPTIsUnknownLikeAnyOther(t *testing.T) {
	for _, pt := range []string{"18", "77"} {
		offer := sdpOf("v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0",
			"m=audio 15282 RTP/AVP "+pt)
		_, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002"})
		var ne *NegotiationError
		if !errors.As(err, &ne) || ne.Kind != KindNoCommonCodec || len(ne.Offered) != 0 {
			t.Fatalf("PT %s: err %v (offered %v), want no_common_codec with nothing offered", pt, err, ne)
		}
	}
}
