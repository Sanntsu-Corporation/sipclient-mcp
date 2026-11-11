package media

import (
	"errors"
	"strings"
	"testing"
)

func mkOffer(t *testing.T, srtp bool, codecs ...string) *Session {
	t.Helper()
	_, s, err := BuildOffer(codecs, "192.0.2.7:16384", srtpPolicy(srtp))
	if err != nil {
		t.Fatalf("mkOffer: %v", err)
	}
	return s
}

func TestParseAnswerHappyPath(t *testing.T) {
	off := mkOffer(t, false, "PCMU", "PCMA")
	ans := "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=x\r\nc=IN IP4 198.51.100.1\r\n" +
		"t=0 0\r\nm=audio 20000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n"
	sess, err := ParseAnswer(off, []byte(ans))
	if err != nil {
		t.Fatalf("ParseAnswer: %v", err)
	}
	if sess.Codec != "PCMA" || sess.RemoteAddr != "198.51.100.1:20000" || sess.State() != StateNegotiated {
		t.Fatalf("sess=%+v", sess)
	}
}

func TestParseAnswerCodecNotOffered(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	ans := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n"
	_, err := ParseAnswer(off, []byte(ans))
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindAnswerCodecNotOffered {
		t.Fatalf("want answer_codec_not_offered, got %v", err)
	}
	d := ne.Detail()
	if d["action"] != "ack_then_bye" {
		t.Fatalf("offer-side must ack_then_bye: %#v", d)
	}
	if v, ok := d["sip_response_sent"]; !ok || v != nil {
		t.Fatalf("sip_response_sent must be null: (%v,%v)", v, ok)
	}
}

func TestParseAnswerSDPAbsent(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	_, err := ParseAnswer(off, nil)
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSDPAbsent {
		t.Fatalf("want sdp_absent, got %v", err)
	}
}

func TestParseAnswerSDPUnparseable(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	_, err := ParseAnswer(off, []byte("this is not sdp"))
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSDPUnparseable {
		t.Fatalf("want sdp_unparseable, got %v", err)
	}
}

func TestParseAnswerRecordsTheNegotiatedTelephoneEventPT(t *testing.T) {
	_, offerSess, err := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	if err != nil {
		t.Fatal(err)
	}
	ans := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20004 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n")
	sess, err := ParseAnswer(offerSess, ans)
	if err != nil {
		t.Fatalf("ParseAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 101 {
		t.Fatalf("TelephoneEventPT=%d want 101", sess.TelephoneEventPT)
	}
}

func TestParseAnswerClearsTelephoneEventWhenThePeerDeclinedIt(t *testing.T) {
	_, offerSess, err := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	if err != nil {
		t.Fatal(err)
	}
	// The peer answers PCMU only: telephone-event was NOT negotiated, and
	// dtmf_send(mode="rfc2833") must then report not_supported rather than
	// silently downgrading (§10.8).
	ans := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	sess, err := ParseAnswer(offerSess, ans)
	if err != nil {
		t.Fatalf("ParseAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 0 {
		t.Fatalf("TelephoneEventPT=%d want 0 — the peer did not accept it", sess.TelephoneEventPT)
	}
}

// TestParseAnswerIgnoresStaleTelephoneEventRtpmapNotInMLine mirrors
// TestBuildAnswerIgnoresStaleTelephoneEventRtpmapNotInMLine on the
// offer-parsing side: an answer whose m=audio line does not list the PT that
// a leftover a=rtpmap:101 telephone-event/8000 line names must clear
// TelephoneEventPT, not honor the stale rtpmap.
func TestParseAnswerIgnoresStaleTelephoneEventRtpmapNotInMLine(t *testing.T) {
	_, offerSess, err := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	if err != nil {
		t.Fatal(err)
	}
	ans := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n")
	sess, err := ParseAnswer(offerSess, ans)
	if err != nil {
		t.Fatalf("ParseAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 0 {
		t.Fatalf("TelephoneEventPT=%d want 0 — 101 is not in the answer's m=audio PT list", sess.TelephoneEventPT)
	}
}

// TestParseAnswerPicksThe8kHzTelephoneEventAmongMultipleRates mirrors the
// BuildAnswer-side multi-rate regression test on the offer-parsing path.
func TestParseAnswerPicksThe8kHzTelephoneEventAmongMultipleRates(t *testing.T) {
	_, offerSess, err := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	if err != nil {
		t.Fatal(err)
	}
	ans := []byte("v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n" +
		"m=audio 20004 RTP/AVP 0 101 111\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\na=rtpmap:111 telephone-event/16000\r\n")
	sess, err := ParseAnswer(offerSess, ans)
	if err != nil {
		t.Fatalf("ParseAnswer: %v", err)
	}
	if sess.TelephoneEventPT != 101 {
		t.Fatalf("TelephoneEventPT=%d want 101 (the 8kHz entry, not 111/16000)", sess.TelephoneEventPT)
	}
}

func TestParseAnswerTakesTheFirstAudioStreamsScopedAddress(t *testing.T) {
	off := mkOffer(t, false, "PCMU", "PCMA")
	ans := sdpOf("v=0", "o=- 1 1 IN IP4 198.51.100.7", "s=x", "c=IN IP4 198.51.100.7", "t=0 0",
		"m=audio 30000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000",
		"m=audio 0 RTP/AVP 8", "c=IN IP4 198.51.100.9", "a=rtpmap:8 PCMA/8000")
	sess, err := ParseAnswer(off, ans)
	if err != nil {
		t.Fatal(err)
	}
	if sess.RemoteAddr != "198.51.100.7:30000" || sess.Codec != "PCMU" {
		t.Fatalf("RemoteAddr %q codec %q, want 198.51.100.7:30000 PCMU", sess.RemoteAddr, sess.Codec)
	}
}

func TestSessionRecordsItsSRTPPolicy(t *testing.T) {
	offer := offerBody(t, true, "PCMU")
	_, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	if sess.SRTPPolicy() != SRTPRequired {
		t.Fatalf("answerer policy %q", sess.SRTPPolicy())
	}
	_, off, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:16384", SRTPOptional)
	if err != nil {
		t.Fatal(err)
	}
	cp := *off
	ans := sdpOf("v=0", "c=IN IP4 198.51.100.7", "m=audio 30000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000")
	got, err := ParseAnswer(&cp, ans)
	if err != nil {
		t.Fatal(err)
	}
	if got.SRTPPolicy() != SRTPOptional || off.SRTPPolicy() != SRTPOptional {
		t.Fatalf("policy after ParseAnswer %q (original %q)", got.SRTPPolicy(), off.SRTPPolicy())
	}
}

func answerWith(t *testing.T, lines ...string) (*Session, error) {
	t.Helper()
	off := mkOffer(t, false, "PCMU", "PCMA")
	return ParseAnswer(off, sdpOf(append([]string{"v=0", "o=- 1 1 IN IP4 198.51.100.7", "s=x", "c=IN IP4 198.51.100.7", "t=0 0"}, lines...)...))
}

func TestParseAnswerMirrorsTheAnswerDirection(t *testing.T) {
	for _, c := range []struct {
		attr string
		want Direction
	}{{"a=sendonly", DirRecvOnly}, {"a=recvonly", DirSendOnly}, {"a=inactive", DirInactive}, {"a=sendrecv", DirSendRecv}, {"", DirSendRecv}} {
		lines := []string{"m=audio 30000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000"}
		if c.attr != "" {
			lines = append(lines, c.attr)
		}
		sess, err := answerWith(t, lines...)
		if err != nil || sess.Direction != c.want || sess.Streams[0].Direction != c.want || sess.Live != 0 {
			t.Fatalf("%q: Direction %q err %v", c.attr, sess.Direction, err)
		}
	}
}

func TestParseAnswerMarksAHeldAnswerInactive(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	ans := sdpOf("v=0", "o=- 1 1 IN IP4 0.0.0.0", "s=x", "c=IN IP4 0.0.0.0", "t=0 0", "m=audio 30000 RTP/AVP 0", "a=sendrecv")
	sess, err := ParseAnswer(off, ans)
	if err != nil || sess.Direction != DirInactive {
		t.Fatalf("Direction %q err %v", sess.Direction, err)
	}
}

func TestParseAnswerRejectedAudioStreamEndsTheCall(t *testing.T) {
	for _, line := range []string{"m=audio 0 RTP/AVP 0", "m=audio 0 RTP/AVP 18"} {
		_, err := answerWith(t, line)
		var ne *NegotiationError
		if !errors.As(err, &ne) || ne.Kind != KindAnswerRejectedAudio {
			t.Fatalf("%q: err %v, want answer_rejected_audio", line, err)
		}
		d := ne.Detail()
		if d["action"] != "ack_then_bye" || d["sip_response_sent"] != nil {
			t.Fatalf("%q: detail %v", line, d)
		}
	}
}

func TestParseAnswerRequiresAnAudioFirstStream(t *testing.T) {
	_, err := answerWith(t, "m=video 0 RTP/AVP 31", "m=audio 30000 RTP/AVP 0")
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSDPUnparseable {
		t.Fatalf("err %v", err)
	}
}

func TestParseAnswerDoesNotMutateTheSessionItWasCopiedFrom(t *testing.T) {
	orig := mkOffer(t, false, "PCMU")
	before := orig.Streams[0]
	cp := *orig
	if _, err := ParseAnswer(&cp, sdpOf("v=0", "c=IN IP4 198.51.100.7", "m=audio 30000 RTP/AVP 0", "a=sendonly")); err != nil {
		t.Fatal(err)
	}
	if orig.Streams[0] != before || len(orig.Streams) != 1 {
		t.Fatalf("original stream changed: %+v", orig.Streams)
	}
	if cp.Streams[0].RemoteAddr != "198.51.100.7:30000" {
		t.Fatalf("copy stream %+v", cp.Streams[0])
	}
}

func TestParseAnswerOptionalTable(t *testing.T) {
	_, line, err := GenerateCryptoAttr()
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *Session {
		_, s, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:16384", SRTPOptional)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := []string{"v=0", "c=IN IP4 198.51.100.7", "m=audio 30000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000"}
	t.Run("crypto present", func(t *testing.T) {
		s, err := ParseAnswer(mk(), sdpOf(append(base, line)...))
		if err != nil || s.RemoteCrypto == nil || s.LocalCrypto == nil {
			t.Fatalf("err %v sess %+v", err, s)
		}
	})
	t.Run("no crypto falls back to plain", func(t *testing.T) {
		s, err := ParseAnswer(mk(), sdpOf(base...))
		if err != nil || s.RemoteCrypto != nil || s.LocalCrypto != nil || s.Codec != "PCMU" {
			t.Fatalf("err %v sess %+v", err, s)
		}
	})
	t.Run("unparseable crypto", func(t *testing.T) {
		_, err := ParseAnswer(mk(), sdpOf(append(base, "a=crypto:1 garbage")...))
		var ne *NegotiationError
		if !errors.As(err, &ne) || ne.Kind != KindSDPUnparseable {
			t.Fatalf("err %v", err)
		}
	})
}

// An answer that maps an audio codec to our event PT (101) leaves that PT audio.
func TestParseAnswerAudioOnTheEventPTIsNotAnEvent(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	ans := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 101 102\r\na=rtpmap:101 PCMU/8000\r\na=rtpmap:102 telephone-event/8000\r\n"
	sess, err := ParseAnswer(off, []byte(ans))
	if err != nil {
		t.Fatal(err)
	}
	if !sess.RecvEventPTs[102] || sess.RecvEventPTs[101] || sess.RecvPTs[101] != "PCMU" {
		t.Fatalf("RecvEventPTs=%v RecvPTs=%v, want 101 audio only", sess.RecvEventPTs, sess.RecvPTs)
	}
}

// The codec list in the 488 detail is distinct, however many times an offer repeats it.
func TestBuildAnswerNoCommonCodecListIsDistinct(t *testing.T) {
	offer := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP" + strings.Repeat(" 111", 500) + "\r\na=rtpmap:111 opus/48000/2\r\n"
	_, _, err := BuildAnswer([]byte(offer), AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:20002", SRTP: SRTPDisabled})
	var ne *NegotiationError
	if !errors.As(err, &ne) || len(ne.Offered) != 1 {
		t.Fatalf("err=%v, want one distinct offered codec", err)
	}
}

// RFC 3264 6.1: the answerer sends at the offer's numbers, we send at the
// answer's. An answer that remaps PCMU to 96 means we send at 96 and must still
// accept PT 0 (our own number) and 96.
func TestParseAnswerRemappedPTSendsAtTheAnswersAndReceivesAtBoth(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	ans := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\n"
	sess, err := ParseAnswer(off, []byte(ans))
	if err != nil {
		t.Fatal(err)
	}
	if sess.SendPT != 96 || sess.RecvPTs[96] != "PCMU" || sess.RecvPTs[0] != "PCMU" || len(sess.RecvPTs) != 2 {
		t.Fatalf("SendPT=%d RecvPTs=%v, want 96 and {96,0}", sess.SendPT, sess.RecvPTs)
	}
}

// Under optional, an RTP/SAVP answer without a=crypto is not plain RTP: the peer
// believes the stream is secure. It is refused (ACK then BYE), never run in the clear.
func TestParseAnswerOptionalSAVPWithoutCryptoIsRefused(t *testing.T) {
	_, off, err := BuildOffer([]string{"PCMU"}, "192.0.2.7:16384", SRTPOptional)
	if err != nil {
		t.Fatal(err)
	}
	ans := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	sess, err := ParseAnswer(off, []byte(ans))
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSDPUnparseable || ne.Detail()["action"] != "ack_then_bye" || sess != nil {
		t.Fatalf("sess=%v err=%v, want sdp_unparseable ack_then_bye", sess, err)
	}
}

// Every payload type the answer maps to an offered codec is received (RFC 3264
// 5.1: the peer may send at any of them); we send at the first.
func TestParseAnswerReceivesAtEveryAliasPT(t *testing.T) {
	off := mkOffer(t, false, "PCMU")
	ans := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 96 97\r\na=rtpmap:96 PCMU/8000\r\na=rtpmap:97 PCMU/8000\r\n"
	sess, err := ParseAnswer(off, []byte(ans))
	if err != nil {
		t.Fatal(err)
	}
	if sess.SendPT != 96 || sess.RecvPTs[96] != "PCMU" || sess.RecvPTs[97] != "PCMU" || sess.RecvPTs[0] != "PCMU" {
		t.Fatalf("SendPT=%d RecvPTs=%v, want send 96, receive {0,96,97}", sess.SendPT, sess.RecvPTs)
	}
}

// When the answer's PT for one codec is the static number of another offered
// codec, our offer's numbering wins and the result is the same on every run.
func TestParseAnswerReceivePTCollisionIsDeterministic(t *testing.T) {
	ans := "v=0\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 8 0\r\na=rtpmap:8 PCMU/8000\r\na=rtpmap:0 PCMA/8000\r\n"
	for i := 0; i < 100; i++ {
		sess, err := ParseAnswer(mkOffer(t, false, "PCMU", "PCMA"), []byte(ans))
		if err != nil {
			t.Fatal(err)
		}
		if sess.RecvPTs[0] != "PCMU" || sess.RecvPTs[8] != "PCMA" {
			t.Fatalf("run %d: RecvPTs=%v, want our numbering {0:PCMU 8:PCMA}", i, sess.RecvPTs)
		}
	}
}
