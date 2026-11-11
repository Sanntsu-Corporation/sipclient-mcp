package media

import (
	"errors"
	"fmt"
	"testing"
)

const loLocal = "127.0.0.1:16384"

func TestParseSDPRefusesANonLiteralConnectionAddress(t *testing.T) {
	for _, h := range []string{"localhost", "media.invalid", "010.0.0.1", "1.2.3.4/127", "1.2.3", "::ffff:1.2.3.4"} {
		sess := sdpOf("v=0", "c=IN IP4 "+h, "m=audio 4000 RTP/AVP 0")
		if _, err := parseSDP(sess, loLocal); err == nil {
			t.Errorf("session-level c=%q accepted", h)
		}
		med := sdpOf("v=0", "m=audio 4000 RTP/AVP 0", "c=IN IP4 "+h)
		if _, err := parseSDP(med, loLocal); err == nil {
			t.Errorf("media-level c=%q accepted", h)
		}
	}
}

func TestParseSDPRefusesMulticastAndBroadcast(t *testing.T) {
	for _, h := range []string{"224.0.0.1", "239.255.255.250", "255.255.255.255"} {
		if _, err := parseSDP(sdpOf("v=0", "c=IN IP4 "+h, "m=audio 4000 RTP/AVP 0"), loLocal); err == nil {
			t.Errorf("c=%q accepted", h)
		}
	}
}

func TestParseSDPLoopbackNeedsALoopbackLocalAddress(t *testing.T) {
	for _, tc := range []struct {
		host, local string
		ok          bool
	}{
		{"127.0.0.1", "192.0.2.7:16384", false},
		{"127.0.0.1", "127.0.0.1:16384", true},
		{"127.9.9.9", "127.0.0.1:16384", true},
		{"198.51.100.1", "127.0.0.1:16384", true},
	} {
		_, err := parseSDP(sdpOf("v=0", "c=IN IP4 "+tc.host, "m=audio 4000 RTP/AVP 0"), tc.local)
		if (err == nil) != tc.ok {
			t.Errorf("c=%s local=%s: err=%v, want ok=%v", tc.host, tc.local, err, tc.ok)
		}
	}
}

func TestParseSDPAcceptsHoldAndPrivateAddresses(t *testing.T) {
	for _, h := range []string{"0.0.0.0", "10.0.0.1", "192.168.1.244", "169.254.1.1"} {
		d, err := parseSDP(sdpOf("v=0", "c=IN IP4 "+h, "m=audio 4000 RTP/AVP 0"), "192.0.2.7:16384")
		if err != nil || d.streams[0].host != h {
			t.Errorf("c=%s: host=%v err=%v", h, d.streams, err)
		}
	}
}

func TestParseSDPMediaPortRange(t *testing.T) {
	for _, p := range []string{"-1", "+5000", "65536", "99999999", "0x10", "000080"} {
		if _, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio "+p+" RTP/AVP 0"), loLocal); err == nil {
			t.Errorf("port %q accepted", p)
		}
	}
	for p, want := range map[string]int{"0": 0, "1": 1, "65535": 65535, "49170/2": 49170} {
		d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio "+p+" RTP/AVP 0"), loLocal)
		if err != nil || d.streams[0].port != want {
			t.Errorf("port %q: %v err=%v, want %d", p, d.streams, err, want)
		}
	}
}

func TestParseSDPValidatesARejectedStreamToo(t *testing.T) {
	_, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio 4000 RTP/AVP 0", "m=video 5000 RTP/AVP 31", "c=IN IP4 localhost"), loLocal)
	if err == nil {
		t.Fatal("hostname on a video stream accepted")
	}
}

func TestBuildAnswerRefusesAHostnameOffer(t *testing.T) {
	offer := sdpOf("v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "c=IN IP4 localhost", "t=0 0", "m=audio 4000 RTP/AVP 0")
	_, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: loLocal, SRTP: SRTPDisabled})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindNoCommonCodec || sess != nil {
		t.Fatalf("err=%v sess=%v, want no_common_codec", err, sess)
	}
	if got := ne.Detail()["sip_response_sent"]; fmt.Sprint(got) != "488" {
		t.Fatalf("sip_response_sent=%v, want 488", got)
	}
}

func TestParseAnswerRefusesAHostnameAnswer(t *testing.T) {
	_, off, err := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	if err != nil {
		t.Fatal(err)
	}
	ans := sdpOf("v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "c=IN IP4 localhost", "t=0 0", "m=audio 4000 RTP/AVP 0")
	_, err = ParseAnswer(off, ans)
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSDPUnparseable || ne.Detail()["action"] != "ack_then_bye" {
		t.Fatalf("err=%v, want sdp_unparseable ack_then_bye", err)
	}
}

func TestIPv6ConnectionLineIsStillIgnored(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 198.51.100.1", "m=audio 4000 RTP/AVP 0", "c=IN IP6 media.invalid"), loLocal)
	if err != nil || d.streams[0].host != "198.51.100.1" {
		t.Fatalf("host=%v err=%v", d.streams, err)
	}
}

// The security half of CF-201 (LA-1) through both public entry points: a
// loopback c= is refused when our own media address is not loopback.
func TestLoopbackPeerAddressIsRefusedForANonLoopbackLocalAddr(t *testing.T) {
	offer := sdpOf("v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0", "m=audio 4000 RTP/AVP 0")
	_, _, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPDisabled})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindNoCommonCodec {
		t.Fatalf("BuildAnswer err=%v, want no_common_codec", err)
	}
	_, off, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:20000", SRTPDisabled)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAnswer(off, offer)
	if !errors.As(err, &ne) || ne.Kind != KindSDPUnparseable {
		t.Fatalf("ParseAnswer err=%v, want sdp_unparseable", err)
	}
}
