package media

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func keyOf(t *testing.T) CryptoParams {
	t.Helper()
	cp, _, err := GenerateCryptoAttr()
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// b64 is a base64 inline key of n decoded bytes.
func b64(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

func b64of(cp CryptoParams) string {
	return strings.SplitN(cp.attrLine("1"), "inline:", 2)[1]
}

func savpOffer(proto string, cryptoLines ...string) []byte {
	lines := []string{"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "c=IN IP4 10.0.0.1", "t=0 0", "m=audio 4000 " + proto + " 0", "a=rtpmap:0 PCMU/8000"}
	return sdpOf(append(lines, cryptoLines...)...)
}

func answerLines(sdp []byte) (cryptos []string) {
	for _, l := range strings.Split(string(sdp), "\r\n") {
		if strings.HasPrefix(l, "a=crypto:") {
			cryptos = append(cryptos, l)
		}
	}
	return
}

func TestBuildAnswerTakesTheFirstSupportedCryptoLine(t *testing.T) {
	k := keyOf(t)
	for _, tc := range []struct {
		name   string
		proto  string
		policy SRTPPolicy
	}{{"required SAVP", "RTP/SAVP", SRTPRequired}, {"optional SAVP", "RTP/SAVP", SRTPOptional}, {"optional AVP", "RTP/AVP", SRTPOptional}} {
		t.Run(tc.name, func(t *testing.T) {
			offer := savpOffer(tc.proto,
				"a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:"+b64(46),
				"a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:"+b64of(k))
			sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: tc.policy})
			if err != nil {
				t.Fatalf("BuildAnswer: %v", err)
			}
			got := answerLines(sdp)
			if len(got) != 1 || !strings.HasPrefix(got[0], "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:") {
				t.Fatalf("answer crypto lines %q, want one starting a=crypto:2", got)
			}
			if sess.RemoteCrypto == nil || *sess.RemoteCrypto != k {
				t.Fatalf("RemoteCrypto %+v, want %+v", sess.RemoteCrypto, k)
			}
			if sess.LocalCrypto == nil || sess.LocalCrypto.MasterKey == k.MasterKey {
				t.Fatalf("LocalCrypto %+v must be a fresh key", sess.LocalCrypto)
			}
		})
	}
}

func TestBuildAnswerSkipsAnInvalidCryptoLine(t *testing.T) {
	k := keyOf(t)
	offer := savpOffer("RTP/SAVP",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"+b64(20),
		"a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:"+b64of(k))
	sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	if got := answerLines(sdp); len(got) != 1 || !strings.HasPrefix(got[0], "a=crypto:7 ") || *sess.RemoteCrypto != k {
		t.Fatalf("answer %q remote %+v, want tag 7 and key %+v", got, sess.RemoteCrypto, k)
	}
}

func TestBuildAnswerSkipsALineWithAnMKI(t *testing.T) {
	k := keyOf(t)
	offer := savpOffer("RTP/SAVP",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"+b64(30)+"|2^20|1:4",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:"+b64of(k))
	sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	if got := answerLines(sdp); len(got) != 1 || !strings.HasPrefix(got[0], "a=crypto:2 ") || *sess.RemoteCrypto != k {
		t.Fatalf("answer %q, want tag 2", got)
	}
}

func TestBuildAnswerWithNoSupportedCryptoLine(t *testing.T) {
	aes256 := "a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:" + b64(46)
	_, _, err := BuildAnswer(savpOffer("RTP/SAVP", aes256), AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	var ne *NegotiationError
	if !errors.As(err, &ne) || ne.Kind != KindSRTPRequiredPeerOfferedAVP {
		t.Fatalf("required: err=%v, want srtp_required_but_peer_offered_avp", err)
	}
	sdp, sess, err := BuildAnswer(savpOffer("RTP/AVP", aes256), AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPOptional})
	if err != nil || len(answerLines(sdp)) != 0 || sess.LocalCrypto != nil {
		t.Fatalf("optional AVP: err=%v answer crypto=%q local=%v, want a plain answer", err, answerLines(sdp), sess.LocalCrypto)
	}
}

func TestBuildAnswerEchoesTheTagOnAReOffer(t *testing.T) {
	k := keyOf(t)
	first := savpOffer("RTP/SAVP", "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"+b64of(k))
	_, prev, err := BuildAnswer(first, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	re := savpOffer("RTP/SAVP", "a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:"+b64of(k))
	sdp, again, err := BuildAnswer(re, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired, Prev: prev})
	if err != nil {
		t.Fatal(err)
	}
	want := prev.LocalCrypto.attrLine("5")
	if got := answerLines(sdp); len(got) != 1 || got[0] != want || *again.LocalCrypto != *prev.LocalCrypto {
		t.Fatalf("answer %q, want %q with Prev's key", got, want)
	}
}

func TestParseCryptoAttrTag(t *testing.T) {
	key := b64(30)
	for tag, ok := range map[string]bool{"1": true, "0": true, "123456789": true, "01": false, "x": false, "1234567890": false, "-1": false} {
		_, err := ParseCryptoAttr("a=crypto:" + tag + " AES_CM_128_HMAC_SHA1_80 inline:" + key)
		if (err == nil) != ok {
			t.Errorf("tag %q: err=%v, want ok=%v", tag, err, ok)
		}
	}
}

func TestParseCryptoAttrSupportedForm(t *testing.T) {
	key := b64(30)
	pre := "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + key
	accepted := map[string]uint64{
		pre: 0, pre + "|2^20": 1048576, pre + "|1048576": 1048576, pre + "|2^0": 1, pre + "|2^31": 1 << 31,
		pre + "|2147483647": 2147483647, pre + "|2^48": 1 << 48, pre + "|281474976710656": 1 << 48,
		pre + " WSH=64": 0, pre + " wsh=64": 0, pre + " Wsh=128": 0, pre + " -X=1": 0, pre + "|2^20 WSH=128 -Y": 1048576,
	}
	for line, want := range accepted {
		cp, err := ParseCryptoAttr(line)
		if err != nil || cp.Lifetime != want {
			t.Errorf("%q: lifetime=%d err=%v, want %d", line, cp.Lifetime, err, want)
		}
	}
	refused := []string{
		pre + "|0", pre + "|2^", pre + "|2^01", pre + "|2^49", pre + "|281474976710657", pre + "|99999999999999999999",
		pre + "|01", pre + "|abc", pre + "|", pre + "|2^31|2^31",
		pre + " WSH=abc", pre + " wsh=32", pre + " wsh=064", pre + " kdr=1", pre + " unencrypted_srtp", pre + " Unauthenticated_SRTP", pre + " fec_order=FEC_SRTP", pre + " 64", pre + " WSH=6", pre + " WSH=32", pre + " WSH=064",
		pre + "|2^20|1:4", pre + "|1:4",
		pre + "|2^20|1:4;inline:" + key + "|2^20|2:4",
		pre + " UNENCRYPTED_SRTP", pre + " KDR=1", pre + " WSH=64 UNENCRYPTED_SRTCP", pre + " SOMETHING",
	}
	for _, line := range refused {
		if _, err := ParseCryptoAttr(line); err == nil {
			t.Errorf("%q accepted", line)
		}
	}
}

func TestAttrLineKeepsTagOne(t *testing.T) {
	k := keyOf(t)
	if !strings.HasPrefix(k.AttrLine(), "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:") {
		t.Fatalf("AttrLine %q", k.AttrLine())
	}
	body, sess, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:16384", SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), sess.LocalCrypto.AttrLine()) {
		t.Fatalf("offer does not carry %q:\n%s", sess.LocalCrypto.AttrLine(), body)
	}
}

func TestParseAnswerRequiresTheOfferedTag(t *testing.T) {
	a, b := keyOf(t), keyOf(t)
	ans := func(proto string, lines ...string) []byte {
		return sdpOf(append([]string{"v=0", "c=IN IP4 198.51.100.1", "t=0 0", "m=audio 20000 " + proto + " 0", "a=rtpmap:0 PCMU/8000"}, lines...)...)
	}
	lineA2 := "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:" + b64of(a)
	lineB1 := "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + b64of(b)
	for _, tc := range []struct {
		name    string
		policy  SRTPPolicy
		answer  []byte
		kind    string // "" = accepted
		wantKey *CryptoParams
	}{
		{"required tag 2", SRTPRequired, ans("RTP/SAVP", lineA2), KindSRTPRequiredPeerAnsweredAVP, nil},
		{"optional tag 2", SRTPOptional, ans("RTP/AVP", lineA2), KindSDPUnparseable, nil},
		{"tag 2 then tag 1", SRTPRequired, ans("RTP/SAVP", lineA2, lineB1), "", &b},
		{"tag 1", SRTPRequired, ans("RTP/SAVP", lineB1), "", &b},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, off, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:16384", tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := ParseAnswer(off, tc.answer)
			var ne *NegotiationError
			if tc.kind != "" {
				if !errors.As(err, &ne) || ne.Kind != tc.kind {
					t.Fatalf("err=%v, want %s", err, tc.kind)
				}
				return
			}
			if err != nil || sess.RemoteCrypto == nil || *sess.RemoteCrypto != *tc.wantKey {
				t.Fatalf("err=%v remote=%+v, want key %+v", err, sess.RemoteCrypto, tc.wantKey)
			}
		})
	}
}

// RFC 4568 4: session-parameter names are case-insensitive, so a lower or mixed
// case WSH= is negotiated like WSH=.
func TestBuildAnswerAcceptsAMixedCaseSessionParameter(t *testing.T) {
	k := keyOf(t)
	for _, param := range []string{"WSH=64", "wsh=64", "Wsh=64"} {
		offer := savpOffer("RTP/SAVP", "a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:"+b64of(k)+" "+param)
		sdp, sess, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
		if err != nil {
			t.Fatalf("%s: %v", param, err)
		}
		if got := answerLines(sdp); len(got) != 1 || !strings.HasPrefix(got[0], "a=crypto:3 ") || *sess.RemoteCrypto != k {
			t.Fatalf("%s: answer %q", param, got)
		}
	}
}
