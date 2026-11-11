package media

import (
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
)

func TestBuildOfferListsAllPrefsInOrder(t *testing.T) {
	sdp, sess, err := BuildOffer(CodecPrefs{"PCMU", "PCMA"}, "192.0.2.7:16384", SRTPDisabled)
	if err != nil {
		t.Fatalf("BuildOffer: %v", err)
	}
	body := string(sdp)
	if !strings.Contains(body, "m=audio 16384 RTP/AVP 0 8 101\r\n") {
		t.Fatalf("m= line wrong:\n%s", body)
	}
	if !strings.Contains(body, "c=IN IP4 192.0.2.7\r\n") {
		t.Fatalf("c= line wrong:\n%s", body)
	}
	if !strings.Contains(body, "a=rtpmap:0 PCMU/8000") || !strings.Contains(body, "a=rtpmap:8 PCMA/8000") {
		t.Fatalf("rtpmap lines missing:\n%s", body)
	}
	if strings.Contains(body, "a=crypto:") {
		t.Fatal("non-SRTP offer must carry no a=crypto")
	}
	if sess.LocalAddr != "192.0.2.7:16384" || sess.State() != StateNegotiating {
		t.Fatalf("session=%+v", sess)
	}
}

func TestBuildOfferSRTPAddsCryptoAndSAVP(t *testing.T) {
	sdp, sess, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:16384", SRTPRequired)
	if err != nil {
		t.Fatalf("BuildOffer: %v", err)
	}
	body := string(sdp)
	if !strings.Contains(body, "m=audio 16384 RTP/SAVP 0 101\r\n") {
		t.Fatalf("SRTP m= line wrong:\n%s", body)
	}
	if !strings.Contains(body, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:") {
		t.Fatalf("SRTP offer missing a=crypto:\n%s", body)
	}
	if sess.LocalCrypto == nil || sess.LocalCrypto.Suite != SuiteAESCM128HMACSHA180 {
		t.Fatalf("session local crypto not populated: %+v", sess.LocalCrypto)
	}
	if sess.RemoteCrypto != nil {
		t.Fatal("BuildOffer must not populate RemoteCrypto (no peer answer yet)")
	}
}

func TestBuildOfferRejectsEmptyPrefsAndUnknownCodec(t *testing.T) {
	if _, _, err := BuildOffer(CodecPrefs{}, "192.0.2.7:16384", SRTPDisabled); err == nil {
		t.Fatal("empty prefs must error")
	}
	if _, _, err := BuildOffer(CodecPrefs{"opus"}, "192.0.2.7:16384", SRTPDisabled); err == nil {
		t.Fatal("unknown/unsupported codec must error")
	}
}

func TestBuildOfferAdvertisesTelephoneEvent(t *testing.T) {
	body, sess, err := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	if err != nil {
		t.Fatalf("BuildOffer: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "a=rtpmap:101 telephone-event/8000") {
		t.Fatalf("offer lacks the telephone-event rtpmap:\n%s", s)
	}
	if !strings.Contains(s, "a=fmtp:101 0-15") {
		t.Fatalf("offer lacks the telephone-event fmtp:\n%s", s)
	}
	if !strings.Contains(s, "m=audio 20000 RTP/AVP 0 101") {
		t.Fatalf("offer's m= line must list 101 after the codecs:\n%s", s)
	}
	if sess.TelephoneEventPT != 101 {
		t.Fatalf("Session.TelephoneEventPT=%d want 101", sess.TelephoneEventPT)
	}
}

// TestTelephoneEventOfferPTMatchesCodecConstant pins telephoneEventOfferPT
// (this package's local restatement) equal to codec.DTMFPayloadType (the
// value the DTMF machinery actually sends/expects), so the two constants
// cannot silently drift apart. Nothing else in the codebase asserts this.
func TestTelephoneEventOfferPTMatchesCodecConstant(t *testing.T) {
	if telephoneEventOfferPT != int(codec.DTMFPayloadType) {
		t.Fatalf("telephoneEventOfferPT=%d want %d (codec.DTMFPayloadType)", telephoneEventOfferPT, codec.DTMFPayloadType)
	}
}

func TestBuildOfferOptionalOffersAVPWithCrypto(t *testing.T) {
	sdp, sess, err := BuildOffer(CodecPrefs{"PCMU"}, "192.0.2.7:16384", SRTPOptional)
	if err != nil {
		t.Fatal(err)
	}
	body := string(sdp)
	if !strings.Contains(body, "m=audio 16384 RTP/AVP 0 101\r\n") || strings.Count(body, "a=crypto:") != 1 || sess.LocalCrypto == nil {
		t.Fatalf("optional offer wrong (LocalCrypto %v):\n%s", sess.LocalCrypto, body)
	}
}
