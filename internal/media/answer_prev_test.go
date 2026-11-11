package media

import (
	"strings"
	"testing"
)

// RFC 3264 8: the o= of a later SDP keeps the session id and increments the version.
func TestBuildAnswerWithPrevIncrementsTheVersion(t *testing.T) {
	prev := &Session{Origin: Origin{SessID: 42, Version: 3}}
	sdp, sess, err := BuildAnswer(offerBody(t, false, "PCMU"),
		AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", Prev: prev})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	if !strings.Contains(string(sdp), "o=- 42 4 IN IP4 192.0.2.7\r\n") {
		t.Errorf("answer o= line is not `o=- 42 4 IN IP4 192.0.2.7`:\n%s", sdp)
	}
	if sess.Origin != (Origin{SessID: 42, Version: 4}) {
		t.Errorf("Origin = %+v, want {42 4}", sess.Origin)
	}
}

// A re-offer's answer keeps the SDES key the live transform already uses.
func TestBuildAnswerWithPrevKeepsOurSRTPKey(t *testing.T) {
	offer := offerBody(t, true, "PCMU")
	_, first, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired})
	if err != nil {
		t.Fatalf("first BuildAnswer: %v", err)
	}
	sdp, again, err := BuildAnswer(offer, AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "192.0.2.7:16384", SRTP: SRTPRequired, Prev: first})
	if err != nil {
		t.Fatalf("re-offer BuildAnswer: %v", err)
	}
	if again.LocalCrypto == nil || *again.LocalCrypto != *first.LocalCrypto {
		t.Fatalf("LocalCrypto changed: %+v vs %+v", again.LocalCrypto, first.LocalCrypto)
	}
	if !strings.Contains(string(sdp), first.LocalCrypto.AttrLine()) {
		t.Errorf("answer does not carry the existing key line %q:\n%s", first.LocalCrypto.AttrLine(), sdp)
	}
}
