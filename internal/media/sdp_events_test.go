package media

import (
	"reflect"
	"testing"
)

func codes(lo, hi int) map[uint8]bool {
	m := map[uint8]bool{}
	for c := lo; c <= hi; c++ {
		m[uint8(c)] = true
	}
	return m
}

func with(m map[uint8]bool, cs ...uint8) map[uint8]bool {
	for _, c := range cs {
		m[c] = true
	}
	return m
}

func TestParseEvents(t *testing.T) {
	for _, c := range []struct {
		in   string
		want map[uint8]bool
	}{
		{"0-15", codes(0, 15)},
		{"0-11", codes(0, 11)},
		{"0-15,66,70-73", with(codes(0, 15), 66, 70, 71, 72, 73)},
		{" 0-3 , 7", with(codes(0, 3), 7)},
		{"", nil}, {"foo", nil}, {"16-5", nil}, {"300", nil}, {"0-300", nil},
		{"5,x,9", with(map[uint8]bool{}, 5, 9)},
		{"255", map[uint8]bool{255: true}},
	} {
		if got := parseEvents(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseEvents(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPeerEventsComeFromThePeersSDP(t *testing.T) {
	mk := func(fmtp ...string) []byte {
		l := []string{"v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0", "m=audio 4000 RTP/AVP 0 101",
			"a=rtpmap:0 PCMU/8000", "a=rtpmap:101 telephone-event/8000"}
		return sdpOf(append(l, fmtp...)...)
	}
	opts := AnswerOptions{Prefs: CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:16384"}
	_, sess, err := BuildAnswer(mk("a=fmtp:101 0-11"), opts)
	if err != nil || !reflect.DeepEqual(sess.PeerEvents, codes(0, 11)) {
		t.Fatalf("PeerEvents %v err %v", sess.PeerEvents, err)
	}
	_, sess, _ = BuildAnswer(mk(), opts)
	if sess.PeerEvents != nil || !sess.PeerAcceptsEvent(15) || sess.PeerAcceptsEvent(16) {
		t.Fatalf("absent list: PeerEvents %v", sess.PeerEvents)
	}
	if got := (&Session{PeerEvents: with(codes(0, 3), 7)}).PeerEventsText(); got != "0-3,7" {
		t.Fatalf("PeerEventsText = %q", got)
	}

	_, off, _ := BuildOffer(CodecPrefs{"PCMU"}, "127.0.0.1:20000", SRTPDisabled)
	ans := sdpOf("v=0", "c=IN IP4 127.0.0.1", "m=audio 4000 RTP/AVP 0 96", "a=rtpmap:0 PCMU/8000",
		"a=rtpmap:96 telephone-event/8000", "a=fmtp:96 0-9", "a=fmtp:101 0-3")
	got, err := ParseAnswer(off, ans)
	if err != nil || !reflect.DeepEqual(got.PeerEvents, codes(0, 9)) {
		t.Fatalf("answer PeerEvents %v err %v", got.PeerEvents, err)
	}
}
