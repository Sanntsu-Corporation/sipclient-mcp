package media

import (
	"strconv"
	"strings"
	"testing"
)

const reofferPCMU = "v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"

func liveSession(t *testing.T, offer string, prefs CodecPrefs, srtp SRTPPolicy) *Session {
	t.Helper()
	_, sess, err := BuildAnswer([]byte(offer), AnswerOptions{Prefs: prefs, LocalAddr: "127.0.0.1:16384", SRTP: srtp})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func mLine(sdp, prefix string) string {
	for _, l := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func TestBuildReOfferListsEveryCodecAtTheLivePort(t *testing.T) {
	prev := liveSession(t, reofferPCMU, CodecPrefs{"PCMU", "PCMA"}, SRTPDisabled)
	body, sess, err := BuildReOffer(prev, CodecPrefs{"PCMU", "PCMA"})
	if err != nil {
		t.Fatal(err)
	}
	if got := mLine(string(body), "m=audio"); got != "m=audio 16384 RTP/AVP 0 8 101" {
		t.Errorf("m line %q", got)
	}
	want := prev.Origin
	if got := mLine(string(body), "o="); got != "o=- "+itoa(want.SessID)+" "+itoa(want.Version+1)+" IN IP4 127.0.0.1" {
		t.Errorf("o= %q (prev %+v)", got, want)
	}
	if !strings.Contains(string(body), "a=sendrecv") {
		t.Error("no a=sendrecv")
	}
	if sess.Origin.Version != want.Version+1 || sess.Origin.SessID != want.SessID {
		t.Errorf("returned origin %+v", sess.Origin)
	}
	// The live codec first: a PCMA session lists 8 before 0.
	prevA := liveSession(t, reofferPCMU, CodecPrefs{"PCMA", "PCMU"}, SRTPDisabled)
	if prevA.Codec != "PCMA" {
		t.Fatalf("precondition: live codec %q, want PCMA", prevA.Codec)
	}
	bodyA, _, err := BuildReOffer(prevA, CodecPrefs{"PCMU", "PCMA"})
	if err != nil {
		t.Fatal(err)
	}
	if got := mLine(string(bodyA), "m=audio"); got != "m=audio 16384 RTP/AVP 8 0 101" {
		t.Errorf("m line %q, want the live codec first", got)
	}
}

func TestBuildReOfferKeepsTheSRTPKeyAndProfile(t *testing.T) {
	offer, _, err := BuildOffer(CodecPrefs{"PCMU"}, "198.51.100.1:20000", SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	prev := liveSession(t, string(offer), CodecPrefs{"PCMU"}, SRTPRequired)
	body, sess, err := BuildReOffer(prev, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	if got := mLine(string(body), "m=audio"); !strings.Contains(got, "RTP/SAVP") {
		t.Errorf("m line %q, want RTP/SAVP", got)
	}
	if n := strings.Count(string(body), "a=crypto"); n != 1 || !strings.Contains(string(body), prev.LocalCrypto.AttrLine()) {
		t.Errorf("want exactly our existing key, got:\n%s", body)
	}
	if sess.LocalCrypto == nil || *sess.LocalCrypto != *prev.LocalCrypto || sess.LocalCrypto == prev.LocalCrypto {
		t.Error("returned session must carry a copy of the live key")
	}
	plain := liveSession(t, reofferPCMU, CodecPrefs{"PCMU"}, SRTPDisabled)
	pb, _, err := BuildReOffer(plain, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pb), "a=crypto") {
		t.Error("a key was added to a plain session")
	}
}

func TestBuildReOfferKeepsEveryMediaLine(t *testing.T) {
	offer := "v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=video 30000 RTP/AVP 0\r\na=rtpmap:0 H264/90000\r\n" +
		"m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
	prev := liveSession(t, offer, CodecPrefs{"PCMU"}, SRTPDisabled)
	if len(prev.Streams) != 2 || prev.Live != 1 {
		t.Fatalf("precondition: streams %d live %d", len(prev.Streams), prev.Live)
	}
	body, sess, err := BuildReOffer(prev, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(body), "\r\n")
	var ms []string
	for _, l := range lines {
		if strings.HasPrefix(l, "m=") {
			ms = append(ms, l)
		}
	}
	if len(ms) != 2 || ms[0] != "m=video 0 "+prev.Streams[0].Proto+" 0" || !strings.HasPrefix(ms[1], "m=audio 16384 ") {
		t.Errorf("m lines %q", ms)
	}
	if len(sess.Streams) != 2 || sess.Live != 1 {
		t.Errorf("returned session streams %d live %d", len(sess.Streams), sess.Live)
	}
}

func TestBuildReOfferReusesTheLiveEventPT(t *testing.T) {
	prev := liveSession(t, reofferPCMU, CodecPrefs{"PCMU"}, SRTPDisabled)
	prev.TelephoneEventPT = 96
	body, _, err := BuildReOffer(prev, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RTP/AVP 0 96", "a=rtpmap:96 telephone-event/8000", "a=fmtp:96 0-15"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
	prev.TelephoneEventPT = 0
	body, _, _ = BuildReOffer(prev, CodecPrefs{"PCMU"})
	if !strings.Contains(string(body), "RTP/AVP 0 101") {
		t.Errorf("default event PT not 101:\n%s", body)
	}
}

func TestBuildReOfferRefusesALocalFault(t *testing.T) {
	good := liveSession(t, reofferPCMU, CodecPrefs{"PCMU"}, SRTPDisabled)
	noStreams := *good
	noStreams.Streams = nil
	badLive := *good
	badLive.Live = 5
	for name, tc := range map[string]struct {
		prev  *Session
		prefs CodecPrefs
	}{
		"nil prev":    {nil, CodecPrefs{"PCMU"}},
		"no streams":  {&noStreams, CodecPrefs{"PCMU"}},
		"live range":  {&badLive, CodecPrefs{"PCMU"}},
		"empty prefs": {good, nil},
		"unsupported": {good, CodecPrefs{"PCMU", "OPUS"}},
	} {
		if _, _, err := BuildReOffer(tc.prev, tc.prefs); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// The answer to a BuildReOffer is read from the live stream's m= line, with every
// other offered stream kept (multi-stream ParseAnswer, CF-207).
func TestParseAnswerReadsTheLiveStreamOfAMultiStreamOffer(t *testing.T) {
	offer := "v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=video 30000 RTP/AVP 0\r\na=rtpmap:0 H264/90000\r\n" +
		"m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
	prev := liveSession(t, offer, CodecPrefs{"PCMU", "PCMA"}, SRTPDisabled)
	_, reoffer, err := BuildReOffer(prev, CodecPrefs{"PCMU", "PCMA"})
	if err != nil {
		t.Fatal(err)
	}
	answer := "v=0\r\no=q 5 5 IN IP4 127.0.0.2\r\ns=-\r\nc=IN IP4 127.0.0.2\r\nt=0 0\r\n" +
		"m=video 0 RTP/AVP 0\r\nm=audio 40000 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
	got, nerr := ParseAnswer(reoffer, []byte(answer))
	if nerr != nil {
		t.Fatalf("ParseAnswer: %v", nerr)
	}
	if got.Codec != "PCMA" || got.RemoteAddr != "127.0.0.2:40000" || len(got.Streams) != 2 || got.Live != 1 {
		t.Errorf("codec %q remote %q streams %d live %d", got.Codec, got.RemoteAddr, len(got.Streams), got.Live)
	}
}

func TestParseAnswerWithTooFewStreamsIsUnparseable(t *testing.T) {
	offer := "v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=video 30000 RTP/AVP 0\r\na=rtpmap:0 H264/90000\r\n" +
		"m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
	prev := liveSession(t, offer, CodecPrefs{"PCMU"}, SRTPDisabled)
	_, reoffer, err := BuildReOffer(prev, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	one := "v=0\r\no=q 5 5 IN IP4 127.0.0.2\r\ns=-\r\nc=IN IP4 127.0.0.2\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	if _, nerr := ParseAnswer(reoffer, []byte(one)); nerr == nil {
		t.Fatal("an answer with fewer m= lines than the offer was accepted")
	}
}

func TestParseAnswerOmittingTrailingStreamsIsUnparseable(t *testing.T) {
	offer := "v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n" +
		"m=video 30000 RTP/AVP 0\r\na=rtpmap:0 H264/90000\r\n"
	prev := liveSession(t, offer, CodecPrefs{"PCMU"}, SRTPDisabled)
	_, reoffer, err := BuildReOffer(prev, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	hdr := "v=0\r\no=q 5 5 IN IP4 127.0.0.2\r\ns=-\r\nc=IN IP4 127.0.0.2\r\nt=0 0\r\n"
	audio := "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	if _, nerr := ParseAnswer(reoffer, []byte(hdr+audio)); nerr == nil {
		t.Fatal("an answer omitting the trailing video m= line was accepted")
	}
	if _, nerr := ParseAnswer(reoffer, []byte(hdr+audio+"m=video 0 RTP/AVP 0\r\n")); nerr != nil {
		t.Fatalf("the answer with both m= lines: %v", nerr)
	}
	// Extra streams beyond the offer are ignored (locked policy).
	if _, nerr := ParseAnswer(reoffer, []byte(hdr+audio+"m=video 0 RTP/AVP 0\r\nm=audio 0 RTP/AVP 0\r\n")); nerr != nil {
		t.Fatalf("an answer with an extra stream: %v", nerr)
	}
}

func TestParseAnswerReceivesOurOfferedEventPT(t *testing.T) {
	prev := liveSession(t, reofferPCMU, CodecPrefs{"PCMU"}, SRTPDisabled)
	prev.TelephoneEventPT = 96
	_, reoffer, err := BuildReOffer(prev, CodecPrefs{"PCMU"})
	if err != nil {
		t.Fatal(err)
	}
	answer := "v=0\r\no=q 5 5 IN IP4 127.0.0.2\r\ns=-\r\nc=IN IP4 127.0.0.2\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
	got, nerr := ParseAnswer(reoffer, []byte(answer))
	if nerr != nil {
		t.Fatal(nerr)
	}
	if !got.RecvEventPTs[96] || !got.RecvEventPTs[101] {
		t.Errorf("RecvEventPTs %v, want 96 and 101", got.RecvEventPTs)
	}
	// a hand-built session with no event PT keeps the 101 default
	hand := &Session{LocalAddr: "127.0.0.1:16384", state: StateNegotiating, offered: CodecPrefs{"PCMU"}, Streams: []Stream{{Media: "audio", Proto: "RTP/AVP", LocalPort: 16384}}}
	got, nerr = ParseAnswer(hand, []byte(answer))
	if nerr != nil {
		t.Fatal(nerr)
	}
	if !got.RecvEventPTs[101] {
		t.Errorf("RecvEventPTs %v, want 101", got.RecvEventPTs)
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }
