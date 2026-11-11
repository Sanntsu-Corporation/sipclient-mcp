package media

import (
	"reflect"
	"strings"
	"testing"
)

func sdpOf(lines ...string) []byte { return []byte(strings.Join(lines, "\r\n") + "\r\n") }

func TestParseSDPScopesConnectionToItsMediaBlock(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "t=0 0", "m=audio 4000 RTP/AVP 0", "m=video 5000 RTP/AVP 31", "c=IN IP4 10.0.0.2"), "127.0.0.1:16384")
	if err != nil {
		t.Fatal(err)
	}
	if d.streams[0].host != "10.0.0.1" || d.streams[1].host != "10.0.0.2" {
		t.Fatalf("hosts %q %q, want 10.0.0.1 10.0.0.2", d.streams[0].host, d.streams[1].host)
	}
}

func TestParseSDPMediaLevelConnectionOverridesSession(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio 4000 RTP/AVP 0", "c=IN IP4 10.0.0.3"), "127.0.0.1:16384")
	if err != nil || d.streams[0].host != "10.0.0.3" {
		t.Fatalf("host %q err %v, want 10.0.0.3", d.streams[0].host, err)
	}
}

func TestParseSDPKeepsEveryStreamInOrder(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=video 15284 RTP/AVP 31", "m=audio 15282 RTP/AVP 0"), "127.0.0.1:16384")
	if err != nil || len(d.streams) != 2 {
		t.Fatalf("streams %d err %v", len(d.streams), err)
	}
	v, a := d.streams[0], d.streams[1]
	if v.media != "video" || v.port != 15284 || !reflect.DeepEqual(v.fmts, []string{"31"}) ||
		a.media != "audio" || a.port != 15282 || !reflect.DeepEqual(a.fmts, []string{"0"}) {
		t.Fatalf("streams %+v", d.streams)
	}
}

func TestParseSDPRefusesAnUnknownTypeLetter(t *testing.T) {
	base := func(extra string) []byte {
		return sdpOf("v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", extra, "c=IN IP4 10.0.0.1", "t=0 0", "m=audio 4000 RTP/AVP 0")
	}
	for _, line := range []string{"y=rfcsweep-d", "Y=x", "garbage", "q=1", "a"} {
		if _, err := parseSDP(base(line), "127.0.0.1:16384"); err == nil {
			t.Errorf("line %q: want an error", line)
		}
	}
	for _, l := range strings.Split(sdpTypeLetters, "") {
		line := l + "=x"
		if l == "m" {
			line = "m=audio 4001 RTP/AVP 0"
		}
		if _, err := parseSDP(base(line), "127.0.0.1:16384"); err != nil {
			t.Errorf("known letter %q: %v", l, err)
		}
	}
	if _, err := parseSDP([]byte("v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n\r\n"), "127.0.0.1:16384"); err != nil {
		t.Errorf("trailing blank line: %v", err)
	}
}

func TestParseSDPDirectionDefaultsAndOverrides(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "a=sendonly", "m=audio 4000 RTP/AVP 0", "m=audio 4002 RTP/AVP 0", "a=inactive"), "127.0.0.1:16384")
	if err != nil || d.streams[0].dir != DirSendOnly || d.streams[1].dir != DirInactive {
		t.Fatalf("dirs %q %q err %v", d.streams[0].dir, d.streams[1].dir, err)
	}
	d, err = parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio 4000 RTP/AVP 0"), "127.0.0.1:16384")
	if err != nil || d.streams[0].dir != DirSendRecv {
		t.Fatalf("default dir %q err %v", d.streams[0].dir, err)
	}
}

func TestParseSDPAttributesBelongToTheirStream(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "a=rtpmap:96 AMR/8000",
		"m=audio 4000 RTP/AVP 96", "a=rtpmap:96 PCMU/8000", "m=video 5000 RTP/AVP 96", "a=rtpmap:96 H264/90000"), "127.0.0.1:16384")
	if err != nil || !reflect.DeepEqual(d.streams[0].codecs, []string{"PCMU"}) {
		t.Fatalf("audio codecs %v err %v", d.streams[0].codecs, err)
	}
}

func TestParseSDPAcceptsAPortCountSuffix(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio 49170/2 RTP/AVP 0"), "127.0.0.1:16384")
	if err != nil || d.streams[0].port != 49170 {
		t.Fatalf("port %v err %v", d.streams, err)
	}
}

func TestParseSDPDropsOutOfRangePayloadTypes(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "m=audio 4000 RTP/AVP 0 200 -1"), "127.0.0.1:16384")
	if err != nil || !reflect.DeepEqual(d.streams[0].codecs, []string{"PCMU"}) {
		t.Fatalf("codecs %v err %v", d.streams[0].codecs, err)
	}
}

func TestParseSDPKeepsTheFirstTimeLine(t *testing.T) {
	d, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", "t=3034423619 3042462419", "t=0 0", "m=audio 4000 RTP/AVP 0"), "127.0.0.1:16384")
	if err != nil || d.timeLine != "t=3034423619 3042462419" {
		t.Fatalf("t line %q err %v", d.timeLine, err)
	}
}

// A bare CR or a control byte in a line would be echoed into our answer (the
// offer's t= line and a rejected stream's m= line are mirrored): refuse it.
func TestParseSDPRefusesControlCharacters(t *testing.T) {
	for _, line := range []string{
		"t=0 0\rm=audio 9 RTP/AVP 0\rc=IN IP4 6.6.6.6",
		"m=vid\x00eo 5002 RTP/AVP 31",
	} {
		if _, err := parseSDP(sdpOf("v=0", "c=IN IP4 10.0.0.1", line, "m=audio 4000 RTP/AVP 0"), "127.0.0.1:16384"); err == nil {
			t.Fatalf("line %q was accepted, want a parse error", line)
		}
	}
}
