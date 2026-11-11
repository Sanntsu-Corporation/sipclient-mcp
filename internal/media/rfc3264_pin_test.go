package media_test

// Lane D (rfc-sweep-d) pins for SDP-builder deviations in RFC 3264 rows (6a D11).
// Each passes today and must be inverted when its NEW-D finding is fixed.

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
)

// sdpLine returns the first SDP line starting with prefix, without its CRLF.
func sdpLine(t *testing.T, body []byte, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(string(body), "\r\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	t.Fatalf("no %q line in SDP %q", prefix, body)
	return ""
}

// TestRFC3264Pin_NEWD1_OfferSessionNameIsProductName pins NEW-D-1 (D-OFF-07,
// RFC 3264 5: "For unicast sessions, it is RECOMMENDED that it consist of a
// single space character (0x20) or a dash (-)." rfc3264.txt:251-253; also
// D-SDP-17, RFC 4566 5.3: "If a session has no meaningful name, the value
// "s= " SHOULD be used (i.e., a single space as the session name)."
// rfc4566.txt:641-643). Evidence: evidence/rg-echo/excerpt.txt frame 4 (our
// INVITE offer: s=sipclient-mcp). Locus: internal/media/sdp.go:BuildOffer (and
// BuildAnswer), bytes emitted via the INVITE and 200 bodies.
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-1 is fixed.
func TestRFC3264Pin_NEWD1_OfferSessionNameIsProductName(t *testing.T) {
	body, _, err := media.BuildOffer(media.CodecPrefs{"PCMU", "PCMA"}, "198.51.100.1:20000", media.SRTPDisabled)
	if err != nil {
		t.Fatalf("BuildOffer: %v", err)
	}
	if got := sdpLine(t, body, "s="); got != "s=sipclient-mcp" {
		t.Fatalf("offer %q is not s=sipclient-mcp: NEW-D-1 is fixed, invert this pin", got)
	}
}

// offerLines joins SDP lines with CRLF (Lane D answer pins).
func offerLines(lines ...string) []byte { return []byte(strings.Join(lines, "\r\n") + "\r\n") }

// laneDBase returns the base offer of the S-series scenarios (Task 3), with the
// m=audio line and further lines replaced or appended by the caller.
func laneDBase(mLine string, extra ...string) []byte {
	l := []string{"v=0", "o=sipp 1696 1696 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0", mLine,
		"a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000", "a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-16"}
	return offerLines(append(l, extra...)...)
}

func laneDAnswer(t *testing.T, offer []byte) ([]byte, *media.Session) {
	t.Helper()
	ans, sess, err := media.BuildAnswer(offer, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU", "PCMA"}, LocalAddr: "127.0.0.1:16384", SRTP: media.SRTPDisabled})
	if err != nil {
		t.Fatalf("BuildAnswer: %v", err)
	}
	return ans, sess
}

// TestRFC3264Pin_NEWD5_AnswerPicksOurPreferenceNotOffersFirst pins NEW-D-5 (L6,
// D-OFF-19, RFC 3264 5.1: "In this case, preferred means that the recipient of
// the offer SHOULD use the format with the highest preference that is
// acceptable to it." rfc3264.txt:364-366). Evidence: evidence/s-order/excerpt.txt
// (offer 8 0 101, answer 0 101) and rtp.txt (our RTP at PT 0). Locus:
// internal/media/sdp.go:BuildAnswer. TestBuildAnswerSelectsOurPrefOrder
// (sdp_answer_test.go) asserts the design and stays unchanged (6a D20).
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-5 is fixed.
func TestRFC3264Pin_NEWD5_AnswerPicksOurPreferenceNotOffersFirst(t *testing.T) {
	ans, _ := laneDAnswer(t, laneDBase("m=audio 15282 RTP/AVP 8 0 101", "a=sendrecv"))
	if got := sdpLine(t, ans, "m=audio"); !strings.Contains(got, " RTP/AVP 0 ") {
		t.Fatalf("answer %q does not list PT 0 first: NEW-D-5 is fixed, invert this pin", got)
	}
}

// mLines returns the m= lines of an SDP body.
func mLines(body []byte) []string {
	var out []string
	for _, l := range strings.Split(string(body), "\r\n") {
		if strings.HasPrefix(l, "m=") {
			out = append(out, l)
		}
	}
	return out
}

// TestRFC3264_NEWD6_AnswerDirectionFollowsTheOfferMatrix (CF-137, was the
// NEW-D-6 pin; RFC 3264 6.1 rfc3264.txt:493-502).
func TestRFC3264_NEWD6_AnswerDirectionFollowsTheOfferMatrix(t *testing.T) {
	cases := []struct {
		name  string
		extra []string
		want  string
		dir   media.Direction
	}{
		{"sendonly", []string{"a=sendonly"}, "a=recvonly", media.DirRecvOnly},
		{"recvonly", []string{"a=recvonly"}, "a=sendonly", media.DirSendOnly},
		{"inactive", []string{"a=inactive"}, "a=inactive", media.DirInactive},
		{"sendrecv", []string{"a=sendrecv"}, "a=sendrecv", media.DirSendRecv},
		{"none", nil, "a=sendrecv", media.DirSendRecv},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ans, sess := laneDAnswer(t, laneDBase("m=audio 15282 RTP/AVP 0 8 101", c.extra...))
			if !strings.Contains(string(ans), c.want+"\r\n") || sess.Direction != c.dir {
				t.Fatalf("want %s / %s, got Direction %s:\n%s", c.want, c.dir, sess.Direction, ans)
			}
		})
	}
	t.Run("session level", func(t *testing.T) {
		offer := offerLines("v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0", "a=sendonly",
			"m=audio 15282 RTP/AVP 0", "a=rtpmap:0 PCMU/8000")
		ans, sess := laneDAnswer(t, offer)
		if !strings.Contains(string(ans), "a=recvonly\r\n") || sess.Direction != media.DirRecvOnly {
			t.Fatalf("session-level sendonly: Direction %s:\n%s", sess.Direction, ans)
		}
	})
}

// TestRFC3264_NEWD7_AnswerHasOneMLinePerOfferedStream (CF-138, was the NEW-D-7
// pin; rfc3264.txt:468-470).
func TestRFC3264_NEWD7_AnswerHasOneMLinePerOfferedStream(t *testing.T) {
	t.Run("audio then rejected video", func(t *testing.T) {
		ans, _ := laneDAnswer(t, laneDBase("m=audio 15282 RTP/AVP 0 8 101", "a=sendrecv", "m=video 0 RTP/AVP 31"))
		ml := mLines(ans)
		if len(ml) != 2 || ml[1] != "m=video 0 RTP/AVP 31" {
			t.Fatalf("m lines %q", ml)
		}
	})
	t.Run("video then audio", func(t *testing.T) {
		offer := offerLines("v=0", "o=sipp 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0",
			"m=video 15284 RTP/AVP 31", "m=audio 15282 RTP/AVP 0 101", "a=rtpmap:0 PCMU/8000", "a=rtpmap:101 telephone-event/8000")
		ans, sess := laneDAnswer(t, offer)
		ml := mLines(ans)
		if len(ml) != 2 || ml[0] != "m=video 0 RTP/AVP 31" || ml[1] != "m=audio 16384 RTP/AVP 0 101" {
			t.Fatalf("m lines %q", ml)
		}
		if sess.Live != 1 || len(sess.Streams) != 2 {
			t.Fatalf("Live %d, %d streams", sess.Live, len(sess.Streams))
		}
		if sess.Streams[0] != (media.Stream{Media: "video", Proto: "RTP/AVP", RemoteAddr: "127.0.0.1:15284", Direction: media.DirInactive}) {
			t.Fatalf("Streams[0] = %+v", sess.Streams[0])
		}
		if s1 := sess.Streams[1]; s1.Media != "audio" || s1.LocalPort != 16384 || s1.Direction != media.DirSendRecv {
			t.Fatalf("Streams[1] = %+v", s1)
		}
		assertLiveMirror(t, sess)
	})
	t.Run("two usable audio", func(t *testing.T) {
		ans, sess := laneDAnswer(t, laneDBase("m=audio 15282 RTP/AVP 0 101", "m=audio 15290 RTP/AVP 8"))
		ml := mLines(ans)
		if len(ml) != 2 || !strings.HasPrefix(ml[1], "m=audio 0 RTP/AVP 8") || sess.Live != 0 {
			t.Fatalf("m lines %q Live %d", ml, sess.Live)
		}
	})
}

// assertLiveMirror checks that the top-level live-stream fields mirror Streams[Live].
func assertLiveMirror(t *testing.T, s *media.Session) {
	t.Helper()
	st := s.Streams[s.Live]
	if s.RemoteAddr != st.RemoteAddr || s.Direction != st.Direction {
		t.Fatalf("session (%s, %s) does not mirror Streams[%d] (%s, %s)", s.RemoteAddr, s.Direction, s.Live, st.RemoteAddr, st.Direction)
	}
}

// TestRFC3264_NEWD10_AnswerTimeLineEqualsTheOffers (CF-141, was the NEW-D-10
// pin; rfc3264.txt:474).
func TestRFC3264_NEWD10_AnswerTimeLineEqualsTheOffers(t *testing.T) {
	offer := offerLines("v=0", "o=sipp 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=3034423619 3042462419",
		"m=audio 15282 RTP/AVP 0 101", "a=rtpmap:0 PCMU/8000", "a=sendrecv")
	ans, _ := laneDAnswer(t, offer)
	if got := sdpLine(t, ans, "t="); got != "t=3034423619 3042462419" {
		t.Fatalf("answer %q is not the offer's t= line", got)
	}
}

// TestRFC3264_NEWD12_AnswerOriginDiffersFromTheOffers (CF-143, was the NEW-D-12
// pin; rfc3264.txt:458-461).
func TestRFC3264_NEWD12_AnswerOriginDiffersFromTheOffers(t *testing.T) {
	offer := laneDBase("m=audio 15282 RTP/AVP 0 8 101", "a=sendrecv")
	offer = []byte(strings.Replace(string(offer), "o=sipp 1696 1696 IN IP4 127.0.0.1", "o=- 1 1 IN IP4 127.0.0.1", 1))
	ans1, sess := laneDAnswer(t, offer)
	ans2, _ := laneDAnswer(t, offer)
	o1, o2 := sdpLine(t, ans1, "o="), sdpLine(t, ans2, "o=")
	if o1 == "o=- 1 1 IN IP4 127.0.0.1" || o1 == o2 {
		t.Fatalf("origins %q %q must differ from the offer's and from each other", o1, o2)
	}
	f := strings.Fields(o1)
	if f[2] != "1" || f[1] != strconv.FormatUint(sess.Origin.SessID, 10) || sess.Origin.Version != 1 {
		t.Fatalf("o= %q does not match Origin %+v", o1, sess.Origin)
	}
}

// TestRFC3264_NEWD18_DynamicPTIsAnsweredAtTheOfferedPT (CF-149 by side effect,
// was the NEW-D-18 pin; rfc3264.txt:541-543).
func TestRFC3264_NEWD18_DynamicPTIsAnsweredAtTheOfferedPT(t *testing.T) {
	offer := offerLines("v=0", "o=sipp 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0",
		"m=audio 15282 RTP/AVP 96 101", "a=rtpmap:96 PCMU/8000", "a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-15", "a=sendrecv")
	ans, _ := laneDAnswer(t, offer)
	fields := strings.Fields(sdpLine(t, ans, "m=audio"))
	if len(fields) < 4 || fields[3] != "96" || sdpLine(t, ans, "a=rtpmap:96") != "a=rtpmap:96 PCMU/8000" {
		t.Fatalf("answer %v does not list PCMU at the offered PT 96:\n%s", fields, ans)
	}
}

// TestRFC3264_NEWD21_OfferedPortZeroIsAnsweredPortZero (CF-152, was the
// NEW-D-21 pin; rfc3264.txt:756-757).
func TestRFC3264_NEWD21_OfferedPortZeroIsAnsweredPortZero(t *testing.T) {
	t.Run("lone rejected stream", func(t *testing.T) {
		_, _, err := media.BuildAnswer(laneDBase("m=audio 0 RTP/AVP 0 101", "a=sendrecv"),
			media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:16384"})
		var ne *media.NegotiationError
		if !errors.As(err, &ne) || ne.Kind != media.KindNoCommonCodec || len(ne.Offered) != 0 || ne.Detail()["sip_response_sent"] != 488 {
			t.Fatalf("err = %v, want 488 no_common_codec with no offered codecs", err)
		}
	})
	t.Run("second stream live", func(t *testing.T) {
		ans, sess := laneDAnswer(t, laneDBase("m=audio 0 RTP/AVP 0", "m=audio 15282 RTP/AVP 0 101"))
		ml := mLines(ans)
		if len(ml) != 2 || !strings.HasPrefix(ml[0], "m=audio 0 ") || strings.HasPrefix(ml[1], "m=audio 0 ") {
			t.Fatalf("m lines %q", ml)
		}
		if sess.RemoteAddr != "127.0.0.1:15282" || sess.Live != 1 {
			t.Fatalf("RemoteAddr %q Live %d", sess.RemoteAddr, sess.Live)
		}
	})
}
