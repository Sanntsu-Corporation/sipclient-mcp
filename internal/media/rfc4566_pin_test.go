package media_test

// Lane D (rfc-sweep-d) pins for SDP-builder deviations in RFC 4566 rows (6a D11).
// Each passes today and must be inverted when its NEW-D finding is fixed.
// sdpLine is in rfc3264_pin_test.go.

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
)

// ntpToUnixOffset is the seconds from 1900 to 1970; no NTP timestamp of this
// century is below it (rfc4566.txt:929-931).
const ntpToUnixOffset = 2208988800

// TestRFC4566Pin_NEWD2_OfferSessionVersionIsNotNTP pins NEW-D-2 (D-SDP-12, RFC
// 4566 5.2: "Again, it is RECOMMENDED that an NTP format timestamp is used."
// rfc4566.txt:589-590). Evidence: evidence/rg-echo/excerpt.txt frame 4 (our
// INVITE offer: o=- 1 1 IN IP4 192.168.1.120) and evidence/md-corpus/queries.txt
// Q-SDP (every body of ours has version 1). Locus:
// internal/media/sdp.go:BuildOffer (and BuildAnswer), bytes emitted via the
// INVITE and 200 bodies.
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-2 is fixed.
func TestRFC4566Pin_NEWD2_OfferSessionVersionIsNotNTP(t *testing.T) {
	body, _, err := media.BuildOffer(media.CodecPrefs{"PCMU", "PCMA"}, "198.51.100.1:20000", media.SRTPDisabled)
	if err != nil {
		t.Fatalf("BuildOffer: %v", err)
	}
	f := strings.Fields(sdpLine(t, body, "o=")) // o=<user> <sess-id> <sess-version> ...
	if len(f) < 4 {
		t.Fatalf("malformed o= line %q", f)
	}
	ver, err := strconv.ParseUint(f[2], 10, 64)
	if err != nil {
		t.Fatalf("o= version %q: %v", f[2], err)
	}
	if ver >= ntpToUnixOffset {
		t.Fatalf("o= version %d looks like an NTP timestamp: NEW-D-2 is fixed, invert this pin", ver)
	}
}

// TestRFC4566_NEWD17_UnknownTypeLetterDescriptionIsRefused (CF-148, was the
// NEW-D-17 pin; RFC 4566 5: "An SDP parser MUST completely ignore any session
// description that contains a type letter that it does not understand."
// rfc4566.txt:485-487). An offer with y=rfcsweep-d draws 488; an answer with an
// unknown letter fails the call sdp_unparseable.
func TestRFC4566_NEWD17_UnknownTypeLetterDescriptionIsRefused(t *testing.T) {
	offer := offerLines("v=0", "o=sipp 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0", "y=rfcsweep-d",
		"m=audio 15282 RTP/AVP 0 101", "a=rtpmap:0 PCMU/8000", "a=sendrecv")
	ans, _, err := media.BuildAnswer(offer, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU", "PCMA"}, LocalAddr: "127.0.0.1:16384", SRTP: media.SRTPDisabled})
	var ne *media.NegotiationError
	if !errors.As(err, &ne) || len(ans) != 0 {
		t.Fatalf("BuildAnswer = (%q, %v), want a NegotiationError and no body", ans, err)
	}
	if ne.Detail()["sip_response_sent"] != 488 {
		t.Fatalf("detail %v does not name 488", ne.Detail())
	}

	t.Run("answer", func(t *testing.T) {
		_, off, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "127.0.0.1:20000", media.SRTPDisabled)
		if err != nil {
			t.Fatal(err)
		}
		body := offerLines("v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "c=IN IP4 127.0.0.1", "t=0 0", "y=x",
			"m=audio 4000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000")
		_, err = media.ParseAnswer(off, body)
		if !errors.As(err, &ne) || ne.Kind != media.KindSDPUnparseable {
			t.Fatalf("ParseAnswer err = %v, want kind sdp_unparseable", err)
		}
	})
}

// TestRFC4566_NEWD20_MediaLevelConnectionAppliesOnlyToItsStream (CF-151, was
// the NEW-D-20 pin; RFC 4566 5.7 per-media c= overrides the session value for
// its own media description, rfc4566.txt:747-749).
func TestRFC4566_NEWD20_MediaLevelConnectionAppliesOnlyToItsStream(t *testing.T) {
	offer := laneDBase("m=audio 15282 RTP/AVP 0 8 101", "a=sendrecv", "m=video 15286 RTP/AVP 31", "c=IN IP4 127.0.0.2")
	_, sess := laneDAnswer(t, offer)
	if sess.RemoteAddr != "127.0.0.1:15282" {
		t.Fatalf("RemoteAddr %q, want the session-level 127.0.0.1:15282", sess.RemoteAddr)
	}
}

// TestRFC4566_NEWD22_TheFirstAudioStreamIsTheTarget (CF-153, was the NEW-D-22
// pin; rfc4566.txt:315-316).
func TestRFC4566_NEWD22_TheFirstAudioStreamIsTheTarget(t *testing.T) {
	offer := laneDBase("m=audio 15282 RTP/AVP 0 8 101", "a=sendrecv", "m=audio 0 RTP/AVP 8")
	_, sess := laneDAnswer(t, offer)
	if sess.RemoteAddr != "127.0.0.1:15282" {
		t.Fatalf("RemoteAddr %q, want 127.0.0.1:15282", sess.RemoteAddr)
	}
}
