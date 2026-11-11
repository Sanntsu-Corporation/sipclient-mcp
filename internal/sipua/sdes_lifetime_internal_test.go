package sipua

import (
	"regexp"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

var inlineKeyRE = regexp.MustCompile(`(inline:\S+)`)

// CF-187 (LA-4b): the peer's key lifetime is part of the key the live SRTP
// transform runs on, so a re-offer that changes only it is refused 488 like any
// other key change (D-10, TestReInviteSRTPChangeDraws488).
func TestReOfferChangingOnlyTheKeyLifetimeDraws488(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := newNotifyTestDialog(u, "cid-reoffer-lifetime")
	base, _, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "198.51.100.1:20000", media.SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	withLifetime := func(lifetime, origin string) []byte {
		s := inlineKeyRE.ReplaceAllString(string(base), "${1}|"+lifetime)
		return []byte(replaceOrigin(s, origin))
	}
	offer1 := withLifetime("2^31", "o=- 999 1 IN IP4 198.51.100.1")
	ans, sess, err := media.BuildAnswer(offer1, media.AnswerOptions{Prefs: media.CodecPrefs{"PCMU"}, LocalAddr: "127.0.0.1:16384", SRTP: media.SRTPRequired})
	if err != nil {
		t.Fatal(err)
	}
	if sess.RemoteCrypto == nil || sess.RemoteCrypto.Lifetime != 1<<31 {
		t.Fatalf("RemoteCrypto %+v, want lifetime 2^31", sess.RemoteCrypto)
	}
	u.calls.mu.Lock()
	d.invite.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	d.invite.SetBody(offer1)
	d.ok.SetBody(ans)
	d.mediaSession = sess
	u.calls.mu.Unlock()

	// Offer 3 first (same key and lifetime, new version): the one path that is not refused.
	if _, status, _ := u.answerInDialogOffer(d, withLifetime("2^31", "o=- 999 3 IN IP4 198.51.100.1")); status == 488 {
		t.Fatalf("a re-offer with the same key and lifetime drew 488")
	}
	// Offer 2: only the lifetime changed.
	if _, status, _ := u.answerInDialogOffer(d, withLifetime("2^30", "o=- 999 4 IN IP4 198.51.100.1")); status != 488 {
		t.Fatalf("status %d, want 488 for a changed lifetime", status)
	}
}
