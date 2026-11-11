package sipua_test

// Lane A (cf6-a-sdp) Task 4 (CF-198): an SRTP dial follows a redirect with a
// fresh SDES key for every new target (RFC 4568 6.1). No test calls t.Parallel.

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

var cryptoKeyRE = regexp.MustCompile(`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:(\S+)`)

// srtpAnswerOK answers an INVITE 200 with an RTP/SAVP answer carrying a fresh key.
func srtpAnswerOK(s *uacStub, raw string, from net.Addr) {
	_, line, err := media.GenerateCryptoAttr()
	if err != nil {
		panic(err)
	}
	sdp := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n" + line + "\r\n"
	s.send(from, stubResponse(raw, 200, "OK", "stubtag2", []string{"Contact: <sip:stub@" + s.addr() + ">"}, sdp))
}

// inviteKeys returns the inline key of every INVITE the stub saw, in order.
func inviteKeys(t *testing.T, s *uacStub) []string {
	t.Helper()
	var keys []string
	for _, inv := range s.requests("INVITE") {
		if n := strings.Count(inv, "a=crypto:"); n != 1 {
			t.Fatalf("an INVITE carries %d a=crypto lines, want 1:\n%s", n, inv)
		}
		m := cryptoKeyRE.FindStringSubmatch(inv)
		if m == nil {
			t.Fatalf("no a=crypto:1 line in:\n%s", inv)
		}
		keys = append(keys, m[1])
	}
	return keys
}

func distinct(keys []string) bool {
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

func srtpRedirectUA(t *testing.T) (*sipua.UA, func() []session.UAEvent) {
	t.Helper()
	ua, _ := newDirectUAWithCodecs(t, fakeclock.New(time.Unix(0, 0)), []string{"PCMU"}, "required")
	return ua, collect(t, ua)
}

func TestRedirectWithAnSDESOfferSendsAFreshKey(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if ruriUser(raw) == "bob" {
			send302(s, raw, from, "<sip:alt@"+s.addr()+">")
			return
		}
		srtpAnswerOK(s, raw, from)
	})
	ua, events := srtpRedirectUA(t)
	res := dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 200)
	invs := s.requests("INVITE")
	if len(invs) != 2 {
		t.Fatalf("INVITEs = %d, want 2", len(invs))
	}
	keys := inviteKeys(t, s)
	if keys[0] == keys[1] {
		t.Error("both targets were offered the same SDES key")
	}
	mask := func(raw string) string {
		body := raw[strings.Index(raw, "\r\n\r\n"):]
		return cryptoKeyRE.ReplaceAllString(body, "KEY")
	}
	if mask(invs[0]) != mask(invs[1]) {
		t.Errorf("the two offers differ beyond the key:\n%s\n---\n%s", mask(invs[0]), mask(invs[1]))
	}
	if mv, ok := ua.MediaView(res.DialogID); !ok || !mv.SRTP {
		t.Errorf("MediaView %+v ok=%v, want SRTP", mv, ok)
	}
	sess := sipua.MediaSessionForTest(ua, res.DialogID)
	if sess == nil || sess.LocalCrypto == nil || !strings.Contains(invs[1], sess.LocalCrypto.AttrLine()) {
		t.Errorf("the live session's key is not the last INVITE's")
	}
}

func TestRedirectFailoverGivesEachTargetItsOwnKey(t *testing.T) {
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		switch ruriUser(raw) {
		case "bob":
			send302(s, raw, from, "<sip:high@"+s.addr()+">;q=0.9", "<sip:low@"+s.addr()+">;q=0.1")
		case "high":
			s.send(from, stubResponse(raw, 486, "Busy Here", "stubtag", nil, ""))
		default:
			srtpAnswerOK(s, raw, from)
		}
	})
	ua, events := srtpRedirectUA(t)
	dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 200)
	keys := inviteKeys(t, s)
	if len(keys) != 3 || !distinct(keys) {
		t.Fatalf("keys %q, want 3 pairwise different", keys)
	}
}

func TestA422RetryToARedirectTargetKeepsItsKey(t *testing.T) {
	var mu sync.Mutex
	altSeen := 0
	s := startUACStub(t, func(s *uacStub, raw string, from net.Addr) {
		if stubMethod(raw) != "INVITE" {
			return
		}
		if ruriUser(raw) == "bob" {
			send302(s, raw, from, "<sip:alt@"+s.addr()+">")
			return
		}
		mu.Lock()
		altSeen++
		n := altSeen
		mu.Unlock()
		if n == 1 {
			s.send(from, stubResponse(raw, 422, "Session Interval Too Small", "stubtag", []string{"Min-SE: 1800"}, ""))
			return
		}
		srtpAnswerOK(s, raw, from)
	})
	ua, events := srtpRedirectUA(t)
	dialRedirect(t, ua, "sip:bob@"+s.addr(), 3, redirectIdentity)
	waitFor(t, events, session.UAEventFinal, 200)
	keys := inviteKeys(t, s)
	if len(keys) != 3 {
		t.Fatalf("INVITEs = %d, want 3", len(keys))
	}
	if keys[1] != keys[2] || keys[0] == keys[1] {
		t.Errorf("keys %q: the 422 retry must keep its target's key and differ from the first", keys)
	}
}
