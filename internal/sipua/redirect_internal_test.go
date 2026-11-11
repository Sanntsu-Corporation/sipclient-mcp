package sipua

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func redirectResponse(contacts ...string) *sip.Response {
	var b strings.Builder
	b.WriteString("SIP/2.0 302 Moved Temporarily\r\nVia: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKx\r\n")
	b.WriteString("From: <sip:a@x>;tag=1\r\nTo: <sip:b@x>;tag=2\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n")
	for _, c := range contacts {
		b.WriteString("Contact: " + c + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	msg, err := sip.ParseMessage([]byte(b.String()))
	if err != nil {
		panic(err)
	}
	return msg.(*sip.Response)
}

func deriveAny(target string) (sip.Uri, error) {
	u, ok := parseValidSIPURI(target)
	if !ok {
		return sip.Uri{}, fmt.Errorf("invalid %q", target)
	}
	return u, nil
}

func checkAny(s string) (string, error) { return s, nil }

func dials(ts []redirectTarget) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.dial)
	}
	return out
}

func TestRedirectTargets(t *testing.T) {
	seenWith := func(keys ...string) map[string]bool {
		m := map[string]bool{}
		for _, k := range keys {
			m[k] = true
		}
		return m
	}
	many := func(n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("<sip:u%d@h>", i))
		}
		return out
	}
	refuseDenied := func(s string) (string, error) {
		if strings.Contains(s, "denied") {
			return "", fmt.Errorf("denied")
		}
		return s, nil
	}
	cases := []struct {
		name     string
		contacts []string
		everSips bool
		seen     map[string]bool
		room     int
		check    func(string) (string, error)
		want     []string
	}{
		{"q order descending", []string{"<sip:a@h>;q=0.2", "<sip:b@h>;q=0.9", "<sip:c@h>;q=0.5"}, false, nil, 5, checkAny,
			[]string{"sip:b@h", "sip:c@h", "sip:a@h"}},
		{"absent q is 1.0, ties keep header order", []string{"<sip:a@h>;q=0.5", "<sip:b@h>", "<sip:c@h>"}, false, nil, 5, checkAny,
			[]string{"sip:b@h", "sip:c@h", "sip:a@h"}},
		{"unparseable q sorts as 0", []string{"<sip:a@h>;q=zzz", "<sip:b@h>;q=0.1"}, false, nil, 5, checkAny,
			[]string{"sip:b@h", "sip:a@h"}},
		{"more than 16 contacts evaluates 16", many(20), false, nil, 100, checkAny, dialsOf(many(16))},
		{"room caps the result", many(5), false, nil, 2, checkAny, []string{"sip:u0@h", "sip:u1@h"}},
		{"everSips drops sip", []string{"<sip:a@h>", "<sips:b@h>"}, true, nil, 5, checkAny, []string{"sips:b@h"}},
		{"scheme filter", []string{"<tel:+1555>", "<http://x>", "<sip:a@h>"}, false, nil, 5, checkAny, []string{"sip:a@h"}},
		{"parameters, headers and password dropped", []string{"<sip:a:pw@h:5070;maddr=1.2.3.4;transport=tcp?X-H=1>"}, false, nil, 5, checkAny,
			[]string{"sip:a@h:5070"}},
		{"seen key folds case, keeps user case", []string{"<SIP:Alt@HOST>", "<sip:alt@host>"}, false, seenWith("sip:Alt@host:0"), 5, checkAny,
			[]string{"sip:alt@host"}},
		{"h and h:5060 are distinct keys", []string{"<sip:a@h:5060>"}, false, seenWith("sip:a@h:0"), 5, checkAny, []string{"sip:a@h:5060"}},
		{"refused candidate is still marked seen", []string{"<sip:denied@h>", "<sip:denied@h>", "<sip:ok@h>"}, false, nil, 5, refuseDenied,
			[]string{"sip:ok@h"}},
		{"check's returned string is used", []string{"<sip:a@h>"}, false, nil, 5,
			func(string) (string, error) { return "sip:rewritten@h", nil }, []string{"sip:rewritten@h"}},
		{"ipv6 contact refused by dialRequestURI", []string{"<sip:a@[::1]:5060>", "<sip:b@h>"}, false, nil, 5, checkAny, []string{"sip:b@h"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := tc.seen
			if seen == nil {
				seen = map[string]bool{}
			}
			got := dials(redirectTargets(redirectResponse(tc.contacts...), tc.everSips, deriveAny, seen, tc.room, tc.check, nil, "d1"))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("targets = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("a refused URI is checked once", func(t *testing.T) {
		calls := 0
		check := func(string) (string, error) { calls++; return "", fmt.Errorf("denied") }
		redirectTargets(redirectResponse("<sip:x@h>", "<sip:x@h>"), false, deriveAny, map[string]bool{}, 5, check, nil, "d1")
		if calls != 1 {
			t.Errorf("check called %d times for the same URI twice in one 3xx, want 1", calls)
		}
	})
	t.Run("sip then sips then sip cannot downgrade", func(t *testing.T) {
		seen := map[string]bool{}
		first := redirectTargets(redirectResponse("<sips:a@h>"), false, deriveAny, seen, 5, checkAny, nil, "d1")
		if len(first) != 1 {
			t.Fatalf("sips target not accepted: %v", dials(first))
		}
		// After a sips leg everSips is set, so a sip candidate is dropped.
		second := redirectTargets(redirectResponse("<sip:b@h>"), true, deriveAny, seen, 5, checkAny, nil, "d1")
		if len(second) != 0 {
			t.Errorf("sip target after a sips leg accepted: %v", dials(second))
		}
	})
}

func dialsOf(contacts []string) []string {
	var out []string
	for _, c := range contacts {
		out = append(out, strings.Trim(c, "<>"))
	}
	return out
}

func TestOffersSDESGuard(t *testing.T) {
	u := &UA{}
	with := &dialog{mediaSession: &media.Session{LocalCrypto: &media.CryptoParams{}}}
	without := &dialog{mediaSession: &media.Session{}}
	if !u.offersSDES(with) {
		t.Error("offersSDES = false for a session with local crypto")
	}
	if u.offersSDES(without) {
		t.Error("offersSDES = true for a session without local crypto")
	}
}

// retarget leaves a request that has no Via and a sips: Request-URI on TLS
// (the fork's CF-172 default) and records that the dial has been sips.
func TestRedirectToSipsOnATLSUALeavesOverTLS(t *testing.T) {
	var uri sip.Uri
	if err := sip.ParseUri("sip:bob@127.0.0.1:5071", &uri); err != nil {
		t.Fatal(err)
	}
	inv := sip.NewRequest(sip.INVITE, uri)
	inv.AppendHeader(sip.NewHeader("Via", "SIP/2.0/TLS 127.0.0.1:5070;branch=z9hG4bKx"))
	inv.AppendHeader(sip.NewHeader("Proxy-Authorization", "Digest p"))
	inv.AppendHeader(sip.NewHeader("Authorization", "Digest a"))
	d := &dialog{invite: inv}
	target, err := deriveAny("sips:bob@127.0.0.1:5071")
	if err != nil {
		t.Fatal(err)
	}
	retarget(d, redirectTarget{dial: "sips:bob@127.0.0.1:5071", uri: target})
	if !d.everSips || !d.redirected {
		t.Errorf("everSips=%v redirected=%v, want both set", d.everSips, d.redirected)
	}
	if got := inv.Transport(); got != "TLS" {
		t.Errorf("Transport() = %q, want TLS", got)
	}
	if len(inv.GetHeaders("Via")) != 0 || len(inv.GetHeaders("Authorization")) != 0 || len(inv.GetHeaders("Proxy-Authorization")) != 0 {
		t.Error("retarget left a Via or credentials on the request")
	}
	if inv.Recipient.Scheme != "sips" {
		t.Errorf("Recipient scheme = %q", inv.Recipient.Scheme)
	}
}

// A queued sip: fallback is dropped at dispatch once a sips: leg has been
// dialled (never downgrade), and a target the live check now refuses is skipped.
func TestNextRedirectTargetEnforcesPolicyAndNoDowngradeAtDispatch(t *testing.T) {
	u := newSipsTestUA(t, "tls", nil)
	var uri sip.Uri
	if err := sip.ParseUri("sip:orig@h", &uri); err != nil {
		t.Fatal(err)
	}
	mk := func(s string) redirectTarget {
		x, err := deriveAny(s)
		if err != nil {
			t.Fatal(err)
		}
		return redirectTarget{dial: s, uri: x}
	}
	t.Run("sip fallback after a sips leg", func(t *testing.T) {
		d := &dialog{invite: sip.NewRequest(sip.INVITE, uri), checkRedirect: checkAny}
		pending := []redirectTarget{mk("sips:a@h"), mk("sip:b@h")}
		first, rest, ok := u.nextRedirectTarget(d, pending)
		if !ok || first.dial != "sips:a@h" {
			t.Fatalf("first = %v ok=%v", first.dial, ok)
		}
		retarget(d, first)
		if _, _, ok := u.nextRedirectTarget(d, rest); ok {
			t.Error("a sip: fallback was dispatched after a sips: leg")
		}
	})
	t.Run("live check refuses a queued target", func(t *testing.T) {
		d := &dialog{invite: sip.NewRequest(sip.INVITE, uri),
			checkRedirect: func(s string) (string, error) {
				if strings.Contains(s, "b@") {
					return "", fmt.Errorf("denied")
				}
				return s, nil
			}}
		got, rest, ok := u.nextRedirectTarget(d, []redirectTarget{mk("sip:b@h"), mk("sip:c@h")})
		if !ok || got.dial != "sip:c@h" || len(rest) != 0 {
			t.Errorf("got %q ok=%v rest=%d, want c with b skipped", got.dial, ok, len(rest))
		}
	})
	t.Run("live check returns a changed URI: it is re-derived", func(t *testing.T) {
		d := &dialog{invite: sip.NewRequest(sip.INVITE, uri),
			checkRedirect: func(string) (string, error) { return "sip:rewritten@h2:5099", nil }}
		got, _, ok := u.nextRedirectTarget(d, []redirectTarget{mk("sip:b@h")})
		if !ok || got.dial != "sip:rewritten@h2:5099" || got.uri.User != "rewritten" || got.uri.Host != "h2" || got.uri.Port != 5099 {
			t.Errorf("got dial=%q uri=%v ok=%v, want the callback's URI re-derived", got.dial, got.uri, ok)
		}
	})
	t.Run("live check returns an invalid URI: refused", func(t *testing.T) {
		d := &dialog{invite: sip.NewRequest(sip.INVITE, uri),
			checkRedirect: func(string) (string, error) { return "sip:x@[::1]:5060", nil }}
		if _, _, ok := u.nextRedirectTarget(d, []redirectTarget{mk("sip:b@h")}); ok {
			t.Error("a target whose live-checked URI dialRequestURI refuses was dispatched")
		}
	})
}

// K1, K8 (CF-198): rekeyOffer swaps the Session and the INVITE body together,
// under u.calls.mu, so a reader never sees one without the other's key.
func TestRekeyOfferSwapsSessionAndBodyTogether(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	offer, sess, err := media.BuildOffer(media.CodecPrefs{"PCMU"}, "127.0.0.1:20000", media.SRTPRequired)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := newNotifyTestDialog(u, "cid-rekey")
	u.calls.mu.Lock()
	d.invite.SetBody(offer)
	d.mediaSession = sess
	u.calls.mu.Unlock()
	first := sess.LocalCrypto.AttrLine()

	stop := make(chan struct{})
	done := make(chan string, 1)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			u.calls.mu.Lock()
			line, body := d.mediaSession.LocalCrypto.AttrLine(), string(d.invite.Body())
			u.calls.mu.Unlock()
			if !strings.Contains(body, line) {
				done <- "the session's key " + line + " is not in the INVITE body"
				return
			}
		}
	}()
	for i := 0; i < 50; i++ {
		if err := u.rekeyOffer(d); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	if msg := <-done; msg != "" {
		t.Fatal(msg)
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.mediaSession.LocalCrypto.AttrLine() == first || d.mediaSession == sess {
		t.Error("the key was not replaced")
	}
	if sess.LocalCrypto.AttrLine() != first {
		t.Error("the old Session was written")
	}
}
