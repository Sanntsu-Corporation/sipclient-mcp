package sipua

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

// CF-184: the remote target a target-refresh request (or its 2xx) replaced.

func contactOf(t *testing.T, v string) *sip.ContactHeader {
	t.Helper()
	req := parseReq(t,
		"UPDATE sip:a@h SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKc",
		"From: <sip:b@h>;tag=1", "To: <sip:a@h>;tag=2", "Call-ID: c", "CSeq: 1 UPDATE",
		"Contact: "+v, "Content-Length: 0")
	return req.Contact()
}

func TestRefreshedTargetReplacesTheDerivedOne(t *testing.T) {
	inv := routeTestInvite(t)
	ok := routeTestOK(t, "Record-Route: <sip:r1;lr>")
	want, wantRoutes := dialogRoute(session.Outbound, inv, ok, nil)
	moved := sip.Uri{Scheme: "sip", User: "moved", Host: "10.9.9.9", Port: 5099}
	target, routes := dialogRoute(session.Outbound, inv, ok, &moved)
	if target.String() != "sip:moved@10.9.9.9:5099" {
		t.Fatalf("target %s, want the refreshed one", target.String())
	}
	if want.String() == target.String() {
		t.Fatal("precondition: the derived target equals the refreshed one")
	}
	if len(routes) != len(wantRoutes) || routes[0].String() != wantRoutes[0].String() {
		t.Fatalf("route set changed by a refresh: %v vs %v", routes, wantRoutes)
	}
	target.Host = "mutated"
	if moved.Host != "10.9.9.9" {
		t.Fatal("dialogRoute aliased the stored refreshed target")
	}
}

func TestRefreshRefusal(t *testing.T) {
	sipTarget := sip.Uri{Scheme: "sip", User: "x", Host: "h"}
	sipsTarget := sip.Uri{Scheme: "sips", User: "x", Host: "h"}
	for _, tc := range []struct {
		name      string
		transport string
		cur       sip.Uri
		contact   string
		refused   bool
	}{
		{"no contact", "udp", sipTarget, "", false},
		{"sip on sip", "udp", sipTarget, "<sip:m@h2>", false},
		{"upper case scheme", "udp", sipTarget, "<SIP:Up@h2>", false},
		{"sips on a TLS UA", "tls", sipTarget, "<sips:m@h2>", false},
		{"sip when current is sips", "tls", sipsTarget, "<sip:m@h2>", true},
		{"sips on a UDP UA", "udp", sipTarget, "<sips:m@h2>", true},
		{"http", "udp", sipTarget, "<http://x>", true},
		{"tel", "udp", sipTarget, "<tel:+15550100>", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c *sip.ContactHeader
			if tc.contact != "" {
				c = contactOf(t, tc.contact)
			}
			got := refreshRefusal(tc.transport, tc.cur, nil, c)
			if (got != "") != tc.refused {
				t.Fatalf("refreshRefusal = %q, refused want %v", got, tc.refused)
			}
		})
	}
}

// sipsInboundDialog registers an answered inbound dialog whose INVITE Contact is sips:.
func sipsInboundDialog(u *UA, callID string) (*dialog, string) {
	d, tag := matchAnswered(u, callID)
	d.invite.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sips", User: "bob", Host: "peer"}})
	return d, tag
}

func TestDowngradingContactIsAnswered400(t *testing.T) {
	down := func(r *sip.Request) *sip.Request {
		r.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "x", Host: "h"}})
		return r
	}
	t.Run("UPDATE", func(t *testing.T) {
		u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
		d, tag := sipsInboundDialog(u, "cid-d-upd")
		tx := &stubServerTx{}
		u.onUpdate(down(matchReq(sip.UPDATE, "cid-d-upd", matchPeerTag, tag)), tx)
		if got := tx.last().StatusCode; got != 400 {
			t.Fatalf("UPDATE -> %d, want 400", got)
		}
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if d.remoteTarget != nil {
			t.Fatal("a refused Contact was stored")
		}
	})
	t.Run("re-INVITE", func(t *testing.T) {
		u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
		d, tag := sipsInboundDialog(u, "cid-d-inv")
		tx := &stubServerTx{}
		u.onInvite(down(matchReq(sip.INVITE, "cid-d-inv", matchPeerTag, tag)), tx)
		if got := tx.last().StatusCode; got != 400 {
			t.Fatalf("re-INVITE -> %d, want 400", got)
		}
		u.calls.mu.Lock()
		defer u.calls.mu.Unlock()
		if d.remoteTarget != nil {
			t.Fatal("a refused Contact was stored")
		}
	})
}

func TestOurRefreshTwoxxWithADowngradingContactIsIgnored(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := sipsInboundDialog(u, "cid-d-2xx")
	res := sip.NewResponseFromRequest(matchReq(sip.UPDATE, "cid-d-2xx", matchPeerTag, "t"), 200, "OK", nil)
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "x", Host: "h"}})
	u.refreshTargetFromResponse(d, res)
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.remoteTarget != nil {
		t.Fatalf("a downgrading 2xx Contact refreshed the target to %s", d.remoteTarget)
	}
}

func TestPeerTargetFollowsTheRefreshedTarget(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := matchAnswered(u, "cid-peer-target")
	moved := sip.Uri{Scheme: "sip", User: "moved", Host: "10.9.9.9", Port: 5099}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	d.remoteTarget = &moved
	if got := peerTargetLocked(d); !strings.Contains(got, "moved@10.9.9.9:5099") {
		t.Fatalf("peerTargetLocked = %q, want the refreshed target", got)
	}
}

func TestDigestRetryGuardReadsTheRefreshedTarget(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	u.cfg.AuthUser, u.cfg.AuthPass = "alice", "secret"
	u.cfg.AOR = "sip:alice@127.0.0.1"
	d, _ := matchAnswered(u, "cid-digest-guard")
	d.invite.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: 5060}})
	req := parseReq(t,
		"INFO sip:bob@127.0.0.1:5060 SIP/2.0",
		"Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKg",
		"From: <sip:alice@127.0.0.1>;tag=1", "To: <sip:bob@127.0.0.1>;tag=2", "Call-ID: c", "CSeq: 2 INFO",
		"Content-Length: 0")
	req.SetDestination("127.0.0.1:5060")
	res := parseRes(t,
		"SIP/2.0 401 Unauthorized",
		"Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKg",
		"From: <sip:alice@127.0.0.1>;tag=1", "To: <sip:bob@127.0.0.1>;tag=2", "Call-ID: c", "CSeq: 2 INFO",
		`WWW-Authenticate: Digest realm="r", nonce="n"`, "Content-Length: 0")
	res.SetSource("127.0.0.1:5060")
	hop := sip.Uri{Host: "127.0.0.1", Port: 5060}
	if !u.inDialogCanRetry(t.Context(), d, req, hop, res) {
		t.Fatal("precondition: the unrefreshed dialog (target on the account host) must allow the retry")
	}
	moved := sip.Uri{Scheme: "sip", User: "evil", Host: "203.0.113.9"}
	u.calls.mu.Lock()
	d.remoteTarget = &moved
	u.calls.mu.Unlock()
	if u.inDialogCanRetry(t.Context(), d, req, hop, res) {
		t.Fatal("a digest retry was allowed although the refreshed remote target is not the account host")
	}
}

// A sip: Contact validated against the old sip: target must not undo a sips:
// upgrade that landed between its validation and its store (CF-171 never-downgrade,
// B-D3). The interleaving is stepped explicitly, on a TLS UA's rules.
func TestConcurrentUpgradeIsNotUndoneByAnEarlierValidatedContact(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := matchAnswered(u, "cid-cas")
	sipB := contactOf(t, "<sip:b@h2>")
	sipsA := contactOf(t, "<sips:a@h3>")

	// Request B passes validation against the current (sip:) target ...
	u.calls.mu.Lock()
	cur, routes := dialogRoute(d.direction, d.invite, d.ok, d.remoteTarget)
	u.calls.mu.Unlock()
	if reason := refreshRefusal("tls", cur, routes, sipB); reason != "" {
		t.Fatalf("B refused before the upgrade: %s", reason)
	}
	// ... request A upgrades the target to sips: ...
	if reason := u.storeRemoteTarget(d, "tls", sipsA); reason != "" {
		t.Fatalf("A refused: %s", reason)
	}
	// ... and B's store, decided against the current target, is refused.
	if reason := u.storeRemoteTarget(d, "tls", sipB); reason == "" {
		t.Error("B's store was accepted although it downgrades the upgraded target")
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.remoteTarget == nil || d.remoteTarget.Scheme != "sips" {
		t.Fatalf("remote target %v, want the sips: upgrade kept", d.remoteTarget)
	}
}

// The UAC path (the 2xx to our refresh) is decided with the store too: a sip:
// Contact after a sips: refresh is ignored.
func TestOurRefreshTwoxxCannotDowngradeAnUpgradedTarget(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	d, _ := matchAnswered(u, "cid-cas-uac")
	if reason := u.storeRemoteTarget(d, "tls", contactOf(t, "<sips:a@h3>")); reason != "" {
		t.Fatalf("upgrade refused: %s", reason)
	}
	if reason := u.storeRemoteTarget(d, "tls", contactOf(t, "<sip:b@h2>")); reason == "" {
		t.Error("a downgrading 2xx Contact was accepted")
	}
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	if d.remoteTarget == nil || d.remoteTarget.Scheme != "sips" {
		t.Fatalf("remote target %v, want sips: kept", d.remoteTarget)
	}
}
