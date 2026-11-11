package sipua_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/peer"
)

// newRegisterUA builds a register-mode UA whose socket is decorated through
// Task 13's WrapConn seam, used exactly as delivered. sipua itself resolves
// and binds the concrete address (§6.5.3 rule 3, toward the registrar) — the
// test never binds, which is the property WrapConn exists to guarantee: a
// decorator cannot substitute a wildcard-bound socket.
func newRegisterUA(t *testing.T, p *peer.Peer, clk *fakeclock.Clock) (*sipua.UA, *countingConn) {
	t.Helper()
	return newRegisterUAExpires(t, p, clk, 300)
}

// newRegisterUAExpires is newRegisterUA with the REQUESTED expiry as a
// parameter, for the tests that must distinguish Config.ExpiresS from the
// vendored builder's hardcoded 300.
func newRegisterUAExpires(t *testing.T, p *peer.Peer, clk *fakeclock.Clock, expiresS int) (*sipua.UA, *countingConn) {
	t.Helper()
	var cc *countingConn
	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + p.Addr(),
		AuthUser:  "alice",
		AuthPass:  "s3cr3t",
		ExpiresS:  expiresS,
		Timeout:   2 * time.Second,
		Clock:     clk,
		LocalAddr: "127.0.0.1:0",
		WrapConn: func(pc net.PacketConn) net.PacketConn {
			cc = &countingConn{PacketConn: pc}
			return cc
		},
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	// C6/D137: sipua.Destroy is DELETED (a second teardown path per
	// session/destroy.go:20; session/destroy.go:destroyUA is the ONE
	// implementation). Test cleanup uses Close, transport teardown only.
	t.Cleanup(func() { _ = ua.Close(context.Background()) })
	return ua, cc
}

func TestRegisterDigestChallengeRetry(t *testing.T) {
	// RegisterExpires grants 120 while the UA requests 300 (Config.ExpiresS,
	// which newRegisterUA sets to 300 and which now reaches the wire via
	// setExpires/registerExpiresS's default): the two values must differ, or
	// res.ExpiresS could be satisfied by restating the request/fallback
	// constant instead of actually reading the registrar's granted Expires
	// off the response.
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t", RegisterExpires: 120})

	ua, cc := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !res.Registered {
		t.Errorf("Registered = false, want true")
	}
	if res.Code != 200 {
		t.Errorf("Code = %d, want 200", res.Code)
	}
	if res.ExpiresS != 120 {
		t.Errorf("ExpiresS = %d, want 120 (the registrar's GRANTED expiry, not the requested 300)", res.ExpiresS)
	}
	if !ua.Registered() || ua.RegisterCode() != 200 {
		t.Errorf("UA state: registered=%v code=%d, want true/200", ua.Registered(), ua.RegisterCode())
	}

	// R1: the exchange is EXACTLY REGISTER -> 401 -> REGISTER -> 200.
	if got := p.Count("REGISTER"); got != 2 {
		t.Errorf("registrar saw %d REGISTERs, want exactly 2 (challenge + digest retry)", got)
	}
	if got := cc.Sent("REGISTER"); got != 2 {
		t.Errorf("UA sent %d REGISTERs, want exactly 2", got)
	}
	if got := cc.Received(401); got != 1 {
		t.Errorf("UA received %d 401s, want exactly 1", got)
	}
	if got := cc.Received(200); got != 1 {
		t.Errorf("UA received %d 200s, want exactly 1", got)
	}

	// D9d / §3d: the Via sent-by MUST equal the address read back from the
	// bound socket. If it does not, sipgo's pooled-listener lookup misses and
	// the next outbound request leaves on a NEW, UNTAPPED socket.
	if got, want := p.LastVia(), ua.BoundAddr().String(); got != want {
		t.Errorf("registrar saw Via sent-by %q, want UA.BoundAddr() %q — a Via that does not match the bound address defeats the D9d tap", got, want)
	}
	// D124: the Via is pinned in TWO independent places — engineConfig().
	// LocalAddr (the FIRST REGISTER's Via) and Task 13's siptest.NewClient
	// LocalAddr (the RETRY's Via). p.LastVia() alone reads only the retry's
	// Via — DoRequestWithDigest's retry always overwrites it — so a
	// regression in the FIRST Via would pass the assertion above. Assert the
	// first Via too.
	if got, want := p.FirstVia(), ua.BoundAddr().String(); got != want {
		t.Errorf("registrar saw FIRST Via sent-by %q, want UA.BoundAddr() %q — engineConfig().LocalAddr must pin the initial REGISTER's Via too (D124)", got, want)
	}
	if strings.HasPrefix(ua.BoundAddr().String(), "0.0.0.0") {
		t.Errorf("UA bound to a wildcard %q; the listener must always be a concrete IP:port (D9d)", ua.BoundAddr())
	}
}

func TestRegisterRejectedIsNotAnError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		reason string
	}{
		{"forbidden", 403, "Forbidden"},
		{"not found", 404, "Not Found"},
		{"interval too brief", 423, "Interval Too Brief"},
		{"service unavailable", 503, "Service Unavailable"},
		{"decline", 603, "Decline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{
				Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
				RegisterStatus: tc.status, RegisterReason: tc.reason,
			})
			ua, _ := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))

			res, err := ua.Register(context.Background())
			if err != nil {
				t.Fatalf("Register returned an error for a %d; a rejected registration is a RESULT, not an error (§11.1, §10.2): %v", tc.status, err)
			}
			if res.Registered {
				t.Errorf("Registered = true, want false")
			}
			if res.Code != tc.status {
				t.Errorf("Code = %d, want %d", res.Code, tc.status)
			}
			if res.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", res.Reason, tc.reason)
			}
			if ua.Registered() {
				t.Errorf("UA.Registered() = true after a %d", tc.status)
			}
			if ua.RegisterCode() != tc.status {
				t.Errorf("UA.RegisterCode() = %d, want %d", ua.RegisterCode(), tc.status)
			}
		})
	}
}

func TestRegisterResultCarriesNoCredentials(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	rendered := fmt.Sprintf("%+v", res)
	if strings.Contains(rendered, "s3cr3t") {
		t.Errorf("RegisterResult leaks the auth password (D6): %s", rendered)
	}
	if strings.Contains(strings.ToLower(rendered), "authorization") {
		t.Errorf("RegisterResult leaks an Authorization header (D6): %s", rendered)
	}
}

func TestUnregisterSendsExpiresZero(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if p.LastExpires() != 300 {
		t.Fatalf("registration Expires = %d, want 300", p.LastExpires())
	}
	if err := ua.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if p.LastExpires() != 0 {
		t.Errorf("registrar saw Expires: %d on the last REGISTER, want 0", p.LastExpires())
	}
	if ua.Registered() {
		t.Errorf("UA.Registered() = true after Unregister")
	}
}

func TestUnregisterWhenNotRegisteredIsANoOp(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))

	if err := ua.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister on an unregistered UA: %v", err)
	}
	if got := p.Count("REGISTER"); got != 0 {
		t.Errorf("registrar saw %d REGISTERs, want 0", got)
	}
}

// TestUnregisterErrorsOnNonSuccessStatus pins D122: session.UserAgent.
// Unregister returns nil ONLY on a 2xx; a non-2xx final response to the
// Expires: 0 REGISTER must return an error naming the code, distinct from a
// rejection of the INITIAL registration (already covered by
// TestRegisterRejectedIsNotAnError). (*Manager).UnregisterAllUAs's confirmed
// count depends on this distinction.
func TestUnregisterErrorsOnNonSuccessStatus(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUA(t, p, fakeclock.New(time.Unix(0, 0)))

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !ua.Registered() {
		t.Fatalf("UA.Registered() = false after a successful Register")
	}

	// Reject the Expires: 0 REGISTER specifically; the initial registration
	// above already succeeded.
	p.SetRegisterStatus(403, "Forbidden")

	err := ua.Unregister(context.Background())
	if err == nil {
		t.Fatalf("Unregister against a 403 returned nil error, want an error naming the code (D122, contract §2.5.5)")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Unregister error = %q, want it to name the code 403", err.Error())
	}
	if ua.Registered() {
		t.Errorf("UA.Registered() = true after a rejected Unregister; local state must still clear")
	}
}

// THERE IS DELIBERATELY NO "no re-register at P1" TEST HERE ANY MORE.
// TestNoReRegisterOrKeepaliveAtP1 asserted that a registered UA never refreshes
// — the P1 contract — and this phase made that false on purpose: Register arms
// the R10 refresher (register.go's startRegisterRefresher) and startKeepalive
// arms the NAT keepalive. It stayed green only because it advanced the fake
// clock WITHOUT clk.BlockUntil, i.e. before the refresher had armed its timer,
// which fakeclock's own package doc calls out as "racing the code it is meant to
// drive" (internal/testutil/fakeclock/fakeclock.go). Adding the single
// BlockUntil(1) every other refresh test in this package already uses made it
// fail 3/3 against correct shipped behaviour — so it was both a false safety net
// and, on the 4-CPU sandbox, a flake bomb for unrelated work.
//
// It is DELETED rather than inverted because inverting it would duplicate two
// existing tests (Rule 18): the refresh half is
// TestRegisterRefreshesBetween50And90PercentOfTheGrantedExpiry
// (register_refresh_test.go), which already asserts the refresh fires, inside
// the granted window, with a BlockUntil; and the keepalive half is
// TestKeepaliveNoneSendsNothing (keepalive_test.go), which already asserts
// nothing is armed via KeepaliveArmed() — a stronger check than the
// datagram-count one this test used.

// TestRegisterInvalidRegistrarIsInvalidArgumentNotPanic pins D123: an IPv6 or
// otherwise malformed registrar must return a clean apierr.InvalidArgument,
// never panic. Register -> siptest.BuildRegister -> the vendored, unexported
// mustParseURI PANICS on "sip:[::1]:5060" ("bad uri: strconv.Atoi: parsing
// \":1]:5060\"") — a crash inside the daemon on an operator-supplied
// registrar address. validSIPURI must catch this before BuildRegister
// is ever called.
func TestRegisterInvalidRegistrarIsInvalidArgumentNotPanic(t *testing.T) {
	cases := []string{
		"sip:[::1]:5060",
		"sip:[2001:db8::1]:5060",
	}
	for _, registrar := range cases {
		t.Run(registrar, func(t *testing.T) {
			ua, err := sipua.New(context.Background(), sipua.Config{
				Transport: "udp",
				Mode:      "register",
				AOR:       "sip:alice@example",
				Registrar: registrar,
				AuthUser:  "alice",
				AuthPass:  "s3cr3t",
				ExpiresS:  300,
				Timeout:   2 * time.Second,
				Clock:     fakeclock.New(time.Unix(0, 0)),
				LocalAddr: "127.0.0.1:0",
			})
			if err != nil {
				t.Fatalf("sipua.New: %v", err)
			}
			t.Cleanup(func() { _ = ua.Close(context.Background()) })

			_, regErr := ua.Register(context.Background())
			if regErr == nil {
				t.Fatalf("Register with registrar %q returned nil error, want apierr.InvalidArgument", registrar)
			}
			var apiErr *apierr.Error
			if !errors.As(regErr, &apiErr) {
				t.Fatalf("Register error for registrar %q is %T, want *apierr.Error: %v", registrar, regErr, regErr)
			}
			if apiErr.Code != apierr.CodeInvalidArgument {
				t.Errorf("apierr.Code = %v, want %v", apiErr.Code, apierr.CodeInvalidArgument)
			}
		})
	}
}

func TestRegisterSendsTheConfiguredExpiresNotTheBuildersHardcode(t *testing.T) {
	// The peer echoes the request's own Expires when RegisterExpires is 0, so
	// the granted value proves what we actually put on the wire.
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 90)

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.ExpiresS != 90 {
		t.Fatalf("granted expires_s=%d want 90 — Config.ExpiresS must reach the wire "+
			"(the vendored builder hardcodes 300)", res.ExpiresS)
	}
	if got := p.LastRequestHeader("REGISTER", "Expires"); got != "90" {
		t.Fatalf("wire Expires=%q want \"90\"", got)
	}
}

func TestResponseExpiresFallsBackToTheRequestedValue(t *testing.T) {
	// A registrar that omits Expires from its 200 must not be reported as 300.
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{OmitRegisterExpires: true},
	})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 120)
	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.ExpiresS != 120 {
		t.Fatalf("granted expires_s=%d want the REQUESTED 120, never the literal 300", res.ExpiresS)
	}
}

// The Contact `expires` PARAMETER is the form RFC 3261 §10.2.4 makes REQUIRED
// of a registrar; the top-level Expires header is optional and plenty of real
// registrars never send it. Reading only the header made the requested value
// look like a grant, and since P3 that value ARMS THE REFRESH TIMER
// (startRegisterRefresher) rather than merely being reported — so the binding
// lapses long before the refresh fires, with nothing failing and ua_status
// still reporting the requested interval.
//
// These cases all pin responseExpires' resolution order: Contact parameter ->
// Expires header -> requested. The peer knobs they use (RegisterContactExpires,
// ExtraRegisterContacts, SuppressRegisterContactEcho) exist because the double
// previously ALWAYS emitted an Expires header, which is exactly why no earlier
// test could see this.
func TestResponseExpiresPrefersTheContactExpiresParameter(t *testing.T) {
	tests := []struct {
		name      string
		behaviour peer.Behaviour
		granted   int // peer.Config.RegisterExpires: the Expires HEADER value
		want      int
	}{{
		// THE FAILING CASE: the only grant on the wire is the Contact
		// parameter. Reading the header alone returns the requested 300 and
		// arms the refresh at 255s against a binding that lapses at 60s.
		name:      "contact param only, no Expires header",
		behaviour: peer.Behaviour{OmitRegisterExpires: true, RegisterContactExpires: "60"},
		want:      60,
	}, {
		// Both present and DISAGREEING: the parameter is authoritative.
		name:      "contact param wins over a disagreeing Expires header",
		behaviour: peer.Behaviour{RegisterContactExpires: "60"},
		granted:   120,
		want:      60,
	}, {
		// Another device's binding for the SAME AOR is listed FIRST. Taking
		// whichever Contact comes first adopts a stranger's expiry — the same
		// class of bug as reading only the header.
		name: "our own binding is chosen among several contacts, ours last",
		behaviour: peer.Behaviour{
			OmitRegisterExpires:    true,
			RegisterContactExpires: "60",
			ExtraRegisterContacts:  []string{"<sip:alice@127.0.0.1:5060>;expires=30"},
		},
		want: 60,
	}, {
		// THE MIRROR IMAGE, and it is not redundant: the case above lists the
		// stranger first, so it fails only against a first-wins bug. With ours
		// first, a UA that reads the LAST Contact adopts the stranger's 30.
		//
		// SCOPE — do not read more into these subcases than they cover. They
		// do NOT exercise the comma-combined parser defect, and they are not
		// what pins it. peer.respond AppendHeaders each Contact separately and
		// (*headers).StringWrite emits one "Contact:" row per header, so the
		// wire here never carries a comma-combined row and parseContactHeader's
		// comma branch is never entered. The divergence in
		// third_party/sipgo/sip/parse_address.go is pinned ONLY by that fork's
		// own parse_address_contact_comma_test.go — deleting it on the belief
		// that these subcases cover it would silently unpin the fix.
		name: "our own binding is chosen among several contacts, ours first",
		behaviour: peer.Behaviour{
			OmitRegisterExpires:        true,
			RegisterContactExpires:     "60",
			ExtraRegisterContactsAfter: []string{"<sip:alice@127.0.0.1:5060>;expires=30"},
		},
		want: 60,
	}, {
		// Ours in the middle: neither a first-wins nor a last-wins reader can
		// satisfy this one by accident.
		name: "our own binding is chosen among several contacts, ours in the middle",
		behaviour: peer.Behaviour{
			OmitRegisterExpires:        true,
			RegisterContactExpires:     "60",
			ExtraRegisterContacts:      []string{"<sip:alice@127.0.0.1:5060>;expires=30"},
			ExtraRegisterContactsAfter: []string{"<sip:alice@127.0.0.2:5060>;expires=1800"},
		},
		want: 60,
	}, {
		// No listed Contact is ours and no Expires header: nothing granted, so
		// the requested value stands. Adopting the stranger's 30 would be worse
		// than the bug being fixed.
		name: "no matching contact and no Expires header falls back to the requested value",
		behaviour: peer.Behaviour{
			OmitRegisterExpires:         true,
			SuppressRegisterContactEcho: true,
			ExtraRegisterContacts:       []string{"<sip:alice@127.0.0.1:5060>;expires=30"},
		},
		want: 300,
	}, {
		// A non-numeric parameter must not become a timer, and must not panic.
		name:      "malformed contact param falls back",
		behaviour: peer.Behaviour{OmitRegisterExpires: true, RegisterContactExpires: "not-a-number"},
		want:      300,
	}, {
		// Neither must a negative one.
		name:      "negative contact param falls back",
		behaviour: peer.Behaviour{OmitRegisterExpires: true, RegisterContactExpires: "-5"},
		want:      300,
	}, {
		// A malformed parameter does not discard a perfectly good header.
		name:      "malformed contact param falls back to the Expires header",
		behaviour: peer.Behaviour{RegisterContactExpires: "not-a-number"},
		granted:   120,
		want:      120,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.Start(t, peer.Config{
				Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
				RegisterExpires: tc.granted, Behaviour: tc.behaviour,
			})
			ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 300)
			res, err := ua.Register(context.Background())
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			if res.ExpiresS != tc.want {
				t.Fatalf("granted expires_s=%d want %d — resolution order is "+
					"Contact `expires` param (RFC 3261 §10.2.4, REQUIRED) -> Expires header "+
					"(optional) -> the requested value", res.ExpiresS, tc.want)
			}
		})
	}
}

// TestRegisterResultContactMatchesOurBindingAmongSeveral is B6:
// RegisterResult.Contact used to come straight from res.Contact(), which
// reads only the LAST Contact header on the wire — so a registrar listing
// another device's binding for the same AOR after ours put the STRANGER's
// address in RegisterResult.Contact. matchingContact (shared with
// contactExpires above, which never had this bug — it always searched every
// listed Contact) fixes it. Ours sits in the MIDDLE of three, the shape
// neither a first-wins nor a last-wins reader can satisfy by accident.
func TestRegisterResultContactMatchesOurBindingAmongSeveral(t *testing.T) {
	p := peer.Start(t, peer.Config{
		Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t",
		Behaviour: peer.Behaviour{
			ExtraRegisterContacts:      []string{"<sip:alice@127.0.0.1:5060>;expires=30"},
			ExtraRegisterContactsAfter: []string{"<sip:alice@127.0.0.2:5060>;expires=1800"},
		},
	})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 300)
	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !strings.Contains(res.Contact, ua.BoundAddr().String()) {
		t.Fatalf("RegisterResult.Contact=%q, want it to contain our own bound address %q — "+
			"three Contacts were listed and ours is in the middle (B6)",
			res.Contact, ua.BoundAddr().String())
	}
}

// TestCommaCombinedContactLineIsSplitAndOursSelected is the LAYER SEAM the
// subcases above deliberately do not cover, and say so: they drive
// responseExpires' selection given contacts that are ALREADY parsed one per
// header, and third_party/sipgo's own parse_address_contact_comma_test.go
// drives the parser on a raw string. Nothing drove a comma-combined row off
// the WIRE all the way through to a granted expiry — so a regression in either
// half stayed invisible to the other's tests. Kamailio and OpenSIPS both emit
// the multi-binding 200 OK this way (RFC 3261 §7.3.1 permits it for any
// comma-separated header), so this is the common registrar shape, not a
// contrived one.
//
// OURS COMES FIRST, AND THAT ORDERING IS THE WHOLE DISCRIMINATOR. The fork's
// one-line divergence narrows parseContactHeader's endInd to the comma, so each
// split section's params are read from ITS OWN section; without it every split
// header carries the LAST section's params. With ours listed LAST the two
// readings coincide and this test could not fail — exactly the coincidence
// shape that made twelve other tests in this wave vacuous. With ours FIRST the
// unfixed parser reports the stranger's 30 against our own 60.
func TestCommaCombinedContactLineIsSplitAndOursSelected(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 300)

	// ONE raw Contact row carrying both bindings, ours first. peer.respond
	// AppendHeaders this verbatim and (*headers).StringWrite emits it as a
	// single "Contact:" line, which is what puts the comma on the wire.
	ours := "<sip:alice@" + ua.BoundAddr().String() + ">;expires=60"
	stranger := "<sip:alice@127.0.0.1:5060>;expires=30"
	p.SetBehaviour(peer.Behaviour{
		OmitRegisterExpires:         true, // no header to fall back to
		SuppressRegisterContactEcho: true, // the combined row below is the only Contact
		ExtraRegisterContacts:       []string{ours + ", " + stranger},
	})

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.ExpiresS != 60 {
		t.Fatalf("granted expires_s=%d want 60 from the comma-combined row %q: 30 means the "+
			"parser gave our section the LAST section's params (the fork's one-line divergence, "+
			"third_party/sipgo/sip/parse_address.go); 300 means the row never split at all and "+
			"responseExpires fell through to the requested value", res.ExpiresS, ours+", "+stranger)
	}
}

func TestUnregisterStillSendsExpiresZero(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 90)
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ua.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if got := p.LastRequestHeader("REGISTER", "Expires"); got != "0" {
		t.Fatalf("deregistration Expires=%q want \"0\"", got)
	}
}

// TestRegisterWithUnsetExpiresDoesNotDeregister pins the bug a naive
// setExpires(req, cfg.ExpiresS) would introduce: ExpiresS == 0 is a valid,
// common "unset" profile configuration (policy validation treats it that
// way, and nothing defaults it before registerExpiresS), so passing the raw
// cfg.ExpiresS straight to setExpires would silently turn the INITIAL
// REGISTER into a de-registration — sending Expires: 0, getting a 200 OK to
// what is actually a de-registration, and reporting Registered: true while
// holding no real registration. registerExpiresS's defaulting-to-300 must
// prevent this.
func TestRegisterWithUnsetExpiresDoesNotDeregister(t *testing.T) {
	p := peer.Start(t, peer.Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	ua, _ := newRegisterUAExpires(t, p, fakeclock.New(time.Unix(0, 0)), 0)

	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := p.LastRequestHeader("REGISTER", "Expires"); got != "300" {
		t.Fatalf("wire Expires=%q want \"300\" — an unset ExpiresS must default, never send Expires: 0", got)
	}
	if got := p.UnregisterCount(); got != 0 {
		t.Fatalf("peer saw %d REGISTERs with Expires: 0, want 0 — an unset ExpiresS must not be treated as a de-registration", got)
	}
}

// TestRegisterRetryDeclinesWhenTheNamedFloorIsAlreadyMet pins
// retryIntervalTooBrief's `floor <= requestedExpiresS` disjunct
// (register.go:348), unpinned until now (fix-round-2 verify report §6, V3):
// deleting it left the whole suite green. It is a test gap, not a soundness
// defect — retryIntervalTooBrief is straight-line with no recursion, so
// termination never depended on this guard — but its own actual job, "a
// floor we already meet is not a reason to re-send", had nothing pinning it.
//
// A HAND-ROLLED REGISTRAR, NOT peer.Peer. peer.Behaviour.Reject423MinExpires
// only ever answers 423 when the request's OWN Expires is BELOW the named
// floor (registerExpires(req) < min); by that construction the floor it names
// is always ABOVE what was requested, never at or below it. There is no
// combination of peer.Config that can produce floor <= requestedExpiresS, so
// this test talks to a minimal one-shot registrar of its own that answers
// every REGISTER with a FIXED 423 naming exactly the requested expiry as its
// Min-Expires — the case the guard exists for.
func TestRegisterRetryDeclinesWhenTheNamedFloorIsAlreadyMet(t *testing.T) {
	reg := newFixedMinExpiresRegistrar(t, 60)

	ua, err := sipua.New(context.Background(), sipua.Config{
		Transport: "udp",
		Mode:      "register",
		AOR:       "sip:alice@example",
		Registrar: "sip:" + reg.Addr(),
		ExpiresS:  60,
		Timeout:   2 * time.Second,
		LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("sipua.New: %v", err)
	}
	t.Cleanup(func() { _ = ua.Close(context.Background()) })

	res, err := ua.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v — a rejected registration is a RESULT, not an error (§11.1)", err)
	}
	if res.Registered || res.Code != 423 {
		t.Fatalf("Register => registered=%v code=%d, want false/423 — a Min-Expires floor the "+
			"request already meets must be reported as the exchange's outcome, not silently retried",
			res.Registered, res.Code)
	}
	// THE LOAD-BEARING ASSERTION: the Result fields above are identical
	// whether or not the retry fires, because this fixed registrar answers
	// every REGISTER it sees the same way. Only the registrar's OWN count
	// distinguishes "declined to retry" (1) from "retried once, got the same
	// 423 again" (2), which is what deleting the guard's `floor <=
	// requestedExpiresS` disjunct produces.
	if n := reg.Count(); n != 1 {
		t.Fatalf("registrar saw %d REGISTERs, want exactly 1 — a Min-Expires floor of %d already "+
			"met by the requested %d must not be retried at all", n, 60, 60)
	}
}

// fixedMinExpiresRegistrar is the minimal one-shot REGISTER responder
// TestRegisterRetryDeclinesWhenTheNamedFloorIsAlreadyMet needs and peer.Peer
// cannot provide (see that test's comment): it answers every REGISTER, no
// digest challenge, with a fixed 423 Interval Too Brief naming exactly
// minExpiresS as its Min-Expires, regardless of what the request itself asked
// for.
type fixedMinExpiresRegistrar struct {
	conn        net.PacketConn
	minExpiresS int
	n           atomic.Int32
}

// newFixedMinExpiresRegistrar starts the registrar and registers its
// teardown; t.Cleanup closes the socket, which unblocks serve's ReadFrom and
// ends its goroutine.
func newFixedMinExpiresRegistrar(t *testing.T, minExpiresS int) *fixedMinExpiresRegistrar {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fixedMinExpiresRegistrar listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	r := &fixedMinExpiresRegistrar{conn: conn, minExpiresS: minExpiresS}
	go r.serve()
	return r
}

func (r *fixedMinExpiresRegistrar) Addr() string { return r.conn.LocalAddr().String() }
func (r *fixedMinExpiresRegistrar) Count() int   { return int(r.n.Load()) }

func (r *fixedMinExpiresRegistrar) serve() {
	parser := sip.NewParser()
	buf := make([]byte, 65535)
	for {
		n, from, err := r.conn.ReadFrom(buf)
		if err != nil {
			return // socket closed by t.Cleanup
		}
		msg, err := parser.ParseSIP(buf[:n])
		if err != nil {
			continue
		}
		req, ok := msg.(*sip.Request)
		if !ok || req.Method != sip.REGISTER {
			continue
		}
		r.n.Add(1)
		res := sip.NewResponseFromRequest(req, 423, "Interval Too Brief", nil)
		res.AppendHeader(sip.NewHeader("Min-Expires", strconv.Itoa(r.minExpiresS)))
		_, _ = r.conn.WriteTo([]byte(res.String()), from)
	}
}
