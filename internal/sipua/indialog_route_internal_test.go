package sipua

// CF-085/086/105/108/171 pure helpers of the in-dialog builder: dialogRoute,
// applyRouteSet, inDialogTransport (indialog.go). No sockets.

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func parseURI(t *testing.T, s string) sip.Uri {
	t.Helper()
	var u sip.Uri
	if err := sip.ParseUri(s, &u); err != nil {
		t.Fatalf("ParseUri(%q): %v", s, err)
	}
	return u
}

func parseReq(t *testing.T, lines ...string) *sip.Request {
	t.Helper()
	m, err := sip.ParseMessage([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

func parseRes(t *testing.T, lines ...string) *sip.Response {
	t.Helper()
	m, err := sip.ParseMessage([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Response)
}

func routeTestInvite(t *testing.T, extra ...string) *sip.Request {
	lines := []string{
		"INVITE sip:bob@h1 SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKx",
		"From: <sip:alice@a>;tag=ft",
		"To: <sip:bob@h1>",
		"Call-ID: c1",
		"CSeq: 1 INVITE",
		"Contact: <sip:alice@10.0.0.1:5060;transport=tcp>",
	}
	lines = append(lines, extra...)
	lines = append(lines, "Content-Length: 0")
	return parseReq(t, lines...)
}

func routeTestOK(t *testing.T, extra ...string) *sip.Response {
	lines := []string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKx",
		"From: <sip:alice@a>;tag=ft",
		"To: <sip:bob@h1>;tag=tt",
		"Call-ID: c1",
		"CSeq: 1 INVITE",
	}
	lines = append(lines, extra...)
	lines = append(lines, "Content-Length: 0")
	return parseRes(t, lines...)
}

func TestDialogRouteOutboundTargetIsTheTwoxxContact(t *testing.T) {
	inv := routeTestInvite(t)
	ok := routeTestOK(t, "Contact: <sip:stub@h2:5080;transport=TCP>")
	target, routes := dialogRoute(session.Outbound, inv, ok, nil)
	if got, want := target.String(), "sip:stub@h2:5080;transport=TCP"; got != want {
		t.Fatalf("target %q, want %q", got, want)
	}
	if len(routes) != 0 {
		t.Fatalf("routes %v, want none", routes)
	}
	target.UriParams.Add("mutated", "1")
	if _, has := ok.Contact().Address.UriParams.Get("mutated"); has {
		t.Fatal("the returned target aliases the 200's Contact")
	}
}

func TestDialogRouteOutboundWithoutContactKeepsTheDialledURI(t *testing.T) {
	inv := routeTestInvite(t)
	ok := routeTestOK(t)
	target, _ := dialogRoute(session.Outbound, inv, ok, nil)
	if target.String() != inv.Recipient.String() {
		t.Fatalf("target %q, want the dialled %q", target.String(), inv.Recipient.String())
	}
	target, routes := dialogRoute(session.Outbound, inv, nil, nil)
	if target.String() != inv.Recipient.String() || routes != nil {
		t.Fatalf("unanswered dialog: target %q routes %v", target.String(), routes)
	}
}

// routeHosts renders each route as host[/rr value]; URI parameter order is a
// map order and not part of the contract.
func routeHosts(routes []sip.Uri) string {
	var out []string
	for _, r := range routes {
		h := r.Host
		if v, ok := r.UriParams.Get("rr"); ok {
			h += "/" + v
		}
		if _, ok := r.UriParams.Get("lr"); !ok {
			h += "/NOLR"
		}
		out = append(out, h)
	}
	return strings.Join(out, " ")
}

func TestDialogRouteOutboundRouteSetIsReversedRecordRoute(t *testing.T) {
	ok := routeTestOK(t,
		"Record-Route: <sip:p1;lr;rr=1>, <sip:p2;lr;rr=2>",
		"Record-Route: <sip:p3;lr>")
	_, routes := dialogRoute(session.Outbound, routeTestInvite(t), ok, nil)
	if got, want := routeHosts(routes), "p3 p2/2 p1/1"; got != want {
		t.Fatalf("routes %q, want %q", got, want)
	}
}

func TestDialogRouteInboundRouteSetIsRecordRouteInOrder(t *testing.T) {
	inv := routeTestInvite(t,
		"Record-Route: <sip:p1;lr;rr=1>, <sip:p2;lr;rr=2>",
		"Record-Route: <sip:p3;lr>")
	target, routes := dialogRoute(session.Inbound, inv, nil, nil)
	if got, want := routeHosts(routes), "p1/1 p2/2 p3"; got != want {
		t.Fatalf("routes %q, want %q", got, want)
	}
	if got, want := target.String(), "sip:alice@10.0.0.1:5060;transport=tcp"; got != want {
		t.Fatalf("target %q, want the INVITE's Contact %q", got, want)
	}
}

func routeReq() *sip.Request {
	return sip.NewRequest(sip.BYE, sip.Uri{Host: "placeholder"})
}

func TestApplyRouteSetEmpty(t *testing.T) {
	req := routeReq()
	target := parseURI(t, "sip:user@remoteua")
	hop, strict := applyRouteSet(req, target, nil)
	if req.Recipient.String() != target.String() || len(req.GetHeaders("Route")) != 0 || hop.String() != target.String() || strict {
		t.Fatalf("ruri %q routes %d hop %q strict %v", req.Recipient.String(), len(req.GetHeaders("Route")), hop.String(), strict)
	}
}

func TestApplyRouteSetLoose(t *testing.T) {
	req := routeReq()
	target := parseURI(t, "sip:user@remoteua")
	routes := []sip.Uri{parseURI(t, "sip:p1;lr;rr=1"), parseURI(t, "sip:p2;lr")}
	hop, strict := applyRouteSet(req, target, routes)
	var got []sip.Uri
	for _, h := range req.GetHeaders("Route") {
		got = append(got, h.(*sip.RouteHeader).Address)
	}
	if req.Recipient.String() != target.String() || strict || routeHosts([]sip.Uri{hop}) != "p1/1" ||
		routeHosts(got) != "p1/1 p2" {
		t.Fatalf("ruri %q hop %q strict %v routes %v", req.Recipient.String(), hop.String(), strict, routeHosts(got))
	}
}

func TestApplyRouteSetStrict(t *testing.T) {
	req := routeReq()
	target := parseURI(t, "sip:user@remoteua")
	routes := []sip.Uri{
		parseURI(t, "sip:proxy1;method=INVITE?X=1"), parseURI(t, "sip:proxy2"),
		parseURI(t, "sip:proxy3;lr"), parseURI(t, "sip:proxy4"),
	}
	hop, strict := applyRouteSet(req, target, routes)
	var got []string
	for _, h := range req.GetHeaders("Route") {
		got = append(got, h.Value())
	}
	if !strict || req.Recipient.String() != "sip:proxy1" || hop.String() != "sip:proxy1" ||
		strings.Join(got, " ") != "<sip:proxy2> <sip:proxy3;lr> <sip:proxy4> <sip:user@remoteua>" {
		t.Fatalf("strict %v ruri %q routes %v", strict, req.Recipient.String(), got)
	}
	if routes[0].Headers.Length() == 0 {
		t.Fatal("applyRouteSet mutated the caller's route")
	}
}

func TestInDialogTransportTable(t *testing.T) {
	cases := []struct {
		ua, target string
		routes     []string
		want       string // "" = precondition_failed
	}{
		{"udp", "sip:h", nil, "UDP"},
		{"udp", "sip:h;transport=TCP", nil, "TCP"},
		{"udp", "sip:h;transport=tcp", nil, "TCP"},
		{"udp", "sip:h;transport=tls", nil, "UDP"},
		{"udp", "sip:h;transport=ws", nil, "UDP"},
		{"udp", "sip:h;transport=wss", nil, "UDP"},
		{"udp", "sip:h;transport=sctp", nil, "UDP"},
		{"tcp", "sip:h", nil, "TCP"},
		{"tcp", "sip:h;transport=udp", nil, "TCP"},
		{"tcp", "sip:h;transport=wss", nil, "TCP"},
		{"tls", "sip:h", nil, "TLS"},
		{"tls", "sip:h;transport=udp", nil, "TLS"},
		{"tls", "sip:h;transport=tcp", nil, "TLS"},
		{"tls", "sips:h", nil, "TLS"},
		{"udp", "sips:h", nil, ""},
		{"tcp", "sips:h;transport=tcp", nil, ""},
		{"udp", "sips:x", []string{"sip:p;lr"}, ""},
		{"udp", "sip:x", []string{"sip:p;lr;transport=tcp"}, "TCP"},
	}
	for _, c := range cases {
		var routes []sip.Uri
		for _, r := range c.routes {
			routes = append(routes, parseURI(t, r))
		}
		got, err := inDialogTransport(c.ua, parseURI(t, c.target), routes)
		if c.want == "" {
			if err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed {
				t.Errorf("(%s, %s, %v): got %q, %v; want precondition_failed", c.ua, c.target, c.routes, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("(%s, %s, %v): got %q, %v; want %q", c.ua, c.target, c.routes, got, err, c.want)
		}
	}
	if got, err := inDialogTransport("", parseURI(t, "sip:h;transport=tcp"), nil); err != nil || got != "TCP" {
		t.Errorf("empty UA transport with tcp target: %q, %v", got, err)
	}
}

func TestBuildInDialogRequestSipsRefusalBurnsNoCSeq(t *testing.T) {
	u := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	u.cfg.Transport = "udp"
	inv := routeTestInvite(t)
	inv.Contact().Address.Scheme = "sips"
	ok := sip.NewResponseFromRequest(inv, 200, "OK", nil)
	d := &dialog{id: "d1", direction: session.Inbound, phase: phaseAnswered, invite: inv, ok: ok, localCSeq: 3}
	if _, _, err := u.buildInDialogRequest(d, sip.BYE); err == nil || apierr.CodeOf(err) != apierr.CodePreconditionFailed {
		t.Fatalf("err = %v, want precondition_failed", err)
	}
	if d.localCSeq != 3 {
		t.Fatalf("localCSeq = %d, want 3 (a refusal reserves nothing)", d.localCSeq)
	}
}
