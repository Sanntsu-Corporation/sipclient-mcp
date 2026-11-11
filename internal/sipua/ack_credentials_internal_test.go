package sipua

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func TestNewAckFor2xxCopiesBothCredentialHeaders(t *testing.T) {
	var uri sip.Uri
	if err := sip.ParseUri("sip:bob@127.0.0.1:5060", &uri); err != nil {
		t.Fatal(err)
	}
	mk := func(hdrs ...[2]string) *sip.Request {
		inv := sip.NewRequest(sip.INVITE, uri)
		inv.AppendHeader(sip.NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKx"))
		inv.AppendHeader(sip.NewHeader("From", "<sip:alice@x>;tag=ft"))
		inv.AppendHeader(sip.NewHeader("To", "<sip:bob@x>"))
		inv.AppendHeader(sip.NewHeader("Call-ID", "cid"))
		inv.AppendHeader(sip.NewHeader("CSeq", "2 INVITE"))
		for _, h := range hdrs {
			inv.AppendHeader(sip.NewHeader(h[0], h[1]))
		}
		return inv
	}
	res := func(inv *sip.Request) *sip.Response {
		return sip.NewResponseFromRequest(inv, sip.StatusOK, "OK", nil)
	}
	values := func(r *sip.Request, name string) []string {
		var out []string
		for _, h := range r.GetHeaders(name) {
			out = append(out, h.Value())
		}
		return out
	}

	// B-D5: the helper's AOR host is "example", so the credentials ride a target
	// on 127.0.0.1 only under the operator's auth_any_host opt-in.
	ua := newClaimTestUA(t, fakeclock.New(time.Unix(0, 0)))
	ua.cfg.AuthAnyHost = true
	inv := mk([2]string{"Authorization", "Digest a"}, [2]string{"Proxy-Authorization", "Digest p"})
	ack, err := ua.newAckFor2xx(inv, res(inv), uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := values(ack, "Authorization"); len(got) != 1 || got[0] != "Digest a" {
		t.Errorf("Authorization = %q", got)
	}
	if got := values(ack, "Proxy-Authorization"); len(got) != 1 || got[0] != "Digest p" {
		t.Errorf("Proxy-Authorization = %q", got)
	}

	inv = mk([2]string{"Proxy-Authorization", "Digest p1"}, [2]string{"Proxy-Authorization", "Digest p2"})
	ack, err = ua.newAckFor2xx(inv, res(inv), uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := values(ack, "Proxy-Authorization"); len(got) != 2 || got[0] != "Digest p1" || got[1] != "Digest p2" {
		t.Errorf("multi-value Proxy-Authorization = %q", got)
	}

	// Without the opt-in a target that is not the account host gets neither header.
	ua.cfg.AuthAnyHost = false
	inv = mk([2]string{"Authorization", "Digest a"}, [2]string{"Proxy-Authorization", "Digest p"})
	ack, err = ua.newAckFor2xx(inv, res(inv), uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := values(ack, "Authorization"); len(got) != 0 {
		t.Errorf("Authorization withheld case = %q", got)
	}
	if got := values(ack, "Proxy-Authorization"); len(got) != 0 {
		t.Errorf("Proxy-Authorization withheld case = %q", got)
	}
}
