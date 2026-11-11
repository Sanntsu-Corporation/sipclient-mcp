package sip

import "testing"

func ackTestInvite(t *testing.T) *Request {
	t.Helper()
	var uri Uri
	if err := ParseUri("sip:bob@10.0.0.1:5060", &uri); err != nil {
		t.Fatal(err)
	}
	req := NewRequest(INVITE, uri)
	req.AppendHeader(NewHeader("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKinv1"))
	req.AppendHeader(NewHeader("From", "<sip:alice@10.0.0.9>;tag=ft"))
	req.AppendHeader(NewHeader("To", "<sip:bob@10.0.0.1>"))
	req.AppendHeader(NewHeader("Call-ID", "cid-1"))
	req.AppendHeader(NewHeader("CSeq", "7 INVITE"))
	return req
}

func ackTestResponse(req *Request, code StatusCode, reason, contact string) *Response {
	res := NewResponseFromRequest(req, code, reason, nil)
	if to := res.To(); to != nil {
		to.Params.Add("tag", "t1")
	}
	if contact != "" {
		res.AppendHeader(NewHeader("Contact", contact))
	}
	return res
}

// CF-089, RFC 3261 17.1.1.3: the non-2xx ACK keeps the INVITE's Request-URI.
func TestNewAckRequestNon2xxKeepsTheOriginalRequestURI(t *testing.T) {
	inv := ackTestInvite(t)
	res := ackTestResponse(inv, 302, "Moved Temporarily", "<sip:alt@10.0.0.2:5070>")
	ack := newAckRequestNon2xx(inv, res, nil)

	if got, want := ack.Recipient.String(), inv.Recipient.String(); got != want {
		t.Errorf("ACK Request-URI = %q, want the INVITE's %q", got, want)
	}
	if vias := ack.GetHeaders("Via"); len(vias) != 1 || vias[0].Value() != inv.Via().Value() {
		t.Errorf("ACK Via = %v, want exactly the INVITE's %q", vias, inv.Via().Value())
	}
	if tag, _ := ack.To().Params.Get("tag"); tag != "t1" {
		t.Errorf("ACK To tag = %q, want t1", tag)
	}
	if ack.CallID().Value() != inv.CallID().Value() {
		t.Errorf("ACK Call-ID %q != INVITE's %q", ack.CallID().Value(), inv.CallID().Value())
	}
	if ack.From().Value() != inv.From().Value() {
		t.Errorf("ACK From %q != INVITE's %q", ack.From().Value(), inv.From().Value())
	}
	if c := ack.CSeq(); c.SeqNo != 7 || c.MethodName != ACK {
		t.Errorf("ACK CSeq = %d %s, want 7 ACK", c.SeqNo, c.MethodName)
	}
}

// Guard: a final with no Contact (passes at baseline).
func TestNewAckRequestNon2xxWithoutContact(t *testing.T) {
	inv := ackTestInvite(t)
	res := ackTestResponse(inv, 486, "Busy Here", "")
	ack := newAckRequestNon2xx(inv, res, nil)
	if got, want := ack.Recipient.String(), inv.Recipient.String(); got != want {
		t.Errorf("ACK Request-URI = %q, want %q", got, want)
	}
}

func TestNewAckRequestNon2xxDoesNotAliasTheInviteURI(t *testing.T) {
	inv := ackTestInvite(t)
	res := ackTestResponse(inv, 302, "Moved Temporarily", "<sip:alt@10.0.0.2:5070>")
	ack := newAckRequestNon2xx(inv, res, nil)
	ack.Recipient.Host = "mutated.example"
	if inv.Recipient.Host != "10.0.0.1" {
		t.Errorf("mutating the ACK's Request-URI changed the INVITE's host to %q", inv.Recipient.Host)
	}
}
