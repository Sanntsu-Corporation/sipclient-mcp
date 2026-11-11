package sipua

// Canonical module (Rule 18) for UAS request screening and capability answers:
// the RFC 3261 8.2 checks that run before a handler sees a request (416, 404,
// 420, 415), the OPTIONS answer (RFC 3261 11) and the 405 with Allow (8.2.1).
//
// Rule 16 reuse: headerValues (sessiontimer.go), u.targets and ourAllow,
// arrivalEnter/arrivalLeaveLocked (arrival.go) and sip.NewResponseFromRequest.
// graphify has no output in this worktree; grep for "Unsupported", 415, 420
// and 416 over internal/sipua found no existing screen.

import (
	"strings"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// understoodOptionTag is the one Require option tag this UA understands
// (RFC 4028 session timers).
const understoodOptionTag = "timer"

// unsupportedRequire returns the Require option tags this UA does not
// understand, in request order (RFC 3261 8.2.2.3).
func unsupportedRequire(req *sip.Request) []string {
	var out []string
	for _, v := range headerValues(req, "Require") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" && !strings.EqualFold(tok, understoodOptionTag) {
				out = append(out, tok)
			}
		}
	}
	return out
}

// sdpBody returns the session description req carries, or nil when it has
// none or carries only an optional part we ignore (RFC 3261 8.2.3). bad is
// "type", "encoding" or "disposition" when a required body is not usable SDP (a 415).
func sdpBody(req *sip.Request) (body []byte, bad string) {
	b := req.Body()
	if len(b) == 0 {
		return nil, ""
	}
	ct := ""
	if h := req.ContentType(); h != nil {
		ct = h.Value()
	}
	mt, _, _ := strings.Cut(ct, ";")
	typeOK := strings.EqualFold(strings.TrimSpace(mt), "application/sdp")
	encOK := true
	for _, v := range append(headerValues(req, "Content-Encoding"), headerValues(req, "e")...) {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" && !strings.EqualFold(tok, "identity") {
				encOK = false
			}
		}
	}
	// RFC 3261 20.11: an absent Content-Disposition means "session"; any other
	// disposition type is one we do not handle, so the body is not a session
	// offer (ignored when handling=optional, else a 415).
	dispOK := dispositionIsSession(req)
	switch {
	case typeOK && encOK && dispOK:
		return b, ""
	case optionalDisposition(req):
		return nil, ""
	case !typeOK:
		return nil, "type"
	case !encOK:
		return nil, "encoding"
	default:
		return nil, "disposition"
	}
}

// dispositionIsSession reports whether req's Content-Disposition is absent or
// of type "session" (RFC 3261 20.11).
func dispositionIsSession(req *sip.Request) bool {
	for _, v := range headerValues(req, "Content-Disposition") {
		typ, _, _ := strings.Cut(v, ";")
		if typ = strings.TrimSpace(typ); typ != "" && !strings.EqualFold(typ, "session") {
			return false
		}
	}
	return true
}

// optionalDisposition reports whether req's Content-Disposition carries the
// parameter handling=optional (RFC 3261 20.11).
func optionalDisposition(req *sip.Request) bool {
	for _, v := range headerValues(req, "Content-Disposition") {
		parts := strings.Split(v, ";")
		for _, p := range parts[1:] {
			k, val, _ := strings.Cut(p, "=")
			if strings.EqualFold(strings.TrimSpace(k), "handling") && strings.EqualFold(strings.TrimSpace(val), "optional") {
				return true
			}
		}
	}
	return false
}

// screenResponse runs the RFC 3261 8.2 checks in order and returns the
// refusal for req, or nil when the handler may run.
func (u *UA) screenResponse(req *sip.Request) *sip.Response {
	if sch := req.Recipient.Scheme; sch != "sip" && sch != "sips" {
		return sip.NewResponseFromRequest(req, 416, "Unsupported URI Scheme", nil)
	}
	if (req.Method == sip.INVITE || req.Method == sip.OPTIONS) && !u.targets(req) {
		return sip.NewResponseFromRequest(req, 404, "Not Found", nil)
	}
	if bad := unsupportedRequire(req); len(bad) > 0 {
		res := sip.NewResponseFromRequest(req, 420, "Bad Extension", nil)
		res.AppendHeader(sip.NewHeader("Unsupported", strings.Join(bad, ", ")))
		return res
	}
	if req.Method == sip.INVITE || req.Method == sip.UPDATE {
		switch _, bad := sdpBody(req); bad {
		case "type", "disposition":
			res := sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil)
			res.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
			return res
		case "encoding":
			res := sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil)
			res.AppendHeader(sip.NewHeader("Accept-Encoding", "identity"))
			return res
		}
	}
	return nil
}

// screen wraps h so a request that fails an RFC 3261 8.2 check is answered by
// the transaction and h is not called. Every handler for a method except ACK
// and CANCEL (which take no 4xx) is registered through it (installHandlers).
func (u *UA) screen(h sipgo.RequestHandler) sipgo.RequestHandler {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		res := u.screenResponse(req)
		if res == nil {
			h(req, tx)
			return
		}
		// A refused NOTIFY or BYE (the arrival-gated methods) still holds the
		// ticket the read loop stamped; release it so it cannot stall a later
		// request of a transfer.
		if arrivalGatedMethods[req.Method] {
			tk := u.arrivalEnter(req)
			u.calls.mu.Lock()
			arrivalLeaveLocked(tk)
			u.calls.mu.Unlock()
		}
		_ = tx.Respond(res)
	}
}

// retryAfterHeld is the Retry-After (seconds) of a 503 for a full held-INVITE
// bound: Timer H, the longest a held handler of an ended call can still live.
const retryAfterHeld = "32"

// onOptions answers OPTIONS (RFC 3261 11). Out of a dialog the status is the
// one an INVITE would get: 503 when the held-INVITE bound is full, else the
// admission verdict (486 at capacity, 503 when shutting down), computed by a
// probe that admits nothing and emits no event; in a dialog it is 200. The 200
// carries the capability headers and no body.
func (u *UA) onOptions(req *sip.Request, tx sip.ServerTransaction) {
	if toTagOf(req) == "" {
		if u.inviteBoundFull() {
			res := sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil)
			res.AppendHeader(sip.NewHeader("Retry-After", retryAfterHeld))
			_ = tx.Respond(res)
			return
		}
		// No handler registered: accept, as admit does.
		if v := u.admit(session.UAEvent{Kind: session.UAEventInbound, Direction: session.Inbound,
			AdmitProbe: true, At: u.cfg.Clock.Now()}); !v.Accept {
			_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusCode(v.Status), v.Reason, nil))
			return
		}
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Allow", ourAllow()))
	res.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
	res.AppendHeader(sip.NewHeader("Accept-Encoding", "identity"))
	res.AppendHeader(sip.NewHeader("Accept-Language", "en"))
	res.AppendHeader(sip.NewHeader("Supported", understoodOptionTag))
	_ = tx.Respond(res)
}

// inviteBoundFull reports whether claimInviteHold would answer an INVITE 503.
func (u *UA) inviteBoundFull() bool {
	bound := u.heldInviteBound()
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return u.calls.heldInvites >= bound
}

// onNoRoute answers a request whose method has no handler: 405 with Allow
// (RFC 3261 8.2.1), through the transaction.
func (u *UA) onNoRoute(req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil {
		return
	}
	res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	res.AppendHeader(sip.NewHeader("Allow", ourAllow()))
	_ = tx.Respond(res)
}

// inviteResponse builds a response to an initial INVITE carrying the dialog's
// one To tag (RFC 3261 8.2.6.2). sip.NewResponseFromRequest mints a fresh tag
// per call (third_party/sipgo/sip/response.go:226-231); this overwrites it.
// The 100 Trying and the responses sent before a dialog exists keep
// sip.NewResponseFromRequest.
func inviteResponse(inv *sip.Request, toTag string, code sip.StatusCode, reason string, body []byte) *sip.Response {
	res := sip.NewResponseFromRequest(inv, code, reason, body)
	if code != 100 && toTag != "" {
		res.To().Params.Add("tag", toTag)
	}
	return res
}
