package sipua

// indialog.go — the ONE outbound in-dialog transaction seam (plan D12).
//
// RFC 3261 §12.2.1.1: the CSeq numbers of requests a UA sends within a dialog
// MUST strictly increase IN THE ORDER THEY ARE SENT. buildInDialogRequest
// (dtmf.go) reserves d.localCSeq under u.calls.mu and releases it before the
// request is dispatched, so on its own it orders RESERVATION, not the WIRE: a
// REFER that reserved CSeq n and a session-timer refresh that reserved n+1
// could reach the transport in either order, and a compliant peer answers the
// late, lower one 500 (§12.2.2). sendInDialog closes that window with a
// per-dialog send-order token held from BEFORE the reservation until the
// transaction layer has written the request — sipgo's TransactionLayer.Request
// writes synchronously in ClientTx.Init before TransactionRequest returns
// (third_party/sipgo/sip/transaction_layer.go:191, transaction_client_tx.go:41)
// — and released BEFORE the response wait, so a slow peer never serializes the
// dialog for a whole Timer F.
//
// PER DIALOG, NOT UA-GLOBAL — the lesson digestRetryMu's scope fix recorded
// (digestauth_lockscope_test.go): only requests that MUST be mutually ordered
// share the token. A 1-slot CHANNEL, not a sync.Mutex, so a waiter honours its
// own ctx.
//
// LOCK ORDER: send-order token -> u.calls.mu. prepare runs with the token held
// and MAY take u.calls.mu; nothing takes the token while holding u.calls.mu,
// and nothing holding the token waits for anything but the transaction layer.
// Every in-dialog request this UA originates goes through here
// (TestEveryInDialogRequestIsSentThroughSendInDialog pins it). Two ACKs are
// the exceptions: the initial INVITE's 2xx ACK (call.go, written pre-
// establishment while d.phase is still phaseAnswering) and the ACK to a
// re-INVITE's 2xx (sendInDialog). Both reuse their INVITE's CSeq and
// allocate none, and both are addressed by addressInDialog (CF-193).
//
// NO FIRST TRANSMISSION FOLLOWS OUR OWN BYE (CF-018). buildInDialogRequest
// refuses every non-BYE method that opens a new transaction (REFER, INFO,
// UPDATE, or re-INVITE) on a dialog that is no longer established, inside
// the same u.calls.mu section that reserves the CSeq, and it only ever runs
// with the token held. Every BYE this UA sends first moves the dialog out of
// an established phase (phaseDone in hangupWithReason; phaseMediaTeardown in
// runDial's ACK-then-BYE branch) BEFORE it comes here for the token. So a
// REFER, INFO, UPDATE or re-INVITE either has its first transmission on the
// wire before our BYE or is refused without consuming a CSeq. Three
// residuals are accepted by design, none fixed by holding u.calls.mu across
// I/O: a peer BYE already crossing ours on the wire (answered 481 by the
// existing paths); a send already admitted under the token (checked and
// CSeq reserved) when a BYE-less teardown (peer BYE, Timer F, UA close)
// marks the dialog done, which no BYE of ours follows; and completion
// traffic of a transaction whose first transmission preceded our BYE
// (for example, retransmissions — see FIRST TRANSMISSION ONLY below — and
// the ACKs RFC 3261 requires for a re-INVITE's final responses), which opens
// no transaction and allocates no CSeq.
//
// ADDRESSING (CF-085/086/105/108/171). buildInDialogRequest is the one place an
// in-dialog request is addressed, through dialogRoute (remote target and route
// set, RFC 3261 12.1), applyRouteSet (Request-URI and Route, 12.2.1.1) and
// inDialogTransport (the transport the next hop is reached over). No call site
// sets a Request-URI, Route, transport or Supported of its own.
//
// FIRST TRANSMISSION ONLY. The token orders each request's FIRST write. Over
// UDP, the transaction layer retransmits a request on its own timer (RFC 3261
// §17.1.2.2, Timer E), so a lost REFER whose retransmission lands after a later
// request's first transmission can still reach the peer out of CSeq order. That
// is inherent to SIP over UDP, not a gap in this seam. A compliant peer answers
// the late one 500, and every caller already treats that as an ordinary
// non-2xx result.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// inDialogSendContendedHook is a TEST-ONLY seam, nil in production — the
// mediaTeardownHook precedent (call.go). It runs when a send finds its dialog's
// send-order token already held, just before it blocks for it, so a test can
// observe "waited its turn" positively instead of inferring it from a sleep.
var inDialogSendContendedHook func(method sip.RequestMethod)

// sendOrderTokLocked returns d's send-order token, creating it on first use.
// Caller MUST hold u.calls.mu.
func sendOrderTokLocked(d *dialog) chan struct{} {
	if d.sendOrder == nil {
		d.sendOrder = make(chan struct{}, 1)
	}
	return d.sendOrder
}

// noTransactionError marks an error from sendInDialog's own TransactionRequest
// call: the request was built and its CSeq consumed, but no transaction could
// even be started (an immediate transport/routing failure) — as distinct from
// a transaction that started and then drew no final response (a timeout) or
// was cancelled waiting for one. Embeds error, so Error() and every existing
// caller's err.Error()/ctx.Err() checks are unaffected; only a caller that
// opts in via noTransactionErr sees the distinction (transfer.go's
// concludeRefer path, CF-009). Unwrap() lets errors.Is/errors.As still
// traverse to the underlying error (e.g. a caller checking ctx.Err() via
// errors.Is) — embedding error alone satisfies Error() but does not, by
// itself, give errors.Is/As a path through.
type noTransactionError struct{ error }

// Unwrap gives errors.Is/errors.As a path into the wrapped error.
func (e *noTransactionError) Unwrap() error { return e.error }

func noTransactionErr(err error) bool {
	var e *noTransactionError
	return errors.As(err, &e)
}

// sendInDialog builds (buildInDialogRequest), prepares, dispatches and drives to
// its final response ONE in-dialog request of the given method on d, with its
// CSeq reservation and its wire dispatch ordered against every other
// sendInDialog on d. Otherwise it is RawTransaction's exact behaviour: an
// option-less TransactionRequest (so sipgo bumps the CSeq once more, as
// dialog.localCSeq's comment documents), bounded by u.cfg.Timeout within ctx,
// and awaitFinal's (digestauth.go) swallow-1xx wait — the same loop as
// siptest's doTx, and the same errors.
//
// prepare adds the call site's own headers/body; it runs with the token held
// (it may take u.calls.mu, never the token) and may be nil. It runs once per
// ATTEMPT on that attempt's request: twice, on two distinct requests, when a
// 401/407 is answered with credentials (CF-122).
//
// ONE SEAM DECIDES THE OUTCOME for every in-dialog method (Rule 18):
//   - a 401/407 is answered ONCE with the UA's configured account, under the
//     CF-046/CF-054 credential guard (the next hop must be the account's host
//     and the challenge and the request's destination pinned), the retry going
//     to the very address the guard checked;
//   - a 2xx to an INVITE (the refresh re-INVITE) is ACKed here, and the live
//     transaction handed to absorbInvite2xx so a retransmitted 2xx is re-ACKed
//     (CF-169, RFC 3261 13.2.2.4);
//   - a 481 or 408, or no final response at all, to any request except BYE ends
//     the dialog locally, without a BYE (CF-109/CF-110, RFC 3261 12.2.1.2).
//
// The returned req is non-nil IFF the request was built — and therefore iff
// prepare ran and a CSeq was consumed (a retried exchange returns the retry's
// request). A nil req with a non-nil err means NOTHING was sent: the wait for the
// token ended (err is ctx.Err(); for a BYE, only u.cfg.Timeout can end it — see
// below), or buildInDialogRequest refused (its own precondition_failed).
func (u *UA) sendInDialog(ctx context.Context, d *dialog, method sip.RequestMethod, prepare func(req *sip.Request)) (*sip.Request, *sip.Response, error) {
	req, res, tx, hop, err := u.inDialogAttempt(ctx, d, method, prepare, nil, nil)
	if req != nil && err == nil && u.inDialogCanRetry(ctx, d, req, hop, res) {
		req2, res2, tx2, _, err2 := u.inDialogAttempt(ctx, d, method, prepare, req, res)
		switch {
		case req2 != nil: // attempt 2 was built: its outcome is the result (S3a, S6)
			tx.Terminate()
			req, res, tx, err = req2, res2, tx2, err2
		case ctx.Err() != nil: // the token wait ended on the caller's ctx (S3b)
			tx.Terminate()
			return req, nil, err2
		}
		// else attempt 2 was refused (the dialog ended meanwhile, S5): attempt 1's
		// challenge stands.
	}
	if (method == sip.INVITE || method == sip.UPDATE) && req != nil && err == nil && res.IsSuccess() {
		u.refreshTargetFromResponse(d, res) // before the re-INVITE's ACK is built (CF-184)
	}
	if tx != nil {
		if method == sip.INVITE && err == nil && res.IsSuccess() {
			u.calls.mu.Lock()
			target, routes := dialogRoute(d.direction, d.invite, d.ok, d.remoteTarget)
			u.calls.mu.Unlock()
			ack, aerr := u.newAckFor2xx(req, res, target, routes)
			if aerr != nil {
				// Cannot happen: refreshRefusal refused any target inDialogTransport
				// rejects, and buildInDialogRequest refused the re-INVITE itself
				// (B-D6). A nil ACK must never reach absorbInvite2xx, which writes it.
				u.log().Warn("ACK of a re-INVITE's 2xx not sent", "dialog_id", d.id, "err", aerr)
				tx.Terminate()
			} else {
				u.writeAck(ack)
				uaCtx := u.uaCtx
				if uaCtx == nil {
					uaCtx = context.Background()
				}
				go u.absorbInvite2xx(uaCtx, tx, req, res, ack) //nolint:contextcheck // the absorber outlives this request's ctx (it ends on Timer M or UA close), like runDial's.
			}
		} else {
			tx.Terminate()
		}
	}
	if req != nil {
		if cause := inDialogEndCause(method, ctx.Err(), res, err); cause != "" {
			causeErr := err
			if causeErr == nil {
				causeErr = fmt.Errorf("%s answered %d", method, res.StatusCode)
			}
			u.endDialogInDialogTimeout(d, string(method), causeErr, cause) //nolint:contextcheck // same u.emit-on-retained-evCtx pattern as concludeRefer: the dialog-ended event is delivered on the long-lived evCtx/u.uaCtx, not this request's ctx.
		}
	}
	return req, res, err
}

// inDialogAttempt is one send of an in-dialog request: take the send-order
// token, build, prepare, dispatch, release the token, await the final response.
// It does NOT terminate the transaction it returns (sendInDialog decides: the
// absorber takes it, or it is terminated). prev and challenge are set for the
// credentialed retry: the request is sent to prev's destination through the
// digest engine. A nil req means nothing was built.
func (u *UA) inDialogAttempt(ctx context.Context, d *dialog, method sip.RequestMethod, prepare func(req *sip.Request), prev *sip.Request, challenge *sip.Response) (req *sip.Request, res *sip.Response, tx sip.ClientTransaction, hop sip.Uri, err error) {
	u.calls.mu.Lock()
	tok := sendOrderTokLocked(d)
	u.calls.mu.Unlock()

	// A BYE's wait for its turn is DETACHED from its caller's cancellation and
	// bounded by u.cfg.Timeout instead (Cycle C round 2, non-blocking 1). Every
	// BYE sender (hangupWithReason, runDial's ACK-then-BYE) has ALREADY set
	// phaseDone and forgotten the dialog, so abandoning the wait would end the
	// call locally with NO BYE on the wire. Before this seam existed that BYE
	// was always dispatched. Only the WAIT is detached: the transaction below
	// still runs on the caller's ctx, exactly as RawTransaction did.
	waitCtx := ctx
	if method == sip.BYE {
		var cancelWait context.CancelFunc
		waitCtx, cancelWait = context.WithTimeout(context.WithoutCancel(ctx), u.cfg.Timeout)
		defer cancelWait()
	}
	select {
	case tok <- struct{}{}:
	default:
		if inDialogSendContendedHook != nil {
			inDialogSendContendedHook(method)
		}
		select {
		case tok <- struct{}{}:
		case <-waitCtx.Done():
			return nil, nil, nil, hop, waitCtx.Err()
		}
	}
	held := true
	release := func() {
		if held {
			held = false
			<-tok
		}
	}
	defer release()

	req, hop, err = u.buildInDialogRequest(d, method)
	if err != nil {
		return nil, nil, nil, hop, err
	}
	if prepare != nil {
		prepare(req)
	}
	tctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()
	if challenge != nil {
		// CF-054: the credential goes only to the address the guard checked.
		req.SetDestination(prev.Destination())
		tx, err = u.digestAuthTransaction(tctx, req, challenge)
	} else {
		tx, err = u.Client().Raw().TransactionRequest(tctx, req)
	}
	// Written (or refused outright): the next sender on this dialog may reserve
	// its CSeq now. Released BEFORE the response wait — see the file comment.
	release()
	if err != nil {
		return req, nil, nil, hop, &noTransactionError{err}
	}
	res, err = u.awaitFinal(tctx, tx)
	return req, res, tx, hop, err
}

// inDialogCanRetry reports whether res, attempt 1's answer to req, is a digest
// challenge sendInDialog may answer with credentials (CF-122): a 401/407 with its
// challenge header, a configured account, the next hop and the Request-URI both being that account's host
// (CF-046) and the challenge source and the request's destination being pinned
// to it (CF-054). The hop is the next-hop URI buildInDialogRequest derived
// (first route, strict router, or remote target). A refusal logs once and leaves
// the 401/407 as the result.
func (u *UA) inDialogCanRetry(ctx context.Context, d *dialog, req *sip.Request, hop sip.Uri, res *sip.Response) bool {
	var want string
	switch res.StatusCode {
	case 401:
		want = "WWW-Authenticate"
	case 407:
		want = "Proxy-Authenticate"
	default:
		return false
	}
	if res.GetHeader(want) == nil {
		return false
	}
	if u.cfg.AuthUser == "" || u.cfg.AuthPass == "" {
		u.log().Warn("digest challenge not answered: no auth credentials configured",
			"dialog_id", d.id, "method", string(req.Method), "status", int(res.StatusCode))
		return false
	}
	if !digestHostAllowed(u.cfg, hop.Host) {
		u.log().Warn("digest challenge not answered: the next hop is not the account's registrar or AOR host",
			"dialog_id", d.id, "target_host", hop.Host, "method", string(req.Method), "status", int(res.StatusCode))
		return false
	}
	// The digest response is end-to-end usable by whoever owns the REMOTE TARGET
	// (the peer's Contact): it must be the account host too (Cycle 5 B1). It is
	// read from the dialog, not from req.Recipient: a strict-routing rewrite
	// (RFC 3261 12.2.1.1) puts the first route there and the target last in Route
	// (Cycle 4 round 1).
	u.calls.mu.Lock()
	inv, ok, dir, refreshed := d.invite, d.ok, d.direction, d.remoteTarget
	u.calls.mu.Unlock()
	target, _ := dialogRoute(dir, inv, ok, refreshed)
	if !digestHostAllowed(u.cfg, target.Host) || !digestHostAllowed(u.cfg, req.Recipient.Host) {
		u.log().Warn("digest challenge not answered: the remote target is not the account's registrar or AOR host",
			"dialog_id", d.id, "target_host", target.Host, "method", string(req.Method), "status", int(res.StatusCode))
		return false
	}
	return u.challengeSourceRefusal(ctx, d.id, hop.Host, req.Destination(), res) == ""
}

// inDialogEndCause reports whether an in-dialog request's outcome ends the dialog
// (RFC 3261 12.2.1.2) and the detail.cause it is reported with; "" keeps it. A
// BYE never does (its sender already ended the dialog), nor a cancelled request
// (nothing was learned), nor a send that never dispatched (CF-009).
func inDialogEndCause(method sip.RequestMethod, ctxErr error, res *sip.Response, err error) string {
	if method == sip.BYE || ctxErr != nil {
		return ""
	}
	if err != nil {
		if noTransactionErr(err) {
			return ""
		}
		if refreshDrewNoResponse(err) {
			return "in_dialog_timeout"
		}
		return ""
	}
	switch res.StatusCode {
	case 481:
		return "in_dialog_481"
	case 408:
		return "in_dialog_408"
	}
	return ""
}

// dialogRoute returns d's remote target and route set (RFC 3261 12.1.1, 12.1.2).
// inv is the dialog's INVITE, ok its 2xx (nil on an inbound dialog). It clones
// and never aliases the dialog's stored headers. refreshed, when non-nil, is the
// remote target a target-refresh request or its 2xx replaced (d.remoteTarget,
// CF-184, RFC 3261 12.2.1.2/12.2.2): it overrides the target, never the route set.
func dialogRoute(dir session.Direction, inv *sip.Request, ok *sip.Response, refreshed *sip.Uri) (target sip.Uri, routes []sip.Uri) {
	target = *inv.Recipient.Clone()
	var rr []sip.Header
	if dir == session.Inbound {
		if c := inv.Contact(); c != nil {
			target = *c.Address.Clone()
		}
		rr = inv.GetHeaders("Record-Route") // as received
	} else {
		if ok == nil {
			return target, nil // not answered yet: the dialled URI, no route set
		}
		if c := ok.Contact(); c != nil {
			target = *c.Address.Clone() // no Contact: keep the dialled URI
		}
		hs := ok.GetHeaders("Record-Route")
		for i := len(hs) - 1; i >= 0; i-- {
			rr = append(rr, hs[i]) // reversed
		}
	}
	for _, h := range rr {
		if r, isRR := h.(*sip.RecordRouteHeader); isRR {
			routes = append(routes, *r.Address.Clone())
		}
	}
	if refreshed != nil {
		target = *refreshed.Clone()
	}
	return target, routes
}

// refreshRefusal reports why the Contact c of a target-refresh request (or of the
// 2xx to ours) cannot become the dialog's remote target, or "" when it can or when
// there is no Contact (the target is kept). Acceptable (CF-184, B-D3): a sip: or
// sips: URI; not sip: when the current target is sips: (CF-171, never downgrade);
// and one inDialogTransport accepts, so a refresh cannot make the dialog
// unreachable.
func refreshRefusal(uaTransport string, cur sip.Uri, routes []sip.Uri, c *sip.ContactHeader) string {
	if c == nil {
		return ""
	}
	next := c.Address
	if next.Scheme != "sip" && next.Scheme != "sips" {
		return "the Contact is not a sip: or sips: URI"
	}
	if cur.IsEncrypted() && !next.IsEncrypted() {
		return "the Contact would downgrade a sips: remote target to sip:"
	}
	if _, err := inDialogTransport(uaTransport, next, routes); err != nil {
		return err.Error()
	}
	return ""
}

// contactRefusal is the UAS side of refreshRefusal for a matched target-refresh
// request (re-INVITE, UPDATE): the 400 to send before anything is applied, or nil
// (B-D3). Call it after the glare, order and busy refusals and before
// appendInDialogRefreshHeaders.
func (u *UA) contactRefusal(d *dialog, req *sip.Request) *sip.Response {
	c := req.Contact()
	if c == nil {
		return nil
	}
	u.calls.mu.Lock()
	cur, routes := dialogRoute(d.direction, d.invite, d.ok, d.remoteTarget)
	u.calls.mu.Unlock()
	reason := refreshRefusal(u.Transport(), cur, routes, c)
	if reason == "" {
		return nil
	}
	u.log().Warn("target-refresh request refused: unacceptable Contact", "dialog_id", d.id, "method", string(req.Method), "reason", reason)
	return sip.NewResponseFromRequest(req, 400, "Bad Request", nil)
}

// setRemoteTarget stores the Contact c of a target-refresh request whose 2xx was
// written (or of the 2xx to ours) as the dialog's remote target (RFC 3261 12.2.2,
// RFC 6141 4.6). The acceptance check runs again here, against the CURRENT target
// and in the same critical section as the store: contactRefusal's earlier check
// saw an older target, and a concurrent refresh that upgraded the target to sips:
// in between must not be undone by a sip: Contact validated before it (CF-171,
// B-D3 never-downgrade). A Contact refused here is kept out with one Warn: its
// 2xx is already on the wire (UAS) or a response cannot be refused (UAC).
func (u *UA) setRemoteTarget(d *dialog, c *sip.ContactHeader) {
	if reason := u.storeRemoteTarget(d, u.Transport(), c); reason != "" {
		u.log().Warn("remote target not refreshed: unacceptable Contact", "dialog_id", d.id, "reason", reason)
	}
}

// storeRemoteTarget is setRemoteTarget's compare-and-set under u.calls.mu: it
// stores c when refreshRefusal accepts it against the current target and returns
// the refusal reason otherwise ("" when stored or when there is no Contact).
func (u *UA) storeRemoteTarget(d *dialog, uaTransport string, c *sip.ContactHeader) string {
	if c == nil {
		return ""
	}
	next := *c.Address.Clone()
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	cur, routes := dialogRoute(d.direction, d.invite, d.ok, d.remoteTarget)
	if reason := refreshRefusal(uaTransport, cur, routes, c); reason != "" {
		return reason
	}
	d.remoteTarget = &next
	return ""
}

// refreshTargetFromResponse is the UAC side: the 2xx to our re-INVITE or UPDATE
// replaces the remote target with its Contact (RFC 3261 12.2.1.2); a Contact
// refreshRefusal rejects is ignored with one Warn (B-D3), decided atomically with
// the store by setRemoteTarget.
func (u *UA) refreshTargetFromResponse(d *dialog, res *sip.Response) {
	u.setRemoteTarget(d, res.Contact())
}

// applyRouteSet writes the Request-URI and Route headers (RFC 3261 12.2.1.1) and
// returns the next hop's URI and whether the first route is a strict router.
func applyRouteSet(req *sip.Request, target sip.Uri, routes []sip.Uri) (hop sip.Uri, strict bool) {
	for req.RemoveHeader("Route") { // RemoveHeader removes one header per call; an ACK from NewAckRequest may carry several
	}
	if len(routes) == 0 {
		req.Recipient = target
		return target, false
	}
	if _, lr := paramFold(routes[0].UriParams, "lr"); lr {
		req.Recipient = target
		for _, r := range routes {
			req.AppendHeader(&sip.RouteHeader{Address: r})
		}
		return routes[0], false
	}
	ruri := *routes[0].Clone()
	ruri.Headers = nil // headers are not allowed in a Request-URI (rfc3261.txt:8465-8488, Table 1)
	for k := range ruri.UriParams {
		if strings.EqualFold(k, "method") {
			delete(ruri.UriParams, k)
		}
	}
	req.Recipient = ruri
	for _, r := range routes[1:] {
		req.AppendHeader(&sip.RouteHeader{Address: r})
	}
	req.AppendHeader(&sip.RouteHeader{Address: target})
	return ruri, true
}

// addressInDialog addresses req per RFC 3261 12.2.1.1 (CF-105/086/108): the
// remote target and route set, loose or strict. The transport is stated
// explicitly (CF-171). A strict first hop is also the destination, because the
// fork would otherwise send to the first Route header; for a loose or empty
// route set the destination is cleared, so one copied from another request (the
// INVITE's, by sip.NewAckRequest) never survives (CF-193). It returns the next hop.
func addressInDialog(req *sip.Request, target sip.Uri, routes []sip.Uri, transport string) sip.Uri {
	hop, strict := applyRouteSet(req, target, routes)
	req.SetTransport(transport)
	if strict {
		probe := sip.NewRequest(req.Method, hop)
		probe.SetTransport(transport)
		req.SetDestination(probe.Destination())
	} else {
		req.SetDestination("")
	}
	return hop
}

// inDialogTransport is CF-171's rule. uaTransport is Config.Transport
// ("udp"|"tcp"|"tls"). A TLS UA, or a sips: hop, always uses TLS and a sips:
// hop on a non-TLS UA is refused; a peer's transport=tcp is followed (TCP is no
// weaker than UDP); udp, tls on a non-TLS UA, ws, wss and unknown values are
// ignored. An empty uaTransport (a bare &UA{} in whitebox tests) returns "",
// and SetTransport("") leaves the fork's own inference. The next hop is the
// first route when there is a route set, else the remote target.
func inDialogTransport(uaTransport string, target sip.Uri, routes []sip.Uri) (string, error) {
	ua := strings.ToLower(uaTransport)
	hop := target
	if len(routes) > 0 {
		hop = routes[0]
	}
	if ua == "tls" || target.IsEncrypted() || hop.IsEncrypted() {
		if ua != "tls" {
			return "", apierr.PreconditionFailed("in-dialog request: the dialog's target is a sips: URI, which needs a TLS user agent")
		}
		return "TLS", nil
	}
	if p, _ := paramFold(hop.UriParams, "transport"); strings.EqualFold(p, "tcp") {
		return "TCP", nil
	}
	return strings.ToUpper(ua), nil
}
