package session

import (
	"context"
	"errors"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// admitInbound is I2's SYNCHRONOUS admission decision for an inbound INVITE
// (R14's incoming_call path). sipua calls it — through the OnAdmit channel —
// BEFORE it rings, so `session` accepts or rejects the call over the §12.2.2
// concurrency caps (or during §11.4 shutdown) with no ring and no dialog leak
// on a reject. On Accept a call is created ALREADY IN `ringing` (§10.3: an
// inbound call never enters `dialing`).
//
// IT MUST NOT LOCK m.mu ITSELF AND MUST NOT CALL checkConcurrencyLocked. The
// real CreateCall already takes m.mu (write) and runs checkConcurrencyLocked
// internally — the deliberately-single cap gate (Rule 18). Holding m.mu and
// then calling CreateCall would DEADLOCK and double-check. This mirrors the
// prior handleInbound body verbatim but returns a verdict rather than logging
// on denial.
//
// ctx is the DAEMON context (decision 17); it is passed to Tap.Retain and to
// nothing else — a client disconnect must not strand a ringing inbound call.
func (m *Manager) admitInbound(ctx context.Context, uaHandle Handle, ev UAEvent) Admission {
	if ev.AdmitProbe {
		return m.probeInbound(uaHandle)
	}
	// Resolve the owning session under the registry READ lock and release it
	// before CreateCall, which takes m.mu (write) itself.
	m.mu.RLock()
	u, ok := m.uas[uaHandle]
	var sid string
	if ok {
		sid = u.sid
	}
	m.mu.RUnlock()
	if !ok {
		// The UA was destroyed between the INVITE arriving and this callback
		// running. §6.3: one actor wins; there is no session to admit into.
		return AdmitReject(500, "unknown ua")
	}

	c, err := m.CreateCall(ctx, sid, uaHandle, Inbound, StateRinging) // does its own m.mu + cap check
	if err != nil {
		// Unknown session, or §12.2.2's concurrency caps / §11.4 shutdown denied
		// it. The INVITE is refused with the mapped SIP final (below) rather than
		// left for sipua's ring timeout.
		return admissionRejectFor(err)
	}

	// THE INBOUND CALL-ID CHANNEL. ev.CallID is the far end's Call-ID, and this
	// event is the ONLY place this side ever sees it — an inbound call returns
	// no DialResult. Set BEFORE the handle is observable to any tool call, so
	// call_ladder never races a call whose ladder key is still "".
	c.setDialogIdentity(ev.DialogID, ev.CallID)

	// D76: to_uri is the far end's own request URI (what they dialled to reach
	// us); from_uri is the caller's URI. Recorded on the same statement pair as
	// the dialog identity, from the same event, so call_status, call_list and
	// the N5 log record are never permanently empty on the inbound path.
	c.setURIs(ev.ToURI, ev.FromURI)

	// U18 — RETAIN THE LADDER RING, IMMEDIATELY AFTER THE SETTER RETURNS AND
	// HOLDING NO LOCK. This is the SECOND AND LAST Retain call site in the
	// project; CallDial's goroutine is the other, and the guard, the argument
	// and the lock discipline are deliberately identical to it. setDialogIdentity
	// has returned (call mutex released) and m.mu was released above, so this
	// adds NO edge to §6.3's hierarchy.
	if m.tap != nil && ev.CallID != "" {
		// HIGH-3: key the retention by (ua_handle, call_id). The peer chose
		// ev.CallID verbatim, so uaHandle is what keeps it from colliding with
		// another UA that the same peer handed the same Call-ID.
		m.tap.Retain(ctx, string(uaHandle), ev.CallID)
	}

	// §10.5's two events, in order. incoming_call carries R14's detail; sipua
	// parsed the SDP, session never does.
	c.Append(ev.At, EventIncomingCall, map[string]any{
		"from_uri":       ev.FromURI,
		"to_uri":         ev.ToURI,
		"offered_codecs": ev.OfferedCodecs,
	})
	c.Append(ev.At, EventRinging, nil)

	return AdmitAccept()
}

// admissionRejectFor maps CreateCall's apierr denial to the SIP final status
// sipua sends (Rule 6a D2, FLAT mapping). It classifies via errors.As on the
// apierr.Error.Rule field — there is no IsShuttingDown predicate — because
// checkConcurrencyLocked tags the §11.4 shutdown refusal as
// apierr.ResourceLimit("shutdown", ...) (caps.go). shutdown → 503 Service
// Unavailable; any concurrency cap (max_concurrent_calls_per_session OR
// max_concurrent_calls_total) → 486 Busy Here.
func admissionRejectFor(err error) Admission {
	var ae *apierr.Error
	if errors.As(err, &ae) && ae.Rule == "shutdown" {
		return AdmitReject(503, "Service Unavailable")
	}
	return AdmitReject(486, "Busy Here")
}

// probeInbound answers an OPTIONS request's "would an INVITE be admitted?"
// (RFC 3261 11) with the verdict admitInbound would give, through the same
// checkConcurrencyLocked gate, but creates no call and appends no event. It
// reads under m.mu (read): checkConcurrencyLocked only reads.
func (m *Manager) probeInbound(uaHandle Handle) Admission {
	lim := m.limits()
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.uas[uaHandle]
	if !ok {
		return AdmitReject(500, "unknown ua")
	}
	s, ok := m.sessions[u.sid]
	if !ok || sessionExpiredLocked(s, m.clk.Now()) {
		return admissionRejectFor(apierr.NotFound("unknown session"))
	}
	if err := m.checkConcurrencyLocked(s, lim); err != nil {
		return admissionRejectFor(err)
	}
	return AdmitAccept()
}
