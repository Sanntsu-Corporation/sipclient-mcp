package mcp

import (
	"context"
	"log/slog"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// toolFn is the shape locked decision 11 fixes for every tool: a payload and an
// error. No tool sees an http.Request, an mcp type, or the envelope.
type toolFn[In any] func(ctx context.Context, sess string, in In) (any, error)

// toolHandler adapts a toolFn to the SDK's handler signature. THIS IS THE ONLY
// PLACE IN THE TREE THAT NAMES THAT SIGNATURE, so a go-sdk upgrade that changes
// it fails to compile here and nowhere else.
//
// The Go error return is always nil: §11.1's "a SIP failure is a successful
// tool call" and §11.2's error taxonomy both travel in the envelope. Returning
// a Go error would surface as an MCP protocol error, which an agent cannot
// distinguish from a transport fault.
func toolHandler[In any](fn toolFn[In], correlationID func() string, log *slog.Logger) func(context.Context, *sdk.CallToolRequest, In) (*sdk.CallToolResult, any, error) {
	return func(ctx context.Context, req *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
		var sess string
		if req != nil && req.Session != nil {
			sess = req.Session.ID()
		}
		payload, ferr := fn(ctx, sess, in)
		body, merr := marshalEnvelope(payload, ferr, correlationID, log)
		if merr != nil {
			// The envelope itself could not be built: a bug in a tool's payload
			// type. Fall back to the internal envelope rather than a protocol
			// error, so the agent still sees the §11.2 shape.
			id := correlationID()
			log.Error("envelope marshal failed", "correlation_id", id, "err", merr.Error())
			body = []byte(`{"ok":false,"code":"internal","message":"internal error (correlation id ` + id + `)"}`)
		}
		return &sdk.CallToolResult{
			Content: []sdk.Content{&sdk.TextContent{Text: string(body)}},
		}, nil, nil
	}
}

func registerTool[In any](s *Server, name, description string, fn toolFn[In]) {
	sdk.AddTool(s.mcp, &sdk.Tool{Name: name, Description: description},
		toolHandler(fn, s.correlationID, s.cfg.Log))
}

// adminGate wraps an admin-scoped tool (Phase 2 §2.4/§2.4a: config_get,
// config_set, admin_token_rotate) with the identityStore.isAdmin check.
// This is the ONE place that check happens (Rule 18): session.ToolService's
// implementations of these three methods have no way to see which token
// authenticated sess (§6.2's layering keeps identity out of internal/session
// entirely), so the gate belongs here, at registration, rather than being
// threaded into every admin-scoped tool's own body.
//
// A denied call never reaches fn at all — Denied is returned as the tool's
// own §11.2 envelope error, exactly like any other apierr.Error a tool
// returns, so an agent presenting only the bearer token sees the same
// error shape it would from any other policy refusal.
func adminGate[In any](s *Server, fn toolFn[In]) toolFn[In] {
	return func(ctx context.Context, sess string, in In) (any, error) {
		if !s.identity.isAdmin(sess) {
			return nil, apierr.Denied("admin_required", "this tool requires the admin token")
		}
		return fn(ctx, sess, in)
	}
}

// P1Tools is the tool-name set registered at this phase, and it is the set
// §14.6's enumeration test asserts against. See DeferredTools and
// Section10ToolNames for why this is not §10's full list.
var P1Tools = []string{
	"call_answer", "call_dial", "call_events", "call_hangup", "call_ladder",
	"call_list", "call_reject", "call_status", "call_wait",
	"ua_create", "ua_destroy", "ua_status",
}

// P2Tools is the tool-name set the P2 phase adds to P1Tools (Rule 6a-4),
// accumulated across waves as each wire up its own tools — capture_start/
// capture_stop (W2, observability), quality_get (W4, RTP audio + quality). It
// is registered ALONGSIDE P1Tools, not folded into it (Rule 19: P1Tools is not
// renamed).
var P2Tools = []string{"capture_start", "capture_stop", "quality_get", "media_play", "media_record_start", "media_record_stop"}

// P3Tools is the tool-name set the P3 phase adds: DTMF send and the received-
// digit reader. It is registered ALONGSIDE P1Tools and P2Tools, not folded into
// either (Rule 19: neither is renamed), exactly as P2Tools was added alongside
// P1Tools.
var P3Tools = []string{"dtmf_send", "dtmf_received"}

// P4Tools is the tool-name set added alongside P1Tools/P2Tools/P3Tools
// (Rule 19: none of those is renamed) starting with Phase 1's
// session_keepalive. Phase 2 extends this same set with config_get,
// config_set and admin_token_rotate (§2.4a): all three are admin-scoped
// (adminGate above), unlike session_keepalive.
// call_transfer (spec 2026-09-26) is the next net-new tool added here,
// re-scoped out of the master spec's §17 exclusions.
var P4Tools = []string{"session_keepalive", "config_get", "config_set", "admin_token_rotate", "call_transfer"}

// DeferredTools names every §10 tool NOT registered by P1Tools, P2Tools or
// P3Tools, with the phase that delivers it. Registering a tool whose
// implementation does not exist would advertise a capability that can only
// return `internal`, which is worse for an agent than the tool being absent.
//
// dtmf_send and dtmf_received LEFT THIS MAP AT P3 (they were tagged "P3" here
// from P1 onward); session_webhook_set is the last entry.
var DeferredTools = map[string]string{
	"session_webhook_set": "P5",
}

// Section10ToolNames is §10.1-§10.11's tool list, transcribed by hand. It is
// the fixed point the two sets above are checked against.
//
// SPEC AMENDMENT (Phase 1, D1): profile_list is REMOVED, not deferred. With
// accounts inline and per-session (owner-locked decision) there is no shared
// profile registry left to enumerate — a tool that could only ever return
// {"profiles":[]} advertises a capability that does not exist, which is worse
// for an agent than absence. session_keepalive (D2) is ADDED in its place.
//
// SPEC AMENDMENT (Phase 2, §2.4a): config_get, config_set and
// admin_token_rotate are ADDED — three admin-scoped MCP tools generalizing
// policy.yaml into MCP-managed objects (§2 of the Phase 2 design). None of
// these three existed in §10's original numbered sections; they are Phase
// 2's own net-new surface, recorded here the same way session_keepalive was.
//
// SPEC AMENDMENT (2026-09-26, call transfer): call_transfer is ADDED (master
// spec §10.14), re-scoped out of §17's exclusion list by
// the call-transfer and hold design.
var Section10ToolNames = []string{
	"admin_token_rotate",
	"call_answer", "call_dial", "call_events", "call_hangup", "call_ladder",
	"call_list", "call_reject", "call_status", "call_transfer", "call_wait",
	"capture_start", "capture_stop", "config_get", "config_set",
	"dtmf_received", "dtmf_send",
	"media_play", "media_record_start", "media_record_stop",
	"quality_get", "session_keepalive", "session_webhook_set",
	"ua_create", "ua_destroy", "ua_status",
}

// registerTools reads s.cfg.Tools, which NewServer has already validated
// non-nil. It takes no parameter: the Tools implementation is Config's, set
// once at construction, and passing it again would be a second source for one
// value.
//
// This is the real body of the method Task 17 shipped as an empty-bodied
// stub so NewServer and Task 17's own tests could build and pass standalone
// (D202); the stub and its doc comment are deleted from server.go in this
// same commit (D216) rather than left as a duplicate declaration.
func (s *Server) registerTools() {
	t := s.cfg.Tools
	registerTool(s, "ua_create", "Create a UA with inline account fields, optionally registering it against a registrar.", t.UACreate)
	registerTool(s, "session_keepalive", "Reset this session's 5-minute TTL and return its cookie and new expiry.", t.SessionKeepalive)
	registerTool(s, "ua_status", "Report this session's UAs, or one named UA.", t.UAStatus)
	registerTool(s, "ua_destroy",
		"Destroy a UA: BYE every live dialog, then REGISTER Expires: 0 if registered. "+
			"This ALSO ENDS THE CALLING SESSION: the session record is deleted outright, "+
			"so every subsequent tool call on this session fails with not_found until a "+
			"new session is initialized.",
		t.UADestroy)
	registerTool(s, "call_dial", "Place a call. Returns immediately with a handle in state dialing. "+
		"A 300/301/302 redirect is followed to its Contact(s), up to limits.max_redirects new INVITEs (config_get); "+
		"each target passes the same checks as to_uri.", t.CallDial)
	registerTool(s, "call_answer", "Answer a ringing inbound call.", t.CallAnswer)
	registerTool(s, "call_reject", "Reject a ringing inbound call with a chosen final status.", t.CallReject)
	registerTool(s, "call_hangup", "Send BYE in the dialog and terminate the call.", t.CallHangup)
	registerTool(s, "call_transfer",
		"Transfer an answered call via SIP REFER. mode \"blind\" needs target (a sip: URI); "+
			"mode \"attended\" needs consult_call (an answered call on the same UA to replace). "+
			"Returns the REFER's own response; the outcome arrives as \"transfer\" events "+
			"(call_wait until=\"transfer\"). If the transferee's BYE ends the call before the "+
			"transfer's final NOTIFY arrives, a call_wait(until=\"transfer\") waiter wakes with the "+
			"terminal event instead — fall back to call_events to find the transfer outcome in that case. "+
			"Never hangs up either call itself.",
		t.CallTransfer)
	registerTool(s, "call_status", "Full status for one call.", t.CallStatus)
	registerTool(s, "call_list", "This session's calls only.", t.CallList)
	registerTool(s, "call_wait",
		"Block until a matching event is appended after `since`, or until timeout_ms. "+
			"`since` defaults to 0 (matches from the start of the log); pass the `seq` from a prior "+
			"call_wait/call_events response to wait for the NEXT new matching event. The only blocking tool.",
		t.CallWait)
	registerTool(s, "call_events", "Drain a call's ordered event log from `since`.", t.CallEvents)
	registerTool(s, "call_ladder", "Render the call's SIP ladder as text, mermaid or json.", t.CallLadder)
	registerTool(s, "capture_start", "Arm a per-call pcap capture (signaling only this wave); scope defaults to signaling, payload_mode to plaintext.", t.CaptureStart)
	registerTool(s, "capture_stop", "Disarm the call's capture and finalize its pcap artifact, reporting bytes, packets, truncation and the artifact URI.", t.CaptureStop)
	registerTool(s, "quality_get", "Tier-1 passive voice-quality metrics and E-model MOS estimate for an answered call.", t.QualityGet)
	registerTool(s, "media_play", "Play a policy-registered prompt into the call's TX audio; prompt is a name, never a path.", t.MediaPlay)
	registerTool(s, "media_record_start", "Start recording the call's received audio to a WAV artifact.", t.MediaRecordStart)
	registerTool(s, "media_record_stop", "Stop the active recording and finalize its WAV artifact (8000/mono/16-bit).", t.MediaRecordStop)
	registerTool(s, "dtmf_send", "Send DTMF digits on an answered call; mode is \"rfc2833\", \"inband\" or \"info\" and defaults to the UA profile's.", t.DTMFSend)
	registerTool(s, "dtmf_received", "Drain the digits received on a call from `since`; answerable after the call has ended.", t.DTMFReceived)
	registerTool(s, "config_get", "Admin-scoped: return the current policy configuration (secrets never included; auth.*_token_file are file paths, not token values).", adminGate(s, t.ConfigGet))
	registerTool(s, "config_set", "Admin-scoped: set one policy key (a curated set — see the daemon's docs). artifact.dir cannot be changed at runtime; set it in the state file and restart.", adminGate(s, t.ConfigSet))
	registerTool(s, "admin_token_rotate",
		"Admin-scoped: generate and install a fresh admin token, returned once in this call's response. "+
			"The calling session keeps working and is automatically re-bound to the new token; "+
			"present the NEW token on every subsequent request, including this session's.",
		adminGate(s, rebindAfterRotate(s, t.AdminTokenRotate)))
}

// rebindAfterRotate is SEC-2's fix: after a SUCCESSFUL admin_token_rotate,
// repoint the CALLING session's §12.6 binding at the token that call just
// minted.
//
// THE BUG IT CLOSES. identityStore.bind recorded sha256(old token) at
// initialize. A rotation left that binding alone, so the caller's next tool
// call had no working credential at all: the old token is now rejected by
// bearerAuth (the digest was recomputed from the rotated file), and the new
// token authenticates but does not match the binding, so resolve() treats the
// id as unknown and the request 404s — an admin's reward for rotating was an
// unexplained dead session.
//
// OPTION (a), NOT (b). Documenting "you must re-initialize" would have been
// smaller, but it leaves a correct, successful admin call returning a state
// its own caller cannot act on, and every future client would have to learn
// that by hitting the 404 once. Re-binding costs one map write on one id and
// makes the tool behave the way its response already implies. The registered
// description above still spells out that the new token is what to present
// from now on, which is the half of option (b) that was worth keeping.
//
// IT WRAPS RATHER THAN LIVES IN session.ToolService BECAUSE IT HAS TO:
// internal/session cannot see identity at all (§6.2's layering — it does not
// know WHICH token authenticated a caller, which is the same reason adminGate
// lives here). The new token is read out of the tool's own response, which is
// the only place it exists; a failed rotation returns an error and no
// payload, so nothing is re-bound.
func rebindAfterRotate[In any](s *Server, fn toolFn[In]) toolFn[In] {
	return func(ctx context.Context, sess string, in In) (any, error) {
		payload, err := fn(ctx, sess, in)
		if err != nil {
			return payload, err
		}
		if m, ok := payload.(map[string]any); ok {
			if tok, ok := m["admin_token"].(string); ok && tok != "" {
				s.identity.rebind(sess, []byte(tok))
			}
		}
		return payload, nil
	}
}
