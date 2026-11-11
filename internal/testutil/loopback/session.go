package loopback

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// Session is ONE logical session (§12.6) against the harness's server: its
// server-issued 128-bit id, its bearer token and its own HTTP client. Task
// 23's and Task 24's suites use several per harness, because R11 isolation
// and §12.7's before-and-after-DELETE clause are only assertable between two
// DIFFERENT live sessions. NewSession performs a real `initialize`, so each
// one holds an id the server actually issued.
type Session struct {
	h     *Harness
	id    string
	token string
	rpc   *rpcClient
}

// NewSession performs a real `initialize` against the harness's server,
// using the SAME bearer token every harness session authenticates with, and
// returns a Session holding the id the server actually issued.
func (h *Harness) NewSession(t *testing.T) *Session {
	t.Helper()
	rpc := newRPCClient(h.srv.URL)
	status, sessionID, _, err := rpc.rawPost(context.Background(), testBearer, "", "initialize",
		map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "loopback-session", "version": "0"},
		})
	if err != nil {
		t.Fatalf("loopback: NewSession: initialize: %v", err)
	}
	if status != http.StatusOK || sessionID == "" {
		t.Fatalf("loopback: NewSession: initialize status=%d session=%q", status, sessionID)
	}
	return &Session{h: h, id: sessionID, token: testBearer, rpc: rpc}
}

// ID is the server-issued §12.6 session id.
func (s *Session) ID() string { return s.id }

// CallTool calls a tool on this session, under context.Background().
func (s *Session) CallTool(name string, args map[string]any) (map[string]any, error) {
	env, _, err := s.rpc.callTool(context.Background(), s.token, s.id, name, args)
	return env, err
}

// MustCallTool fails the test on any error.
func (s *Session) MustCallTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	env, err := s.CallTool(name, args)
	if err != nil {
		t.Fatalf("loopback: session %s: %s: %v", s.id, name, err)
	}
	return env
}

// Dial dials toURI from ua on this session, returning the call handle.
func (s *Session) Dial(uaHandle, toURI string) (string, error) {
	env, err := s.CallTool("call_dial", map[string]any{"ua": uaHandle, "to_uri": toURI})
	if err != nil {
		return "", err
	}
	handle, _ := env["call_handle"].(string)
	s.h.rememberHandle(handle, s.id)
	return handle, nil
}

// MustDial fails the test on any error.
func (s *Session) MustDial(t *testing.T, uaHandle, toURI string) string {
	t.Helper()
	c, err := s.Dial(uaHandle, toURI)
	if err != nil {
		t.Fatalf("loopback: session %s: call_dial: %v", s.id, err)
	}
	return c
}

// MustCreateUA creates a "direct" mode UA on this session.
func (s *Session) MustCreateUA(t *testing.T, mode string) string {
	t.Helper()
	env := s.MustCallTool(t, "ua_create", map[string]any{"mode": mode, "transport": s.h.opts.transport})
	handle, _ := env["ua_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: session %s: ua_create returned no ua_handle: %+v", s.id, env)
	}
	s.h.rememberHandle(handle, s.id)
	return handle
}

// MustCreateUAWithAccount creates a "register" mode UA on this session
// against the named Account fixture (see WithAccounts/TestAccount), the
// Session counterpart of (*Harness).MustCreateUAWithAccount.
func (s *Session) MustCreateUAWithAccount(t *testing.T, name string) string {
	t.Helper()
	env := s.MustCallTool(t, "ua_create", s.h.UACreateArgsForAccount(t, name))
	handle, _ := env["ua_handle"].(string)
	if handle == "" {
		t.Fatalf("loopback: session %s: ua_create returned no ua_handle: %+v", s.id, env)
	}
	s.h.rememberHandle(handle, s.id)
	return handle
}

// MustDialAnswered creates a fresh "direct" UA on this session and dials the
// harness's own peer, waiting for `answered`, mirroring
// (*Harness).MustDialAnswered on this session's own id/token.
func (s *Session) MustDialAnswered(t *testing.T) string {
	t.Helper()
	ua := s.MustCreateUA(t, "direct")
	return s.MustDialAnsweredOn(t, ua)
}

// MustDialAnsweredOn dials on a caller-supplied ua and waits for `answered`.
func (s *Session) MustDialAnsweredOn(t *testing.T, uaHandle string) string {
	t.Helper()
	c := s.MustDial(t, uaHandle, s.h.PeerURI())
	s.MustWait(t, c, "answered", 5000)
	return c
}

// MustHangup hangs c up and fails the test on any error, mirroring
// (*Harness).MustHangup on this session's own id/token.
func (s *Session) MustHangup(t *testing.T, c string) {
	t.Helper()
	s.MustCallTool(t, "call_hangup", map[string]any{"call": c})
}

// CallList lists this session's own calls (R11 isolation).
func (s *Session) CallList() ([]CallListEntry, error) {
	env, err := s.CallTool("call_list", nil)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(env["calls"])
	var out []CallListEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MustCallList is CallList's asserted twin, failing the test on any tool
// error, mirroring (*Harness).MustCallList on this session's own id/token.
func (s *Session) MustCallList(t *testing.T) []CallListEntry {
	t.Helper()
	env := s.MustCallTool(t, "call_list", nil)
	return decodeCallList(t, env)
}

// MustWaitForInboundCall polls call_list, bounded by d, for a call handle not
// already known to this harness, mirroring (*Harness).MustWaitForInboundCall
// on this session's own id/token — the discovered handle is registered as
// OWNED BY THIS SESSION, not the harness's own.
func (s *Session) MustWaitForInboundCall(t *testing.T, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		for _, c := range s.MustCallList(t) {
			s.h.handleMu.Lock()
			_, known := s.h.handleOwner[c.CallHandle]
			s.h.handleMu.Unlock()
			if !known {
				s.h.rememberHandle(c.CallHandle, s.id)
				return c.CallHandle
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("loopback: session %s: MustWaitForInboundCall: no new inbound call within %s", s.id, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// MustCallStatus fails the test on any tool error, mirroring
// (*Harness).MustCallStatus on this session's own id/token.
func (s *Session) MustCallStatus(t *testing.T, callHandle string) CallStatus {
	t.Helper()
	env := s.MustCallTool(t, "call_status", map[string]any{"call": callHandle})
	return decodeCallStatus(t, env)
}

// MustCallEvents fails the test on any tool error and returns the decoded
// event log, mirroring (*Harness).MustCallEvents on this session's own
// id/token.
func (s *Session) MustCallEvents(t *testing.T, callHandle string, since int64) []session.Event {
	t.Helper()
	env := s.MustCallTool(t, "call_events", map[string]any{"call": callHandle, "since": since})
	b, _ := json.Marshal(env["events"])
	var out []session.Event
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("loopback: session %s: decode call_events: %v", s.id, err)
	}
	return out
}

// MustUAStatus fails the test on any tool error, mirroring
// (*Harness).MustUAStatus on this session's own id/token: LocalAddr is
// resolved separately, from the harness's own session.Manager, using THIS
// session's id (not h.sessionID) so a UA minted on a sub-session resolves
// correctly.
func (s *Session) MustUAStatus(t *testing.T, uaHandle string) CallStatus {
	t.Helper()
	env := s.MustCallTool(t, "ua_status", map[string]any{"ua": uaHandle})
	uas, _ := env["uas"].([]any)
	if len(uas) == 0 {
		t.Fatalf("loopback: session %s: ua_status(%s) returned no UAs: %+v", s.id, uaHandle, env)
	}
	u, _ := uas[0].(map[string]any)
	registered, _ := u["registered"].(bool)

	cs := CallStatus{Registered: registered}
	ua, err := s.h.mgr.ResolveUA(context.Background(), s.id, session.Handle(uaHandle))
	if err != nil {
		t.Fatalf("loopback: session %s: MustUAStatus: resolve %s: %v", s.id, uaHandle, err)
	}
	cs.LocalAddr = ua.Agent().LocalAddr().String()
	return cs
}

// CallWait calls call_wait on this session under context.Background(),
// decoding both §10.5 shapes.
func (s *Session) CallWait(callHandle, until string, timeoutMs int) WaitResult {
	return s.CallWaitCtx(context.Background(), callHandle, until, timeoutMs)
}

// CallWaitCtx calls call_wait on this session under ctx — Task 23's two
// call sites that need to cancel a parked wait mid-flight (§6.3 rule 4) use
// this rather than CallWait.
func (s *Session) CallWaitCtx(ctx context.Context, callHandle, until string, timeoutMs int) WaitResult {
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond+5*time.Second)
	defer cancel()
	env, _, err := s.rpc.callTool(callCtx, s.token, s.id, "call_wait",
		map[string]any{"call": callHandle, "until": until, "timeout_ms": timeoutMs})
	return decodeWaitResult(env, err)
}

// MustWait fails the test unless the matching event arrived.
func (s *Session) MustWait(t *testing.T, callHandle, until string, timeoutMs int) WaitResult {
	t.Helper()
	res := s.CallWait(callHandle, until, timeoutMs)
	if res.Err != nil {
		t.Fatalf("loopback: session %s: call_wait(%s, %s): %v", s.id, callHandle, until, res.Err)
	}
	if res.TimedOut {
		t.Fatalf("loopback: session %s: call_wait(%s, %s) timed out after %dms",
			s.id, callHandle, until, timeoutMs)
	}
	return res
}

// WaiterCount wraps (*session.Manager).SessionWaiterCount(s.id).
func (s *Session) WaiterCount() int64 { return s.h.mgr.SessionWaiterCount(s.id) }

// CloseConnection drops the transport (forces a fresh TCP connection on the
// next request) while keeping the logical session: §12.6's identity is
// server-side, not connection-based.
func (s *Session) CloseConnection(t *testing.T) {
	t.Helper()
	s.rpc.hc.CloseIdleConnections()
}

// ReconnectErr is Reconnect's error-returning twin: it drops the transport
// and then verifies the SAME session id (§12.6 resumption) is still live by
// issuing one request over the fresh connection.
func (s *Session) ReconnectErr() error {
	s.rpc.hc.CloseIdleConnections()
	_, _, err := s.rpc.call(context.Background(), s.token, s.id, "tools/list", nil)
	return err
}

// Reconnect fails the test on any error.
func (s *Session) Reconnect(t *testing.T) {
	t.Helper()
	if err := s.ReconnectErr(); err != nil {
		t.Fatalf("loopback: session %s: Reconnect: %v", s.id, err)
	}
}

// AbandonSessionID represents the agent crashing: the id is gone forever.
// Deliberately a no-op beyond documenting intent — an abandoned session sends
// no DELETE and makes no further request; §12.6's server-side retention is
// exercised by simply never calling this Session again.
func (s *Session) AbandonSessionID(t *testing.T) {
	t.Helper()
}

// Close actively terminates the session with an MCP DELETE, failing the test
// on any error.
func (s *Session) Close(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, s.h.srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("loopback: session %s: build DELETE: %v", s.id, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set(sessionIDHeader, s.id)
	resp, err := s.rpc.hc.Do(req)
	if err != nil {
		t.Fatalf("loopback: session %s: DELETE /mcp: %v", s.id, err)
	}
	_ = resp.Body.Close()
}
