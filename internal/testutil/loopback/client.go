package loopback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// sessionIDHeader mirrors internal/transport/mcp's unexported sessionIDHeader
// constant ("Mcp-Session-Id"). It cannot be imported — the real one is
// package-private — so it is restated here as the one place this package
// names the wire header.
const sessionIDHeader = "Mcp-Session-Id"

// rpcClient is the raw JSON-RPC-over-HTTP client this package speaks with,
// shared by Harness and Session. It is hand-rolled rather than built on the
// SDK's own client transport because several callers here need control the
// SDK client does not expose: presenting a CALLER-CHOSEN session id (§12.6
// Reconnect/foreign-session tests), reading raw undecoded bytes and status
// codes (AdminDeleteRaw, Initialize's both-halves-of-the-unknown-id rule),
// and a fresh JSON-RPC id per call (D211) under caller control.
type rpcClient struct {
	baseURL string
	hc      *http.Client
	nextID  atomic.Int64
}

func newRPCClient(baseURL string) *rpcClient {
	return &rpcClient{baseURL: baseURL, hc: &http.Client{}}
}

// jsonrpcResponse is the single-response shape this client decodes — either
// delivered as a bare application/json body, or as one "data:" frame of a
// text/event-stream body (the SDK picks between the two; a single
// request/response exchange with no server push is not required to stream).
type jsonrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *jsonrpcError   `json:"error"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rawPost issues one JSON-RPC POST and returns the raw response: HTTP status,
// the Mcp-Session-Id response header, and the decoded body (nil if the HTTP
// status was not 200, since the SDK writes no JSON-RPC envelope on a
// transport-level rejection such as a 401 or a 404).
//
// D211: every call mints a UNIQUE id via c.nextID — the SDK multiplexes
// concurrent POSTs sharing one Mcp-Session-Id and correlates by id, so a
// repeated literal id hangs the loser.
func (c *rpcClient) rawPost(ctx context.Context, token, sessionID, method string, params any) (
	status int, respSessionID string, body []byte, err error,
) {
	id := c.nextID.Add(1)
	reqBody := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		reqBody["params"] = params
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return 0, "", nil, fmt.Errorf("loopback: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/mcp", bytes.NewReader(b))
	if err != nil {
		return 0, "", nil, fmt.Errorf("loopback: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set(sessionIDHeader, sessionID)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("loopback: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header.Get(sessionIDHeader), nil, fmt.Errorf("loopback: read body: %w", err)
	}
	return resp.StatusCode, resp.Header.Get(sessionIDHeader), out, nil
}

// call performs a full JSON-RPC round trip and returns the decoded result, or
// an error if the transport, JSON-RPC or HTTP layer reports one.
func (c *rpcClient) call(ctx context.Context, token, sessionID, method string, params any) (
	json.RawMessage, string, error,
) {
	status, respSessionID, body, err := c.rawPost(ctx, token, sessionID, method, params)
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK {
		return nil, respSessionID, fmt.Errorf("loopback: %s: HTTP %d: %s", method, status, string(body))
	}
	rpcResp, err := decodeJSONRPCFrame(resp2ContentType(body), body)
	if err != nil {
		return nil, respSessionID, fmt.Errorf("loopback: %s: %w", method, err)
	}
	if rpcResp.Error != nil {
		return nil, respSessionID, fmt.Errorf("loopback: %s: jsonrpc error %d: %s",
			method, rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, respSessionID, nil
}

// resp2ContentType sniffs whether body looks like an SSE frame stream
// ("event:"/"data:" lines) rather than a bare JSON object, without needing
// the response's Content-Type header at this call site (rawPost already
// discarded it; sniffing the body is equivalent and keeps the signature
// simple, since both shapes are unambiguous from their first non-space
// byte).
func resp2ContentType(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return "application/json"
	}
	return "text/event-stream"
}

// decodeJSONRPCFrame decodes either a bare JSON-RPC response object, or the
// first "data: " frame of an SSE stream carrying one.
func decodeJSONRPCFrame(contentType string, body []byte) (jsonrpcResponse, error) {
	if contentType == "application/json" {
		var r jsonrpcResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return jsonrpcResponse{}, fmt.Errorf("decode JSON-RPC response: %w (body: %s)", err, body)
		}
		return r, nil
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		var r jsonrpcResponse
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &r); err != nil {
			continue
		}
		return r, nil
	}
	return jsonrpcResponse{}, fmt.Errorf("no JSON-RPC frame found in SSE body: %s", body)
}

// callToolResult is the MCP CallToolResult shape this client decodes: one
// TextContent item carrying the §11 JSON envelope as its Text.
type callToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

// callTool performs tools/call and decodes the §11 envelope, reconstructing
// an *apierr.Error from an ok:false envelope so ErrorCode/ErrorRule/
// ErrorLimits work on the returned error exactly as they do on a live
// apierr.Error from in-process code.
func (c *rpcClient) callTool(ctx context.Context, token, sessionID, name string, args map[string]any) (
	map[string]any, string, error,
) {
	if args == nil {
		args = map[string]any{}
	}
	result, respSessionID, err := c.call(ctx, token, sessionID, "tools/call",
		map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, respSessionID, err
	}
	var ctr callToolResult
	if err := json.Unmarshal(result, &ctr); err != nil {
		return nil, respSessionID, fmt.Errorf("loopback: %s: decode CallToolResult: %w (result: %s)", name, err, result)
	}
	if len(ctr.Content) != 1 || ctr.Content[0].Type != "text" {
		return nil, respSessionID, fmt.Errorf("loopback: %s: CallToolResult.Content = %+v, want one text item",
			name, ctr.Content)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(ctr.Content[0].Text), &env); err != nil {
		return nil, respSessionID, fmt.Errorf("loopback: %s: envelope is not JSON: %w (%s)",
			name, err, ctr.Content[0].Text)
	}
	if ok, _ := env["ok"].(bool); !ok {
		return env, respSessionID, envelopeToAPIErr(env)
	}
	return env, respSessionID, nil
}

// envelopeToAPIErr rebuilds an *apierr.Error from an ok:false §11 envelope,
// so a caller across this HTTP boundary can use ErrorCode/ErrorRule/
// ErrorLimits exactly as in-process session code does.
func envelopeToAPIErr(env map[string]any) error {
	e := &apierr.Error{Code: apierr.Code(strVal(env, "code")), Message: strVal(env, "message"), Rule: strVal(env, "rule")}
	if v, ok := env["limit"]; ok {
		if n, ok := v.(float64); ok {
			i := int(n)
			e.Limit = &i
		}
	}
	if v, ok := env["current"]; ok {
		if n, ok := v.(float64); ok {
			i := int(n)
			e.Current = &i
		}
	}
	if d, ok := env["detail"].(map[string]any); ok {
		e.Detail = d
	}
	return e
}

func strVal(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// ErrorCode reads err's apierr code, or "" if err is nil or not an
// *apierr.Error — including a success WaitResult's nil Err, so
// `ErrorCodeOf(res) != "resource_limit"` is a valid assertion on a success
// too.
func ErrorCode(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return string(ae.Code)
	}
	return ""
}

// ErrorRule reads err's apierr rule, or "" if err is nil or carries none.
func ErrorRule(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae.Rule
	}
	return ""
}

// ErrorLimits reads err's apierr Limit/Current pair, or (0, 0) if err is nil,
// not an *apierr.Error, or not limit-shaped.
func ErrorLimits(err error) (limit, current int) {
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		return 0, 0
	}
	if ae.Limit != nil {
		limit = *ae.Limit
	}
	if ae.Current != nil {
		current = *ae.Current
	}
	return limit, current
}

// ---- Harness tool-call surface ---------------------------------------------

// CallTool calls a tool on the harness's own session, using
// context.Background().
func (h *Harness) CallTool(name string, args map[string]any) (map[string]any, error) {
	return h.CallToolCtx(context.Background(), name, args)
}

// CallToolCtx calls a tool on the harness's own session under ctx. D211: a
// fresh JSON-RPC id per call, minted by h.rpc.
func (h *Harness) CallToolCtx(ctx context.Context, name string, args map[string]any) (map[string]any, error) {
	env, _, err := h.rpc.callTool(ctx, testBearer, h.sessionID, name, args)
	return env, err
}

// MustCallTool calls a tool and fails the test on any error, returning the
// decoded ok:true envelope.
func (h *Harness) MustCallTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	env, err := h.CallTool(name, args)
	if err != nil {
		t.Fatalf("loopback: %s: %v", name, err)
	}
	return env
}

// RawToolCall issues one tools/call and returns the raw, undecoded HTTP
// status and body — for assertions that must be statements about the WIRE
// (e.g. Part 4.3's R11 isolation clause: "no admin response body contains a
// call_handle"), not about a decoded Go value.
func (h *Harness) RawToolCall(ctx context.Context, name string, args map[string]any) (status int, body string) {
	if args == nil {
		args = map[string]any{}
	}
	st, _, b, err := h.rpc.rawPost(ctx, testBearer, h.sessionID, "tools/call",
		map[string]any{"name": name, "arguments": args})
	if err != nil {
		return 0, err.Error()
	}
	return st, string(b)
}

// RawToolCallAs is RawToolCall's arbitrary-identity twin (D349): RawToolCall
// hardcodes testBearer and h.sessionID, so it cannot present the
// caller-chosen id/token pair §12.6's wire half needs (a foreign id, a wrong
// token, a fabricated id, an absent id). h.rpc.rawPost already takes both
// parameters, so this is a thin pass-through — RawToolCall itself is left
// untouched (Rule 16 backward-compat).
func (h *Harness) RawToolCallAs(t *testing.T, sessionID, token, name string, args map[string]any) (status int, body string) {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	st, _, b, err := h.rpc.rawPost(context.Background(), token, sessionID, "tools/call",
		map[string]any{"name": name, "arguments": args})
	if err != nil {
		return 0, err.Error()
	}
	return st, string(b)
}

// ToolCallAs calls name and decodes its ok:true envelope into a T, failing
// the test on any tool error or decode failure.
func ToolCallAs[T any](h *Harness, t *testing.T, name string, args map[string]any) T {
	t.Helper()
	env := h.MustCallTool(t, name, args)
	return decodeInto[T](t, env)
}

func decodeInto[T any](t *testing.T, v any) T {
	t.Helper()
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("loopback: re-marshal for decode: %v", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("loopback: decode into %T: %v (from %s)", out, err, b)
	}
	return out
}

// InitializeResult is one raw `initialize` exchange (§12.6): the HTTP status
// and the Mcp-Session-Id the server issued.
type InitializeResult struct {
	Status    int
	SessionID string
}

// Initialize performs a raw `initialize` request, presenting presentedID (the
// empty string for none) and token, and reports the resulting status and
// issued session id — both halves of §12.6's unknown-id rule are assertable
// on this.
func (h *Harness) Initialize(t *testing.T, presentedID, token string) InitializeResult {
	t.Helper()
	status, sessionID, _, err := h.rpc.rawPost(context.Background(), token, presentedID, "initialize",
		map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "loopback", "version": "0"},
		})
	if err != nil {
		t.Fatalf("loopback: initialize: %v", err)
	}
	return InitializeResult{Status: status, SessionID: sessionID}
}

// ---- plain HTTP helpers ----------------------------------------------------

// GetAuthed issues a bearer-authenticated GET against the harness's own
// server and returns the status and body.
func (h *Harness) GetAuthed(t *testing.T, path, token string) (int, string) {
	t.Helper()
	return h.rawGet(t, path, token)
}

// GetRaw issues an UNAUTHENTICATED GET (for /healthz, N4's single exemption).
func (h *Harness) GetRaw(t *testing.T, path string) (int, string) {
	t.Helper()
	return h.rawGet(t, path, "")
}

func (h *Harness) rawGet(t *testing.T, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("loopback: build GET %s: %v", path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.rpc.hc.Do(req)
	if err != nil {
		t.Fatalf("loopback: GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("loopback: read GET %s body: %v", path, err)
	}
	return resp.StatusCode, string(b)
}

// ---- admin plane ------------------------------------------------------------

type adminUAsResponse struct {
	UAs         []session.AdminUAView `json:"uas"`
	Count       int                   `json:"count"`
	MaxUAsTotal int                   `json:"max_uas_total"`
}

// AdminDelete issues DELETE /admin/uas/{uaHandle} with the harness's own
// admin token and returns the decoded body and any error.
func (h *Harness) AdminDelete(uaHandle string) (session.AdminDestroyed, error) {
	status, body := h.rawAdminDelete(h.t, uaHandle, h.opts.adminToken)
	if status != http.StatusOK {
		return session.AdminDestroyed{}, fmt.Errorf("loopback: admin delete %s: HTTP %d: %s", uaHandle, status, body)
	}
	var out session.AdminDestroyed
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return session.AdminDestroyed{}, fmt.Errorf("loopback: admin delete %s: decode: %w", uaHandle, err)
	}
	return out, nil
}

// AdminDeleteCtx is AdminDelete under an explicit context, for cancellation
// tests.
func (h *Harness) AdminDeleteCtx(ctx context.Context, uaHandle string) (session.AdminDestroyed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, h.srv.URL+"/admin/uas/"+uaHandle, nil)
	if err != nil {
		return session.AdminDestroyed{}, err
	}
	req.Header.Set("Authorization", "Bearer "+h.opts.adminToken)
	resp, err := h.rpc.hc.Do(req)
	if err != nil {
		return session.AdminDestroyed{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return session.AdminDestroyed{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return session.AdminDestroyed{}, fmt.Errorf("loopback: admin delete %s: HTTP %d: %s", uaHandle, resp.StatusCode, b)
	}
	var out session.AdminDestroyed
	if err := json.Unmarshal(b, &out); err != nil {
		return session.AdminDestroyed{}, err
	}
	return out, nil
}

// MustAdminDelete fails the test instead of returning an error.
func (h *Harness) MustAdminDelete(t *testing.T, uaHandle string) session.AdminDestroyed {
	t.Helper()
	out, err := h.AdminDelete(uaHandle)
	if err != nil {
		t.Fatalf("loopback: %v", err)
	}
	return out
}

// AdminDeleteRaw returns the UNDECODED status and body — for §12.7's
// no-call_handle wire assertion.
func (h *Harness) AdminDeleteRaw(t *testing.T, uaHandle string) (status int, body string) {
	t.Helper()
	return h.rawAdminDelete(t, uaHandle, h.opts.adminToken)
}

func (h *Harness) rawAdminDelete(t *testing.T, uaHandle, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, h.srv.URL+"/admin/uas/"+uaHandle, nil)
	if err != nil {
		t.Fatalf("loopback: build admin delete: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.rpc.hc.Do(req)
	if err != nil {
		t.Fatalf("loopback: admin delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("loopback: read admin delete body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// MustAdminListUAs decodes GET /admin/uas with the harness's own admin
// token.
func (h *Harness) MustAdminListUAs(t *testing.T) []session.AdminUAView {
	t.Helper()
	status, body := h.rawGet(t, "/admin/uas", h.opts.adminToken)
	if status != http.StatusOK {
		t.Fatalf("loopback: admin list UAs: HTTP %d: %s", status, body)
	}
	var out adminUAsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("loopback: admin list UAs: decode: %v", err)
	}
	return out.UAs
}

// AdminListUAsRaw returns the UNDECODED body of GET /admin/uas.
func (h *Harness) AdminListUAsRaw(t *testing.T) string {
	t.Helper()
	_, body := h.rawGet(t, "/admin/uas", h.opts.adminToken)
	return body
}
