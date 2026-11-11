package loopback

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestCallWaitCancelledViaMCPNotification is spec §11.2's `cancelled` code
// acceptance (D360/D361): a call_wait parked on a call, cancelled by an
// explicit MCP `notifications/cancelled` naming its own JSON-RPC request id,
// returns `code:"cancelled"` — not `internal` — on the STILL-OPEN first
// connection, and is NOT logged as an internal server error.
//
// This is package loopback (white-box), not loopback_test, because it needs
// direct control of the JSON-RPC request id to name in the cancellation
// notification's requestId — something CallWaitCtx's automatic id minting
// does not expose.
//
// Technique reused from Task 29's D360 probe: park call_wait on one HTTP
// connection, then send notifications/cancelled on a SECOND connection while
// the first stays open. §12.6 session identity is server-side, not
// connection-based, so both requests carry the SAME Mcp-Session-Id.
func TestCallWaitCancelledViaMCPNotification(t *testing.T) {
	h := New(t)
	defer h.Close()
	c := h.MustDialAnswered(t)

	// D211: mint this call's own JSON-RPC id from the harness's shared
	// counter, exactly as h.rpc.callTool does, so it cannot collide with any
	// other in-flight request.
	reqID := h.rpc.nextID.Add(1)
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "call_wait",
			"arguments": map[string]any{"call": c, "until": "terminated", "timeout_ms": 300000},
		},
	})
	if err != nil {
		t.Fatalf("marshal call_wait request: %v", err)
	}

	type waitResp struct {
		status int
		body   []byte
		err    error
	}
	respCh := make(chan waitResp, 1)
	firstConn := &http.Client{}
	go func() {
		req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", bytes.NewReader(reqBody))
		if err != nil {
			respCh <- waitResp{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+testBearer)
		req.Header.Set(sessionIDHeader, h.sessionID)
		resp, err := firstConn.Do(req)
		if err != nil {
			respCh <- waitResp{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, rerr := io.ReadAll(resp.Body)
		respCh <- waitResp{status: resp.StatusCode, body: b, err: rerr}
	}()

	h.WaitForWaiterCount(t, c, 1, 5*time.Second)

	// SECOND connection: a fresh http.Client sending notifications/cancelled
	// naming the parked call_wait's own request id, on the SAME MCP session,
	// while the first connection stays open and parked.
	cancelBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/cancelled",
		"params":  map[string]any{"requestId": reqID},
	})
	if err != nil {
		t.Fatalf("marshal cancellation notification: %v", err)
	}
	cancelReq, err := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", bytes.NewReader(cancelBody))
	if err != nil {
		t.Fatalf("build cancellation request: %v", err)
	}
	cancelReq.Header.Set("Content-Type", "application/json")
	cancelReq.Header.Set("Accept", "application/json, text/event-stream")
	cancelReq.Header.Set("Authorization", "Bearer "+testBearer)
	cancelReq.Header.Set(sessionIDHeader, h.sessionID)
	secondConn := &http.Client{}
	cancelResp, err := secondConn.Do(cancelReq)
	if err != nil {
		t.Fatalf("send cancellation notification: %v", err)
	}
	_ = cancelResp.Body.Close()

	var wr waitResp
	select {
	case wr = <-respCh:
	case <-time.After(5 * time.Second):
		t.Fatal("call_wait did not return after notifications/cancelled")
	}
	if wr.err != nil {
		t.Fatalf("call_wait request: %v", wr.err)
	}
	if wr.status != http.StatusOK {
		t.Fatalf("call_wait HTTP status = %d, want 200: %s", wr.status, wr.body)
	}

	rpcResp, err := decodeJSONRPCFrame(resp2ContentType(wr.body), wr.body)
	if err != nil {
		t.Fatalf("decode call_wait response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("call_wait returned a JSON-RPC error: %d %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	var ctr callToolResult
	if err := json.Unmarshal(rpcResp.Result, &ctr); err != nil {
		t.Fatalf("decode CallToolResult: %v (%s)", err, rpcResp.Result)
	}
	if len(ctr.Content) != 1 || ctr.Content[0].Type != "text" {
		t.Fatalf("CallToolResult.Content = %+v, want one text item", ctr.Content)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(ctr.Content[0].Text), &env); err != nil {
		t.Fatalf("envelope is not JSON: %v (%s)", err, ctr.Content[0].Text)
	}

	if ok, _ := env["ok"].(bool); ok {
		t.Fatalf("envelope ok = true, want false: %+v", env)
	}
	if code, _ := env["code"].(string); code != "cancelled" {
		t.Fatalf("envelope code = %q, want %q: %+v", code, "cancelled", env)
	}

	// It must NOT be logged as an internal server error — a cancelling agent
	// did the right thing.
	if h.LogHasEvent("tool returned a non-apierr error") {
		t.Fatalf("cancelled call_wait was logged as an internal server error:\n%s", h.RawLog())
	}
}
