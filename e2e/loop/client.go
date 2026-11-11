package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpClient is the go-sdk streamable-HTTP client bound to the local daemon,
// with the bearer token injected on every request.
type mcpClient struct {
	sess    *sdk.ClientSession
	baseURL string
	bearer  string
}

// bearerRoundTripper stamps Authorization: Bearer <token> onto every request
// the streamable transport makes — the daemon's bearerAuth requires it on /mcp.
type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (b bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// connectClient dials the daemon's /mcp endpoint and completes the MCP
// initialize handshake (which mints the logical session id).
func connectClient(ctx context.Context, endpoint, bearer string) (*mcpClient, error) {
	httpClient := &http.Client{
		Transport: bearerRoundTripper{base: http.DefaultTransport, token: bearer},
	}
	transport := &sdk.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "loop-gate", Version: "0.1.0"}, nil)

	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sess, err := client.Connect(connectCtx, transport, nil)
	if err != nil {
		return nil, err
	}
	return &mcpClient{
		sess:    sess,
		baseURL: strings.TrimSuffix(endpoint, "/mcp"),
		bearer:  bearer,
	}, nil
}

func (c *mcpClient) close() {
	if c != nil && c.sess != nil {
		_ = c.sess.Close()
	}
}

// listToolNames returns the advertised tool names, sorted.
func (c *mcpClient) listToolNames(ctx context.Context) ([]string, error) {
	res, err := c.sess.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names, nil
}

// call invokes an MCP tool and returns the parsed §11 envelope. A tool call
// always succeeds at the protocol level (the daemon returns SIP outcomes as
// ok:true payloads); a transport/protocol failure or an ok:false envelope with
// a non-benign code is surfaced as a Go error so callers can distinguish a
// genuine fault from an expected SIP result.
func (c *mcpClient) call(ctx context.Context, name string, args map[string]any) (map[string]any, error) {
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := c.sess.CallTool(callCtx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, fmt.Errorf("%s: transport error: %w", name, err)
	}
	if len(res.Content) == 0 {
		return nil, fmt.Errorf("%s: empty tool result", name)
	}
	text, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		return nil, fmt.Errorf("%s: unexpected content type %T", name, res.Content[0])
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(text.Text), &env); err != nil {
		return nil, fmt.Errorf("%s: envelope is not JSON: %w (%s)", name, err, text.Text)
	}
	return env, nil
}

// callOK invokes a tool and fails unless the envelope is ok:true. Use it for
// control operations (ua_create, call_answer, call_hangup, ...) whose ok:false
// is always a real fault, never an expected SIP status.
func (c *mcpClient) callOK(ctx context.Context, name string, args map[string]any) (map[string]any, error) {
	env, err := c.call(ctx, name, args)
	if err != nil {
		return nil, err
	}
	if ok, _ := env["ok"].(bool); !ok {
		return nil, fmt.Errorf("%s failed: %s (%s)", name, str(env["code"]), str(env["message"]))
	}
	return env, nil
}

// fetchArtifact resolves a mcp://sipclient/artifacts/{h}/{name} URI to the
// daemon's bearer-authed GET /artifacts/{h}/{name} and returns the body bytes.
func (c *mcpClient) fetchArtifact(ctx context.Context, uri string) ([]byte, error) {
	rel, ok := strings.CutPrefix(uri, "mcp://sipclient/artifacts/")
	if !ok {
		return nil, fmt.Errorf("fetchArtifact: unexpected uri %q", uri)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/artifacts/"+rel, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetchArtifact: GET %s: status %d", req.URL, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// fetchMetrics GETs the daemon's bearer-authed GET /metrics (Task 33, C12)
// and returns the raw Prometheus-text body, following fetchArtifact's exact
// pattern above — /metrics is bearer-guarded like every route but
// GET /healthz (internal/transport/mcp/auth.go).
func (c *mcpClient) fetchMetrics(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/metrics", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetchMetrics: GET %s: status %d", req.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// checkPlumbing proves the MCP-over-HTTP surface end to end without emitting
// any SIP: a UA is created and destroyed, and the P1 tool set is advertised.
//
// IT USED TO CALL profile_list, AND THAT TOOL NO LONGER EXISTS (Phase 1, D1).
// With accounts inline and per-session there is no shared profile registry
// left to enumerate, so the tool was removed rather than deferred. The
// equivalent proof is now a ua_create + ua_destroy round-trip: it exercises
// the same chain the old check did (authenticated MCP request -> session
// binding -> a tool that touches real daemon state -> envelope back) and, as
// a bonus the enumeration never gave, proves the INLINE ACCOUNT PATH itself
// works — the very thing that replaced profiles.
//
// IT STAYS SIP-SILENT. The UA is created in DIRECT mode, which sends nothing
// on creation (register mode would emit a REGISTER to the rig, which -sanity
// exists to avoid); ua_destroy on a direct-mode UA with no calls likewise
// sends nothing.
//
// IT OPENS ITS OWN MCP SESSION AND THROWS IT AWAY, which is not
// fastidiousness — running the round-trip on the gate's own session would
// consume one of its max_uas_per_session slots for no reason.
func checkPlumbing(ctx context.Context, d *daemon, cfg gateConfig) error {
	fmt.Println("\n== MCP-over-HTTP plumbing check ==")

	c, err := connectClient(ctx, d.endpoint, d.bearer)
	if err != nil {
		return fmt.Errorf("connect plumbing-check client: %w", err)
	}
	defer c.close()

	// tools/list runs first, before ua_create/ua_destroy: ua_destroy
	// (multi-UA-per-session wave) tears down only the one handle it creates
	// and leaves the session itself alone, so there is no ordering
	// requirement here today. Kept first anyway, since nothing depends on it
	// running later.
	toolNames, err := c.listToolNames(ctx)
	if err != nil {
		return fmt.Errorf("tools/list: %w", err)
	}
	fmt.Printf("tools/list -> %d tools: %v\n", len(toolNames), toolNames)
	for _, want := range []string{
		"ua_create", "ua_destroy", "ua_status",
		"call_dial", "call_answer", "call_reject", "call_hangup",
		"call_status", "call_list", "call_wait",
	} {
		if !contains(toolNames, want) {
			return fmt.Errorf("tools/list missing expected tool %q", want)
		}
	}
	// profile_list was REMOVED, not deferred: it must not come back.
	if contains(toolNames, "profile_list") {
		return fmt.Errorf("tools/list advertises profile_list, which Phase 1 removed with the profile registry")
	}

	// The inline-account round-trip LAST, for the reason given above.
	args, err := uaCreateArgs("direct", cfg.directP, cfg.asteriskIP, "udp", cfg.localAddr, []string{"PCMU"})
	if err != nil {
		return err
	}
	env, err := c.callOK(ctx, "ua_create", args)
	if err != nil {
		return fmt.Errorf("ua_create (inline account %q): %w", cfg.directP, err)
	}
	handle := str(env["ua_handle"])
	if handle == "" {
		return fmt.Errorf("ua_create returned no ua_handle: %v", env)
	}
	// A credential leak in the response is a hard failure, not a warning —
	// the assertion profile_list used to carry, kept at the boundary that
	// now echoes an account back.
	for _, bad := range []string{"auth_pass", "auth_user"} {
		if _, leaked := env[bad]; leaked {
			return fmt.Errorf("ua_create response echoed %s — credentials must never come back out", bad)
		}
	}
	fmt.Printf("ua_create -> %s (inline account %q, direct mode, no SIP emitted)\n", handle, cfg.directP)

	if _, err := c.callOK(ctx, "ua_destroy", map[string]any{"ua": handle}); err != nil {
		return fmt.Errorf("ua_destroy(%s): %w", handle, err)
	}
	fmt.Printf("ua_destroy -> %s torn down\n", handle)

	fmt.Println("plumbing OK: inline-account ua_create/ua_destroy round-trip, call_*/ua_* tools advertised")
	return nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// num coerces a JSON number to int. Both float64 (encoding/json's default) and
// int are accepted because some payloads round-trip through Go values.
//
// D12 (P4-W2-08, W2): AN ABSENT FIELD AND A GENUINE ZERO ARE INDISTINGUISHABLE
// HERE — both give 0. So `num(m["packets_sent"]) <= 0` fails identically whether
// the stream sent nothing or the field was renamed away, and the failure message
// says "0 packets" either way, which sends the reader after the wrong bug.
//
// WHEN THE DISTINCTION MATTERS, CHECK PRESENCE SEPARATELY:
//
//	v, ok := m["packets_sent"]
//	if !ok {
//	    return false, "quality_get response has no packets_sent field at all"
//	}
//	if num(v) <= 0 { ... }
//
// Not changed to return (int, bool): dozens of call sites across the scenario
// files would each need a second check, for a failure mode that is REPORTED
// wrongly rather than MISSED (the assertion still fails). Documented instead,
// which is what the deferral itself concluded.
func num(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// numf coerces a JSON number (float64) or int to float64.
func numf(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
