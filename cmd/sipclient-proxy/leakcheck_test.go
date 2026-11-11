package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/proxy"
)

// Diagnostics for the live gate (P5). When a live run goes wrong, the transcript,
// a result body or the proxy's stderr may contain exactly the password or token
// the run is checking for, so a failure message must never print them. These
// helpers report which operation failed and which secret check failed, by label,
// with byte counts and typed fields only.

type namedSecret struct{ label, value string }
type namedText struct{ label, text string }

// leakReport returns "" when no secret appears in any text (in any spelling the
// proxy scrubs), else a message naming only labels and byte counts.
func leakReport(secrets []namedSecret, texts []namedText) string {
	var hits []string
	for _, s := range secrets {
		for _, t := range texts {
			if s.value != "" && proxy.ContainsSecret(s.value, t.text) {
				hits = append(hits, fmt.Sprintf("%s appears in the %s (%d bytes searched)", s.label, t.label, len(t.text)))
			}
		}
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return "SECRET LEAK: " + strings.Join(hits, "; ") + " (the text itself is deliberately not shown)"
}

// describeResult mentions a tool result without showing it.
func describeResult(op string, res *sdk.CallToolResult) string {
	n := 0
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			n += len(tc.Text)
		}
	}
	return fmt.Sprintf("%s: isError=%v, %d bytes of text content (not shown: it may hold a secret)", op, res.IsError, n)
}

// registrationSummary renders a ua_create envelope through an allow-list of typed
// fields; every other field (contact, session_cookie, free text) is left out.
func registrationSummary(m map[string]any) string {
	var parts []string
	for _, k := range []string{"ok", "registered", "register_code"} {
		switch v := m[k].(type) {
		case bool:
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		case float64:
			parts = append(parts, fmt.Sprintf("%s=%d", k, int(v)))
		}
	}
	if len(parts) == 0 {
		return "no typed fields"
	}
	return strings.Join(parts, " ")
}

const (
	leakSecret     = `e2e"pass-SECRET-VALUE`
	leakTranscript = "ua_create -> ROW-OF-TRANSCRIPT-BODY"
)

// A forced leak must be found in every spelling, and the failure message must
// contain neither the secret nor any part of the transcript.
func TestLeakReportNamesNeitherSecretNorTranscript(t *testing.T) {
	spellings := map[string]string{
		"raw":         leakSecret,
		"json":        strings.Trim(mustJSON(t, leakSecret), `"`),
		"base64":      base64.StdEncoding.EncodeToString([]byte(leakSecret)),
		"basic style": base64.RawURLEncoding.EncodeToString([]byte(leakSecret)),
	}
	for name, spelled := range spellings {
		msg := leakReport(
			[]namedSecret{{"rig password", leakSecret}, {"daemon token", "some-other-token-value"}},
			[]namedText{{"tool-call transcript", leakTranscript + " " + spelled}, {"proxy stderr", "clean"}},
		)
		if msg == "" {
			t.Errorf("%s: a leak in that spelling was not found", name)
			continue
		}
		for _, forbidden := range []string{leakSecret, spelled, "SECRET-VALUE", "ROW-OF-TRANSCRIPT-BODY", "clean"} {
			if strings.Contains(msg, forbidden) {
				t.Errorf("%s: the message shows %q: %s", name, forbidden, msg)
			}
		}
		for _, want := range []string{"rig password", "tool-call transcript"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: the message should name %q: %s", name, want, msg)
			}
		}
		if strings.Contains(msg, "daemon token") || strings.Contains(msg, "proxy stderr") {
			t.Errorf("%s: only the failing checks may be named: %s", name, msg)
		}
	}
}

func TestLeakReportCleanIsEmpty(t *testing.T) {
	if msg := leakReport([]namedSecret{{"rig password", leakSecret}, {"empty", ""}}, []namedText{{"transcript", "nothing here"}, {"stderr", ""}}); msg != "" {
		t.Fatalf("clean text must give no report, got %q", msg)
	}
}

func TestDescribeResultNeverShowsContent(t *testing.T) {
	res := &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "PASSWORD-IN-BODY"}, &sdk.TextContent{Text: "more"}}}
	got := describeResult("ua_create", res)
	if strings.Contains(got, "PASSWORD-IN-BODY") || strings.Contains(got, "more") || !strings.Contains(got, "ua_create") ||
		!strings.Contains(got, "isError=true") || !strings.Contains(got, "20 bytes") {
		t.Fatalf("describeResult = %q", got)
	}
}

func TestRegistrationSummaryUsesAnAllowList(t *testing.T) {
	m := map[string]any{"ok": true, "registered": false, "register_code": float64(401), "expires_s": float64(3600), "contact": "sip:1001@10.0.0.5", "session_cookie": "COOKIE-VALUE", "error": "free text"}
	got := registrationSummary(m)
	if got != "ok=true registered=false register_code=401" {
		t.Fatalf("registrationSummary = %q", got)
	}
	if got := registrationSummary(map[string]any{"contact": "x", "registered": "yes"}); got != "no typed fields" {
		t.Fatalf("untyped fields must not be shown: %q", got)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
