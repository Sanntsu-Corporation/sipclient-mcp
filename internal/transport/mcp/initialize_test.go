package mcp

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

func TestIsInitialize(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"plain initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, true},
		{"leading whitespace", "\n\t  " + `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, true},
		// A naive strings.Contains(`"method":"initialize"`) returns FALSE
		// here. A false negative 404s a legitimate re-initialize.
		{"space after the method colon", `{"jsonrpc":"2.0","id":1,"method": "initialize"}`, true},
		{"pretty printed", "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"method\": \"initialize\"\n}", true},
		{"method last", `{"id":1,"params":{},"jsonrpc":"2.0","method":"initialize"}`, true},
		{"batch containing initialize", `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"initialize"}]`, true},
		{"batch with leading whitespace", "  [{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\"}]", true},

		{"tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_status"}}`, false},
		// A naive substring match returns TRUE here — a false positive that
		// hands a fresh session to a request that should have been rejected.
		{"initialize only as a string argument", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"note":"\"method\":\"initialize\""}}}`, false},
		{"initialize as a param value", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"of":"initialize"}}`, false},
		{"batch with no initialize", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, false},
		{"notification with no method", `{"jsonrpc":"2.0","id":1,"result":{}}`, false},
		{"empty body", ``, false},
		{"whitespace only", "  \n ", false},
		{"malformed json", `{"method":"initialize"`, false},
		{"json array of scalars", `[1,2,3]`, false},
		{"json scalar", `"initialize"`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isInitialize([]byte(tc.body)); got != tc.want {
				t.Fatalf("isInitialize(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// TestInitializeResultAdvertisesTransfer pins that the initialize result
// carries the capability summary, so a probing agent sees call transfer.
func TestInitializeResultAdvertisesTransfer(t *testing.T) {
	hs, _, _ := newTestServer(t, fakeclock.New(time.Unix(0, 0)), time.Minute)
	req, err := http.NewRequest(http.MethodPost, hs.URL+"/mcp", strings.NewReader(initBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"instructions"`) || !strings.Contains(string(body), "call transfer") {
		t.Fatalf("initialize result lacks the capability summary: %s", body)
	}
}
