package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

var errUnexpectedForTest = errors.New("boom")

// discardLogger lives in policy_testhelper_test.go (Task 17 Step 17.5) — one
// declaration for the package, not one per test file (Rule 18).

func fixedCorrelation() string { return "corr-0001" }

func TestMarshalEnvelopeSuccess(t *testing.T) {
	type dialResult struct {
		CallHandle string `json:"call_handle"`
		State      string `json:"state"`
	}
	type sipResult struct {
		Phase   string `json:"phase"`
		SIPCode int    `json:"sip_code"`
		Reason  string `json:"reason"`
	}
	type failedCall struct {
		CallHandle string    `json:"call_handle"`
		State      string    `json:"state"`
		Result     sipResult `json:"result"`
	}

	tests := []struct {
		name    string
		payload any
		want    string
	}{
		{
			name:    "nil payload",
			payload: nil,
			want:    `{"ok":true}`,
		},
		{
			name:    "object payload",
			payload: dialResult{CallHandle: "call_91c4", State: "dialing"},
			want:    `{"ok":true,"call_handle":"call_91c4","state":"dialing"}`,
		},
		{
			// §11.1, made STRUCTURAL by decision 11: a 486 arrives as a nil
			// error with the code in the payload. It cannot become an error,
			// because the only path that produces ok:false takes a non-nil
			// error, and no tool returns one for a far-end response.
			name: "a 486 is a successful tool call",
			payload: failedCall{
				CallHandle: "call_91c4",
				State:      "failed",
				Result:     sipResult{Phase: "invite", SIPCode: 486, Reason: "Busy Here"},
			},
			want: `{"ok":true,"call_handle":"call_91c4","state":"failed",` +
				`"result":{"phase":"invite","sip_code":486,"reason":"Busy Here"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := marshalEnvelope(tc.payload, nil, fixedCorrelation, discardLogger())
			if err != nil {
				t.Fatalf("marshalEnvelope: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("envelope =\n  %s\nwant\n  %s", got, tc.want)
			}
			var probe struct {
				OK bool `json:"ok"`
			}
			if err := json.Unmarshal(got, &probe); err != nil || !probe.OK {
				t.Fatalf("envelope does not carry ok:true: %s (%v)", got, err)
			}
		})
	}
}

func TestMarshalEnvelopeErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "denied with a rule and limits (§12.2.2)",
			err: apierr.DeniedLimit("max_concurrent_calls_total", 50, 50,
				"server already holds 50 concurrent calls (policy max_concurrent_calls_total=50)"),
			want: `{"ok":false,"code":"denied",` +
				`"message":"server already holds 50 concurrent calls (policy max_concurrent_calls_total=50)",` +
				`"rule":"max_concurrent_calls_total","limit":50,"current":50}`,
		},
		{
			name: "not_found with no optional fields",
			err:  apierr.NotFound("unknown call handle"),
			want: `{"ok":false,"code":"not_found","message":"unknown call handle"}`,
		},
		{
			name: "media_negotiation with a detail object",
			err: apierr.MediaNegotiation("no_common_codec",
				map[string]any{"kind": "no_common_codec"},
				"no codec in common: peer offered [PCMA], this UA accepts [PCMU]"),
			want: `{"ok":false,"code":"media_negotiation",` +
				`"message":"no codec in common: peer offered [PCMA], this UA accepts [PCMU]",` +
				`"detail":{"kind":"no_common_codec"}}`,
		},
		{
			name: "a wrapped apierr is still recognised",
			err:  fmt.Errorf("dialling: %w", apierr.NotFound("unknown UA handle")),
			want: `{"ok":false,"code":"not_found","message":"unknown UA handle"}`,
		},
		{
			name: "anything else becomes internal with a correlation id",
			err:  errUnexpectedForTest,
			want: `{"ok":false,"code":"internal","message":"internal error (correlation id corr-0001)"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := marshalEnvelope(nil, tc.err, fixedCorrelation, discardLogger())
			if err != nil {
				t.Fatalf("marshalEnvelope: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("envelope =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

// TestInternalEnvelopeLeaksNothing: the underlying error text must reach the
// LOG and never the agent (§11.2 `internal`, §12.2 credential isolation).
func TestInternalEnvelopeLeaksNothing(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	got, err := marshalEnvelope(nil, errors.New("dial tcp 10.0.0.1:5060: secret-token-abc"), fixedCorrelation, log)
	if err != nil {
		t.Fatalf("marshalEnvelope: %v", err)
	}
	if bytes.Contains(got, []byte("secret-token-abc")) {
		t.Fatalf("internal envelope leaked the underlying error: %s", got)
	}
	if !bytes.Contains(buf.Bytes(), []byte("corr-0001")) {
		t.Fatalf("correlation id absent from the log: %s", buf.Bytes())
	}
	if !bytes.Contains(buf.Bytes(), []byte("secret-token-abc")) {
		t.Fatalf("underlying error absent from the log: %s", buf.Bytes())
	}
}
