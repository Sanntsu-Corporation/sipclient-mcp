package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

// errEnvelope is the ok:false shape of §11.2. Rule/Limit/Current carry the
// §12.2.2 denial fields; Detail carries the media_negotiation and tls_failure
// detail objects, whose delivered type is map[string]any.
type errEnvelope struct {
	OK      bool           `json:"ok"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Rule    string         `json:"rule,omitempty"`
	Limit   *int           `json:"limit,omitempty"`
	Current *int           `json:"current,omitempty"`
	Detail  map[string]any `json:"detail,omitempty"`
}

// marshalEnvelope converts a tool function's (payload, error) return — locked
// decision 11 — into the single §11 JSON envelope.
//
// Locked decision 10: this is the ONLY place an apierr.Error becomes JSON. No
// other package builds this shape, which is what keeps §11.2's code table
// enumerable and §6.2's layering intact.
func marshalEnvelope(payload any, err error, correlationID func() string, log *slog.Logger) ([]byte, error) {
	if err == nil {
		return marshalOK(payload)
	}
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return json.Marshal(errEnvelope{
			OK:      false,
			Code:    string(ae.Code),
			Message: ae.Message,
			Rule:    ae.Rule,
			Limit:   ae.Limit,
			Current: ae.Current,
			Detail:  ae.Detail,
		})
	}
	// A cancelled call_wait (§11.2 `cancelled`, D360/D361): the MCP caller
	// sent notifications/cancelled while parked. The go-sdk writes this
	// response unconditionally even for a cancelled call
	// (jsonrpc2/conn.go:664), so the envelope IS delivered on a still-open
	// connection. This is not a bug — a cancelling agent did the right
	// thing — so it is deliberately NOT logged as one.
	if errors.Is(err, context.Canceled) {
		ae := apierr.Cancelled("the request was cancelled by the MCP client")
		return json.Marshal(errEnvelope{
			OK:      false,
			Code:    string(ae.Code),
			Message: ae.Message,
		})
	}
	// Anything that is not an apierr.Error is a bug (§11.2 `internal`). The
	// correlation id is echoed to the caller and logged with the underlying
	// error, which is never shown to the agent.
	id := correlationID()
	log.Error("tool returned a non-apierr error", "correlation_id", id, "err", err.Error())
	return json.Marshal(errEnvelope{
		OK:      false,
		Code:    string(apierr.CodeInternal),
		Message: fmt.Sprintf("internal error (correlation id %s)", id),
	})
}

// marshalOK splices "ok":true into the payload's own JSON object, so a tool
// payload is never nested under a wrapper key an agent would have to unwrap.
func marshalOK(payload any) ([]byte, error) {
	if payload == nil {
		return []byte(`{"ok":true}`), nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal tool payload: %w", err)
	}
	if len(b) == 0 || b[0] != '{' {
		return nil, fmt.Errorf("tool payload must marshal to a JSON object, got %s", b)
	}
	if string(b) == "{}" {
		return []byte(`{"ok":true}`), nil
	}
	out := make([]byte, 0, len(b)+len(`{"ok":true,`))
	out = append(out, `{"ok":true,`...)
	out = append(out, b[1:]...)
	return out, nil
}
