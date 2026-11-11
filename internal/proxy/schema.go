package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AccountArgDescription is the description of the added "account" property.
const AccountArgDescription = "Name of a SIP account configured on this machine (call account_list to see the names). " +
	"When set, the account supplies mode, transport, registrar, aor, auth_user, auth_pass and auth_any_host; do not send those fields " +
	"together with account. Passwords are never shown."

// UACreateDescriptionNote is appended to the mirrored ua_create description.
const UACreateDescriptionNote = " Prefer {\"account\": \"<name>\"} (see account_list) over typing credentials; " +
	"account cannot be combined with mode, transport, registrar, aor, auth_user, auth_pass or auth_any_host."

// RewriteUACreateSchema returns a deep copy of the upstream ua_create input
// schema with an optional "account" property and "mode" no longer required.
func RewriteUACreateSchema(in any) (map[string]any, error) {
	if in == nil {
		return nil, errors.New("ua_create schema is missing")
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("ua_create schema is not JSON: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("ua_create schema is not an object: %w", err)
	}
	if out["type"] != "object" {
		return nil, errors.New(`ua_create schema type must be "object"`)
	}
	props, ok := out["properties"].(map[string]any)
	if !ok {
		props = map[string]any{}
		out["properties"] = props
	}
	props["account"] = map[string]any{"type": "string", "description": AccountArgDescription}
	if req, ok := out["required"].([]any); ok {
		kept := make([]any, 0, len(req))
		for _, r := range req {
			if r != "mode" {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(out, "required")
		} else {
			out["required"] = kept
		}
	}
	return out, nil
}
