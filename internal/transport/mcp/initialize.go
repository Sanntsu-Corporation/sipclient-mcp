package mcp

import (
	"bytes"
	"encoding/json"
)

// isInitialize reports whether body is a JSON-RPC 2.0 message, or a batch of
// them, carrying an "initialize" request.
//
// It PARSES the body. §3e constraint 1 is explicit that a substring match on
// `"method":"initialize"` is a §12.6 CORRECTNESS BUG, not a style issue:
// ordinary JSON whitespace defeats it (false negative -> a legitimate
// re-initialize is 404ed) and an "initialize" string appearing in a tool
// argument fools it (false positive -> a fresh session is handed to a request
// that should have been rejected).
//
// A body that does not parse is not an initialize. That is the safe direction:
// the caller 404s it, disclosing nothing, and the SDK would have rejected it
// anyway.
func isInitialize(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	type rpc struct {
		Method string `json:"method"`
	}
	if trimmed[0] == '[' {
		var batch []rpc
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return false
		}
		for _, m := range batch {
			if m.Method == "initialize" {
				return true
			}
		}
		return false
	}
	var one rpc
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return false
	}
	return one.Method == "initialize"
}
