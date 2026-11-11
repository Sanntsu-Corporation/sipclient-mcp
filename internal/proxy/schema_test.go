package proxy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func upstreamSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"mode", "other_required"},
		"properties": map[string]any{
			"mode":       map[string]any{"type": "string"},
			"auth_pass":  map[string]any{"type": "string"},
			"local_addr": map[string]any{"type": "string"},
		},
	}
}

func jsonRoundTrip(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRewriteUACreateSchema(t *testing.T) {
	t.Run("adds optional account and drops mode from required", func(t *testing.T) {
		out, err := RewriteUACreateSchema(upstreamSchema())
		if err != nil {
			t.Fatal(err)
		}
		acct := out["properties"].(map[string]any)["account"].(map[string]any)
		if acct["type"] != "string" || !strings.Contains(acct["description"].(string), "account_list") {
			t.Fatalf("bad account property: %v", acct)
		}
		if !reflect.DeepEqual(out["required"], []any{"other_required"}) {
			t.Fatalf("required = %v", out["required"])
		}
	})
	t.Run("required removed when mode was the only entry", func(t *testing.T) {
		s := upstreamSchema()
		s["required"] = []any{"mode"}
		out, _ := RewriteUACreateSchema(s)
		if _, ok := out["required"]; ok {
			t.Fatalf("empty required must be deleted: %v", out["required"])
		}
	})
	t.Run("does not mutate the input", func(t *testing.T) {
		s := upstreamSchema()
		before, _ := json.Marshal(s)
		_, _ = RewriteUACreateSchema(s)
		after, _ := json.Marshal(s)
		if string(before) != string(after) {
			t.Fatalf("input mutated:\n%s\n%s", before, after)
		}
	})
	t.Run("preserves everything else", func(t *testing.T) {
		out, _ := RewriteUACreateSchema(upstreamSchema())
		if out["additionalProperties"] != false || out["type"] != "object" {
			t.Fatalf("top-level keywords lost: %v", out)
		}
		props := out["properties"].(map[string]any)
		for _, k := range []string{"mode", "auth_pass", "local_addr"} {
			if _, ok := props[k]; !ok {
				t.Errorf("property %q lost", k)
			}
		}
	})
	t.Run("preserves unknown keywords, nested keys and big numbers", func(t *testing.T) {
		s := upstreamSchema()
		s["x-vendor"] = map[string]any{"k": []any{1, "two", nil}}
		s["$defs"] = map[string]any{"d": map[string]any{"type": "integer", "minimum": 5}}
		s["examples"] = []any{map[string]any{"mode": "direct"}}
		s["properties"].(map[string]any)["local_addr"] = map[string]any{"type": "string", "pattern": "^[0-9.:]+$", "x-note": "kept"}
		out, err := RewriteUACreateSchema(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"x-vendor", "$defs", "examples"} {
			if !reflect.DeepEqual(out[k], jsonRoundTrip(t, s[k])) {
				t.Errorf("keyword %q changed: %v", k, out[k])
			}
		}
		la := out["properties"].(map[string]any)["local_addr"].(map[string]any)
		if la["pattern"] != "^[0-9.:]+$" || la["x-note"] != "kept" {
			t.Errorf("property sub-keywords lost: %v", la)
		}
	})
	t.Run("schema without properties or required", func(t *testing.T) {
		out, err := RewriteUACreateSchema(map[string]any{"type": "object"})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := out["properties"].(map[string]any)["account"]; !ok {
			t.Fatal("account not added")
		}
	})
	t.Run("errors", func(t *testing.T) {
		for name, in := range map[string]any{
			"nil": nil, "non-object type": map[string]any{"type": "string"}, "unmarshalable": make(chan int),
		} {
			if _, err := RewriteUACreateSchema(in); err == nil {
				t.Errorf("%s: expected error", name)
			}
		}
	})
}
