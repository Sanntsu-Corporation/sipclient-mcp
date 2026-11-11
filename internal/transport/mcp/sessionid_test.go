package mcp

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewSessionID(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := newSessionID()
		if len(id) != 32 {
			t.Fatalf("len(id) = %d, want 32 (128 bits hex)", len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("id %q is not hex: %v", id, err)
		}
		if strings.ContainsRune(id, '_') {
			t.Fatalf("id %q carries a prefix; §12.6 session ids are UNPREFIXED "+
				"(contrast decision 12's ua_/call_ handles)", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q at iteration %d", id, i)
		}
		seen[id] = struct{}{}
	}
}
