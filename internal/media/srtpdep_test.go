package media

import (
	"testing"

	"github.com/pion/srtp/v3"
)

// TestPionSRTPSymbolsPresent pins the exact pion/srtp/v3 surface Task 5 builds
// on, so a version bump that renames any of them fails here rather than deep in
// the transform. It constructs a context with a real key and the explicit
// replay-protection option — the option Task 5's invariant is built around.
func TestPionSRTPSymbolsPresent(t *testing.T) {
	key := make([]byte, 16)
	salt := make([]byte, 14)
	ctx, err := srtp.CreateContext(key, salt, srtp.ProtectionProfileAes128CmHmacSha1_80,
		srtp.SRTPReplayProtection(64))
	if err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	if ctx == nil {
		t.Fatal("CreateContext returned nil context")
	}
}
