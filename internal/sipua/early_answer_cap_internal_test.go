package sipua

import "testing"

// CF-205: the cap is the largest UDP payload (the sipgo fork's unexported
// udpMaxDatagramPayload, restated).
func TestEarlySDPCapCoversTheLargestUDPPayload(t *testing.T) {
	if maxEarlySDPLen != 65535-20-8 {
		t.Fatalf("maxEarlySDPLen = %d, want %d", maxEarlySDPLen, 65535-20-8)
	}
}
