package calltester

import (
	"errors"
	"syscall"
	"testing"
)

// Both calltester peers send their first RTP packet at the same instant; on a
// kernel < 6.12 with a NAT table (Docker) conntrack drops the loser of that race
// and sendto returns EPERM (CF-036).
func TestSendRTPRetriesOnceOnEPERM(t *testing.T) {
	calls := 0
	sent, err := sendRTP(func([]byte) (int, error) {
		calls++
		if calls == 1 {
			return 0, syscall.EPERM
		}
		return 1, nil
	}, []byte{1})
	if err != nil || !sent || calls != 2 {
		t.Fatalf("sent=%v err=%v calls=%d, want sent=true err=nil calls=2", sent, err, calls)
	}
}

func TestSendRTPPersistentEPERMIsOneLostPacketNotAnError(t *testing.T) {
	calls := 0
	sent, err := sendRTP(func([]byte) (int, error) {
		calls++
		return 0, syscall.EPERM
	}, []byte{1})
	if err != nil || sent || calls != 2 {
		t.Fatalf("sent=%v err=%v calls=%d, want sent=false err=nil calls=2", sent, err, calls)
	}
}

func TestSendRTPOtherErrorsAreReturnedWithoutRetry(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	sent, err := sendRTP(func([]byte) (int, error) {
		calls++
		return 0, boom
	}, []byte{1})
	if !errors.Is(err, boom) || sent || calls != 1 {
		t.Fatalf("sent=%v err=%v calls=%d, want sent=false err=boom calls=1", sent, err, calls)
	}
}
