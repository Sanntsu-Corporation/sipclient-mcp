package sip

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/fakes"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// SIPCLIENT-MCP DIVERGENCE (CF-111) tests: RFC 3261 17.1.2.2 says Timer E keeps
// retransmitting a non-INVITE request in Proceeding, reset to T2.

// stampWriter records the time of every write.
type stampWriter struct {
	mu sync.Mutex
	at []time.Time
}

func (w *stampWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.at = append(w.at, time.Now())
	w.mu.Unlock()
	return len(p), nil
}

func (w *stampWriter) stamps() []time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Time(nil), w.at...)
}

// proceedingFixture builds an initialised non-INVITE (OPTIONS) or INVITE client
// transaction over a fake UDP or TCP connection with fast timers.
func proceedingFixture(t *testing.T, invite bool, transport string) (*ClientTx, *Request, *stampWriter) {
	t.Helper()
	SetTimers(10*time.Millisecond, 40*time.Millisecond, 50*time.Millisecond)
	t.Cleanup(func() { SetTimers(500*time.Millisecond, 4*time.Second, 5*time.Second) })

	req, _, _ := testCreateInvite(t, "sip:127.0.0.99:5060", transport, "127.0.0.2:5060")
	if !invite {
		req.Method = OPTIONS
		req.RemoveHeader("CSeq")
		req.AppendHeader(&CSeqHeader{SeqNo: 1, MethodName: OPTIONS})
	}
	w := &stampWriter{}
	var conn Connection
	if transport == "udp" {
		conn = &UDPConnection{PacketConn: &fakes.UDPConn{
			Reader:  &io.LimitedReader{},
			Writers: map[string]io.Writer{"127.0.0.99:5060": w},
		}}
	} else {
		conn = &TCPConnection{Conn: &fakes.TCPConn{Reader: &io.LimitedReader{}, Writer: w}}
	}
	tx := NewClientTx("cf111", req, conn, log.Logger)
	require.NoError(t, tx.Init())
	t.Cleanup(tx.Terminate)
	go func() { // drain: Receive blocks until the TU consumes
		for {
			select {
			case <-tx.Responses():
			case <-tx.done:
				return
			}
		}
	}()
	return tx, req, w
}

func TestNonInviteProceedingRetransmitsAtT2(t *testing.T) {
	tx, req, w := proceedingFixture(t, false, "udp")
	tx.Receive(NewResponseFromRequest(req, StatusTrying, "Trying", nil))
	require.Eventually(t, func() bool { return len(w.stamps())-1 >= 3 }, 2*time.Second, 5*time.Millisecond,
		"retransmissions after the 100")

	st := w.stamps()
	require.GreaterOrEqual(t, len(st)-1, 3, "retransmissions after the 100")
	for i := 2; i < len(st); i++ {
		require.GreaterOrEqual(t, st[i].Sub(st[i-1]), 32*time.Millisecond, "gap %d must be about T2, no doubling", i)
	}
}

func TestNonInviteFinalInProceedingStopsRetransmission(t *testing.T) {
	tx, req, w := proceedingFixture(t, false, "udp")
	tx.Receive(NewResponseFromRequest(req, StatusTrying, "Trying", nil))
	require.Eventually(t, func() bool { return len(w.stamps()) >= 2 }, 2*time.Second, 5*time.Millisecond) // one retransmission at 10 ms
	tx.Receive(NewResponseFromRequest(req, StatusOK, "OK", nil))
	n := len(w.stamps())
	require.GreaterOrEqual(t, n, 2)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, n, len(w.stamps()), "no write after the final")
	require.NoError(t, compareFunctions(tx.currentFsmState(), tx.stateCompleted))
}

func TestNonInviteReliableProceedingNeverRetransmits(t *testing.T) {
	tx, req, w := proceedingFixture(t, false, "tcp")
	tx.Receive(NewResponseFromRequest(req, StatusTrying, "Trying", nil))
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 1, len(w.stamps()))
}

func TestInviteProceedingStillStopsTimerA(t *testing.T) {
	tx, req, w := proceedingFixture(t, true, "udp")
	tx.Receive(NewResponseFromRequest(req, StatusTrying, "Trying", nil))
	n := len(w.stamps())
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, n, len(w.stamps()), "INVITE Proceeding does not retransmit")
}

func TestActResendProceedingAfterTerminateDoesNotPanic(t *testing.T) {
	tx := terminatedClientTx()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("actResendProceeding panicked on a nil timer_a: %v", r)
		}
	}()
	require.Equal(t, FsmInputNone, tx.actResendProceeding())
}
