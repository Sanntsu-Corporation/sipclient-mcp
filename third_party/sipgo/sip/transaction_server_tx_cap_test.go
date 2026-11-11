package sip

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// CF-212: above the cap a transaction the FSM would keep is deleted when its
// handler returns (the pre-CF-194 behaviour), so the kept set stays bounded.
// It relies on the process-global keptServerTx being zero at the start, which
// holds while no test in this package uses t.Parallel.
func TestTerminateAfterHandlerCapsKeptTransactions(t *testing.T) {
	withFastTimers(t)
	require.Eventually(t, func() bool { return keptServerTx.Load() == 0 }, 3*time.Second, 10*time.Millisecond,
		"kept transactions left by an earlier test")
	const limit = 2
	var txs []*ServerTx
	for i := 0; i < limit+1; i++ {
		tx, req, _ := timerJTx(t, "BYE", "UDP")
		tx.key += strconv.Itoa(i)
		require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
		tx.terminateAfterHandler(limit)
		txs = append(txs, tx)
	}
	require.False(t, isDone(txs[0]))
	require.False(t, isDone(txs[1]))
	require.True(t, isDone(txs[2]), "the (N+1)th kept transaction must be deleted at handler return")
	require.EqualValues(t, limit, keptServerTx.Load())

	// An over-cap 2xx'd INVITE is deleted too, so a goroutine forwarding its
	// ACKs until Done (internal/sipua forwardAcks) exits at once.
	inv, invReq, _ := timerJTx(t, "INVITE", "UDP")
	require.NoError(t, inv.Respond(NewResponseFromRequest(invReq, StatusOK, "OK", nil)))
	forwarderDone := make(chan struct{})
	go func() {
		defer close(forwarderDone)
		for {
			select {
			case <-inv.Acks():
			case <-inv.Done():
				return
			}
		}
	}()
	inv.terminateAfterHandler(limit)
	select {
	case <-forwarderDone:
	case <-time.After(300 * time.Millisecond): // well inside Timer L (640 ms here)
		inv.Terminate()
		t.Fatal("the ACK forwarder of an over-cap INVITE did not exit")
	}
	require.EqualValues(t, limit, keptServerTx.Load())

	// A kept transaction's delete frees its slot.
	txs[0].Terminate()
	require.EqualValues(t, limit-1, keptServerTx.Load())
	tx, req, _ := timerJTx(t, "INVITE", "UDP")
	require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
	tx.terminateAfterHandler(limit)
	require.False(t, isDone(tx), "a freed slot keeps the next transaction")
	tx.Terminate()
	txs[1].Terminate()
	require.EqualValues(t, 0, keptServerTx.Load())
}
