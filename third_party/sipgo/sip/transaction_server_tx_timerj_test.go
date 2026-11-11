package sip

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/fakes"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// CF-194: ServerTx.TerminateAfterHandler keeps a transaction the FSM still owns.

func countIn(l *lockedBuf, s string) int { return strings.Count(l.String(), s) }

func withFastTimers(t *testing.T) {
	SetTimers(10*time.Millisecond, 80*time.Millisecond, 50*time.Millisecond)
	t.Cleanup(func() { SetTimers(500*time.Millisecond, 4*time.Second, 5*time.Second) })
}

func timerJTx(t *testing.T, method, transport string) (*ServerTx, *Request, *lockedBuf) {
	t.Helper()
	req := testCreateMessage(t, []string{
		method + " sip:bob@127.0.0.99:5060 SIP/2.0",
		"Via: SIP/2.0/" + transport + " 127.0.0.2:5060;branch=z9hG4bKtermj" + method,
		"From: <sip:alice@127.0.0.2>;tag=a1",
		"To: <sip:bob@127.0.0.99>",
		"Call-ID: timerj-" + method + transport,
		"CSeq: 1 " + method,
		"Content-Length: 0",
		"",
		"",
	}).(*Request)
	out := &lockedBuf{}
	var conn Connection
	if transport == "UDP" {
		conn = &UDPConnection{PacketConn: &fakes.UDPConn{
			Reader:  bytes.NewBuffer(nil),
			Writers: map[string]io.Writer{"127.0.0.2:5060": out},
		}}
	} else {
		conn = &TCPConnection{Conn: &fakes.TCPConn{Reader: &io.LimitedReader{}, Writer: out}}
	}
	tx := NewServerTx("termj-"+method+transport, req, conn, log.Logger)
	require.NoError(t, tx.Init())
	return tx, req, out
}

func isDone(tx *ServerTx) bool {
	select {
	case <-tx.Done():
		return true
	default:
		return false
	}
}

func TestTerminateAfterHandlerKeepsACompletedUDPNonInviteUntilTimerJ(t *testing.T) {
	withFastTimers(t)
	tx, req, out := timerJTx(t, "BYE", "UDP")
	require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
	tx.TerminateAfterHandler()
	require.False(t, isDone(tx), "Completed non-INVITE over UDP must outlive the handler")
	require.NoError(t, tx.Receive(req))
	require.Eventually(t, func() bool { return countIn(out, "200 OK") == 2 }, time.Second, 5*time.Millisecond)
	select {
	case <-tx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Timer J did not delete the transaction")
	}
}

func TestTerminateAfterHandlerKeepsAnAcceptedInviteUntilTimerL(t *testing.T) {
	for _, transport := range []string{"UDP", "TCP"} {
		t.Run(transport, func(t *testing.T) {
			withFastTimers(t)
			tx, req, out := timerJTx(t, "INVITE", transport)
			res := NewResponseFromRequest(req, StatusOK, "OK", nil)
			require.NoError(t, tx.Respond(res))
			tx.TerminateAfterHandler()
			require.False(t, isDone(tx), "Accepted INVITE must outlive the handler")
			require.Equal(t, 1, countIn(out, "200 OK"))
			require.NoError(t, tx.Receive(req)) // J7: absorbed
			time.Sleep(30 * time.Millisecond)
			require.Equal(t, 1, countIn(out, "200 OK"))
			require.NoError(t, tx.Respond(res)) // J8: TU copy
			require.Eventually(t, func() bool { return countIn(out, "200 OK") == 2 }, time.Second, 5*time.Millisecond)
			ack := testCreateMessage(t, []string{
				"ACK sip:bob@127.0.0.99:5060 SIP/2.0",
				"Via: SIP/2.0/" + transport + " 127.0.0.2:5060;branch=z9hG4bKtermjINVITE",
				"From: <sip:alice@127.0.0.2>;tag=a1",
				"To: <sip:bob@127.0.0.99>;tag=b1",
				"Call-ID: timerj-INVITE" + transport,
				"CSeq: 1 ACK",
				"Content-Length: 0",
				"",
				"",
			}).(*Request)
			go func() { _ = tx.Receive(ack) }()
			select {
			case got := <-tx.Acks():
				require.Equal(t, "ACK", got.Method.String())
			case <-time.After(time.Second):
				t.Fatal("J9: ACK not passed to the TU")
			}
			select {
			case <-tx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("Timer L did not delete the transaction")
			}
		})
	}
}

func TestTerminateAfterHandlerDeletesAReliableNonInvite(t *testing.T) {
	withFastTimers(t)
	tx, req, _ := timerJTx(t, "BYE", "TCP")
	require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
	tx.TerminateAfterHandler()
	require.True(t, isDone(tx))
}

func TestTerminateAfterHandlerDeletesANonInviteWithoutFinal(t *testing.T) {
	withFastTimers(t)
	tx, _, _ := timerJTx(t, "BYE", "UDP")
	tx.TerminateAfterHandler()
	require.True(t, isDone(tx), "no response")

	tx2, req2, _ := timerJTx(t, "INFO", "UDP")
	require.NoError(t, tx2.Respond(NewResponseFromRequest(req2, StatusTrying, "Trying", nil)))
	tx2.TerminateAfterHandler()
	require.True(t, isDone(tx2), "only a provisional")
}

func TestTerminateAfterHandlerDeletesARejectedInvite(t *testing.T) {
	withFastTimers(t)
	tx, req, _ := timerJTx(t, "INVITE", "UDP")
	require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusBusyHere, "Busy Here", nil)))
	tx.TerminateAfterHandler()
	require.True(t, isDone(tx))
}

// An Accepted INVITE deleted before Timer L fires stops Timer L (no closure left
// referencing the transaction for 64*T1).
func TestEarlyDeleteOfAnAcceptedInviteStopsTimerL(t *testing.T) {
	withFastTimers(t)
	tx, req, _ := timerJTx(t, "INVITE", "UDP")
	require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
	tx.TerminateAfterHandler()
	tx.mu.Lock()
	armed := tx.timer_l != nil
	tx.mu.Unlock()
	require.True(t, armed, "Timer L must be armed after a 2xx")
	tx.Terminate()
	tx.mu.Lock()
	defer tx.mu.Unlock()
	require.Nil(t, tx.timer_l, "delete must stop Timer L")
}
