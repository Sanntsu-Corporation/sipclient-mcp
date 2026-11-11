package sip

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/emiago/sipgo/fakes"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// lockedBuf is an io.Writer safe to read while a transaction timer may write.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestActCancelVetoSuppressesThe487 is the CF-096 fork divergence (VENDOR.md):
// a per-transaction OnCancel hook that returns false vetoes actCancel's
// automatic 487 and leaves the INVITE transaction in Proceeding, so the TU's
// own final can still go out; a hook that returns true keeps upstream's 487.
func TestActCancelVetoSuppressesThe487(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow bool
	}{{"veto", false}, {"allow", true}} {
		t.Run(tc.name, func(t *testing.T) {
			req, _, _ := testCreateInvite(t, "sip:127.0.0.99:5060", "udp", "127.0.0.2:5060")
			out := &lockedBuf{}
			conn := &UDPConnection{PacketConn: &fakes.UDPConn{
				Reader:  bytes.NewBuffer(nil),
				Writers: map[string]io.Writer{"127.0.0.2:5060": out},
			}}
			tx := NewServerTx("cf096", req, conn, log.Logger)
			require.NoError(t, tx.Init())
			t.Cleanup(tx.Terminate)
			require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusTrying, "Trying", nil)))

			called := 0
			tx.OnCancel(func(*Request) bool { called++; return tc.allow })
			require.NoError(t, tx.Receive(newCancelRequest(req)))
			require.Equal(t, 1, called, "the hook runs once per matched CANCEL")

			got487 := strings.Contains(out.String(), "SIP/2.0 487")
			if tc.allow {
				require.True(t, got487, "an allowing hook keeps the automatic 487")
				require.NoError(t, compareFunctions(tx.currentFsmState(), tx.inviteStateCompleted))
				require.ErrorIs(t, tx.Err(), ErrTransactionCanceled)
				return
			}
			require.False(t, got487, "a vetoing hook must suppress the automatic 487")
			require.NoError(t, compareFunctions(tx.currentFsmState(), tx.inviteStateProcceeding))
			require.NoError(t, tx.Err())
			// The TU's own final still goes out on the live transaction.
			require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
			require.NoError(t, compareFunctions(tx.currentFsmState(), tx.inviteStateAccepted))
		})
	}
}
