package sip

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

type ServerTx struct {
	baseTx
	acks chan *Request
	// cancels chan *Request
	onCancel     func(r *Request) bool
	timer_g      *time.Timer
	timer_g_time time.Duration
	timer_h      *time.Timer
	timer_i      *time.Timer
	timer_i_time time.Duration
	timer_j      *time.Timer
	timer_1xx    *time.Timer
	timer_l      *time.Timer
	reliable     bool
	kept         bool // counted in keptServerTx (CF-212); guarded by mu

	closeOnce sync.Once
}

// SIPCLIENT-MCP DIVERGENCE (CF-212): maxKeptServerTx caps the transactions
// TerminateAfterHandler leaves to Timer J or Timer L, process-wide. Each lives
// 64*T1 (32 s) and holds about 5.4 KB, so 1024 bounds them near 5.5 MB while
// allowing about 32 such requests a second; above the cap a transaction is
// deleted at handler return as before CF-194 (a retransmission is re-handled,
// never rejected).
const maxKeptServerTx = 1024

// keptServerTx counts the transactions currently kept past their handler.
var keptServerTx atomic.Int64

func NewServerTx(key string, origin *Request, conn Connection, logger zerolog.Logger) *ServerTx {
	tx := new(ServerTx)
	tx.key = key
	tx.conn = conn

	// about ~10 retransmits
	tx.acks = make(chan *Request)
	// tx.cancels = make(chan *Request)
	tx.done = make(chan struct{})
	tx.log = logger
	tx.origin = origin
	tx.reliable = IsReliable(origin.Transport())
	return tx
}

func (tx *ServerTx) Init() error {
	tx.initFSM()

	tx.mu.Lock()
	if tx.reliable {
		tx.timer_i_time = 0
	} else {
		tx.timer_g_time = Timer_G
		tx.timer_i_time = Timer_I
	}
	tx.mu.Unlock()

	// RFC 3261 - 17.2.1
	if tx.Origin().IsInvite() {
		// tx.Log().Tracef("set timer_1xx to %v", Timer_1xx)
		tx.mu.Lock()
		tx.timer_1xx = time.AfterFunc(Timer_1xx, func() {
			trying := NewResponseFromRequest(
				tx.Origin(),
				100,
				"Trying",
				nil,
			)
			// tx.Log().Trace("timer_1xx fired")
			if err := tx.Respond(trying); err != nil {
				tx.log.Error().Err(err).Msg("send '100 Trying' response failed")
			}
		})
		tx.mu.Unlock()
	}
	tx.log.Debug().Str("tx", tx.Key()).Msg("Server transaction initialized")
	return nil
}

// Receive is endpoint for handling received server requests.
// NOTE: it could block while passing request to client,
// therefore running in seperate goroutine is needed
func (tx *ServerTx) Receive(req *Request) error {
	tx.mu.Lock()
	if tx.timer_1xx != nil {
		tx.timer_1xx.Stop()
		tx.timer_1xx = nil
	}
	tx.mu.Unlock()

	var input fsmInput
	switch {
	case req.Method == tx.origin.Method:
		input = server_input_request
	case req.IsAck(): // ACK for non-2xx response
		input = server_input_ack
	case req.IsCancel():
		input = server_input_cancel
	default:
		return fmt.Errorf("unexpected message error")
	}

	tx.spinFsmWithRequest(input, req)
	return nil
}

func (tx *ServerTx) Respond(res *Response) error {
	if res.IsCancel() {
		return tx.conn.WriteMsg(res)
	}

	tx.mu.Lock()
	if tx.timer_1xx != nil {
		tx.timer_1xx.Stop()
		tx.timer_1xx = nil
	}
	tx.mu.Unlock()

	var input fsmInput
	switch {
	case res.IsProvisional():
		input = server_input_user_1xx
	case res.IsSuccess():
		input = server_input_user_2xx
	default:
		input = server_input_user_300_plus
	}
	tx.spinFsmWithResponse(input, res)
	// In case of termination or some error
	return tx.Err()
}

// Acks makes channel for sending acks. Channel is created on demand
func (tx *ServerTx) Acks() <-chan *Request {
	return tx.acks
}

func (tx *ServerTx) ackSend(r *Request) {
	select {
	case <-tx.done:
		tx.log.Warn().Str("callid", r.CallID().Value()).Msg("ACK missed")
	case tx.acks <- r:
	}
}

func (tx *ServerTx) ackSendAsync(r *Request) {
	select {
	case tx.acks <- r:
		return
	default:
	}

	// Go routines should be cheap and it will prevent blocking
	go tx.ackSend(r)
}

// func (tx *ServerTx) Cancels() <-chan *Request {
// 	if tx.cancels != nil {
// 		return tx.cancels
// 	}
// 	tx.cancels = make(chan *Request)
// 	return tx.cancels
// }

// func (tx *ServerTx) cancelSend(r *Request) {
// 	select {
// 	case <-tx.done:
// 		tx.log.Warn().Str("callid", r.CallID().Value()).Msg("CANCEL missed")
// 	case tx.cancels <- r:
// 	}
// }

// func (tx *ServerTx) cancelSendAsync(r *Request) {
// 	tx.onCancel(r)

// 	// select {
// 	// case tx.cancels <- r:
// 	// default:
// 	// 	// Go routines should be cheap and it will prevent blocking
// 	// 	go tx.cancelSend(r)
// 	// }
// }

func (tx *ServerTx) OnCancel(f func(r *Request) bool) {
	tx.fsmMu.Lock()
	defer tx.fsmMu.Unlock()
	tx.onCancel = f
}

func (tx *ServerTx) Terminate() {
	tx.log.Debug().Msg("Server transaction terminating")
	tx.delete()
}

// TerminateAfterHandler deletes the transaction when its handler returns, except
// where the FSM's own timer must still own it.
//
// SIPCLIENT-MCP DIVERGENCE (CF-194): upstream deleted every transaction at
// handler return, which defeated RFC 3261 17.2.2 (a non-INVITE transaction that
// sent its final stays Completed until Timer J, over an unreliable transport, and
// re-sends that final on a request retransmission) and RFC 6026 7.1 (an INVITE
// transaction that sent a 2xx stays Accepted until Timer L). Timer J's and Timer
// L's rows delete it later. CF-212: at most maxKeptServerTx are kept.
func (tx *ServerTx) TerminateAfterHandler() { tx.terminateAfterHandler(maxKeptServerTx) }

func (tx *ServerTx) terminateAfterHandler(limit int64) {
	tx.mu.Lock()
	var keep bool
	if tx.Origin().IsInvite() {
		keep = tx.timer_l != nil
	} else {
		keep = !tx.reliable && tx.timer_j != nil
	}
	select {
	case <-tx.done: // already deleted: nothing to count
		keep = false
	default:
	}
	if keep {
		if keptServerTx.Add(1) <= limit {
			tx.kept = true
		} else {
			keptServerTx.Add(-1)
			keep = false
		}
	}
	tx.mu.Unlock()
	if keep {
		return
	}
	tx.Terminate()
}

// func (tx *ServerTx) OnTerminate(f func()) {
// 	// NOT YET EXPOSED
// }

// Choose the right FSM init function depending on request method.
func (tx *ServerTx) initFSM() {
	if tx.Origin().IsInvite() {
		tx.baseTx.initFSM(tx.inviteStateProcceeding)
	} else {
		tx.baseTx.initFSM(tx.stateTrying)
	}
}

func (tx *ServerTx) delete() {
	tx.closeOnce.Do(func() {
		tx.mu.Lock()
		close(tx.done)
		if tx.kept {
			keptServerTx.Add(-1)
		}
		onterm := tx.onTerminate
		tx.mu.Unlock()
		if onterm != nil {
			onterm(tx.key)
		}
		// TODO with ref this can be added, but normally we expect client does closing
		// if _, err := tx.conn.TryClose(); err != nil {
		// 	tx.log.Info().Err(err).Msg("Closing connection returned error")
		// }
	})

	// time.Sleep(time.Microsecond)

	tx.mu.Lock()
	if tx.timer_i != nil {
		tx.timer_i.Stop()
		tx.timer_i = nil
	}
	if tx.timer_g != nil {
		tx.timer_g.Stop()
		tx.timer_g = nil
	}
	// tx.Log().Debug("transaction done")
	if tx.timer_h != nil {
		tx.timer_h.Stop()
		tx.timer_h = nil
	}
	if tx.timer_j != nil {
		tx.timer_j.Stop()
		tx.timer_j = nil
	}
	if tx.timer_1xx != nil {
		tx.timer_1xx.Stop()
		tx.timer_1xx = nil
	}
	// SIPCLIENT-MCP DIVERGENCE (CF-194): an Accepted INVITE now outlives its
	// handler, so an early delete (transport error, UA close) must also stop
	// Timer L instead of leaving its closure referencing the transaction.
	if tx.timer_l != nil {
		tx.timer_l.Stop()
		tx.timer_l = nil
	}
	tx.mu.Unlock()
	tx.log.Debug().Str("tx", tx.Key()).Msg("Server transaction destroyed")
}
