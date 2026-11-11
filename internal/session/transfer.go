package session

import "context"

// handleTransfer is the UAEventTransfer handler: §10.14's transfer event, with
// sipua's detail passed through unchanged — the flat-scalar convention
// session_refresh uses (decision 16). It resolves through
// callByDialogIDForEvent, not the live-only callByDialogID: the transferee's
// BYE (spec §4.5) routinely races the final NOTIFY, and the outcome must still
// land in the log that explains why the call ended.
func (m *Manager) handleTransfer(_ context.Context, uaHandle Handle, ev UAEvent) {
	c := m.callByDialogIDForEvent(uaHandle, ev.DialogID)
	if c == nil {
		return
	}
	c.Append(m.clk.Now(), EventTransfer, ev.Detail)
}
