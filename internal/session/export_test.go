package session

import "context"

// HandleUAEventForTest exposes handleUAEvent to session_test for the media_start
// mapping test above; no other external test needs it yet.
func (m *Manager) HandleUAEventForTest(ctx context.Context, uaHandle Handle, ev UAEvent) {
	m.handleUAEvent(ctx, uaHandle, ev)
}

// SetDialErrorHook installs (or clears, with nil) the barrier CallDial's
// dial-error branch runs last, so a test can wait until that branch has
// attempted its terminal claim. Tests using it must not run in parallel.
func SetDialErrorHook(fn func()) { dialErrorHook = fn }
