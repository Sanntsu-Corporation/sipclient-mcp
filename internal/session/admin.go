package session

import (
	"context"
	"time"
)

// LiveUAs returns every LIVE UA on the server, across all sessions (§12.7).
//
// TERMINATED AND DESTROYED UAS ARE NOT INCLUDED: this is a live-object view,
// not §N3's retention view. It is the operator's input for deciding whether a
// UA is stranded, which is a human judgement — session_connected and
// session_last_seen_at are reported so a person can make it, and NO TIME-BASED
// RULE IS DERIVED FROM THEM (D11 point 5 is untouched).
//
// It exposes NO call_handle and no call content, so R11 is untouched: an agent
// still resolves only its own handles and the operator holds none.
func (m *Manager) LiveUAs(_ context.Context) []AdminUAView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AdminUAView, 0, len(m.uas))
	for _, s := range m.sessions {
		for _, u := range s.liveUAs {
			active := 0
			for _, c := range s.liveCalls {
				if c.uaHandle == u.handle {
					active++
				}
			}
			cfg := u.Config()
			out = append(out, AdminUAView{
				UAHandle:          string(u.handle),
				Session:           s.id,
				Mode:              cfg.Mode,
				AOR:               cfg.AOR,
				Transport:         string(cfg.Transport),
				Registered:        u.Registered(),
				ActiveCalls:       active,
				CreatedAt:         u.CreatedAt(),
				SessionConnected:  s.connected,
				SessionLastSeenAt: s.lastSeen,
			})
		}
	}
	return out
}

// AdminUAView is §12.7's worked JSON, field for field.
type AdminUAView struct {
	UAHandle          string    `json:"ua_handle"`
	Session           string    `json:"session"`
	Mode              string    `json:"mode"`
	AOR               string    `json:"aor"`
	Transport         string    `json:"transport"`
	Registered        bool      `json:"registered"`
	ActiveCalls       int       `json:"active_calls"`
	CreatedAt         time.Time `json:"created_at"`
	SessionConnected  bool      `json:"session_connected"`
	SessionLastSeenAt time.Time `json:"session_last_seen_at"`
}

// AdminDestroyed is the DELETE response body.
//
// Session is `json:"-"` DELIBERATELY. §12.7 requires the AUDIT LINE to carry the
// owning session id — an operator must be able to explain a UA that vanished —
// and the DELETE RESPONSE BODY not to. The id is a §12.6 credential factor;
// carrying it in the body would widen its exposure past the audit log's own
// access controls.
type AdminDestroyed struct {
	UAHandle        string `json:"ua_handle"`
	Unregistered    bool   `json:"unregistered"`
	CallsTerminated int    `json:"calls_terminated"`
	Session         string `json:"-"`
}
