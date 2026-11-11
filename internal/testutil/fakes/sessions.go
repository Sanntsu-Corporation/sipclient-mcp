package fakes

import (
	"context"
	"sync"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/clock"
)

// Sessions is a fake logical-session registry. It models exactly what §12.6
// gives internal/session: a record exists while it owns any live object, and
// an EMPTY record ages out after ResumeWindow measured on the INJECTED clock
// (locked decision 18) — never on wall time.
//
// THE AGEING RULE IS THE POINT, AND IT MUST BE REAL. An Alive that always
// returned true would make P1d's entire §12.6 identity matrix pass — every
// unknown-id case included — while proving nothing at all, and this wave has
// already shipped tests of exactly that shape. The two halves are asymmetric
// and both are load-bearing: a record owning ANY live object survives with NO
// deadline (D11 point 5: a live UA is never destroyed by the passage of
// time), while an empty one is gone once the window elapses.
//
// It holds NO clock of its own: internal/clock is the production interface
// and internal/testutil/fakeclock the test fake, and a third would be a
// Rule 18 defect.
type Sessions struct {
	Clock        clock.Clock
	ResumeWindow time.Duration

	// OpenErr, when non-nil, makes Open fail with this error instead of
	// creating a record — lets a transport-layer test simulate ANY
	// Sessions.Open failure (this cap included) without needing a real
	// session.Manager. Zero value nil preserves every existing caller's
	// behavior unchanged.
	OpenErr error

	mu   sync.Mutex
	recs map[string]*sessionRec
}

type sessionRec struct {
	liveObjects int
	emptySince  time.Time
	lastSeen    time.Time
}

// NewSessions returns an empty Sessions fake reading c, ageing empty records
// out after window.
func NewSessions(c clock.Clock, window time.Duration) *Sessions {
	return &Sessions{Clock: c, ResumeWindow: window, recs: map[string]*sessionRec{}}
}

// Open creates a logical session record under a server-issued id.
func (s *Sessions) Open(_ context.Context, id string) error {
	if s.OpenErr != nil {
		return s.OpenErr
	}
	now := s.Clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[id] = &sessionRec{emptySince: now, lastSeen: now}
	return nil
}

// Alive reports whether the record still exists. A record owning a live
// object does, with NO deadline; an EMPTY record past the resume window does
// not, and is reaped on the way out so the map does not grow without bound.
func (s *Sessions) Alive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return false
	}
	if r.liveObjects > 0 {
		return true
	}
	if s.Clock.Now().Sub(r.emptySince) >= s.ResumeWindow {
		delete(s.recs, id)
		return false
	}
	return true
}

// Seen records that the session was contacted, feeding §12.7's
// session_last_seen_at. It deliberately does NOT reset emptySince: §12.6 ages
// out an empty record on the resume window, and letting a bare poll refresh
// that window would keep an abandoned session alive forever.
func (s *Sessions) Seen(id string) {
	now := s.Clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.recs[id]; ok {
		r.lastSeen = now
	}
}

// AddLiveObject models ua_create, or an inbound INVITE creating a call on a
// UA this session owns.
func (s *Sessions) AddLiveObject(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.recs[id]; ok {
		r.liveObjects++
	}
}

// DropLiveObject models ua_destroy, or a call terminating. The resume window
// starts counting only when the LAST live object goes away.
func (s *Sessions) DropLiveObject(id string) {
	now := s.Clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok || r.liveObjects == 0 {
		return
	}
	r.liveObjects--
	if r.liveObjects == 0 {
		r.emptySince = now
	}
}
