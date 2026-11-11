package fakes

import (
	"context"
	"sync"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

var _ session.MediaSession = (*MediaSession)(nil)

// MediaSession is a hand-written fake of session.MediaSession. P1 wires no
// media, so this fake also serves as the shape a P1 no-op implementation
// takes: every method succeeds and records that it was called.
type MediaSession struct {
	mu sync.Mutex

	StartErr       error
	StopErr        error
	PlayErr        error
	RecordStartErr error
	RecordStopErr  error
	SendDTMFErr    error
	StatsResult    session.MediaStats
	StatsErr       error

	Starts       []session.MediaConfig
	StopCalls    int
	Played       []string
	RecordStarts []string
	RecordStops  int
	DTMFSent     []SentDTMF

	handler session.DTMFFunc
	hctx    context.Context
}

// SentDTMF is one recorded SendDTMF call.
type SentDTMF struct {
	Digits string
	Mode   session.DTMFMode
}

// NewMediaSession returns an empty MediaSession fake.
func NewMediaSession() *MediaSession { return &MediaSession{} }

// Start records the negotiated MediaConfig.
func (m *MediaSession) Start(_ context.Context, cfg session.MediaConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Starts = append(m.Starts, cfg)
	return m.StartErr
}

// Stop records that the media session was stopped.
func (m *MediaSession) Stop(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StopCalls++
	return m.StopErr
}

// Play records the prompt name played.
func (m *MediaSession) Play(_ context.Context, promptName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Played = append(m.Played, promptName)
	return m.PlayErr
}

// RecordStart records the artifact name recording started under.
func (m *MediaSession) RecordStart(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RecordStarts = append(m.RecordStarts, name)
	return m.RecordStartErr
}

// RecordStop records that recording was stopped.
func (m *MediaSession) RecordStop(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RecordStops++
	return m.RecordStopErr
}

// SendDTMF records the digits and mode sent.
func (m *MediaSession) SendDTMF(_ context.Context, digits string, mode session.DTMFMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DTMFSent = append(m.DTMFSent, SentDTMF{Digits: digits, Mode: mode})
	return m.SendDTMFErr
}

// Stats returns the scripted MediaStats.
func (m *MediaSession) Stats(_ context.Context) (session.MediaStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.StatsResult, m.StatsErr
}

// OnDTMF registers the single upward DTMF callback.
func (m *MediaSession) OnDTMF(ctx context.Context, fn session.DTMFFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handler = fn
	m.hctx = ctx
}

// EmitDTMF delivers a received-DTMF event upward.
func (m *MediaSession) EmitDTMF(ev session.DTMFEvent) {
	m.mu.Lock()
	fn, ctx := m.handler, m.hctx
	m.mu.Unlock()
	if fn != nil {
		fn(ctx, ev)
	}
}
