package mcp

import (
	"context"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// Sessions is the narrow, consumer-side view internal/transport/mcp takes of
// internal/session (Go convention, §6.2.1 style). internal/session is
// authoritative for liveness, ownership and the §12.6 resume window; this
// package never re-derives any of them.
//
// It is SATISFIED DIRECTLY BY *session.Manager (contract Part 3): Open, Alive
// and Seen are registry operations Manager already owns and guards, so an
// adapter forwarding three calls unchanged would be a layer with no behaviour
// (Rule 15).
//
// THIS IS THE ONLY DECLARATION OF Sessions IN THE TREE. Task 17's Interfaces
// block references it; it does not restate it.
type Sessions interface {
	// Open creates a logical session record under a server-issued id.
	// Idempotent.
	Open(ctx context.Context, id string) error
	// Alive reports whether a record with this id currently exists AND has
	// not passed its fixed 5-minute TTL (Phase 1, owner-locked decision,
	// superseding the old "owns a live UA or call -> no deadline" rule). This
	// is the transport's choke point: a non-Alive session 404s every
	// non-initialize request and its identity binding is dropped
	// (resolve/sessionIDMiddleware, server.go), so the TTL becomes observable
	// here with no separate plumbing.
	Alive(id string) bool
	// Seen records that the session was contacted, feeding §12.7's
	// session_last_seen_at and §12.6's resume-window clock.
	Seen(id string)
}

// Tools is the consumer-side view of §10's thirteen P1 MCP tools, satisfied
// directly by *session.ToolService (contract Part 3, §2.8). Declared here per
// D202: Task 17 builds Config whole and NewServer's construction path
// references Tools, so the type is authored once, in this package's single
// dependency-declaration file, rather than split across the task that first
// needs it (17) and the task that fills in registration (18, tools.go).
type Tools interface {
	UACreate(ctx context.Context, sess string, in session.UACreateInput) (any, error)
	// SessionKeepalive is D2/D7's session_keepalive (Phase 1): resets the
	// caller's 5-minute session TTL and returns {session_cookie, expires_at}.
	SessionKeepalive(ctx context.Context, sess string, in session.SessionKeepaliveInput) (any, error)
	UAStatus(ctx context.Context, sess string, in session.UAStatusInput) (any, error)
	UADestroy(ctx context.Context, sess string, in session.UADestroyInput) (any, error)
	CallDial(ctx context.Context, sess string, in session.CallDialInput) (any, error)
	CallAnswer(ctx context.Context, sess string, in session.CallAnswerInput) (any, error)
	CallReject(ctx context.Context, sess string, in session.CallRejectInput) (any, error)
	CallHangup(ctx context.Context, sess string, in session.CallHangupInput) (any, error)
	CallStatus(ctx context.Context, sess string, in session.CallStatusInput) (any, error)
	CallList(ctx context.Context, sess string, in session.CallListInput) (any, error)
	CallWait(ctx context.Context, sess string, in session.CallWaitInput) (any, error)
	CallEvents(ctx context.Context, sess string, in session.CallEventsInput) (any, error)
	CallLadder(ctx context.Context, sess string, in session.CallLadderInput) (any, error)
	CaptureStart(ctx context.Context, sess string, in session.CaptureStartInput) (any, error)
	CaptureStop(ctx context.Context, sess string, in session.CaptureStopInput) (any, error)
	QualityGet(ctx context.Context, sess string, in session.QualityGetInput) (any, error)
	MediaPlay(ctx context.Context, sess string, in session.MediaPlayInput) (any, error)
	MediaRecordStart(ctx context.Context, sess string, in session.MediaRecordStartInput) (any, error)
	MediaRecordStop(ctx context.Context, sess string, in session.MediaRecordStopInput) (any, error)
	DTMFSend(ctx context.Context, sess string, in session.DTMFSendInput) (any, error)
	DTMFReceived(ctx context.Context, sess string, in session.DTMFReceivedInput) (any, error)

	// CallTransfer is call_transfer (master spec §10.14; spec 2026-09-26 §4.1).
	CallTransfer(ctx context.Context, sess string, in session.CallTransferInput) (any, error)

	// ConfigGet, ConfigSet and AdminTokenRotate are Phase 2's three
	// admin-scoped tools (§2.4a). Admin scoping itself is enforced in THIS
	// package (identityStore.isAdmin, wired at registration in tools.go's
	// adminGate), not by session: session.ToolService has no visibility
	// into which token authenticated sess, only the session id string every
	// other Tools method already gets.
	ConfigGet(ctx context.Context, sess string, in session.ConfigGetInput) (any, error)
	ConfigSet(ctx context.Context, sess string, in session.ConfigSetInput) (any, error)
	AdminTokenRotate(ctx context.Context, sess string, in session.AdminTokenRotateInput) (any, error)
}

// Admin is the consumer-side view of §12.7's operator plane, satisfied
// directly by *session.Manager (contract Part 3). Declared here per D202
// alongside Sessions and Tools, one authoring pass (Rule 18): Config (built
// whole in Task 17) and Handler()'s registerAdminRoutes call both reference
// it before Task 19 supplies registerAdminRoutes' body.
type Admin interface {
	// LiveUAs returns every LIVE UA on the server, across all sessions.
	// Terminated and destroyed UAs are NOT included — a live-object view, not
	// the §N3 retention view.
	LiveUAs(ctx context.Context) []session.AdminUAView

	// DestroyUA resolves the UA and destroys it (§12.7): BYE every live
	// dialog, REGISTER Expires: 0 if registered, then destroy and leave the
	// §N3 terminated registry entry behind. Returns apierr.Error with
	// CodeNotFound when no LIVE UA bears the handle, including one already
	// destroyed. Full teardown-context and lock-release properties are
	// internal/session's (P1b Task 11a); this package is a thin caller.
	DestroyUA(ctx context.Context, uaHandle string) (session.AdminDestroyed, error)
}

// ReadyStatus is §5 N5's readiness payload, rendered as JSON verbatim by both
// the 200 and 503 /readyz responses (BuildReadyStatus, observability.go).
type ReadyStatus struct {
	Ready               bool   `json:"ready"`
	PolicyLoadedAt      string `json:"policy_loaded_at"`
	ArtifactDirWritable bool   `json:"artifact_dir_writable"`
	UptimeS             int64  `json:"uptime_s"`
}

// ReadyFunc reports §5 N5 readiness. Declared here per D202 so Config (built
// whole in Task 17) compiles standalone; Task 21 supplies the real ReadyStatus
// fields and BuildReadyStatus.
type ReadyFunc func() ReadyStatus
