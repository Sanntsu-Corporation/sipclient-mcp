package session_test

import (
	"context"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// §13.3: when the artifact tree is over the watermark, sipua.UA.RecordStart is
// the single enforcement point (it is also the plan executor's direct call
// path) and returns resource_limit. ToolService.MediaRecordStart no longer
// computes this itself; this test proves it correctly PROPAGATES the agent's
// error rather than needing its own copy of the check.
func TestMediaRecordStartResourceLimitWhenOverWatermark(t *testing.T) {
	ua := fakes.NewUserAgent()
	ua.RecordStartErr = apierr.ResourceLimit("artifact.max_bytes", 1, 4096,
		"artifact store is over its high-watermark and only live-call data remains")
	art := fakes.NewArtifactStore()
	m, ts, ctx, uaHandle := newFixture(t, art, fakes.NewTap(),
		func(context.Context, session.UAConfig) (session.UserAgent, error) { return ua, nil })
	call, c := mustDial(t, m, ts, "s1", uaHandle, nil)

	_, err := ts.MediaRecordStart(ctx, "s1", session.MediaRecordStartInput{Call: call})
	if apierr.CodeOf(err) != apierr.CodeResourceLimit {
		t.Fatalf("code=%v err=%v want resource_limit", apierr.CodeOf(err), err)
	}
	evs, _, _ := c.Events(0)
	for _, e := range evs {
		if e.Type == session.EventRecordStart {
			t.Fatal("record_start event appended despite the watermark refusal")
		}
	}
}
