package sipua

import (
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media/codec"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

func newStateLoop() *mediaLoop {
	ml := &mediaLoop{emit: func(session.UAEvent) {}}
	ml.assemble(nil, nil)
	return ml
}

func TestMediaStateIsASingleExclusionSlot(t *testing.T) {
	ml := newStateLoop()
	if !ml.claimOp(opPlay, codec.NewSineSource(1000)) {
		t.Fatal("first claim must win")
	}
	if ml.claimOp(opRecord, nil) {
		t.Fatal("a record claim during a play must fail (W5 semantics)")
	}
	if ml.claimOp(opDTMFInband, nil) {
		t.Fatal("an inband-DTMF claim during a play must fail")
	}
	ml.releaseOp()
	if !ml.claimOp(opDTMFInband, codec.NewSineSource(697)) {
		t.Fatal("the slot must be free after release")
	}
}

func TestReleaseOpRestoresThePriorSource(t *testing.T) {
	ml := newStateLoop()
	prior := ml.currentSrc()
	tone := codec.NewSineSource(941)
	if !ml.claimOp(opDTMFInband, tone) {
		t.Fatal("claim")
	}
	if ml.currentSrc() != codec.AudioSource(tone) {
		t.Fatal("claimOp did not install the supplied source")
	}
	ml.releaseOp()
	if ml.currentSrc() != prior {
		t.Fatal("releaseOp did not restore the prior source")
	}
}

func TestStoppedIsATerminalAbsorbingState(t *testing.T) {
	ml := newStateLoop()
	ml.stop()
	if !ml.isStopped() {
		t.Fatal("stop must mark the state stopped")
	}
	if ml.claimOp(opPlay, nil) {
		t.Fatal("every claim after stop must fail")
	}
	if ml.installRecorder(nil) {
		t.Fatal("installRecorder must refuse a stopped loop")
	}
}

func TestTakeRecorderResolvesToExactlyOneWinner(t *testing.T) {
	ml := newStateLoop()
	rec := &codec.WAVRecorder{}
	if !ml.installRecorder(rec) {
		t.Fatal("installRecorder")
	}
	if got := ml.takeRecorder(); got != rec {
		t.Fatalf("first take got %v want %v", got, rec)
	}
	if got := ml.takeRecorder(); got != nil {
		t.Fatal("the second take must observe nil — exactly one winner (§6.3)")
	}
}
