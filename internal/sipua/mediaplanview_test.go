package sipua

import "testing"

func TestMediaPlanViewAbsentWithNoPlan(t *testing.T) {
	u := &UA{}
	ml := &mediaLoop{}
	ml.assemble(nil, nil)
	d := &dialog{id: "d1", phase: phaseAnswered, mediaLoop: ml}
	u.register(d)
	if _, ok := u.MediaPlanView("d1"); ok {
		t.Fatal("MediaPlanView reported present with no plan running")
	}
	if _, ok := u.MediaPlanView("unknown"); ok {
		t.Fatal("MediaPlanView reported present for an unknown dialog")
	}
}
