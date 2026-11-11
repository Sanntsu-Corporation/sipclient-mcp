package session

import "testing"

func TestMediaPlanViewZeroValue(t *testing.T) {
	var v MediaPlanView
	if v.Present {
		t.Fatal("zero MediaPlanView must not be Present")
	}
}
