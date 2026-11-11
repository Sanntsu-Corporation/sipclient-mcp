package metrics

import (
	"strings"
	"testing"
)

func TestCountersAndWriteText(t *testing.T) {
	r := New([]string{"local_hangup", "remote_bye"})
	r.AddActiveCalls(2)
	r.AddActiveUAs(1)
	r.IncCallsTotal()
	r.IncCallsTotal()
	r.IncTerminationReason("local_hangup")
	r.IncWebhookBlocked()
	r.IncJanitorSweeps()
	r.IncPolicyReloadFailures()

	var sb strings.Builder
	if err := r.WriteText(&sb); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	got := sb.String()
	want := []string{
		"active_calls 2\n",
		"active_uas 1\n",
		"calls_total 2\n",
		`calls_by_termination_reason{reason="local_hangup"} 1` + "\n",
		`calls_by_termination_reason{reason="remote_bye"} 0` + "\n",
		"webhook_delivery_failures 0\n",
		"webhook_blocked 1\n",
		"janitor_sweeps_total 1\n",
		"janitor_bytes_reclaimed_total 0\n",
		"tx_underruns_total 0\n",
		"policy_reload_failures_total 1\n",
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("WriteText output missing line %q; got:\n%s", line, got)
		}
	}
}

func TestIncTerminationReasonPanicsOnUnknownReason(t *testing.T) {
	r := New([]string{"local_hangup"})
	defer func() {
		if recover() == nil {
			t.Fatal("IncTerminationReason(unknown) did not panic")
		}
	}()
	r.IncTerminationReason("not_a_real_reason")
}

// TestHasReason pins the I1 guard's precondition: HasReason must reflect
// exactly the set New was given, so callers can skip IncTerminationReason's
// by-design panic on a label outside that set.
func TestHasReason(t *testing.T) {
	r := New([]string{"local_hangup", "remote_bye"})
	if !r.HasReason("local_hangup") {
		t.Error("HasReason(\"local_hangup\") = false, want true (registered at New)")
	}
	if !r.HasReason("remote_bye") {
		t.Error("HasReason(\"remote_bye\") = false, want true (registered at New)")
	}
	if r.HasReason("weird_unregistered") {
		t.Error("HasReason(\"weird_unregistered\") = true, want false (never registered)")
	}
}
