package quality

import "testing"

func TestAccumulatorCountersAndLossPct(t *testing.T) {
	a := New()
	for i := 0; i < 100; i++ {
		a.RecordSent()
		a.RecordReceived()
	}
	// 5 concealed (lost) slots on top of 100 received => loss_pct 5/(105).
	for i := 0; i < 5; i++ {
		a.RecordConcealed()
	}
	a.RecordOutOfOrder()
	a.RecordDuplicate()
	a.RecordLateDiscard()
	a.RecordSRTPAuthFailure()
	a.RecordRogueSource()
	a.RecordTXUnderrun(3)

	s := a.Snapshot("PCMU", 2100, 60)
	if s.PacketsReceived != 100 || s.PacketsLost != 5 {
		t.Fatalf("received=%d lost=%d", s.PacketsReceived, s.PacketsLost)
	}
	if s.LossPct < 4.5 || s.LossPct > 5.0 {
		t.Fatalf("loss_pct=%.2f want ~4.76", s.LossPct)
	}
	if s.OutOfOrder != 1 || s.Duplicates != 1 || s.LateDiscards != 1 {
		t.Fatalf("ooo/dup/late = %d/%d/%d", s.OutOfOrder, s.Duplicates, s.LateDiscards)
	}
	if s.SRTPAuthFailures != 1 || s.RogueSourcePackets != 1 || s.TXUnderruns != 3 {
		t.Fatalf("srtp/rogue/underrun = %d/%d/%d", s.SRTPAuthFailures, s.RogueSourcePackets, s.TXUnderruns)
	}
}

// §15.1 O2: an srtp_auth_failure is disjoint from packets_lost and must not move
// mos_estimate relative to a clean run.
func TestSRTPAuthFailureDoesNotDepressMOS(t *testing.T) {
	clean := New()
	for i := 0; i < 100; i++ {
		clean.RecordSent()
		clean.RecordReceived()
		clean.RecordJitterSample(float64(i % 3))
	}
	cleanSnap := clean.Snapshot("PCMU", 2000, 60)

	authfail := New()
	for i := 0; i < 100; i++ {
		authfail.RecordSent()
		authfail.RecordReceived()
		authfail.RecordJitterSample(float64(i % 3))
	}
	for i := 0; i < 10; i++ {
		authfail.RecordSRTPAuthFailure()
	}
	authSnap := authfail.Snapshot("PCMU", 2000, 60)

	if authSnap.PacketsLost != cleanSnap.PacketsLost {
		t.Fatalf("auth failures moved packets_lost: %d vs %d", authSnap.PacketsLost, cleanSnap.PacketsLost)
	}
	if authSnap.MOSEstimate != cleanSnap.MOSEstimate {
		t.Fatalf("auth failures moved mos_estimate: %.3f vs %.3f", authSnap.MOSEstimate, cleanSnap.MOSEstimate)
	}
}

func TestBurstGaps(t *testing.T) {
	a := New()
	a.RecordBurstGap(120, 3)
	s := a.Snapshot("PCMU", 1000, 60)
	if len(s.BurstGaps) != 1 || s.BurstGaps[0].AtMs != 120 || s.BurstGaps[0].Packets != 3 {
		t.Fatalf("burst_gaps=%v", s.BurstGaps)
	}
}
