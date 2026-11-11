package media

import "testing"

func frame(v int16) []int16 { return []int16{v} }

func TestSeqDeltaWrap(t *testing.T) {
	if d := SeqDelta(0, 65535); d != 1 {
		t.Fatalf("SeqDelta(0,65535)=%d want 1", d)
	}
	if d := SeqDelta(65535, 0); d != -1 {
		t.Fatalf("SeqDelta(65535,0)=%d want -1", d)
	}
	if d := SeqDelta(5, 2); d != 3 {
		t.Fatalf("SeqDelta(5,2)=%d want 3", d)
	}
}

// §6.5.1 acceptance: a 3-packet reorder within window is fully corrected —
// out_of_order == 3, packets_lost == 0.
func TestJitterBufferReorderWithinWindow(t *testing.T) {
	jb := NewJitterBuffer(3)
	if o := jb.Push(1, frame(1)); o != OutcomePlaced {
		t.Fatalf("push 1: %v", o)
	}
	jb.Push(2, frame(2))
	jb.Push(3, frame(3))
	if o := jb.Push(7, frame(7)); o != OutcomePlaced {
		t.Fatalf("push 7: %v", o)
	}
	reorders := 0
	for _, s := range []uint16{6, 5, 4} {
		if jb.Push(s, frame(int16(s))) == OutcomeReorder {
			reorders++
		}
	}
	if reorders != 3 {
		t.Fatalf("out_of_order=%d want 3", reorders)
	}
	// Every slot 1..7 is now filled: seven pops, all present, zero gaps.
	for want := int16(1); want <= 7; want++ {
		f, present := jb.Pop()
		if !present || f[0] != want {
			t.Fatalf("pop want %d present, got %v present=%v", want, f, present)
		}
	}
}

// §6.5.1 acceptance: a packet delayed past the window is late_discards, and its
// empty slot at playout is the source of the single packets_lost.
func TestJitterBufferLateDiscard(t *testing.T) {
	jb := NewJitterBuffer(3)
	jb.Push(1, frame(1))
	jb.Push(2, frame(2))
	jb.Push(3, frame(3))
	// Play out 1,2,3, then a gap at 4 (empty slot -> the loss).
	for want := int16(1); want <= 3; want++ {
		if f, present := jb.Pop(); !present || f[0] != want {
			t.Fatalf("pop %d: %v present=%v", want, f, present)
		}
	}
	if _, present := jb.Pop(); present {
		t.Fatal("slot 4 must be an empty (lost) slot at playout")
	}
	// Now seq 4 arrives late — its slot has already been played out.
	if o := jb.Push(4, frame(4)); o != OutcomeLate {
		t.Fatalf("late push classified %v want OutcomeLate", o)
	}
}

// §6.5.1 acceptance: a duplicate is dropped and never inflates packets_received.
func TestJitterBufferDuplicate(t *testing.T) {
	jb := NewJitterBuffer(3)
	jb.Push(1, frame(1))
	jb.Push(2, frame(2))
	if o := jb.Push(2, frame(99)); o != OutcomeDuplicate {
		t.Fatalf("duplicate push classified %v want OutcomeDuplicate", o)
	}
	// The original frame survives, not the duplicate's payload.
	jb.Pop()
	if f, _ := jb.Pop(); f[0] != 2 {
		t.Fatalf("duplicate overwrote slot: got %d want 2", f[0])
	}
}
