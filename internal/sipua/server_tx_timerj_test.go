package sipua_test

import (
	"testing"
	"time"
)

// CF-194: a non-INVITE server transaction that sent its final response stays in
// Completed until Timer J (RFC 3261 17.2.2), so a retransmitted request is
// answered with the stored final and is not handled again.

func TestRetransmittedInDialogRequestIsAbsorbedByItsTransaction(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf194-info@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	info := func(branch string, cseq int) string {
		return r.request("INFO", ruri, cid, branch, cseq, tag, "Content-Type: application/dtmf-relay\r\n", "")
	}
	first := info("z9hG4bKcf194X", 11)
	r.send(first)
	if !stubWait(func() bool { return countCode(r, "INFO", 200) == 1 }, 2*time.Second) {
		t.Fatal("no 200 to INFO CSeq 11")
	}
	r.send(info("z9hG4bKcf194Y", 12))
	if !stubWait(func() bool { return countCode(r, "INFO", 200) == 2 }, 2*time.Second) {
		t.Fatal("no 200 to INFO CSeq 12")
	}
	r.send(first) // the retransmission of CSeq 11
	if !stubWait(func() bool { return countCode(r, "INFO", 200) == 3 }, 2*time.Second) {
		codes, _ := r.responses("INFO")
		t.Fatalf("the retransmitted INFO drew %v, want the stored 200 again (not a re-handled 500)", codes)
	}
	if countCode(r, "INFO", 500) != 0 {
		t.Error("the retransmission was handled again (500 out of order)")
	}
}

func TestRetransmittedByeGetsTheSameFinal(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	cid := "cf194-bye@127.0.0.1"
	tag := answeredTag(t, ua, events, r, ruri, cid)
	bye := r.request("BYE", ruri, cid, "z9hG4bKcf194Z", 11, tag, "", "")
	r.send(bye)
	if !stubWait(func() bool { return countCode(r, "BYE", 200) == 1 }, 2*time.Second) {
		t.Fatal("no 200 to the BYE")
	}
	r.send(bye)
	if !stubWait(func() bool { return countCode(r, "BYE", 200) == 2 }, 2*time.Second) {
		codes, _ := r.responses("BYE")
		t.Fatalf("the retransmitted BYE drew %v, want the same 200 (not 481)", codes)
	}
}
