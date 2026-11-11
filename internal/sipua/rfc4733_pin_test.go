package sipua_test

// Lane D (rfc-sweep-d) pins for RFC 4733 deviations seen as the offerer (6a
// D11). The answer's media socket is the test's: it reads our RTP and sends the
// crafted event packets (laneDOutbound in rfc3264_pin_test.go). Each pin passes
// today and must be inverted when its finding is fixed. No t.Parallel.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

const laneDBaseAnswer = "m=audio PORT RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n"

// laneDEndEvent sends a three-packet end of event (marker on the first when
// marker is set; an event already in flight has had its marker) and returns the
// next sequence number.
func laneDEndEvent(t *testing.T, c *laneDCall, seq uint16, ts uint32, code byte, dur uint16, marker bool) uint16 {
	t.Helper()
	for i := 0; i < 3; i++ {
		c.send(t, 101, marker && i == 0, seq, ts, laneDEvent(code, true, false, dur))
		seq++
	}
	return seq
}

// TestRFC4733_NEWD25_DigitOutsideThePeersEventsListIsRefused (CF-156, was the
// NEW-D-25 pin; RFC 4733 2.5.1.1, rfc4733.txt:604-606). The answer lists 0-11:
// "A" (event 12) is refused with invalid_argument and nothing reaches the wire;
// control: "5" is sent as event 5.
func TestRFC4733_NEWD25_DigitOutsideThePeersEventsListIsRefused(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, "m=audio PORT RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\na=sendrecv\r\n")
	_, _, err := c.ua.SendDTMF(context.Background(), c.dlg, "A", session.DTMFModeRFC2833, 100, 0)
	if apierr.CodeOf(err) != apierr.CodeInvalidArgument || !strings.Contains(err.Error(), "event 12") {
		t.Fatalf("SendDTMF(A) err = %v, want invalid_argument naming event 12", err)
	}
	// Nothing of the refused send reaches the wire: drain, then send the control.
	time.Sleep(500 * time.Millisecond)
	for drained := false; !drained; {
		select {
		case p := <-c.pkts:
			if p.PayloadType == 101 {
				t.Fatalf("an event packet (code %d) was sent for the refused digit", p.Payload[0])
			}
		default:
			drained = true
		}
	}
	if sent, _, err := c.ua.SendDTMF(context.Background(), c.dlg, "5", session.DTMFModeRFC2833, 100, 0); err != nil || sent != 1 {
		t.Fatalf("SendDTMF(5): sent=%d err=%v", sent, err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case p := <-c.pkts:
			if p.PayloadType == 101 && len(p.Payload) == 4 {
				if p.Payload[0] != 5 {
					t.Fatalf("event code %d, want 5", p.Payload[0])
				}
				return
			}
		case <-deadline:
			t.Fatal("no event packet reached the answer's media socket")
		}
	}
}

// TestRFC4733Pin_NEWD26_ZeroDurationEventIsReported pins NEW-D-26 (L18, D-EVT-05,
// RFC 4733 2.3.5: "The receiver SHOULD ignore an event report with zero duration
// if the event is not a state." rfc4733.txt:498-500). Evidence:
// evidence/u-rx/rtp.txt (digit 7 at duration 0, E on three packets; dtmf_received
// returns 7 with duration_ms 0). Locus: internal/sipua/medialoop.go:
// handleTelephoneEvent. Control: a normal digit 1 is reported first.
//
// PIN OF A DEVIATION: invert this assertion when NEW-D-26 is fixed.
func TestRFC4733Pin_NEWD26_ZeroDurationEventIsReported(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, laneDBaseAnswer)
	seq := laneDEndEvent(t, c, 1, 1000, 1, 480, true)
	waitForCond(t, func() bool { return c.reported("1") == 1 })
	laneDEndEvent(t, c, seq, 2000, 7, 0, true)
	time.Sleep(time.Second)
	if c.reported("7") == 0 {
		t.Fatal("the zero-duration digit 7 was not reported: NEW-D-26 is fixed, invert this pin")
	}
}

// TestRFC4733_NEWD27_LateEventPacketIsIgnored (CF-158, was the NEW-D-27 pin;
// RFC 4733 2.5.2.2, rfc4733.txt:947-961): a late intermediate packet of an event
// that already ended is ignored, so digit 5 is reported once. Control: digit 9.
func TestRFC4733_NEWD27_LateEventPacketIsIgnored(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, laneDBaseAnswer)
	seq := uint16(1)
	for i, d := range []uint16{160, 320, 480} {
		c.send(t, 101, i == 0, seq, 4000, laneDEvent(5, false, false, d))
		seq++
	}
	seq = laneDEndEvent(t, c, seq, 4000, 5, 480, false)
	c.send(t, 101, false, seq, 4000, laneDEvent(5, false, false, 320)) // late intermediate packet
	seq++
	c.send(t, 101, true, seq, 5000, laneDEvent(9, false, false, 160))
	seq++
	laneDEndEvent(t, c, seq, 5000, 9, 480, false)
	waitForCond(t, func() bool { return c.reported("9") == 1 })
	if n := c.reported("5"); n != 1 {
		t.Fatalf("digit 5 reported %d times, want exactly once", n)
	}
}

// TestRFC4733_NEWD31_LongEventSegmentsAddUp (CF-162, was the NEW-D-31 pin; RFC
// 4733 2.5.2.3, rfc4733.txt:991-994): the segments of a long event add up, so
// digit 8 is reported once at 8231 ms.
func TestRFC4733_NEWD31_LongEventSegmentsAddUp(t *testing.T) {
	c := laneDOutbound(t, []string{"PCMU"}, laneDBaseAnswer)
	c.send(t, 101, true, 1, 8000, laneDEvent(8, false, false, 160))
	c.send(t, 101, false, 2, 8000, laneDEvent(8, false, false, 0xFFFF))
	c.send(t, 101, false, 3, 8000+0xFFFF, laneDEvent(8, false, false, 160))
	laneDEndEvent(t, c, 4, 8000+0xFFFF, 8, 320, false)
	waitForCond(t, func() bool { return c.reported("8") >= 1 })
	time.Sleep(200 * time.Millisecond)
	if n := c.reported("8"); n != 1 {
		t.Fatalf("digit 8 reported %d times, want once", n)
	}
	for _, ev := range c.dtmfReports() {
		if ev.Digit == "8" && ev.DurationMs != 8231 {
			t.Fatalf("digit 8 duration_ms %d, want 8231 (both segments)", ev.DurationMs)
		}
	}
}
