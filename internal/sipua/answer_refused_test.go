package sipua_test

// Lane D (cf5-d) Task 6 (CF-131): Answer reports a teardown as a typed
// *session.AnswerRefusedError and tells session its 200 is on the wire through
// AnswerRequest.OnAnswered, before any media starts. No test calls t.Parallel.

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
)

func TestAnswerRefusalsAreTyped(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extra, sdp string
		status     int
		code       apierr.Code
	}{
		{"422 interval below min_se_s", "Supported: timer\r\nSession-Expires: 30\r\n", stubSDP, 422, apierr.CodePreconditionFailed},
		{"488 no common codec", "", sdpUnsupported, 488, apierr.CodeMediaNegotiation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ua, events, r, ruri := uasUA(t)
			r.send(r.request("INVITE", ruri, "cf5d-ref"+strconv.Itoa(tc.status)+"@127.0.0.1", "z9hG4bKcf5dRF"+strconv.Itoa(tc.status), 1, "", tc.extra, tc.sdp))
			in := waitFor(t, events, session.UAEventInbound, 0)
			err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID})
			var refused *session.AnswerRefusedError
			if !errors.As(err, &refused) {
				t.Fatalf("Answer error %v is not a *session.AnswerRefusedError", err)
			}
			if refused.Status != tc.status {
				t.Errorf("Status = %d, want %d", refused.Status, tc.status)
			}
			if got := apierr.CodeOf(err); got != tc.code {
				t.Errorf("apierr code = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestAnswerCallsOnAnsweredOnceBeforeMedia(t *testing.T) {
	ua, events, r, ruri := uasUA(t)
	r.send(r.invite(ruri, "cf5d-oa@127.0.0.1", "z9hG4bKcf5dOA", 1, ""))
	in := waitFor(t, events, session.UAEventInbound, 0)
	calls, loopAtHook := 0, true
	err := ua.Answer(context.Background(), session.AnswerRequest{DialogID: in.DialogID, OnAnswered: func() {
		calls++
		_, loopAtHook = ua.QualityView(in.DialogID)
	}})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if calls != 1 {
		t.Errorf("OnAnswered called %d times, want 1", calls)
	}
	if loopAtHook {
		t.Error("the media loop was already running when OnAnswered ran")
	}
	if _, ok := ua.QualityView(in.DialogID); !ok {
		t.Error("no media loop after Answer returned")
	}
}

var mAudioPort = regexp.MustCompile(`m=audio (\d+) `)

// With the ACK racing the end of Answer, session's answered record still comes
// before the media_start the ACK's answer makes possible.
func TestOnAnsweredPrecedesMediaStartWhenTheAckRaces(t *testing.T) {
	c := startOfferless(t, "ord")
	sock, port := laneDMediaSocket(t)
	var mu sync.Mutex
	var order []string
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	c.ua.OnEvent(context.Background(), func(_ context.Context, ev session.UAEvent) {
		if ev.Kind == session.UAEventMediaStart {
			note("media_start")
		}
	})
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	sipua.SetAnswerRespondedHook(func() {
		c.wait200(t)
		c.goodAck(port)
		if !stubWait(func() bool { return sipua.DialogAckedForTest(c.ua, c.dlg) }, 3*time.Second) {
			t.Error("the ACK was not accepted during the answering window")
		}
		m := mAudioPort.FindStringSubmatch(c.ok)
		if m == nil {
			t.Error("no m=audio line in the 200")
			return
		}
		p, _ := strconv.Atoi(m[1])
		dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}
		go func() {
			for seq := uint16(0); ; seq++ {
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
				}
				pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8, SequenceNumber: seq, Timestamp: uint32(seq) * 160, SSRC: 7}, Payload: make([]byte, 160)}
				raw, _ := pkt.Marshal()
				_, _ = sock.WriteToUDP(raw, dst)
			}
		}()
		time.Sleep(100 * time.Millisecond) // RTP arrives while the dialog is still phaseAnswering
	})
	t.Cleanup(func() { sipua.SetAnswerRespondedHook(nil) })
	err := c.ua.Answer(context.Background(), session.AnswerRequest{DialogID: c.dlg, OnAnswered: func() { note("answered") }})
	sipua.SetAnswerRespondedHook(nil)
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !stubWait(func() bool { mu.Lock(); defer mu.Unlock(); return len(order) >= 2 }, 3*time.Second) {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("order %v, want [answered media_start]", order)
	}
	mu.Lock()
	defer mu.Unlock()
	if order[0] != "answered" || order[1] != "media_start" {
		t.Errorf("order %v, want [answered media_start]", order)
	}
}
