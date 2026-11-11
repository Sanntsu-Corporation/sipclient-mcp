package sipua_test

// Lane D (cf5-d) Task 2: one To tag per INVITE server transaction (CF-072,
// RFC 3261 8.2.6.2). No test calls t.Parallel.

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipua"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
)

const sdpUnsupported = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n"

// toTagFor returns the To tag of the first response with the given code.
func toTagFor(t *testing.T, r *rawUAC, code int) string {
	t.Helper()
	if !stubWait(func() bool { return r.hasCode("INVITE", code) }, 3*time.Second) {
		c, _ := r.responses("INVITE")
		t.Fatalf("no %d (got %v)", code, c)
	}
	codes, msgs := r.responses("INVITE")
	for i, c := range codes {
		if c == code {
			return tagOf(stubHeaders(msgs[i], "To")[0])
		}
	}
	return ""
}

func TestOneToTagForEveryFinal(t *testing.T) {
	ctx := context.Background()
	type row struct {
		name  string
		body  string
		extra string
		final int
		act   func(t *testing.T, ua *sipua.UA, r *rawUAC, ruri, cid, branch, tag180 string, in session.UAEvent, clk *fakeclock.Clock)
	}
	rows := []row{
		{"reject 486", stubSDP, "", 486, func(t *testing.T, ua *sipua.UA, _ *rawUAC, _, _, _, _ string, in session.UAEvent, _ *fakeclock.Clock) {
			if err := ua.Reject(ctx, in.DialogID, 486, ""); err != nil {
				t.Fatal(err)
			}
		}},
		{"ring timeout 480", stubSDP, "", 480, func(_ *testing.T, _ *sipua.UA, _ *rawUAC, _, _, _, _ string, _ session.UAEvent, clk *fakeclock.Clock) {
			clk.Advance(2 * time.Second)
		}},
		{"cancel 487", stubSDP, "", 487, func(_ *testing.T, _ *sipua.UA, r *rawUAC, ruri, cid, branch, _ string, _ session.UAEvent, _ *fakeclock.Clock) {
			r.send(r.request("CANCEL", ruri, cid, branch, 1, "", "", ""))
		}},
		{"early BYE 487", stubSDP, "", 487, func(_ *testing.T, _ *sipua.UA, r *rawUAC, ruri, cid, _, tag180 string, _ session.UAEvent, _ *fakeclock.Clock) {
			r.send(r.request("BYE", ruri, cid, "z9hG4bKcf5dTTbye", 2, tag180, "", ""))
		}},
		{"hangup 603", stubSDP, "", 603, func(t *testing.T, ua *sipua.UA, _ *rawUAC, _, _, _, _ string, in session.UAEvent, _ *fakeclock.Clock) {
			if err := ua.Hangup(ctx, in.DialogID, ""); err != nil {
				t.Fatal(err)
			}
		}},
		{"timer 422", stubSDP, "Supported: timer\r\nSession-Expires: 30\r\n", 422, func(t *testing.T, ua *sipua.UA, _ *rawUAC, _, _, _, _ string, in session.UAEvent, _ *fakeclock.Clock) {
			if err := ua.Answer(ctx, session.AnswerRequest{DialogID: in.DialogID}); err == nil {
				t.Fatal("Answer succeeded, want the 422 refusal")
			}
		}},
		{"codec 488", sdpUnsupported, "", 488, func(t *testing.T, ua *sipua.UA, _ *rawUAC, _, _, _, _ string, in session.UAEvent, _ *fakeclock.Clock) {
			if err := ua.Answer(ctx, session.AnswerRequest{DialogID: in.DialogID}); err == nil {
				t.Fatal("Answer succeeded, want the 488 refusal")
			}
		}},
		{"answer 200", stubSDP, "", 200, func(t *testing.T, ua *sipua.UA, _ *rawUAC, _, _, _, _ string, in session.UAEvent, _ *fakeclock.Clock) {
			if err := ua.Answer(ctx, session.AnswerRequest{DialogID: in.DialogID}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for i, rw := range rows {
		t.Run(rw.name, func(t *testing.T) {
			clk := fakeclock.New(time.Unix(0, 0))
			ua, _ := newDirectUA(t, clk)
			events := collect(t, ua)
			r := newRawUAC(t, ua)
			ruri := "sip:alice@" + ua.BoundAddr().String()
			cid := "cf5d-tt" + string(rune('a'+i)) + "@127.0.0.1"
			branch := "z9hG4bKcf5dTT" + string(rune('a'+i))
			r.send(r.request("INVITE", ruri, cid, branch, 1, "", rw.extra, rw.body))
			in := waitFor(t, events, session.UAEventInbound, 0)
			tag180 := toTagFor(t, r, 180)
			rw.act(t, ua, r, ruri, cid, branch, tag180, in, clk)
			if got := toTagFor(t, r, rw.final); got != tag180 {
				t.Errorf("%d carries To tag %q, the 180 carried %q", rw.final, got, tag180)
			}
		})
	}
}

func TestToTagIsSixtyFourBitsAndUnique(t *testing.T) {
	_, _, r, ruri := uasUA(t)
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	var tags []string
	for _, id := range []string{"a", "b"} {
		r.send(r.invite(ruri, "cf5d-uniq"+id+"@127.0.0.1", "z9hG4bKcf5dU"+id, 1, ""))
	}
	if !stubWait(func() bool {
		c, _ := r.responses("INVITE")
		n := 0
		for _, x := range c {
			if x == 180 {
				n++
			}
		}
		return n == 2
	}, 3*time.Second) {
		t.Fatal("want two 180s")
	}
	codes, msgs := r.responses("INVITE")
	for i, c := range codes {
		if c == 180 {
			tags = append(tags, tagOf(stubHeaders(msgs[i], "To")[0]))
		}
	}
	for _, tg := range tags {
		if !re.MatchString(tg) {
			t.Errorf("To tag %q is not 16 hex characters", tg)
		}
	}
	if len(tags) == 2 && tags[0] == tags[1] {
		t.Errorf("two INVITEs share To tag %q", tags[0])
	}
}
