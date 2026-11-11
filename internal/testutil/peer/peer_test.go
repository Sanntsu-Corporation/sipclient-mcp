package peer

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPeerChallengesThenAccepts(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0", AuthUser: "alice", AuthPass: "s3cr3t"})
	defer p.Close()

	conn, err := net.Dial("udp", p.Addr())
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := "REGISTER sip:" + p.Addr() + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + conn.LocalAddr().String() + ";branch=z9hG4bK-1\r\n" +
		"From: <sip:alice@example>;tag=t1\r\n" +
		"To: <sip:alice@example>\r\n" +
		"Call-ID: peer-test-1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Max-Forwards: 70\r\n" +
		"Contact: <sip:alice@" + conn.LocalAddr().String() + ">\r\n" +
		"Expires: 300\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write REGISTER: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "SIP/2.0 401 ") {
		t.Fatalf("want a 401 challenge, got:\n%s", got)
	}
	if !strings.Contains(got, "WWW-Authenticate: Digest realm=") {
		t.Errorf("401 carries no digest challenge:\n%s", got)
	}
	if p.Count("REGISTER") != 1 {
		t.Errorf("peer REGISTER count = %d, want 1", p.Count("REGISTER"))
	}
	if p.LastExpires() != 300 {
		t.Errorf("peer LastExpires = %d, want 300", p.LastExpires())
	}
	if p.LastVia() != conn.LocalAddr().String() {
		t.Errorf("peer LastVia = %q, want %q", p.LastVia(), conn.LocalAddr().String())
	}
}

// TestDialExpectingStatusAndLastInboundFinalStatus exercises D308's widened
// surface: two peers, one dialling the other's default-answer behaviour.
// DialExpectingStatus drives the call AND blocks for the observed status;
// LastInboundFinalStatus is the UAS side's own record of what it sent.
func TestDialExpectingStatusAndLastInboundFinalStatus(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uas.Close()
	uac := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uac.Close()

	got := uac.DialExpectingStatus(t, "sip:bob@"+uas.Addr())
	if got != 200 {
		t.Fatalf("DialExpectingStatus = %d, want 200", got)
	}
	if n := uas.InviteCount(); n != 1 {
		t.Fatalf("uas.InviteCount() = %d, want 1", n)
	}
	if got := uas.LastInboundFinalStatus(); got != 200 {
		t.Fatalf("uas.LastInboundFinalStatus() = %d, want 200", got)
	}
	if n := uac.FinalResponseCount(); n != 1 {
		t.Fatalf("uac.FinalResponseCount() = %d, want 1", n)
	}
	// LastViaHostPort, on the UAS side, is the DIALLER's address — the Via
	// of the last request the UAS received.
	if got := uas.LastViaHostPort(); got != uac.Addr() {
		t.Fatalf("uas.LastViaHostPort() = %q, want the dialler's address %q", got, uac.Addr())
	}
}

// TestWaitForByeAndByeCount exercises SendFinal's twin, WaitForBye/ByeCount:
// the UAS side (which answered) hangs up, and the UAC side observes the BYE.
func TestWaitForByeAndByeCount(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uas.Close()
	uac := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uac.Close()

	if got := uac.DialExpectingStatus(t, "sip:bob@"+uas.Addr()); got != 200 {
		t.Fatalf("DialExpectingStatus = %d, want 200", got)
	}
	// uas ACCEPTED the call as UAS, so it — not uac — is the one SendBye can
	// address (D128/D305: no dialog argument, "the most recent call this
	// peer accepted as UAS").
	uas.SendBye(t)
	uac.WaitForBye(t, time.Second)
	if n := uac.ByeCount(); n != 1 {
		t.Fatalf("uac.ByeCount() = %d, want 1", n)
	}
}

// TestSendFinalAddressesByCallID proves SendFinal's dialogID parameter is
// genuinely load-bearing (a real, peer-observed SIP Call-ID), not the same
// dead parameter D128/D305 found on SendBye's stale contract signature: two
// concurrent inbound INVITEs are answered with DIFFERENT chosen statuses,
// addressed by their distinct Call-IDs.
func TestSendFinalAddressesByCallID(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0", Behaviour: Behaviour{AnswerAfter: time.Hour}})
	defer uas.Close()
	uac1 := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uac1.Close()
	uac2 := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uac2.Close()

	// A long AnswerAfter means inviteFlow will not answer on its own within
	// this test's lifetime; SendFinal races it deliberately.
	uac1.Dial(t, "sip:bob@"+uas.Addr())
	uac2.Dial(t, "sip:bob@"+uas.Addr())

	deadline := time.Now().Add(2 * time.Second)
	for uas.InviteCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("uas.InviteCount() = %d after 2s, want 2", uas.InviteCount())
		}
		time.Sleep(5 * time.Millisecond)
	}

	uas.mu.Lock()
	var callIDs []string
	for id := range uas.inboundInvites {
		callIDs = append(callIDs, id)
	}
	uas.mu.Unlock()
	if len(callIDs) != 2 {
		t.Fatalf("recorded %d distinct inbound Call-IDs, want 2", len(callIDs))
	}

	uas.SendFinal(t, callIDs[0], 200)
	uas.SendFinal(t, callIDs[1], 486)

	deadline = time.Now().Add(2 * time.Second)
	for uac1.FinalResponseCount() == 0 || uac2.FinalResponseCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("final responses not observed within 2s: uac1=%d uac2=%d",
				uac1.FinalResponseCount(), uac2.FinalResponseCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
	got1, got2 := uac1.LastFinalStatus(), uac2.LastFinalStatus()
	wantPair := (got1 == 200 && got2 == 486) || (got1 == 486 && got2 == 200)
	if !wantPair {
		t.Fatalf("final statuses = %d, %d — want one 200 and one 486, addressed by distinct Call-IDs",
			got1, got2)
	}
}

// TestInviteFlowAppendsSessionExpiresAndAllowOnTheInitialAnswer is the
// regression test for the wave review's Critical #1: EVERY downstream RFC
// 4028 consumer (Tasks 27/29/30) needs Session-Expires/Allow on the INITIAL
// INVITE's 200, not only on a later in-dialog refresh response — Task 29's
// refreshMethodFor in particular branches on whether THIS answer's own Allow
// lists UPDATE, and no session timer is armed at all without Session-Expires
// here.
func TestInviteFlowAppendsSessionExpiresAndAllowOnTheInitialAnswer(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0", Behaviour: Behaviour{
		AnswerSessionExpires: "1800;refresher=uac",
		AnswerAllow:          "INVITE, ACK, BYE, CANCEL, INFO, UPDATE",
	}})
	defer uas.Close()
	uac := Start(t, Config{Addr: "127.0.0.1:0"})
	defer uac.Close()

	if got := uac.DialExpectingStatus(t, "sip:bob@"+uas.Addr()); got != 200 {
		t.Fatalf("DialExpectingStatus = %d, want 200", got)
	}
	if got := uac.LastResponseHeader("INVITE", 200, "Session-Expires"); got != "1800;refresher=uac" {
		t.Fatalf("Session-Expires on the INITIAL 200 OK = %q, want the configured value", got)
	}
	if got := uac.LastResponseHeader("INVITE", 200, "Allow"); got != "INVITE, ACK, BYE, CANCEL, INFO, UPDATE" {
		t.Fatalf("Allow on the INITIAL 200 OK = %q, want the configured value", got)
	}
}

// TestReject422MinSEForcesARetryOnTheSameCallID is the regression test for
// Critical #1's second half — see Behaviour.Reject422MinSE's own doc comment
// for the exact contract (unconditional first rejection; the retry must
// reuse the same Call-ID). Driven over a raw socket (rather than peer.Dial,
// which always mints a fresh Call-ID) so this test controls the Call-ID/CSeq
// of both attempts directly, independent of whether any UA-side retry logic
// exists yet (it does not, until Task 27).
func TestReject422MinSEForcesARetryOnTheSameCallID(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0", Behaviour: Behaviour{Reject422MinSE: 1800}})
	defer uas.Close()

	conn, err := net.Dial("udp", uas.Addr())
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	send := func(cseq int, sessionExpiresHeader string) string {
		t.Helper()
		req := "INVITE sip:bob@" + uas.Addr() + " SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP " + conn.LocalAddr().String() + ";branch=z9hG4bK-" + strconv.Itoa(cseq) + "\r\n" +
			"From: <sip:alice@example>;tag=t1\r\n" +
			"To: <sip:bob@example>\r\n" +
			"Call-ID: reject422-retry-test\r\n" +
			"CSeq: " + strconv.Itoa(cseq) + " INVITE\r\n" +
			"Max-Forwards: 70\r\n" +
			"Contact: <sip:alice@" + conn.LocalAddr().String() + ">\r\n" +
			sessionExpiresHeader +
			"Content-Length: 0\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write INVITE: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			got := string(buf[:n])
			if strings.HasPrefix(got, "SIP/2.0 100 ") || strings.HasPrefix(got, "SIP/2.0 180 ") {
				continue // skip provisionals on the accepted retry
			}
			return got
		}
	}

	// First attempt already carries a Session-Expires that WOULD meet the
	// floor — the peer must still reject it, unconditionally, exactly once.
	first := send(1, "Session-Expires: 1800\r\n")
	if !strings.HasPrefix(first, "SIP/2.0 422 ") {
		t.Fatalf("first attempt = %q, want 422 (unconditional on the first try)", first)
	}
	if !strings.Contains(first, "Min-SE: 1800") {
		t.Fatalf("422 carries no Min-SE: 1800:\n%s", first)
	}

	// Retry: SAME Call-ID, raised CSeq, Session-Expires meeting the floor.
	retry := send(2, "Session-Expires: 1800\r\n")
	if !strings.HasPrefix(retry, "SIP/2.0 200 ") {
		t.Fatalf("retry on the same Call-ID meeting the floor = %q, want 200", retry)
	}
}

// TestRegisterOmitsExpiresWhenConfigured is the regression test for Critical
// #1's third fix: OmitRegisterExpires must drop the Expires header from the
// REGISTER's 200 OK entirely, simulating a registrar that never echoes it —
// previously declared but consulted nowhere.
func TestRegisterOmitsExpiresWhenConfigured(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0", Behaviour: Behaviour{OmitRegisterExpires: true}})
	defer p.Close()

	conn, err := net.Dial("udp", p.Addr())
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := "REGISTER sip:" + p.Addr() + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + conn.LocalAddr().String() + ";branch=z9hG4bK-omit\r\n" +
		"From: <sip:alice@example>;tag=t1\r\n" +
		"To: <sip:alice@example>\r\n" +
		"Call-ID: omit-expires-test\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Max-Forwards: 70\r\n" +
		"Contact: <sip:alice@" + conn.LocalAddr().String() + ">\r\n" +
		"Expires: 300\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write REGISTER: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "SIP/2.0 200 ") {
		t.Fatalf("want 200 OK, got:\n%s", got)
	}
	if strings.Contains(got, "Expires:") {
		t.Fatalf("OmitRegisterExpires is set, but the 200 OK still carries Expires:\n%s", got)
	}
}

// TestSendUPDATEToCallerReachesTheCallerInTheCorrectOrientation is the
// regression test for Critical #2: SendUPDATE alone only works on a call
// THIS peer dialed (peer-as-UAC); Task 30's actual scenario is the OPPOSITE
// orientation — the UA dials, the peer answers as UAS, and then the PEER
// itself must send the periodic refresh INTO the dialog it answered.
// SendUPDATE cannot reach that orientation (its p.lastSentInvite would be
// nil); SendUPDATEToCaller is built for exactly it. Exercised with a second
// peer.Peer standing in for "the UA" — the wire orientation SendUPDATEToCaller
// produces is independent of what answers on the other end, and a second
// Peer lets this test read the received headers back without needing Task
// 29's not-yet-built UA-side onUpdate handler.
//
// It also calls SendUPDATEToCaller a SECOND time and asserts the CSeq
// advanced (the fix round's Important #2): Task 30's own stated purpose is a
// PERIODIC refresh, i.e. repeated calls on the same dialog, and a hardcoded
// CSeq would make every UPDATE after the first look like a retransmission or
// draw an RFC 3261 §12.2.2 remote-sequence rejection from a real UA.
func TestSendUPDATEToCallerReachesTheCallerInTheCorrectOrientation(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0"}) // answers as UAS, then refreshes
	defer uas.Close()
	uac := Start(t, Config{Addr: "127.0.0.1:0"}) // dials; plays "the caller"
	defer uac.Close()

	if got := uac.DialExpectingStatus(t, "sip:bob@"+uas.Addr()); got != 200 {
		t.Fatalf("DialExpectingStatus = %d, want 200", got)
	}

	uas.SendUPDATEToCaller(t, "1800;refresher=uas")

	deadline := time.Now().Add(2 * time.Second)
	for uac.Count("UPDATE") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("caller never received the UPDATE within 2s; methods observed: %v", uac.Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := uac.LastRequestHeader("UPDATE", "Session-Expires"); got != "1800;refresher=uas" {
		t.Fatalf("UPDATE Session-Expires = %q, want the configured value", got)
	}

	// A second, PERIODIC refresh on the same dialog.
	uas.SendUPDATEToCaller(t, "1800;refresher=uas")
	deadline = time.Now().Add(2 * time.Second)
	for uac.Count("UPDATE") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("caller never received the SECOND UPDATE within 2s; methods observed: %v", uac.Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}
	seqs := uac.CSeqs("UPDATE")
	if len(seqs) != 2 {
		t.Fatalf("CSeqs(UPDATE) = %v, want exactly 2 entries", seqs)
	}
	if seqs[1] <= seqs[0] {
		t.Fatalf("second SendUPDATEToCaller's CSeq %d did not advance past the first's %d", seqs[1], seqs[0])
	}
}

// TestInDialogUpdateAndInfoAreDialogMatched is the regression test for F/I2:
// the in-dialog UPDATE and INFO arms answered EVERYTHING 200, with no Call-ID
// or To-tag check at all, while the in-dialog re-INVITE arm was dialog-matched.
// A session-timer refresh or a DTMF INFO built on a wrong or dead dialog could
// therefore not fail any test on the far side of this peer. Both arms now go
// through the same inDialog matcher the re-INVITE arm uses and answer 481
// Call/Transaction Does Not Exist when the To-tag names no dialog this peer has.
//
// Driven over a raw socket rather than peer.Dial so the To-tag on each
// in-dialog request is chosen by this test — right in one case, deliberately
// wrong in the other.
func TestInDialogUpdateAndInfoAreDialogMatched(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0", Behaviour: Behaviour{AnswerSessionExpires: "1800;refresher=uac"}})
	defer p.Close()

	conn, err := net.Dial("udp", p.Addr())
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	const callID = "dialog-matching-test"
	send := func(method string, cseq int, toTag string) string {
		t.Helper()
		to := "<sip:bob@example>"
		if toTag != "" {
			to += ";tag=" + toTag
		}
		req := method + " sip:bob@" + p.Addr() + " SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP " + conn.LocalAddr().String() + ";branch=z9hG4bK-" + method + strconv.Itoa(cseq) + "\r\n" +
			"From: <sip:alice@example>;tag=t1\r\n" +
			"To: " + to + "\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n" +
			"Max-Forwards: 70\r\n" +
			"Contact: <sip:alice@" + conn.LocalAddr().String() + ">\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write %s: %v", method, err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if rerr != nil {
				t.Fatalf("read response to %s: %v", method, rerr)
			}
			got := string(buf[:n])
			if strings.HasPrefix(got, "SIP/2.0 100 ") || strings.HasPrefix(got, "SIP/2.0 180 ") {
				continue
			}
			return got
		}
	}

	ok := send("INVITE", 1, "")
	if !strings.HasPrefix(ok, "SIP/2.0 200 ") {
		t.Fatalf("INVITE = %q, want 200", ok)
	}
	ourTag := toTagOfRawResponse(t, ok)

	// The dialog the peer actually answered: both methods draw a real answer.
	if got := send("UPDATE", 2, ourTag); !strings.HasPrefix(got, "SIP/2.0 200 ") {
		t.Fatalf("in-dialog UPDATE on the peer's OWN dialog = %q, want 200", got)
	}
	if got := send("INFO", 3, ourTag); !strings.HasPrefix(got, "SIP/2.0 200 ") {
		t.Fatalf("in-dialog INFO on the peer's OWN dialog = %q, want 200", got)
	}

	// A To-tag naming no dialog this peer has: 481, not a 200 that hides the
	// caller's mistake.
	if got := send("UPDATE", 4, "not-a-dialog-this-peer-has"); !strings.HasPrefix(got, "SIP/2.0 481 ") {
		t.Fatalf("UPDATE carrying an unknown To-tag = %q, want 481 Call/Transaction Does Not Exist", got)
	}
	if got := send("INFO", 5, "not-a-dialog-this-peer-has"); !strings.HasPrefix(got, "SIP/2.0 481 ") {
		t.Fatalf("INFO carrying an unknown To-tag = %q, want 481 Call/Transaction Does Not Exist", got)
	}

	// No To-tag at all is an OUT-of-dialog request, which UPDATE and INFO
	// never legally are: also 481.
	if got := send("UPDATE", 6, ""); !strings.HasPrefix(got, "SIP/2.0 481 ") {
		t.Fatalf("UPDATE carrying NO To-tag = %q, want 481", got)
	}
}

// toTagOfRawResponse reads the To-tag off a raw SIP response's To header.
func toTagOfRawResponse(t *testing.T, res string) string {
	t.Helper()
	for _, line := range strings.Split(res, "\r\n") {
		if !strings.HasPrefix(line, "To:") && !strings.HasPrefix(line, "t:") {
			continue
		}
		i := strings.Index(line, ";tag=")
		if i < 0 {
			continue
		}
		tag := line[i+len(";tag="):]
		if j := strings.IndexAny(tag, ";, "); j >= 0 {
			tag = tag[:j]
		}
		return tag
	}
	t.Fatalf("no To-tag in response:\n%s", res)
	return ""
}

// TestRefreshSessionExpiresGrantsADifferentIntervalPerRefresh is the
// regression test for A/I3's enabling half: buildRefreshResponse always echoed
// the SAME AnswerSessionExpires, so the granted interval always equalled the
// current one and a UA's entire session-timer re-base path could be deleted
// with every test still green. Behaviour.RefreshSessionExpires makes the peer
// grant a DIFFERENT interval and role per refresh; the sequence's last element
// repeats once exhausted, and the empty default is unchanged (every other test
// in this package and in internal/sipua covers that).
func TestRefreshSessionExpiresGrantsADifferentIntervalPerRefresh(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0", Behaviour: Behaviour{
		AnswerSessionExpires:  "1800;refresher=uac",
		RefreshSessionExpires: []string{"900;refresher=uas", "600;refresher=uac"},
	}})
	defer p.Close()

	conn, err := net.Dial("udp", p.Addr())
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	const callID = "refresh-sequence-test"
	send := func(method string, cseq int, toTag string) string {
		t.Helper()
		to := "<sip:bob@example>"
		if toTag != "" {
			to += ";tag=" + toTag
		}
		req := method + " sip:bob@" + p.Addr() + " SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP " + conn.LocalAddr().String() + ";branch=z9hG4bK-" + method + strconv.Itoa(cseq) + "\r\n" +
			"From: <sip:alice@example>;tag=t1\r\n" +
			"To: " + to + "\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n" +
			"Max-Forwards: 70\r\n" +
			"Contact: <sip:alice@" + conn.LocalAddr().String() + ">\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write %s: %v", method, err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if rerr != nil {
				t.Fatalf("read response to %s: %v", method, rerr)
			}
			got := string(buf[:n])
			if strings.HasPrefix(got, "SIP/2.0 100 ") || strings.HasPrefix(got, "SIP/2.0 180 ") {
				continue
			}
			return got
		}
	}
	sessionExpiresOf := func(res string) string {
		t.Helper()
		for _, line := range strings.Split(res, "\r\n") {
			if v, ok := strings.CutPrefix(line, "Session-Expires: "); ok {
				return v
			}
		}
		return ""
	}

	// The INITIAL answer still carries AnswerSessionExpires: the sequence
	// governs REFRESHES, which is the whole point — the granted interval must
	// be able to differ from the current one.
	ok := send("INVITE", 1, "")
	if got := sessionExpiresOf(ok); got != "1800;refresher=uac" {
		t.Fatalf("initial 200 Session-Expires = %q, want the AnswerSessionExpires 1800;refresher=uac", got)
	}
	ourTag := toTagOfRawResponse(t, ok)

	// Refresh 1 (UPDATE) and refresh 2 (an in-dialog re-INVITE) walk the
	// sequence: BOTH arms share the counter, and both interval and role differ
	// from the current value.
	if got := sessionExpiresOf(send("UPDATE", 2, ourTag)); got != "900;refresher=uas" {
		t.Fatalf("refresh 1 granted Session-Expires = %q, want the scripted 900;refresher=uas", got)
	}
	if got := sessionExpiresOf(send("INVITE", 3, ourTag)); got != "600;refresher=uac" {
		t.Fatalf("refresh 2 (re-INVITE) granted Session-Expires = %q, want the scripted 600;refresher=uac", got)
	}
	// Exhausted: the LAST element repeats.
	if got := sessionExpiresOf(send("UPDATE", 4, ourTag)); got != "600;refresher=uac" {
		t.Fatalf("refresh 3 granted Session-Expires = %q, want the last element repeated (600;refresher=uac)", got)
	}
}

// TestDefaultAnswerMirrorsTheOffersTelephoneEventPayloadType gives the peer's
// telephone-event MIRRORING a discriminating input. Every UA under test offers
// telephone-event at PT 101 (internal/media's telephoneEventOfferPT), so in the
// whole suite the mirrored PT and a hardcoded 101 COINCIDE: replacing
// buildDefaultAnswer's `pt` with the literal 101 leaves internal/sipua's entire
// DTMF suite green. That is the same "the double echoes the value it was given"
// shape as A/I3, and it matters because the mirroring is what makes this double
// model a real negotiation — RFC 4733 leaves the number to negotiation, and
// nothing else in the suite proves a UA honours a telephone-event PT it did not
// itself propose.
//
// buildDefaultAnswer is tested directly rather than over the wire: inviteFlow's
// use of it is already pinned by internal/sipua's rfc2833 tests, which fail with
// "telephone-event was not negotiated" the moment the answer stops carrying it.
func TestDefaultAnswerMirrorsTheOffersTelephoneEventPayloadType(t *testing.T) {
	// PT 96, deliberately NOT the 101 every UA in this repo offers.
	const offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=ua\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=audio 40000 RTP/AVP 0 96\r\na=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:96 telephone-event/8000\r\na=fmtp:96 0-15\r\na=sendrecv\r\n"

	got := string(buildDefaultAnswer([]byte(offer), false))
	for _, want := range []string{
		"m=audio 40002 RTP/AVP 0 96\r\n",
		"a=rtpmap:96 telephone-event/8000\r\n",
		"a=fmtp:96 0-15\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("answer to a telephone-event/96 offer is missing %q — the peer did not "+
				"mirror the offer's payload type:\n%s", want, got)
		}
	}
	if strings.Contains(got, "101") {
		t.Fatalf("answer names PT 101, which the offer never proposed:\n%s", got)
	}

	// StripTelephoneEvent still wins over the mirroring (Task 22's far-end
	// not_supported case).
	if s := string(buildDefaultAnswer([]byte(offer), true)); strings.Contains(s, "telephone-event") {
		t.Fatalf("StripTelephoneEvent must omit telephone-event entirely:\n%s", s)
	}
}

// TestRegisterRefresh200EchoesContactLikeTheInitial200 pins P4-W2-13's
// Contact-on-refresh triage outcome (Phase 4 W2).
//
// THE DEFERRAL CLAIMED A MISSING Contact ON A REFRESH 200 AND CITED
// peer.go:1242-1257. That citation was stale: at HEAD those lines are
// inviteFlow's Reject422MinSE handling, nothing to do with REGISTER. The real
// REGISTER-200 construction is a SINGLE path in respondRegister() — the method
// switch that routes to it has no refresh-specific case — and it echoes the
// request's Contact unconditionally unless SuppressRegisterContactEcho is set.
// So there was no
// defect to fix, only an unpinned invariant.
//
// This is what makes the triage outcome durable rather than a paragraph in a
// closeout doc: if anyone ever adds a refresh-specific branch that forgets the
// echo, RFC 3261 12.1.1 fidelity breaks here first. The double's fidelity is
// worth pinning even though internal/sipua never reads a refresh response's
// Contact today, because "nothing reads it today" is exactly the reasoning that
// lets a test double silently drift away from the registrar it models.
func TestRegisterRefresh200EchoesContactLikeTheInitial200(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0"})
	defer p.Close()

	conn, err := net.Dial("udp", p.Addr())
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	contact := "<sip:alice@" + conn.LocalAddr().String() + ">"
	send := func(cseq int) string {
		t.Helper()
		req := "REGISTER sip:" + p.Addr() + " SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP " + conn.LocalAddr().String() + ";branch=z9hG4bK-refresh-" + strconv.Itoa(cseq) + "\r\n" +
			"From: <sip:alice@example>;tag=t1\r\n" +
			"To: <sip:alice@example>\r\n" +
			"Call-ID: contact-echo-test\r\n" +
			"CSeq: " + strconv.Itoa(cseq) + " REGISTER\r\n" +
			"Max-Forwards: 70\r\n" +
			"Contact: " + contact + "\r\n" +
			"Expires: 300\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, werr := conn.Write([]byte(req)); werr != nil {
			t.Fatalf("write REGISTER cseq=%d: %v", cseq, werr)
		}
		if derr := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); derr != nil {
			t.Fatalf("set deadline: %v", derr)
		}
		buf := make([]byte, 4096)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			t.Fatalf("read response to cseq=%d: %v", cseq, rerr)
		}
		return string(buf[:n])
	}

	initial := send(1)
	if !strings.HasPrefix(initial, "SIP/2.0 200 ") {
		t.Fatalf("initial REGISTER: want 200 OK, got:\n%s", initial)
	}
	if !strings.Contains(initial, "Contact:") {
		t.Fatalf("initial 200 OK carries no Contact:\n%s", initial)
	}

	// THE REFRESH: same Call-ID, higher CSeq — RFC 3261 10.2's refresh shape.
	refresh := send(2)
	if !strings.HasPrefix(refresh, "SIP/2.0 200 ") {
		t.Fatalf("refresh REGISTER: want 200 OK, got:\n%s", refresh)
	}
	if !strings.Contains(refresh, "Contact:") {
		t.Fatalf("REFRESH 200 OK CARRIES NO Contact — RFC 3261 12.1.1 requires the "+
			"registrar to list the bindings, and respondRegister() has a single REGISTER-200 path "+
			"that echoes it unconditionally. A refresh-specific branch that skips the echo has been "+
			"introduced; that is the P4-W2-13 defect this test exists to catch:\n%s", refresh)
	}
	if p.Count("REGISTER") != 2 {
		t.Fatalf("peer saw %d REGISTERs, want 2", p.Count("REGISTER"))
	}
}

// TestSendReInviteToCallerAdvancesCSeqAcrossRepeatedCalls pins D23 (Phase 4 W2).
//
// SendReInviteToCaller hardcoded CSeq:1 while its UPDATE twin already drew from
// a real per-dialog counter — an asymmetry that made a SECOND re-INVITE on the
// same dialog indistinguishable from a retransmission of the first. Both helpers
// now share toCallerCSeq, so this asserts the second re-INVITE's CSeq is
// strictly higher than the first's.
//
// Test-infra fidelity only: no production code reads this. That is precisely why
// it needs a test — nothing else would notice the regression.
func TestSendReInviteToCallerAdvancesCSeqAcrossRepeatedCalls(t *testing.T) {
	uas := Start(t, Config{Addr: "127.0.0.1:0"}) // answers as UAS, then re-INVITEs
	defer uas.Close()
	uac := Start(t, Config{Addr: "127.0.0.1:0"}) // dials; plays "the caller"
	defer uac.Close()

	if got := uac.DialExpectingStatus(t, "sip:bob@"+uas.Addr()); got != 200 {
		t.Fatalf("DialExpectingStatus = %d, want 200", got)
	}

	uas.SendReInviteToCaller(t)
	deadline := time.Now().Add(2 * time.Second)
	for uac.Count("INVITE") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("caller never received the re-INVITE within 2s; methods observed: %v", uac.Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}

	uas.SendReInviteToCaller(t)
	deadline = time.Now().Add(2 * time.Second)
	for uac.Count("INVITE") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("caller never received the SECOND re-INVITE within 2s; methods observed: %v", uac.Methods())
		}
		time.Sleep(5 * time.Millisecond)
	}

	seqs := uac.CSeqs("INVITE")
	if len(seqs) != 2 {
		t.Fatalf("CSeqs(INVITE) = %v, want exactly 2 entries", seqs)
	}
	first, second := seqs[0], seqs[1]
	if second <= first {
		t.Fatalf("second re-INVITE CSeq = %d, first = %d; repeated in-dialog requests must "+
			"advance (RFC 3261 12.2.1.1) — a hardcoded CSeq makes the second look like a "+
			"retransmission of the first", second, first)
	}
}

// TestPeerDialAcksA2xx: the peer is a UAC when it dials, so it ACKs the 2xx,
// and every retransmitted copy of it (RFC 3261 13.2.2.4), with the UAS's To
// tag, the INVITE's CSeq number and a fresh top-Via branch.
func TestPeerDialAcksA2xx(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0"})
	uas, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = uas.Close() }()

	p.Dial(t, "sip:x@"+uas.LocalAddr().String())

	read := func() (string, net.Addr) {
		t.Helper()
		_ = uas.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		n, from, err := uas.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return string(buf[:n]), from
	}
	hdr := func(msg, name string) string {
		for _, l := range strings.Split(msg, "\r\n") {
			if strings.HasPrefix(strings.ToLower(l), strings.ToLower(name)+":") {
				return strings.TrimSpace(l[len(name)+1:])
			}
		}
		return ""
	}
	inv, from := read()
	if !strings.HasPrefix(inv, "INVITE ") {
		t.Fatalf("first datagram is not an INVITE:\n%s", inv)
	}
	ok := "SIP/2.0 200 OK\r\nVia: " + hdr(inv, "Via") + "\r\nFrom: " + hdr(inv, "From") +
		"\r\nTo: " + hdr(inv, "To") + ";tag=uas1\r\nCall-ID: " + hdr(inv, "Call-ID") +
		"\r\nCSeq: " + hdr(inv, "CSeq") + "\r\nContact: <sip:x@" + uas.LocalAddr().String() + ">\r\nContent-Length: 0\r\n\r\n"
	invBranch := hdr(inv, "Via")[strings.Index(hdr(inv, "Via"), "branch="):]
	for i := 0; i < 2; i++ { // the 200 and a retransmitted copy
		if _, err := uas.WriteTo([]byte(ok), from); err != nil {
			t.Fatalf("write 200: %v", err)
		}
		ack, _ := read()
		if !strings.HasPrefix(ack, "ACK ") {
			t.Fatalf("copy %d: not answered with an ACK:\n%s", i, ack)
		}
		if got := hdr(ack, "CSeq"); got != strings.Fields(hdr(inv, "CSeq"))[0]+" ACK" {
			t.Errorf("ACK CSeq %q, INVITE CSeq %q", got, hdr(inv, "CSeq"))
		}
		if !strings.Contains(hdr(ack, "To"), "tag=uas1") {
			t.Errorf("ACK To %q lacks the UAS tag", hdr(ack, "To"))
		}
		if v := hdr(ack, "Via"); v == "" || strings.Contains(v, invBranch) {
			t.Errorf("ACK Via %q must carry a fresh branch (INVITE: %q)", v, invBranch)
		}
	}
}

// TestPeerAcksA2xxToItsReInvite: the peer ACKs, once per copy, the 2xx to an
// in-dialog INVITE it sent with a body (CF-208: the UA under test retransmits an
// un-ACKed 2xx to a re-INVITE), but not the 2xx to an offerless one (its ACK must
// carry the answer, which is the test's job).
func TestPeerAcksA2xxToItsReInvite(t *testing.T) {
	p := Start(t, Config{Addr: "127.0.0.1:0"})
	uas, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = uas.Close() }()
	p.Dial(t, "sip:x@"+uas.LocalAddr().String())
	read := func() (string, net.Addr) {
		t.Helper()
		_ = uas.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		n, from, err := uas.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return string(buf[:n]), from
	}
	hdr := func(msg, name string) string {
		for _, l := range strings.Split(msg, "\r\n") {
			if strings.HasPrefix(strings.ToLower(l), strings.ToLower(name)+":") {
				return strings.TrimSpace(l[len(name)+1:])
			}
		}
		return ""
	}
	inv, from := read()
	ok := func(req string) string {
		return "SIP/2.0 200 OK\r\nVia: " + hdr(req, "Via") + "\r\nFrom: " + hdr(req, "From") +
			"\r\nTo: " + hdr(req, "To") + ";tag=uas1\r\nCall-ID: " + hdr(req, "Call-ID") +
			"\r\nCSeq: " + hdr(req, "CSeq") + "\r\nContact: <sip:x@" + uas.LocalAddr().String() + ">\r\nContent-Length: 0\r\n\r\n"
	}
	if _, err := uas.WriteTo([]byte(ok(inv)), from); err != nil {
		t.Fatal(err)
	}
	if ack, _ := read(); !strings.HasPrefix(ack, "ACK ") {
		t.Fatalf("the dialled INVITE's 2xx was not ACKed:\n%s", ack)
	}
	p.SendReInvite(t)
	re, from := read()
	if !strings.HasPrefix(re, "INVITE ") {
		t.Fatalf("not the re-INVITE:\n%s", re)
	}
	for i := 0; i < 2; i++ { // the 200 and a retransmitted copy
		if _, err := uas.WriteTo([]byte(ok(re)), from); err != nil {
			t.Fatal(err)
		}
		ack, _ := read()
		if !strings.HasPrefix(ack, "ACK ") || hdr(ack, "CSeq") != strings.Fields(hdr(re, "CSeq"))[0]+" ACK" {
			t.Fatalf("copy %d of the re-INVITE's 200 not ACKed with its CSeq:\n%s", i, ack)
		}
	}
}
