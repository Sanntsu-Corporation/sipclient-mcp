package main

// scenarios_p4.go — Phase 4 Wave 1's M8/D5 scenario: registration-refresh,
// against the live rig, placed LAST in gate.go's scenarios slice.
//
// Subject: the STANDING r.registerUA (created once at gate startup) — NEVER a
// new register-mode UA. The rig's e2e-uac-register AOR is configured
// max_contacts=1, remove_existing=yes (e2e/asterisk/conf/pjsip.conf): a
// second REGISTER against it evicts the standing UA's contact and would break
// this scenario's own later assertions (and any later manual re-run). A
// future scenario author adding to this file must not add one either.
//
// Drive: none. By the time this scenario runs (last), the refresh timer has
// already been running ~5.5 min and has fired several times — this is an
// OBSERVATION WINDOW proving SUSTAINED refresh, not just the first one.
//
// What this scenario CANNOT prove: Asterisk never reuses a nonce (Phase 4
// Inputs §1), so RFC 7616 nc=1,2,3,4 monotonicity is not observable here —
// that is already proven at unit level against internal/testutil/peer in M3.
// This scenario proves the REWRITE didn't break registration-refresh against
// a REAL registrar: regression-safety, not the nonce-count feature.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// registrationRefreshPoll is how often ua_status is sampled while waiting
	// for refreshes.
	registrationRefreshPoll = 5 * time.Second
	// registrationRefreshDeadline: Asterisk grants 60s for e2e-uac-register
	// (policy.yaml); registerRefreshFraction=0.85 +/- registerRefreshJitter=
	// 0.05 (internal/sipua/register.go) fires the actual refresh at 48-54s per
	// cycle, so two cycles take <=108s worst case. 130s gives margin.
	registrationRefreshDeadline = 130 * time.Second
	// registrationRefreshWant is the minimum number of refreshes (next_
	// refresh_ms jump-ups) this scenario requires before it can pass.
	registrationRefreshWant = 2
	// registrationGrantedExpiresS is the registrar's ACTUAL grant, read off
	// its authoritative Contact `expires` parameter — NOT policy.yaml's
	// REQUESTED expires_s: 60. Verified live against this rig (2026-07-29):
	// see scenarioRegistrationRefresh's doc comment for the evidence.
	registrationGrantedExpiresS = 59
)

// boolv coerces a §11 envelope field to bool (main.go's str/num/numf cover
// string/int/float64 but nothing already coerces bool).
func boolv(v any) bool {
	b, _ := v.(bool)
	return b
}

// uaStatusOne calls ua_status for a single UA and returns its one entry.
func (r *rig) uaStatusOne(ctx context.Context, ua string) (map[string]any, error) {
	env, err := r.cl.callOK(ctx, "ua_status", map[string]any{"ua": ua})
	if err != nil {
		return nil, err
	}
	uas, _ := env["uas"].([]any)
	if len(uas) == 0 {
		return nil, fmt.Errorf("ua_status returned no entries for %s", ua)
	}
	m, ok := uas[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("ua_status entry for %s is not an object", ua)
	}
	return m, nil
}

// rigContactPrefix identifies this scenario's AOR/profile in `pjsip show
// contacts`' fixed-width table. The table truncates the Aor/ContactUri
// column well before the host or port (confirmed live: a 5-digit-port
// contact showed only "e2e-uac-register/sip:e2e-uac-register@192.168." with
// everything after cut off), so a full contact-URI match is not possible
// through this CLI view — the AOR/profile prefix, which the table always
// keeps intact, is what rigContactPresent matches on instead. This scenario
// is already pinned to exactly this one profile/AOR (see the file's own doc
// comment on why a second register-mode UA must never be added here), so the
// prefix alone is unambiguous for its purposes.
const rigContactPrefix = "e2e-uac-register/sip:e2e-uac-register@"

// rigContactPresent asks Asterisk itself (over ssh, `pjsip show contacts`)
// whether e2e-uac-register's AOR currently lists a contact. ok is false when
// ssh/the CLI call itself failed (a transport problem, not a verdict);
// present is only meaningful when ok is true.
func (r *rig) rigContactPresent(ctx context.Context) (present bool, ok bool) {
	out, ok := r.asteriskRX(ctx, "pjsip show contacts")
	if !ok {
		return false, false
	}
	return strings.Contains(out, rigContactPrefix), true
}

// registerRequest is one REGISTER Asterisk RECEIVED, as parsed out of its own
// pjsip logger dump (docker logs).
type registerRequest struct {
	callID  string
	cseq    int
	contact string // bare URI, brackets stripped (see stripAngleBrackets)
}

// stripAngleBrackets removes a name-addr's enclosing "<...>" if present,
// returning s unchanged otherwise. Asterisk's logged Contact header reads
// `Contact: <sip:user@host:port>`, while r.registerContact (from ua_create's
// own `contact` field, session/toolservice.go) is the bare URI with no
// brackets — this normalises the wire form for a direct comparison.
func stripAngleBrackets(s string) string {
	if i := strings.Index(s, "<"); i >= 0 {
		s = s[i+1:]
		if j := strings.Index(s, ">"); j >= 0 {
			s = s[:j]
		}
	}
	return s
}

// parseRegisterRequests walks logText's "<--- Received/Transmitting SIP
// ... --->" delimited blocks and returns one registerRequest per REGISTER
// Asterisk RECEIVED, in log (chronological) order. Only request blocks whose
// first SIP line starts "REGISTER " are counted; Asterisk's own 401/200
// RESPONSES to those requests start "SIP/2.0 ..." and are skipped, so a
// two-refresh window's ~4 REGISTERs (each 401-challenged) count as 4, not 8.
//
// Confirmed empirically against the live rig (M8/D5 dispatch, 2026-07-29): a
// raw OPTIONS probe sent while `pjsip set logger on` was armed showed up in
// `docker logs` as
//
//	<--- Received SIP request (338 bytes) from UDP:<ip>:<port> --->
//	OPTIONS sip:... SIP/2.0
//	...
//	Call-ID: ...
//	CSeq: 1 OPTIONS
//	...
//	<blank line>
//
// — i.e. the logger's SIP-message dump DOES reach docker logs, so the
// pre-approved fallback (demote assertion 2 to a printed diagnostic) did NOT
// need to fire.
func parseRegisterRequests(logText string) []registerRequest {
	var blocks []registerRequest
	var cur []string
	inBlock := false
	flush := func() {
		defer func() { cur = nil; inBlock = false }()
		if !inBlock || len(cur) == 0 || !strings.HasPrefix(cur[0], "REGISTER ") {
			return
		}
		var b registerRequest
		for _, l := range cur[1:] {
			if v, ok := strings.CutPrefix(l, "Call-ID:"); ok {
				b.callID = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(l, "CSeq:"); ok {
				fields := strings.Fields(v)
				if len(fields) > 0 {
					b.cseq, _ = strconv.Atoi(fields[0])
				}
			}
			if v, ok := strings.CutPrefix(l, "Contact:"); ok {
				b.contact = stripAngleBrackets(strings.TrimSpace(v))
			}
		}
		if b.callID != "" {
			blocks = append(blocks, b)
		}
	}
	for _, line := range strings.Split(logText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<---") && strings.HasSuffix(trimmed, "--->") {
			flush()
			inBlock = true
			continue
		}
		if inBlock {
			if trimmed == "" {
				flush()
				continue
			}
			cur = append(cur, trimmed)
		}
	}
	flush()
	return blocks
}

// scenarioRegistrationRefresh (M8/D5): the standing register-mode UA's
// refresh timer, observed live against Asterisk over a >=2-refresh window.
//
// Assertion 1 (registrar-side, independent — the gate's actual verdict):
// polls Asterisk's OWN live registrar state (`pjsip show contacts`, over
// ssh — asteriskRX, not the log) at every step of the same cadence the local
// ua_status poll uses, and requires the AOR's contact to be listed, without a
// single gap, at every one of those samples across the whole window.
//
// THE ORIGINAL DESIGN (grep docker-logs "Added contact"/"Updated contact"
// lines within this scenario's OWN window) DID NOT SURVIVE CONTACT WITH THE
// LIVE RIG — an unconfirmed assumption this dispatch was told to verify, not
// trust. Confirmed empirically (2026-07-29, by grepping this rig's full
// docker-logs history grouped by contact URI): Asterisk's PJSIP registrar
// logs "Added contact" ONCE per UA lifetime, at the INITIAL REGISTER only —
// refreshes of an UNCHANGED contact/binding are silent at console/NOTICE
// level (0 "Updated contact" lines exist anywhere in this rig's history, and
// every distinct contact URI appears exactly once, refreshes included). So
// the log-line count could never reach >=2 inside a scenario window that
// starts AFTER the UA's one-time initial REGISTER — no literal-constant fix
// applies here, unlike the expires_s correction below; the underlying
// observable itself doesn't repeat.
//
// THE REPLACEMENT is still registrar-side and independent of our own
// client's self-report (a different code path from session/toolservice.go's
// ua_status), and is anti-stale BY CONSTRUCTION rather than by string
// binding: the AOR is `max_contacts=1, remove_existing=yes` and this
// scenario's own doc comment already establishes nothing else ever registers
// against it during a gate run, so if Asterisk's registrar shows a contact
// for this AOR at any sample, it can only be THIS run's — and if this run's
// refresh had failed, the granted 59s expiry (see below) means the contact
// would have been evicted from Asterisk's own state well before the >=100s
// window this scenario spans, which is what the continuous-presence
// requirement actually catches.
//
// Assertion 2 (wire-level identity — the actual invariant M3's rewrite must
// preserve): bracket with `pjsip set logger on`/`off` (deferred `off`, plus
// runGate's own unconditional second `off` in its teardown as a safety net),
// then parse the REGISTER blocks in the same log window: exactly one
// distinct Call-ID across every REGISTER (RFC 3261 §10.2) and strictly
// increasing CSeq across them (Asterisk challenges every REGISTER, so a
// two-refresh window yields ~4 REGISTERs — this walks M3's
// 401->digest-recompute->CSeq-bump retry path live, not just the send).
//
// Assertion 3 (local state, throughout): registered stays true, register_code
// stays 200, expires_s stays 59, and next_refresh_ms shows a sawtooth pattern
// (at least one sample greater than the immediately preceding one) — only
// reachable if recordRefresh genuinely re-bases refreshBaseAt on each
// successful refresh; a monotone decrease to 0 and staying there is the
// failure shape this assertion catches.
//
// EXPIRES_S IS 59, NOT policy.yaml's REQUESTED 60 — VERIFIED LIVE, NOT
// ASSUMED. Every 200 OK this UA's REGISTER/refresh gets back carries a
// top-level `Expires: 60` header AND an authoritative Contact `;expires=59`
// parameter (confirmed against 7 consecutive grants in one gate run,
// 2026-07-29: 100% show 59, 0% show 60). RFC 3261 §10.2.4 — and
// responseExpires's own doc comment in internal/sipua/register.go — make the
// Contact parameter authoritative over the header, and that is exactly what
// this project's client reads (contactExpires, checked before the Expires
// header fallback). So 59 is the CORRECT value a spec-compliant client
// reports; asserting 60 here would fail every healthy run on this rig, not
// catch a regression.
func scenarioRegistrationRefresh(ctx context.Context, r *rig) (bool, string) {
	if strings.TrimSpace(r.cfg.sshTarget) == "" {
		return false, "-ssh is required: this scenario's registrar-side verdict is Asterisk's own live state"
	}
	if r.registerContact == "" {
		return false, "no stored register contact URI to bind the wire-level assertion to (createRegisterUA never set it)"
	}
	start := time.Now()

	st0, err := r.uaStatusOne(ctx, r.registerUA)
	if err != nil {
		return false, "ua_status (start): " + err.Error()
	}
	if !boolv(st0["registered"]) {
		return false, "standing register UA is not registered at scenario start"
	}
	prevNext := int64(numf(st0["next_refresh_ms"]))

	// Assertion 1's very first sample, before any refresh has had a chance to
	// happen — establishes that the AOR is populated at all going in.
	rigSamples, rigAbsences := 0, 0
	if present, ok := r.rigContactPresent(ctx); ok {
		rigSamples++
		if !present {
			rigAbsences++
		}
	} else {
		return false, "pjsip show contacts (start): ssh/CLI call failed"
	}

	// Assertion 2's bracket. loggerArmed tracks whether `pjsip set logger on`
	// itself succeeded; the reachability of its SIP-message dump into docker
	// logs was confirmed empirically ahead of this dispatch (see
	// parseRegisterRequests's doc comment), so no fallback is needed here —
	// but the bracket is still conditioned on ssh/CLI success so a CLI hiccup
	// degrades to a clear failure reason rather than a silent no-op.
	loggerArmed := false
	if _, ok := r.asteriskRX(ctx, "pjsip set logger on"); ok {
		loggerArmed = true
	}
	if loggerArmed {
		defer func() { _, _ = r.asteriskRX(ctx, "pjsip set logger off") }()
	}

	sawSawtooth := false
	refreshes := 0
	deadline := start.Add(registrationRefreshDeadline)
	for {
		if !sleepCtx(ctx, registrationRefreshPoll) {
			return false, "cancelled while waiting for registration refresh"
		}
		st, err := r.uaStatusOne(ctx, r.registerUA)
		if err != nil {
			return false, "ua_status (poll): " + err.Error()
		}
		if !boolv(st["registered"]) {
			return false, "standing register UA dropped registered=false mid-window"
		}
		if code := num(st["register_code"]); code != 200 {
			return false, fmt.Sprintf("register_code=%d mid-window, want 200", code)
		}
		if es := num(st["expires_s"]); es != registrationGrantedExpiresS {
			return false, fmt.Sprintf("expires_s=%d mid-window, want %d", es, registrationGrantedExpiresS)
		}
		next := int64(numf(st["next_refresh_ms"]))
		if next > prevNext {
			sawSawtooth = true
			refreshes++
		}
		prevNext = next

		// Assertion 1: the registrar's OWN state, sampled every poll — see
		// this function's doc comment for why this replaced the original
		// log-line design.
		if present, ok := r.rigContactPresent(ctx); ok {
			rigSamples++
			if !present {
				rigAbsences++
			}
		} else {
			return false, "pjsip show contacts (poll): ssh/CLI call failed"
		}

		if refreshes >= registrationRefreshWant || time.Now().After(deadline) {
			break
		}
	}
	if refreshes < registrationRefreshWant {
		return false, fmt.Sprintf("observed %d refreshes, want >= %d within %s (next_refresh_ms never jumped up enough times)",
			refreshes, registrationRefreshWant, registrationRefreshDeadline)
	}
	if !sawSawtooth {
		return false, "next_refresh_ms never showed a sawtooth jump-up — recordRefresh may not be re-basing refreshBaseAt"
	}
	if rigAbsences > 0 {
		return false, fmt.Sprintf("Asterisk's own AOR showed NO contact on %d/%d samples spanning >=%d refreshes — the registrar itself did not see the binding survive",
			rigAbsences, rigSamples, registrationRefreshWant)
	}

	stEnd, err := r.uaStatusOne(ctx, r.registerUA)
	if err != nil {
		return false, "ua_status (end): " + err.Error()
	}
	if !boolv(stEnd["registered"]) {
		return false, "standing register UA is not registered at scenario end"
	}
	if code := num(stEnd["register_code"]); code != 200 {
		return false, fmt.Sprintf("register_code=%d at scenario end, want 200", code)
	}
	if es := num(stEnd["expires_s"]); es != registrationGrantedExpiresS {
		return false, fmt.Sprintf("expires_s=%d at scenario end, want %d", es, registrationGrantedExpiresS)
	}
	if present, ok := r.rigContactPresent(ctx); !ok {
		return false, "pjsip show contacts (end): ssh/CLI call failed"
	} else if !present {
		return false, "Asterisk's own AOR shows no contact at scenario end"
	}

	// Assertion 2, if the logger toggle itself succeeded (empirically the SIP
	// dump reaches docker logs for this rig — see parseRegisterRequests's doc
	// comment; the fallback below is the pre-approved demotion path for a CLI
	// hiccup specifically, not for the reachability question, which is
	// already settled).
	wireNote := "assertion 2 (Call-ID/CSeq) DEMOTED to diagnostic: `pjsip set logger on` did not succeed over ssh this run"
	if loggerArmed {
		window := time.Since(start) + 5*time.Second
		logText, ok := r.rigAsteriskLog(ctx, window)
		if !ok {
			return false, "rigAsteriskLog: could not read the rig's Asterisk log over ssh (needed for the armed assertion 2)"
		}
		allBlocks := parseRegisterRequests(logText)
		// Bound to THIS run's own contact URI, the same anti-stale discipline
		// dtmfRigDigits/scenarioDTMFRFC2833Rig establish elsewhere in this
		// file set — belt-and-suspenders alongside the logger bracket's own
		// time-scoping (the logger is only armed for this scenario's own
		// window, so no other REGISTER traffic could appear in it regardless).
		var blocks []registerRequest
		for _, b := range allBlocks {
			if b.contact == r.registerContact {
				blocks = append(blocks, b)
			}
		}
		if len(blocks) == 0 {
			fmt.Println("  note: pjsip logger was armed but no REGISTER request blocks matching this run's own contact " +
				"were found in the log window (demoting assertion 2 to a printed diagnostic per the pre-approved fallback)")
			wireNote = "assertion 2 (Call-ID/CSeq) DEMOTED to diagnostic: logger armed but no matching REGISTER blocks parsed from the window"
		} else {
			callIDs := map[string]bool{}
			cseqs := make([]int, len(blocks))
			increasing := true
			for i, b := range blocks {
				callIDs[b.callID] = true
				cseqs[i] = b.cseq
				if i > 0 && b.cseq <= blocks[i-1].cseq {
					increasing = false
				}
			}
			if len(callIDs) != 1 {
				return false, fmt.Sprintf("saw %d distinct Call-IDs across %d REGISTERs in the window, want exactly 1 (RFC 3261 §10.2)",
					len(callIDs), len(blocks))
			}
			if !increasing {
				return false, fmt.Sprintf("CSeq did not strictly increase across the %d REGISTERs in the window: %v", len(blocks), cseqs)
			}
			wireNote = fmt.Sprintf("wire-level: 1 distinct Call-ID, CSeq %v across %d REGISTERs (401-challenge retries included)", cseqs, len(blocks))
		}
	}

	return true, fmt.Sprintf("%d refreshes observed (next_refresh_ms sawtooth confirmed), registrar confirms contact present on %d/%d samples; %s",
		refreshes, rigSamples, rigSamples, wireNote)
}
