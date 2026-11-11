# Vendored SIP engine snapshot

A point-in-time copy, not a module dependency (spec §8 D1, locked decision 8).
From here the copy is **owned and modifiable** and may diverge freely from upstream.

## Source

| | |
|---|---|
| Upstream | an in-house SIP test engine, now maintained here |
| Source commit | `04c6a81861fb670dbf78a2eb041a384293c9d923` |
| Copy date | `2026-07-18` |
| **Upstream Go version** | **`go 1.24.0`** |
| `github.com/emiago/sipgo` | `v0.24.1` |
| `github.com/pion/rtp` | `v1.8.11` |

### Note on the Go version divergence

This snapshot is **Go 1.24.0 source**, while `sipclient-mcp`'s `go.mod` declares
**`go 1.25.0`**. That divergence is deliberate and approved (handoff decision U4):
`github.com/modelcontextprotocol/go-sdk` raised its floor to `go 1.25.0` at v1.4.0,
and the project pins that SDK at `v1.6.1`. The mismatch is benign in the direction
it occurs — Go 1.24.0 source compiles unchanged under 1.25 — and it is recorded
here so a reader of the vendored tree finds it without reading the handoff.

## Files

Copied recursively from upstream `pkg/sip/`. Upstream `go.mod`, `go.sum` and
`README.md` were **not** copied: this is a package tree inside `sipclient-mcp`'s
module, not a nested module.

### `digest/`
- `digest.go`

### `config/`
- `config.go`
- `local_policy.go`

### `siptest/`
- `builders.go`
- `builders_test.go`
- `client.go`
- `digest_retry_test.go`
- `sdp.go`
- `uac.go`
- `uas.go`
- `proxy.go` — **moved out of this tree**, see modifications below.

### `calltester/`
- `audio.go`
- `media.go`
- `passive_endpoint.go`
- `quality.go`
- `runner.go`
- `runner_test.go`
- `sink.go`
- `store.go`
- `types.go`

## Modifications made at import time

Every modification is listed here. The import commit is byte-identical to upstream
apart from item 1; every other item lands in the immediately following commit, so
the two together are a complete and reviewable record of what changed.

| # | Modification | Rationale |
|---|---|---|
| 1 | Import path of the original module → `github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine`, in 16 import lines across 10 files (`calltester/{passive_endpoint,runner,sink}.go`, `siptest/{builders,builders_test,client,digest_retry_test,sdp,uac,uas}.go`). No other byte changed. | The tree now lives in a different module. |
| 2 | `siptest/proxy.go` moved to `internal/testutil/sipproxy/proxy.go`; its package clause changed from `siptest` to `sipproxy`. Exactly one line differs from upstream. | The file imports `testing` from a non-`_test.go` file (spec §7.1 ⚠), which linked `testing` into any production build importing `siptest`. It is a **move to `testutil`, not a rename to `_test.go`**: spec §14.1 shares this proxy across several packages' tests and `_test.go` files cannot be imported across packages. Asserted by `internal/importguard`. No upstream caller referenced `StartProxy`. Note: `calltester/runner.go` imports `siptest` at production level, so before this move `calltester`'s transitive dependency set also included `testing` — the fix clears both, not only `siptest` directly. |
| 3 | `internal/testutil/sipproxy/proxy.go`: added a package doc comment (`// Package sipproxy provides a minimal REGISTER-recording SIP proxy used by integration tests.`) above the `package sipproxy` clause, and changed `fmt.Sscanf(s, "%d", &n)` to `_, _ = fmt.Sscanf(s, "%d", &n)` in `intPort`. | `golangci-lint run ./internal/testutil/...` flagged the moved file (not covered by decision 14's `internal/sipengine/` exclusion): `revive` (package-comments) and `errcheck` (unchecked `fmt.Sscanf` return). Both are the minimal fix the linter reports; `intPort`'s behavior is unchanged (`n` stays `0` on a non-numeric `s`, exactly as before). |
| 4 | `siptest/builders.go`: `buildVia` and the Contact URI take an explicit `transport` parameter instead of the literal `Transport: "UDP"` at the original line 123; `BuildRegister`/`BuildInvite` signatures widened to accept `transport string`. Call sites updated to pass `"udp"`: `siptest/uac.go` (lines 41, 68), `calltester/runner.go` (lines 250, 270), and the vendored tests `siptest/builders_test.go` and `siptest/digest_retry_test.go`. | Required by spec §15.1 obligation O1: transport-neutral by shape, UDP-only by wiring at P1. The vendored builders previously hardcoded the Via/Contact transport token; P4 must be able to add TCP and TLS by passing a different value, changing no signature. |
| 5 | `internal/testutil/sipproxy/proxy.go` — ADDED `func (p *Proxy) SetDigest(realm, user string, pass policy.Secret)` and the unexported `digest *digestCreds` field and `digestOK` helper. Additive only; no upstream line changed. | The upstream proxy's explicit non-goal is auth — it accepts any REGISTER payload — so it cannot exercise R1's `REGISTER → 401 → REGISTER → 200` digest ladder, which spec §14.1 and P1e Task 22 Step 6 require. **Off by default** (`digest` nil ⇒ upstream behaviour exactly), so the vendored routing tests that depend on accepting any REGISTER are unchanged. Verification goes through `internal/sipengine/digest` rather than a hand-rolled MD5 (Rule 16). The password is carried as a `policy.Secret` and revealed only inside `digestOK` — see row 6. |
| 6 | `internal/testutil/sipproxy/proxy.go` — ADDED an import of `github.com/sanntsu-corporation/sipclient-mcp/internal/policy` (and of `internal/sipengine/digest`), and typed `digestCreds.pass` as `policy.Secret`. NEW IMPORT EDGES into the moved vendored file; recorded separately from row 5 because an import added to vendored code is the change most likely to be silently dropped on a re-vendor. | Keeps the fixture password redacted across `SetDigest`'s API boundary: `policy.Secret` renders `[REDACTED]` under `String`, `GoString`, `MarshalJSON` and `LogValue`, so an intermediate log of `SetDigest`'s arguments — the kind added while debugging a digest mismatch — cannot print it. The Secret's Reveal method is called on exactly one line, inside `digestOK`, where MD5(HA1:nonce:HA2) genuinely requires the plaintext. **This is a sanctioned TEST-ONLY reveal and P1a's assertion does not count it**: `TestRevealAppearsOnlyInProductionWiring` is scoped to production code, excluding `internal/policy` (which owns the primitive) and `internal/testutil` (which cannot ship). The one production reveal the rule permits is P1d's `cmd/` wiring closure. That exclusion is sound only because `TestDaemonDoesNotShipTestUtil` proves the daemon cannot reach this package — the two assertions are one control. The import edge is acyclic and legal: `internal/testutil/**` may import anything (§1.1), and nothing outside `testutil` imports `sipproxy`. |
| 7 | `internal/testutil/sipproxy/proxy.go` — ADDED `func (p *Proxy) RegisterCount(user string) int` and `func (p *Proxy) ChallengeCount(user string) int`, plus the `registers` and `challenges` maps. Additive only. | P1e Task 22 Step 6 asserts the ladder is exactly two REGISTERs and one challenge. Counting REGISTERs **on the wire** is the only way to distinguish "challenged then retried" from "accepted first time"; the response code alone cannot. |
| 8 | `internal/testutil/sipproxy/proxy.go` — ADDED `func (p *Proxy) UnregisterCount(user string) int` and the `unregisters` map. Additive only. | Discharges spec §12.7's acceptance clause *"the far end observes exactly one `REGISTER Expires: 0`"*, asserted at P1e Task 23 Step 7. It is counted **at the registrar, not at the peer UAS**: a register-mode UA deregisters against its registrar and the far-end peer never sees that message, so `peer.Peer.UnregisterCount()` — a different type, taking no argument — cannot observe it. Incremented on the **accepted** path only, so a challenged-and-retried deregistration counts once. |
| 9 | `internal/testutil/sipproxy/proxy.go` — `handleRegister`: on an ACCEPTED REGISTER carrying `Expires: 0`, the routing entry `p.contacts[user]` is now `delete`d instead of left in place (and the following Contact-recording block is skipped for that request via a new local `isUnregister` bool). No new export; behavior-only change to an existing unexported method. | D11 point 4 ("a subsequent INVITE to a destroyed UA's AOR gets 404 Not Found") could not be discharged over the wire on the registrar-routed path: `sipua`'s `Unregister` reuses `BuildRegister` wholesale and so its Expires:0 REGISTER still carries a real Contact host:port, and the proxy previously re-recorded that same stale contact after counting the unregister — `forwardRequest`'s existing `!ok` → 404 branch was therefore unreachable via deregistration. This is a test-registrar fidelity fix: a real registrar (and Asterisk) drops the contact on unregister. Discharged by `internal/testutil/loopback/admin_wire_test.go`'s `TestAdminDeleteRegisterModeAORGets404` (P1e Task 34). `UnregisterCount` (row 8) needed no change: it still counts on the accepted path only, unaffected by whether the contact is cleared. |

**Verified additive (D312):** `diff` of the original `siptest/proxy.go` against `internal/testutil/sipproxy/proxy.go`
produces the package clause line plus **only added (`>`) lines** — no `<` line beyond the two already
recorded in rows 2 and 3 (the move's package clause, and the `Sscanf` errcheck fix). Rows 5–8 above
are that additive diff's content.

## Import scope at P1 (locked decision 9)

All four packages are copied — the snapshot is the artifact D1 describes — but P1
imports only a subset.

| Package / file | P1 status |
|---|---|
| `digest/` | **Imported.** Reused directly (§7.1: the cleanest part of the engine). |
| `siptest/builders.go` | **Imported.** Via transport is hardcoded `"UDP"`; a transport parameter is added later for R5. |
| `siptest/client.go` | **Imported.** Transaction plumbing. Note `sipgo.WithClientAddr(cfg.LocalAddr)` at line 20 — the Via-pinning half of the §3d concrete-bind constraint. `sipua` must preserve it. |
| `siptest/uac.go` | **Imported** for `DoRequestWithDigest` — encodes a hard-won sipgo v0.24.1 workaround. `RunUAC` is reference only (blocking, single-call, no handles). |
| `siptest/uas.go`, `siptest/sdp.go` | **Not imported.** `RunUAS` is superseded by `sipua`; `DefaultSDP` is a hardcoded PCMU-only offer that §7.1 marks **Replace**. |
| `config/` | **Not imported by any first-party `sipclient-mcp` code**, but **compiled as a transitive dependency of `siptest`** — `siptest/{builders,client,sdp,uac,uas}.go` all import it. It is linked, not ported. Do not read its presence in the build graph as adoption of its configuration model. |
| `calltester/` | **Reference only / port at P2.** Not imported by anything. §7.3: `internal/media` is a rewrite that ports the algorithms, not a wrapper. **`calltester/media.go`'s loss accounting is known wrong** — plain unsigned sequence comparison, broken across the uint16 wrap, no duplicate or out-of-order accounting (spec §14.2). It must not be ported as-is. |
