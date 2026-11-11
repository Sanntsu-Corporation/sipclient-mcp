// Package importguard holds the import-boundary assertions of spec §14.2.
// It contains test files only; there is no production code here.
package importguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/sanntsu-corporation/sipclient-mcp"

// deps returns the transitive import set reported by `go list -deps` for the
// given arguments, run from inside the module.
func deps(t *testing.T, args ...string) (map[string]bool, error) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-deps", "-f", "{{.ImportPath}}"}, args...)...)
	cmd.Dir = ".." // internal/ ; any directory inside the module works
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, &listError{args: args, out: string(out), err: err}
	}
	set := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		// Test-augmented variants are printed as "path [path.test]";
		// the import path is the first field.
		if f := strings.Fields(strings.TrimSpace(line)); len(f) > 0 {
			set[f[0]] = true
		}
	}
	return set, nil
}

type listError struct {
	args []string
	out  string
	err  error
}

func (e *listError) Error() string {
	return "go list " + strings.Join(e.args, " ") + ": " + e.err.Error() + "\n" + e.out
}

// forbidden reports every entry of banned present in set, matching a package
// and everything beneath it (so internal/media/codec is caught by
// internal/media).
func forbidden(set map[string]bool, banned []string) []string {
	var hits []string
	for imp := range set {
		for _, b := range banned {
			if imp == b || strings.HasPrefix(imp, b+"/") {
				hits = append(hits, imp)
			}
		}
	}
	return hits
}

// TestSipengineDoesNotLinkTesting asserts that no vendored engine package drags
// the testing package into a production build. siptest/proxy.go imported
// "testing" from a non-_test.go file upstream (spec §7.1); vendoring moves it to
// internal/testutil/sipproxy.
func TestSipengineDoesNotLinkTesting(t *testing.T) {
	pkgs := []string{
		module + "/internal/sipengine/siptest",
		module + "/internal/sipengine/digest",
		module + "/internal/sipengine/config",
		module + "/internal/sipengine/calltester",
	}

	for _, pkg := range pkgs {
		t.Run(pkg, func(t *testing.T) {
			set, err := deps(t, pkg)
			if err != nil {
				t.Fatalf("go list failed: %v", err)
			}
			if set["testing"] {
				t.Errorf("%s links the testing package into the production build", pkg)
			}
		})
	}
}

// TestClockDoesNotImportTestutil asserts the dependency direction of locked
// decision 18: fakeclock depends on clock, never the reverse. If internal/clock
// ever reached into internal/testutil, spec §9's guarantee that testutil is
// unreachable from the shipped daemon would be void the moment any production
// package took a Clock.
func TestClockDoesNotImportTestutil(t *testing.T) {
	set, err := deps(t, module+"/internal/clock")
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	for imp := range set {
		if strings.HasPrefix(imp, module+"/internal/testutil") {
			t.Errorf("internal/clock imports %s; testutil must never be reachable from production code (spec §9)", imp)
		}
	}
}

// TestDetectorFlagsAKnownImport is the NEGATIVE CONTROL for every assertion
// in this file. An import-boundary test that has never been observed failing
// proves nothing: if `go list` silently returned an empty set — a changed
// flag, a build error swallowed, a wrong working directory — every other
// assertion here would pass vacuously forever. This test asserts the
// detector DOES see imports that internal/session certainly has.
func TestDetectorFlagsAKnownImport(t *testing.T) {
	set, err := deps(t, module+"/internal/session")
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	if len(set) < 5 {
		t.Fatalf("dependency set is implausibly small (%d entries); the detector is not working", len(set))
	}
	for _, known := range []string{"context", "io", "time"} {
		if !set[known] {
			t.Errorf("detector did not see %q among internal/session's deps; it cannot be trusted to see a forbidden one", known)
		}
	}
}

// engineLayer is the set §6.2.1 and §14.2 forbid: if any of these appears in
// internal/session's TEST binary, session's tests are not running on fakes.
var engineLayer = []string{
	module + "/internal/sipua",
	module + "/internal/media",
	module + "/internal/trace",
	module + "/internal/artifact",
	module + "/internal/sipengine",
	"github.com/emiago/sipgo",
	"github.com/pion/rtp",
}

// TestSessionTestPackageRunsOnFakes is §6.2.1's acceptance: internal/session's
// TEST binary must import none of the engine layer. -test is what makes this
// an assertion about the tests and not merely about the production package: a
// fake in internal/testutil/fakes that quietly imported internal/sipua would
// pull sipgo into this set and FAIL THE BUILD of the boundary, rather than
// passing silently while pretending to be a fake.
func TestSessionTestPackageRunsOnFakes(t *testing.T) {
	set, err := deps(t, "-test", module+"/internal/session")
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	if hits := forbidden(set, engineLayer); len(hits) > 0 {
		t.Errorf("internal/session's test binary imports the engine layer, so its tests are not running on fakes: %v", hits)
	}
}

// TestSessionProductionPackageDoesNotImportTheEngineLayer is the SEPARATE
// assertion about the PRODUCTION package. It is not implied by the -test
// variant above and is not redundant with it: the two could only be merged if
// the test binary were a superset in the direction that matters, and the
// assertion that actually protects §6.2's layering is this one — a production
// edge from session to sipua or sipgo would propagate to transport/mcp, which
// imports session, and break §14.2's transport-boundary row too.
//
// NOTE what is NOT forbidden here: internal/policy. U9 explicitly permits
// session -> policy, because Manager reads limits live from
// cfg.Policy.Current() and policy.Limits is the ONE canonical limits type
// (Rule 18). Adding policy to engineLayer would be a defect.
func TestSessionProductionPackageDoesNotImportTheEngineLayer(t *testing.T) {
	set, err := deps(t, module+"/internal/session")
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}
	if hits := forbidden(set, engineLayer); len(hits) > 0 {
		t.Errorf("internal/session (production) imports the engine layer, violating §6.2 and Part 1.1: %v", hits)
	}
}

// TestTransportMCPDoesNotImportTheEngineLayer is §6.2's layering rule: the
// MCP layer never touches sipgo, RTP or codec types. It speaks only to
// session and policy.
func TestTransportMCPDoesNotImportTheEngineLayer(t *testing.T) {
	pkg := module + "/internal/transport/mcp"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list failed: %v", err)
	}
	if hits := forbidden(set, engineLayer); len(hits) > 0 {
		t.Errorf("%s transitively imports the engine layer, violating §6.2: %v", pkg, hits)
	}
}

// TestDaemonDoesNotShipTestUtil is §9's rule that internal/testutil is
// test-only scaffolding and is never reachable from the shipped daemon.
//
// IT CARRIES MORE WEIGHT THAN ITS OWN §9 ROW. TestRevealAppearsOnlyIn-
// ProductionWiring excludes internal/testutil from its credential-de-redaction
// scan, and that exclusion is sound ONLY because this test holds. Weaken this
// and a .Reveal() could reach a shipped binary unseen. Do not narrow it to a
// named subpackage, and do not soften the failure to a skip.
//
// This is also the CANONICAL home for the property (Rule 18, U8): P1e Task 22
// previously asserted the same thing as TestTestutilIsUnreachableFromThe-
// Daemon and now cites this instead. The assertion below is at least as
// strong — `forbidden` matches the prefix, so it catches
// internal/testutil itself AND every package beneath it.
func TestDaemonDoesNotShipTestUtil(t *testing.T) {
	pkg := module + "/cmd/sipclient-mcpd"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list failed: %v", err)
	}
	if hits := forbidden(set, []string{module + "/internal/testutil"}); len(hits) > 0 {
		t.Errorf("%s transitively imports test-only scaffolding: %v", pkg, hits)
	}
}

// TestTraceImportsNeitherSipuaNorSipgo is Part 1.3's layering rule, and it is
// an INVERSION of what an earlier draft asserted. internal/trace is a PURE
// RENDERER over session.SIPRecord: it parses nothing, so it needs neither
// sipgo nor internal/sipua. The wire tap (ObservingConn) lives in
// internal/sipua, which already owns the socket and the §3d concrete-bind
// constraint, and which emits a fully-populated session.SIPRecord into the
// session.Tap that session installed at construction.
//
// Removing both edges is what makes trace's three renderers testable against
// hand-built records, and it is why session.SIPRecord carries only plain
// scalars and MUST NOT gain a sip.Message field.
//
// P1c Task 16 must NOT reintroduce a trace -> sipua edge "for the record
// type": the record type is session's.
func TestTraceImportsNeitherSipuaNorSipgo(t *testing.T) {
	pkg := module + "/internal/trace"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list failed: %v", err)
	}
	banned := []string{module + "/internal/sipua", "github.com/emiago/sipgo"}
	if hits := forbidden(set, banned); len(hits) > 0 {
		t.Errorf("%s imports what Part 1.3 forbids — it is a pure renderer over session.SIPRecord: %v", pkg, hits)
	}
}

// TestSipuaDoesNotImportTrace is §6.2's peer rule, the other direction of
// Part 1.3: internal/sipua and internal/trace are PEERS and never call each
// other. sipua must NOT import trace, or sipua would carry a compile-time
// dependency on the renderer — exactly what §6.2's tap-wiring exception
// (session installs the trace tap into sipua at construction) exists to
// prevent.
//
// Uses the same deps/forbidden/skipIfPackageMissing helpers as every other
// row in this file (Rule 18) rather than go/build.Import: build.Import sees
// only DIRECT imports and would silently miss a transitive edge, which is
// the entire point of a boundary guard.
func TestSipuaDoesNotImportTrace(t *testing.T) {
	pkg := module + "/internal/sipua"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list failed: %v", err)
	}
	banned := []string{module + "/internal/trace"}
	if hits := forbidden(set, banned); len(hits) > 0 {
		t.Errorf("%s imports %v; sipua must hold only the session.Tap interface, never the renderer (§6.2)", pkg, hits)
	}
}

// revealSites reports one "path:line" per REAL .Reveal() call site among the
// given files: a *ast.CallExpr whose Fun is a *ast.SelectorExpr named
// "Reveal". Comments and string-literal contents are never part of the
// expression tree go/parser builds, so a `// DO NOT ADD .Reveal().` comment or
// a `.Reveal()` inside a string literal is never mistaken for a call here —
// unlike a textual/git-grep count, which cannot tell the two apart.
//
// This is deliberately the SAME counting method as
// .superpowers/sdd/integrity-check.sh's G5 gate (Rule 18: one canonical
// implementation of the .Reveal()-call-site invariant). G5 shells out to a
// generated Go binary because bash has no AST parser available to it; this
// test IS Go, so it calls go/parser directly instead of regenerating that
// binary.
func revealSites(t *testing.T, files []string) []string {
	t.Helper()
	var sites []string
	fset := token.NewFileSet()
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("revealSites: parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Reveal" {
				return true
			}
			sites = append(sites, fset.Position(call.Pos()).String())
			return true
		})
	}
	return sites
}

// TestRevealAppearsOnlyInProductionWiring is B2's greppable half, and it is a
// §14.2-style source assertion rather than an import assertion — which is why
// it lives here: internal/importguard is the canonical home for assertions
// about the shape of the tree (Rule 18), not merely its imports.
//
// policy.Secret redacts itself in String, GoString, MarshalJSON and LogValue.
// The ONE way to get the plaintext back is .Reveal(), and that is deliberate:
// it makes every credential de-redaction a greppable event.
//
// WHAT THIS ASSERTS, AND WHY IT IS SHAPED THIS WAY. An earlier form of this
// test counted .Reveal() across the whole tree and required exactly one. That
// shape was WRONG, and the reason generalises: an "appears exactly once"
// invariant over a REQUIRED primitive is unstable, because some call site
// must exist and any legitimate second one breaks the test rather than the
// property. The durable form names the BOUNDARY BEING PROTECTED — no
// de-redaction in anything the shipped daemon links — and enforces it by
// excluding code the daemon provably cannot reach.
//
// There are two irreducible reveals, and only the first is production:
//
//  1. PRODUCTION — the wiring closure where session.UAConfig (holding a
//     policy.Secret) becomes sipua.Config (holding a string), because
//     Part 1.1 forbids the direct edge sipua -> policy. The redaction
//     guarantee is upheld one layer up and the plaintext crosses there, once.
//     P1d Task 20's daemon and P1e's loopback harness are THE SAME CLOSURE at
//     two composition roots.
//  2. TEST-ONLY — internal/testutil/sipproxy's digest verifier. Digest auth
//     IS MD5 over the plaintext, so R1's REGISTER -> 401 -> REGISTER -> 200
//     acceptance cannot be verified without revealing it. It reveals INSIDE
//     the digest computation, with SetDigest taking a policy.Secret, so the
//     value stays redacted across the API boundary.
//
// EXCLUDING internal/testutil IS ONLY SOUND BECAUSE THE DAEMON CANNOT REACH
// IT. That is not an assumption here — it is asserted by
// TestDaemonDoesNotShipTestUtil in this same file. If that test is ever
// weakened or deleted, THIS exclusion silently becomes a hole through which a
// credential de-redaction could reach a shipped binary. The two travel
// together.
func TestRevealAppearsOnlyInProductionWiring(t *testing.T) {
	// The ":(top)" pathspec magic makes every path repo-root-relative
	// regardless of the directory `go test` runs the binary in — without it
	// these exclusions would be resolved against internal/importguard and
	// silently match nothing, which is the vacuous-pass this assertion is
	// itself guarding against.
	//
	// A STANDALONE ":(top)" POSITIVE PATHSPEC IS REQUIRED ALONGSIDE THE
	// EXCLUDES, not merely the ":(top,exclude)" magic on each exclusion.
	// Observed directly: with only the four exclude pathspecs below and no
	// positive ":(top)", `git grep` run from internal/importguard/ (this
	// package's own directory, which is where `go test ./internal/importguard/`
	// executes the binary) silently scopes its IMPLICIT positive match to the
	// current directory and below — not the whole repository — because an
	// all-exclude pathspec list has no positive pathspec to make root-relative.
	// Since this package's only file matches ":(top,exclude)*_test.go", the
	// search collapsed to zero matches from every subdirectory, which is
	// exactly the vacuous-pass this assertion exists to prevent. Confirmed
	// fixed by adding ":(top)" as an explicit leading positive pathspec: the
	// same query then finds internal/session/collaborators.go's `.Reveal()`
	// prose from any cwd, matching the repo-root run.
	//
	// internal/testutil is excluded because the daemon cannot reach it —
	// TestDaemonDoesNotShipTestUtil, below, is what makes that true.
	//
	// -l (not -n) is deliberate: git grep here is a fast TEXTUAL PRE-FILTER
	// for CANDIDATE FILES only — any file mentioning ".Reveal()" anywhere,
	// comment, string literal or real call. revealSites is what actually
	// DECIDES whether a candidate's mention is a real call site, exactly as
	// G5's own comment describes for the identical split there.
	out, err := exec.Command("git", "grep", "-l", "--full-name", `\.Reveal()`, "--",
		":(top)", ":(top,exclude)internal/policy", ":(top,exclude)internal/testutil",
		":(top,exclude)*_test.go", ":(top,exclude)docs").CombinedOutput()
	// git grep exits 1 with EMPTY output when there are simply no matches;
	// a non-zero exit WITH output is a real failure.
	if err != nil && len(strings.TrimSpace(string(out))) > 0 {
		t.Fatalf("git grep failed: %v\n%s", err, out)
	}
	var candidates []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			candidates = append(candidates, line)
		}
	}

	// --full-name paths are repo-root-relative regardless of cwd (the same
	// ":(top)" property discussed above); this test's own binary runs with
	// cwd == internal/importguard, so the paths must be rejoined against the
	// repo root before go/parser can open them.
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel: %v\n%s", err, root)
	}
	repoRoot := strings.TrimSpace(string(root))
	files := make([]string, len(candidates))
	for i, c := range candidates {
		files[i] = filepath.Join(repoRoot, c)
	}

	sites := revealSites(t, files)

	switch {
	case len(sites) == 1:
		// The armed, expected steady state once Task 20's production wiring
		// closure lands: exactly one REAL, go/ast-verified .Reveal() call
		// site. Not a textual mention — see revealSites — so a
		// "DO NOT ADD .Reveal()." comment can never masquerade as this.
	case len(sites) == 0:
		t.Skipf("BOUNDARY ROW NOT YET ARMED: no .Reveal() call site exists in production " +
			"code. The one legitimate site is the wiring closure where session.UAConfig " +
			"becomes sipua.Config (cmd/sipclient-mcpd, P1d Task 20), which has not landed. " +
			"This row MUST show PASS, not SKIP, at the P1 exit gate.")
	default:
		t.Errorf("found %d .Reveal() call sites in PRODUCTION code, want 1 — the wiring "+
			"closure where session.UAConfig becomes sipua.Config. Each is a deliberate "+
			"de-redaction of a credential inside a shipped binary and must be justified "+
			"before this count is raised. Test-only reveals belong under internal/testutil, "+
			"which is excluded here BECAUSE TestDaemonDoesNotShipTestUtil proves the daemon "+
			"cannot link it:\n%s", len(sites), strings.Join(sites, "\n"))
	}
}

// skipIfPackageMissing skips a boundary row whose package this task has not
// yet created, and does so LOUDLY. These rows arm automatically when the
// package appears: the task that creates internal/transport/mcp and the task
// that creates cmd/sipclient-mcpd each own confirming that its row has gone
// from SKIP to PASS, and P1's exit gate requires every test in this file to
// PASS with no skips.
func skipIfPackageMissing(t *testing.T, pkg string, err error) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, "no required module provides package") ||
		strings.Contains(msg, "is not in std") ||
		strings.Contains(msg, "no Go files") ||
		strings.Contains(msg, "cannot find package") {
		t.Skipf("BOUNDARY ROW NOT YET ARMED: %s does not exist. This row MUST show PASS, not SKIP, at the P1 exit gate.", pkg)
	}
}

// repoRoot resolves the module root from this package's own directory
// (internal/importguard), two levels down from it.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	return root
}

// TestForwardPackagesAreAbsentAtP1 is P1e Task 22 Step 10: locked decision 13
// creates internal/testutil/netfault at P2 and internal/testutil/certs at
// P4; neither is stubbed empty at P1. An empty stub would be dead code
// (Rule 15) and would make the later plan's "create netfault"/"create certs"
// step a no-op nobody notices.
//
// P2 Wave 2 Task 7 creates internal/testutil/netfault, so it is removed from
// this guard's list (see TestNetfaultAbsentFromDaemon, below, for its
// import-boundary assertion instead); internal/testutil/certs remains here —
// it is still P4.
//
// This is the ONLY assertion P1e Task 22 adds to this file — the
// testutil-unreachability property itself is TestDaemonDoesNotShipTestUtil,
// above, per Rule 18: two tests of one property is exactly how one gets
// weakened later by someone who believes the other still holds.
func TestForwardPackagesAreAbsentAtP1(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range []string{
		filepath.Join(root, "internal", "testutil", "certs"),
	} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("%s exists at P1; decision 13 creates certs at P4", dir)
		}
	}
}

// TestMediaCodecDoesNotImportSessionOrSipua is the Global Constraint for
// internal/media/codec (Task 8, DTMF): the package is pure DSP — no sockets,
// no goroutines — and must sit BELOW both internal/session and internal/sipua
// so either can depend on it without a cycle. This row previously did not
// exist for ANY package under internal/media/codec: adding a forbidden import
// there compiled clean and the importguard suite still reported ok, silently
// leaving the constraint unenforced. Task 8 is the task that actually builds
// out DTMF logic in this package, so it is the one that arms this row.
func TestMediaCodecDoesNotImportSessionOrSipua(t *testing.T) {
	pkg := module + "/internal/media/codec"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list failed: %v", err)
	}
	banned := []string{module + "/internal/session", module + "/internal/sipua"}
	if hits := forbidden(set, banned); len(hits) > 0 {
		t.Errorf("%s imports %v; it must stay pure DSP below both session and sipua", pkg, hits)
	}
}

// TestNetfaultAbsentFromDaemon is §14.6's named, more-legible restatement of
// TestDaemonDoesNotShipTestUtil for the P2 Wave 2 fault injector: the daemon
// binary must never transitively import internal/testutil/netfault. A tool
// that could inject loss would let an agent manufacture a quality result, so
// this boundary carries the same weight as the general testutil guard above,
// named explicitly for netfault (D10).
func TestNetfaultAbsentFromDaemon(t *testing.T) {
	pkg := module + "/cmd/sipclient-mcpd"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list: %v", err)
	}
	if hits := forbidden(set, []string{module + "/internal/testutil/netfault"}); len(hits) > 0 {
		t.Errorf("daemon transitively imports the test-only fault injector: %v", hits)
	}
}

// TestProxyDoesNotLinkDaemonCode asserts spec 2026-09-30 D1: the sipclient-proxy
// binary links no daemon internals and no test scaffolding.
func TestProxyDoesNotLinkDaemonCode(t *testing.T) {
	pkg := module + "/cmd/sipclient-proxy"
	set, err := deps(t, pkg)
	if err != nil {
		skipIfPackageMissing(t, pkg, err)
		t.Fatalf("go list failed: %v", err)
	}
	banned := []string{
		module + "/internal/testutil", module + "/internal/session", module + "/internal/sipua",
		module + "/internal/transport", module + "/internal/policy", module + "/internal/sipengine",
	}
	if hits := forbidden(set, banned); len(hits) > 0 {
		t.Errorf("%s transitively imports daemon/test code: %v", pkg, hits)
	}
}
