package session

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// eventAppendingLookupExceptions names the *Manager.handle* methods that append
// an event to a Call and yet DELIBERATELY keep the live-only callByDialogID,
// with the reason each is exempt. It is the enforced form of the second half of
// THE EVENT-LOOKUP INVARIANT (registry.go).
//
// A new handler does NOT get added here to make this test pass. Either it
// appends and uses callByDialogIDForEvent, or it claims live state and its
// exemption is argued in review and recorded here with a reason.
//
// THERE IS EXACTLY ONE ENTRY, AND THE BAR FOR A SECOND IS THE ONE IT MEETS:
// handleDialogEnded is not a bystander that might race the live->terminated move,
// it is the code that CAUSES the move. An argument of the form "this event cannot
// arrive after termination" is NOT sufficient — handleMediaStart was exempted on
// exactly that reasoning and it was wrong, because emission order says nothing
// about the order the one-way event goroutine hands events to their handlers.
var eventAppendingLookupExceptions = map[string]string{
	"handleDialogEnded": "state-claiming AND part of the termination sequence itself: its Try* " +
		"transition is what causes the live->terminated move (and resolves the race through " +
		"terminal()), and it appends only on the path it has just claimed",
}

// appendingCalls are the Call methods that WRITE to a call's event log or digit
// ring. A handler that reaches any of them is an event-appending handler.
var appendingCalls = map[string]bool{
	"Append": true, "RecordDigit": true, "applyPlanStep": true, "applyPlanError": true,
}

// TestEventAppendingHandlersUseTheForEventLookup is the source-level half of THE
// EVENT-LOOKUP INVARIANT (registry.go). The behavioural half is
// TestFinalPlanStepSurvivesRecordTermination and its siblings.
//
// LIMITATION: the AST walk only sees calls to appendingCalls made DIRECTLY in a
// handle* method's own body — an append reached through an intermediate helper
// function is invisible to it. A future refactor that factors an append into a
// helper must re-check the invariant by hand rather than trusting this test.
func TestEventAppendingHandlersUseTheForEventLookup(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	type handler struct {
		appends  bool
		forEvent bool
		liveOnly bool
	}
	handlers := map[string]*handler{}

	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil {
					continue
				}
				if !strings.HasPrefix(fn.Name.Name, "handle") {
					continue
				}
				h := &handler{}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "callByDialogIDForEvent":
						h.forEvent = true
					case "callByDialogID":
						h.liveOnly = true
					default:
						if appendingCalls[sel.Sel.Name] {
							h.appends = true
						}
					}
					return true
				})
				handlers[fn.Name.Name] = h
			}
		}
	}

	if len(handlers) == 0 {
		t.Fatal("no handle* methods found; the walk is broken, not the code")
	}

	for name, h := range handlers {
		if h.forEvent && h.liveOnly {
			t.Errorf("%s uses BOTH lookups; one handler resolves its *Call exactly one way "+
				"(THE EVENT-LOOKUP INVARIANT, registry.go)", name)
		}
		if !h.appends {
			continue
		}
		if reason, exempt := eventAppendingLookupExceptions[name]; exempt {
			if h.forEvent {
				t.Errorf("%s is listed as a live-only exception (%s) but uses "+
					"callByDialogIDForEvent; drop it from eventAppendingLookupExceptions", name, reason)
			}
			continue
		}
		if !h.forEvent {
			t.Errorf("%s appends an event but does not resolve its *Call through "+
				"callByDialogIDForEvent. THE EVENT-LOOKUP INVARIANT (registry.go): an "+
				"event-appending handler MUST use the ForEvent lookup, or the call's LAST "+
				"event is dropped when RecordTermination wins the race. If this handler "+
				"claims live state instead, add it to eventAppendingLookupExceptions WITH "+
				"ITS REASON.", name)
		}
	}

	// A stale exemption is as bad as a missing one: it silently licenses the next
	// handler that inherits the name.
	for name := range eventAppendingLookupExceptions {
		h, ok := handlers[name]
		if !ok {
			t.Errorf("eventAppendingLookupExceptions names %s, which no longer exists", name)
			continue
		}
		if !h.appends {
			t.Errorf("eventAppendingLookupExceptions names %s, which no longer appends any "+
				"event; remove the exemption", name)
		}
	}
}
