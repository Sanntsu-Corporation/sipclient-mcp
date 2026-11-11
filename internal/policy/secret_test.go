package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const testPass = "sup3rs3cr3t-auth-pass"

// assertRedacted checks that a rendering of a Secret neither contains the
// plaintext nor omits the redaction marker, naming which rendering (verb,
// method, etc.) failed.
func assertRedacted(t *testing.T, name, got string) {
	t.Helper()
	if strings.Contains(got, testPass) {
		t.Errorf("%s leaked the secret: %s", name, got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("%s = %q, want it to mention REDACTED", name, got)
	}
}

func TestSecretNeverRendersItsValue(t *testing.T) {
	s := NewSecret(testPass)

	if got := s.Reveal(); got != testPass {
		t.Fatalf("Reveal() = %q, want %q", got, testPass)
	}

	// Format verbs are driven from data (rather than passed as literals to
	// fmt.Sprintf) so staticcheck's S1025 doesn't mistake the %s case for a
	// redundant call to String() and suggest collapsing away %s coverage.
	verbs := []string{"%v", "%s", "%+v", "%#v", "%q"}
	for _, verb := range verbs {
		assertRedacted(t, verb, fmt.Sprintf(verb, s))
	}

	// These two don't go through a literal fmt verb, so they sit outside the
	// table: String() is a direct method call, and the struct case exercises
	// a Secret nested inside another value.
	assertRedacted(t, "String", s.String())
	assertRedacted(t, "in a struct", fmt.Sprintf("%+v", struct{ P Secret }{P: s}))

	b, err := json.Marshal(struct {
		P Secret `json:"p"`
	}{P: s})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), testPass) {
		t.Errorf("json.Marshal leaked the secret: %s", b)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cred", slog.Any("pass", s))
	if strings.Contains(buf.String(), testPass) {
		t.Errorf("slog leaked the secret: %s", buf.String())
	}
}
