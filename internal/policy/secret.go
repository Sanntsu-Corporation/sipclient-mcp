package policy

import "log/slog"

const redacted = "[REDACTED]"

// Secret carries a credential out of internal/policy to the one caller that
// needs it (internal/sipua, for digest authentication). Every rendering
// method is overridden so that a Secret reaching a log line, a fmt verb or a
// JSON response emits [REDACTED] instead of its value. This is spec D6
// credential isolation made structural rather than conventional: leaking
// requires calling Reveal() explicitly, which is greppable.
type Secret struct {
	v string
}

// NewSecret wraps a plaintext credential.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the plaintext. The only legitimate caller is the code that
// computes a SIP digest response.
func (s Secret) Reveal() string { return s.v }

// String implements fmt.Stringer.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (s Secret) GoString() string { return redacted }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }
