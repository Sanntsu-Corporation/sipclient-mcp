// Package apierr is the single source of the error codes defined by spec §11.2.
//
// Errors are returned as ordinary Go error values from internal/session and are
// converted to the JSON result envelope exactly once, in internal/transport/mcp
// (locked decision 11). This package deliberately carries no JSON struct tags and
// no MarshalJSON: a second serialisation here would compete with the transport's
// and break the §6.2 layering rule.
package apierr

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable error code. The complete set is spec §11.2's
// table, which that section declares exhaustive.
type Code string

// The eleven codes below are spec §11.2's table, transcribed verbatim and in
// the spec's document order.
const (
	CodeDenied             Code = "denied"
	CodeNotFound           Code = "not_found"
	CodeGone               Code = "gone"
	CodeInvalidArgument    Code = "invalid_argument"
	CodePreconditionFailed Code = "precondition_failed"
	CodeNotSupported       Code = "not_supported"
	CodeMediaNegotiation   Code = "media_negotiation"
	CodeTLSFailure         Code = "tls_failure"
	CodeResourceLimit      Code = "resource_limit"
	CodeCancelled          Code = "cancelled"
	CodeInternal           Code = "internal"
)

// AllCodes returns every code in spec §11.2's table, in that table's order. It
// returns a fresh slice on each call so a caller cannot mutate the enum.
func AllCodes() []Code {
	return []Code{
		CodeDenied,
		CodeNotFound,
		CodeGone,
		CodeInvalidArgument,
		CodePreconditionFailed,
		CodeNotSupported,
		CodeMediaNegotiation,
		CodeTLSFailure,
		CodeResourceLimit,
		CodeCancelled,
		CodeInternal,
	}
}

// Error is a spec §11.2 error. It is returned as a plain Go error from
// internal/session; internal/transport/mcp converts it to the JSON envelope.
type Error struct {
	// Code is the stable machine-readable code. Always set.
	Code Code
	// Message is human-readable. Always set.
	Message string
	// Detail names the failure precisely where §11.2 defines a detail object.
	Detail map[string]any
	// Rule names the exact policy key or pattern that fired, for denied and
	// resource_limit. §12.2.2 requires a concurrency denial to name the key that
	// bound.
	Rule string
	// Limit and Current accompany Rule for a cap. Both nil when the code is not
	// limit-shaped, matching §11.2's "limit": null for a pattern denial.
	Limit   *int
	Current *int
}

func (e *Error) Error() string {
	return string(e.Code) + ": " + e.Message
}

// CodeOf extracts the Code from err when err is (or wraps) an *Error, and ""
// otherwise — the single accessor callers use to classify an error without a
// type assertion at each call site.
func CodeOf(err error) Code {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// Denied reports a policy refusal naming the rule that fired (§11.2). Use
// DeniedLimit when the refusal is a concurrency cap and §12.2.2 requires the
// limit and current value alongside the key.
func Denied(rule, msg string) *Error {
	return &Error{Code: CodeDenied, Message: msg, Rule: rule}
}

// DeniedLimit reports a §12.2.2 concurrency denial, naming the exact policy key
// that bound together with its limit and the current value.
func DeniedLimit(rule string, limit, current int, msg string) *Error {
	return &Error{Code: CodeDenied, Message: msg, Rule: rule, Limit: &limit, Current: &current}
}

// NotFound reports that no resource matches the caller's handle or identifier.
// msg must be the complete human-readable sentence describing what was not
// found — this is NotFound(msg string), not NotFound(kind, id string); a
// kind/id decomposition is not recoverable from *Error and serves no consumer,
// so every caller formats its own sentence (e.g. via fmt.Sprintf).
func NotFound(msg string) *Error {
	return &Error{Code: CodeNotFound, Message: msg}
}

// Gone reports that a resource existed but has since been reclaimed. msg must
// be the complete human-readable sentence, formatted by the caller as for
// NotFound.
func Gone(msg string) *Error {
	return &Error{Code: CodeGone, Message: msg}
}

// InvalidArgument reports that a caller-supplied argument failed validation.
func InvalidArgument(msg string) *Error {
	return &Error{Code: CodeInvalidArgument, Message: msg}
}

// PreconditionFailed reports that the target is not in a state that allows the
// requested operation.
func PreconditionFailed(msg string) *Error {
	return &Error{Code: CodePreconditionFailed, Message: msg}
}

// NotSupported reports that the requested capability is not implemented.
func NotSupported(msg string) *Error {
	return &Error{Code: CodeNotSupported, Message: msg}
}

// MediaNegotiation reports an SDP offer/answer failure. kind is §11.2's
// detail.kind taxonomy and is stored under Detail["kind"]; detail carries the
// remaining case-specific fields and may be nil.
func MediaNegotiation(kind string, detail map[string]any, msg string) *Error {
	d := make(map[string]any, len(detail)+1)
	for k, v := range detail {
		d[k] = v
	}
	d["kind"] = kind
	return &Error{Code: CodeMediaNegotiation, Message: msg, Detail: d}
}

// TLSFailure reports a TLS handshake or certificate verification failure
// (§7's tls_failure classification). kind is §7's closed detail.kind
// taxonomy and is stored under Detail["kind"]; detail carries the remaining
// case-specific fields (peer, subject, fingerprint) and may be nil.
func TLSFailure(kind string, detail map[string]any, msg string) *Error {
	d := make(map[string]any, len(detail)+1)
	for k, v := range detail {
		d[k] = v
	}
	d["kind"] = kind
	return &Error{Code: CodeTLSFailure, Message: msg, Detail: d}
}

// ResourceLimit reports a server-side limit, naming the policy key in Rule.
func ResourceLimit(key string, limit, current int, msg string) *Error {
	return &Error{Code: CodeResourceLimit, Message: msg, Rule: key, Limit: &limit, Current: &current}
}

// Cancelled reports that the MCP caller cancelled the in-flight request via
// `notifications/cancelled` (§11.2, D361). This is not a bug — a cancelling
// agent did the right thing — so, unlike Internal, no correlation id is
// echoed and callers must not log it as a server fault.
func Cancelled(msg string) *Error {
	return &Error{Code: CodeCancelled, Message: msg}
}

// Internal reports an unexpected server fault. §11.2 requires the correlation id
// to be echoed in the message, so an operator can join the response to the log.
func Internal(correlationID, msg string) *Error {
	return &Error{
		Code:    CodeInternal,
		Message: fmt.Sprintf("%s (correlation_id=%s)", msg, correlationID),
	}
}
