package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
)

func TestNormalise(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "already canonical", in: "sip:1800555@carrier-a.example", want: "sip:1800555@carrier-a.example"},
		{name: "bare host port gets a sip scheme", in: "192.0.2.10:5060", want: "sip:192.0.2.10:5060"},
		{name: "bare host gets a sip scheme", in: "lab.internal", want: "sip:lab.internal"},
		{name: "uppercase scheme lowercased", in: "SIP:user@lab.internal", want: "sip:user@lab.internal"},
		{name: "sips preserved", in: "SIPS:user@lab.internal", want: "sips:user@lab.internal"},
		{name: "host case folded", in: "sip:user@LAB.Internal", want: "sip:user@lab.internal"},
		{name: "user part case preserved", in: "sip:TestUser@lab.internal", want: "sip:TestUser@lab.internal"},
		{name: "uri parameters stripped", in: "sip:user@lab.internal;transport=udp", want: "sip:user@lab.internal"},
		{name: "headers stripped", in: "sip:user@lab.internal?X-Foo=bar", want: "sip:user@lab.internal"},
		{name: "params and headers stripped", in: "sip:user@lab.internal;transport=tcp?X-Foo=bar", want: "sip:user@lab.internal"},
		{name: "surrounding whitespace trimmed", in: "  sip:user@lab.internal  ", want: "sip:user@lab.internal"},
		{name: "angle brackets stripped", in: "<sip:user@lab.internal>", want: "sip:user@lab.internal"},
		{name: "angle brackets with inner whitespace get re-trimmed", in: "< sip:x@lab.internal >", want: "sip:x@lab.internal"},
		{name: "semicolon before the host is not stripped", in: "sip:user;foo@lab.internal", want: "sip:user;foo@lab.internal"},
		{name: "header containing an at-sign is stripped, not just truncated to the host", in: "sip:x@lab.internal?Replaces=abc@def", want: "sip:x@lab.internal"},
		{name: "parameter value containing an at-sign is stripped, not just truncated to the host", in: "sip:x@lab.internal;foo=a@b", want: "sip:x@lab.internal"},
		{name: "maddr parameter containing an at-sign is stripped, not just truncated to the host", in: "sip:x@lab.internal;maddr=1.2.3.4@x", want: "sip:x@lab.internal"},
		{name: "trailing dot on the host is stripped", in: "sip:user@lab.internal.", want: "sip:user@lab.internal"},
		{name: "trailing dot before the port is stripped", in: "sip:user@lab.internal.:5060", want: "sip:user@lab.internal:5060"},
		{name: "bare host with a trailing dot", in: "lab.internal.", want: "sip:lab.internal"},
		{name: "bare host port with a trailing dot", in: "LAB.internal.:5061", want: "sip:lab.internal:5061"},
		{name: "trailing dot with sips, case and parameters", in: "SIPS:user@LAB.Internal.;transport=tls", want: "sips:user@lab.internal"},
		{name: "repeated trailing dots are all stripped", in: "sip:user@lab.internal..", want: "sip:user@lab.internal"},
		{name: "a dot at the end of the user part is kept", in: "sip:user.@lab.internal", want: "sip:user.@lab.internal"},
		{name: "ipv6 literal is untouched", in: "sip:user@[2001:db8::1]:5060", want: "sip:user@[2001:db8::1]:5060"},
		{name: "empty stays empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalise(tt.in); got != tt.want {
				t.Errorf("Normalise(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func policyWithDestinations(t *testing.T, allow, deny []string) *Policy {
	t.Helper()
	tok := writeFile(t, "token", "bearer-token-value\n")
	var b strings.Builder
	fmt.Fprintf(&b, "auth:\n  bearer_token_file: %s\ndestinations:\n", tok)
	b.WriteString("  allow: [")
	for i, a := range allow {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "'%s'", a)
	}
	b.WriteString("]\n  deny: [")
	for i, d := range deny {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "'%s'", d)
	}
	b.WriteString("]\n")
	p, err := Load(writePolicy(t, b.String()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

func TestCheckDestination(t *testing.T) {
	const (
		labAllow  = `^sip:.*@lab\.internal$`
		e164Allow = `^sip:\+?1[0-9]{10}@carrier-a\.example$`
		premium   = `^sip:\+?1900`
		labDeny   = `^sip:blocked@lab\.internal$`
	)

	tests := []struct {
		name       string
		allow      []string
		deny       []string
		uri        string
		wantRule   string
		wantDenied bool
	}{
		{
			name: "no lists configured permits everything",
			uri:  "sip:anyone@anywhere.example",
		},
		{
			name:     "allow list present and matched permits, naming the pattern",
			allow:    []string{labAllow, e164Allow},
			uri:      "sip:probe@lab.internal",
			wantRule: labAllow,
		},
		{
			name:       "allow list present and unmatched is DENIED BY DEFAULT",
			allow:      []string{labAllow},
			uri:        "sip:probe@elsewhere.example",
			wantRule:   RuleAllowListDefault,
			wantDenied: true,
		},
		{
			name:       "deny wins over a matching allow",
			allow:      []string{labAllow},
			deny:       []string{labDeny},
			uri:        "sip:blocked@lab.internal",
			wantRule:   labDeny,
			wantDenied: true,
		},
		{
			name:       "deny applies with no allow list configured",
			deny:       []string{premium},
			uri:        "sip:+19005551212@carrier-a.example",
			wantRule:   premium,
			wantDenied: true,
		},
		{
			name: "unmatched by deny with no allow list is permitted",
			deny: []string{premium},
			uri:  "sip:+18005551212@carrier-a.example",
		},
		{
			name:       "first matching deny pattern is the one named",
			deny:       []string{premium, `^sip:\+?1`},
			uri:        "sip:+19005551212@carrier-a.example",
			wantRule:   premium,
			wantDenied: true,
		},
		{
			name:       "evaluation is on the NORMALISED uri: params cannot evade an anchored deny",
			deny:       []string{labAllow},
			uri:        "sip:probe@lab.internal;transport=udp",
			wantRule:   labAllow,
			wantDenied: true,
		},
		{
			name:       "evaluation is on the NORMALISED uri: case cannot evade a deny",
			deny:       []string{labAllow},
			uri:        "SIP:probe@LAB.Internal",
			wantRule:   labAllow,
			wantDenied: true,
		},
		{
			name:     "evaluation is on the NORMALISED uri: a bare host:port is schemed first",
			allow:    []string{`^sip:192\.0\.2\.10:5060$`},
			uri:      "192.0.2.10:5060",
			wantRule: `^sip:192\.0\.2\.10:5060$`,
		},
		{
			name:       "evaluation is on the NORMALISED uri: padded angle brackets cannot evade a deny",
			deny:       []string{labAllow},
			uri:        "< sip:x@lab.internal >",
			wantRule:   labAllow,
			wantDenied: true,
		},
		{
			name:       "evaluation is on the NORMALISED uri: a semicolon before the host cannot evade a deny",
			deny:       []string{labAllow},
			uri:        "sip:user;foo@lab.internal",
			wantRule:   labAllow,
			wantDenied: true,
		},
		{
			name:       "evaluation is on the NORMALISED uri: an at-sign in a header value cannot evade a deny",
			deny:       []string{labAllow},
			uri:        "sip:x@lab.internal?Replaces=abc@def",
			wantRule:   labAllow,
			wantDenied: true,
		},
		{
			name:       "evaluation is on the NORMALISED uri: an at-sign in a parameter value cannot evade a deny",
			deny:       []string{labAllow},
			uri:        "sip:x@lab.internal;foo=a@b",
			wantRule:   labAllow,
			wantDenied: true,
		},
		{
			name:       "evaluation is on the NORMALISED uri: an at-sign in a maddr parameter cannot evade a deny",
			deny:       []string{labAllow},
			uri:        "sip:x@lab.internal;maddr=1.2.3.4@x",
			wantRule:   labAllow,
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := policyWithDestinations(t, tt.allow, tt.deny)
			_, rule, err := p.CheckDestination(tt.uri)

			if rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", rule, tt.wantRule)
			}
			if !tt.wantDenied {
				if err != nil {
					t.Fatalf("want permitted, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want denied, got nil error")
			}
			var apiErr *apierr.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("want *apierr.Error, got %T: %v", err, err)
			}
			if apiErr.Code != apierr.CodeDenied {
				t.Errorf("code = %q, want %q", apiErr.Code, apierr.CodeDenied)
			}
			// §11.2: a denied response NAMES THE RULE THAT FIRED. The
			// returned rule and the error's Rule field must agree, so the
			// caller can build the denied shape from either.
			if apiErr.Rule != tt.wantRule {
				t.Errorf("apierr Rule = %q, want %q", apiErr.Rule, tt.wantRule)
			}
			// A destination denial carries no numeric bound: Limit and
			// Current belong to the §12.2.2 cap denials, which Task 9 builds
			// with apierr.DeniedLimit. Asserting they are nil here keeps the
			// two denial shapes distinguishable by an agent.
			if apiErr.Limit != nil || apiErr.Current != nil {
				t.Errorf("a destination denial must carry no limit/current, got limit=%v current=%v",
					apiErr.Limit, apiErr.Current)
			}
		})
	}
}

// CF-211: a trailing dot names the same DNS host, so it must not evade a
// '$'-anchored deny pattern.
func TestCheckDestinationDenyIsNotEvadedByATrailingDot(t *testing.T) {
	p := policyWithDestinations(t, nil, []string{`@denied\.example(:[0-9]+)?$`})
	for _, target := range []string{
		"sip:x@denied.example",
		"sip:x@denied.example.",
		"sip:x@DENIED.example.:5060",
		"sips:x@denied.example..",
	} {
		if _, _, err := p.CheckDestination(target); err == nil {
			t.Errorf("CheckDestination(%q) was allowed, want a deny", target)
		}
	}
	if _, _, err := p.CheckDestination("sip:x@allowed.example."); err != nil {
		t.Errorf("CheckDestination(allowed.example.) = %v, want allowed", err)
	}
}
