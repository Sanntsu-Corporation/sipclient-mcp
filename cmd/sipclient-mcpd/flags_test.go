package main

import "testing"

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    daemonConfig
		wantErr bool
	}{
		{
			name: "defaults, state given explicitly",
			args: []string{"--policy", "/etc/sipclient/policy.yaml", "--state", "/tmp/state.yaml"},
			want: daemonConfig{
				PolicyPath: "/etc/sipclient/policy.yaml",
				ListenAddr: "127.0.0.1:8080",
				StatePath:  "/tmp/state.yaml",
			},
		},
		{
			name: "listen overridden",
			args: []string{"--policy", "/tmp/p.yaml", "--listen", "0.0.0.0:9999", "--state", "/tmp/state.yaml"},
			want: daemonConfig{PolicyPath: "/tmp/p.yaml", ListenAddr: "0.0.0.0:9999", StatePath: "/tmp/state.yaml"},
		},
		{
			name: "version needs no policy and no state",
			args: []string{"--version"},
			want: daemonConfig{ListenAddr: "127.0.0.1:8080", ShowVersion: true},
		},
		{
			// Phase 2 §2.5: --policy is no longer required. A completely
			// bare invocation is legal — the daemon bootstraps its own
			// default state file (§2.2a) — and --state, left unset here,
			// resolves to defaultStatePath()'s non-empty default rather
			// than staying blank.
			name: "policy optional, state defaults to a non-empty path",
			args: []string{},
		},
		{
			name: "print-tokens flag parses",
			args: []string{"--print-tokens", "--state", "/tmp/state.yaml"},
			want: daemonConfig{ListenAddr: "127.0.0.1:8080", StatePath: "/tmp/state.yaml", PrintTokens: true},
		},
		{
			name: "no shutdown-grace flag: the grace period is a policy key",
			args: []string{"--policy", "/tmp/p.yaml", "--state", "/tmp/state.yaml", "--shutdown-grace", "3s"},
			// Two sources for one number would let §11.4's shutdown and §12.7's
			// admin DELETE diverge. The flag does not exist.
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFlags(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFlags(%v) = %+v, want error", tt.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlags(%v) unexpected error: %v", tt.args, err)
			}
			if tt.name == "policy optional, state defaults to a non-empty path" {
				if got.StatePath == "" {
					t.Fatalf("parseFlags(%v).StatePath is empty, want a resolved default", tt.args)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("parseFlags(%v) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}
