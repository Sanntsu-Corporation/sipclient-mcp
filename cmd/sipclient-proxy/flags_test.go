package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseServeFlags(t *testing.T) {
	def := func() (string, error) { return "/default/sipclient-proxy.json", nil }
	tests := []struct {
		name string
		args []string
		def  func() (string, error)
		want serveConfig
		err  bool
	}{
		{"default path", nil, def, serveConfig{ConfigPath: "/default/sipclient-proxy.json"}, false},
		{"config override", []string{"--config", "/x.json"}, def, serveConfig{ConfigPath: "/x.json"}, false},
		{"version needs no path", []string{"--version"}, func() (string, error) { return "", errors.New("no home") }, serveConfig{ShowVersion: true}, false},
		{"unknown flag", []string{"--nope"}, def, serveConfig{}, true},
		{"positional arg", []string{"stray"}, def, serveConfig{}, true},
		{"default path error", nil, func() (string, error) { return "", errors.New("no home") }, serveConfig{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseServeFlags(tc.args, tc.def)
			if (err != nil) != tc.err || got != tc.want {
				t.Fatalf("got %+v err=%v; want %+v err=%v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	if got := versionString(); !strings.HasPrefix(got, "sipclient-proxy dev (commit none, built unknown)") {
		t.Fatalf("unstamped versionString = %q", got)
	}
}
