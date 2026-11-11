package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/apierr"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakeclock"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/testutil/fakes"
)

// fakeArtifactStore is a small in-test fake session.ArtifactStore: Resolve
// returns fixed bytes for the one known uri and apierr.NotFound otherwise.
// Only URI and Resolve are exercised by serveArtifact; the rest satisfy the
// interface.
type fakeArtifactStore struct {
	knownURI string
	name     string
	body     []byte
}

func (f *fakeArtifactStore) OpenCallDir(context.Context, string) error { return nil }
func (f *fakeArtifactStore) Create(context.Context, string, string) (io.WriteCloser, error) {
	return nil, nil
}
func (f *fakeArtifactStore) Close(context.Context, string, string) (session.ArtifactInfo, error) {
	return session.ArtifactInfo{}, nil
}
func (f *fakeArtifactStore) Remove(context.Context, string, string) error { return nil }
func (f *fakeArtifactStore) URI(callHandle, name string) string {
	return "mcp://sipclient/artifacts/" + callHandle + "/" + name
}
func (f *fakeArtifactStore) Resolve(_ context.Context, uri string) (session.ArtifactInfo, io.ReadCloser, error) {
	if uri != f.knownURI {
		return session.ArtifactInfo{}, nil, apierr.NotFound("unknown artifact")
	}
	return session.ArtifactInfo{Name: f.name, Bytes: int64(len(f.body))}, io.NopCloser(strings.NewReader(string(f.body))), nil
}
func (f *fakeArtifactStore) UsageBytes(context.Context) (int64, error)        { return 0, nil }
func (f *fakeArtifactStore) NonLiveUsageBytes(context.Context) (int64, error) { return 0, nil }

// newArtifactTestEnvFor builds a test server whose single resolvable artifact
// is call_1/<name> with the given body — letting content-type tests exercise
// different extensions.
func newArtifactTestEnvFor(t *testing.T, name string, body []byte) http.Handler {
	t.Helper()
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	store, _ := testPolicyStore(t, clk, testToken, "")
	fake := &fakeArtifactStore{
		knownURI: "mcp://sipclient/artifacts/call_1/" + name,
		name:     name,
		body:     body,
	}
	srv, err := NewServer(Config{
		Sessions:  fakes.NewSessions(clk, time.Hour),
		Tools:     fakes.NewTools(),
		Policy:    store,
		Artifacts: fake,
		Log:       discardLogger(),
		Clock:     clk,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv.Handler()
}

func newArtifactTestEnv(t *testing.T) http.Handler {
	t.Helper()
	return newArtifactTestEnvFor(t, "capture.pcap", []byte("fake pcap bytes"))
}

func TestArtifactServeBearerAuth(t *testing.T) {
	handler := newArtifactTestEnv(t)

	get := func(t *testing.T, path, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	t.Run("no token", func(t *testing.T) {
		rr := get(t, "/artifacts/call_1/capture.pcap", "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		rr := get(t, "/artifacts/call_1/capture.pcap", "wrong")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("right token", func(t *testing.T) {
		rr := get(t, "/artifacts/call_1/capture.pcap", testToken)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if got := rr.Body.String(); got != "fake pcap bytes" {
			t.Fatalf("body = %q, want %q", got, "fake pcap bytes")
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/vnd.tcpdump.pcap" {
			t.Fatalf("Content-Type = %q, want %q", ct, "application/vnd.tcpdump.pcap")
		}
	})

	t.Run("traversal path rejected", func(t *testing.T) {
		rr := get(t, "/artifacts/call_1/..%2f..%2fpasswd", testToken)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

// TestServeArtifactContentType proves the Content-Type header is inferred
// from the artifact's name rather than hardcoded: .pcap keeps the existing
// W2 MIME type, .wav (W5 recordings) gets audio/wav instead of a lying pcap
// type, and an unrecognized extension falls back to a generic octet-stream.
func TestServeArtifactContentType(t *testing.T) {
	cases := []struct {
		name        string
		body        []byte
		wantContent string
	}{
		{name: "capture.pcap", body: []byte("fake pcap bytes"), wantContent: "application/vnd.tcpdump.pcap"},
		{name: "recording.wav", body: []byte("fake wav bytes"), wantContent: "audio/wav"},
		{name: "notes.txt", body: []byte("fake text bytes"), wantContent: "application/octet-stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := newArtifactTestEnvFor(t, tc.name, tc.body)
			req := httptest.NewRequest(http.MethodGet, "/artifacts/call_1/"+tc.name, nil)
			req.Header.Set("Authorization", "Bearer "+testToken)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
			}
			if got := rr.Body.String(); got != string(tc.body) {
				t.Fatalf("body = %q, want %q", got, string(tc.body))
			}
			if ct := rr.Header().Get("Content-Type"); ct != tc.wantContent {
				t.Fatalf("Content-Type = %q, want %q", ct, tc.wantContent)
			}
		})
	}
}
