package mcp

import (
	"io"
	"net/http"
	"path/filepath"
	"strconv"
)

// artifactContentType maps an artifact's file extension to the Content-Type
// it should be served with. Unrecognized extensions fall back to a safe
// generic type rather than a guess.
func artifactContentType(name string) string {
	switch filepath.Ext(name) {
	case ".pcap":
		return "application/vnd.tcpdump.pcap"
	case ".wav":
		return "audio/wav"
	default:
		return "application/octet-stream"
	}
}

// serveArtifact serves a per-call artifact (W2: capture.pcap, W5: recording
// .wav) by resolving the request path through the session.ArtifactStore.
// Bearer-authed (§12.2) — the mux wraps it in bearerAuth, whose only
// exemption is /healthz (N4). Path traversal is refused by the store's
// Resolve (Task 4), so a crafted call_handle/name never escapes the artifact
// dir.
func (s *Server) serveArtifact(w http.ResponseWriter, r *http.Request) {
	callHandle := r.PathValue("call_handle")
	name := r.PathValue("name")
	// Build the canonical mcp:// resource URI via the store's OWN URI() (finding 2),
	// rather than hardcoding a scheme here — Resolve expects the same string the
	// store minted, and the GET path is only the transport, not the uri.
	uri := s.cfg.Artifacts.URI(callHandle, name)
	info, rc, err := s.cfg.Artifacts.Resolve(r.Context(), uri)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer func() { _ = rc.Close() }()
	w.Header().Set("Content-Type", artifactContentType(info.Name))
	w.Header().Set("Content-Length", strconv.FormatInt(info.Bytes, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}
