// Package fakes holds the hand-written §6.2.1 fakes of session's four
// collaborator interfaces, plus the §12.6 Sessions fake — no mocking
// framework, per §6.2.1 and Rule 17.
package fakes

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

var _ session.ArtifactStore = (*ArtifactStore)(nil)

// ArtifactStore is a hand-written fake of session.ArtifactStore, backed by an
// in-memory map. P1 writes no artifacts, so this fake also documents the
// shape a P1 no-op takes.
type ArtifactStore struct {
	mu sync.Mutex

	OpenErr    error
	CreateErr  error
	CloseErr   error
	ResolveErr error

	UsageBytesResult int64
	UsageBytesErr    error

	NonLiveUsageBytesResult int64
	NonLiveUsageBytesErr    error

	OpenedDirs []string
	buffers    map[string]*bytes.Buffer
	infos      map[string]session.ArtifactInfo
}

// NewArtifactStore returns an empty ArtifactStore fake.
func NewArtifactStore() *ArtifactStore {
	return &ArtifactStore{
		buffers: make(map[string]*bytes.Buffer),
		infos:   make(map[string]session.ArtifactInfo),
	}
}

// OpenCallDir records that callHandle's artifact directory was opened.
func (a *ArtifactStore) OpenCallDir(_ context.Context, callHandle string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.OpenedDirs = append(a.OpenedDirs, callHandle)
	return a.OpenErr
}

// Create opens an in-memory buffer for callHandle/name.
func (a *ArtifactStore) Create(_ context.Context, callHandle, name string) (io.WriteCloser, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.CreateErr != nil {
		return nil, a.CreateErr
	}
	buf := &bytes.Buffer{}
	a.buffers[a.URI(callHandle, name)] = buf
	return nopWriteCloser{buf}, nil
}

// Close finalises callHandle/name's buffer and returns its ArtifactInfo.
func (a *ArtifactStore) Close(_ context.Context, callHandle, name string) (session.ArtifactInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.CloseErr != nil {
		return session.ArtifactInfo{}, a.CloseErr
	}
	uri := a.URI(callHandle, name)
	info := session.ArtifactInfo{
		CallHandle: callHandle,
		Name:       name,
		URI:        uri,
		Bytes:      int64(a.buffers[uri].Len()),
	}
	a.infos[uri] = info
	return info, nil
}

// Remove deletes callHandle/name's buffer and info, idempotently.
func (a *ArtifactStore) Remove(_ context.Context, callHandle, name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := a.URI(callHandle, name)
	delete(a.buffers, key)
	delete(a.infos, key)
	return nil // idempotent
}

// URI formats the fake's canonical artifact URI for callHandle/name.
func (a *ArtifactStore) URI(callHandle, name string) string {
	return fmt.Sprintf("mcp://sipclient/artifacts/%s/%s", callHandle, name)
}

// Resolve looks up a previously closed artifact by its URI.
func (a *ArtifactStore) Resolve(_ context.Context, uri string) (session.ArtifactInfo, io.ReadCloser, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ResolveErr != nil {
		return session.ArtifactInfo{}, nil, a.ResolveErr
	}
	info, ok := a.infos[uri]
	if !ok {
		return session.ArtifactInfo{}, nil, fmt.Errorf("fakes: no artifact at %s", uri)
	}
	return info, io.NopCloser(bytes.NewReader(a.buffers[uri].Bytes())), nil
}

// UsageBytes returns the scripted UsageBytesResult/UsageBytesErr pair.
func (a *ArtifactStore) UsageBytes(_ context.Context) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.UsageBytesResult, a.UsageBytesErr
}

// NonLiveUsageBytes returns the scripted NonLiveUsageBytesResult/NonLiveUsageBytesErr pair.
func (a *ArtifactStore) NonLiveUsageBytes(_ context.Context) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.NonLiveUsageBytesResult, a.NonLiveUsageBytesErr
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
