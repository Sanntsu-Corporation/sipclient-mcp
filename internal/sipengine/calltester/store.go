package calltester

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Store struct {
	stateDir string
}

func NewStore(stateDir string) *Store {
	return &Store{stateDir: stateDir}
}

func (s *Store) Write(state persistedState) error {
	if err := os.MkdirAll(s.stateDir, 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	path := s.path(state.Status.TestCallID)
	tmp := path + ".tmp"
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

func (s *Store) Read(testCallID string) (persistedState, error) {
	payload, err := os.ReadFile(s.path(testCallID))
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(payload, &state); err != nil {
		return persistedState{}, fmt.Errorf("decode state: %w", err)
	}
	return state, nil
}

func (s *Store) path(testCallID string) string {
	return filepath.Join(s.stateDir, fmt.Sprintf("%s.json", testCallID))
}
