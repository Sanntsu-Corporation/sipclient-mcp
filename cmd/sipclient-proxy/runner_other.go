//go:build !windows

package main

import (
	"errors"
	"os/exec"
)

// batchCommand is never reached off Windows (isBatchShim is false there).
func batchCommand(string, []string) (*exec.Cmd, error) {
	return nil, errors.New("batch shims exist only on Windows")
}
