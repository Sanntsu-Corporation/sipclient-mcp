//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// batchCommand runs a .cmd/.bat shim through cmd.exe with an explicit command
// line. os/exec would re-quote Args with CommandLineToArgvW rules, which cmd.exe
// does not use, hence SysProcAttr.CmdLine. UNVERIFIED on a real Windows machine.
func batchCommand(path string, args []string) (*exec.Cmd, error) {
	line, err := batchCmdLine(path, args)
	if err != nil {
		return nil, err
	}
	comspec, err := systemCmdExe(os.Getenv) // an absolute path: never PATH or the current directory (N11)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(comspec)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /c "` + line + `"`}
	return cmd, nil
}
