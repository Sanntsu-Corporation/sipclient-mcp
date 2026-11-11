//go:build unix

package sipua

import "syscall"

// clearBroadcast clears SO_BROADCAST on a media socket (see bindMediaPort).
func clearBroadcast(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return serr
}
