package session

import (
	"crypto/rand"
	"encoding/hex"
)

// Handle's format (a "ua_"/"call_" prefix plus 64 bits of crypto/rand as hex,
// decision 12) is declared on the type itself in collaborators.go
// (P1a Task 7). This file supplies the two constructors.

const (
	uaHandlePrefix   = "ua_"
	callHandlePrefix = "call_"
)

func newHandle(prefix string) Handle {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never returns an error on any supported platform
		// since Go 1.24; a failure here means the CSPRNG is unavailable and
		// no handle we could issue would be unguessable.
		panic("session: crypto/rand unavailable: " + err.Error())
	}
	return Handle(prefix + hex.EncodeToString(b[:]))
}

func newUAHandle() Handle   { return newHandle(uaHandlePrefix) }
func newCallHandle() Handle { return newHandle(callHandlePrefix) }
