package sip

import (
	"bytes"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
)

type Connection interface {
	// LocalAddr used for connection
	LocalAddr() net.Addr
	// WriteMsg marshals message and sends to socket
	WriteMsg(msg Message) error
	// Reference of connection can be increased/decreased to prevent closing to earlyss
	Ref(i int) int
	// Close decreases reference and if ref = 0 closes connection. Returns last ref. If 0 then it is closed
	TryClose() (int, error)

	Close() error
}

var bufPool = sync.Pool{
	New: func() interface{} {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation:
		b := new(bytes.Buffer)
		// b.Grow(2048)
		return b
	},
}

type ConnectionPool struct {
	// TODO consider sync.Map way with atomic checks to reduce mutex contention
	sync.RWMutex
	m map[string]Connection
	// unkeyed holds dialed connections that AddOrTrack refused a key, each
	// mapped to the key it wanted. A Connection can be a map key and be
	// compared with == only because every Connection in this fork is a
	// pointer type.
	unkeyed map[Connection]string
}

func NewConnectionPool() ConnectionPool {
	return ConnectionPool{
		m:       make(map[string]Connection),
		unkeyed: make(map[Connection]string),
	}
}

func (p *ConnectionPool) Add(a string, c Connection) {
	// TODO how about multi connection support for same remote address
	// We can then check ref count

	if c.Ref(0) < 1 {
		c.Ref(1) // Make 1 reference count by default
	}
	p.Lock()
	p.m[a] = c
	p.Unlock()
}

// AddIfNotExists stores c under a only when a is free and reports whether it
// stored. An existing entry, and c, are left untouched when it returns false.
//
// SIPCLIENT-MCP DIVERGENCE (CF-069): upstream tested !exists where it meant
// exists, so it never stored a new key and overwrote a held one. The check
// and the store now run in one critical section.
func (p *ConnectionPool) AddIfNotExists(a string, c Connection) bool {
	p.Lock()
	defer p.Unlock()
	return p.addIfNotExistsLocked(a, c)
}

// addIfNotExistsLocked is AddIfNotExists with p's write lock held.
func (p *ConnectionPool) addIfNotExistsLocked(a string, c Connection) bool {
	if _, exists := p.m[a]; exists {
		return false
	}
	if c.Ref(0) < 1 {
		c.Ref(1) // Make 1 reference count by default
	}
	p.m[a] = c
	return true
}

// AddOrTrack stores c under a when a is free and reports true. Otherwise it
// leaves the holder alone, tracks c (so Clear closes it and CloseAndDelete can
// promote it) and reports false.
//
// SIPCLIENT-MCP DIVERGENCE (CF-064 part 2): a dialed connection no longer
// overwrites a live key. The check and the tracking run in one critical
// section, so a holder's exit cannot free the key between them.
func (p *ConnectionPool) AddOrTrack(a string, c Connection) bool {
	p.Lock()
	defer p.Unlock()
	if p.addIfNotExistsLocked(a, c) {
		return true
	}
	p.unkeyed[c] = a
	return false
}

// Getting connection pool increases reference
// Make sure you TryClose after finish
func (p *ConnectionPool) Get(a string) (c Connection) {
	p.RLock()
	c, exists := p.m[a]
	p.RUnlock()
	if !exists {
		return nil
	}
	c.Ref(1)
	// TODO handling more references
	// if c.Ref(1) <= 1 {
	// 	return nil
	// }

	return c
}

// CloseAndDelete closes connection and deletes from pool.
//
// SIPCLIENT-MCP DIVERGENCE (CF-064): the key is deleted only while it still
// maps to c. A connection exiting after a newer one was added under the same
// key must not remove the newer one's entry. The comparison is by identity of
// the dynamic pointer; every Connection in this fork is a pointer type, so it
// cannot panic on an uncomparable value.
//
// SIPCLIENT-MCP DIVERGENCE (CF-064 part 2): c is also forgotten from the
// tracked set. When c owned addr, one tracked connection that wanted addr and
// is not yet closed is promoted to hold it.
func (p *ConnectionPool) CloseAndDelete(c Connection, addr string) {
	p.Lock()
	defer p.Unlock()
	ref, _ := c.TryClose() // Be nice. Saves from double closing
	if ref > 0 {
		if err := c.Close(); err != nil {
			log.Warn().Err(err).Msg("Closing conection return error")
		}
	}
	delete(p.unkeyed, c)
	if cur, ok := p.m[addr]; ok && cur == c {
		delete(p.m, addr)
		for w, want := range p.unkeyed {
			if want == addr && w.Ref(0) > 0 {
				p.m[addr] = w
				delete(p.unkeyed, w)
				break
			}
		}
	}
}

// Delete removes addr only while it still maps to c; it closes nothing.
//
// SIPCLIENT-MCP DIVERGENCE (CF-069): upstream deleted unconditionally, so a
// connection exiting after a newer one took the key removed the newer one's
// entry. The comparison is by identity of the dynamic pointer; every
// Connection in this fork is a pointer type, so it cannot panic on an
// uncomparable value.
func (p *ConnectionPool) Delete(c Connection, addr string) {
	p.Lock()
	defer p.Unlock()
	if cur, ok := p.m[addr]; ok && cur == c {
		delete(p.m, addr)
	}
}

// DeleteMultiple removes each of addrs that still maps to c; it closes
// nothing. SIPCLIENT-MCP DIVERGENCE (CF-069): see Delete.
func (p *ConnectionPool) DeleteMultiple(c Connection, addrs []string) {
	p.Lock()
	defer p.Unlock()
	for _, a := range addrs {
		if cur, ok := p.m[a]; ok && cur == c {
			delete(p.m, a)
		}
	}
}

// Clear will clear all connection from pool and close them
func (p *ConnectionPool) Clear() {
	p.Lock()
	defer p.Unlock()
	for _, c := range p.m {
		if c.Ref(0) <= 0 {
			continue
		}
		if err := c.Close(); err != nil {
			log.Warn().Err(err).Msg("Closing conection return error")
		}
	}
	for c := range p.unkeyed {
		if c.Ref(0) <= 0 {
			continue
		}
		if err := c.Close(); err != nil {
			log.Warn().Err(err).Msg("Closing conection return error")
		}
	}
	// Remove all
	p.m = make(map[string]Connection)
	p.unkeyed = make(map[Connection]string)
}

func (p *ConnectionPool) Size() int {
	p.RLock()
	l := len(p.m)
	p.RUnlock()
	return l
}
