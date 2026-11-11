package session_test

import (
	"crypto/tls"
	"net"
	"reflect"
	"testing"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/session"
)

// transportSpecific is the set of stdlib types that name ONE transport. If any
// of them appears in session.UserAgent's surface, the interface cannot survive
// P4's TCP/TLS diff unchanged and obligation O1 (§15.1) is not dischargeable.
//
// Built from real reflect.Types rather than from strings so a typo cannot
// silently empty the set — a string table is exactly how this kind of guard
// decays into a vacuous pass.
var transportSpecific = map[reflect.Type]bool{
	reflect.TypeOf(net.UDPAddr{}):  true,
	reflect.TypeOf(net.TCPAddr{}):  true,
	reflect.TypeOf(net.UnixAddr{}): true,
	reflect.TypeOf(tls.Conn{}):     true,
}

// walk unwraps the composite kinds a signature can hide a concrete address
// type inside — *net.UDPAddr, []*net.UDPAddr, map[string]*net.TCPAddr — and
// reports the first forbidden type it reaches, or nil.
func walk(t reflect.Type, depth int) reflect.Type {
	if t == nil || depth > 8 {
		return nil
	}
	if transportSpecific[t] {
		return t
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
		return walk(t.Elem(), depth+1)
	case reflect.Map:
		if hit := walk(t.Key(), depth+1); hit != nil {
			return hit
		}
		return walk(t.Elem(), depth+1)
	}
	return nil
}

// TestUserAgentSurfaceNamesNoTransportSpecificType is the INTERFACE half of
// O1's gate (U17). P1c Task 13's Via-builder assertions are the other half;
// neither alone discharges O1, which is why the obligation went unmet while a
// green gate reported otherwise.
func TestUserAgentSurfaceNamesNoTransportSpecificType(t *testing.T) {
	iface := reflect.TypeOf((*session.UserAgent)(nil)).Elem()
	if iface.Kind() != reflect.Interface {
		t.Fatalf("session.UserAgent resolved to %v, want an interface", iface.Kind())
	}
	// Guard against the reflection itself going hollow: if the method set is
	// empty this test would pass on an interface it never inspected.
	if iface.NumMethod() == 0 {
		t.Fatal("session.UserAgent has no methods; this assertion would pass vacuously")
	}

	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		fn := m.Type // an interface method's Type carries no receiver
		for j := 0; j < fn.NumIn(); j++ {
			if hit := walk(fn.In(j), 0); hit != nil {
				t.Errorf("UserAgent.%s parameter %d names the transport-specific type %v (O1, §15.1): the P4 TCP/TLS diff cannot leave this signature unchanged", m.Name, j, hit)
			}
		}
		for j := 0; j < fn.NumOut(); j++ {
			if hit := walk(fn.Out(j), 0); hit != nil {
				t.Errorf("UserAgent.%s result %d names the transport-specific type %v (O1, §15.1): the P4 TCP/TLS diff cannot leave this signature unchanged", m.Name, j, hit)
			}
		}
	}
}
