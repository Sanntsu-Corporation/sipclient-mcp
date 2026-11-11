// Package fakedns is a hermetic loopback UDP DNS responder for tests, with the
// same zone contract as the sipgo fork's own test helper (a _test.go file of
// another module, so it cannot be imported). stdlib only.
package fakedns

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Start serves zone on 127.0.0.1:0 and returns a Go resolver pointed at it plus
// a func returning the lower-case "name/TYPE" of every query in arrival order.
//
// zone maps "name/TYPE" (TYPE one of A, AAAA, SRV) to answers: an IP for A and
// AAAA, "priority weight port target" for SRV. A name with no record of any
// type draws NXDOMAIN; a known name without the asked type draws NOERROR with no
// answer. An answer list {"!SERVFAIL"} makes that type answer SERVFAIL for the
// name and for the name with any suffix appended (Go's LookupSRV walks the
// host's resolv.conf search list and returns the last name's error, so a
// suffixed NXDOMAIN would otherwise mask the SERVFAIL). Answers are never
// truncated and never set the TC bit. The socket closes with the test.
func Start(t testing.TB, zone map[string][]string) (*net.Resolver, func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakedns: listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	known := map[string]bool{}
	servfail := map[string]bool{} // "name/TYPE"
	for k, v := range zone {
		known[k[:strings.LastIndex(k, "/")]] = true
		if len(v) == 1 && v[0] == "!SERVFAIL" {
			servfail[strings.ToLower(k)] = true
		}
	}
	var mu sync.Mutex
	var log []string

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			q := append([]byte(nil), buf[:n]...)
			i := 12
			var labels []string
			for i < n && q[i] != 0 {
				l := int(q[i])
				labels = append(labels, string(q[i+1:i+1+l]))
				i += 1 + l
			}
			i++ // root
			qtype := binary.BigEndian.Uint16(q[i : i+2])
			qend := i + 4
			name := strings.ToLower(strings.Join(labels, "."))
			tname := map[uint16]string{1: "A", 28: "AAAA", 33: "SRV"}[qtype]
			mu.Lock()
			log = append(log, name+"/"+tname)
			mu.Unlock()

			rcode := byte(0)
			var answers []byte
			count := 0
			if fails(servfail, name, tname) {
				rcode = 2
			} else {
				for _, v := range zone[name+"/"+tname] {
					var rdata []byte
					switch qtype {
					case 1:
						rdata = net.ParseIP(v).To4()
					case 28:
						rdata = net.ParseIP(v).To16()
					case 33:
						f := strings.Fields(v)
						pr, _ := strconv.Atoi(f[0])
						wt, _ := strconv.Atoi(f[1])
						po, _ := strconv.Atoi(f[2])
						rdata = []byte{byte(pr >> 8), byte(pr), byte(wt >> 8), byte(wt), byte(po >> 8), byte(po)}
						if tgt := strings.TrimSuffix(f[3], "."); tgt != "" { // "." is the root
							for _, lab := range strings.Split(tgt, ".") {
								rdata = append(rdata, byte(len(lab)))
								rdata = append(rdata, lab...)
							}
						}
						rdata = append(rdata, 0)
					}
					rr := []byte{0xC0, 0x0C, byte(qtype >> 8), byte(qtype), 0, 1, 0, 0, 0, 30, byte(len(rdata) >> 8), byte(len(rdata))}
					answers = append(answers, rr...)
					answers = append(answers, rdata...)
					count++
				}
				if count == 0 && !known[name] {
					rcode = 3
				}
			}
			resp := append([]byte(nil), q[:2]...)
			resp = append(resp, 0x81, 0x80|rcode, 0, 1, byte(count>>8), byte(count), 0, 0, 0, 0)
			resp = append(resp, q[12:qend]...)
			resp = append(resp, answers...)
			_, _ = pc.WriteTo(resp, from)
		}
	}()

	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	return r, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), log...)
	}
}

// fails reports whether name/tname, or name with any suffix appended, is a
// configured SERVFAIL.
func fails(servfail map[string]bool, name, tname string) bool {
	for k := range servfail {
		i := strings.LastIndex(k, "/")
		kn, kt := k[:i], k[i+1:]
		if strings.EqualFold(kt, tname) && (name == kn || strings.HasPrefix(name, kn+".")) {
			return true
		}
	}
	return false
}
