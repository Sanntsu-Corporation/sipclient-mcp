package fakedns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func zoneFixture() map[string][]string {
	srv20 := make([]string, 20)
	for i := range srv20 {
		srv20[i] = "0 0 5060 t" + string(rune('a'+i)) + ".big.test."
	}
	return map[string][]string{
		"a.test/A":               {"10.0.0.1"},
		"v6.test/AAAA":           {"2001:db8::1"},
		"_sip._udp.h.test/SRV":   {"1 2 5070 sip1.h.test."},
		"h.test/A":               {"10.0.0.9"},
		"_sip._udp.bad.test/SRV": {"!SERVFAIL"},
		"_sip._udp.big.test/SRV": srv20,
		"noa.test/AAAA":          {"2001:db8::2"},
	}
}

func TestFakeDNSAnswersTheZone(t *testing.T) {
	r, queries := Start(t, zoneFixture())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupIPAddr(ctx, "a.test")
	if err != nil || len(addrs) != 1 || addrs[0].IP.String() != "10.0.0.1" {
		t.Errorf("A lookup = %v, %v", addrs, err)
	}
	addrs, err = r.LookupIPAddr(ctx, "v6.test")
	if err != nil || len(addrs) != 1 || addrs[0].IP.String() != "2001:db8::1" {
		t.Errorf("AAAA-only lookup = %v, %v", addrs, err)
	}
	_, recs, err := r.LookupSRV(ctx, "sip", "udp", "h.test")
	if err != nil || len(recs) != 1 || recs[0].Port != 5070 || recs[0].Target != "sip1.h.test." {
		t.Errorf("SRV lookup = %+v, %v", recs, err)
	}
	_, err = r.LookupIPAddr(ctx, "nothing.test")
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsNotFound {
		t.Errorf("unknown name error = %v, want IsNotFound", err)
	}
	// A known name asked for another type: no addresses (NOERROR, no data).
	if addrs, _ := r.LookupIPAddr(ctx, "noa.test"); len(addrs) != 1 {
		t.Errorf("noa.test = %v, want its AAAA only", addrs)
	}
	_, _, err = r.LookupSRV(ctx, "sip", "udp", "bad.test")
	if !errors.As(err, &de) || de.IsNotFound || !de.IsTemporary {
		t.Errorf("!SERVFAIL error = %v, want a temporary, not-NotFound error", err)
	}
	_, recs, err = r.LookupSRV(ctx, "sip", "udp", "big.test")
	if err != nil || len(recs) != 20 {
		t.Errorf("20-record SRV = %d records, %v", len(recs), err)
	}

	// The suffixed name draws SERVFAIL too, whatever the host's search list is.
	c, err := r.Dial(ctx, "udp", "")
	if err != nil {
		t.Fatalf("dial fake: %v", err)
	}
	defer func() { _ = c.Close() }()
	if rc := rawRcode(t, c, "_sip._udp.bad.test.example.", 33); rc != 2 {
		t.Errorf("suffixed name rcode = %d, want 2 (SERVFAIL)", rc)
	}
	if rc := rawRcode(t, c, "_sip._udp.other.test.", 33); rc != 3 {
		t.Errorf("unrelated name rcode = %d, want 3 (NXDOMAIN)", rc)
	}

	log := strings.Join(queries(), " ")
	for _, want := range []string{"a.test/a", "_sip._udp.h.test/srv", "nothing.test/a"} {
		if !strings.Contains(strings.ToLower(log), want) {
			t.Errorf("query log %q lacks %q", log, want)
		}
	}
}

func rawRcode(t *testing.T, c net.Conn, name string, qtype uint16) byte {
	t.Helper()
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	if _, err := c.Write(q); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil || n < 4 {
		t.Fatalf("read: %d, %v", n, err)
	}
	return buf[3] & 0x0f
}
