package sipua

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

func TestNewTLSConfigs(t *testing.T) {
	pool := x509.NewCertPool()
	server, client, err := newTLSConfigs(net.ParseIP("127.0.0.1"), pool, true, nil)
	if err != nil {
		t.Fatalf("newTLSConfigs: %v", err)
	}

	// Client config: carries the resolved trust material and the
	// verification hook (M7b, §7 scope item 5).
	if client.RootCAs != pool {
		t.Error("client config's RootCAs must be the pool passed in (pointer identity)")
	}
	if !client.InsecureSkipVerify {
		t.Error("client config's InsecureSkipVerify must reflect what was passed in (true)")
	}
	if client.VerifyConnection == nil {
		t.Error("client config must carry the item-5 fingerprint VerifyConnection hook")
	}
	if client.ServerName != "" {
		t.Error("client config's ServerName must be left empty so sipgo can substitute raddr.Hostname per-dial")
	}
	if len(client.Certificates) != 1 {
		t.Fatalf("client config: want exactly one self-signed cert, got %d", len(client.Certificates))
	}
	if client.MinVersion < tls.VersionTLS12 {
		t.Errorf("client config MinVersion = %x, want >= TLS1.2", client.MinVersion)
	}

	// Server config: no client-side verification posture, no hooks — the
	// split's whole point is that no shared object is left for a hook to
	// leak across onto inbound handshakes.
	if server.InsecureSkipVerify {
		t.Error("server config must not set InsecureSkipVerify")
	}
	if server.RootCAs != nil {
		t.Error("server config must not carry RootCAs (never consulted server-side)")
	}
	if server.VerifyConnection != nil {
		t.Error("server config must carry no VerifyConnection hook")
	}
	if server.VerifyPeerCertificate != nil {
		t.Error("server config must carry no VerifyPeerCertificate hook")
	}
	if server.ClientAuth != tls.NoClientCert {
		t.Errorf("server config ClientAuth = %v, want NoClientCert (mTLS is P4-D05)", server.ClientAuth)
	}
	if len(server.Certificates) != 1 {
		t.Fatalf("server config: want exactly one self-signed cert, got %d", len(server.Certificates))
	}
	if server.MinVersion < tls.VersionTLS12 {
		t.Errorf("server config MinVersion = %x, want >= TLS1.2", server.MinVersion)
	}

	// Second call, the default posture: nil pool, verification on.
	_, client2, err := newTLSConfigs(net.ParseIP("127.0.0.1"), nil, false, nil)
	if err != nil {
		t.Fatalf("newTLSConfigs: %v", err)
	}
	if client2.RootCAs != nil {
		t.Error("default posture: client config's RootCAs must be nil (use host roots)")
	}
	if client2.InsecureSkipVerify {
		t.Error("default posture: client config's InsecureSkipVerify must be false")
	}
}
