package sip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseInviteWithVia(t *testing.T, via string, extraVia string) *Request {
	t.Helper()
	raw := "OPTIONS sip:alice@example.test SIP/2.0\r\n" +
		"Via: " + via + "\r\n" + extraVia +
		"From: <sip:bob@example.test>;tag=ft\r\n" +
		"To: <sip:alice@example.test>\r\n" +
		"Call-ID: stamp-1@example.test\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	return msg.(*Request)
}

// CF-077 (RFC 3261 18.2.1, RFC 3581 4): the receiving transport stamps the top
// Via with `received` (and fills an empty `rport`).
func TestHandleMessageStampsTheTopVia(t *testing.T) {
	cases := []struct {
		name         string
		via          string
		source       string
		wantReceived string // "" means the parameter must be absent
		wantRport    string // value, or "<absent>"
	}{
		{"a domain sent-by", "SIP/2.0/UDP localhost:5099;branch=z9hG4bKa", "127.0.0.1:40000", "127.0.0.1", "<absent>"},
		{"a different IP sent-by", "SIP/2.0/UDP 127.0.0.2:5099;branch=z9hG4bKb", "127.0.0.1:40000", "127.0.0.1", "<absent>"},
		{"the same IP sent-by", "SIP/2.0/UDP 127.0.0.1:5099;branch=z9hG4bKc", "127.0.0.1:40000", "", "<absent>"},
		{"empty rport, same IP", "SIP/2.0/UDP 127.0.0.1:5099;rport;branch=z9hG4bKd", "127.0.0.1:40000", "127.0.0.1", "40000"},
		{"valued rport, same IP", "SIP/2.0/UDP 127.0.0.1:5099;rport=1234;branch=z9hG4bKe", "127.0.0.1:40000", "", "1234"},
		{"source empty", "SIP/2.0/UDP localhost:5099;branch=z9hG4bKg", "", "", "<absent>"},
		{"zoned source", "SIP/2.0/UDP localhost:5099;branch=z9hG4bKk", "[fe80::1%eth0]:5060", "", "<absent>"},
		{"IPv6 sent-by equal to source", "SIP/2.0/UDP [::1]:5099;branch=z9hG4bKv6", "[::1]:40000", "", "<absent>"},
		{"IPv6 sent-by differs", "SIP/2.0/UDP [::2]:5099;branch=z9hG4bKv7", "[::1]:40000", "::1", "<absent>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewTransportLayer(net.DefaultResolver, NewParser(), nil, false, nil)
			t.Cleanup(func() { _ = l.Close() })
			var seen *Request
			l.OnMessage(func(m Message) { seen = m.(*Request) })

			req := parseInviteWithVia(t, tc.via, "Via: SIP/2.0/UDP below.example;branch=z9hG4bKlow\r\n")
			if tc.source != "" {
				req.SetSource(tc.source)
			}
			l.handleMessage(req)

			require.NotNil(t, seen, "OnMessage handler must see the request")
			via := seen.Via()
			got, ok := via.Params.Get("received")
			if tc.wantReceived == "" {
				require.False(t, ok, "received must be absent, got %q", got)
			} else {
				require.True(t, ok, "received must be set")
				require.Equal(t, tc.wantReceived, got)
			}
			rp, ok := via.Params.Get("rport")
			if tc.wantRport == "<absent>" {
				require.False(t, ok)
			} else {
				require.True(t, ok)
				require.Equal(t, tc.wantRport, rp)
			}
			// the second Via is never touched
			vias := seen.GetHeaders("Via")
			require.Len(t, vias, 2)
			require.False(t, vias[1].(*ViaHeader).Params.Has("received"))
		})
	}
}

func TestHandleMessageLeavesAResponseViaAlone(t *testing.T) {
	l := NewTransportLayer(net.DefaultResolver, NewParser(), nil, false, nil)
	t.Cleanup(func() { _ = l.Close() })
	raw := "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP localhost:5099;branch=z9hG4bKr\r\n" +
		"From: <sip:b@e>;tag=t\r\nTo: <sip:a@e>;tag=u\r\nCall-ID: r@e\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	res := msg.(*Response)
	res.SetSource("127.0.0.1:40000")
	l.handleMessage(res)
	require.False(t, res.Via().Params.Has("received"))
}

func TestStampReceivedWithoutAViaDoesNothing(t *testing.T) {
	req := NewRequest(OPTIONS, Uri{Host: "example.test"})
	req.SetSource("127.0.0.1:40000")
	require.NotPanics(t, func() { stampReceived(req) })
	require.Nil(t, req.Via())
}
