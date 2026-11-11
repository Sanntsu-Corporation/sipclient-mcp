package siptest

import (
	"fmt"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
)

func DefaultSDP(cfg config.Config) []byte {
	return []byte(fmt.Sprintf(
		"v=0\r\n"+
			"o=- 1 1 IN IP4 127.0.0.1\r\n"+
			"s=sip-tester\r\n"+
			"c=IN IP4 127.0.0.1\r\n"+
			"t=0 0\r\n"+
			"m=audio 40000 RTP/AVP 0\r\n"+
			"a=rtpmap:0 PCMU/8000\r\n"+
			"a=sendrecv\r\n",
	))
}
