package calltester

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
)

const defaultPassiveCallDuration = 10 * time.Second

// AttachPassiveEndpoint registers SIP server handlers on an existing user
// agent so an actor session can answer inbound INVITE/BYE requests while its
// transport is served externally by the actor runtime.
func AttachPassiveEndpoint(ctx context.Context, ua *sipgo.UserAgent, cfg config.Config, runtime *Runtime) (*sipgo.Server, error) {
	server, err := sipgo.NewServer(ua)
	if err != nil {
		return nil, fmt.Errorf("create passive endpoint server: %w", err)
	}

	callDuration := cfg.CallDuration
	if callDuration <= 0 {
		callDuration = defaultPassiveCallDuration
	}

	server.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		offerHost, _, _ := net.SplitHostPort(cfg.LocalAddr)
		if offerHost == "" {
			offerHost = "127.0.0.1"
		}
		remoteMedia, err := parseRemoteMedia(req.Body(), offerHost)
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		media, closeMedia, err := runtime.mediaSession(offerHost)
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Media Failure", nil))
			return
		}
		if closeMedia {
			defer media.Close()
		}

		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		ok := sip.NewSDPResponseFromRequest(req, media.SDP())
		_ = tx.Respond(ok)

		go func() {
			_, _ = media.Stream(ctx, remoteMedia, callDuration, cfg.AudioSource)
		}()
	})

	server.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {})

	server.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	server.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	return server, nil
}
