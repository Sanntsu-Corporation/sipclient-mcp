package calltester

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

type SinkConfig struct {
	ListenAddr     string
	AuthUser       string
	AuthPass       string
	Realm          string
	AudioSource    string
	CallDurationMS int
}

func StartSink(ctx context.Context, cfg SinkConfig) (<-chan struct{}, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}
	if cfg.CallDurationMS <= 0 {
		cfg.CallDurationMS = 30_000
	}

	internalCfg := config.Config{
		ListenAddr:   cfg.ListenAddr,
		Realm:        cfg.Realm,
		AuthUser:     cfg.AuthUser,
		AuthPass:     cfg.AuthPass,
		AudioSource:  cfg.AudioSource,
		CallDuration: time.Duration(cfg.CallDurationMS) * time.Millisecond,
	}

	ua, err := sipgo.NewUA()
	if err != nil {
		return nil, fmt.Errorf("create sink ua: %w", err)
	}
	server, err := sipgo.NewServer(ua)
	if err != nil {
		ua.Close()
		return nil, fmt.Errorf("create sink server: %w", err)
	}

	done := make(chan struct{})
	nonce := "cvstest-external-sink"

	server.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		if !sinkAuthOK(internalCfg, nonce, req) {
			_ = tx.Respond(sinkChallenge(internalCfg, nonce, req))
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	server.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		if !sinkAuthOK(internalCfg, nonce, req) {
			_ = tx.Respond(sinkChallenge(internalCfg, nonce, req))
			return
		}
		offerHost, _, _ := net.SplitHostPort(cfg.ListenAddr)
		remoteMedia, err := parseRemoteMedia(req.Body(), offerHost)
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		media, err := newMediaSession(offerHost)
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Media Failure", nil))
			return
		}

		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		ok := sip.NewSDPResponseFromRequest(req, media.SDP())
		_ = tx.Respond(ok)
		go func() {
			defer media.Close()
			_, _ = media.Stream(ctx, remoteMedia, internalCfg.CallDuration, internalCfg.AudioSource)
		}()
	})

	server.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		// ACK for 2xx INVITE is a separate request; consume it so sipgo does not default to 405.
	})

	server.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	go func() {
		defer close(done)
		defer server.Close()
		defer ua.Close()
		_ = server.ListenAndServe(ctx, "udp", cfg.ListenAddr)
	}()
	return done, nil
}

func sinkChallenge(cfg config.Config, nonce string, req *sip.Request) *sip.Response {
	realm := cfg.Realm
	if realm == "" {
		realm = "siptester"
	}
	response := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
	header := `Digest realm="` + realm + `", nonce="` + nonce + `", algorithm=MD5, qop="auth"`
	response.AppendHeader(sip.NewHeader("WWW-Authenticate", header))
	return response
}

func sinkAuthOK(cfg config.Config, nonce string, req *sip.Request) bool {
	if cfg.AuthUser == "" || cfg.AuthPass == "" {
		return true
	}
	header := req.GetHeader("Authorization")
	if header == nil {
		return false
	}
	fields, err := digest.ParseAuthorization(header.Value())
	if err != nil {
		return false
	}
	if fields["username"] != cfg.AuthUser || fields["nonce"] != nonce {
		return false
	}
	return digest.VerifyMD5Auth(cfg.AuthUser, cfg.AuthPass, string(req.Method), fields)
}
