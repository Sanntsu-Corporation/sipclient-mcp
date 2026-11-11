package siptest

import (
	"context"
	"log"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

func RunUAS(ctx context.Context, cfg config.Config, ua *sipgo.UserAgent) error {
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		return err
	}
	defer srv.Close()

	nonce := "static-nonce-for-poc"

	srv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		if !uasAuthOK(cfg, nonce, req) {
			_ = tx.Respond(uasChallenge(cfg, nonce, req))
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		if !uasAuthOK(cfg, nonce, req) {
			_ = tx.Respond(uasChallenge(cfg, nonce, req))
			return
		}

		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		time.Sleep(300 * time.Millisecond)

		ok := sip.NewSDPResponseFromRequest(req, DefaultSDP(cfg))
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Host: "127.0.0.1"}})
		_ = tx.Respond(ok)

		select {
		case <-tx.Acks():
			log.Printf("UAS: got ACK")
		case <-tx.Done():
			log.Printf("UAS: INVITE tx done: %v", tx.Err())
		case <-ctx.Done():
			return
		}
	})

	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		log.Printf("UAS: got ACK")
	})

	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	log.Printf("UAS listening udp %s", cfg.ListenAddr)
	return srv.ListenAndServe(ctx, "udp", cfg.ListenAddr)
}

func uasChallenge(cfg config.Config, nonce string, req *sip.Request) *sip.Response {
	realm := cfg.Realm
	if realm == "" {
		realm = "siptester"
	}
	res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
	www := `Digest realm="` + realm + `", nonce="` + nonce + `", algorithm=MD5, qop="auth"`
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", www))
	return res
}

func uasAuthOK(cfg config.Config, nonce string, req *sip.Request) bool {
	if cfg.AuthUser == "" || cfg.AuthPass == "" {
		return true
	}

	h := req.GetHeader("Authorization")
	if h == nil {
		return false
	}

	fields, err := digest.ParseAuthorization(h.Value())
	if err != nil {
		return false
	}
	if fields["username"] != cfg.AuthUser {
		return false
	}
	if fields["nonce"] != nonce {
		return false
	}
	return digest.VerifyMD5Auth(cfg.AuthUser, cfg.AuthPass, string(req.Method), fields)
}
