package siptest

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
)

func RunUAC(ctx context.Context, cfg config.Config, ua *sipgo.UserAgent) error {
	var srv *sipgo.Server
	var srvErrCh chan error
	if cfg.PersistentRegister || cfg.AutoAnswer {
		var err error
		srv, err = newPersistentEndpointServer(cfg, ua)
		if err != nil {
			return err
		}
		srvErrCh = make(chan error, 1)
		go func() {
			srvErrCh <- srv.ListenAndServe(ctx, "udp", cfg.LocalAddr)
		}()
		// give listener time to bind before REGISTER
		time.Sleep(150 * time.Millisecond)
		defer srv.Close()
	}

	c, err := NewClient(cfg, ua)
	if err != nil {
		return err
	}
	defer c.Close()

	if cfg.DoRegister {
		req := BuildRegister(cfg, "udp")
		start := time.Now()

		res, err := c.DoRequestWithDigest(ctx, req)
		if err != nil {
			return fmt.Errorf("REGISTER: %w", err)
		}
		log.Printf("REGISTER -> %d %s (%s)", res.StatusCode, res.Reason, time.Since(start))
		if res.StatusCode != 200 {
			return fmt.Errorf("REGISTER failed: %d %s", res.StatusCode, res.Reason)
		}

		if cfg.PersistentRegister && !cfg.DoCall {
			log.Printf("Persistent REGISTER mode enabled; endpoint online at %s", cfg.LocalAddr)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-srvErrCh:
				if err != nil {
					return fmt.Errorf("persistent endpoint: %w", err)
				}
				return nil
			}
		}
	}

	if cfg.DoCall {
		inv := BuildInvite(cfg, "udp", DefaultSDP(cfg))
		start := time.Now()

		res, err := c.DoRequestWithDigest(ctx, inv)
		if err != nil {
			return fmt.Errorf("INVITE: %w", err)
		}
		log.Printf("INVITE -> %d %s (%s)", res.StatusCode, res.Reason, time.Since(start))
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return fmt.Errorf("INVITE failed: %d %s", res.StatusCode, res.Reason)
		}

		ack := sip.NewAckRequest(inv, res, nil)
		if err := c.client.WriteRequest(ack); err != nil {
			return fmt.Errorf("ACK send: %w", err)
		}
		log.Printf("ACK sent; holding call for %s", cfg.CallDuration)

		select {
		case <-time.After(cfg.CallDuration):
		case <-ctx.Done():
			return ctx.Err()
		}

		bye := BuildByeFromInvite(inv, res)
		byeRes, err := c.doTx(ctx, bye, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("BYE: %w", err)
		}
		log.Printf("BYE -> %d %s", byeRes.StatusCode, byeRes.Reason)
		if byeRes.StatusCode != 200 {
			return fmt.Errorf("BYE failed: %d %s", byeRes.StatusCode, byeRes.Reason)
		}
	}

	return nil
}

func newPersistentEndpointServer(cfg config.Config, ua *sipgo.UserAgent) (*sipgo.Server, error) {
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}

	contactHost, _, _ := net.SplitHostPort(cfg.LocalAddr)
	if contactHost == "" {
		contactHost = "127.0.0.1"
	}

	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		time.Sleep(300 * time.Millisecond)
		ok := sip.NewSDPResponseFromRequest(req, DefaultSDP(cfg))
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Host: contactHost}})
		_ = tx.Respond(ok)
	})

	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {})

	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	srv.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	return srv, nil
}

// DoRequestWithDigest sends req; if it receives 401/407 + Digest challenge,
// it computes Authorization/Proxy-Authorization and retries once using
// sipgo's native digest-retry pattern (mirrors sipgo/client.go:456-468
// digestProxyAuthRequest): mutate req in place, bump CSeq explicitly,
// strip Via, then dispatch via TransactionRequest with ClientRequestAddVia.
//
// Caller constraint: the sipgo.Client wrapped by c must have been built
// from a LocalAddr whose port is 0. The retry path dispatches through
// ClientRequestAddVia, which emits a Via of c.host:c.port; on dual-stack
// Linux a non-zero c.port makes the transport layer's pool lookup miss
// and attempt a fresh bind on an already-held port (EADDRINUSE). The
// probe's doRegister rewrites cfg.LocalAddr to host:0 before calling
// NewClient (W2-F1, see internal/probe/sipdriver/register.go:473-476).
func (c *Client) DoRequestWithDigest(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	res, err := c.doTx(ctx, req, c.cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 401 && res.StatusCode != 407 {
		return res, nil
	}
	if c.cfg.AuthUser == "" || c.cfg.AuthPass == "" {
		return res, fmt.Errorf("got %d but no -auth-user/-auth-pass provided", res.StatusCode)
	}

	var (
		challengeHeader sip.Header
		authzHeaderName string
	)
	switch res.StatusCode {
	case 401:
		challengeHeader = res.GetHeader("WWW-Authenticate")
		authzHeaderName = "Authorization"
		if challengeHeader == nil {
			return res, fmt.Errorf("401 without WWW-Authenticate")
		}
	case 407:
		challengeHeader = res.GetHeader("Proxy-Authenticate")
		authzHeaderName = "Proxy-Authorization"
		if challengeHeader == nil {
			return res, fmt.Errorf("407 without Proxy-Authenticate")
		}
	}

	ch, err := digest.ParseChallenge(challengeHeader.Value())
	if err != nil {
		return res, fmt.Errorf("parse digest challenge: %w", err)
	}

	uri := req.Recipient.String()
	auth := digest.ComputeAuthorization(c.cfg.AuthUser, c.cfg.AuthPass, string(req.Method), uri, ch, 1)

	// Mutate req in place — defensive remove then append so chained retries
	// do not accumulate duplicate auth headers.
	req.RemoveHeader(authzHeaderName)
	req.AppendHeader(sip.NewHeader(authzHeaderName, auth.HeaderValue()))

	// Bump CSeq explicitly (RFC 3261 §20.16 monotonicity).
	cseq := req.CSeq()
	if cseq == nil {
		return res, fmt.Errorf("REGISTER missing CSeq header")
	}
	cseq.SeqNo++

	// Strip Via so sipgo re-adds a fresh one via ClientRequestAddVia. Capture
	// the original Via's transport first: once the Via is gone, req.Transport()
	// has no signal left (no cached transport, no ;transport= URI param in
	// this codebase's usage) and falls back to sip.DefaultProtocol (UDP),
	// silently misrouting the retry. Pin it via SetTransport so the rebuilt
	// Via (and the transport layer's dial) use the original transport.
	origVia := req.Via()
	req.RemoveHeader("Via")
	if origVia != nil && origVia.Transport != "" {
		req.SetTransport(origVia.Transport)
	}

	return c.doTxWithAddVia(ctx, req, c.cfg.Timeout)
}

// doTxWithAddVia dispatches req via sipgo's options path. Passing
// ClientRequestAddVia means sipgo will NOT auto-bump CSeq (the options
// slice is non-empty, bypassing client.go:143-150) and WILL prepend a
// fresh Via using c.host:c.port. Callers must bump CSeq themselves
// before invoking this (see DoRequestWithDigest). On transport-bind
// failure (EADDRINUSE etc), TransactionRequest returns the error
// immediately — fail-fast per W4-F2b design.
func (c *Client) doTxWithAddVia(ctx context.Context, req *sip.Request, timeout time.Duration) (*sip.Response, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tx, err := c.client.TransactionRequest(tctx, req, sipgo.ClientRequestAddVia)
	if err != nil {
		return nil, err
	}
	defer tx.Terminate()
	for {
		select {
		case res := <-tx.Responses():
			if res == nil {
				continue
			}
			if res.StatusCode < 200 {
				continue
			}
			return res, nil
		case <-tx.Done():
			return nil, fmt.Errorf("tx done: %v", tx.Err())
		case <-tctx.Done():
			return nil, tctx.Err()
		}
	}
}
