package siptest

import (
	"context"
	"fmt"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
)

type Client struct {
	cfg    config.Config
	ua     *sipgo.UserAgent
	client *sipgo.Client
}

func NewClient(cfg config.Config, ua *sipgo.UserAgent) (*Client, error) {
	cl, err := sipgo.NewClient(ua, sipgo.WithClientAddr(cfg.LocalAddr), sipgo.WithClientNAT())
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, ua: ua, client: cl}, nil
}

func (c *Client) Close() error { return c.client.Close() }

func (c *Client) Raw() *sipgo.Client { return c.client }

func (c *Client) RawTransaction(ctx context.Context, req *sip.Request, timeout time.Duration) (*sip.Response, error) {
	return c.doTx(ctx, req, timeout)
}

func (c *Client) doTx(ctx context.Context, req *sip.Request, timeout time.Duration) (*sip.Response, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tx, err := c.client.TransactionRequest(tctx, req)
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
