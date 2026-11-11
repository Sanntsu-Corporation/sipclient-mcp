package siptest

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
)

func BuildRegister(cfg config.Config, transport string) *sip.Request {
	target := mustParseURI(cfg.TargetURI)
	req := sip.NewRequest(sip.REGISTER, target)

	viaHost, viaPort := hostPort(cfg.LocalAddr)
	req.AppendHeader(buildVia(viaHost, viaPort, transport))

	registerUser := cfg.FromUser
	if cfg.AuthUser != "" {
		registerUser = cfg.AuthUser
	}
	fromURI := sip.Uri{User: registerUser, Host: cfg.FromDomain}
	toURI := sip.Uri{User: registerUser, Host: cfg.FromDomain}

	fromParams := sip.NewParams()
	fromParams.Add("tag", sip.GenerateTagN(8))
	req.AppendHeader(&sip.FromHeader{Address: fromURI, Params: fromParams})
	req.AppendHeader(&sip.ToHeader{Address: toURI})

	callID := sip.CallIDHeader(sip.RandString(10) + "@" + viaHost)
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.REGISTER})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)

	req.AppendHeader(&sip.ContactHeader{
		Address: contactURI(registerUser, viaHost, viaPort, transport),
	})
	exp := sip.ExpiresHeader(300)
	req.AppendHeader(&exp)

	return req
}

func BuildInvite(cfg config.Config, transport string, sdp []byte) *sip.Request {
	// Default: logical callee sip:toUser@toDomain
	reqURI := sip.Uri{User: cfg.ToUser, Host: cfg.ToDomain}

	// If -target is direct ip:port (no user), do IP-to-IP by using target host/port
	if u, ok := tryParseURI(cfg.TargetURI); ok && u.User == "" && u.Host != "" {
		reqURI = sip.Uri{User: cfg.ToUser, Host: u.Host, Port: u.Port}
	}

	req := sip.NewRequest(sip.INVITE, reqURI)

	viaHost, viaPort := hostPort(cfg.LocalAddr)
	req.AppendHeader(buildVia(viaHost, viaPort, transport))

	fromURI := sip.Uri{User: cfg.FromUser, Host: cfg.FromDomain}
	toURI := sip.Uri{User: cfg.ToUser, Host: cfg.ToDomain}

	fromParams := sip.NewParams()
	fromParams.Add("tag", sip.GenerateTagN(8))
	req.AppendHeader(&sip.FromHeader{Address: fromURI, Params: fromParams})
	req.AppendHeader(&sip.ToHeader{Address: toURI})

	callID := sip.CallIDHeader(sip.RandString(10) + "@" + viaHost)
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)

	req.AppendHeader(&sip.ContactHeader{
		Address: contactURI(cfg.FromUser, viaHost, viaPort, transport),
	})

	ct := sip.ContentTypeHeader("application/sdp")
	req.AppendHeader(&ct)
	req.SetBody(sdp)
	return req
}

func BuildByeFromInvite(inv *sip.Request, ok *sip.Response) *sip.Request {
	bye := sip.NewRequest(sip.BYE, inv.Recipient)

	if v := inv.Via(); v != nil {
		bye.AppendHeader(sip.HeaderClone(v))
	}
	if f := inv.From(); f != nil {
		bye.AppendHeader(sip.HeaderClone(f))
	}
	if cid := inv.CallID(); cid != nil {
		bye.AppendHeader(sip.HeaderClone(cid))
	}

	// To-tag must come from 200 OK: in sipgo v0.24.1 tag is a param
	if invTo := inv.To(); invTo != nil {
		to := &sip.ToHeader{DisplayName: invTo.DisplayName, Address: invTo.Address, Params: invTo.Params.Clone()}
		if okTo := ok.To(); okTo != nil {
			to.DisplayName = okTo.DisplayName
			to.Address = okTo.Address
			to.Params = okTo.Params.Clone()
		}
		bye.AppendHeader(to)
	}

	bye.AppendHeader(&sip.CSeqHeader{SeqNo: 2, MethodName: sip.BYE})
	mf := sip.MaxForwardsHeader(70)
	bye.AppendHeader(&mf)

	if c := inv.Contact(); c != nil {
		bye.AppendHeader(sip.HeaderClone(c))
	}
	return bye
}

// buildVia derives the Via transport token from the transport parameter (O1,
// §15.1). It is deliberately NOT a literal: P4 adds TCP and TLS by passing a
// different value here, changing no signature.
func buildVia(host string, port int, transport string) *sip.ViaHeader {
	v := &sip.ViaHeader{
		ProtocolName:    "SIP",
		ProtocolVersion: "2.0",
		Transport:       strings.ToUpper(transport),
		Host:            host,
		Port:            port,
		Params:          sip.NewParams(),
	}
	v.Params.Add("branch", sip.GenerateBranchN(10))
	v.Params.Add("rport", "")
	return v
}

// contactURI derives the Contact transport parameter from the same value. UDP
// is RFC 3261's default and carries no parameter.
func contactURI(user, host string, port int, transport string) sip.Uri {
	u := sip.Uri{User: user, Host: host, Port: port}
	if !strings.EqualFold(transport, "udp") {
		u.UriParams = sip.NewParams()
		u.UriParams.Add("transport", strings.ToLower(transport))
	}
	return u
}

func hostPort(addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", 5066
	}
	pi, _ := strconv.Atoi(p)
	if h == "" {
		h = "127.0.0.1"
	}
	return h, pi
}

func mustParseURI(s string) sip.Uri {
	var u sip.Uri
	if err := sip.ParseUri(normalizeSIPURI(s), &u); err != nil {
		panic(fmt.Errorf("bad uri %q: %w", s, err))
	}
	return u
}

func tryParseURI(s string) (sip.Uri, bool) {
	var u sip.Uri
	if err := sip.ParseUri(normalizeSIPURI(s), &u); err != nil {
		return sip.Uri{}, false
	}
	return u, true
}

func normalizeSIPURI(s string) string {
	ls := strings.ToLower(s)
	if strings.HasPrefix(ls, "sip:") || strings.HasPrefix(ls, "sips:") {
		return s
	}
	return "sip:" + s
}
