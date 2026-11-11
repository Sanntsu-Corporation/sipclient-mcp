package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// ApplyLocalPolicy normalizes cfg.LocalAddr according to EndpointType.
// RFC3261-relevant behavior: Contact/Via source endpoint should represent the
// reachable UAC transport address used for this registration/dialog.
func ApplyLocalPolicy(cfg *Config) error {
	host, port, err := splitHostPortLoosely(cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("parse -local: %w", err)
	}
	if host == "" || host == "0.0.0.0" {
		h, derr := detectOutboundHost(cfg.TargetURI)
		if derr != nil {
			return fmt.Errorf("detect local host: %w", derr)
		}
		host = h
	}

	switch strings.ToLower(strings.TrimSpace(cfg.EndpointType)) {
	case "", "custom":
		if port == 0 {
			p, err := reserveUDPPort(host)
			if err != nil {
				return err
			}
			port = p
		}
	case "register":
		p, err := reserveUDPPort(host)
		if err != nil {
			return err
		}
		port = p
	case "ip2ip":
		port = 5060
	default:
		return fmt.Errorf("invalid -endpoint-type=%q (use register|ip2ip|custom)", cfg.EndpointType)
	}

	cfg.LocalAddr = net.JoinHostPort(host, strconv.Itoa(port))
	return nil
}

func splitHostPortLoosely(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, nil
	}
	if strings.Count(s, ":") == 0 {
		return s, 0, nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if p == "" {
		return h, 0, nil
	}
	pi, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, pi, nil
}

func reserveUDPPort(host string) (int, error) {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, fmt.Errorf("reserve udp port on %s: %w", host, err)
	}
	defer pc.Close()
	udp, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected local addr type %T", pc.LocalAddr())
	}
	return udp.Port, nil
}

func detectOutboundHost(target string) (string, error) {
	var u sip.Uri
	if err := sip.ParseUri(normalizeSIPURI(target), &u); err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("empty host in target %q", target)
	}
	port := u.Port
	if port == 0 {
		port = 5060
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected local addr type %T", conn.LocalAddr())
	}
	return la.IP.String(), nil
}

func normalizeSIPURI(s string) string {
	ls := strings.ToLower(s)
	if strings.HasPrefix(ls, "sip:") || strings.HasPrefix(ls, "sips:") {
		return s
	}
	return "sip:" + s
}
