package sipua

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"

	"github.com/sanntsu-corporation/sipclient-mcp/internal/media"
)

// redirectTarget is one accepted redirect Contact: the string handed to (and
// returned by) the session's CheckRedirect, and the Request-URI dialRequestURI
// derived from it.
type redirectTarget struct {
	dial string
	uri  sip.Uri
}

// isFollowed3xx reports whether code is a redirect this UA follows (CF-090):
// 300, 301 and 302. 305 (Use Proxy) and 380 (Alternative Service) are not.
func isFollowed3xx(code sip.StatusCode) bool {
	return code == 300 || code == 301 || code == 302
}

// redirectKey is the target-set identity of a URI (RFC 3261 8.1.3.4: a client
// MUST NOT add any given URI to the target set more than once): lower-cased
// scheme and host, the user part as written, port 0 when absent.
func redirectKey(uri sip.Uri) string {
	return strings.ToLower(uri.Scheme) + ":" + uri.User + "@" + strings.ToLower(uri.Host) + ":" + strconv.Itoa(uri.Port)
}

// redirectTargets picks the targets to try from a 300/301/302's Contacts
// (RFC 3261 8.1.3.4), best first, at most room of them. Contacts come from
// GetHeaders (Contact() returns only the last), ordered by q descending (absent
// q is 1.0, an unparseable q 0), ties in header order. A Contact is skipped when
// its scheme is not sip/sips, when it would downgrade a dial that has had a
// sips: Request-URI (everSips), when its URI is already in seen (it is added
// before the checks, so a refused URI is not offered twice), when check
// refuses it, or when derive (dialRequestURI) does. The candidate string is
// scheme, user, host and port only: maddr, transport and other URI parameters,
// headers and any password are dropped, so a Contact cannot steer the request
// or smuggle headers. At most maxForkTags Contacts are evaluated and evaluation
// stops once room targets are accepted.
func redirectTargets(res *sip.Response, everSips bool, derive func(string) (sip.Uri, error),
	seen map[string]bool, room int, check func(string) (string, error),
	log *slog.Logger, dialogID string) []redirectTarget {
	log = logOrDefault(log)
	type ranked struct {
		hdr *sip.ContactHeader
		q   float64
	}
	var contacts []ranked
	for _, h := range res.GetHeaders("Contact") {
		c, ok := h.(*sip.ContactHeader)
		if !ok {
			continue
		}
		q := 1.0
		if v, has := c.Params.Get("q"); has {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				f = 0
			}
			q = f
		}
		contacts = append(contacts, ranked{c, q})
	}
	sort.SliceStable(contacts, func(i, j int) bool { return contacts[i].q > contacts[j].q })
	if len(contacts) > maxForkTags {
		log.Info("redirect: Contacts beyond the cap are ignored",
			"dialog_id", dialogID, "status", int(res.StatusCode), "contacts", len(contacts), "cap", maxForkTags)
		contacts = contacts[:maxForkTags]
	}

	var out []redirectTarget
	for _, c := range contacts {
		if len(out) >= room {
			break
		}
		a := c.hdr.Address
		scheme := strings.ToLower(a.Scheme)
		if scheme != "sip" && scheme != "sips" {
			continue
		}
		if everSips && scheme == "sip" {
			continue
		}
		cand := scheme + ":"
		if a.User != "" {
			cand += a.User + "@"
		}
		cand += a.Host
		if a.Port > 0 {
			cand += ":" + strconv.Itoa(a.Port)
		}
		var parsed sip.Uri
		if err := sip.ParseUri(cand, &parsed); err != nil {
			continue
		}
		key := redirectKey(parsed)
		if seen[key] {
			continue
		}
		seen[key] = true
		dial, err := check(cand)
		if err != nil {
			log.Info("redirect target refused", "dialog_id", dialogID, "status", int(res.StatusCode),
				"host", a.Host, "reason", err.Error())
			continue
		}
		uri, err := derive(dial)
		if err != nil {
			log.Info("redirect target refused", "dialog_id", dialogID, "status", int(res.StatusCode),
				"host", a.Host, "reason", fmt.Sprint(err))
			continue
		}
		out = append(out, redirectTarget{dial: dial, uri: uri})
	}
	return out
}

// retarget points d's INVITE at t for the next leg, in place on runDial's
// goroutine (the convention retry422 documents): Call-ID, From (tag), To and the
// SDP offer stay; the Via is removed so the transport adds one with a new
// branch; credentials for the old target are removed; and the cached
// destination is cleared, because for a hostname target the fork stores the
// resolved address on the request and Destination() returns it before looking at
// the Recipient. The transport is left alone: a sip: target on a non-UDP UA
// carries transport=<tcp|tls> (dialRequestURI) and a sips: target gets TLS from
// the fork's default (CF-172).
func retarget(d *dialog, t redirectTarget) {
	inv := d.invite
	inv.Recipient = t.uri
	inv.RemoveHeader("Via")
	inv.RemoveHeader("Authorization")
	inv.RemoveHeader("Proxy-Authorization")
	inv.SetDestination("")
	if strings.EqualFold(t.uri.Scheme, "sips") {
		d.everSips = true
	}
	d.redirected = true
}

// offersSDES reports whether d's offer carries SDES keys: such a dial gets a
// fresh key for every new target (rekeyOffer, CF-198), so one master key is
// never handed to two targets.
func (u *UA) offersSDES(d *dialog) bool {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	return d.mediaSession != nil && d.mediaSession.LocalCrypto != nil
}

// rekeyOffer replaces d's offer with a fresh one for the next redirect target:
// the same offer Dial built (same codecs, bound media address and SRTP policy),
// with a new SDES master key (RFC 4568 6.1). The session and the INVITE body
// change in one u.calls.mu section, so a reader sees both old or both new; the
// old Session is replaced, never written. On error nothing changes.
func (u *UA) rekeyOffer(d *dialog) error {
	u.calls.mu.Lock()
	defer u.calls.mu.Unlock()
	old := d.mediaSession
	body, sess, err := media.BuildOffer(u.codecPrefs(), old.LocalAddr, old.SRTPPolicy())
	if err != nil {
		return err
	}
	d.mediaSession = sess
	d.invite.SetBody(body)
	return nil
}

// nextRedirectTarget takes the next dispatchable target from pending (best
// first). A queued target was checked when its 3xx arrived, but the live policy
// and the dial's state may have changed since (a deny added while an earlier
// target rang, a sips: leg dialled meanwhile), so each is revalidated here, on
// runDial's goroutine and holding no lock: the never-downgrade rule, the
// session's live CheckRedirect, and dialRequestURI. Refused targets are skipped.
// ok is false when none is left.
func (u *UA) nextRedirectTarget(d *dialog, pending []redirectTarget) (next redirectTarget, rest []redirectTarget, ok bool) {
	for i, t := range pending {
		if d.everSips && !strings.EqualFold(t.uri.Scheme, "sips") {
			continue
		}
		dial, err := d.checkRedirect(t.dial)
		if err != nil {
			u.log().Info("queued redirect target refused at dispatch", "dialog_id", d.id, "host", t.uri.Host, "reason", err.Error())
			continue
		}
		uri, err := u.dialRequestURI(dial)
		if err != nil {
			u.log().Info("queued redirect target refused at dispatch", "dialog_id", d.id, "host", t.uri.Host, "reason", err.Error())
			continue
		}
		return redirectTarget{dial: dial, uri: uri}, pending[i+1:], true
	}
	return redirectTarget{}, nil, false
}
