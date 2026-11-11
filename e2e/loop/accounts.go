package main

// accounts.go — the gate's SIP account inventory, migrated out of
// policy.yaml's deleted `profiles:` section (Phase 1, D1/D6).
//
// WHAT CHANGED AND WHY IT HAD TO. ua_create used to take a `profile` name and
// resolve the account server-side from policy.yaml. That registry is gone:
// policy.Profile is deleted, policy.Load's strict decoder now rejects a file
// carrying `profiles:` outright, and `profile` is no longer a ua_create
// parameter at all — a call still passing one has the field ignored, so a
// register-mode UA would be created with NO AOR and fail invalid_argument.
// Every field the profile used to supply therefore travels INLINE on the
// request now.
//
// THE NAMES SURVIVE THE MIGRATION ON PURPOSE. Scenarios, comments, run.sh and
// the Asterisk rig's own conf/pjsip.conf all refer to these accounts by name
// ("e2e-uac-register" is the ONLY AOR the rig knows), so the name stays the
// lookup key here and the call sites keep passing it. Only what the name
// resolves to moved: from a server-side registry to this map.
//
// MIGRATION MAP (policy.yaml profile field -> ua_create argument):
//
//	name                 -> (harness-side lookup key only; never sent)
//	aor                  -> aor
//	auth_user            -> auth_user
//	auth_pass_file       -> auth_pass (the VALUE, read from the file below)
//	registrar            -> registrar
//	expires_s            -> expires_s
//	keepalive            -> keepalive
//	keepalive_interval_s -> keepalive_interval_s
//	session_expires_s    -> session_expires_s
//	min_se_s             -> min_se_s
//	transport            -> NOT carried here: ua_create's own `transport`
//	                        argument selects udp/tcp/tls and every call site
//	                        already passes it (tcptls.go parameterizes it).
//
// e2e-uac-inband IS NOW WIRED UP (CF-026): see gateAccounts below. It was
// dropped in the migration as "no scenario referenced" it, which was true
// right up until scenarioDTMFInbandRig started dialling ext 602 as
// e2e-uac-direct instead — whose endpoint config is dtmf_mode=rfc4733
// (conf/pjsip.conf), so Asterisk never ran its Goertzel inband detector on
// that account's audio at all. e2e-uac-info remains unwired: the SIP-INFO-
// vs-Asterisk scenario already passes against e2e-uac-direct, because
// chan_pjsip honours SIP INFO DTMF regardless of the configured dtmf_mode —
// unlike inband, which chan_pjsip gates behind the account's own setting.

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// account is one entry of the inventory above: the inline ua_create fields
// this account needs, minus the password (shared, read once at call time) and
// minus transport/local_addr/codec_pref (per-call-site, not per-account).
//
// A zero-valued field is OMITTED from the request rather than sent as 0/"",
// which matters: ua_create applies its own documented default to an absent
// field, and sending an explicit zero would be a different, out-of-range
// value that the inline-account bounds check now rejects.
type account struct {
	aor                string
	authUser           string
	registrar          string // empty for direct-mode accounts (§7: rejected there)
	expiresS           int
	keepalive          string
	keepaliveIntervalS int
	sessionExpiresS    int
	minSES             int
	srtp               string // "disabled" | "optional" | "required"; empty omits it
	allowCleartextSDES bool   // true forwards allow_cleartext_sdes
}

// gateAccounts is the inventory, one entry per account the scenarios name.
// "{RIG}" in aor/registrar is a template for the Asterisk rig's address;
// accountArgs substitutes gateConfig.asteriskIP, so read the map only
// through accountArgs/uaCreateArgs.
// The values are the deleted policy.yaml profiles', verbatim — the whole
// migration is meant to change WHERE they live, never what they are.
var gateAccounts = map[string]account{
	// Callee. Registers against the Asterisk rig; e2e-uac-register is the
	// ONLY AOR the rig knows, so extension 720/721 dials
	// PJSIP/e2e-uac-register and this UA receives the inbound INVITE (the
	// SUT's inbound path).
	"e2e-uac-register": {
		aor:       "sip:e2e-uac-register@{RIG}",
		authUser:  "e2e-uac-register",
		registrar: "sip:{RIG}:5070",
		expiresS:  60,
		keepalive: "crlf",
	},
	// Caller. Direct mode: dials the literal to_uri
	// (sip:720@{RIG}:5070) with no registrar. The account still
	// supplies the From identity and the digest credentials so the challenged
	// INVITE authenticates (§14.5: a credential-less direct INVITE died
	// transport_failure). registrar is deliberately absent — direct mode
	// never routes via a registrar, and ua_create REFUSES one there.
	"e2e-uac-direct": {
		aor:      "sip:e2e-uac-direct@{RIG}",
		authUser: "e2e-uac-direct",
	},
	// CF-026: direct mode, dedicated to the inband-DTMF-vs-Asterisk scenario.
	// Its ONLY difference from e2e-uac-direct is which Asterisk endpoint it
	// authenticates as — conf/pjsip.conf's [e2e-uac-inband] is dtmf_mode =
	// inband, the one endpoint on the rig actually configured to run Goertzel
	// detection on inbound audio.
	"e2e-uac-inband": {
		aor:      "sip:e2e-uac-inband@{RIG}",
		authUser: "e2e-uac-inband",
	},
	// T7 (P2 W2c): TLS register account. Same AOR identity as
	// e2e-uac-register (Asterisk's registrar matches the AOR by name, not by
	// transport — the [e2e-uac-register] AOR/endpoint pair in conf/pjsip.conf
	// is transport-agnostic), but a DIFFERENT registrar: Asterisk's TLS
	// transport binds {RIG}:5071, distinct from the UDP/TCP
	// transports' shared :5070. ua_create's own `transport` argument selects
	// tcp vs tls; e2e-uac-register above is reused unmodified for TCP since
	// Asterisk's TCP listener is also :5070.
	"e2e-uac-register-tls": {
		aor:       "sip:e2e-uac-register@{RIG}",
		authUser:  "e2e-uac-register",
		registrar: "sip:{RIG}:5071",
		expiresS:  60,
		keepalive: "crlf",
	},
	// Task 33: session-timer scenarios. 90/90 (rather than the default
	// 1800/90) so the interval/2 refresh Task 29 arms lands at ~45s — long
	// enough that the gate stays a real exercise of the refresh path, short
	// enough that the gate doesn't spend the better part of an hour on it.
	// Asterisk's e2e-uac-register/-direct endpoints both advertise
	// timers_min_se=90 (live-verified), so 90 is accepted without a 422
	// retry. Used both against the rig (ext 605, long-hold) and against Task
	// 33's own local stubs (RULING 2).
	"e2e-uac-sessiontimer": {
		aor:             "sip:e2e-uac-direct@{RIG}",
		authUser:        "e2e-uac-direct",
		sessionExpiresS: 90,
		minSES:          90,
	},
	// Lane A (cf5-a, CF-170): the rig's e2e-uac-srtp endpoint requires SDES
	// (conf/pjsip.conf, media_encryption_optimistic = no). Same identity, two
	// SRTP policies; both run over TLS, which protects the keys.
	"e2e-uac-srtp-required": {
		aor:      "sip:e2e-uac-srtp@{RIG}",
		authUser: "e2e-uac-srtp",
		srtp:     "required",
	},
	"e2e-uac-srtp-optional": {
		aor:      "sip:e2e-uac-srtp@{RIG}",
		authUser: "e2e-uac-srtp",
		srtp:     "optional",
	},
	// cf6-a (CF-198): the e2e-uac-srtp identity over UDP, so the capture can read
	// both offers' keys (over TLS it could not); needs the cleartext-SDES opt-in.
	"e2e-uac-srtp-required-udp": {
		aor:                "sip:e2e-uac-srtp@{RIG}",
		authUser:           "e2e-uac-srtp",
		srtp:               "required",
		allowCleartextSDES: true,
	},
	// Lane A: the e2e-uac-direct identity (plain RTP endpoint) with srtp
	// optional over UDP, which needs the cleartext-SDES opt-in.
	"e2e-uac-direct-srtp-optional": {
		aor:                "sip:e2e-uac-direct@{RIG}",
		authUser:           "e2e-uac-direct",
		srtp:               "optional",
		allowCleartextSDES: true,
	},
	// cf5-b: the e2e-uac-register AOR, credentials and registrar with a 90/90
	// session timer, so the leg Asterisk bridges to it refreshes every ~45 s (the
	// x-in-udp rig shape). The harness name is a lookup key; the rig is unchanged.
	"e2e-uac-register-st90": {
		aor:             "sip:e2e-uac-register@{RIG}",
		authUser:        "e2e-uac-register",
		registrar:       "sip:{RIG}:5070",
		expiresS:        60,
		keepalive:       "crlf",
		sessionExpiresS: 90,
		minSES:          90,
	},
	// Task 33 (C8/RULING 2): keepalive is only observable by pointing the
	// registrar at something WE control that can count inbound OPTIONS —
	// Asterisk answers OPTIONS but exposes no counter for it, and the tool
	// surface has no UA-scoped ladder/capture (C8). registrar is a FIXED
	// local port (keepalive_stub.go's keepaliveStubAddr).
	"e2e-uac-keepalive": {
		aor:                "sip:e2e-uac-keepalive@127.0.0.1",
		authUser:           "e2e-uac-keepalive",
		registrar:          "sip:127.0.0.1:39310",
		expiresS:           60,
		keepalive:          "options",
		keepaliveIntervalS: 5,
	},
}

// gateAuthPass reads the committed test password once per process. It is the
// inline replacement for every profile's auth_pass_file: the daemon used to
// read that file itself, and now the harness reads it and sends the value.
//
// The file is committed on purpose and is TEST-ONLY (see the rig's README);
// the value guards only lab endpoints on the Asterisk rig.
var gateAuthPass = sync.OnceValues(func() (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	return readTrimmed(filepath.Join(root, "e2e", "loop", "auth_pass.txt"))
})

// accountArgs returns the inline ua_create fields for the named account,
// ready to be merged into a call site's own mode/transport/local_addr/
// codec_pref arguments. An unknown name is an error rather than an empty
// map: a typo would otherwise create a UA with no identity at all and fail
// several steps later, on the wire, as an unexplained 401.
func accountArgs(name, rigIP string) (map[string]any, error) {
	a, ok := gateAccounts[name]
	if !ok {
		return nil, fmt.Errorf("unknown gate account %q (see accounts.go)", name)
	}
	pass, err := gateAuthPass()
	if err != nil {
		return nil, fmt.Errorf("read the gate's auth password: %w", err)
	}
	args := map[string]any{
		"aor":       strings.ReplaceAll(a.aor, "{RIG}", rigIP),
		"auth_user": a.authUser,
		"auth_pass": pass,
	}
	// Zero-valued fields are omitted — see account's doc comment.
	if a.registrar != "" {
		args["registrar"] = strings.ReplaceAll(a.registrar, "{RIG}", rigIP)
	}
	if a.expiresS != 0 {
		args["expires_s"] = a.expiresS
	}
	if a.keepalive != "" {
		args["keepalive"] = a.keepalive
	}
	if a.keepaliveIntervalS != 0 {
		args["keepalive_interval_s"] = a.keepaliveIntervalS
	}
	if a.sessionExpiresS != 0 {
		args["session_expires_s"] = a.sessionExpiresS
	}
	if a.minSES != 0 {
		args["min_se_s"] = a.minSES
	}
	if a.srtp != "" {
		args["srtp"] = a.srtp
	}
	if a.allowCleartextSDES {
		args["allow_cleartext_sdes"] = true
	}
	return args, nil
}

// uaCreateArgs builds a complete ua_create argument map: the named account's
// inline fields plus this call site's own mode/transport/local_addr/
// codec_pref. It is the ONE place the two halves are joined, so a call site
// cannot forget the account half and silently create an identity-less UA —
// which is exactly the failure the deleted `profile` parameter now produces
// when it is left in place (ignored, no AOR, invalid_argument).
func uaCreateArgs(mode, accountName, rigIP, transport, localAddr string, codecs []string) (map[string]any, error) {
	args, err := accountArgs(accountName, rigIP)
	if err != nil {
		return nil, err
	}
	args["mode"] = mode
	args["transport"] = transport
	args["local_addr"] = localAddr
	args["codec_pref"] = codecs
	// §10.2: direct mode REFUSES a registrar outright (it dials the literal
	// to_uri and never routes through one), so an account that carries one is
	// only usable in direct mode with it stripped. Stripping here rather than
	// at each call site keeps "which accounts are direct-usable" from becoming
	// a second, drifting piece of knowledge.
	if mode == "direct" {
		delete(args, "registrar")
	}
	return args, nil
}
