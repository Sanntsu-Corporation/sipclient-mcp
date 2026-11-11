#!/usr/bin/env bash
# assert-tcp-tls-capture.sh — P2 Wave 2c Task 7 both-direction TCP/TLS gate
# assertion (spec §14.5). Template: assert-nat-rport.sh (P2 W2b).
#
# Asserts, against a REAL daemon-side pcap artifact (captured via
# capture_start/capture_stop — e2e/loop/tcptls.go arms one on the register
# UA's inbound leg), the three properties T7's real-peer TCP/TLS gate needs:
#
#   (a) BOTH-DIRECTION — packets flow BOTH Asterisk -> SUT (inbound requests)
#       AND SUT -> Asterisk (outbound responses) within the captured dialog.
#   (b) PROTOCOL 6     — the capture is over TCP (protocol 6), not UDP: true
#       for both the tcp and the tls transport, since T5's tap records the
#       TLS tap's POST-HANDSHAKE PLAINTEXT onto the same TCP-framed pcap —
#       the wire itself is ciphertext for TLS, this is why the daemon's own
#       artifact (not an Asterisk-host tcpdump) is the only place this
#       assertion can run for TLS at all (see the file's own header note).
#   (c) ;transport=    — the T4 wire marker (Answer 200 Contact / the
#       Asterisk-redialed R-URI) carries ";transport=tcp" or
#       ";transport=tls" as appropriate.
#
# Unlike assert-nat-rport.sh (which decodes a tcpdump capture taken ON THE
# ASTERISK HOST), this script's input is the DAEMON'S OWN pcap artifact
# (e2e/loop/policy.yaml's artifact.dir, e.g.
# e2e/loop/artifacts/<call_handle>/capture.pcap) — a live Asterisk-host
# tcpdump of TLS traffic would show only ciphertext, so the daemon's
# post-handshake tap (T5) is the ONLY place a text-grep assertion can work
# for TLS. For tcp the same script also works unmodified against the same
# kind of artifact (arming a capture is transport-agnostic).
#
# Usage:
#   ./assert-tcp-tls-capture.sh <pcap-path> [tcp|tls]
#
# The transport argument selects which ;transport= value check (c) requires;
# omit it to accept either. WS_IP (the SUT) and RIG_HOST (Asterisk) are
# required; see e2e/asterisk/README.md.
#
# Exits 0 iff all checks pass; non-zero and prints the missing evidence
# otherwise.
set -euo pipefail

SRC="${1:-}"
TRANSPORT="${2:-}"
SUT_IP="${WS_IP:?WS_IP is not set: see e2e/asterisk/README.md}"
ASTERISK_IP="${RIG_HOST:?RIG_HOST is not set: see e2e/asterisk/README.md}"

if [[ -z "$SRC" || ! -e "$SRC" ]]; then
  echo "FATAL: capture not found: ${SRC:-<none given>}" >&2
  echo "usage: $0 <pcap-path> [tcp|tls]" >&2
  exit 2
fi
case "$TRANSPORT" in
  ""|tcp|tls) ;;
  *) echo "FATAL: transport argument must be tcp, tls, or omitted; got ${TRANSPORT}" >&2; exit 2 ;;
esac

# Decode to ASCII once (tcpdump -A -n; prepend sudo if the file is root-owned).
DECODE="$(tcpdump -r "$SRC" -A -n 2>/dev/null || sudo tcpdump -r "$SRC" -A -n 2>/dev/null)"
if [[ -z "$DECODE" ]]; then
  echo "FATAL: could not decode any packets from $SRC" >&2
  exit 2
fi
# Frame count over TCP specifically (protocol 6), independent of the -A text
# decode above — this is a link-layer/IP-layer property, not a text grep.
TCP_FRAMES="$(tcpdump -r "$SRC" -n 'tcp' 2>/dev/null | wc -l || true)"

fail=0
check() { # <label> <grep-egrep-pattern> [source-text, default DECODE]
  local label="$1" pat="$2" src="${3:-$DECODE}" n
  n="$(printf '%s\n' "$src" | grep -aciE "$pat" || true)"
  if [[ "$n" -gt 0 ]]; then
    printf '  PASS  %-46s (%d match(es))\n' "$label" "$n"
  else
    printf '  FAIL  %-46s (0 matches for: %s)\n' "$label" "$pat"
    fail=1
  fi
}

echo "=== P2 W2c T7 TCP/TLS capture assertion over $SRC (SUT $SUT_IP, Asterisk $ASTERISK_IP${TRANSPORT:+, transport=$TRANSPORT}) ==="

# (a) both-direction: packets Asterisk->SUT (inbound) AND SUT->Asterisk
# (outbound). tcpdump's summary line reads "<ts> IP <src>.<port> >
# <dst>.<port>: Flags ..."; not anchored at column 0 (the timestamp precedes
# it), so this greps the "IP <src> > <dst>:" substring instead.
check "inbound: Asterisk -> SUT packets present" \
      "IP ${ASTERISK_IP//./\\.}\\.[0-9]+ > ${SUT_IP//./\\.}\\.[0-9]+:"
check "outbound: SUT -> Asterisk packets present" \
      "IP ${SUT_IP//./\\.}\\.[0-9]+ > ${ASTERISK_IP//./\\.}\\.[0-9]+:"

# (b) protocol 6 (TCP) frames — checked directly against tcpdump's own TCP
# filter, not a text grep, since this is a wire-level property.
if [[ "$TCP_FRAMES" -gt 0 ]]; then
  printf '  PASS  %-46s (%d frame(s))\n' "protocol 6: TCP frames present" "$TCP_FRAMES"
else
  printf '  FAIL  %-46s (0 TCP frames decoded)\n' "protocol 6: TCP frames present"
  fail=1
fi

# (c) ;transport= wire marker (T4) on the Contact / R-URI
case "$TRANSPORT" in
  tcp) check "wire marker: ;transport=tcp present" ";transport=tcp" ;;
  tls) check "wire marker: ;transport=tls present" ";transport=tls" ;;
  *)   check "wire marker: ;transport=tcp or tls present" ";transport=(tcp|tls)" ;;
esac

echo
if [[ "$fail" -ne 0 ]]; then
  echo "=== TCP/TLS capture gate: FAIL ==="
  exit 1
fi
echo "=== TCP/TLS capture gate: PASS (both directions + protocol 6 + ;transport= all observed) ==="
