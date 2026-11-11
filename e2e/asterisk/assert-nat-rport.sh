#!/usr/bin/env bash
# assert-nat-rport.sh — P2 Wave 2b NAT rport exit-gate assertion (spec §14.5).
#
# Asserts, against a REAL on-the-wire capture of a loop-call gate run, the three
# RFC 3581 rport properties W2b adds:
#
#   1. ADVERTISE  — the SUT's outbound REGISTER Via carries ;rport, INCLUDING on
#                   the digest-challenged retry (Task 2: WithClientNAT).
#   2. LEARN/ECHO — the registrar's response Via carries received=<ip> AND
#                   rport=<port> (Task 3 reads these to learn the public addr).
#   3. USE/CONTACT— the callee (register-mode UA) emits a Contact at its
#                   bound==learned host:port. NOTE: on a flat lab LAN
#                   learned==bound, so this check only confirms the callee's
#                   Contact is well-formed at its own address — it does NOT by
#                   itself prove Answer consumed the LEARNED value over the
#                   bound one. That learned!=bound proof lives in Task 3's
#                   mutation-verified sipproxy unit test
#                   (TestRportIntegration_AnswerUsesLearnedAddress); this gate
#                   only exercises the mechanism end-to-end against a real peer.
#
# This is a MANUAL-gate assertion (like smoke-test.sh): it consumes a capture
# taken on the Asterisk test host while `./e2e/loop/run.sh` runs on the SUT.
#
# CAVEAT (rig-specific): the checks are line-oriented greps, not transaction-
# correlated, and check #2's pattern assumes Asterisk's param order
# (rport=...;received=...). They validate THIS rig's wire format; a compliant
# registrar that reorders Via params could make check #2 miss. The per-message,
# transaction-correlated proof is the unit test cited above.
#
# Capture (on the test host, i.e. RIG_SSH), then run the loop on
# the SUT (WS_IP):
#
#   # test host:
#   sudo timeout 140 tcpdump -i any -s 0 -w /tmp/w2b-rport.pcap \
#        'udp and host $WS_IP and port 5060'
#   # SUT (concurrently):
#   ./e2e/loop/run.sh
#
# Then assert (test host, or copy the pcap anywhere tcpdump can read it):
#
#   ./assert-nat-rport.sh /tmp/w2b-rport.pcap
#
# Accepts a .pcap (decoded via tcpdump -A, may need sudo) or a pre-decoded .txt.
# Exits 0 iff all three checks pass; non-zero and prints the missing evidence
# otherwise. The SUT address is read from $WS_IP (required).
set -euo pipefail

SRC="${1:-/tmp/w2b-rport.pcap}"
SUT_IP="${WS_IP:?WS_IP is not set: see e2e/asterisk/README.md}"

if [[ ! -e "$SRC" ]]; then
  echo "FATAL: capture not found: $SRC" >&2
  exit 2
fi

# Decode to ASCII once. A .pcap is read with tcpdump -A (prepend 'sudo' if the
# file is root-owned); a .txt is assumed already decoded.
case "$SRC" in
  *.txt) DECODE="$(cat "$SRC")" ;;
  *)     DECODE="$(tcpdump -r "$SRC" -A -n 2>/dev/null || sudo tcpdump -r "$SRC" -A -n 2>/dev/null)" ;;
esac

if [[ -z "$DECODE" ]]; then
  echo "FATAL: could not decode any packets from $SRC" >&2
  exit 2
fi

fail=0
check() { # <label> <grep-egrep-pattern>
  local label="$1" pat="$2" n
  n="$(printf '%s\n' "$DECODE" | grep -aciE "$pat" || true)"
  if [[ "$n" -gt 0 ]]; then
    printf '  PASS  %-42s (%d match(es))\n' "$label" "$n"
  else
    printf '  FAIL  %-42s (0 matches for: %s)\n' "$label" "$pat"
    fail=1
  fi
}

echo "=== P2 W2b NAT rport gate assertion over $SRC (SUT $SUT_IP) ==="

# 1. Outbound REGISTER Via from the SUT advertises a BARE ;rport (no value) —
#    distinct from the registrar's echoed ;rport=<port> (checked in #2). grep is
#    line-oriented so `.` never crosses the CRLF; `;rport` followed by a non-'='
#    (the trailing CR) or end-of-line excludes the echoed rport=<port> form.
check "advertise: REGISTER Via carries ;rport" \
      "Via: SIP/2.0/UDP ${SUT_IP}:[0-9]+;.*;rport([^=]|\$)"

# 2. A response Via echoes BOTH received=<ip> and rport=<port> for the SUT.
check "learn/echo: response Via has received+rport" \
      "Via: SIP/2.0/UDP ${SUT_IP}:[0-9]+;rport=[0-9]+;received=${SUT_IP//./\\.}"

# 3. The callee (register UA) emits a well-formed Contact at its own host:port
#    (bound==learned on this flat LAN — see the header note; not a learned!=bound proof).
check "use/contact: callee Contact well-formed at its addr" \
      "Contact: <sip:e2e-uac-register@${SUT_IP}:[0-9]+>"

echo
if [[ "$fail" -ne 0 ]]; then
  echo "=== NAT rport gate: FAIL ==="
  exit 1
fi
echo "=== NAT rport gate: PASS (advertise + learn/echo + use all observed on the wire) ==="
