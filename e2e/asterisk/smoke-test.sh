#!/usr/bin/env bash
# e2e/asterisk/smoke-test.sh
#
# Runs the full sipp scenario matrix (scenarios/*.xml) against a live
# instance of this platform and prints a per-scenario PASS/FAIL/SKIP
# summary, exiting non-zero if anything failed. This answers "is the
# §14.5 gate rig actually healthy right now?" -- not a test framework,
# just sipp's own exit code (0 = call succeeded per its mandatory recv
# matches) as the verdict for each scenario.
#
# Run this ON the test host (that's where deploy.sh builds and deploys the
# sipp Compose service this script invokes -- see USAGE.md). Usage:
# ./smoke-test.sh [host]
set -euo pipefail

HOST="${1:-${RIG_HOST:?RIG_HOST is not set: see e2e/asterisk/README.md}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/tmp/e2e-asterisk-smoke"
mkdir -p "${LOG_DIR}"

# echo-pcmu/echo-pcma play a real RTP stream via sipp's
# play_pcap_audio action, which needs a raw socket. Rather than requiring
# host sudo for that, every scenario runs through the containerized `sipp`
# Compose service (e2e/asterisk/docker-compose.yml), which is granted only
# the NET_RAW capability that action needs.

# Preflight: fail fast if the sipp image doesn't exist yet, rather than
# letting `docker compose run` build it lazily inside the first scenario's
# run() call below -- that would launder a build failure into a confusing
# scenario FAIL (retried across all 9 scenarios) instead of a clear error.
sipp_image="$(cd "${SCRIPT_DIR}" && docker compose config --images sipp 2>/dev/null)" || sipp_image=""
if [ -z "${sipp_image}" ] || ! docker image inspect "${sipp_image}" > /dev/null 2>&1; then
  echo "sipp image not built -- run ./deploy.sh first." >&2
  exit 1
fi

PASS=0
FAIL=0
SKIP=0

run() {
  local name="$1" file="$2" port="$3"
  shift 3
  local log="${LOG_DIR}/${name}.log"
  printf '  %-20s ... ' "${name}"
  if (cd "${SCRIPT_DIR}" && docker compose run --rm -T sipp \
      -sf "/scenarios/${file}" "${HOST}:${port}" \
      -m 1 -nostdin -timeout 20s -timeout_error "$@") \
      > "${log}" 2>&1; then
    echo "PASS  ($(grep -m1 'Successful call' "${log}" | tail -1 | tr -s ' '))"
    PASS=$((PASS + 1))
  else
    echo "FAIL  (see ${log})"
    tail -n 20 "${log}"
    FAIL=$((FAIL + 1))
  fi
}

skip() {
  local name="$1" reason="$2"
  printf '  %-20s ... SKIP  (%s)\n' "${name}" "${reason}"
  SKIP=$((SKIP + 1))
}

echo "=== e2e/asterisk smoke test against ${HOST} ==="
echo
echo "-- UDP (default transport) --"
run register           register.xml           5070
run echo-pcmu           echo-pcmu.xml           5070
run echo-pcma           echo-pcma.xml           5070
run reject-486           reject-486.xml           5070
run reject-404           reject-404.xml           5070
run srtp-sdes           srtp-sdes.xml           5070
run srtp-refuse-plain   srtp-refuse-plain.xml   5070

echo
echo "-- TCP transport (register only -- proves the transport itself"
echo "   works; the call/codec/SRTP surfaces above are already proven"
echo "   over UDP and don't need re-proving per transport) --"
run register-tcp       register.xml           5070 -t t1

echo
echo "-- TLS transport --"
skip register-tls "the installed sipp 3.7.2 build cannot complete a TLS handshake in single-socket mode (-t l1) -- known tooling limitation, not a platform defect. See USAGE.md Troubleshooting / Known limitations."

echo
echo "=== ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ==="

[ "${FAIL}" -eq 0 ]
