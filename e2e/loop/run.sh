#!/usr/bin/env bash
# run.sh — thin wrapper around the loop-call interop gate.
#
# Runs from the repository root regardless of where it is invoked, so the
# daemon's repo-root-relative policy paths resolve. Forwards all arguments to
# the harness (e.g. -sanity, -local <ip>, -ssh "").
#
#   ./e2e/loop/run.sh            # full gate
#   ./e2e/loop/run.sh -sanity    # non-live plumbing check only
#
# The scenario count is whatever gate.go's slice holds (it prints "N/N passed");
# do not restate it here — this comment said 17/17 while the slice held 19.
# `go test ./e2e/loop/` (gate_test.go, D4) is the other entry point; it skips
# unless SIPCLIENT_E2E_GATE=1 and the rig answers an ssh preflight.
#
# RIG_HOST, WS_IP and RIG_SSH (see e2e/asterisk/README.md) are mapped onto the
# SIPCLIENT_E2E_ASTERISK / SIPCLIENT_E2E_LOCAL / SIPCLIENT_E2E_SSH variables the
# harness reads; the harness stops with a message if the rig address is unset
# (except for -sanity).
set -euo pipefail
export SIPCLIENT_E2E_ASTERISK="${SIPCLIENT_E2E_ASTERISK:-${RIG_HOST:-}}"
export SIPCLIENT_E2E_LOCAL="${SIPCLIENT_E2E_LOCAL:-${WS_IP:-}}"
export SIPCLIENT_E2E_SSH="${SIPCLIENT_E2E_SSH:-${RIG_SSH:-}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
exec go run ./e2e/loop "$@"
