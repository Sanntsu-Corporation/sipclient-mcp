#!/usr/bin/env bash
# e2e/asterisk/deploy.sh
#
# Rsyncs this directory to the E2E Asterisk test host and (re)builds and
# (re)starts the container there. The host is provisioned entirely from
# these committed files -- no ad-hoc host-only config.
#
# Usage: RIG_HOST=<addr> RIG_SSH=<user@host> ./deploy.sh [user@host] [remote_dir]
# The ssh target is the first argument if given, otherwise RIG_SSH; RIG_HOST is the
# address Asterisk binds, rendered into conf/pjsip.conf and conf/rtp.conf.
set -euo pipefail

HOST="${1:-${RIG_SSH:?RIG_SSH is not set: see e2e/asterisk/README.md}}"
RIG_HOST="${RIG_HOST:?RIG_HOST is not set: see e2e/asterisk/README.md}"
REMOTE_DIR="${2:-~/e2e-asterisk}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "${SCRIPT_DIR}/conf/keys/ca.crt" ]; then
  echo "conf/keys/ca.crt not found -- run ./gen-certs.sh first (TLS transport needs it)." >&2
  exit 1
fi

# Asterisk config cannot read environment variables, so stage a copy and render
# the @RIG_HOST@ token (bind addresses in conf/*.conf) before syncing.
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT
cp -R "${SCRIPT_DIR}/." "${STAGE_DIR}/"
for f in "${STAGE_DIR}"/conf/*.conf; do
  sed "s/@RIG_HOST@/${RIG_HOST}/g" "$f" > "$f.rendered" && mv "$f.rendered" "$f"
done

echo "Deploying to ${HOST}:${REMOTE_DIR} ..."
ssh "${HOST}" "mkdir -p ${REMOTE_DIR}"
rsync -az --delete "${STAGE_DIR}/" "${HOST}:${REMOTE_DIR}/"

echo "Building and starting the container on ${HOST} ..."
ssh "${HOST}" "cd ${REMOTE_DIR} && docker compose up -d --build && docker compose --profile tools build sipp"

echo "Done."
