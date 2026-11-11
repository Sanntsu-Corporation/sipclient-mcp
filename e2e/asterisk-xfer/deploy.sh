#!/usr/bin/env bash
# e2e/asterisk-xfer/deploy.sh
#
# Stages the call-transfer rig — the host-independent asterisk.conf,
# logger.conf and modules.conf from e2e/asterisk/conf (reused, not copied into
# git: Rule 16/18) plus this directory's own conf/ — rsyncs it to the host and
# (re)starts the container from the PRE-BUILT image. No docker build.
#
# Usage: RIG_HOST=<addr> XFER_ASTERISK_IMAGE=<image> ./deploy.sh [user@host] [remote_dir]
# The ssh target defaults to RIG_SSH; RIG_HOST is the address Asterisk binds,
# rendered into the @RIG_HOST@ token in conf/*.conf (see e2e/asterisk/README.md).
# The host user/access model is a preflight item — see README.md.
set -euo pipefail

HOST="${1:-${RIG_SSH:?RIG_SSH is not set: see e2e/asterisk/README.md}}"
RIG_HOST="${RIG_HOST:?RIG_HOST is not set: see e2e/asterisk/README.md}"
REMOTE_DIR="${2:-~/e2e-asterisk-xfer}"
: "${XFER_ASTERISK_IMAGE:?set XFER_ASTERISK_IMAGE to the Asterisk image already built on the host (README.md preflight)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_CONF="${SCRIPT_DIR}/../asterisk/conf"

if [ ! -f "${SCRIPT_DIR}/conf/keys/ca.crt" ]; then
  echo "conf/keys/ca.crt not found -- run:" >&2
  echo "  KEYS_DIR=${SCRIPT_DIR}/conf/keys CERT_HOST=${RIG_HOST} ${SCRIPT_DIR}/../asterisk/gen-certs.sh" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
mkdir -p "${STAGE}/conf"
cp "${BASE_CONF}/asterisk.conf" "${BASE_CONF}/logger.conf" "${BASE_CONF}/modules.conf" "${STAGE}/conf/"
cp -R "${SCRIPT_DIR}/conf/." "${STAGE}/conf/"
for f in "${STAGE}"/conf/*.conf; do
  sed "s/@RIG_HOST@/${RIG_HOST}/g" "$f" > "$f.rendered" && mv "$f.rendered" "$f"
done
cp "${SCRIPT_DIR}/docker-compose.yml" "${STAGE}/"
printf 'XFER_ASTERISK_IMAGE=%s\n' "${XFER_ASTERISK_IMAGE}" > "${STAGE}/.env"

echo "Deploying to ${HOST}:${REMOTE_DIR} ..."
ssh "${HOST}" "mkdir -p ${REMOTE_DIR}"
rsync -az --delete "${STAGE}/" "${HOST}:${REMOTE_DIR}/"
ssh "${HOST}" "cd ${REMOTE_DIR} && docker compose up -d"
echo "Done."
