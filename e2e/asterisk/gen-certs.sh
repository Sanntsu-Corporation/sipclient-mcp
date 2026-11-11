#!/usr/bin/env bash
# e2e/asterisk/gen-certs.sh
#
# Generates a self-signed CA and a server cert for the Asterisk PJSIP TLS
# transport (conf/pjsip.conf [transport-tls]). Output goes to conf/keys/,
# which docker-compose.yml bind-mounts (as part of ./conf) to
# /etc/asterisk/keys inside the container.
#
# Nothing under keys/ is committed -- see .gitignore. Re-run this script
# after a fresh checkout, or whenever certs expire, before deploying.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# KEYS_DIR/CERT_HOST let the call-transfer rig (e2e/asterisk-xfer) reuse this
# generator. The certificate's IP SAN comes from CERT_HOST, defaulting to RIG_HOST.
KEYS_DIR="${KEYS_DIR:-${SCRIPT_DIR}/conf/keys}"
CERT_HOST="${CERT_HOST:-${RIG_HOST:?RIG_HOST is not set: see e2e/asterisk/README.md}}"
DAYS=3650
SAN="IP:${CERT_HOST},DNS:localhost,IP:127.0.0.1"

mkdir -p "${KEYS_DIR}"
cd "${KEYS_DIR}"

echo "Generating CA..."
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "${DAYS}" \
  -keyout ca.key -out ca.crt \
  -subj "/O=sipclient-mcp e2e/CN=e2e-asterisk-test-ca"

echo "Generating server key + CSR..."
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout server.key -out server.csr \
  -subj "/O=sipclient-mcp e2e/CN=${CERT_HOST}"

echo "Signing server cert with SAN=${SAN}..."
openssl x509 -req -sha256 -days "${DAYS}" \
  -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt \
  -extfile <(printf "subjectAltName=%s" "${SAN}")

rm -f server.csr ca.srl
# World-readable, not owner-only: the key files are bind-mounted read-only
# into the container, where Asterisk runs as its own "asterisk" user (a
# different uid than whatever host user generated/rsynced these files), so
# it needs read access. These are lab-only, non-production test certs --
# see README.md -- so this is not a meaningful exposure.
chmod 644 ca.key server.key ca.crt server.crt

echo
echo "Done. Files written to: ${KEYS_DIR}"
echo
echo "sipclient-mcp needs the CA cert as its TLS trust anchor:"
echo "  ${KEYS_DIR}/ca.crt"
