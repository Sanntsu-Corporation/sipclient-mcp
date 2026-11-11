# e2e/asterisk/Dockerfile
#
# Internal test-infrastructure image for the sipclient-mcp §14.5 interop gate.
# This is NOT the SIP client under test — it is the far-end Asterisk PBX that
# sipclient-mcp is tested against, so both ends do not share our
# implementation's misunderstandings.
#
# Distro Asterisk 20 from Ubuntu 24.04 "noble" universe (verified present;
# Debian bookworm/trixie have no asterisk package). No third-party or
# community Asterisk image.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Enable universe (asterisk and libsrtp2-dev both live there),
# then install Asterisk 20 plus English sound prompts (wav for quality,
# gsm as the lightweight fallback Asterisk also ships) and SRTP support.
RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        asterisk \
        asterisk-core-sounds-en-wav \
        asterisk-core-sounds-en-gsm \
        libsrtp2-1 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Config is bind-mounted read-only from ./conf at /etc/asterisk by
# docker-compose.yml; nothing config-related is baked into the image.

# Run in the foreground (-f) so Docker supervises the process directly and
# `docker logs` captures Asterisk's console output. -vvv gives verbose
# console logging useful while iterating on config.
CMD ["asterisk", "-f", "-vvv"]
