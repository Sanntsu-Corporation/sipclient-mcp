GO        ?= go
BIN       := bin/sipclient-mcpd
PKG       := ./cmd/sipclient-mcpd

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILDDATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILDDATE)

PROXY_PKG     := ./cmd/sipclient-proxy
PROXY_TARGETS := darwin/arm64 windows/amd64
PROXY_DIST    := dist/proxy
PROXY_LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILDDATE)

MCPD_TARGETS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64
MCPD_DIST    := dist/mcpd

.PHONY: build test lint clean dtmf-vectors proxy-dist dist

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

test:
	# importguard shells out via exec.Command rather than statically importing the
	# packages it inspects, so Go's build cache can't see inspected-package changes;
	# force it fresh here while the rest of the suite keeps its cache.
	$(GO) test -count=1 ./internal/importguard/...
	$(GO) test -race -timeout 20m ./...

lint:
	golangci-lint run

clean:
	rm -rf bin

# dtmf-vectors regenerates the pinned Q.23 DTMF fixtures under testdata/dtmf.
# The generated files ARE COMMITTED; this target exists so the fixtures are
# reproducible, not so the test suite depends on running it.
dtmf-vectors:
	$(GO) run ./scripts/gen-dtmf-vectors

# proxy-dist cross-compiles sipclient-proxy (CGO off) for the client platforms,
# zips each build and writes SHA-256 sums. Windows signing (osslsigncode) and
# macOS notes are documented in docs/sipclient-proxy.md, not automated here.
# In a git worktree run with GOFLAGS=-buildvcs=false.
proxy-dist:
	rm -rf $(PROXY_DIST)
	mkdir -p $(PROXY_DIST)
	set -e; for t in $(PROXY_TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; \
	  if [ "$$os" = windows ]; then ext=".exe"; fi; \
	  name=sipclient-proxy_$(VERSION)_$${os}_$${arch}; \
	  mkdir -p $(PROXY_DIST)/$$name; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(PROXY_LDFLAGS)" \
	    -o $(PROXY_DIST)/$$name/sipclient-proxy$$ext $(PROXY_PKG); \
	  mkdir -p $(PROXY_DIST)/$$name/third_party/sipgo; \
	  cp LICENSE THIRD_PARTY_NOTICES.md $(PROXY_DIST)/$$name/; \
	  cp third_party/sipgo/LICENSE $(PROXY_DIST)/$$name/third_party/sipgo/; \
	  (cd $(PROXY_DIST) && python3 -m zipfile -c $$name.zip $$name); \
	done
	cd $(PROXY_DIST) && sha256sum *.zip > SHA256SUMS

# dist cross-compiles sipclient-mcpd (CGO off) for the daemon platforms, zips
# each build and writes SHA-256 sums. Modelled on proxy-dist; no signing here.
# In a git worktree run with GOFLAGS=-buildvcs=false.
dist:
	rm -rf $(MCPD_DIST)
	mkdir -p $(MCPD_DIST)
	set -e; for t in $(MCPD_TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; \
	  if [ "$$os" = windows ]; then ext=".exe"; fi; \
	  name=sipclient-mcpd_$(VERSION)_$${os}_$${arch}; \
	  mkdir -p $(MCPD_DIST)/$$name; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
	    -o $(MCPD_DIST)/$$name/sipclient-mcpd$$ext $(PKG); \
	  mkdir -p $(MCPD_DIST)/$$name/third_party/sipgo; \
	  cp LICENSE THIRD_PARTY_NOTICES.md $(MCPD_DIST)/$$name/; \
	  cp third_party/sipgo/LICENSE $(MCPD_DIST)/$$name/third_party/sipgo/; \
	  (cd $(MCPD_DIST) && python3 -m zipfile -c $$name.zip $$name); \
	done
	cd $(MCPD_DIST) && sha256sum *.zip > SHA256SUMS
