# Contributing

Thanks for helping. This is a Go project; you need Go 1.25 or newer.

## Build, test, lint

```bash
make build   # writes bin/sipclient-mcpd
make test    # go test -race ./... plus an uncached run of internal/importguard
make lint    # golangci-lint run (needs golangci-lint v2 installed)
```

The vendored `third_party/sipgo` is a separate Go module with its own tests; run
`go test ./...` inside that directory if you change it. On a fresh clone, first
generate its test certificates (needs `openssl`), as CI does; they are git-ignored
and an embedded test file needs them to compile:

```bash
cd third_party/sipgo/testdata && bash ./generate_certs_rsa.sh
```

## Tests need no external host

`make test` needs no external services. Tests run against in-process peers and loopback
sockets and contact no external host.

Two groups of tests need a real SIP server and are **opt-in**; they skip
themselves unless you set environment variables:

| Variable | Enables |
|---|---|
| `SIPCLIENT_E2E_GATE=1` | The interop gate in `e2e/loop` against an Asterisk rig |
| `SIPPROXY_LIVE=1` | The live proxy test in `cmd/sipclient-proxy` (build tag `live`) |

Both also need the rig's address variables described in
[e2e/asterisk/README.md](e2e/asterisk/README.md). You do not need the rig to
contribute; CI runs without it.

## Platform notes

Linux is the reference platform; CI runs on ubuntu. On macOS, about ten
`internal/sipua` test files bind `127.0.0.2`, which the loopback interface does
not have by default. Add it before running the tests, and remove it afterwards:

```bash
sudo ifconfig lo0 alias 127.0.0.2 up
sudo ifconfig lo0 -alias 127.0.0.2
```

Without the alias those tests fail. In the vendored sipgo module,
`TestUDPWriteMsgResponseLimitIsTheDatagramMaximum` also fails on macOS because
`net.inet.udp.maxdgram` is 9216 there.

## Pull requests

Open a plain pull request against `main`. There is no DCO or CLA sign-off. Keep a
change focused, add or update tests for behavior you change, and make sure
`make test` and `make lint` pass. Match the style of the file you are editing and
avoid unrelated reformatting.

## Code comments mention `CF-nnn`

Strings of the form `CF-nnn` in code comments are historical issue identifiers from
the project's earlier tracker. They are kept as pointers to the reasoning behind a
piece of code and have no meaning outside it; you do not need to look them up or
use that format in new comments. Similar internal references in comments (such as
`Rule NN`, `Phase N`, section numbers, or wave and task IDs) are likewise
historical labels from the private development history and can be ignored.

## Vendored sipgo

`third_party/sipgo` is a fork of `github.com/emiago/sipgo` wired in through a
`replace` directive in `go.mod`. It is owned by this project and may be modified,
but every change to it must be recorded in
[third_party/sipgo/VENDOR.md](third_party/sipgo/VENDOR.md). The same applies to
`internal/sipengine`, see [internal/sipengine/VENDOR.md](internal/sipengine/VENDOR.md).

## Conduct and security

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Report
security issues privately as described in [SECURITY.md](SECURITY.md).
