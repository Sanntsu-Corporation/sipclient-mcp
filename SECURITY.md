# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately with GitHub's **Report a vulnerability** button on the
repository's **Security** tab (private vulnerability reporting). Include the
affected version or commit, what you observed, and the smallest steps that
reproduce it.

Reports are triaged by the project maintainers. If you cannot use GitHub's
private reporting, email security@sanntsu.com instead. We acknowledge a report within
5 business days and aim to share an assessment and a fix plan within 30 days.

## Supported versions

Only the latest `0.x` release receives security fixes. There are no backports to
older releases.

## Scope and known limitations

`sipclient-mcp` is a development tool meant for a trusted machine or network.
Its threat model, what the bearer token does and does not protect, and the
issues already known are described in the README sections
[Security model](README.md#security-model) and
[Known limitations](README.md#known-limitations). Reports about behavior those
sections already document are still welcome, but may be handled as ordinary
issues.
