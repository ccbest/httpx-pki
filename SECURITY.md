# Security Policy

`httpx-pki` handles client private keys and the passwords that protect them,
so security reports are taken seriously and handled promptly.

## Reporting a vulnerability

Please **do not open a public issue** for anything security-sensitive. Instead,
report it privately via GitHub's vulnerability reporting:

> https://github.com/ccbest/httpx-pki/security/advisories/new

You should receive an acknowledgement within a few days. Please include a
minimal reproduction if you can, and give a reasonable window for a fix and
release before public disclosure.

## Scope

Reports especially welcome (non-exhaustive):

- Private-key or password material leaking somewhere unintended — disk, logs,
  `repr()`, warnings, exception messages, or living longer than documented.
- Server-verification bypasses: any way a certificate is accepted that
  `verify=`'s documented semantics say should be rejected.
- Flaws in the platform-store integrations (Windows CryptoAPI / macOS
  Security framework export paths).
- Supply-chain issues with the release pipeline described below.

Already-documented behavior — e.g. that a pickled session contains the
decrypted private key (see the README's security note) — is not a
vulnerability by itself, but ways to *exploit* such behavior beyond what is
documented are in scope.

## Supported versions

Only the **latest release** receives security fixes. There are no maintenance
branches for older versions; fixes ship as a new release.

## Supply chain

How releases are produced, so you can decide what to trust:

- Releases are built and published exclusively by GitHub Actions from a tagged
  commit in this repository, via [PyPI Trusted Publishing][tp] (OIDC — no
  long-lived PyPI tokens exist) with [PEP 740][pep740] digital attestations.
  Provenance is shown on each file at
  [pypi.org/project/httpx-pki](https://pypi.org/project/httpx-pki/#files).
- The workflow verifies that the release tag matches the package's
  `__version__` before building, so a release is auditable to one commit.
- All GitHub Actions used by CI and release workflows are pinned to full
  commit SHAs.
- Runtime dependencies are limited to `httpx`, `cryptography`, and `certifi`
  (plus the optional `truststore` extra).

As a consumer, install with a lockfile that records hashes (uv, poetry, or
`pip-tools` + `pip install --require-hashes`) — as you would for any
security-sensitive dependency.

[tp]: https://docs.pypi.org/trusted-publishers/
[pep740]: https://peps.python.org/pep-0740/
