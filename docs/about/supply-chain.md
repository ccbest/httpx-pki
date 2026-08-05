# Supply chain

A library that handles client private keys deserves scrutiny of how it is built
and shipped. This page describes how releases are produced, so you can decide
what to trust.

## How a release is made

- **Published exclusively from GitHub Actions**, from a tagged commit in the
  repository, via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
  (OIDC). **No long-lived PyPI tokens exist**, so there is no publishing
  credential to steal.
- **[PEP 740](https://peps.python.org/pep-0740/) digital attestations** are
  generated for every artifact. Provenance is shown per file at
  [pypi.org/project/httpx-pki](https://pypi.org/project/httpx-pki/#files).
- **The tag is verified against the code.** The workflow checks that the release
  tag matches the package's `__version__` before building, so every release is
  auditable to exactly one commit.
- **All GitHub Actions are pinned to full commit SHAs**, not tags. Tags are
  mutable and have been repointed at malicious commits in real supply-chain
  attacks. Dependabot keeps the pins current.

## Runtime dependencies

The footprint is deliberately small:

| Package | Why |
| --- | --- |
| [httpx2](https://github.com/pydantic/httpx2) | The HTTP client being extended |
| [cryptography](https://cryptography.io/en/latest/) | Parsing and decrypting certificate material |
| [truststore](https://truststore.readthedocs.io/en/latest/) | The OS trust store behind `verify=True` |
| [certifi](https://github.com/certifi/python-certifi) | The bundle behind `verify="certifi"` |

There are no optional runtime dependencies. See [](../install.md).

## What you should do

Install with a lockfile that records hashes — as you would for any
security-sensitive dependency:

::::{tab-set}

:::{tab-item} uv
```console
$ uv lock
$ uv sync --locked
```
:::

:::{tab-item} Poetry
```console
$ poetry lock
$ poetry install
```
:::

:::{tab-item} pip-tools
```console
$ pip-compile --generate-hashes
$ pip install --require-hashes -r requirements.txt
```
:::

::::

To verify a release yourself, check the attestations on the PyPI file listing
against the tagged commit in the repository.

## Next steps

- [](security.md) — how key material is handled, and how to report an issue
- [SECURITY.md](https://github.com/ccbest/httpx-pki/blob/main/SECURITY.md) —
  the full policy
