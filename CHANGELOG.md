# Changelog

Notable changes to httpx-pki, by release. This project follows
[semantic versioning](https://semver.org/); entries are feature-level — see
the git history for the fine print.

## Unreleased

- On Linux, the decrypted private key **never touches disk**: certificate
  material is staged for OpenSSL in an anonymous in-memory file
  (`memfd_create`, read via `/proc/self/fd`) instead of a temporary PEM file.
  Matters most with `auto_reload`, which re-stages the key on every rotation.
  Environments where memfd or procfs is unavailable (e.g. a blocking seccomp
  profile) fall back to the previous behavior — a `0600` temp file deleted as
  soon as OpenSSL has read it — which remains the path on Windows and macOS.
- `verify="system"` verifies servers against the **operating-system trust
  store** (Windows CryptoAPI / macOS Security framework / OpenSSL's system CA
  paths on Linux) via the optional [truststore](https://truststore.readthedocs.io/)
  dependency — install with `pip install httpx-pki[system]`. Built for
  corporate/private CAs distributed through the OS, which certifi never
  carries. Works with every constructor and `build_ssl_context`;
  `HTTPX_PKI_CA=system` selects it for `from_env`; survives pickling. Never
  chosen implicitly: `verify=True` still means certifi, exactly like httpx.
- `CertInfo` now carries the audit fields: `serial_number` (plus a
  `serial_number_hex` convenience property), `issuer_common_name` /
  `issuer_distinguished_name`, and `fingerprint_sha256` / `fingerprint_sha1`
  (uppercase hex; the SHA-1 form matches the platform stores' thumbprints, so
  it can be passed straight to a `thumbprint=` selector).
- Warnings now carry filterable categories: `PKIWarning` (base, a
  `UserWarning`) with `CertificateValidityWarning`, `TLSConfigWarning`, and
  `PicklingWarning` subclasses — silence one concern (e.g. "expires soon")
  without regex-matching message text or hiding the others.
- `warn_if_expires_within` is an explicit, documented parameter of every
  constructor (`from_pkcs12`, `from_pem`, `from_key_pair`, `from_env`, and the
  platform-store constructors), not just `PKIClient(...)`. It previously
  worked on the alternates only by accident of `**kwargs` forwarding.
- Internal: `__init__` and the six `from_*` constructors now live once on the
  shared mixin instead of being duplicated across `PKIClient` and
  `AsyncPKIClient` (~200 lines removed; no behavior or typing change —
  `MySession.from_pkcs12(...)` still types as `MySession`).

## 0.4.0 — 2026-07-14

### Certificate rotation (hot reload)

- `client.reload()` re-reads the certificate source — file, `from_env`
  variables, or a platform certificate store — and swaps the fresh certificate
  into the mounted SSL context in place, so new handshakes present it without
  rebuilding the client. The swap is atomic: an unreadable source leaves the
  previous certificate serving.
- `auto_reload=True` (or a `timedelta` throttle) watches the source files and
  reloads automatically when they change — built for cert-manager/Vault-style
  environments where certificates rotate under a running process.
- `strict_validity=True` runs `check_validity()` before every request, so an
  expired certificate fails with a clear `CertificateExpiredError` instead of
  an opaque handshake error.

### macOS keychain support

- `PKIClient.from_macos_keychain()` (and the async equivalent) pulls an
  exportable identity straight from the keychain, selected by name substring,
  thumbprint, or predicate — the macOS sibling of the Windows cert store
  integration, with the same selection semantics and error types.
- `list_macos_certificates()`, `select_macos_certificate()`, `MacCert`, and
  `build_macos_ssl_context()` round out the surface.
- CI now runs the full test matrix on macOS (alongside Linux and Windows),
  including live mTLS round trips against a real temporary keychain.

## 0.3.0 — 2026-07-13

- The Windows cert store helpers went public: `build_windows_ssl_context()`,
  `list_windows_certificates()`, and `select_windows_certificate()`.
- Leaf-plus-intermediates bundles are preserved everywhere: `from_key_pair`
  and `from_env` keep chain certificates found alongside the leaf (identified
  by private-key match, in any order), and the new `HTTPX_PKI_CHAIN`
  environment variable supplies extra intermediates.
- Alternate constructors are subclass-aware in type checkers:
  `MySession.from_pkcs12(...)` now types as `MySession`, not the base class.
- A PEM bundle containing multiple private keys is rejected up front rather
  than silently using one of them.
- `httpx_pki.testing` mints certificates with realistic extensions
  (`digitalSignature`/`keyEncipherment` KeyUsage, `clientAuth` EKU), so strict
  servers accept them.
- Python 3.14 support.

## 0.2.0 — 2026-07-02

- `client.certificate` exposes the parsed `cryptography` x509 certificate and
  `client.ssl_context` the exact SSL context mounted on the session, for
  building custom transports that present the same client certificate.

## 0.1.0 — 2026-06-30

Initial release.

- `PKIClient` / `AsyncPKIClient`: subclassable httpx sessions with a client
  certificate mounted, built from PKCS#12 or PEM (encoding detected from
  content, never the file extension), a separate cert + key pair, environment
  variables (`from_env`), or the Windows certificate store.
- `build_ssl_context()` for using the certificate-loading machinery without
  the session wrapper.
- Expiry awareness: loading an expired or not-yet-valid certificate warns
  immediately; `check_validity()`, `is_expired`, `expires_in`, and friends
  make it inspectable.
- Early validation that the private key matches the certificate, instead of a
  cryptic OpenSSL handshake failure later.
- `httpx_pki.testing` helpers (`make_ca`, `make_client_cert`) for minting
  throwaway certificates in downstream test suites.
- Pickling support (the pickle contains the decrypted key — treat it as a
  secret).
