# Changelog

Notable changes to httpx-pki, by release. This project follows
[semantic versioning](https://semver.org/); entries are feature-level — see
the git history for the fine print.

## 0.7.0 — Unreleased

- **Multi-identity PKCS#12 bundles** are now handled properly. A `.p12` can
  hold more than one identity (a key plus its certificate) — the dual key pair
  a CA issues when it escrows the encryption key but not the signing key, as
  Entrust, PIV/CAC, S/MIME key archival, and several national eID schemes do.
  `list_pkcs12_identities()` reports what a file holds (index, friendly name,
  key usage, extended key usage, fingerprints — never the private keys), and
  every PKCS#12 entry point — `PKIClient(...)`, `from_pkcs12`, `from_env`,
  `build_ssl_context` — takes `identity=` (file position, name or fingerprint,
  or a predicate over the new `P12Identity`), `key_usage=`, and
  `extended_key_usage=`, which intersect when combined. The selection is
  recorded on the source, so `reload()` / `auto_reload` re-select the same
  identity after a rotation even if the new file orders them differently, and
  it survives pickling. `HTTPX_PKI_IDENTITY`, `HTTPX_PKI_KEY_USAGE`, and
  `HTTPX_PKI_EXT_KEY_USAGE` do the same for `from_env`.
- **Behavior change:** loading a bundle that holds several identities without a
  selector now raises `AmbiguousCertificateError`, listing the identities and
  what distinguishes them, instead of silently presenting whichever one the
  file happened to store first. Bundles with a single identity — very nearly
  all of them — are completely unaffected. (`cryptography` returns only the
  first key in a file and discards the rest, so the previous behavior was an
  arbitrary choice between real alternatives.)
- **Bug fix:** a second identity's certificate is no longer presented to the
  server as a *chain* certificate. It is a leaf certificate of its own, not an
  intermediate, and sending it can make a strict server reject the chain.
- A **renewed certificate stored alongside the one it replaces** — two
  certificates over a single key pair, which is what renewing rather than
  rekeying produces — is now recognized as two identities rather than one
  identity plus a stray chain certificate. Since nothing but the validity
  window distinguishes them, the identity listing in the error message carries
  each certificate's expiry.
- **The platform stores got the same selectors.**
  `from_windows_cert_store`, `from_macos_keychain`, and their
  `build_*_ssl_context` counterparts take `key_usage=` and
  `extended_key_usage=` — which matters most there, since Active Directory key
  archival and macOS keychains routinely hold both halves of a dual key pair
  under one subject, and an exact thumbprint was previously the only way out.
  `WinCert` and `MacCert` now carry the parsed `certificate`, its `info`
  (`CertInfo`), and `key_usage` / `extended_key_usage`, so a `predicate=` can
  select on anything a certificate holds — including skipping the expired copy
  a store keeps after a renewal. One predicate now reads the same across
  PKCS#12 files, the Windows store, and the keychain.
- **Behavior change:** store selectors now **intersect** instead of overriding.
  Passing `name=` together with `thumbprint=` used to silently ignore the name
  (the documented "order of specificity"); now every selector given must match,
  as the PKCS#12 selectors do. Callers passing a single selector are
  unaffected; callers passing several that agree get the same result as before.
- `CertInfo` now reports `key_usage` and `extended_key_usage` — the extensions
  that tell the halves of a dual key pair apart — for every certificate, not
  just those inside a PKCS#12 bundle. Usage names are accepted in camelCase as
  well as snake_case, extended usages also as dotted OIDs, and `nonRepudiation`
  as a spelling of the bit X.509 renamed to `contentCommitment`.
- `httpx_pki.testing.make_pkcs12()` writes multi-identity bundles (in the
  layout OpenSSL and Windows produce), which neither `cryptography` nor the
  `openssl` command line can do; `make_client_cert()` gained `key_usage=` and
  `extended_key_usage=` overrides to mint the two halves.

## 0.6.0 — 2026-07-15

- **PKCS#7 (`.p7b`/`.p7c`) certificate bundles** are accepted anywhere
  certificates (not keys) are accepted, in DER or PEM: `certificate=` and
  `chain=` in `from_key_pair`, the chain variable of `from_env`, a PEM bundle
  holding a `PKCS7` block, and — new for `verify=` — a `.p7b` path as the CA
  bundle (converted internally; OpenSSL's `cafile` is PEM-only). This is the
  format Windows CAs commonly export chains in.
- Passing a certificate with no private key as the single source now raises a
  pointed error naming the right entry point, instead of the misleading
  "invalid PKCS#12 data or wrong password": bare DER certificates are directed
  to `from_key_pair`, certs-only PKCS#7 bundles to `chain=`/`verify=`.

## 0.5.0 — 2026-07-14

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
  `PicklingWarning` subclasses.
- `warn_if_expires_within` is an explicit, documented parameter of every
  constructor (`from_pkcs12`, `from_pem`, `from_key_pair`, `from_env`, and the
  platform-store constructors), not just `PKIClient(...)`. It previously
  worked on the alternates only by accident of `**kwargs` forwarding.

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
