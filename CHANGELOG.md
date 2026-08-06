# Changelog

Notable changes to httpx-pki, by release. This project follows
[semantic versioning](https://semver.org/); entries are feature-level — see
the git history for the fine print.

## 0.8.0 — 2026-08-05

- **httpx2 is now the required dependency**, completing the shift 0.7 started.
  `PKIClient` / `AsyncPKIClient` subclass `httpx2.Client` / `httpx2.AsyncClient`
  by default. The original httpx remains fully supported as a fallback: with
  `httpx>=0.28` installed, httpx-pki binds to httpx whenever httpx2 is absent,
  exactly as before, and `HTTPX_PKI_BACKEND` (`httpx` or `httpx2`) forces the
  choice when both are installed. `httpx_pki.HTTP_BACKEND` still reports the
  resolution. There is deliberately no `[httpx]` extra: extras are additive,
  so installing one could never remove httpx2 or switch the backend by itself
  — and the fallback audience already depends on httpx directly.
- **Behavior change: `verify=True` now verifies servers against the OS trust
  store** (Windows CryptoAPI / macOS Security framework / OpenSSL's system CA
  paths on Linux) instead of the certifi bundle, matching httpx2's
  truststore-backed default. Corporate/private CAs distributed through the OS
  now verify out of the box. `verify="system"` remains as a synonym of `True`;
  `verify="certifi"` (added in 0.7) pins the certifi bundle for callers who
  want the old behavior. `SSLKEYLOGFILE` is honored by every context either
  way.
- **Breaking: `from_key_pair`'s `key_password=` is now `password=`**, the same
  keyword every other constructor and `reload()` already used. Rename the 
  argument at call sites: `from_key_pair(cert, key, key_password=...)` becomes
  `from_key_pair(cert, key, password=...)`.
- **Breaking: `CertInfo.not_before` / `not_after` are now `not_valid_before` /
  `not_valid_after`**, matching the client properties of the same name (and
  `cryptography`'s own vocabulary) so the two objects no longer spell the same
  instant two ways. `httpx_pki.testing.make_client_cert()` takes the renamed
  keywords to match, keeping mint-and-read-back symmetric.
- **Breaking: the platform stores' `predicate=` is now `identity=`**, the same
  keyword PKCS#12 and PEM bundles already used, on
  `from_windows_cert_store`, `from_macos_keychain`, `build_windows_ssl_context`,
  `build_macos_ssl_context`, `select_windows_certificate`, and
  `select_macos_certificate`. `identity` is the library's noun everywhere else
  (`P12Identity`, `list_identities()`, `HTTPX_PKI_IDENTITY`), and having one
  spelling for bundles and another for stores meant `currently_valid` had to be
  documented twice in different vocabulary. It now reads
  `identity=currently_valid` everywhere.

  On the stores `identity=` accepts everything a bundle's does *except* an
  integer position: a store has no stable enumeration order, so a position
  would select a different certificate from one run to the next, and it raises
  `TypeError` rather than silently indexing. A string is a name substring or an
  exact SHA-1/SHA-256 fingerprint, matching the bundle rule. `name=` and
  `thumbprint=` are unchanged and remain the unambiguous spellings.
- **New: the `_init_state()` subclass hook** — the documented seam for
  subclasses that take constructor keywords of their own. It runs exactly once
  on every construction path (`__init__`, every `from_*` alternate
  constructor, and unpickling — the latter two never call `__init__`, so
  extending `__init__` alone was not enough), receiving the extra-keyword dict
  before it is forwarded to httpx. Pop your keywords, set your attributes;
  what remains must be valid httpx keywords, so unclaimed arguments still fail
  loudly. State set in the hook survives a pickle round trip automatically,
  and `reload()`/`auto_reload` leave it untouched. See the subclassing section
  of the advanced-usage guide.
- **Bug fix: `warn_if_expires_within` now survives `reload()` and pickling.**
  The window was applied once at construction and then forgotten, so the
  early-expiry warning went permanently quiet after the first rotation — and
  after any pickle round trip — which silently disabled the one signal the
  documented `auto_reload` + `warn_if_expires_within` pairing exists to give a
  long-lived service. It is now retained on the client and re-applied to the
  *freshly loaded* certificate on every reload: a rotation onto another
  short-lived certificate warns again, one onto a healthy certificate goes
  quiet, and a client that never asked for the warning still never gets one.
  The two unconditional warnings (expired, not-yet-valid) already fired on
  reload and are unchanged.
- **Bug fix: `reload(password=...)` no longer silently discards the password**
  for sources that supply their own. A client built by `from_env()` reads
  `{prefix}PASSWORD` itself, and the Windows store and macOS keychain export
  under an internally generated single-use password — for all three the
  argument had nothing to decrypt and was dropped without a word, so removing
  a password from the environment and passing it to `reload()` instead failed
  with a bare "wrong password" from a caller who had supplied one. It now
  raises `TypeError` naming which case you are in and where the password
  belongs, matching how `auto_reload` already rejects a source it cannot
  watch. Reloads that pass no password are unaffected.
- **Breaking: the certificate-source argument is now `source=` everywhere.**
  `PKIClient(...)` / `AsyncPKIClient(...)`, `from_pkcs12`, and
  `build_ssl_context` called it `cert=` while `from_pem`, `list_identities`,
  and `list_pkcs12_identities` already called it `source=`; the parameter is
  typed `CertSource` (a path, `bytes`, or `Path`, and for a bundle it holds a
  key and chain as well as a certificate), so `source` describes it and now
  names it everywhere. Callers passing it positionally — every example in the
  docs — are unaffected.

  This also fixes a real defect: because the constructor's first parameter was
  named `cert`, httpx's deprecated `cert=` keyword bound to it instead of
  reaching the guard, so `PKIClient(bundle, cert=...)` raised a bare
  `_PKIMixin.__init__() got multiple values for argument 'cert'` — leaking a
  private class name and explaining nothing — where every `from_*` constructor
  gave a pointed message. The guard now fires uniformly.

  `from_key_pair(certificate=..., private_key=...)` is unchanged: there
  `certificate` really is the certificate, distinct from the key. So is
  `cert_info(cert_pem)`, which takes PEM bytes rather than a source.
- **truststore is now a direct required dependency** (it also arrives
  transitively with httpx2, but httpx-pki calls it directly). The `[system]`
  and `[httpx2]` extras still install but are no-ops; they are kept so
  invocations from the 0.5–0.7 docs keep working.

## 0.7.0 — 2026-07-31

- **httpx2 support.** httpx development continues under pydantic's stewardship
  as [httpx2](https://github.com/pydantic/httpx2), and httpx-pki now works with
  either package: when httpx2 is importable it is preferred (`PKIClient` /
  `AsyncPKIClient` subclass `httpx2.Client` / `httpx2.AsyncClient`), otherwise
  httpx-pki binds to httpx as before. The new `httpx_pki.HTTP_BACKEND` reports
  which backend was resolved, and the `HTTPX_PKI_BACKEND` environment variable
  (`httpx` or `httpx2`) forces the choice — the escape hatch for environments
  where httpx2 arrives as a transitive dependency but existing code expects the
  httpx base classes. httpx-pki never touches `sys.modules`: your own
  `import httpx` is not redirected. Install the backend with
  `pip install httpx-pki[httpx2]`. (0.8 will swap the roles: httpx2 becomes the
  required dependency, httpx the supported fallback.)
- **`verify="certifi"`** pins the certifi CA bundle by name — today a synonym
  for `verify=True`, everywhere `verify` is accepted (constructors,
  `build_ssl_context`, `HTTPX_PKI_CA=certifi`). It exists because 0.8 will flip
  the `verify=True` default from certifi to the OS trust store to match httpx2;
  callers who want the certifi bundle regardless can start saying so now.
  `verify="system"` is unchanged — and no longer needs the `[system]` extra
  when httpx2 is installed, since truststore is one of httpx2's dependencies.
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
- **Multi-identity PEM bundles** are accepted everywhere PKCS#12 ones are. A
  `.pem` concatenating two key+cert pairs — or one key followed by its old and
  renewed certificates — used to be hard-rejected ("PEM data contains multiple
  private keys"); it now holds selectable identities, chosen with the same
  `identity=` / `key_usage=` / `extended_key_usage=` selectors on
  `PKIClient(...)`, `from_pem`, `from_env`, and `build_ssl_context`. Keys are
  paired to certificates by public key in any block order, the selection is
  recorded so `reload()` / `auto_reload` re-select after a rotation, and the
  other identities' certificates stay out of the presented chain. A key
  matching no certificate is still rejected as an assembly mistake (a
  byte-duplicated key block is not).
- **Behavior change:** a PEM bundle holding one key and two certificates over
  it — what renewing without rekeying produces — previously loaded silently,
  presenting whichever certificate came first and relegating the other
  (typically the renewal) to the chain. It now raises
  `AmbiguousCertificateError` listing both, like its PKCS#12 counterpart;
  `identity=currently_valid` is the usual resolution. Bundles holding a single
  identity — very nearly all of them — are completely unaffected, and bundles
  with several *keys* were never silently mis-loaded (they were refused
  outright).
- **`currently_valid`** answers "just give me the one that works right now" —
  the renewal case, where a bundle or store holds the renewed certificate
  alongside the one it replaces and previously only a hand-written predicate
  could choose. It is accepted anywhere a predicate is:
  `identity=currently_valid` for PKCS#12/PEM bundles,
  `predicate=currently_valid` for the Windows store and macOS keychain, and
  the literal `currently_valid` in `HTTPX_PKI_IDENTITY`. Not-yet-valid and
  expired candidates never match; during a renewal overlap the tie resolves to
  the latest validity window — but only between certificates that are
  otherwise interchangeable (same subject and usages). The halves of a dual
  key pair, whose windows differ only by seconds of mint time, stay ambiguous
  rather than being picked between arbitrarily: freshness cannot tell a
  signing certificate from an encryption one, so combine with `key_usage=`.
  Survives pickling; `reload()` re-applies it, so a rotation that drops in the
  next renewal is picked up without reconfiguration.
- `list_identities()` reports what a certificate source holds — PKCS#12 or
  PEM, detected from the content exactly like the constructors, and never
  returning private keys. `list_pkcs12_identities` remains for callers who
  want only PKCS#12 accepted.
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
- Building a session from the **macOS keychain** no longer emits
  `UserWarning: PKCS#12 bundle could not be parsed as DER, falling back to
  parsing as BER`. The Security framework writes a field whose ASN.1 DEFAULT
  already implies it, which `cryptography` warns about; those bytes are
  generated by the OS and consumed in-process, so there is nothing a caller
  could do differently. The warning still fires for caller-supplied files,
  where re-exporting is a real fix. (Pre-existing — the previous parse warned
  the same way.) `httpx_pki.testing.make_pkcs12(strict_der=False)` reproduces
  the encoding for downstream test suites.
- **Bug fix:** a Windows export refused because the private key is not
  exportable now says so, and says how to fix it. `ctypes.get_last_error()`
  returns a *signed* int, so `NTE_BAD_KEY_STATE` (`0x8009000B`) arrived as
  `-0x7ff6fff5` and never matched the known non-exportable codes — the message
  fell through to the unhelpful "PFX export failed (Windows error
  -0x7ff6fff5)". The codes are compared unsigned now, the set also covers the
  CNG `NTE_NOT_SUPPORTED`, and the message names the re-import flags that mark
  a key exportable (plus the TPM/smart-card case, where no flag will help).
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
