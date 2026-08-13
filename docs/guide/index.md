# User guide

Everything httpx-pki does, grouped by the question you arrived with. If you
just want a working request, start with the [quickstart](../quickstart.md)
instead — and if you have an error in hand,
[troubleshooting](../troubleshooting.md) is organized by symptom.

## Getting a certificate loaded

Where your credential lives, and how to point httpx-pki at it.

- [](taking-inventory.md) — before you know which file to point at: what a
  folder of exports holds, which files pair up, and how to load each pairing
- [](loading-certificates.md) — PKCS#12, PEM, separate key and certificate,
  PKCS#7 chains, and why the file extension never matters
- [](windows-store.md) — pulling an exportable certificate out of the Windows
  certificate store
- [](macos-keychain.md) — the same on macOS, including the consent prompt that
  catches out headless deployments
- [](environment.md) — configuring the whole thing from `HTTPX_PKI_*`
  variables, for containers and 12-factor deployments

## When one source holds several certificates

Common wherever a CA archives the encryption key but not the signing key, and
after any renewal that leaves the old certificate in place.

- [](choosing-a-certificate.md) — key usage, extended key usage, name,
  fingerprint, position, and arbitrary predicates
- [](inspecting-a-certificate.md) — what a loaded certificate says about
  itself: subject, issuer, validity, fingerprints, usages

## Getting the connection right

- [](server-trust.md) — `verify=`, the OS trust store, private CAs, and the
  ways a TLS setup can look fine while doing nothing
- [](backends.md) — httpx2, httpx, how the binding is resolved, and the one
  behavior difference between them

## Keeping it working

- [](expiry-and-rotation.md) — warn early, reload automatically, or fail
  loudly when a certificate rolls over
- [](../reference/exceptions.md) — every error and warning httpx-pki produces,
  what each message means, and how to filter them

## Going further

- [](advanced.md) — subclassing, using the bare `ssl.SSLContext`, and the
  custom-transport rule that silently drops your certificate
- [](testing.md) — minting throwaway certificates, including multi-identity
  bundles nothing else readily produces

---

Looking for a specific class or function? The
[API reference](../reference/api.md) is generated from the source.
