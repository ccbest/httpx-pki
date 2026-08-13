# Non-goals

httpx-pki is scoped to credentials whose private key **can be exported into
memory**. That is a real boundary, not a roadmap gap, and this page exists so
you can rule the library out quickly.

## Non-exportable keys: PKCS#11, smartcards, HSMs, TPMs

YubiKeys, CAC/PIV cards, Windows keys marked non-exportable, the Secure
Enclave — none of these work, and none can be made to.

These are fundamentally incompatible with Python's `ssl` module, which must
hold the raw key bytes and offers no way to delegate the handshake signature to
external hardware. That is a limitation of the standard library, not of this
library: **no package built on stdlib `ssl` can support them.**

**What to use instead:** an OpenSSL PKCS#11 provider configured outside Python,
so the handshake signature happens in the hardware.

## Java keystores (JKS / JCEKS)

Not supported, because Java itself moved on — PKCS#12 has been the default
keystore format since Java 9.

**What to use instead:** convert once, then use the result directly.

```console
$ keytool -importkeystore -srckeystore client.jks \
      -destkeystore client.p12 -deststoretype PKCS12
```

## Workload-identity protocol clients

No SPIFFE/SPIRE, Vault agent, or cert-manager integration.

All of these already materialize rotating PEM or PKCS#12 files, which
[`auto_reload`](../guide/expiry-and-rotation.md) handles. A protocol
integration would add heavy dependencies for no new capability.

**What to use instead:** point httpx-pki at the file the agent writes.

```python
PKIClient("/var/run/secrets/workload/client.pem", auto_reload=True)
```

## OCSP / CRL revocation checking

Stdlib `ssl` provides nothing to build on, so httpx-pki does not attempt it.

**Partial exception:** `verify=True` delegates verification to the OS on
Windows and macOS, where the platform verifier applies its own revocation
policy. Beyond that, revocation is out of scope. See
[](../guide/server-trust.md).

## Fetching anything over the network

httpx-pki never makes a request of its own. Reading a certificate does not
cause one, and neither does [`explain()`](../guide/inspecting-a-certificate.md)
or [`inventory()`](../guide/taking-inventory.md) — the latter reads the one
directory you name, top level only, and nothing else.

This is a security boundary, not an omission. When a chain is incomplete,
`explain()` reports the URL the certificate names for its issuer — its
Authority Information Access extension — but does not retrieve it. **That URL
comes from the certificate being inspected, which is untrusted input.**

**What to do instead:** fetch it yourself, deliberately, once you have read
where it points.

## Next steps

- [](how-it-works.md) — why these boundaries fall where they do
- [](../guide/index.md) — what httpx-pki *does* do
