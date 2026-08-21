# Server trust (`verify`)

Two different certificates are in play on an mTLS connection, and httpx-pki
keeps them separate:

- the **client certificate** you present, which is everything the rest of this
  guide is about
- the **server's** certificate, which `verify` decides how to check

`verify` behaves just like httpx2, plus two literals of httpx-pki's own.

| `verify=` | Meaning |
| --- | --- |
| `True` | **Default.** The operating-system trust store |
| `"system"` | Explicit synonym of `True` |
| `"certifi"` | Pin the certifi CA bundle |
| a path | A CA bundle — PEM, DER, or certs-only PKCS#7 — or a **directory** of them |
| a **list** of any of the above | All of their anchors, [combined](#combining-trust-sources) |
| an `ssl.SSLContext` | Your own — the client certificate is loaded **into it**, [with caveats](#passing-your-own-ssl-context) |
| `False` | No verification, with a warning |

## The default: the OS trust store

Since 0.8, `verify=True` verifies the server against the **operating-system
trust store** — Windows CryptoAPI, the macOS Security framework, or OpenSSL's
system CA paths on Linux — via the same
[truststore](https://truststore.readthedocs.io/en/latest/) machinery httpx2 and pip use.

That is where private CAs distributed through your OS live: group policy, MDM,
or a TLS-inspecting corporate proxy. It is the difference between working and
not for the classic failure where your client certificate loads fine and then:

```text
CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
```

certifi has never heard of your company's internal CA. The OS store has.

`verify="system"` is an explicit synonym, kept from when the OS store was
opt-in. Both spellings survive pickling.

:::{note}
Upgrading from 0.7 or earlier? This is a **behavior change** — `verify=True`
used to mean the certifi bundle. Pass `verify="certifi"` to keep the old
behavior.
:::

## A private CA from a file

When the CA is not in the OS store — the usual case for an internal service
whose CA arrived as an email attachment — point `verify` at it:

```python
PKIClient("client.p12", password="secret", verify="/etc/ssl/custom-ca.pem")
```

The bundle may be PEM **or a certs-only PKCS#7** (DER or PEM), which is handy
when the CA was exported from a Windows CA — a format OpenSSL itself cannot
read as a `cafile`.

### The extension does not matter here either

Just as with [certificate files](loading-certificates.md#the-extension-does-not-matter),
what counts is the bytes, not the name. CA chains turn up as `.crt` at least as
often as `.pem`, and both work — as does a file with several PEM certificates
concatenated, which is the usual shape of a chain:

```python
verify="/etc/pki/internal-ca.crt"       # PEM content, .crt name
verify="/etc/pki/internal-ca.cer"       # PEM content, .cer name
verify="/etc/pki/chain.pem"             # several PEM certs concatenated
verify="/etc/pki/chain.p7b"             # PKCS#7, DER or PEM
```

```python
verify="/etc/pki/internal-ca.der"       # bare DER, since 0.9
verify="/etc/pki/ca.d"                  # a directory of any of the above
```

:::{note}
A **directory** is read by httpx-pki rather than handed to OpenSSL as a
`capath`, which matters twice over. OpenSSL's `capath` requires
`c_rehash`-style hashed filenames, so a directory mounted from a Kubernetes
ConfigMap — holding `internal-ca.crt`, not `a1b2c3d4.0` — would be ignored
entirely. And a `capath` is resolved lazily, so it is invisible to the macOS
and Windows platform verifiers, which would silently drop it while Linux kept
working.

Files in the directory that are not certificates — a `README`, a CRL — are
skipped. One level deep; subdirectories are not searched. A directory with no
certificates at all will produce an error.
:::

:::{tip}
A CA-bundle file literally named `system` or `certifi` would collide with the
literals. Pass it as a `Path` to disambiguate:

```python
PKIClient("client.p12", password="secret", verify=Path("system"))
```
:::

## Seeing what you actually trust

[`explain()`](inspecting-a-certificate.md#what-you-are-trusting-anchor-by-anchor)
lists every anchor a `verify=` resolves to, with its key and expiry, and marks
any that OpenSSL would reject:

```console
$ python -m httpx_pki explain client.p12 --verify internal-ca.pem
```

## Combining trust sources

Naming a CA bundle **replaces** the default trust rather than adding to it —
which is right when you want to talk to exactly one internal service, and
wrong as soon as the same client also talks to anything public.

Pass a list to get both:

```python
PKIClient(
    "client.p12",
    password="secret",
    verify=["system", "/etc/pki/internal-root.pem"],
)
```

That verifies against the OS trust store **and** your private root. Any mix
works — several bundles, a bundle and a directory, `certifi` instead of
`system`:

```python
verify=["system", "/etc/pki/ca.d"]                 # OS store + a directory
verify=["certifi", "/etc/pki/internal-root.pem"]   # public CAs + ours
verify=["/etc/pki/root-a.pem", "/etc/pki/root-b.pem"]   # two private roots
```

A single-element list means exactly what the bare value means, so
`verify=["internal.pem"]` and `verify="internal.pem"` are the same thing — and
a list without `system` or `certifi` in it still replaces the default trust.

`False` and a ready-made `ssl.SSLContext` cannot appear in a list. Neither can
be merged with anything: one turns verification off, and the other is already a
finished decision. Both raise `TypeError`.

:::{note}
On **Windows** the combination is two attempts rather than one: the system
chain engine first, then one restricted to the extra anchors. For the question
"does this server verify?" the answer is the same, but a chain that needs to
mix anchors from both sets can fail on Windows while succeeding on Linux and
macOS. This is truststore's design and nothing httpx-pki can change.
:::

(intermediate-as-anchor)=
## An intermediate — or a leaf — as the anchor

The contexts httpx-pki builds from a bundle or directory verify **partial
chains** — the Python 3.13 default, applied on every version httpx-pki
supports: any certificate in `verify=` can terminate a chain, not only a
self-signed root.

That makes two narrower-than-a-root configurations work as written:

- **An intermediate CA** in `verify=` anchors the servers under *it* — and
  only those. Servers under a sibling intermediate of the same root will not
  verify, and the root's say over the intermediate — revocation, distrust —
  is never consulted. Scoping trust to your issuing CA is a legitimate,
  deliberate setup; trusting the root is the one that keeps working when the
  PKI adds another intermediate.
- **A CA-issued leaf** in `verify=` pins exactly that server certificate: it
  verifies today and stops verifying the day the server renews it.

Neither warns at construction — they work. Both are described in the
[`explain()`](inspecting-a-certificate.md) report (`trust.intermediate`,
`trust.leaf`), which is where their trade-offs are spelled out.

A full-chain export — root *and* intermediates in one bundle — is better than
harmless: the extra intermediates let verification succeed against a server
that forgets to send its own.

This applies to the contexts httpx-pki builds itself. When `"system"` is in
the mix, extra anchors are handed to the platform verifier, whose treatment of
intermediate anchors is its own; a caller-supplied `ssl.SSLContext` keeps
whatever flags it came with.

## Pinning certifi

The certifi bundle — the default through 0.7, and still what the original httpx
uses for `verify=True` — remains available by name, for callers who want
exactly the bundled public CAs regardless of what the OS store holds:

```python
PKIClient("client.p12", password="secret", verify="certifi")
```

This works with every constructor and with `build_ssl_context`. For
`from_env`, `HTTPX_PKI_CA=certifi` (or `system`) selects the corresponding
trust — see [](environment.md#server-trust).

## Passing your own SSL context

You can hand `verify` a ready-made {py:class}`ssl.SSLContext`, but there is a
sharp edge:

:::{warning}
httpx-pki loads the client certificate **into that exact object** — an
`SSLContext` cannot be copied. Sharing one context across several clients means
each load overwrites the previous certificate. You get a warning:

```text
TLSConfigWarning: verify= was given a pre-built ssl.SSLContext; httpx-pki
loads the client certificate into it in place. Do not share this context with
other clients -- use verify=True or a CA-bundle path (letting httpx-pki build
a dedicated context) if it must stay cert-free.
```
:::

Pass `verify=True` or a CA-bundle path instead and httpx-pki builds a dedicated
context per client.

### Sharing a context swaps the identity on the wire

This is not a stylistic warning — the consequence is that a client presents
somebody else's certificate. Building one context and reusing it looks like an
obvious optimization:

```python
import ssl
from httpx_pki import PKIClient

# ❌ One context, shared between two identities
shared = ssl.create_default_context(cafile="/etc/pki/internal-ca.pem")

alice = PKIClient("alice.p12", password="…", verify=shared)
bob = PKIClient("bob.p12", password="…", verify=shared)

alice.get("https://mtls.example.com/")     # presents BOB's certificate
```

Against a real server that reports the certificate it received:

```text
alice-client presents : 39A205B9…   ✓ as expected
bob-client   presents : B0685021…   ✓ as expected
alice-client, again   : B0685021…   ✗ now presenting bob's certificate
```

Constructing `bob` called `load_cert_chain` on the same object, overwriting
alice's certificate. Nothing in `alice` reflects this —
`alice.cert_info()` still reports alice's certificate. Only the server sees the
swap.

The fix is a context per client. Simplest is to not build one at all:

```python
CA = "/etc/pki/internal-ca.pem"

# ✅ httpx-pki builds a dedicated context for each
alice = PKIClient("alice.p12", password="…", verify=CA)
bob = PKIClient("bob.p12", password="…", verify=CA)

# ✅ Or, if you need to configure it yourself, construct one per client
alice = PKIClient(
    "alice.p12",
    password="…",
    verify=ssl.create_default_context(cafile=CA),
)
bob = PKIClient(
    "bob.p12",
    password="…",
    verify=ssl.create_default_context(cafile=CA),
)
```

:::{danger}
**Threads make this a race.** A shared context has no per-client state, so two
threads each constructing a client over it swap identities depending on
ordering — no error, no failed handshake, just requests authenticated as the
wrong principal, intermittently:

```python
# ❌ Racy: every worker loads its certificate into the same object
shared = ssl.create_default_context(cafile=CA)

def fetch(p12: str) -> str:
    client = PKIClient(p12, password="…", verify=shared)
    return client.get("https://mtls.example.com/").text

with ThreadPoolExecutor() as pool:
    list(pool.map(fetch, ["alice.p12", "bob.p12"]))
```

Give every client its own context. Passing `verify=True` or a CA-bundle path is
the simplest way, since httpx-pki then builds a dedicated one per client.
:::

Note that a client itself is fine to use from multiple threads — httpx clients
are thread-safe. The hazard is specifically **sharing one `SSLContext` object
across client constructions**.

### Pickling drops a custom context

Pickling matters at **process** boundaries — `multiprocessing`, a
`ProcessPoolExecutor`, a prefork task queue — not between threads, which share
memory and never pickle.

A custom context does not survive that trip. The unpickled client does not
fail; it quietly falls back to default verification, having warned you:

```text
PicklingWarning: a custom ssl.SSLContext passed as verify= cannot be pickled;
the unpickled client falls back to default server verification.
```

If you pickled the client precisely to carry a restrictive trust configuration
into a worker, that configuration is gone and verification is weaker than you
intended. `verify=True`, `"system"`, `"certifi"`, and CA-bundle paths all
survive pickling — prefer them.

## Disabling verification

```python
PKIClient("client.p12", password="secret", verify=False)
```

```text
TLSConfigWarning: verify=False disables server certificate verification;
connections are vulnerable to man-in-the-middle attacks.
```

Presenting a client certificate to a server you have not authenticated is
worth thinking twice about — it proves who *you* are to an endpoint you have
not established the identity of. Prefer pointing `verify` at the CA bundle,
even in development.

## Debugging with `SSLKEYLOGFILE`

Contexts httpx-pki builds honor the standard `SSLKEYLOGFILE` variable, writing
TLS session keys where a capture tool such as Wireshark can use them to decrypt
the handshake — invaluable when an mTLS failure is not saying much:

```console
$ SSLKEYLOGFILE=/tmp/keys.log python -m myapp
```

A context you passed in yourself is left untouched.

:::{danger}
This decrypts your traffic by design. Never set it in production. See
[](../about/security.md).
:::

## Next steps

- [](expiry-and-rotation.md) — keeping a long-lived client working
- [](advanced.md) — building the SSL context yourself
- [](inspecting-a-certificate.md) — what you are presenting
