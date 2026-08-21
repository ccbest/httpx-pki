# Troubleshooting

Find your error in the table, follow the link, apply the fix. If you have no
error at all — the request succeeds and the server still treats you as the wrong
principal — that is the [last group](#it-connects-as-the-wrong-identity).

:::{tip}
**Start here if you were handed certificates and do not know what is in them.**
Two commands, depending on how much you have narrowed it down.

A whole folder, and you do not know which file is which — `inventory()` says
what each file is, which files pair into an identity, and how to load each
pairing:

```console
$ python -m httpx_pki inventory ./corp-export
```

One source, and you want to know what would stop it working — `explain()` lays
out what it holds, what it would present, what it would trust, and what is
wrong with it, without building a client and without needing the load to
succeed first:

```console
$ python -m httpx_pki explain corp.p12
```

```python
print(httpx_pki.inventory("./corp-export"))
print(httpx_pki.explain("corp.p12", password="secret"))
print(client.explain())          # when you already have a session
```

See [](guide/taking-inventory.md) and
[](guide/inspecting-a-certificate.md#explaining-a-whole-configuration).
:::

## Find your error

Errors from httpx-pki name the problem and usually the fix. Errors from OpenSSL,
which is everything under *at request time*, do not — your certificate loaded
fine and something about the connection was rejected.

Rows are keyed on the **distinctive phrase**, not the whole message, since most
of these carry a filename or a count as well. Match on that.

| What you see | What it means | Fix |
| --- | --- | --- |
| **At construction** | | |
| `invalid PKCS#12 data or wrong password` | Usually the password. httpx-pki says this only after ruling out the cert-only cases below | Check the password, then [](guide/loading-certificates.md) |
| `could not parse private key (wrong password?)` | The key is encrypted and `password=` was wrong or missing | [](guide/loading-certificates.md) |
| `…no private key…` (four wordings) | Your source has certificates but no key — you are holding half a credential | [](#no-private-key) |
| `…no certificate…` (two wordings) | The reverse: a key with no certificate | [](#no-certificate) |
| `…does not match…` (two wordings) | The cert and key you paired are not a pair | [](#the-key-and-certificate-do-not-match) |
| `AmbiguousCertificateError` | Several credentials matched and httpx-pki will not guess. The message lists them | [](guide/choosing-a-certificate.md) |
| `CertificateNotFoundError` | Your selector matched nothing. The message lists what was there to match | [](guide/choosing-a-certificate.md) |
| `could not load CA bundle` | A `verify=` entry that is not PEM, DER, or PKCS#7 | [](guide/server-trust.md#the-extension-does-not-matter-here-either) |
| `CA directory … contains no certificates` | A `verify=` directory holding nothing loadable | [](guide/server-trust.md#the-extension-does-not-matter-here-either) |
| `HTTPX_PKI_CERT is not set` | `from_env()` with nothing to read | [](guide/environment.md) |
| `only available on Windows` / `on macOS` | A platform constructor called off-platform | [](guide/windows-store.md) |
| **At request time** | | |
| `CERTIFICATE_VERIFY_FAILED` | **You** do not trust the **server's** certificate. Nothing to do with your client certificate | [](#you-do-not-trust-the-server) |
| `TLSV1_ALERT_UNKNOWN_CA` | The **server** does not trust **yours** — most often because you are not sending the intermediates | [](#the-server-does-not-trust-you) |
| `TLSV13_ALERT_CERTIFICATE_REQUIRED` | Your certificate never reached the wire | [](#the-server-wanted-a-certificate-and-did-not-get-one) |
| `SSLV3_ALERT_HANDSHAKE_FAILURE` | The same, on a pre-TLS 1.3 connection | [](#the-server-wanted-a-certificate-and-did-not-get-one) |
| `EOF occurred in violation of protocol` | The handshake succeeded and the connection then died — on a route-scoped mTLS server, the sign that it asked for your certificate too late to be answered | [](#the-server-asked-after-the-handshake) |
| `SSLV3_ALERT_CERTIFICATE_EXPIRED` | Expired, and the server checked | [](#your-certificate-has-expired) |
| **No error at all** | | |
| The server authenticates you as the wrong principal | A shared `ssl.SSLContext`, the wrong half of a dual key pair, or a rotation you did not pick up | [](#it-connects-as-the-wrong-identity) |
| `reach the issuer` | None of your chain certificates connect your certificate to its issuer | [](#the-server-does-not-trust-you) |
| `none of the … trust anchors can be used` | Every `verify=` anchor is expired or otherwise unusable | [](guide/server-trust.md#combining-trust-sources) |

:::{tip}
Not finding your message? [](reference/exceptions.md) has the full set with each
message spelled out — including the **warnings**, which fire on setups that run
without any error at all but do not do what they look like they do.
:::

## Do you have both halves?

mTLS needs a **certificate and the private key that matches it**. The
certificate is public and states who you are; the private key is what proves you
are entitled to it. The handshake needs both, so any source you hand to
`PKIClient` has to carry both.

This is the most common thing to get wrong, because several of the file formats
a PKI team hands out contain no private key at all:

| Format | Private key inside? |
| --- | --- |
| PKCS#12 — `.p12`, `.pfx` | Usually — carrying both is what the format is for |
| PEM — `.pem` | Maybe — it holds whatever blocks were concatenated into it |
| A single certificate — `.crt`, `.cer` | **No.** A certificate is only ever the public half |
| PKCS#7 — `.p7b`, `.p7c` | **No.** Certificates only; the format cannot hold a key |
| A key file — `.key` | The key, but no certificate to go with it |

Those names are conventions, not guarantees — as everywhere else in httpx-pki,
[what counts is the bytes](guide/loading-certificates.md#the-extension-does-not-matter).

If both halves are somewhere in one folder,
[`inventory()`](guide/taking-inventory.md) reads all of it and says which two
files pair up:

```console
$ python -m httpx_pki inventory ./corp-export
```

And if you have a single file in hand, try to load it: httpx-pki inspects the
content when a load fails and tells you what it actually found.

### "…no private key…"

Four messages say this, depending on what httpx-pki found when it looked:

```text
CertificateLoadError: no private key found in PEM data

CertificateLoadError: PKCS#12 data contains no private key

CertificateLoadError: the data is a DER certificate with no private key;
pass it to from_key_pair(certificate=..., private_key=...)

CertificateLoadError: the data is a certificate-only PKCS#7 bundle with no
private key; use it as chain= in from_key_pair or as a verify= CA bundle
```

***There are three ways to land here, and they need different responses.***

**1. The key is in a separate file.** The normal shape outside Windows. Use
`from_key_pair` rather than the single-source constructor:

```python
PKIClient.from_key_pair("client.crt", "client.key")
```

Not sure which file the key is in — or whether it is even the right key?
`python -m httpx_pki inventory` matches keys to certificates by public key and
prints the `from_key_pair` call for each pair it finds.

**2. You were sent the chain, not your credential.** A `.p7b` from a Windows CA is
frequently the *issuing chain* — useful as `chain=` when you present your
certificate, or as a `verify=` CA bundle for checking the server, but never a
credential on its own. See [](guide/server-trust.md).

**3. You genuinely do not have the key.** If you were only ever sent a certificate,
mTLS is not possible with it and no library can change that — the key was either
kept by whoever generated the request, or never left the machine that made it.
Go back to your PKI team and ask for a PKCS#12 export, or issue a fresh
certificate from a CSR you generate yourself, so you hold the key from the
start.

### "…no certificate…"

The reverse pair reads the same way:

```text
CertificateLoadError: no certificate found in PEM data
CertificateLoadError: PKCS#12 data contains no certificate
```

A key with no certificate is equally unusable — you have the proof but not the
claim. The fix is the same: find the other half — and
[](guide/taking-inventory.md) is how to find it, if it is anywhere in the same
folder.

## The key and certificate do not match

Two wordings, depending on whether you paired two files or handed over one
bundle that was assembled wrongly:

```text
CertificateLoadError: private key does not match certificate
(their public keys differ)

CertificateLoadError: private key does not match any certificate
in the PEM data
```

httpx-pki compares the public key inside the certificate against the public half
of the private key, and refuses the pair when they differ. Usually one of the
two files is from a different issuance — an older certificate, or the key left
over from a CSR that was superseded.

Catching it here is deliberate. Left alone it surfaces much later as an
unexplained handshake rejection, with nothing pointing at the file pair.

To find the pairing that *does* work, run
[`inventory()`](guide/taking-inventory.md) over the folder both files came
from. It matches every key against every certificate by public key, so a
superseded key and the certificate it no longer belongs to are reported apart —
each as unpaired, alongside whatever they each really go with.

## It fails when you make a request

The certificate loaded, so the problem is the connection. httpx surfaces these
as `ConnectError` or — for alerts that arrive after the handshake appears to
finish, which is normal in TLS 1.3 — as `ReadError`.

The first question is **which side is complaining**, because the two look
similar and have opposite fixes.

### You do not trust the server

```text
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
unable to get local issuer certificate
```

Your side rejected *their* certificate: nothing in your trust store issued it.
Nothing to do with your client certificate. Almost always an internal service
whose CA is not public.

Point `verify` at the CA that issued the server's certificate:

```python
PKIClient("client.p12", password="secret", verify="/etc/pki/internal-ca.pem")
```

If the CA is distributed through your OS by group policy or MDM, the default
`verify=True` already reads the OS trust store and should find it. Full detail
in [](guide/server-trust.md).

### The server does not trust you

```text
[SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca
```

The mirror image: the server could not build a path from your certificate to a
CA it trusts. Two causes, in order of likelihood.

**You are not sending the intermediates.** Your certificate is almost never
signed by the root directly — there is at least one intermediate CA in between.
The server needs that intermediate to connect your certificate to the root it
trusts, and by convention the *client* supplies it. A PKCS#12 bundle normally
carries the chain and httpx-pki presents it automatically, but a bare
`client.crt` and `client.key` carry nothing, so you must supply it:

```python
PKIClient.from_key_pair("client.crt", "client.key", chain="intermediate.crt")
```

`chain=` also takes a list, or a `.p7b`, which is how Windows CAs usually export
one:

```python
PKIClient.from_key_pair("client.crt", "client.key", chain=["intermediate.crt", "sub-ca.crt"])
PKIClient.from_key_pair("client.crt", "client.key", chain="chain.p7b")
```

Send every intermediate between your certificate and the root. The root itself
is not normally needed — the server already has it, which is the whole point of
trusting it.

To see what you are currently presenting, `cert_info()` describes the leaf; see
[](guide/inspecting-a-certificate.md).

**The server really does not trust your CA.** If the chain is complete, your
certificate is from an issuer the server was never configured to accept. That is
a server-side change, not a client one.

### The server wanted a certificate and did not get one

```text
[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required
[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure
```

Your certificate was never put on the wire. If you passed a custom `transport=`
or `mounts=`, that is the cause — httpx uses the transport as-is and ignores the
client-level `verify=`, so the certificate is silently dropped. httpx-pki warns
about this at construction:

```text
TLSConfigWarning: a custom transport=/mounts= makes httpx ignore verify=, so
the client certificate is NOT mounted on this session.
```

The fix is to mount the context on the inner transport — see
[](guide/advanced.md#custom-transports).

If you passed neither, and the server requires mTLS on only *some* of its
routes, see the next section instead.

### The server asked after the handshake

```text
[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required
SSLEOFError: EOF occurred in violation of protocol
```

**_Quick fix: upgrade to httpx-pki 0.9 or later._**

Distinctive shape: the TLS handshake **succeeds**, and the connection dies
afterwards. `cert_info()` shows exactly the certificate you expect, and the same
client works against a server that requires mTLS on every route.

This is a server that wants a client certificate for certain endpoints only — it 
cannot know which you asked for until it has read the request,
which is after the handshake. Through TLS 1.2 it got your certificate by
renegotiating. TLS 1.3 removed renegotiation and replaced it, for this case,
with *post-handshake authentication* ([RFC 8446 §4.6.2][rfc8446-pha]): the
server sends a bare `CertificateRequest` once the handshake is done.

A server may only ask a client that advertised willingness in its ClientHello —
the very first bytes of the connection, long before the route is known. Every
context httpx-pki builds advertises it, so **this should not happen on
httpx-pki 0.9 or later.** If you see it:

- **On httpx-pki 0.8 or earlier**, this is the cause. Upgrade.
- **On a context you built yourself** and passed to a plain `httpx.Client`, set
  the flag — this is the one thing `build_ssl_context()` does that a hand-rolled
  `ssl.create_default_context()` does not:

  ```python
  ctx = ssl.create_default_context()
  ctx.load_cert_chain("client.pem")
  ctx.post_handshake_auth = True      # or just use build_ssl_context()
  ```

- **With a custom `transport=` or `mounts=`**, the certificate never reached the
  wire at all — see the section above.

Servers that behave this way include ASP.NET Core Kestrel with
`ClientCertificateMode.DelayCertificate`, Apache `mod_ssl` with
`SSLVerifyClient` inside a `<Location>`, and IIS with per-path *negotiate client
certificate*.

[rfc8446-pha]: https://www.rfc-editor.org/rfc/rfc8446#section-4.6.2

### Your certificate has expired

```text
[SSL: SSLV3_ALERT_CERTIFICATE_EXPIRED] sslv3 alert certificate expired
```

The server checked the validity window and rejected it. httpx-pki warns about
this at load time too, so it may already be in your logs:

```text
CertificateValidityWarning: client certificate expired on 2026-08-01;
mTLS handshakes will fail.
```

To turn expiry into a clear error before the connection is attempted rather than
an alert from the far side, use `strict_validity=True`. To pick up rotations
automatically, use `auto_reload`. Both are in
[](guide/expiry-and-rotation.md).

## It connects as the wrong identity

The awkward category: everything succeeds, and the server authenticates you as
somebody or something else.

**You picked the wrong half of a dual key pair.** A bundle holding a signing and
an encryption certificate needs a selector, and for mTLS you want the signing
half — an encryption-only certificate cannot sign the handshake, so it typically
fails outright rather than misauthenticating:

```python
PKIClient("corp.p12", password="secret", key_usage="digital_signature")
```

Background in [](guide/choosing-a-certificate.md#why-one-file-holds-two-certificates).

**You shared one `ssl.SSLContext` between clients.** This one genuinely does
misauthenticate, silently: constructing the second client overwrites the first
client's certificate in the shared object, and only the server sees the swap.
`cert_info()` on the first client still reports what you expect. Worked through
in [](guide/server-trust.md#sharing-a-context-swaps-the-identity-on-the-wire).

**Your certificate rotated underneath you.** An established connection keeps the
certificate it handshook with, so a reload only affects new connections. See
[](guide/expiry-and-rotation.md#what-to-expect).

## Still stuck

Make the warnings loud. Most silent-failure modes warn at construction, and
Python shows a given warning [only once per process](reference/exceptions.md#why-you-may-only-see-a-warning-once)
by default:

```console
$ python -W always myapp.py
```

Turning `TLSConfigWarning` into an error is the sharpest version of this — every
message under it describes a client that is not doing what it looks like it is
doing:

```python
import warnings
from httpx_pki import TLSConfigWarning

warnings.filterwarnings("error", category=TLSConfigWarning)
```

Check what you are actually presenting:

```python
client = PKIClient("client.p12", password="secret")
print(client.cert_info())
```

And if the handshake still says nothing useful, `SSLKEYLOGFILE` lets Wireshark
decrypt it — see [](guide/server-trust.md#debugging-with-sslkeylogfile), and
note the warning there about never setting it in production.

## Next steps

- [](reference/exceptions.md) — every error and warning, and how to filter them
- [](guide/loading-certificates.md) — every source format in full
- [](guide/server-trust.md) — everything `verify=` accepts
