# Security notes

httpx-pki handles client private keys and the passwords protecting them. This
page collects everything about where that material lives and how long it stays
there, so nothing here should be a surprise later.

To report a vulnerability, see
[SECURITY.md](https://github.com/ccbest/httpx-pki/blob/main/SECURITY.md) —
please **do not open a public issue** for anything security-sensitive.

## The key stays in memory

The decrypted private key is never written to a file you can find. On Linux it
is staged in an anonymous `memfd` that ceases to exist when closed; elsewhere it
is a `0600` temporary file that exists only for as long as OpenSSL needs to read
it. See [](how-it-works.md#staging-the-key-never-touches-disk-on-linux).

`repr()` never reveals key material.

## Pickling a client embeds the decrypted key

:::{danger}
To support pickling, a client stores its certificate material and rebuilds the
SSL context on unpickle. **The pickle therefore contains the decrypted private
key in cleartext.**

Treat a pickled client exactly as you would treat the key itself: never write
one to untrusted storage, send it over an untrusted channel, cache it, or log
it.
:::

Two things are *not* carried across, both with a `PicklingWarning`:

- a custom `ssl.SSLContext` passed as `verify=` — the unpickled client falls
  back to default server verification
- an unpicklable certificate source, such as a Windows-store `identity`
  lambda — the unpickled client works but cannot `reload()`

The second is a quiet weakening if you pickled the client precisely to carry a
restrictive trust configuration into a worker process. See
[](../guide/server-trust.md#pickling-drops-a-custom-context).

## Passwords are not retained — with one exception

The source password is discarded after the material is loaded. Reloading a
password-protected source requires passing it again:

```python
client.reload(password="secret")
```

**Enabling `auto_reload` changes that.** An unattended reload has no other way
to decrypt a rotated source, so the password is retained on the client for its
lifetime — and appears in its pickles, which already carry the decrypted key.

That is a deliberate trade, not an oversight. If it is not one you want, reload
manually and pass the password each time. See
[](../guide/expiry-and-rotation.md#passwords-and-unattended-reloads).

## `SSLKEYLOGFILE` decrypts your traffic

Contexts httpx-pki builds honor the standard `SSLKEYLOGFILE` variable, writing
TLS session keys where a capture tool can use them to decrypt the handshake.
That is exactly what it is for when debugging — and exactly why it must never
be set in production. A context you passed in yourself is left untouched.

See [](../guide/server-trust.md#debugging-with-sslkeylogfile).

## Configurations that look safe and are not

Three warnings describe setups that run without error while failing to do what
they appear to do. They are worth reading rather than silencing:

- **`verify=False`** — no server verification, so a client certificate is
  presented to an endpoint whose identity was never established
- **A shared `ssl.SSLContext`** — two clients silently end up presenting the
  same identity, which
  [changes who a request authenticates as](../guide/server-trust.md#sharing-a-context-swaps-the-identity-on-the-wire)
- **A custom `transport=`** — httpx ignores `verify=`, so no client certificate
  is presented at all

Promoting `TLSConfigWarning` to an error in CI catches all three. See
[](../reference/exceptions.md#making-them-fatal).

## What is in scope for a report

Reports are especially welcome for:

- private-key or password material leaking anywhere unintended — disk, logs,
  `repr()`, warnings, exception messages, or living longer than documented
- server-verification bypasses: any way a certificate is accepted that
  `verify=`'s documented semantics say should be rejected
- flaws in the platform-store integrations
- supply-chain issues with the release pipeline — see [](supply-chain.md)

Already-documented behavior, such as a pickled client containing the decrypted
key, is not a vulnerability by itself. Ways to *exploit* such behavior beyond
what is documented are in scope.

Only the **latest release** receives security fixes.

## Next steps

- [](supply-chain.md) — how releases are built and verified
- [](how-it-works.md) — where key material actually goes
