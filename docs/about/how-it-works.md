# How it works

Python's standard-library `ssl` module cannot load PKCS#12, and cannot load key
material from memory at all — it reads certificate chains from file paths and
nothing else. Everything httpx-pki does follows from working around that one
limitation without ever writing your private key somewhere it can linger.

## The path from bundle to handshake

1. **Parse.** [`cryptography`](https://cryptography.io/en/latest/) extracts the private
   key, the leaf certificate, and any chain certificates from whatever you
   supplied — PKCS#12, PEM, separate files, or an export from an OS store.
2. **Select.** If the source holds several identities, the requested one is
   chosen and the rest are discarded rather than mistaken for chain
   certificates. See [](../guide/choosing-a-certificate.md#why-httpx-pki-parses-these-itself).
3. **Stage.** The material is put somewhere OpenSSL can read it — see below.
4. **Load.** An `ssl.SSLContext` is built, server trust configured per
   `verify=`, and the client certificate loaded into it.
5. **Mount.** That context is handed to httpx as `verify=`, the supported path
   since httpx 0.28.

The client keeps the context, which is what makes
[hot reload](../guide/expiry-and-rotation.md) possible: a rotated certificate is
swapped into the same object in place, so every transport already holding it
picks up the change.

## Staging: the key never touches disk on Linux

Step 3 is the interesting one, because OpenSSL insists on a file path.

**On Linux**, the material is staged in an anonymous in-memory file created
with `memfd_create`, which OpenSSL reads through `/proc/self/fd`. That file has
no name in any directory and ceases to exist the moment it is closed — nothing
to unlink, nothing for a crash to leave behind, nothing for a temp-directory
sweeper to find.

This matters most with `auto_reload`, where the key is re-staged on every
rotation. Over a long-lived process that is a lot of opportunities to leave key
material lying around, and none of them do.

**On other platforms** — or in a rare Linux sandbox where `memfd` or `procfs`
is unavailable — the material lands in a `0600` temporary PEM file just long
enough for OpenSSL to read it, and is then deleted.

## Why PKCS#12 parsing is hand-rolled

`cryptography` returns a single private key from a PKCS#12 file, so a bundle
holding two identities loses one of them and leaves its certificate looking like
a chain certificate. httpx-pki reads the key bags itself and pairs keys to
certificates by public key. The full explanation, with what `cryptography`
actually returns, is in
[](../guide/choosing-a-certificate.md#why-httpx-pki-parses-these-itself).

`cryptography` still does all the cryptographic work — decrypting the file's
encrypted portions, parsing certificates, deserializing keys. What httpx-pki
adds is the structural read that tells one identity from another.

## The modules

For anyone reading the source:

| Module | |
| --- | --- |
| `_compat` | Resolves the httpx2 / httpx backend at import |
| `_material` | The canonical `Material` — key, leaf, chain — and PEM handling |
| `_pkcs12` | Reading identities out of a PKCS#12 bundle |
| `_select` | The identity selectors shared by files and both OS stores |
| `_ssl` | Building the `ssl.SSLContext`, staging, and `verify=` |
| `_mixin` | Everything the client classes share: constructors, reload, validity |
| `_client` | The two public classes, binding the mixin to its httpx base |
| `_winstore` / `_keychain` | The OS certificate stores |
| `_env` | Reading configuration out of the environment |

## Next steps

- [](security.md) — what all this means for your key material
- [](non-goals.md) — what deliberately does not work this way
- [](../guide/index.md) — the user guide
