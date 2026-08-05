# Expiry and rotation

A client presenting an expired certificate is the most common silent mTLS
failure, and certificates keep getting shorter-lived: cert-manager renews a
mounted Secret at two-thirds of its lifetime, Vault PKI issues certificates
measured in hours. A client snapshots its certificate at construction, so a
long-running process needs a plan for what happens next.

httpx-pki gives you three, in increasing order of automation:

- **[Warn early](#warning-before-it-expires)** — know a rollover is coming
- **[Reload](#reloading-a-rotated-certificate)** — pick up the new file,
  manually or automatically
- **[Fail loudly](#strict-validity)** — turn an expired certificate into a
  clear error instead of a handshake failure

## Warning before it expires

Loading an already-expired or not-yet-valid certificate warns immediately:

```text
CertificateValidityWarning: client certificate expired on 2026-08-01;
mTLS handshakes will fail.
```

To hear about one that is merely *about* to roll over, pass
`warn_if_expires_within` — accepted by every constructor, `from_*` included:

```python
from datetime import timedelta
from httpx_pki import PKIClient

client = PKIClient(
    "client.p12",
    password="secret",
    warn_if_expires_within=timedelta(days=14),
)
```

```text
CertificateValidityWarning: client certificate expires on 2026-08-07
(in 4 day(s)).
```

The window is kept on the client, so it keeps applying for the client's
lifetime: every [reload](#reloading-a-rotated-certificate) re-checks the
*freshly loaded* certificate against it, and it survives pickling. A rotation
that lands another short-lived certificate warns again; one that lands a
healthy certificate goes quiet. That is what makes it useful next to
`auto_reload` — see [](#strict-validity).

To check on demand rather than be warned, the validity properties and
`check_validity()` are covered in [](inspecting-a-certificate.md).

## Reloading a rotated certificate

`reload()` re-reads the source — file, `from_env` variables, Windows store, or
macOS keychain — and swaps the fresh certificate into the mounted SSL context
**in place**, so new handshakes present it immediately:

```python
client = PKIClient("/etc/certs/client.pem")

# ... cert-manager rotates /etc/certs/client.pem ...

client.reload()
```

### Automatically

`auto_reload` stats the source files before each request and reloads when they
change, throttled to at most once per second by default:

```python
from datetime import timedelta

PKIClient("/etc/certs/client.pem", auto_reload=True)
PKIClient("/etc/certs/client.pem", auto_reload=timedelta(seconds=30))
```

Nothing else in your code changes — the next request after a rotation simply
presents the new certificate.

### What to expect

**The swap is atomic.** If the rotated file is unreadable or garbage,
`reload()` raises `CertificateLoadError` and the *previous* certificate keeps
serving:

```text
CertificateLoadError: invalid PKCS#12 data or wrong password
```

With `auto_reload` that error surfaces on the triggering request and is retried
on the next one. You never end up with a client that has no certificate.

**Established connections keep their certificate.** TLS has no mid-connection
re-authentication, so only new connections present the rotated certificate.
Existing ones carry on until they close.

**Rotation tooling should replace files atomically** — write-then-rename, which
kubelet and cert-manager already do. A reload that catches a half-written file
raises rather than mounting garbage, but atomic replacement avoids the churn.

:::{note}
`auto_reload` needs a filesystem path to watch. Constructing from in-memory
bytes, the Windows store, or the macOS keychain raises:

```text
TypeError: auto_reload requires a filesystem-path certificate source to watch
```

The stores can still be re-exported with a manual `reload()` — see
[](windows-store.md#reloading) and [](macos-keychain.md#reloading).
:::

### Passwords and unattended reloads

Reloading a password-protected source needs the password again. httpx-pki does
not retain it by default:

```python
client = PKIClient("client.p12", password="secret")

client.reload()                      # CertificateLoadError
client.reload(password="secret")     # works
```

Enabling `auto_reload` **does** retain the password on the client, since an
unattended reload has no other way to decrypt the source:

```python
client = PKIClient("client.p12", password="secret", auto_reload=True)
client.reload()                      # works — password retained
```

That is a deliberate trade: it keeps the password in memory for the client's
lifetime. See [](../about/security.md).

:::{note}
`password=` applies only to sources httpx-pki decrypts on your behalf — a
PKCS#12 or PEM bundle, or a separate key file. Three sources supply their own,
and passing one to them raises rather than being quietly discarded:

```text
TypeError: reload(password=...) does not apply to a from_env() client: the
password is read from HTTPX_PKI_PASSWORD along with the rest of the
configuration. Set that variable instead of passing one here.

TypeError: reload(password=...) does not apply to a client built from the
Windows certificate store: the certificate is exported under an internally
generated single-use password, so there is none to supply. Drop the argument.
```

The macOS keychain says the same as the Windows store.
:::

(strict-validity)=
## Strict validity

`strict_validity=True` runs `check_validity()` before every request, so a
certificate that expired anyway fails clearly *before* the connection is
attempted:

```python
client = PKIClient("client.p12", password="secret", strict_validity=True)
client.get("https://mtls.example.com/")
```

```text
CertificateExpiredError: client certificate expired on 2026-08-01 18:02 UTC
```

Without it you get an opaque OpenSSL handshake error from the far side instead
— which is the failure this whole page exists to prevent.

Combining it with `auto_reload` is the belt-and-braces setup for a long-lived
service: pick up rotations automatically, and fail legibly if one is ever
missed.

```python
PKIClient(
    "/etc/certs/client.pem",
    auto_reload=True,
    strict_validity=True,
    warn_if_expires_within=timedelta(days=7),
)
```

## Silencing the validity warnings

The warnings on this page are all `CertificateValidityWarning`, so a single
filter quiets them without touching anything else httpx-pki reports:

```python
import warnings
from httpx_pki import CertificateValidityWarning

warnings.filterwarnings("ignore", category=CertificateValidityWarning)
```

See [](../reference/exceptions.md) for the other categories and for making
warnings fatal.

## Next steps

- [](inspecting-a-certificate.md) — checking validity on demand
- [](../reference/exceptions.md) — every error and warning, and how to filter them
- [](server-trust.md) — the other half of the connection
- [](advanced.md) — rotation when you are using the SSL context directly
