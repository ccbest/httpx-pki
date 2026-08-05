# Advanced usage

## Subclassing

`PKIClient` and `AsyncPKIClient` are ordinary httpx clients, so wrapping your
service's conventions around one works exactly as you would expect:

```python
from httpx_pki import PKIClient


class MyServiceSession(PKIClient):
    def __init__(self, p12, **kwargs):
        super().__init__(p12, base_url="https://service.internal", **kwargs)

    def health(self):
        return self.get("/health").json()
```

Everything the base class offers — `cert_info()`, `reload()`, the validity
properties, context-manager support, pickling — is inherited.

### Extra constructor keywords: `_init_state()`

Extending `__init__` as above is fine for baking in fixed httpx settings, but
it is **not** enough when your subclass takes keywords of its own, because two
paths build a session without ever calling `__init__`: the `from_*` alternate
constructors (which return your subclass — `MyServiceSession.from_env()` types
and behaves as a `MyServiceSession`) and unpickling. State set only in
`__init__` would be missing on both.

The supported seam is the `_init_state()` hook. It runs exactly once on
**every** construction path, receiving the constructor's extra keyword dict
before it is forwarded to httpx. Pop your keywords out and set your
attributes; pop with a default so the attributes exist even when the caller
passed nothing:

```python
from httpx_pki import PKIClient


class ProxiedSession(PKIClient):
    def _init_state(self, kwargs):
        self.proxy_url = kwargs.pop("proxy_url", None)
        self.do_not_proxy = kwargs.pop("do_not_proxy", ())


ProxiedSession("client.p12", password="secret", proxy_url="http://proxy:3128")
ProxiedSession.from_env()               # hook still runs; defaults apply
ProxiedSession.from_pkcs12(             # extras pass through any from_*
    "client.p12", "secret", proxy_url="http://proxy:3128"
)
```

Rules of the road:

- **Anything you leave in the dict goes to httpx**, so an unclaimed keyword
  still fails loudly with a `TypeError` — you only bypass httpx's checking for
  the keywords you pop.
- **Pickling is automatic.** The keyword set is snapshotted before the hook
  pops it, and unpickling re-runs the hook with the original keywords, so
  state set here survives a pickle round trip — as long as the values are
  picklable. (Like the rest of the pickle behavior, this restores the session
  *as constructed*; later mutations of those attributes are not captured.)
- **`reload()` and `auto_reload` do not re-run the hook** — rotation swaps
  certificate material in place and leaves your state alone.
- **Do not touch other session state in the hook.** It runs mid-construction,
  before the httpx base class is initialized.
- **Chain in grandchildren** with `super()._init_state(kwargs)`.

## Just the SSL context

If you do not want the client wrapper, `build_ssl_context()` gives you the hard
part on its own: a ready {py:class}`ssl.SSLContext` with the client certificate
mounted, for a plain `httpx.Client`, a transport, or anything else that accepts
a context.

```python
import httpx
from httpx_pki import build_ssl_context

ctx = build_ssl_context("client.p12", password="secret")
client = httpx.Client(verify=ctx)
```

It takes the same `verify=` values and the same identity selectors as the
constructors:

```python
ctx = build_ssl_context(
    "corp.p12",
    password="secret",
    verify="/etc/ssl/ca.pem",
    key_usage="digital_signature",
)
```

`build_windows_ssl_context()` and `build_macos_ssl_context()` are the same seam
for the OS stores, selecting exactly as their `from_*` constructors do:

```python
from httpx_pki import build_windows_ssl_context

ctx = build_windows_ssl_context(identity=lambda c: c.friendly_name == "prod")
```

:::{warning}
A context built this way is yours alone — do not reuse one across several
clients. See
[](server-trust.md#sharing-a-context-swaps-the-identity-on-the-wire).
:::

(custom-transports)=
## Custom transports

httpx-pki works with libraries that supply their own transport — retries,
caching, instrumentation — but there is one **httpx rule** to know first, and it
is not specific to this library:

:::{important}
When you pass a custom `transport=` (or `mounts=`) to an httpx client, httpx
uses that transport **as-is** and ignores the client-level `verify=` / `cert=`.
The TLS configuration — including your client certificate — must live on the
transport itself.
:::

So passing a custom transport to `PKIClient` silently drops the certificate.
httpx-pki notices and warns:

```python
# ❌ The certificate is NOT mounted
from httpx_pki import PKIClient
from httpx_retries import RetryTransport

client = PKIClient("client.p12", password="secret", transport=RetryTransport())
```

```text
TLSConfigWarning: a custom transport=/mounts= makes httpx ignore verify=, so
the client certificate is NOT mounted on this session. Build the context with
build_ssl_context() and put it on the inner transport instead, e.g.
httpx.HTTPTransport(verify=ctx).
```

The request then fails at the handshake, because the server asked for a
certificate that was never presented:

```text
ReadError: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required
```

### Putting the certificate on the inner transport

`build_ssl_context()` is exactly the seam for this. Mount the context on the
**inner** transport that the custom one wraps:

```python
# ✅ The certificate lives on the inner transport
import httpx
from httpx_pki import build_ssl_context
from httpx_retries import RetryTransport, Retry

ctx = build_ssl_context("client.p12", password="secret", verify="/etc/ssl/ca.pem")

transport = RetryTransport(
    transport=httpx.HTTPTransport(verify=ctx),
    retry=Retry(total=5),
)
client = httpx.Client(transport=transport)      # mTLS and retries

resp = client.get("https://mtls.example.com/")
```

### Keeping `PKIClient` as well

If you want your `PKIClient` subclass — its methods, `base_url`,
`cert_info()` — **and** a custom transport, give it the same inner transport.
Its own `verify=` is ignored, since the transport wins, but everything else is
preserved:

```python
ctx = build_ssl_context("client.p12", password="secret")
inner = httpx.HTTPTransport(verify=ctx)

client = PKIClient(
    "client.p12",
    password="secret",
    transport=RetryTransport(transport=inner, retry=Retry(total=5)),
)

client.cert_info()      # still works
client.cn               # still works
```

You will still get the `TLSConfigWarning` — httpx-pki cannot tell that you
mounted the certificate on the inner transport yourself. Silence it once you
have checked the wiring:

```python
warnings.filterwarnings("ignore", category=TLSConfigWarning)
```

The same rule applies to any custom-transport library and to hand-built
`mounts=`: put the TLS configuration on the transport, not on the client.

:::{note}
httpx2 deprecates `verify=<str>` on **its own** clients and transports, so use
`httpx.HTTPTransport(verify=ctx)` with a real context rather than a path.
httpx-pki's own `verify=` is unaffected — it accepts paths and literals and
builds the context for you.
:::

## Rotation without a client

`reload()` belongs to the client, so a bare context does not rotate. Rebuild
the context and remount it, or keep a `PKIClient` for the lifecycle and take
`client.ssl_context` when you need the raw object:

```python
client = PKIClient("/etc/certs/client.pem", auto_reload=True)
ctx = client.ssl_context      # reloads swap the certificate into this object
```

Because reloads mutate the context **in place**, a transport holding that same
object keeps working across a rotation. See [](expiry-and-rotation.md).

## Next steps

- [](server-trust.md) — everything `verify=` accepts
- [](testing.md) — throwaway certificates for exercising all of this
- [](../reference/api.md) — the full API surface
