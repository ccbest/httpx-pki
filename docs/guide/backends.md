# Backends: httpx2 and httpx

httpx development continues under pydantic's stewardship as
[httpx2](https://github.com/pydantic/httpx2), which is API-compatible with
httpx. Since 0.8, **httpx2 is httpx-pki's required dependency** and the session
classes subclass `httpx2.Client` / `httpx2.AsyncClient`.

The original httpx remains fully supported as a fallback. Nothing in
httpx-pki's own API changes between the two: the same constructors, the same
keyword arguments, the same behavior. What changes is which library
`PKIClient` inherits from — which matters in exactly one place, covered under
[](#the-isinstance-caveat) below.

## How the backend is chosen

Resolution happens **once, at first import** of `httpx_pki`, and applies to the
whole process. Every internal module binds to the same resolved backend.

1. If `HTTPX_PKI_BACKEND` is set to `httpx` or `httpx2`, that backend is used.
2. Otherwise httpx2 is used when it can be imported.
3. Otherwise httpx-pki falls back to httpx.

So the ordinary install resolves to httpx2, and an environment with httpx and
no httpx2 resolves to httpx — with no configuration in either case. See
[](../install.md#using-httpx-instead-of-httpx2) for how to build the latter.

:::{note}
httpx-pki never touches `sys.modules`. Your own `import httpx` is never
redirected, whichever backend httpx-pki resolved.
:::

## Checking which backend you have

```python
import httpx_pki

print(httpx_pki.HTTP_BACKEND)     # 'httpx2' or 'httpx'
```

Useful in a startup log line or a test assertion when you care which one you
are on.

## Forcing the choice

Set `HTTPX_PKI_BACKEND` before the process starts:

```console
$ HTTPX_PKI_BACKEND=httpx python -m myapp
```

The main reason to reach for this is httpx2 arriving in your environment as
some *other* package's transitive dependency, while your own code still expects
`PKIClient` to subclass the original `httpx.Client`.

Because the variable is read at import time, setting it from inside your
program only works before the first `import httpx_pki` — set it in the
environment, not in `main()`.

Two ways it fails loudly rather than silently:

```text
# HTTPX_PKI_BACKEND=foo
ImportError: HTTPX_PKI_BACKEND='foo' is not a supported backend; set it to
"httpx" or "httpx2", or unset it to prefer httpx2 when installed
```

```text
# HTTPX_PKI_BACKEND=httpx2, but httpx2 is not installed
ModuleNotFoundError: No module named 'httpx2'
```

Forcing a backend never falls back — if you asked for one, you get it or an
error.

(the-isinstance-caveat)=
## The isinstance caveat

This is the one behavior difference worth knowing about. With both packages
installed, httpx-pki resolves to httpx2, so a client is **not** an instance of
the *original* `httpx.Client`:

```python
import httpx, httpx2
from httpx_pki import PKIClient

client = PKIClient("client.p12", password="secret")

isinstance(client, httpx.Client)     # False
isinstance(client, httpx2.Client)    # True
```

Runtime type checks, `@singledispatch` registrations, and Pydantic models
annotated against `httpx.Client` will all be affected. Duck-typed code is not —
the two classes have the same interface.

There are two fixes.

**Force the backend**, if you want to keep using the original httpx:

```console
$ HTTPX_PKI_BACKEND=httpx python -m myapp
```

**Or alias httpx to httpx2 application-wide**, which makes `import httpx`
resolve to httpx2 everywhere and keeps such checks consistent:

```python
import httpx2

httpx2.alias_httpx()      # before anything imports httpx

import httpx
from httpx_pki import PKIClient

httpx is httpx2                      # True
isinstance(client, httpx.Client)     # True
```

Calling `alias_httpx()` is your application's decision — a library should not
make it for you, so httpx-pki does not.

## Type annotations

For type checkers, httpx-pki always annotates against httpx2: it is the
required dependency, so it resolves in every environment that has httpx-pki
installed. httpx is typed API-compatibly, so the annotations stay correct on
the fallback too — mypy will not complain either way.
