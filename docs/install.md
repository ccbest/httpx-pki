# Install

httpx-pki supports **Python 3.10 through 3.14** on Linux, macOS, and Windows.

::::{tab-set}

:::{tab-item} pip
```console
$ pip install httpx-pki
```
:::

:::{tab-item} uv
```console
$ uv add httpx-pki
```
:::

:::{tab-item} Poetry
```console
$ poetry add httpx-pki
```
:::

::::

## Check it worked

```python
import httpx_pki

print(httpx_pki.__version__)      # 0.9.0
print(httpx_pki.HTTP_BACKEND)     # 'httpx2'
```

`HTTP_BACKEND` reports which HTTP library the client classes were built on. On
a normal install it is always `'httpx2'`.

## Using httpx instead of httpx2

httpx-pki still works with the original httpx, and the two are equally
supported — see [](guide/backends.md) for what actually differs. The backend is
chosen at import time by what is installed: **httpx2 absent and `httpx>=0.28`
present means httpx-pki binds to httpx**, with no configuration.

So the goal is an environment with httpx and no httpx2. Install with
`--no-deps` to stop pip pulling httpx2 in, then install the runtime
dependencies yourself:

```console
$ pip install "httpx>=0.28" cryptography truststore
$ pip install --no-deps httpx-pki
```

Confirm the result:

```python
import httpx_pki

print(httpx_pki.HTTP_BACKEND)     # 'httpx'
```

:::{note}
`pip check` will report `httpx-pki requires httpx2, which is not installed`.
That is expected and harmless — httpx2 is declared as a hard requirement so
the ordinary install needs no extras, and `--no-deps` is the documented way
out of it. Nothing at runtime consults the metadata.
:::

### If both httpx and httpx2 are installed

When httpx2 arrives anyway — usually as some other package's transitive
dependency — httpx-pki prefers it. Set `HTTPX_PKI_BACKEND` to force the
choice:

```console
$ HTTPX_PKI_BACKEND=httpx python -m myapp
```

Details in [](guide/backends.md).

## Development install

```console
$ git clone https://github.com/ccbest/httpx-pki
$ cd httpx-pki
$ pip install -e ".[dev]"
$ pytest
```

`[docs]` installs the Sphinx toolchain for building this site.
