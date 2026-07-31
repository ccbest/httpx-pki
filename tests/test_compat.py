"""Tests for the httpx / httpx2 backend resolution in httpx_pki._compat.

The resolution runs at import time, so each scenario re-executes the module
with ``importlib.reload`` under a controlled environment (the ``_resolution``
context manager), and restores the real resolution afterwards. Only
``_compat``'s own attributes rebind on reload -- the session classes keep the
base they subclassed at package import, which is exactly the process-wide
semantics the module documents.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
import sys
import types
from collections.abc import Iterator

import pytest

import httpx_pki
from httpx_pki import _compat

_UNSET = object()

# The httpx2-only CI leg uninstalls httpx entirely; scenarios that resolve to
# the real httpx package cannot run there.
requires_httpx = pytest.mark.skipif(
    importlib.util.find_spec("httpx") is None, reason="httpx is not installed"
)


@contextlib.contextmanager
def _resolution(
    backend_env: str | None = None, httpx2: object = _UNSET
) -> Iterator[types.ModuleType]:
    """Reload _compat with HTTPX_PKI_BACKEND and/or the httpx2 module forced.

    *httpx2* is planted directly in ``sys.modules``: a stub module simulates an
    installed httpx2 whether or not the real one is present, and ``None`` makes
    ``import httpx2`` raise ImportError (the stdlib treats a None entry as an
    uninstalled module), simulating its absence.
    """
    import os

    old_env = os.environ.pop("HTTPX_PKI_BACKEND", None)
    had_httpx2 = "httpx2" in sys.modules
    old_httpx2 = sys.modules.get("httpx2")
    try:
        if backend_env is not None:
            os.environ["HTTPX_PKI_BACKEND"] = backend_env
        if httpx2 is not _UNSET:
            sys.modules["httpx2"] = httpx2  # type: ignore[assignment]
        yield importlib.reload(_compat)
    finally:
        if old_env is None:
            os.environ.pop("HTTPX_PKI_BACKEND", None)
        else:
            os.environ["HTTPX_PKI_BACKEND"] = old_env
        if httpx2 is not _UNSET:
            if had_httpx2:
                sys.modules["httpx2"] = old_httpx2  # type: ignore[assignment]
            else:
                sys.modules.pop("httpx2", None)
        importlib.reload(_compat)


def test_backend_is_reported() -> None:
    assert httpx_pki.HTTP_BACKEND in ("httpx", "httpx2")
    assert httpx_pki.HTTP_BACKEND == _compat.httpx.__name__


def test_sessions_subclass_resolved_backend() -> None:
    assert issubclass(httpx_pki.PKIClient, _compat.httpx.Client)
    assert issubclass(httpx_pki.AsyncPKIClient, _compat.httpx.AsyncClient)


def test_httpx2_preferred_when_importable() -> None:
    stub = types.ModuleType("httpx2")
    with _resolution(httpx2=stub) as compat:
        assert compat.httpx is stub
        assert compat.HTTP_BACKEND == "httpx2"


@requires_httpx
def test_falls_back_to_httpx_without_httpx2() -> None:
    with _resolution(httpx2=None) as compat:
        assert compat.HTTP_BACKEND == "httpx"


@requires_httpx
def test_env_var_forces_httpx() -> None:
    # Even with httpx2 "installed", the escape hatch keeps the httpx backend.
    with _resolution(backend_env="httpx", httpx2=types.ModuleType("httpx2")) as compat:
        assert compat.HTTP_BACKEND == "httpx"


def test_env_var_forces_httpx2() -> None:
    stub = types.ModuleType("httpx2")
    with _resolution(backend_env="httpx2", httpx2=stub) as compat:
        assert compat.httpx is stub
        assert compat.HTTP_BACKEND == "httpx2"


def test_env_var_forcing_missing_httpx2_raises() -> None:
    with pytest.raises(ImportError):
        with _resolution(backend_env="httpx2", httpx2=None):
            pass  # pragma: no cover -- reload raises before yielding


def test_env_var_rejects_unknown_backend() -> None:
    with pytest.raises(ImportError, match="not a supported backend"):
        with _resolution(backend_env="requests"):
            pass  # pragma: no cover -- reload raises before yielding
