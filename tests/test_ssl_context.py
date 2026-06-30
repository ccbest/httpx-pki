"""Tests for the public build_ssl_context() helper."""

from __future__ import annotations

import ssl

import httpx
import pytest

from httpx_pki import build_ssl_context
from tests.conftest import P12_PASSWORD


def test_build_ssl_context_returns_context(client_p12: bytes) -> None:
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD)
    assert isinstance(ctx, ssl.SSLContext)


def test_passed_context_is_mutated_in_place_with_warning(client_p12: bytes) -> None:
    # A caller-supplied context is reused as-is and gets the client cert loaded
    # into it; we warn so a shared context is not surprising.
    ctx = ssl.create_default_context()
    with pytest.warns(UserWarning, match="pre-built ssl.SSLContext"):
        out = build_ssl_context(client_p12, password=P12_PASSWORD, verify=ctx)
    assert out is ctx


def test_build_ssl_context_autodetects_pem(client_p12: bytes) -> None:
    # PEM source works too (auto-detected by content).
    from httpx_pki.testing import make_ca, make_client_cert

    bundle = make_client_cert("c", ca=make_ca())
    ctx = build_ssl_context(bundle.pem)
    assert isinstance(ctx, ssl.SSLContext)


def test_build_ssl_context_mounts_on_plain_httpx_client(
    mtls_server: object, client_p12: bytes
) -> None:
    # The whole point: use the context with a vanilla httpx.Client, no PKCSession.
    server = mtls_server  # MTLSServer(url, ca_file)
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(server.ca_file)  # type: ignore[attr-defined]
    )
    with httpx.Client(verify=ctx) as client:
        resp = client.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert resp.text == "mtls-ok"
