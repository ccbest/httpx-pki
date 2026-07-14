"""Tests for the public build_ssl_context() helper."""

from __future__ import annotations

import ssl
import sys
from pathlib import Path

import httpx
import pytest

from httpx_pki import (
    CertificateLoadError,
    PKIClient,
    TLSConfigWarning,
    build_ssl_context,
)
from tests.conftest import P12_PASSWORD


def test_build_ssl_context_returns_context(client_p12: bytes) -> None:
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD)
    assert isinstance(ctx, ssl.SSLContext)


def test_passed_context_is_mutated_in_place_with_warning(client_p12: bytes) -> None:
    # A caller-supplied context is reused as-is and gets the client cert loaded
    # into it; we warn so a shared context is not surprising.
    ctx = ssl.create_default_context()
    with pytest.warns(TLSConfigWarning, match="pre-built ssl.SSLContext"):
        out = build_ssl_context(client_p12, password=P12_PASSWORD, verify=ctx)
    assert out is ctx


def test_build_ssl_context_autodetects_pem(client_p12: bytes) -> None:
    # PEM source works too (auto-detected by content).
    from httpx_pki.testing import make_ca, make_client_cert

    bundle = make_client_cert("c", ca=make_ca())
    ctx = build_ssl_context(bundle.pem)
    assert isinstance(ctx, ssl.SSLContext)


def test_sslkeylogfile_enables_key_logging(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Contexts we build come from ssl.create_default_context, which honors
    # SSLKEYLOGFILE; lock that in as documented behavior.
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD)
    assert ctx.keylog_filename == str(keylog)


def test_sslkeylogfile_leaves_caller_context_alone(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A caller-supplied context (built raw, so the stdlib hasn't applied
    # SSLKEYLOGFILE to it either) must not have key logging switched on by us.
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with pytest.warns(TLSConfigWarning, match="pre-built ssl.SSLContext"):
        out = build_ssl_context(client_p12, password=P12_PASSWORD, verify=ctx)
    assert out.keylog_filename is None


def test_build_ssl_context_mounts_on_plain_httpx_client(
    mtls_server: object, client_p12: bytes
) -> None:
    # The whole point: use the context with a vanilla httpx.Client, no PKIClient.
    server = mtls_server  # MTLSServer(url, ca_file)
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(server.ca_file)  # type: ignore[attr-defined]
    )
    with httpx.Client(verify=ctx) as client:
        resp = client.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert resp.text == "mtls-ok"


# -- verify="system" (OS trust store via the optional truststore package) ----


def test_verify_system_returns_truststore_context(client_p12: bytes) -> None:
    truststore = pytest.importorskip("truststore")
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify="system")
    # The truststore context (with the client cert already loaded) is handed
    # back directly; PROTOCOL_TLS_CLIENT keeps hostname checking on.
    assert isinstance(ctx, truststore.SSLContext)
    assert ctx.check_hostname is True


def test_verify_system_without_truststore_raises(
    client_p12: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A None entry in sys.modules makes `import truststore` raise ImportError,
    # simulating an environment without the [system] extra.
    monkeypatch.setitem(sys.modules, "truststore", None)
    with pytest.raises(ImportError, match=r"httpx-pki\[system\]"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify="system")


def test_verify_system_rejects_private_ca_server(
    mtls_server: object, client_p12: bytes
) -> None:
    # The test server's certificate is signed by the throwaway test CA, which
    # no OS trusts -- so a failed handshake proves the OS trust store (not
    # certifi, not the test CA bundle) is really making the decision. The
    # verification-failure message wording varies by platform verifier, so
    # only the error type is asserted.
    pytest.importorskip("truststore")
    server = mtls_server
    with PKIClient(client_p12, password=P12_PASSWORD, verify="system") as session:
        with pytest.raises(httpx.ConnectError):
            session.get(server.url)  # type: ignore[attr-defined]


def test_verify_system_honors_sslkeylogfile(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # create_default_context applies SSLKEYLOGFILE itself; the "system" branch
    # applies it manually so key-logging behavior stays uniform.
    pytest.importorskip("truststore")
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify="system")
    assert ctx.keylog_filename == str(keylog)


def test_verify_path_named_system_is_a_file(client_p12: bytes) -> None:
    # The literal str "system" selects the OS store; a Path("system") is the
    # escape hatch for a CA bundle actually named "system" (here: missing).
    with pytest.raises(CertificateLoadError, match="could not load CA bundle"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=Path("system"))
