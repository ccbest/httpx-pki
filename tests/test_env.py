"""Tests for PKIClient.from_env()."""

from __future__ import annotations

from pathlib import Path

import pytest

from httpx_pki import AsyncPKIClient, CertificateLoadError, PKIClient
from httpx_pki.testing import make_ca, make_client_cert


def test_from_env_pkcs12(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = make_client_cert("envclient", ca=make_ca())
    p12 = tmp_path / "client.p12"
    p12.write_bytes(bundle.pkcs12("pw"))
    monkeypatch.setenv("HTTPX_PKI_CERT", str(p12))
    monkeypatch.setenv("HTTPX_PKI_PASSWORD", "pw")
    with PKIClient.from_env() as session:
        assert session.cn == "envclient"


def test_from_env_separate_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_client_cert("kp", ca=make_ca())
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_bytes(bundle.cert_pem)
    key.write_bytes(bundle.key_pem)
    monkeypatch.setenv("HTTPX_PKI_CERT", str(cert))
    monkeypatch.setenv("HTTPX_PKI_KEY", str(key))
    with PKIClient.from_env() as session:
        assert session.cn == "kp"


def test_from_env_separate_key_with_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = make_ca()
    bundle = make_client_cert("kp-chain", ca=ca)
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    chain = tmp_path / "chain.pem"
    cert.write_bytes(bundle.cert_pem)
    key.write_bytes(bundle.key_pem)
    chain.write_bytes(ca.cert_pem)
    monkeypatch.setenv("HTTPX_PKI_CERT", str(cert))
    monkeypatch.setenv("HTTPX_PKI_KEY", str(key))
    monkeypatch.setenv("HTTPX_PKI_CHAIN", str(chain))
    with PKIClient.from_env() as session:
        assert session._material.ca_pems == [ca.cert_pem]


def test_from_env_cert_bundle_keeps_intermediates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CERT is a leaf-plus-intermediate bundle (intermediate FIRST, so leaf
    # detection by key match is exercised) with a separate KEY.
    ca = make_ca()
    bundle = make_client_cert("kp-bundled", ca=ca)
    cert = tmp_path / "client-fullchain.crt"
    key = tmp_path / "client.key"
    cert.write_bytes(ca.cert_pem + bundle.cert_pem)
    key.write_bytes(bundle.key_pem)
    monkeypatch.setenv("HTTPX_PKI_CERT", str(cert))
    monkeypatch.setenv("HTTPX_PKI_KEY", str(key))
    with PKIClient.from_env() as session:
        assert session.cn == "kp-bundled"
        assert session._material.ca_pems == [ca.cert_pem]


def test_from_env_chain_appended_to_single_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without KEY, CHAIN certs are appended to whatever the PKCS#12 carries.
    ca = make_ca()
    bundle = make_client_cert("p12-chain", ca=ca)
    p12 = tmp_path / "client.p12"
    chain = tmp_path / "chain.pem"
    p12.write_bytes(bundle.pkcs12())
    chain.write_bytes(ca.cert_pem)
    monkeypatch.setenv("HTTPX_PKI_CERT", str(p12))
    monkeypatch.setenv("HTTPX_PKI_CHAIN", str(chain))
    with PKIClient.from_env() as session:
        assert ca.cert_pem in session._material.ca_pems


def test_from_env_custom_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_client_cert("svc", ca=make_ca())
    p12 = tmp_path / "client.p12"
    p12.write_bytes(bundle.pkcs12())
    monkeypatch.setenv("MYAPP_CERT", str(p12))
    with PKIClient.from_env("MYAPP_") as session:
        assert session.cn == "svc"


def test_from_env_missing_cert_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HTTPX_PKI_CERT", raising=False)
    with pytest.raises(CertificateLoadError, match="HTTPX_PKI_CERT"):
        PKIClient.from_env()


def test_from_env_ca_used_for_server_trust(
    mtls_server: object,
    client_p12_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = mtls_server  # MTLSServer(url, ca_file)
    monkeypatch.setenv("HTTPX_PKI_CERT", str(client_p12_file))
    monkeypatch.setenv("HTTPX_PKI_PASSWORD", "secret")
    monkeypatch.setenv("HTTPX_PKI_CA", str(server.ca_file))  # type: ignore[attr-defined]
    with PKIClient.from_env() as session:
        resp = session.get(server.url)  # type: ignore[attr-defined]
        assert resp.text == "mtls-ok"


def test_from_env_explicit_verify_overrides_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_client_cert("c", ca=make_ca())
    p12 = tmp_path / "client.p12"
    p12.write_bytes(bundle.pkcs12())
    monkeypatch.setenv("HTTPX_PKI_CERT", str(p12))
    monkeypatch.setenv("HTTPX_PKI_CA", "/nonexistent/ca.pem")
    # explicit verify wins, so the bogus CA path is never opened
    with PKIClient.from_env(verify=True) as session:
        assert session.cn == "c"


async def test_async_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_client_cert("async-c", ca=make_ca())
    p12 = tmp_path / "client.p12"
    p12.write_bytes(bundle.pkcs12())
    monkeypatch.setenv("HTTPX_PKI_CERT", str(p12))
    async with AsyncPKIClient.from_env() as session:
        assert session.cn == "async-c"
