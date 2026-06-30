"""Unit tests for construction, context-manager use, pickling, and cert info."""

from __future__ import annotations

import pickle
import ssl
from pathlib import Path

import httpx
import pytest

from httpx_pki import AsyncPKCSession, CertificateLoadError, PKCSession
from tests.conftest import CLIENT_CN, P12_PASSWORD, Signed


def test_from_pkcs12_path(client_p12_file: Path) -> None:
    session = PKCSession(client_p12_file, password=P12_PASSWORD)
    assert isinstance(session, httpx.Client)
    assert session._transport is not None
    session.close()


def test_from_pkcs12_bytes(client_p12: bytes) -> None:
    session = PKCSession(client_p12, password=P12_PASSWORD)
    assert session.cert_info().common_name == CLIENT_CN
    session.close()


def test_password_as_bytes(client_p12: bytes) -> None:
    with PKCSession(client_p12, password=P12_PASSWORD.encode()) as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_from_pkcs12_classmethod(client_p12: bytes) -> None:
    with PKCSession.from_pkcs12(client_p12, P12_PASSWORD) as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_from_key_pair(client: Signed, ca: Signed) -> None:
    with PKCSession.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
        ca=ca.cert_pem,
    ) as session:
        info = session.cert_info()
        assert info.common_name == CLIENT_CN
        assert "test-client.example.com" in info.subject_alt_names


def test_wrong_password_raises(client_p12: bytes) -> None:
    with pytest.raises(CertificateLoadError):
        PKCSession(client_p12, password="wrong")


def test_garbage_bytes_raises() -> None:
    with pytest.raises(CertificateLoadError):
        PKCSession(b"not a pkcs12 blob", password="x")


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(CertificateLoadError):
        PKCSession(tmp_path / "nope.p12", password="x")


def test_bad_source_type_raises() -> None:
    with pytest.raises(TypeError):
        PKCSession(12345)  # type: ignore[arg-type]


def test_context_manager_closes(client_p12: bytes) -> None:
    session = PKCSession(client_p12, password=P12_PASSWORD)
    with session as entered:
        assert entered is session
        assert not session.is_closed
    assert session.is_closed


def test_httpx_kwargs_passthrough(client_p12: bytes) -> None:
    with PKCSession(
        client_p12,
        password=P12_PASSWORD,
        base_url="https://api.example.com",
        headers={"User-Agent": "httpx-pki-test"},
    ) as session:
        assert str(session.base_url) == "https://api.example.com"
        assert session.headers["User-Agent"] == "httpx-pki-test"


def test_cert_info_fields(client_p12: bytes) -> None:
    with PKCSession(client_p12, password=P12_PASSWORD) as session:
        info = session.cert_info()
        assert info.common_name == CLIENT_CN
        assert info.distinguished_name == f"CN={CLIENT_CN}"
        assert info.not_after > info.not_before
        assert "test-client.example.com" in info.subject_alt_names


def test_cn_and_dn_properties(client_p12: bytes) -> None:
    with PKCSession(client_p12, password=P12_PASSWORD) as session:
        assert session.CN == CLIENT_CN
        assert session.DN == f"CN={CLIENT_CN}"


def test_pickle_round_trip(client_p12: bytes) -> None:
    session = PKCSession(
        client_p12, password=P12_PASSWORD, base_url="https://api.example.com"
    )
    restored = pickle.loads(pickle.dumps(session))
    try:
        assert isinstance(restored, PKCSession)
        # canonical material is byte-for-byte preserved
        assert restored._material == session._material
        # a fresh, distinct live SSL context was rebuilt
        assert isinstance(restored._httpx_kwargs, dict)
        assert str(restored.base_url) == "https://api.example.com"
        assert restored.cert_info().common_name == CLIENT_CN
    finally:
        session.close()
        restored.close()


def test_repr_hides_secrets(client_p12: bytes) -> None:
    with PKCSession(client_p12, password=P12_PASSWORD) as session:
        text = repr(session)
        assert CLIENT_CN in text
        assert P12_PASSWORD not in text
        assert "PRIVATE KEY" not in text
        assert b"PRIVATE KEY".decode() not in text


def test_subclassing(client_p12: bytes) -> None:
    class MySession(PKCSession):
        def __init__(self, p12: bytes, **kwargs: object) -> None:
            super().__init__(p12, password=P12_PASSWORD, **kwargs)

        def greet(self) -> str:
            return "hi"

    with MySession(client_p12) as session:
        assert session.greet() == "hi"
        assert session.cert_info().common_name == CLIENT_CN


def test_verify_false_warns(client_p12: bytes) -> None:
    with pytest.warns(UserWarning, match="verify=False"):
        session = PKCSession(client_p12, password=P12_PASSWORD, verify=False)
    session.close()


def test_verify_custom_context_not_pickled(client_p12: bytes) -> None:
    ctx = ssl.create_default_context()
    session = PKCSession(client_p12, password=P12_PASSWORD, verify=ctx)
    try:
        with pytest.warns(UserWarning, match="custom ssl.SSLContext"):
            pickle.dumps(session)
    finally:
        session.close()


async def test_async_from_pkcs12(client_p12: bytes) -> None:
    async with AsyncPKCSession(client_p12, password=P12_PASSWORD) as session:
        assert isinstance(session, httpx.AsyncClient)
        assert session.cert_info().common_name == CLIENT_CN


async def test_async_pickle_round_trip(client_p12: bytes) -> None:
    session = AsyncPKCSession(client_p12, password=P12_PASSWORD)
    restored = pickle.loads(pickle.dumps(session))
    try:
        assert isinstance(restored, AsyncPKCSession)
        assert restored._material == session._material
    finally:
        await session.aclose()
        await restored.aclose()
