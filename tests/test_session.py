"""Unit tests for construction, context-manager use, pickling, and cert info."""

from __future__ import annotations

import pickle
import ssl
import sys
from pathlib import Path

import httpx
import pytest

from httpx_pki import (
    AsyncPKIClient,
    CertificateLoadError,
    CertificateValidityWarning,
    PicklingWarning,
    PKIClient,
    PKIWarning,
    TLSConfigWarning,
    UnsupportedPlatformError,
)
from tests.conftest import CLIENT_CN, P12_PASSWORD, Signed


def test_from_pkcs12_path(client_p12_file: Path) -> None:
    session = PKIClient(client_p12_file, password=P12_PASSWORD)
    assert isinstance(session, httpx.Client)
    assert session._transport is not None
    session.close()


def test_from_pkcs12_bytes(client_p12: bytes) -> None:
    session = PKIClient(client_p12, password=P12_PASSWORD)
    assert session.cert_info().common_name == CLIENT_CN
    session.close()


def test_password_as_bytes(client_p12: bytes) -> None:
    with PKIClient(client_p12, password=P12_PASSWORD.encode()) as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_from_pkcs12_classmethod(client_p12: bytes) -> None:
    with PKIClient.from_pkcs12(client_p12, P12_PASSWORD) as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_from_key_pair(client: Signed, ca: Signed) -> None:
    with PKIClient.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
    ) as session:
        info = session.cert_info()
        assert info.common_name == CLIENT_CN
        assert "test-client.example.com" in info.subject_alt_names


def test_from_key_pair_with_chain(client: Signed, ca: Signed) -> None:
    # chain= takes one source or a list; both produce the same ca_pems.
    with PKIClient.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
        chain=ca.cert_pem,
    ) as session:
        assert session.cn == CLIENT_CN
        assert session._material.ca_pems == [ca.cert_pem]
    with PKIClient.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
        chain=[ca.cert_pem],
    ) as session:
        assert session._material.ca_pems == [ca.cert_pem]


def test_from_key_pair_chain_multi_cert_blob(client: Signed, ca: Signed) -> None:
    # A single chain source holding several PEM certs splits into each cert.
    blob = ca.cert_pem + client.cert_pem
    with PKIClient.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
        chain=blob,
    ) as session:
        assert session._material.ca_pems == [ca.cert_pem, client.cert_pem]


def test_wrong_password_raises(client_p12: bytes) -> None:
    with pytest.raises(CertificateLoadError):
        PKIClient(client_p12, password="wrong")


def test_garbage_bytes_raises() -> None:
    with pytest.raises(CertificateLoadError):
        PKIClient(b"not a pkcs12 blob", password="x")


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(CertificateLoadError):
        PKIClient(tmp_path / "nope.p12", password="x")


def test_bad_source_type_raises() -> None:
    with pytest.raises(TypeError):
        PKIClient(12345)  # type: ignore[arg-type]


def test_context_manager_closes(client_p12: bytes) -> None:
    session = PKIClient(client_p12, password=P12_PASSWORD)
    with session as entered:
        assert entered is session
        assert not session.is_closed
    assert session.is_closed


def test_httpx_kwargs_passthrough(client_p12: bytes) -> None:
    with PKIClient(
        client_p12,
        password=P12_PASSWORD,
        base_url="https://api.example.com",
        headers={"User-Agent": "httpx-pki-test"},
    ) as session:
        assert str(session.base_url) == "https://api.example.com"
        assert session.headers["User-Agent"] == "httpx-pki-test"


def test_cert_info_fields(client: Signed, client_p12: bytes) -> None:
    from cryptography.hazmat.primitives import hashes

    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        info = session.cert_info()
        assert info.common_name == CLIENT_CN
        assert info.distinguished_name == f"CN={CLIENT_CN}"
        assert info.not_after > info.not_before
        assert "test-client.example.com" in info.subject_alt_names
        # Audit fields, against the ground-truth cryptography object.
        assert info.serial_number == client.cert.serial_number
        assert info.issuer_common_name == "httpx-pki test CA"
        assert info.issuer_distinguished_name == client.cert.issuer.rfc4514_string()
        assert (
            info.fingerprint_sha256
            == client.cert.fingerprint(hashes.SHA256()).hex().upper()
        )
        assert (
            info.fingerprint_sha1
            == client.cert.fingerprint(hashes.SHA1()).hex().upper()
        )


def test_cert_info_serial_number_hex() -> None:
    from httpx_pki import cert_info
    from httpx_pki.testing import make_client_cert

    bundle = make_client_cert("self-signed")  # no ca= -> self-signed
    info = cert_info(bundle.cert_pem)
    # Uppercase hex, whole bytes, round-trips to the integer serial.
    assert info.serial_number_hex == info.serial_number_hex.upper()
    assert len(info.serial_number_hex) % 2 == 0
    assert int(info.serial_number_hex, 16) == info.serial_number
    # Self-signed: the issuer is the subject.
    assert info.issuer_common_name == info.common_name
    assert info.issuer_distinguished_name == info.distinguished_name


def test_cert_info_san_types() -> None:
    # SANs of every type are surfaced as strings; dns_names is the DNS subset.
    from httpx_pki import cert_info
    from httpx_pki.testing import make_ca, make_client_cert

    bundle = make_client_cert(
        "multi",
        ca=make_ca(),
        dns_names=["svc.internal", "svc.example.com"],
        ip_addresses=["10.0.0.5"],
    )
    info = cert_info(bundle.cert_pem)
    assert info.dns_names == ["svc.internal", "svc.example.com"]
    assert "svc.internal" in info.subject_alt_names
    assert "10.0.0.5" in info.subject_alt_names  # IP SANs no longer dropped


def test_certificate_property_exposes_extensions(client_p12: bytes) -> None:
    # The certificate property returns a cryptography x509 object, giving access
    # to extensions (like Key Usage) that cert_info does not summarize.
    from cryptography import x509

    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        cert = session.certificate
        assert isinstance(cert, x509.Certificate)
        assert cert.subject.rfc4514_string() == f"CN={CLIENT_CN}"
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature
        assert ku.key_encipherment


def test_ssl_context_is_the_mounted_context(client_p12: bytes) -> None:
    # ssl_context returns the very object mounted on the default transport (not a
    # rebuild), so custom transports can present the same client certificate.
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        ctx = session.ssl_context
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx is session.ssl_context
        # httpx wraps the context in the default transport's SSL config; it's the
        # same object we handed to verify=.
        transport = session._transport_for_url(httpx.URL("https://example.com"))
        assert transport._pool._ssl_context is ctx


def test_cn_and_dn_properties(client_p12: bytes) -> None:
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        assert session.cn == CLIENT_CN
        assert session.dn == f"CN={CLIENT_CN}"


def test_pickle_round_trip(client_p12: bytes) -> None:
    session = PKIClient(
        client_p12, password=P12_PASSWORD, base_url="https://api.example.com"
    )
    restored = pickle.loads(pickle.dumps(session))
    try:
        assert isinstance(restored, PKIClient)
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
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        text = repr(session)
        assert CLIENT_CN in text
        assert P12_PASSWORD not in text
        assert "PRIVATE KEY" not in text
        assert b"PRIVATE KEY".decode() not in text


def test_subclassing(client_p12: bytes) -> None:
    class MySession(PKIClient):
        def __init__(self, p12: bytes, **kwargs: object) -> None:
            super().__init__(p12, password=P12_PASSWORD, **kwargs)

        def greet(self) -> str:
            return "hi"

    with MySession(client_p12) as session:
        assert session.greet() == "hi"
        assert session.cert_info().common_name == CLIENT_CN


def test_subclass_alternate_constructor(client_p12: bytes) -> None:
    class MySession(PKIClient):
        def greet(self) -> str:
            return "hi"

    # The inherited classmethod builds (and types, via its bound TypeVar) the
    # subclass -- mypy sees MySession here, not PKIClient.
    with MySession.from_pkcs12(client_p12, password=P12_PASSWORD) as session:
        assert type(session) is MySession
        assert session.greet() == "hi"


def test_cert_kwarg_rejected(client: Signed) -> None:
    # httpx's deprecated cert= must not slip through **kwargs and collide with
    # the SSL context we mount on verify=.
    with pytest.raises(TypeError, match="cert="):
        PKIClient.from_key_pair(
            certificate=client.cert_pem,
            private_key=client.key_pem,
            cert="ignored.pem",
        )


def test_warning_hierarchy() -> None:
    # The categories are public API: importable from the package root, and all
    # PKIWarning subclasses of UserWarning so generic filters keep matching.
    for category in (CertificateValidityWarning, TLSConfigWarning, PicklingWarning):
        assert issubclass(category, PKIWarning)
    assert issubclass(PKIWarning, UserWarning)


def test_verify_false_warns(client_p12: bytes) -> None:
    with pytest.warns(TLSConfigWarning, match="verify=False"):
        session = PKIClient(client_p12, password=P12_PASSWORD, verify=False)
    session.close()


def test_custom_transport_warns(client_p12: bytes) -> None:
    with pytest.warns(TLSConfigWarning, match="custom transport=/mounts="):
        session = PKIClient(
            client_p12, password=P12_PASSWORD, transport=httpx.HTTPTransport()
        )
    session.close()


def test_custom_mounts_warns(client_p12: bytes) -> None:
    with pytest.warns(TLSConfigWarning, match="custom transport=/mounts="):
        session = PKIClient(
            client_p12,
            password=P12_PASSWORD,
            mounts={"https://": httpx.HTTPTransport()},
        )
    session.close()


def test_http_only_mount_does_not_warn(client_p12: bytes) -> None:
    # An http://-only mount leaves the default https transport (which honors
    # verify=) in place, so the client cert is still mounted -- no warning.
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        session = PKIClient(
            client_p12,
            password=P12_PASSWORD,
            mounts={"http://": httpx.HTTPTransport()},
        )
    session.close()


def test_no_transport_does_not_warn(client_p12: bytes) -> None:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        session = PKIClient(client_p12, password=P12_PASSWORD)
    session.close()


def test_verify_system_pickles_cleanly(client_p12: bytes) -> None:
    # verify="system" is a plain string, so -- unlike a custom SSLContext --
    # it survives pickling without any PicklingWarning fallback.
    pytest.importorskip("truststore")
    import warnings

    session = PKIClient(client_p12, password=P12_PASSWORD, verify="system")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            restored = pickle.loads(pickle.dumps(session))
    finally:
        session.close()
    with restored:
        assert restored._verify_policy == "system"


def test_verify_custom_context_not_pickled(client_p12: bytes) -> None:
    ctx = ssl.create_default_context()
    with pytest.warns(TLSConfigWarning, match="pre-built ssl.SSLContext"):
        session = PKIClient(client_p12, password=P12_PASSWORD, verify=ctx)
    try:
        with pytest.warns(PicklingWarning, match="custom ssl.SSLContext"):
            pickle.dumps(session)
    finally:
        session.close()


async def test_async_from_pkcs12(client_p12: bytes) -> None:
    async with AsyncPKIClient(client_p12, password=P12_PASSWORD) as session:
        assert isinstance(session, httpx.AsyncClient)
        assert session.cert_info().common_name == CLIENT_CN


async def test_async_pickle_round_trip(client_p12: bytes) -> None:
    session = AsyncPKIClient(client_p12, password=P12_PASSWORD)
    restored = pickle.loads(pickle.dumps(session))
    try:
        assert isinstance(restored, AsyncPKIClient)
        assert restored._material == session._material
    finally:
        await session.aclose()
        await restored.aclose()


# -- async alternate constructors (near-copies of the sync ones; exercised
# -- explicitly so an edit landing on only one side is caught) ---------------


async def test_async_from_pkcs12_classmethod(client_p12: bytes) -> None:
    async with AsyncPKIClient.from_pkcs12(
        client_p12, password=P12_PASSWORD
    ) as session:
        assert session.cn == CLIENT_CN


async def test_async_from_pem(client: Signed, ca: Signed) -> None:
    blob = client.key_pem + client.cert_pem + ca.cert_pem
    async with AsyncPKIClient.from_pem(blob) as session:
        assert session.cn == CLIENT_CN
        assert session._material.ca_pems == [ca.cert_pem]


async def test_async_from_key_pair(client: Signed, ca: Signed) -> None:
    async with AsyncPKIClient.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
        chain=ca.cert_pem,
    ) as session:
        assert session.cn == CLIENT_CN
        assert session._material.ca_pems == [ca.cert_pem]


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
async def test_async_from_windows_cert_store_raises_off_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        AsyncPKIClient.from_windows_cert_store(name="anything")
