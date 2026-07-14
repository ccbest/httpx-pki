"""Tests for input-format handling: PKCS#12 vs PEM, auto-detection, errors."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from httpx_pki import CertificateLoadError, PKIClient
from tests.conftest import CLIENT_CN, P12_PASSWORD, Signed


def _pem_bundle(client: Signed, ca: Signed) -> bytes:
    # key + leaf cert + CA cert concatenated, as is common for a .pem file.
    return client.key_pem + client.cert_pem + ca.cert_pem


def test_pem_bundle_autodetected(client: Signed, ca: Signed) -> None:
    with PKIClient(_pem_bundle(client, ca)) as session:
        info = session.cert_info()
        assert info.common_name == CLIENT_CN


def test_from_pem_explicit(client: Signed, ca: Signed) -> None:
    with PKIClient.from_pem(_pem_bundle(client, ca)) as session:
        assert session.cn == CLIENT_CN


def test_pem_bundle_order_independent(client: Signed, ca: Signed) -> None:
    # cert before key should parse the same.
    blob = client.cert_pem + ca.cert_pem + client.key_pem
    with PKIClient.from_pem(blob) as session:
        assert session.cn == CLIENT_CN


def test_pem_bundle_leaf_after_ca(client: Signed, ca: Signed) -> None:
    # The CA cert is listed before the leaf: the leaf is identified by matching
    # the key, not by position, so this must load (and keep the CA as chain).
    blob = client.key_pem + ca.cert_pem + client.cert_pem
    with PKIClient.from_pem(blob) as session:
        assert session.cn == CLIENT_CN
        assert session._material.ca_pems == [ca.cert_pem]


def test_encrypted_pem_key_with_password(client: Signed, ca: Signed) -> None:
    encrypted_key = client.key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"keypw"),
    )
    blob = encrypted_key + client.cert_pem
    with PKIClient.from_pem(blob, password="keypw") as session:
        assert session.cn == CLIENT_CN


def test_pem_without_key_raises(client: Signed) -> None:
    with pytest.raises(CertificateLoadError, match="no private key"):
        PKIClient(client.cert_pem)


def test_pem_with_multiple_keys_raises(client: Signed, ca: Signed) -> None:
    # Two keys in one bundle means it was assembled from the wrong pieces;
    # refuse it rather than silently picking one.
    blob = client.key_pem + ca.key_pem + client.cert_pem
    with pytest.raises(CertificateLoadError, match="multiple private keys"):
        PKIClient.from_pem(blob)


def test_pem_without_cert_raises(client: Signed) -> None:
    with pytest.raises(CertificateLoadError, match="no certificate"):
        PKIClient(client.key_pem)


def test_pkcs12_still_autodetected(client_p12: bytes) -> None:
    # Binary input is routed to the PKCS#12 path.
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        assert session.cn == CLIENT_CN


def test_pem_path_input_nonstandard_extension(
    client: Signed, ca: Signed, tmp_path: Path
) -> None:
    pem_file = tmp_path / "client.tls"  # extension is ignored; content wins
    pem_file.write_bytes(_pem_bundle(client, ca))
    with PKIClient(pem_file) as session:
        assert session.cn == CLIENT_CN


# -- PKCS#7 (.p7b) certs-only bundles -----------------------------------------


def _p7b(encoding: serialization.Encoding, *signed: Signed) -> bytes:
    return pkcs7.serialize_certificates([s.cert for s in signed], encoding)


@pytest.mark.parametrize(
    "encoding", [serialization.Encoding.DER, serialization.Encoding.PEM]
)
def test_key_pair_chain_accepts_pkcs7(
    client: Signed, ca: Signed, encoding: serialization.Encoding
) -> None:
    with PKIClient.from_key_pair(
        certificate=client.cert_pem,
        private_key=client.key_pem,
        chain=_p7b(encoding, ca),
    ) as session:
        assert session._material.ca_pems == [ca.cert_pem]


def test_key_pair_certificate_accepts_pkcs7(client: Signed, ca: Signed) -> None:
    # Leaf and CA in one .p7b, CA listed first: the leaf is identified by
    # matching the private key, not by position.
    bundle = _p7b(serialization.Encoding.DER, ca, client)
    with PKIClient.from_key_pair(
        certificate=bundle, private_key=client.key_pem
    ) as session:
        assert session.cn == CLIENT_CN
        assert session._material.ca_pems == [ca.cert_pem]


def test_pem_bundle_with_pkcs7_block(client: Signed, ca: Signed) -> None:
    # A PEM-encoded PKCS7 block riding along in a bundle is expanded in place.
    blob = client.key_pem + client.cert_pem + _p7b(serialization.Encoding.PEM, ca)
    with PKIClient.from_pem(blob) as session:
        assert session.cn == CLIENT_CN
        assert session._material.ca_pems == [ca.cert_pem]


def test_single_source_pkcs7_pointed_error(ca: Signed) -> None:
    # A .p7b holds no private key, so it can never be the single source; the
    # error must say that instead of blaming the PKCS#12 password.
    with pytest.raises(CertificateLoadError, match="certificate-only PKCS#7"):
        PKIClient(_p7b(serialization.Encoding.DER, ca))


def test_single_source_der_cert_pointed_error(client: Signed) -> None:
    der = client.cert.public_bytes(serialization.Encoding.DER)
    with pytest.raises(
        CertificateLoadError, match="DER certificate with no private key"
    ):
        PKIClient(der)


def test_single_source_garbage_still_generic() -> None:
    # The diagnostics must not misfire on data that is simply broken.
    with pytest.raises(CertificateLoadError, match="invalid PKCS#12"):
        PKIClient(b"\x30\x03not a certificate at all")


def test_pkcs12_wrong_password_still_generic(client_p12: bytes) -> None:
    with pytest.raises(CertificateLoadError, match="invalid PKCS#12"):
        PKIClient(client_p12, password="wrong")
