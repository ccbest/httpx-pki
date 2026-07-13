"""Tests for the httpx_pki.testing certificate helpers."""

from __future__ import annotations

import datetime

from cryptography import x509

from httpx_pki import PKIClient
from httpx_pki.testing import CertBundle, make_ca, make_client_cert


def test_ca_has_certsign_key_usage() -> None:
    # Without keyCertSign in a KeyUsage extension, OpenSSL 3.x (Python 3.13+)
    # rejects the CA as a trust anchor -- "CA cert does not include key usage
    # extension" -- breaking every mTLS round trip built on these helpers.
    ku = make_ca().cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign
    assert ku.crl_sign


def test_client_cert_has_clientauth_extensions() -> None:
    # Strict servers reject a client certificate without clientAuth in its
    # EKU; the minted certs must look like ones a real CA would issue.
    cert = make_client_cert("realistic", ca=make_ca()).cert
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature
    assert ku.key_encipherment
    assert not ku.key_cert_sign
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_self_signed_client_cert_loads() -> None:
    bundle = make_client_cert("solo")
    assert isinstance(bundle, CertBundle)
    assert bundle.common_name == "solo"
    assert bundle.ca_pem == b""
    with PKIClient(bundle.pkcs12()) as session:
        assert session.cn == "solo"


def test_ca_signed_with_sans() -> None:
    ca = make_ca()
    bundle = make_client_cert(
        "svc",
        ca=ca,
        dns_names=["svc.example.com"],
        ip_addresses=["127.0.0.1"],
    )
    assert bundle.ca_pem == ca.cert_pem
    with PKIClient.from_pem(bundle.pem) as session:
        info = session.cert_info()
        assert "svc.example.com" in info.subject_alt_names


def test_pkcs12_password_round_trip() -> None:
    bundle = make_client_cert("x", ca=make_ca())
    with PKIClient(bundle.pkcs12("hunter2"), password="hunter2") as session:
        assert session.cn == "x"


def test_expired_bundle_window_is_in_the_past() -> None:
    bundle = make_client_cert("old", ca=make_ca(), expired=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert bundle.cert.not_valid_after_utc < now
