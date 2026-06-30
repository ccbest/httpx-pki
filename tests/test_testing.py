"""Tests for the httpx_pki.testing certificate helpers."""

from __future__ import annotations

import datetime

from httpx_pki import PKCSession
from httpx_pki.testing import CertBundle, make_ca, make_client_cert


def test_self_signed_client_cert_loads() -> None:
    bundle = make_client_cert("solo")
    assert isinstance(bundle, CertBundle)
    assert bundle.common_name == "solo"
    assert bundle.ca_pem == b""
    with PKCSession(bundle.pkcs12()) as session:
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
    with PKCSession.from_pem(bundle.pem) as session:
        info = session.cert_info()
        assert "svc.example.com" in info.subject_alt_names


def test_pkcs12_password_round_trip() -> None:
    bundle = make_client_cert("x", ca=make_ca())
    with PKCSession(bundle.pkcs12("hunter2"), password="hunter2") as session:
        assert session.cn == "x"


def test_expired_bundle_window_is_in_the_past() -> None:
    bundle = make_client_cert("old", ca=make_ca(), expired=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert bundle.cert.not_valid_after_utc < now
