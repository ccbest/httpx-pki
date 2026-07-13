"""Tests that a private key not matching its certificate is rejected early."""

from __future__ import annotations

import pytest

from httpx_pki import CertificateLoadError, PKIClient
from httpx_pki.testing import make_ca, make_client_cert


def test_from_key_pair_mismatch_raises() -> None:
    ca = make_ca()
    a = make_client_cert("a", ca=ca)
    b = make_client_cert("b", ca=ca)
    with pytest.raises(CertificateLoadError, match="does not match"):
        PKIClient.from_key_pair(certificate=a.cert_pem, private_key=b.key_pem)


def test_from_pem_mismatch_raises() -> None:
    ca = make_ca()
    a = make_client_cert("a", ca=ca)
    b = make_client_cert("b", ca=ca)
    blob = b.key_pem + a.cert_pem  # wrong key for this cert
    with pytest.raises(CertificateLoadError, match="does not match"):
        PKIClient.from_pem(blob)


def test_matching_pair_is_accepted() -> None:
    a = make_client_cert("a", ca=make_ca())
    with PKIClient.from_key_pair(
        certificate=a.cert_pem, private_key=a.key_pem
    ) as session:
        assert session.cn == "a"


def test_from_key_pair_certificate_bundle_keeps_chain() -> None:
    # certificate= holds intermediate-then-leaf; the leaf is found by key
    # match and the intermediate is presented as chain, not dropped.
    ca = make_ca()
    a = make_client_cert("a", ca=ca)
    with PKIClient.from_key_pair(
        certificate=ca.cert_pem + a.cert_pem, private_key=a.key_pem
    ) as session:
        assert session.cn == "a"
        assert session._material.ca_pems == [ca.cert_pem]


def test_from_key_pair_certificate_bundle_mismatch_raises() -> None:
    ca = make_ca()
    a = make_client_cert("a", ca=ca)
    b = make_client_cert("b", ca=ca)
    with pytest.raises(CertificateLoadError, match="does not match"):
        PKIClient.from_key_pair(
            certificate=ca.cert_pem + a.cert_pem, private_key=b.key_pem
        )
