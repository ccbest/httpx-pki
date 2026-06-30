"""Tests that a private key not matching its certificate is rejected early."""

from __future__ import annotations

import pytest

from httpx_pki import CertificateLoadError, PKCSession
from httpx_pki.testing import make_ca, make_client_cert


def test_from_key_pair_mismatch_raises() -> None:
    ca = make_ca()
    a = make_client_cert("a", ca=ca)
    b = make_client_cert("b", ca=ca)
    with pytest.raises(CertificateLoadError, match="does not match"):
        PKCSession.from_key_pair(certificate=a.cert_pem, private_key=b.key_pem)


def test_from_pem_mismatch_raises() -> None:
    ca = make_ca()
    a = make_client_cert("a", ca=ca)
    b = make_client_cert("b", ca=ca)
    blob = b.key_pem + a.cert_pem  # wrong key for this cert
    with pytest.raises(CertificateLoadError, match="does not match"):
        PKCSession.from_pem(blob)


def test_matching_pair_is_accepted() -> None:
    a = make_client_cert("a", ca=make_ca())
    with PKCSession.from_key_pair(
        certificate=a.cert_pem, private_key=a.key_pem
    ) as session:
        assert session.CN == "a"
