"""Tests for certificate expiry awareness (properties, warnings, check_validity)."""

from __future__ import annotations

import datetime

import pytest

from httpx_pki import (
    CertificateExpiredError,
    CertificateNotYetValidError,
    PKIClient,
)
from httpx_pki.testing import make_ca, make_client_cert


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def test_validity_properties_on_fresh_cert() -> None:
    bundle = make_client_cert("c", ca=make_ca())
    with PKIClient(bundle.pkcs12()) as session:
        assert session.is_expired is False
        assert session.is_not_yet_valid is False
        assert session.expires_in > datetime.timedelta(days=300)
        assert session.not_valid_after > session.not_valid_before
        session.check_validity()  # does not raise


def test_expired_cert_warns_on_load_and_check_raises() -> None:
    bundle = make_client_cert("c", ca=make_ca(), expired=True)
    with pytest.warns(UserWarning, match="expired"):
        session = PKIClient(bundle.pkcs12())
    try:
        assert session.is_expired is True
        assert session.expires_in < datetime.timedelta(0)
        with pytest.raises(CertificateExpiredError, match="expired"):
            session.check_validity()
    finally:
        session.close()


def test_not_yet_valid_cert_warns_and_check_raises() -> None:
    not_before = _now() + datetime.timedelta(days=10)
    not_after = _now() + datetime.timedelta(days=40)
    bundle = make_client_cert(
        "c", ca=make_ca(), not_before=not_before, not_after=not_after
    )
    with pytest.warns(UserWarning, match="not valid until"):
        session = PKIClient(bundle.pkcs12())
    try:
        assert session.is_not_yet_valid is True
        with pytest.raises(CertificateNotYetValidError, match="not valid until"):
            session.check_validity()
    finally:
        session.close()


def test_warn_if_expires_within_fires() -> None:
    not_after = _now() + datetime.timedelta(days=5)
    bundle = make_client_cert("c", ca=make_ca(), not_after=not_after)
    with pytest.warns(UserWarning, match="expires on"):
        session = PKIClient(
            bundle.pkcs12(), warn_if_expires_within=datetime.timedelta(days=10)
        )
    session.close()


def test_check_validity_within_window_raises() -> None:
    not_after = _now() + datetime.timedelta(days=5)
    bundle = make_client_cert("c", ca=make_ca(), not_after=not_after)
    with PKIClient(bundle.pkcs12()) as session:
        session.check_validity()  # currently valid -> ok
        with pytest.raises(CertificateExpiredError, match="within"):
            session.check_validity(within=datetime.timedelta(days=10))


def test_warn_if_expires_within_silent_when_far_off() -> None:
    bundle = make_client_cert("c", ca=make_ca())  # ~365 days
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning becomes an error
        session = PKIClient(
            bundle.pkcs12(), warn_if_expires_within=datetime.timedelta(days=10)
        )
    session.close()
