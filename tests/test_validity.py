"""Tests for certificate expiry awareness (properties, warnings, check_validity)."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from httpx_pki import (
    CertificateExpiredError,
    CertificateNotYetValidError,
    CertificateValidityWarning,
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
    with pytest.warns(CertificateValidityWarning, match="expired"):
        session = PKIClient(bundle.pkcs12())
    try:
        assert session.is_expired is True
        assert session.expires_in < datetime.timedelta(0)
        with pytest.raises(CertificateExpiredError, match="expired"):
            session.check_validity()
    finally:
        session.close()


def test_not_yet_valid_cert_warns_and_check_raises() -> None:
    not_valid_before = _now() + datetime.timedelta(days=10)
    not_valid_after = _now() + datetime.timedelta(days=40)
    bundle = make_client_cert(
        "c",
        ca=make_ca(),
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
    )
    with pytest.warns(CertificateValidityWarning, match="not valid until"):
        session = PKIClient(bundle.pkcs12())
    try:
        assert session.is_not_yet_valid is True
        with pytest.raises(CertificateNotYetValidError, match="not valid until"):
            session.check_validity()
    finally:
        session.close()


def test_warn_if_expires_within_fires() -> None:
    not_valid_after = _now() + datetime.timedelta(days=5)
    bundle = make_client_cert("c", ca=make_ca(), not_valid_after=not_valid_after)
    with pytest.warns(CertificateValidityWarning, match="expires on"):
        session = PKIClient(
            bundle.pkcs12(), warn_if_expires_within=datetime.timedelta(days=10)
        )
    session.close()


@pytest.mark.parametrize(
    "constructor", ["from_pkcs12", "from_pem", "from_key_pair", "from_env"]
)
def test_warn_if_expires_within_on_alternate_constructors(
    constructor: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # warn_if_expires_within is an explicit parameter of every alternate
    # constructor, not something that happens to fall through **kwargs.
    not_valid_after = _now() + datetime.timedelta(days=5)
    bundle = make_client_cert("c", ca=make_ca(), not_valid_after=not_valid_after)
    within = datetime.timedelta(days=10)
    with pytest.warns(CertificateValidityWarning, match="expires on"):
        if constructor == "from_pkcs12":
            session = PKIClient.from_pkcs12(
                bundle.pkcs12(), warn_if_expires_within=within
            )
        elif constructor == "from_pem":
            session = PKIClient.from_pem(bundle.pem, warn_if_expires_within=within)
        elif constructor == "from_key_pair":
            session = PKIClient.from_key_pair(
                certificate=bundle.cert_pem,
                private_key=bundle.key_pem,
                warn_if_expires_within=within,
            )
        else:
            path = tmp_path / "client.pem"
            path.write_bytes(bundle.pem)
            for var in ("PASSWORD", "KEY", "CHAIN", "CA"):
                monkeypatch.delenv(f"HTTPX_PKI_{var}", raising=False)
            monkeypatch.setenv("HTTPX_PKI_CERT", str(path))
            session = PKIClient.from_env(warn_if_expires_within=within)
    session.close()


def test_check_validity_within_window_raises() -> None:
    not_valid_after = _now() + datetime.timedelta(days=5)
    bundle = make_client_cert("c", ca=make_ca(), not_valid_after=not_valid_after)
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


def test_warn_if_expires_within_survives_reload(tmp_path: Path) -> None:
    # The window is retained on the client, so a rotated certificate is judged
    # against the same threshold the session was built with. Without this the
    # warning goes quiet after the first rotation -- exactly when the
    # auto_reload + warn_if_expires_within pairing is meant to be watching.
    ca = make_ca()
    path = tmp_path / "client.pem"
    path.write_bytes(
        make_client_cert(
            "c", ca=ca, not_valid_after=_now() + datetime.timedelta(days=5)
        ).pem
    )
    within = datetime.timedelta(days=10)
    with pytest.warns(CertificateValidityWarning, match="expires on"):
        session = PKIClient(path, warn_if_expires_within=within)
    try:
        # A rotation that lands another short-lived certificate must warn again.
        path.write_bytes(
            make_client_cert(
                "c", ca=ca, not_valid_after=_now() + datetime.timedelta(days=6)
            ).pem
        )
        with pytest.warns(CertificateValidityWarning, match="expires on"):
            session.reload()
    finally:
        session.close()


def test_reload_reevaluates_the_window_against_the_new_cert(
    tmp_path: Path,
) -> None:
    # The window is re-applied to the fresh certificate, not replayed: rotating
    # to a comfortably-valid one must go quiet again.
    import warnings

    ca = make_ca()
    path = tmp_path / "client.pem"
    path.write_bytes(
        make_client_cert(
            "c", ca=ca, not_valid_after=_now() + datetime.timedelta(days=5)
        ).pem
    )
    with pytest.warns(CertificateValidityWarning, match="expires on"):
        session = PKIClient(path, warn_if_expires_within=datetime.timedelta(days=10))
    try:
        path.write_bytes(make_client_cert("c", ca=ca).pem)  # ~365 days
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            session.reload()
    finally:
        session.close()


def test_reload_without_a_window_stays_silent(tmp_path: Path) -> None:
    # A client that never asked for the early warning must not start getting
    # one from the reload path.
    import warnings

    ca = make_ca()
    path = tmp_path / "client.pem"
    path.write_bytes(
        make_client_cert(
            "c", ca=ca, not_valid_after=_now() + datetime.timedelta(days=5)
        ).pem
    )
    with PKIClient(path) as session:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            session.reload()


def test_warn_if_expires_within_survives_pickle() -> None:
    import pickle

    bundle = make_client_cert(
        "c", ca=make_ca(), not_valid_after=_now() + datetime.timedelta(days=5)
    )
    with pytest.warns(CertificateValidityWarning, match="expires on"):
        session = PKIClient(
            bundle.pkcs12(), warn_if_expires_within=datetime.timedelta(days=10)
        )
    try:
        payload = pickle.dumps(session)
    finally:
        session.close()
    with pytest.warns(CertificateValidityWarning, match="expires on"):
        restored = pickle.loads(payload)
    restored.close()
