"""Tests for Windows certificate store selection logic and the lazy guard.

The real ctypes enumeration/export cannot run off Windows, so those functions
are monkeypatched. Everything else -- selection, error handling, the non-Windows
guard, and the full constructor glue -- runs on any platform.
"""

from __future__ import annotations

import sys

import pytest

import httpx_pki._winstore as winstore
from httpx_pki import (
    AmbiguousCertificateError,
    CertificateNotFoundError,
    PKCSession,
    UnsupportedPlatformError,
    WinCert,
)
from httpx_pki._winstore import (
    WinCert as WinCertModule,
)
from httpx_pki._winstore import (
    load_windows_pkcs12,
    select_certificate,
)
from tests.conftest import CLIENT_CN, Signed

CANDIDATES = [
    WinCert(
        subject_cn="ACME Prod Client", friendly_name="prod", thumbprint="AA11BB"
    ),
    WinCert(
        subject_cn="ACME Dev Client", friendly_name="dev cert", thumbprint="CC22DD"
    ),
    WinCert(subject_cn="Unrelated", friendly_name=None, thumbprint="EE33FF"),
]


def test_import_safety() -> None:
    # Importing the module must never touch windll, on any platform.
    assert winstore.WinCert is WinCertModule


def test_select_by_substring_cn() -> None:
    chosen = select_certificate(CANDIDATES, name="prod")
    assert chosen.thumbprint == "AA11BB"


def test_select_by_substring_friendly_name() -> None:
    chosen = select_certificate(CANDIDATES, name="dev cert")
    assert chosen.subject_cn == "ACME Dev Client"


def test_select_is_case_insensitive() -> None:
    assert select_certificate(CANDIDATES, name="UNRELATED").thumbprint == "EE33FF"


def test_select_by_thumbprint_with_separators() -> None:
    chosen = select_certificate(CANDIDATES, thumbprint="cc:22:dd")
    assert chosen.subject_cn == "ACME Dev Client"


def test_select_by_predicate() -> None:
    chosen = select_certificate(
        CANDIDATES, predicate=lambda c: c.friendly_name == "prod"
    )
    assert chosen.thumbprint == "AA11BB"


def test_select_no_selector_single_candidate() -> None:
    only = [CANDIDATES[0]]
    assert select_certificate(only) is only[0]


def test_select_not_found() -> None:
    with pytest.raises(CertificateNotFoundError, match="missing"):
        select_certificate(CANDIDATES, name="missing")


def test_select_ambiguous_lists_candidates() -> None:
    with pytest.raises(AmbiguousCertificateError) as exc:
        select_certificate(CANDIDATES, name="acme")
    message = str(exc.value)
    assert "ACME Prod Client" in message
    assert "ACME Dev Client" in message
    assert "AA11BB" in message


def test_select_no_selector_multiple_is_ambiguous() -> None:
    with pytest.raises(AmbiguousCertificateError):
        select_certificate(CANDIDATES)


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
def test_load_raises_on_non_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        load_windows_pkcs12(name="anything")


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
def test_constructor_raises_on_non_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        PKCSession.from_windows_cert_store(name="anything")


def test_from_windows_cert_store_mocked(
    monkeypatch: pytest.MonkeyPatch, client: Signed, client_p12: bytes
) -> None:
    # Stand in for the real store: one matching cert, and an export that returns
    # a genuine PFX (built by the conftest fixtures) under a known password.
    fake = WinCert(
        subject_cn=CLIENT_CN, friendly_name="my client", thumbprint="DEADBEEF"
    )

    def fake_enumerate(store: str, location: str) -> list[WinCert]:
        assert store == "MY"
        assert location == "CurrentUser"
        return [fake]

    def fake_export(cert: WinCert) -> tuple[bytes, bytes]:
        assert cert is fake
        from tests.conftest import P12_PASSWORD

        return client_p12, P12_PASSWORD.encode()

    monkeypatch.setattr(winstore, "_enumerate_store", fake_enumerate)
    monkeypatch.setattr(winstore, "_export_pfx", fake_export)
    monkeypatch.setattr(winstore.sys, "platform", "win32")

    with PKCSession.from_windows_cert_store(name="test-client") as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_from_windows_cert_store_not_found_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(winstore, "_enumerate_store", lambda store, location: [])
    monkeypatch.setattr(winstore.sys, "platform", "win32")
    with pytest.raises(CertificateNotFoundError):
        PKCSession.from_windows_cert_store(name="nope")
