"""Tests for Windows certificate store selection logic and the lazy guard.

The real ctypes enumeration/export cannot run off Windows, so those functions
are monkeypatched. Everything else -- selection, error handling, the non-Windows
guard, and the full constructor glue -- runs on any platform.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization

import httpx_pki._winstore as winstore
from httpx_pki import (
    AmbiguousCertificateError,
    CertificateLoadError,
    CertificateNotFoundError,
    PKIClient,
    UnsupportedPlatformError,
    WinCert,
    build_windows_ssl_context,
    cert_info,
    list_windows_certificates,
)
from httpx_pki._winstore import (
    WinCert as WinCertModule,
)
from httpx_pki._winstore import (
    load_windows_pkcs12,
    select_windows_certificate,
)
from httpx_pki.testing import CertBundle, make_client_cert
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
    chosen = select_windows_certificate(CANDIDATES, name="prod")
    assert chosen.thumbprint == "AA11BB"


def test_select_by_substring_friendly_name() -> None:
    chosen = select_windows_certificate(CANDIDATES, name="dev cert")
    assert chosen.subject_cn == "ACME Dev Client"


def test_select_is_case_insensitive() -> None:
    tp = select_windows_certificate(CANDIDATES, name="UNRELATED").thumbprint
    assert tp == "EE33FF"


def test_select_by_thumbprint_with_separators() -> None:
    chosen = select_windows_certificate(CANDIDATES, thumbprint="cc:22:dd")
    assert chosen.subject_cn == "ACME Dev Client"


def test_select_by_predicate() -> None:
    chosen = select_windows_certificate(
        CANDIDATES, predicate=lambda c: c.friendly_name == "prod"
    )
    assert chosen.thumbprint == "AA11BB"


def test_select_no_selector_single_candidate() -> None:
    only = [CANDIDATES[0]]
    assert select_windows_certificate(only) is only[0]


def test_select_not_found() -> None:
    with pytest.raises(CertificateNotFoundError, match="missing"):
        select_windows_certificate(CANDIDATES, name="missing")


def test_select_ambiguous_lists_candidates() -> None:
    with pytest.raises(AmbiguousCertificateError) as exc:
        select_windows_certificate(CANDIDATES, name="acme")
    message = str(exc.value)
    assert "ACME Prod Client" in message
    assert "ACME Dev Client" in message
    assert "AA11BB" in message


def test_select_no_selector_multiple_is_ambiguous() -> None:
    with pytest.raises(AmbiguousCertificateError):
        select_windows_certificate(CANDIDATES)


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
def test_load_raises_on_non_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        load_windows_pkcs12(name="anything")


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
def test_list_raises_on_non_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        list_windows_certificates()


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
def test_build_windows_ssl_context_raises_on_non_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        build_windows_ssl_context(name="anything")


def test_list_windows_certificates_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # The enumerated contexts carry live handles; the listing must hand back
    # metadata-only copies (handle=None) and free every enumerated handle.
    fake = _FakeCrypt32()
    a = WinCert("ACME Prod", "prod", "AA", handle=1)
    b = WinCert("ACME Dev", "dev", "BB", handle=2)
    monkeypatch.setattr(winstore, "_enumerate_store", lambda store, location: [a, b])
    monkeypatch.setattr(winstore, "_load_crypt32", lambda: fake)
    monkeypatch.setattr(winstore.sys, "platform", "win32")

    listed = list_windows_certificates()

    assert [c.thumbprint for c in listed] == ["AA", "BB"]
    assert all(c.handle is None for c in listed)
    assert sorted(fake.freed) == [1, 2]


def test_build_windows_ssl_context_mocked(
    monkeypatch: pytest.MonkeyPatch, client_p12: bytes
) -> None:
    import ssl

    fake = WinCert(subject_cn=CLIENT_CN, friendly_name="internal", thumbprint="DEAD")
    monkeypatch.setattr(winstore, "_enumerate_store", lambda store, location: [fake])

    def fake_export(cert: WinCert) -> tuple[bytes, bytes]:
        from tests.conftest import P12_PASSWORD

        return client_p12, P12_PASSWORD.encode()

    monkeypatch.setattr(winstore, "_export_pfx", fake_export)
    monkeypatch.setattr(winstore.sys, "platform", "win32")

    ctx = build_windows_ssl_context(predicate=lambda c: "internal" in c.friendly_name)
    assert isinstance(ctx, ssl.SSLContext)


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows guard")
def test_constructor_raises_on_non_windows() -> None:
    with pytest.raises(UnsupportedPlatformError):
        PKIClient.from_windows_cert_store(name="anything")


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

    with PKIClient.from_windows_cert_store(name="test-client") as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_from_windows_cert_store_not_found_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(winstore, "_enumerate_store", lambda store, location: [])
    monkeypatch.setattr(winstore.sys, "platform", "win32")
    with pytest.raises(CertificateNotFoundError):
        PKIClient.from_windows_cert_store(name="nope")


class _FakeCrypt32:
    def __init__(self) -> None:
        self.freed: list[object] = []

    def CertFreeCertificateContext(self, handle: object) -> None:  # noqa: N802
        self.freed.append(handle)


def test_unchosen_contexts_are_freed(
    monkeypatch: pytest.MonkeyPatch, client_p12: bytes
) -> None:
    # Only the non-chosen enumerated context is freed here; the chosen one is
    # released inside _export_pfx (mocked away), so it must not appear.
    fake = _FakeCrypt32()
    chosen = WinCert("ACME Prod", "prod", "AA", handle=1)
    other = WinCert("ACME Dev", "dev", "BB", handle=2)
    monkeypatch.setattr(
        winstore, "_enumerate_store", lambda store, location: [chosen, other]
    )
    monkeypatch.setattr(winstore, "_load_crypt32", lambda: fake)
    monkeypatch.setattr(winstore, "_export_pfx", lambda cert: (client_p12, b"secret"))
    monkeypatch.setattr(winstore.sys, "platform", "win32")

    load_windows_pkcs12(thumbprint="AA")
    assert fake.freed == [2]


def test_all_contexts_freed_on_selection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When selection fails, every duplicated context must be released.
    fake = _FakeCrypt32()
    a = WinCert("ACME Prod", "prod", "AA", handle=1)
    b = WinCert("ACME Dev", "dev", "BB", handle=2)
    monkeypatch.setattr(winstore, "_enumerate_store", lambda store, location: [a, b])
    monkeypatch.setattr(winstore, "_load_crypt32", lambda: fake)
    monkeypatch.setattr(winstore.sys, "platform", "win32")

    with pytest.raises(AmbiguousCertificateError):
        load_windows_pkcs12(name="acme")
    assert sorted(fake.freed) == [1, 2]


def test_free_contexts_skips_handleless(monkeypatch: pytest.MonkeyPatch) -> None:
    # Handle-less stand-ins must not trigger a crypt32 load (which faults off-Win).
    def boom() -> object:
        raise AssertionError("crypt32 must not load when there is nothing to free")

    monkeypatch.setattr(winstore, "_load_crypt32", boom)
    winstore._free_contexts([WinCert("a", None, "AA")])  # handle defaults to None


# -- usage selection and intersecting selectors (all platforms) ---------------


def _candidate(
    common_name: str,
    friendly_name: str | None,
    *,
    key_usage: list[str],
    extended_key_usage: list[str] | None = None,
) -> WinCert:
    """A synthetic store record backed by a real certificate."""
    bundle = make_client_cert(
        common_name, key_usage=key_usage, extended_key_usage=extended_key_usage
    )
    info = cert_info(bundle.cert_pem)
    return WinCert(
        subject_cn=common_name,
        friendly_name=friendly_name,
        thumbprint=info.fingerprint_sha1,
        certificate=bundle.cert,
        info=info,
    )


DUAL_CN = "ACME Dual User"
DUAL = [
    _candidate(
        DUAL_CN,
        "Signature",
        key_usage=["digital_signature"],
        extended_key_usage=["client_auth"],
    ),
    _candidate(
        DUAL_CN,
        "Encryption",
        key_usage=["key_encipherment"],
        extended_key_usage=["email_protection"],
    ),
]


def test_select_by_key_usage() -> None:
    chosen = select_windows_certificate(DUAL, key_usage="digital_signature")
    assert chosen.friendly_name == "Signature"


def test_select_by_extended_key_usage() -> None:
    chosen = select_windows_certificate(DUAL, extended_key_usage="email_protection")
    assert chosen.friendly_name == "Encryption"


def test_name_and_usage_intersect() -> None:
    # The name alone matches both halves of the pair; the usage resolves it.
    with pytest.raises(AmbiguousCertificateError):
        select_windows_certificate(DUAL, name=DUAL_CN)
    chosen = select_windows_certificate(
        DUAL, name=DUAL_CN, key_usage="digital_signature"
    )
    assert chosen.friendly_name == "Signature"


def test_selectors_that_disagree_match_nothing() -> None:
    # Every selector must match: a thumbprint from one candidate and a name
    # from the other cannot both be satisfied. (Before selectors intersected,
    # the thumbprint won and the name was ignored.)
    with pytest.raises(CertificateNotFoundError):
        select_windows_certificate(
            DUAL, thumbprint=DUAL[0].thumbprint, name="Encryption"
        )


def test_usage_selector_skips_records_without_a_certificate() -> None:
    with pytest.raises(CertificateNotFoundError):
        select_windows_certificate(CANDIDATES, key_usage="digital_signature")


def test_usage_accessors_default_to_empty() -> None:
    assert CANDIDATES[0].key_usage == frozenset()
    assert CANDIDATES[0].extended_key_usage == []
    assert DUAL[0].key_usage == frozenset({"digital_signature"})


def test_ambiguous_message_shows_usage_and_expiry() -> None:
    with pytest.raises(AmbiguousCertificateError) as exc:
        select_windows_certificate(DUAL, name=DUAL_CN)
    message = str(exc.value)
    assert "key_usage=digital_signature" in message
    assert "expires=" in message


# -- CERT_CONTEXT reading (simulated; the real struct is Windows-only) --------


class _FakeCertContext(ctypes.Structure):
    """The CERT_CONTEXT layout, with DWORD spelled as its c_uint32 equivalent.

    Lets the DER extraction and its self-check run off Windows: the field order
    and sizes are what _enumerate_store declares, so this exercises the same
    cast, the same string_at, and the same thumbprint verification.
    """

    _fields_ = [
        ("dwCertEncodingType", ctypes.c_uint32),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", ctypes.c_uint32),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


def _fake_context(der: bytes) -> tuple[int, object, object]:
    """A CERT_CONTEXT holding *der*, plus the objects keeping it alive."""
    buf = (ctypes.c_ubyte * len(der)).from_buffer_copy(der)
    context = _FakeCertContext(
        1, ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)), len(der), None, None
    )
    return ctypes.addressof(context), context, buf


def test_certificate_details_reads_the_encoded_certificate() -> None:
    bundle = make_client_cert("ctx-read", key_usage=["digital_signature"])
    expected = cert_info(bundle.cert_pem)
    address, _ctx, _buf = _fake_context(
        bundle.cert.public_bytes(serialization.Encoding.DER)
    )
    certificate, info = winstore._certificate_details(
        address, _FakeCertContext, expected.fingerprint_sha1
    )
    assert certificate is not None and info is not None
    assert info.fingerprint_sha1 == expected.fingerprint_sha1
    assert info.key_usage == frozenset({"digital_signature"})


def test_certificate_details_rejects_a_thumbprint_mismatch() -> None:
    # Stands in for a wrong struct offset: the bytes parsed are not the
    # certificate Windows says this context is, so the record must report no
    # certificate rather than usages read out of the wrong memory.
    bundle = make_client_cert("ctx-mismatch")
    address, _ctx, _buf = _fake_context(
        bundle.cert.public_bytes(serialization.Encoding.DER)
    )
    assert winstore._certificate_details(address, _FakeCertContext, "00" * 20) == (
        None,
        None,
    )


def test_certificate_details_survives_unparseable_bytes() -> None:
    address, _ctx, _buf = _fake_context(b"not a certificate")
    assert winstore._certificate_details(address, _FakeCertContext, "") == (
        None,
        None,
    )


def test_certificate_details_handles_an_empty_context() -> None:
    context = _FakeCertContext(1, None, 0, None, None)
    assert winstore._certificate_details(
        ctypes.addressof(context), _FakeCertContext, ""
    ) == (None, None)


# -- real store, end to end (Windows + HTTPX_PKI_WINSTORE_TESTS only) ---------
#
# Nothing else in this file executes the ctypes enumeration or export: they are
# monkeypatched everywhere. This suite is the only place the real crypt32 path
# runs, which is also what proves the CERT_CONTEXT layout above.

WINSTORE_CN = "httpx-pki-winstore-dual"
_PFX_PW = "httpx-pki-test"

requires_winstore = pytest.mark.skipif(
    sys.platform != "win32" or not os.environ.get("HTTPX_PKI_WINSTORE_TESTS"),
    reason="real-store tests need Windows and HTTPX_PKI_WINSTORE_TESTS=1",
)


def _powershell(script: str, *, check: bool = True) -> str:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        # Surface stderr: CalledProcessError alone shows only the argv, which
        # makes CI failures undiagnosable.
        raise RuntimeError(
            f"powershell failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


@dataclass
class StoreFixture:
    """The dual key pair provisioned into CurrentUser\\MY."""

    signing: CertBundle
    encryption: CertBundle


@pytest.fixture(scope="session")
def store_identities(
    ca_bundle: CertBundle, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[StoreFixture]:
    """Import a dual key pair into the user's personal certificate store.

    Both certificates share a subject and differ only in usage -- what Active
    Directory key archival provisions, and the case ``key_usage=`` exists for.
    They are signed by the conftest CA so the mtls_server fixture accepts them,
    imported ``-Exportable`` so the PFX export can run unattended, and removed
    (key included) afterwards. Only CurrentUser\\MY is ever touched.
    """
    signing = make_client_cert(
        WINSTORE_CN,
        ca=ca_bundle,
        key_usage=["digital_signature"],
        extended_key_usage=["client_auth"],
    )
    encryption = make_client_cert(
        WINSTORE_CN,
        ca=ca_bundle,
        key_usage=["key_encipherment"],
        extended_key_usage=["email_protection"],
    )
    directory = tmp_path_factory.mktemp("winstore")
    imported: list[str] = []
    try:
        for label, bundle in (("sig", signing), ("enc", encryption)):
            path = directory / f"{label}.pfx"
            path.write_bytes(bundle.pkcs12(_PFX_PW))
            _powershell(
                f"$pw = ConvertTo-SecureString -String '{_PFX_PW}' "
                "-Force -AsPlainText; "
                f"Import-PfxCertificate -FilePath '{path}' "
                "-CertStoreLocation Cert:\\CurrentUser\\My "
                "-Password $pw -Exportable | Out-Null"
            )
            imported.append(cert_info(bundle.cert_pem).fingerprint_sha1)
        yield StoreFixture(signing=signing, encryption=encryption)
    finally:
        for thumbprint in imported:
            _powershell(
                f"Remove-Item -Path Cert:\\CurrentUser\\My\\{thumbprint} "
                "-DeleteKey -ErrorAction SilentlyContinue",
                check=False,
            )


def _listed(cn: str = WINSTORE_CN) -> list[WinCert]:
    return [c for c in list_windows_certificates() if c.subject_cn == cn]


@requires_winstore
def test_real_store_reads_the_encoded_certificates(
    store_identities: StoreFixture,
) -> None:
    # THE layout assertion: if the CERT_CONTEXT offsets were wrong, the DER
    # would not parse or its thumbprint would not match, and _certificate_details
    # would have returned (None, None) for every record.
    listed = _listed()
    assert len(listed) == 2
    for candidate in listed:
        assert candidate.certificate is not None
        assert candidate.info is not None
        assert candidate.info.fingerprint_sha1 == candidate.thumbprint
        assert candidate.handle is None  # freed before returning
    assert {frozenset(c.key_usage) for c in listed} == {
        frozenset({"digital_signature"}),
        frozenset({"key_encipherment"}),
    }


@requires_winstore
def test_real_store_dual_pair_needs_a_usage(
    store_identities: StoreFixture,
) -> None:
    with pytest.raises(AmbiguousCertificateError) as exc:
        PKIClient.from_windows_cert_store(name=WINSTORE_CN)
    assert "key_usage=" in str(exc.value)


@requires_winstore
def test_real_store_selects_the_signing_half(
    store_identities: StoreFixture, mtls_server: object
) -> None:
    server = mtls_server  # MTLSServer(url, ca_file)
    with PKIClient.from_windows_cert_store(
        name=WINSTORE_CN,
        key_usage="digital_signature",
        verify=str(server.ca_file),  # type: ignore[attr-defined]
    ) as session:
        assert session.cn == WINSTORE_CN
        assert (
            session.certificate.serial_number
            == store_identities.signing.cert.serial_number
        )
        # The server sees the half we selected, not whichever the store
        # happened to enumerate first.
        resp = session.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert (
            resp.headers["X-Client-Fingerprint"]
            == session.cert_info().fingerprint_sha256
        )
        # reload() re-exports from the store with the same selector.
        session.reload()
        assert session.cert_info().key_usage == frozenset({"digital_signature"})


@requires_winstore
def test_real_store_selects_by_extended_key_usage(
    store_identities: StoreFixture,
) -> None:
    with PKIClient.from_windows_cert_store(
        name=WINSTORE_CN, extended_key_usage="email_protection"
    ) as session:
        assert (
            session.certificate.serial_number
            == store_identities.encryption.cert.serial_number
        )


@requires_winstore
def test_real_store_thumbprint_selection(store_identities: StoreFixture) -> None:
    raw = cert_info(store_identities.signing.cert_pem).fingerprint_sha1
    pretty = ":".join(raw[i : i + 2] for i in range(0, len(raw), 2)).lower()
    with PKIClient.from_windows_cert_store(thumbprint=pretty) as session:
        assert session.certificate.serial_number == (
            store_identities.signing.cert.serial_number
        )


@requires_winstore
def test_real_store_build_ssl_context(store_identities: StoreFixture) -> None:
    context = build_windows_ssl_context(
        name=WINSTORE_CN, key_usage="digital_signature"
    )
    assert context is not None


# -- export error mapping (all platforms; the mapping is pure) ----------------


def test_non_exportable_error_is_named_even_when_signed() -> None:
    # ctypes.get_last_error() returns a signed int, so NTE_BAD_KEY_STATE
    # (0x8009000B) arrives as -0x7ff6fff5. It must still be recognized as
    # "not exportable" rather than falling through to the generic message.
    with pytest.raises(CertificateLoadError) as exc:
        winstore._raise_export_error(-0x7FF6FFF5)
    message = str(exc.value)
    assert "not exportable" in message
    assert "Import-PfxCertificate -Exportable" in message
    assert "0x8009000b" in message.lower()


@pytest.mark.parametrize("code", sorted(winstore._NON_EXPORTABLE_ERRORS))
def test_every_non_exportable_code_is_named(code: int) -> None:
    # Each one, in both the unsigned and the signed spelling Windows may hand
    # back, since the sign depends on how the value reaches us.
    for value in (code, code - 0x100000000):
        with pytest.raises(CertificateLoadError, match="not exportable"):
            winstore._raise_export_error(value)


def test_other_export_failures_keep_the_generic_message() -> None:
    with pytest.raises(CertificateLoadError) as exc:
        winstore._raise_export_error(0x00000005)  # ERROR_ACCESS_DENIED
    message = str(exc.value)
    assert "PFX export failed" in message
    assert "0x00000005" in message
    assert "not exportable" not in message


def test_records_are_hashable_and_compare_on_identity() -> None:
    # list_windows_certificates() results must survive set()/dict use; the
    # parsed certificate and info are derived, so they stay out of equality.
    assert len(set(DUAL)) == 2
    plain = WinCert(
        subject_cn=DUAL[0].subject_cn,
        friendly_name=DUAL[0].friendly_name,
        thumbprint=DUAL[0].thumbprint,
    )
    assert plain == DUAL[0]
    assert len({plain, DUAL[0]}) == 1
