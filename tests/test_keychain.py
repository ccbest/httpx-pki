"""Tests for the macOS keychain integration.

The selection logic is pure and runs on every platform, as do the mocked
plumbing tests and the non-macOS platform guards. The real-keychain tests run
only on macOS with HTTPX_PKI_KEYCHAIN_TESTS=1 (set in CI): they provision a
throwaway keychain with the `security` CLI, so a developer's Mac is never
touched unless explicitly opted in.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

import httpx_pki._keychain as keychain
from httpx_pki import (
    AmbiguousCertificateError,
    AsyncPKIClient,
    CertificateNotFoundError,
    MacCert,
    PKIClient,
    UnsupportedPlatformError,
    build_macos_ssl_context,
    cert_info,
    list_macos_certificates,
    select_macos_certificate,
)
from httpx_pki._keychain import load_macos_pkcs12
from httpx_pki.testing import CertBundle, make_client_cert
from tests.conftest import CLIENT_CN, P12_PASSWORD, Signed, _sign

CANDIDATES = [
    MacCert(subject_cn="ACME Prod Client", label="prod", thumbprint="AA11BB"),
    MacCert(subject_cn="ACME Dev Client", label="dev cert", thumbprint="CC22DD"),
    MacCert(subject_cn="Unrelated", label=None, thumbprint="EE33FF"),
]


# -- pure selection (all platforms) -------------------------------------------


def test_select_by_substring_cn() -> None:
    chosen = select_macos_certificate(CANDIDATES, name="prod")
    assert chosen.thumbprint == "AA11BB"


def test_select_by_substring_label() -> None:
    chosen = select_macos_certificate(CANDIDATES, name="dev cert")
    assert chosen.subject_cn == "ACME Dev Client"


def test_select_is_case_insensitive() -> None:
    tp = select_macos_certificate(CANDIDATES, name="UNRELATED").thumbprint
    assert tp == "EE33FF"


def test_select_by_thumbprint_with_separators() -> None:
    chosen = select_macos_certificate(CANDIDATES, thumbprint="cc:22:dd")
    assert chosen.subject_cn == "ACME Dev Client"


def test_select_by_identity_predicate() -> None:
    chosen = select_macos_certificate(
        CANDIDATES, identity=lambda c: c.label == "prod"
    )
    assert chosen.thumbprint == "AA11BB"


def test_select_no_selector_single_candidate() -> None:
    only = [CANDIDATES[0]]
    assert select_macos_certificate(only) is only[0]


def test_select_not_found() -> None:
    with pytest.raises(CertificateNotFoundError, match="missing"):
        select_macos_certificate(CANDIDATES, name="missing")


def test_select_ambiguous_lists_candidates() -> None:
    with pytest.raises(AmbiguousCertificateError) as exc:
        select_macos_certificate(CANDIDATES, name="acme")
    message = str(exc.value)
    assert "ACME Prod Client" in message
    assert "ACME Dev Client" in message
    assert "AA11BB" in message


def test_select_no_selector_multiple_is_ambiguous() -> None:
    with pytest.raises(AmbiguousCertificateError):
        select_macos_certificate(CANDIDATES)


# -- platform guards (run everywhere but macOS) -------------------------------


@pytest.mark.skipif(sys.platform == "darwin", reason="tests the non-macOS guard")
def test_load_raises_off_macos() -> None:
    with pytest.raises(UnsupportedPlatformError):
        load_macos_pkcs12(name="anything")


@pytest.mark.skipif(sys.platform == "darwin", reason="tests the non-macOS guard")
def test_list_raises_off_macos() -> None:
    with pytest.raises(UnsupportedPlatformError):
        list_macos_certificates()


@pytest.mark.skipif(sys.platform == "darwin", reason="tests the non-macOS guard")
def test_build_macos_ssl_context_raises_off_macos() -> None:
    with pytest.raises(UnsupportedPlatformError):
        build_macos_ssl_context(name="anything")


@pytest.mark.skipif(sys.platform == "darwin", reason="tests the non-macOS guard")
def test_constructors_raise_off_macos() -> None:
    with pytest.raises(UnsupportedPlatformError):
        PKIClient.from_macos_keychain(name="anything")
    with pytest.raises(UnsupportedPlatformError):
        AsyncPKIClient.from_macos_keychain(name="anything")


# -- mocked plumbing (all platforms) ------------------------------------------


class _FakeCF:
    def __init__(self) -> None:
        self.released: list[object] = []

    def CFRelease(self, handle: object) -> None:  # noqa: N802
        self.released.append(handle)


def test_list_macos_certificates_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # The enumerated identities carry retained handles; the listing must hand
    # back metadata-only copies (handle=None) and release every handle.
    fake = _FakeCF()
    a = MacCert("ACME Prod", "prod", "AA", handle=1)
    b = MacCert("ACME Dev", "dev", "BB", handle=2)
    monkeypatch.setattr(keychain, "_enumerate_identities", lambda: [a, b])
    monkeypatch.setattr(keychain, "_load_frameworks", lambda: (None, fake))

    listed = list_macos_certificates()

    assert [c.thumbprint for c in listed] == ["AA", "BB"]
    assert all(c.handle is None for c in listed)
    assert sorted(fake.released) == [1, 2]  # type: ignore[type-var]


def test_from_macos_keychain_mocked(
    monkeypatch: pytest.MonkeyPatch, client_p12: bytes
) -> None:
    # Stand in for the real keychain: one matching identity, and an export
    # that returns a genuine PFX (from the conftest fixtures).
    fake_cert = MacCert(
        subject_cn=CLIENT_CN, label="my client", thumbprint="DEADBEEF"
    )

    def fake_export(cert: MacCert) -> tuple[bytes, bytes]:
        assert cert is fake_cert
        return client_p12, P12_PASSWORD.encode()

    monkeypatch.setattr(keychain, "_enumerate_identities", lambda: [fake_cert])
    monkeypatch.setattr(keychain, "_export_identity", fake_export)
    monkeypatch.setattr(keychain.sys, "platform", "darwin")

    with PKIClient.from_macos_keychain(name="test-client") as session:
        assert session.cert_info().common_name == CLIENT_CN


def test_reload_reexports_from_keychain_mocked(
    monkeypatch: pytest.MonkeyPatch, client_p12: bytes
) -> None:
    # reload() must re-run the keychain export with the recorded selector.
    fake_cert = MacCert(subject_cn=CLIENT_CN, label=None, thumbprint="AA")
    exports: list[MacCert] = []

    def fake_export(cert: MacCert) -> tuple[bytes, bytes]:
        exports.append(cert)
        return client_p12, P12_PASSWORD.encode()

    monkeypatch.setattr(keychain, "_enumerate_identities", lambda: [fake_cert])
    monkeypatch.setattr(keychain, "_export_identity", fake_export)
    monkeypatch.setattr(keychain.sys, "platform", "darwin")

    with PKIClient.from_macos_keychain(name="test-client") as session:
        session.reload()
        assert session.cn == CLIENT_CN
    assert len(exports) == 2


def test_from_macos_keychain_not_found_mocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(keychain, "_enumerate_identities", lambda: [])
    monkeypatch.setattr(keychain.sys, "platform", "darwin")
    with pytest.raises(CertificateNotFoundError):
        PKIClient.from_macos_keychain(name="nope")


def test_unchosen_identities_are_freed(
    monkeypatch: pytest.MonkeyPatch, client_p12: bytes
) -> None:
    # Only the non-chosen identity is released here; the chosen one is
    # released inside _export_identity (mocked away), so it must not appear.
    fake = _FakeCF()
    chosen = MacCert("ACME Prod", "prod", "AA", handle=1)
    other = MacCert("ACME Dev", "dev", "BB", handle=2)
    monkeypatch.setattr(keychain, "_enumerate_identities", lambda: [chosen, other])
    monkeypatch.setattr(keychain, "_load_frameworks", lambda: (None, fake))
    monkeypatch.setattr(
        keychain, "_export_identity", lambda cert: (client_p12, b"secret")
    )
    monkeypatch.setattr(keychain.sys, "platform", "darwin")

    load_macos_pkcs12(thumbprint="AA")
    assert fake.released == [2]


def test_all_identities_freed_on_selection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeCF()
    a = MacCert("ACME Prod", "prod", "AA", handle=1)
    b = MacCert("ACME Dev", "dev", "BB", handle=2)
    monkeypatch.setattr(keychain, "_enumerate_identities", lambda: [a, b])
    monkeypatch.setattr(keychain, "_load_frameworks", lambda: (None, fake))
    monkeypatch.setattr(keychain.sys, "platform", "darwin")

    with pytest.raises(AmbiguousCertificateError):
        load_macos_pkcs12(name="acme")
    assert sorted(fake.released) == [1, 2]  # type: ignore[type-var]


def test_free_identities_skips_handleless(monkeypatch: pytest.MonkeyPatch) -> None:
    # Handle-less stand-ins must not load the frameworks (which raise off-mac).
    def boom() -> object:
        raise AssertionError("frameworks must not load with nothing to free")

    monkeypatch.setattr(keychain, "_load_frameworks", boom)
    keychain._free_identities([MacCert("a", None, "AA")])  # handle is None


# -- real keychain, end to end (macOS + HTTPX_PKI_KEYCHAIN_TESTS only) --------

KEYCHAIN_CN = "httpx-pki-keychain-client"
DUAL_KEYCHAIN_CN = "httpx-pki-keychain-dual"
_KEYCHAIN_PW = "httpx-pki-test"

requires_keychain = pytest.mark.skipif(
    sys.platform != "darwin" or not os.environ.get("HTTPX_PKI_KEYCHAIN_TESTS"),
    reason="real-keychain tests need macOS and HTTPX_PKI_KEYCHAIN_TESTS=1",
)


def _security(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["security", *args], check=False, capture_output=True, text=True
    )
    if check and proc.returncode != 0:
        # Surface stderr: CalledProcessError alone shows only the argv, which
        # makes CI failures undiagnosable.
        raise RuntimeError(
            f"security {' '.join(args)} failed "
            f"({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc


def _legacy_p12(key: object, cert: object, name: str) -> bytes:
    """A PKCS#12 the Security framework can import.

    macOS `security import` cannot read a PKCS#12 encrypted with the modern
    AES/PBKDF2 defaults (BestAvailableEncryption); use the legacy 3DES/SHA-1
    PBE it understands.
    """
    legacy_encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50_000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(b"p12pw")
    )
    return pkcs12.serialize_key_and_certificates(
        name=name.encode(),
        key=key,  # type: ignore[arg-type]
        cert=cert,  # type: ignore[arg-type]
        cas=None,
        encryption_algorithm=legacy_encryption,
    )


@dataclass
class KeychainFixture:
    """What the throwaway keychain holds: a plain identity and a dual pair."""

    single: Signed
    signing: CertBundle
    encryption: CertBundle


@pytest.fixture(scope="session")
def keychain_identity(
    ca: Signed, ca_bundle: CertBundle, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[KeychainFixture]:
    """Provision a throwaway keychain with three identities.

    CN=httpx-pki-keychain-client is the plain one; CN=httpx-pki-keychain-dual
    is a dual key pair -- the same subject issued a signing and an encryption
    certificate, as a CA that escrows the encryption key produces, and the case
    that makes ``key_usage=`` selection necessary rather than convenient.

    All three are signed by the conftest CA so the mtls_server fixture accepts
    them, and imported with -A (any application may use the key) so the export
    needs no interactive consent. The keychain is prepended to the user search
    list for the session and fully removed afterwards.
    """
    signed = _sign(ca, KEYCHAIN_CN)
    signing = make_client_cert(
        DUAL_KEYCHAIN_CN,
        ca=ca_bundle,
        key_usage=["digital_signature"],
        extended_key_usage=["client_auth"],
    )
    encryption = make_client_cert(
        DUAL_KEYCHAIN_CN,
        ca=ca_bundle,
        key_usage=["key_encipherment"],
        extended_key_usage=["email_protection"],
    )

    keychain_dir = tmp_path_factory.mktemp("keychain")
    imports = [
        ("client.p12", signed.key, signed.cert, KEYCHAIN_CN),
        ("dual-sig.p12", signing.key, signing.cert, "dual signature"),
        ("dual-enc.p12", encryption.key, encryption.cert, "dual encryption"),
    ]
    kc_path = keychain_dir / "httpx-pki-test.keychain-db"

    _security("create-keychain", "-p", _KEYCHAIN_PW, str(kc_path))
    _security("set-keychain-settings", str(kc_path))  # never auto-lock
    _security("unlock-keychain", "-p", _KEYCHAIN_PW, str(kc_path))
    for filename, key, cert, label in imports:
        p12_path = keychain_dir / filename
        p12_path.write_bytes(_legacy_p12(key, cert, label))
        _security("import", str(p12_path), "-k", str(kc_path), "-P", "p12pw", "-A")
    # Since Sierra, key ACLs are additionally partition-scoped; open them up so
    # the export needs no prompt. Best-effort: not all versions need it.
    _security(
        "set-key-partition-list",
        "-S",
        "apple-tool:,apple:,unsigned:",
        "-s",
        "-k",
        _KEYCHAIN_PW,
        str(kc_path),
        check=False,
    )

    listing = _security("list-keychains", "-d", "user").stdout
    previous = [
        line.strip().strip('"') for line in listing.splitlines() if line.strip()
    ]
    _security("list-keychains", "-d", "user", "-s", str(kc_path), *previous)
    try:
        yield KeychainFixture(
            single=signed, signing=signing, encryption=encryption
        )
    finally:
        _security("list-keychains", "-d", "user", "-s", *previous, check=False)
        _security("delete-keychain", str(kc_path), check=False)


@requires_keychain
def test_keychain_list_finds_identity(keychain_identity: KeychainFixture) -> None:
    certs = list_macos_certificates()
    matching = [c for c in certs if c.subject_cn == KEYCHAIN_CN]
    assert len(matching) == 1
    assert matching[0].handle is None
    assert matching[0].thumbprint  # non-empty SHA-1 hex


@requires_keychain
def test_keychain_end_to_end_mtls(
    keychain_identity: KeychainFixture, mtls_server: object
) -> None:
    # The full proof: select from the real keychain, export, mount, and
    # complete a live mTLS handshake; then reload() re-exports successfully.
    server = mtls_server  # MTLSServer(url, ca_file)
    with PKIClient.from_macos_keychain(
        name=KEYCHAIN_CN, verify=str(server.ca_file)  # type: ignore[attr-defined]
    ) as session:
        assert session.cn == KEYCHAIN_CN
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]
        session.reload()
        assert session.cn == KEYCHAIN_CN
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]


@requires_keychain
def test_keychain_thumbprint_selection(keychain_identity: KeychainFixture) -> None:
    listed = [
        c for c in list_macos_certificates() if c.subject_cn == KEYCHAIN_CN
    ]
    # Exercise normalization: colon-separated, lowercase.
    raw = listed[0].thumbprint
    pretty = ":".join(raw[i : i + 2] for i in range(0, len(raw), 2)).lower()
    with PKIClient.from_macos_keychain(thumbprint=pretty) as session:
        assert session.cn == KEYCHAIN_CN


@requires_keychain
def test_keychain_not_found(keychain_identity: KeychainFixture) -> None:
    with pytest.raises(CertificateNotFoundError):
        PKIClient.from_macos_keychain(name="httpx-pki-no-such-cert")


# -- usage selection and intersecting selectors (all platforms) ---------------


def _candidate(
    common_name: str,
    label: str | None,
    *,
    key_usage: list[str],
    extended_key_usage: list[str] | None = None,
) -> MacCert:
    """A synthetic keychain record backed by a real certificate."""
    bundle = make_client_cert(
        common_name, key_usage=key_usage, extended_key_usage=extended_key_usage
    )
    info = cert_info(bundle.cert_pem)
    return MacCert(
        subject_cn=common_name,
        label=label,
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
    chosen = select_macos_certificate(DUAL, key_usage="digital_signature")
    assert chosen.label == "Signature"


def test_select_by_extended_key_usage() -> None:
    chosen = select_macos_certificate(DUAL, extended_key_usage="email_protection")
    assert chosen.label == "Encryption"


def test_name_and_usage_intersect() -> None:
    # The name alone matches both halves of the pair; the usage resolves it.
    with pytest.raises(AmbiguousCertificateError):
        select_macos_certificate(DUAL, name=DUAL_CN)
    chosen = select_macos_certificate(
        DUAL, name=DUAL_CN, key_usage="digital_signature"
    )
    assert chosen.label == "Signature"


def test_selectors_that_disagree_match_nothing() -> None:
    # Every selector must match: a thumbprint from one candidate and a name
    # from the other cannot both be satisfied. (Before selectors intersected,
    # the thumbprint won and the name was ignored.)
    with pytest.raises(CertificateNotFoundError):
        select_macos_certificate(
            DUAL, thumbprint=DUAL[0].thumbprint, name="Encryption"
        )


def test_usage_selector_skips_records_without_a_certificate() -> None:
    # The hand-built CANDIDATES carry no certificate, so nothing is known
    # about their usages and a usage selector cannot match them.
    with pytest.raises(CertificateNotFoundError):
        select_macos_certificate(CANDIDATES, key_usage="digital_signature")


def test_usage_accessors_default_to_empty() -> None:
    assert CANDIDATES[0].key_usage == frozenset()
    assert CANDIDATES[0].extended_key_usage == []
    assert DUAL[0].key_usage == frozenset({"digital_signature"})
    assert DUAL[0].extended_key_usage == ["client_auth"]


def test_unknown_usage_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown key usage"):
        select_macos_certificate(DUAL, key_usage="signing")


def test_ambiguous_message_shows_usage_and_expiry() -> None:
    with pytest.raises(AmbiguousCertificateError) as exc:
        select_macos_certificate(DUAL, name=DUAL_CN)
    message = str(exc.value)
    assert "key_usage=digital_signature" in message
    assert "key_usage=key_encipherment" in message
    assert "expires=" in message


@requires_keychain
def test_keychain_dual_pair_needs_a_usage(
    keychain_identity: KeychainFixture,
) -> None:
    # Both halves share the subject, so the name alone cannot resolve them.
    with pytest.raises(AmbiguousCertificateError) as exc:
        PKIClient.from_macos_keychain(name=DUAL_KEYCHAIN_CN)
    assert "key_usage=" in str(exc.value)


@requires_keychain
def test_keychain_selects_the_signing_half(
    keychain_identity: KeychainFixture, mtls_server: object
) -> None:
    server = mtls_server  # MTLSServer(url, ca_file)
    with PKIClient.from_macos_keychain(
        name=DUAL_KEYCHAIN_CN,
        key_usage="digital_signature",
        verify=str(server.ca_file),  # type: ignore[attr-defined]
    ) as session:
        assert session.cn == DUAL_KEYCHAIN_CN
        assert session.cert_info().key_usage == frozenset({"digital_signature"})
        assert (
            session.certificate.serial_number
            == keychain_identity.signing.cert.serial_number
        )
        # The server sees the half we selected, not whichever the keychain
        # happened to return first.
        resp = session.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert (
            resp.headers["X-Client-Fingerprint"]
            == session.cert_info().fingerprint_sha256
        )
        # reload() re-exports with the same selector.
        session.reload()
        assert session.cert_info().key_usage == frozenset({"digital_signature"})


@requires_keychain
def test_keychain_selects_by_extended_key_usage(
    keychain_identity: KeychainFixture,
) -> None:
    with PKIClient.from_macos_keychain(
        name=DUAL_KEYCHAIN_CN, extended_key_usage="email_protection"
    ) as session:
        assert (
            session.certificate.serial_number
            == keychain_identity.encryption.cert.serial_number
        )


@requires_keychain
def test_keychain_listing_reports_usages(
    keychain_identity: KeychainFixture,
) -> None:
    listed = [
        c for c in list_macos_certificates() if c.subject_cn == DUAL_KEYCHAIN_CN
    ]
    assert len(listed) == 2
    assert {frozenset(c.key_usage) for c in listed} == {
        frozenset({"digital_signature"}),
        frozenset({"key_encipherment"}),
    }
    for candidate in listed:
        assert candidate.info is not None
        assert candidate.certificate is not None
        assert candidate.handle is None  # released before returning


def test_records_are_hashable_and_compare_on_identity() -> None:
    # list_macos_certificates() results must survive set()/dict use; the
    # parsed certificate and info are derived, so they stay out of equality.
    assert len(set(DUAL)) == 2
    plain = MacCert(
        subject_cn=DUAL[0].subject_cn,
        label=DUAL[0].label,
        thumbprint=DUAL[0].thumbprint,
    )
    assert plain == DUAL[0]
    assert len({plain, DUAL[0]}) == 1
