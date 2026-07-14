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
    list_macos_certificates,
    select_macos_certificate,
)
from httpx_pki._keychain import load_macos_pkcs12
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


def test_select_by_predicate() -> None:
    chosen = select_macos_certificate(
        CANDIDATES, predicate=lambda c: c.label == "prod"
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


@pytest.fixture(scope="session")
def keychain_identity(
    ca: Signed, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Signed]:
    """Provision CN=httpx-pki-keychain-client into a throwaway keychain.

    The identity is signed by the conftest CA so the mtls_server fixture
    accepts it, and imported with -A (any application may use the key) so the
    export needs no interactive consent. The keychain is prepended to the user
    search list for the session and fully removed afterwards.
    """
    signed = _sign(ca, KEYCHAIN_CN)
    # macOS `security import` cannot read a PKCS#12 encrypted with the modern
    # AES/PBKDF2 defaults (BestAvailableEncryption); use the legacy 3DES/SHA-1
    # PBE the Security framework understands.
    legacy_encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50_000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(b"p12pw")
    )
    p12_path = tmp_path_factory.mktemp("keychain") / "client.p12"
    p12_path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=KEYCHAIN_CN.encode(),
            key=signed.key,
            cert=signed.cert,
            cas=None,
            encryption_algorithm=legacy_encryption,
        )
    )
    kc_path = tmp_path_factory.mktemp("keychain") / "httpx-pki-test.keychain-db"

    _security("create-keychain", "-p", _KEYCHAIN_PW, str(kc_path))
    _security("set-keychain-settings", str(kc_path))  # never auto-lock
    _security("unlock-keychain", "-p", _KEYCHAIN_PW, str(kc_path))
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
        yield signed
    finally:
        _security("list-keychains", "-d", "user", "-s", *previous, check=False)
        _security("delete-keychain", str(kc_path), check=False)


@requires_keychain
def test_keychain_list_finds_identity(keychain_identity: Signed) -> None:
    certs = list_macos_certificates()
    matching = [c for c in certs if c.subject_cn == KEYCHAIN_CN]
    assert len(matching) == 1
    assert matching[0].handle is None
    assert matching[0].thumbprint  # non-empty SHA-1 hex


@requires_keychain
def test_keychain_end_to_end_mtls(
    keychain_identity: Signed, mtls_server: object
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
def test_keychain_thumbprint_selection(keychain_identity: Signed) -> None:
    listed = [
        c for c in list_macos_certificates() if c.subject_cn == KEYCHAIN_CN
    ]
    # Exercise normalization: colon-separated, lowercase.
    raw = listed[0].thumbprint
    pretty = ":".join(raw[i : i + 2] for i in range(0, len(raw), 2)).lower()
    with PKIClient.from_macos_keychain(thumbprint=pretty) as session:
        assert session.cn == KEYCHAIN_CN


@requires_keychain
def test_keychain_not_found(keychain_identity: Signed) -> None:
    with pytest.raises(CertificateNotFoundError):
        PKIClient.from_macos_keychain(name="httpx-pki-no-such-cert")
