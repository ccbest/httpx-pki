"""Tests for scan(): directory classification, pairing, and the CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from httpx_pki import CertificateLoadError, scan
from httpx_pki.__main__ import main
from tests.conftest import P12_PASSWORD, Signed

KEY_PASSWORD = b"keypw"


def _encrypted_key(signed: Signed) -> bytes:
    return signed.key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(KEY_PASSWORD),
    )


def _write(directory: Path, **files: bytes) -> Path:
    for name, data in files.items():
        (directory / name.replace("_", ".")).write_bytes(data)
    return directory


def test_pair_across_files(client: Signed, ca: Signed, tmp_path: Path) -> None:
    # The motivating case: cert in one file, encrypted key in another, chain
    # in a third, none with a helpful extension.
    _write(
        tmp_path,
        client_pem=client.cert_pem,
        client_ukey=_encrypted_key(client),
        chain_crt=ca.cert_pem,
    )
    report = scan(tmp_path, passwords=["wrong-first", KEY_PASSWORD])
    assert report.usable
    [identity] = report.identities
    assert identity.certificate_file == "client.pem"
    assert identity.key_file == "client.ukey"
    assert identity.chain_file == "chain.crt"
    assert identity.password_index == 2
    assert 'from_key_pair(certificate="client.pem"' in identity.suggestion
    assert 'private_key="client.ukey"' in identity.suggestion
    assert "password=..." in identity.suggestion
    assert 'chain="chain.crt"' in identity.suggestion
    # The chain file is claimed by the identity, not left as a mystery.
    assert not report.unpaired


def test_single_file_bundle_suggests_single_source(
    client: Signed, tmp_path: Path
) -> None:
    _write(tmp_path, bundle_pem=client.key_pem + client.cert_pem)
    report = scan(tmp_path)
    [identity] = report.identities
    assert identity.bundle_file == "bundle.pem"
    assert identity.suggestion == 'PKIClient("bundle.pem")'


def test_pkcs12_identity(client_p12: bytes, tmp_path: Path) -> None:
    _write(tmp_path, export_p12=client_p12)
    report = scan(tmp_path, passwords=[P12_PASSWORD])
    [identity] = report.identities
    assert identity.bundle_file == "export.p12"
    assert identity.password_index == 1
    assert identity.suggestion == 'PKIClient("export.p12", password=...)'


def test_locked_files_reported_not_skipped(
    client: Signed, client_p12: bytes, tmp_path: Path
) -> None:
    # The design rule: a file a password fails to open lands in LOCKED,
    # because silently dropping it is the notepad failure mode again.
    _write(tmp_path, legacy_p12=client_p12, old_ukey=_encrypted_key(client))
    report = scan(tmp_path, passwords=["wrong"])
    assert not report.usable
    assert {f.name for f in report.locked} == {"legacy.p12", "old.ukey"}
    assert all("none of the given passwords" in f.summary for f in report.locked)
    # Every file is accounted for somewhere.
    assert {f.name for f in report.files} == {"legacy.p12", "old.ukey"}


def test_passwords_never_appear_in_report(
    client: Signed, client_p12: bytes, tmp_path: Path
) -> None:
    # The report names password positions, never values: it will be pasted
    # into tickets and terminal logs.
    _write(
        tmp_path,
        export_p12=client_p12,
        client_pem=client.cert_pem,
        client_ukey=_encrypted_key(client),
    )
    text = str(scan(tmp_path, passwords=[P12_PASSWORD, KEY_PASSWORD]))
    assert P12_PASSWORD not in text
    assert KEY_PASSWORD.decode() not in text
    assert "password #1" in text and "password #2" in text


def test_same_certificate_grouped(
    client: Signed, client_p12: bytes, tmp_path: Path
) -> None:
    # The same leaf reachable as a PKCS#12 and as extracted halves is one
    # certificate with two routes, and the report must say so rather than
    # present two mystery identities.
    _write(
        tmp_path,
        export_p12=client_p12,
        client_pem=client.cert_pem,
        client_key=client.key_pem,
    )
    report = scan(tmp_path, passwords=[P12_PASSWORD])
    assert len(report.identities) == 2
    pair = next(i for i in report.identities if i.key_file == "client.key")
    assert pair.same_certificate_as == "export.p12"


def test_unpaired_cert_and_key(client: Signed, ca: Signed, tmp_path: Path) -> None:
    other = Signed(ca.key, ca.cert)  # a cert file with no key alongside
    _write(tmp_path, stray_crt=other.cert_pem, stray_key=client.key_pem)
    report = scan(tmp_path)
    assert not report.identities
    summaries = {f.name: f.summary for f in report.unpaired}
    assert "no matching key here" in summaries["stray.crt"]
    assert "no matching certificate" in summaries["stray.key"]


def test_unpaired_issuer_named(client: Signed, ca: Signed, tmp_path: Path) -> None:
    # A cert-only file holding an identity's issuer is an alternative
    # chain=/verify= source, not a mystery -- but only when it was not
    # already claimed as the suggested chain (a second copy here).
    _write(
        tmp_path,
        bundle_pem=client.key_pem + client.cert_pem + ca.cert_pem,
        issuer_pem=ca.cert_pem,
    )
    report = scan(tmp_path)
    [entry] = report.unpaired
    assert entry.name == "issuer.pem"
    assert "holds the issuer of bundle.pem" in entry.summary


def test_csr_note_names_the_key(client: Signed, tmp_path: Path) -> None:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(client.cert.subject)
        .sign(client.key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    # The legacy Windows/keytool label must classify the same way.
    legacy = csr.replace(b"CERTIFICATE REQUEST", b"NEW CERTIFICATE REQUEST")
    _write(
        tmp_path,
        bundle_pem=client.key_pem + client.cert_pem,
        request_csr=legacy,
    )
    report = scan(tmp_path)
    assert any(
        "request.csr" in note and "for the key of bundle.pem" in note
        for note in report.notes
    )


def test_dump_note_matches_fingerprint(client: Signed, tmp_path: Path) -> None:
    fingerprint = client.cert.fingerprint(hashes.SHA256()).hex(":").upper()
    dump = (
        "Certificate:\n    Data:\n"
        f"    Fingerprint (SHA-256):\n        {fingerprint}\n"
    )
    _write(
        tmp_path,
        bundle_pem=client.key_pem + client.cert_pem,
        info_txt=dump.encode(),
    )
    report = scan(tmp_path)
    assert any(
        "info.txt" in note and "matches bundle.pem" in note
        for note in report.notes
    )


def test_subdirectories_counted_not_descended(
    client: Signed, tmp_path: Path
) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "bundle.pem").write_bytes(
        client.key_pem + client.cert_pem
    )
    report = scan(tmp_path)
    assert report.skipped_subdirs == 1
    assert not report.identities


def test_garbage_and_empty(tmp_path: Path) -> None:
    _write(tmp_path, junk_bin=b"\x00\x01garbage")
    report = scan(tmp_path)
    assert not report.usable
    assert any("junk.bin" in note for note in report.notes)
    with pytest.raises(CertificateLoadError, match="not a directory"):
        scan(tmp_path / "missing")


def test_cli_scan_exit_codes(
    client: Signed,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write(tmp_path, client_pem=client.cert_pem, client_ukey=_encrypted_key(client))
    monkeypatch.setenv("SCAN_PW", KEY_PASSWORD.decode())
    assert main(["scan", str(tmp_path), "--password-env", "SCAN_PW"]) == 0
    assert "from_key_pair" in capsys.readouterr().out
    # Nothing loadable: non-zero, but still a report rather than an error.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["scan", str(empty)]) == 1
    assert "0 identities" in capsys.readouterr().out
