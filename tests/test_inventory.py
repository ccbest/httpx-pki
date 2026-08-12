"""Tests for inventory(): directory classification, pairing, and the CLI."""

from __future__ import annotations

import ast
import base64
import getpass
import os
import sys
import textwrap
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from httpx_pki import CertificateLoadError, _inventory, inventory
from httpx_pki.__main__ import main
from httpx_pki.testing import make_client_cert
from tests.conftest import P12_PASSWORD, Signed

KEY_PASSWORD = b"keypw"

DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM


def _encrypted_key(signed: Signed) -> bytes:
    return signed.key.private_bytes(
        PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(KEY_PASSWORD),
    )


def _der_key(signed: Signed, password: bytes | None = None) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.NoEncryption()
        if password is None
        else serialization.BestAvailableEncryption(password)
    )
    return signed.key.private_bytes(
        DER, serialization.PrivateFormat.PKCS8, encryption
    )


def _write(directory: Path, **files: bytes) -> Path:
    for name, data in files.items():
        (directory / name.replace("_", ".")).write_bytes(data)
    return directory


# -- PKCS#7 --------------------------------------------------------------------
# `cryptography` reads certificate-only PKCS#7 but will not write it, and a
# .p7b is exactly what a Windows or Java export drops in such a folder. The
# structure is small enough to encode by hand: a SignedData carrying nothing
# but certificates, which is all a chain bundle ever is.

_SIGNED_DATA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
_DATA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])


def _tlv(tag: int, payload: bytes) -> bytes:
    """One DER tag-length-value, with the length in short or long form."""
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    width = (len(payload).bit_length() + 7) // 8
    return bytes([tag, 0x80 | width]) + len(payload).to_bytes(width, "big") + payload


def _pkcs7(*certs: x509.Certificate) -> bytes:
    """*certs* as a certificate-only PKCS#7 blob, DER."""
    signed_data = _tlv(
        0x30,
        _tlv(0x02, b"\x01")  # version
        + _tlv(0x31, b"")  # digestAlgorithms: none
        + _tlv(0x30, _tlv(0x06, _DATA_OID))  # encapContentInfo: data
        + _tlv(0xA0, b"".join(cert.public_bytes(DER) for cert in certs))
        + _tlv(0x31, b""),  # signerInfos: none
    )
    return _tlv(0x30, _tlv(0x06, _SIGNED_DATA_OID) + _tlv(0xA0, signed_data))


def _armor(label: str, der: bytes) -> bytes:
    """*der* wrapped in a PEM block, the way a tool that emits text would."""
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()


def test_pair_across_files(client: Signed, ca: Signed, tmp_path: Path) -> None:
    # The motivating case: cert in one file, encrypted key in another, chain
    # in a third, none with a helpful extension.
    _write(
        tmp_path,
        client_pem=client.cert_pem,
        client_ukey=_encrypted_key(client),
        chain_crt=ca.cert_pem,
    )
    report = inventory(tmp_path, passwords=["wrong-first", KEY_PASSWORD])
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
    report = inventory(tmp_path)
    [identity] = report.identities
    assert identity.bundle_file == "bundle.pem"
    assert identity.suggestion == 'PKIClient("bundle.pem")'


def test_pkcs12_identity(client_p12: bytes, tmp_path: Path) -> None:
    _write(tmp_path, export_p12=client_p12)
    report = inventory(tmp_path, passwords=[P12_PASSWORD])
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
    report = inventory(tmp_path, passwords=["wrong"])
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
    text = str(inventory(tmp_path, passwords=[P12_PASSWORD, KEY_PASSWORD]))
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
    report = inventory(tmp_path, passwords=[P12_PASSWORD])
    assert len(report.identities) == 2
    pair = next(i for i in report.identities if i.key_file == "client.key")
    assert pair.same_certificate_as == "export.p12"


def test_partly_locked_file_lands_in_locked(client: Signed, tmp_path: Path) -> None:
    # The layout `openssl pkcs12 -out client.pem` writes: both halves in one
    # file, the key encrypted. Reporting only the certificate would call it an
    # orphan and never offer the password prompt that opens it.
    _write(tmp_path, bundle_pem=_encrypted_key(client) + client.cert_pem)
    report = inventory(tmp_path, passwords=["wrong"])
    assert not report.usable
    [entry] = report.locked
    assert entry.name == "bundle.pem"
    assert "1 certificate" in entry.summary
    assert "encrypted private key" in entry.summary
    assert not report.unpaired  # not an orphaned certificate: its key is right there
    # With the password it is one self-contained source.
    opened = inventory(tmp_path, passwords=[KEY_PASSWORD])
    assert not opened.locked
    [identity] = opened.identities
    assert identity.suggestion == 'PKIClient("bundle.pem", password=...)'


def test_self_contained_file_beats_a_stray_key_copy(
    client: Signed, tmp_path: Path
) -> None:
    # A loose copy of the key sorts first, but the file holding both halves
    # loads on its own -- suggesting the two-file call for it would be a
    # pairing nobody needs to make.
    _write(
        tmp_path,
        a_copy_key=client.key_pem,
        bundle_pem=client.key_pem + client.cert_pem,
    )
    report = inventory(tmp_path)
    [identity] = report.identities
    assert identity.bundle_file == "bundle.pem"
    assert identity.suggestion == 'PKIClient("bundle.pem")'
    # The spare copy is named rather than passed over.
    assert any("a.copy.key" in note and "second copy" in note for note in report.notes)


@pytest.mark.skipif(sys.platform == "win32", reason="filename is illegal on NTFS")
def test_hostile_filename_is_neutralized(client: Signed, tmp_path: Path) -> None:
    # A filename out of somebody else's archive is as untrusted as the
    # certificates inside it: the escape must not reach the terminal, and the
    # quote must not end the suggestion's string literal early.
    (tmp_path / 'we"ird\x1b[31m.pem').write_bytes(client.key_pem + client.cert_pem)
    [identity] = inventory(tmp_path).identities
    text = str(inventory(tmp_path))
    assert "\x1b" not in text
    assert identity.suggestion == 'PKIClient("we\\"ird\\u001b[31m.pem")'
    # The suggestion is still the real filename, so it still works.
    assert ast.literal_eval(
        identity.suggestion.removeprefix("PKIClient(").removesuffix(")")
    ) == 'we"ird\x1b[31m.pem'


def test_unpaired_cert_and_key(client: Signed, ca: Signed, tmp_path: Path) -> None:
    other = Signed(ca.key, ca.cert)  # a cert file with no key alongside
    _write(tmp_path, stray_crt=other.cert_pem, stray_key=client.key_pem)
    report = inventory(tmp_path)
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
    report = inventory(tmp_path)
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
    report = inventory(tmp_path)
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
    report = inventory(tmp_path)
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
    report = inventory(tmp_path)
    assert report.skipped_subdirs == 1
    assert not report.identities


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file types")
def test_irregular_entries_named_not_read(client: Signed, tmp_path: Path) -> None:
    # A FIFO would block the read forever and a broken link has nothing
    # behind it, so neither is opened -- but neither may vanish either: a
    # name in `ls` that the report does not mention reads as a broken tool.
    _write(tmp_path, bundle_pem=client.key_pem + client.cert_pem)
    os.mkfifo(tmp_path / "pipe.pem")
    (tmp_path / "gone.p12").symlink_to(tmp_path / "not-there.p12")
    report = inventory(tmp_path)
    assert {f.name for f in report.files} == {"bundle.pem", "gone.p12", "pipe.pem"}
    summaries = {f.name: f.summary for f in report.files}
    assert "broken symlink" in summaries["gone.p12"]
    assert "not a regular file" in summaries["pipe.pem"]
    assert sum("not read" in note for note in report.notes) == 2
    # The real file is still inventoried as usual.
    [identity] = report.identities
    assert identity.bundle_file == "bundle.pem"


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symlinks")
def test_symlinked_file_is_followed(client: Signed, tmp_path: Path) -> None:
    # Somebody linked it in on purpose: from where they stand the certificate
    # is in this folder, and the report names it as they see it.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "real.pem").write_bytes(client.key_pem + client.cert_pem)
    (tmp_path / "linked.pem").symlink_to(elsewhere / "real.pem")
    report = inventory(tmp_path)
    [identity] = report.identities
    assert identity.bundle_file == "linked.pem"
    assert identity.suggestion == 'PKIClient("linked.pem")'
    assert report.skipped_subdirs == 1  # the directory it points into


def test_garbage_and_empty(tmp_path: Path) -> None:
    _write(tmp_path, junk_bin=b"\x00\x01garbage")
    report = inventory(tmp_path)
    assert not report.usable
    assert any("junk.bin" in note for note in report.notes)
    with pytest.raises(CertificateLoadError, match="not a directory"):
        inventory(tmp_path / "missing")


def test_cli_inventory_exit_codes(
    client: Signed,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write(tmp_path, client_pem=client.cert_pem, client_ukey=_encrypted_key(client))
    monkeypatch.setenv("INVENTORY_PW", KEY_PASSWORD.decode())
    assert main(["inventory", str(tmp_path), "--password-env", "INVENTORY_PW"]) == 0
    assert "from_key_pair" in capsys.readouterr().out
    # Nothing loadable: non-zero, but still a report rather than an error.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["inventory", str(empty)]) == 1
    assert "0 identities" in capsys.readouterr().out


def test_cli_prompts_for_a_locked_file(
    client: Signed,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A file holding a key back is offered a prompt, whatever else it gave up.
    _write(tmp_path, bundle_pem=_encrypted_key(client) + client.cert_pem)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: KEY_PASSWORD.decode())
    assert main(["inventory", str(tmp_path)]) == 0
    assert 'PKIClient("bundle.pem", password=...)' in capsys.readouterr().out


# -- DER: what a Windows or Java export drops in the folder --------------------


def test_der_certificate_and_key_pair(client: Signed, tmp_path: Path) -> None:
    # No PEM armor anywhere: both halves are raw DER under extensions that
    # say nothing, which is the ordinary shape of a Windows export.
    _write(
        tmp_path,
        client_cer=client.cert.public_bytes(DER),
        client_der=_der_key(client),
    )
    [identity] = inventory(tmp_path).identities
    assert identity.certificate_file == "client.cer"
    assert identity.key_file == "client.der"
    assert identity.suggestion == (
        'from_key_pair(certificate="client.cer", private_key="client.der")'
    )


def test_der_encrypted_key_opens_and_locks(client: Signed, tmp_path: Path) -> None:
    _write(
        tmp_path,
        client_cer=client.cert.public_bytes(DER),
        client_der=_der_key(client, KEY_PASSWORD),
    )
    [identity] = inventory(tmp_path, passwords=["wrong", KEY_PASSWORD]).identities
    assert identity.needs_password
    assert identity.password_index == 2
    assert "password=..." in identity.suggestion
    # An encrypted DER key nothing opens is locked, not mistaken for garbage.
    locked = inventory(tmp_path, passwords=["wrong"])
    assert not locked.identities
    assert [f.name for f in locked.locked] == ["client.der"]
    assert "encrypted private key" in locked.locked[0].summary


def test_der_pkcs7_is_read_as_certificates(ca: Signed, tmp_path: Path) -> None:
    _write(tmp_path, chain_p7b=_pkcs7(ca.cert))
    [entry] = inventory(tmp_path).unpaired
    assert entry.name == "chain.p7b"
    assert entry.kind == "certificates"
    assert "all CA certificates" in entry.summary


def test_pem_pkcs7_is_read_as_certificates(ca: Signed, tmp_path: Path) -> None:
    _write(tmp_path, chain_p7c=_armor("PKCS7", _pkcs7(ca.cert)))
    [entry] = inventory(tmp_path).unpaired
    assert entry.name == "chain.p7c"
    assert "1 certificate" in entry.summary


def test_der_garbage_is_named_unknown(tmp_path: Path) -> None:
    # Starts like DER and is nothing: every parse must fail without the file
    # being dropped or blamed on a password.
    _write(tmp_path, blob_der=b"\x30\x82\x00\x05hello")
    report = inventory(tmp_path, passwords=["irrelevant"])
    assert [f.kind for f in report.files] == ["unknown"]
    assert not report.locked
    assert any(
        "blob.der" in note and "not recognizable" in note for note in report.notes
    )


def test_pkcs12_found_when_the_header_sniff_misses(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The PFX sniff is a shortcut, not the authority: with it defeated, the
    # full parse still has to recognize the bundle.
    monkeypatch.setattr(_inventory, "_PFX_VERSION", b"\xff\xff\xff")
    _write(tmp_path, export_p12=client_p12)
    [identity] = inventory(tmp_path, passwords=[P12_PASSWORD]).identities
    assert identity.bundle_file == "export.p12"


# -- PEM blocks that do not parse ----------------------------------------------


def test_broken_blocks_do_not_cost_the_good_ones(
    client: Signed, tmp_path: Path
) -> None:
    # Armor around nonsense, of every label the scan knows. Each is skipped
    # on its own; the usable pair in the same file still comes out.
    rubbish = base64.b64encode(b"not a key, not a certificate, not a request")
    broken = b"".join(
        b"-----BEGIN " + label + b"-----\n"
        + rubbish
        + b"\n-----END " + label + b"-----\n"
        for label in (b"PRIVATE KEY", b"CERTIFICATE", b"PKCS7", b"CERTIFICATE REQUEST")
    )
    _write(tmp_path, mixed_pem=broken + client.key_pem + client.cert_pem)
    report = inventory(tmp_path)
    [identity] = report.identities
    assert identity.bundle_file == "mixed.pem"
    assert not report.locked  # unreadable is not the same as password-protected


def test_pem_armor_with_no_known_blocks(tmp_path: Path) -> None:
    _write(tmp_path, params_pem=_armor("DH PARAMETERS", b"\x30\x03\x02\x01\x00"))
    report = inventory(tmp_path)
    assert not report.usable
    assert any(
        "params.pem" in note and "no recognizable blocks" in note
        for note in report.notes
    )


# -- pairing and de-duplication ------------------------------------------------


def test_two_identities_in_one_file(ca: Signed, tmp_path: Path) -> None:
    # A file somebody built with `cat`: two whole identities in one blob. Each
    # key finds its own certificate rather than the first one in the file.
    first = make_client_cert("first", ca=None)
    second = make_client_cert("second", ca=None)
    _write(
        tmp_path,
        both_pem=first.key_pem + first.cert_pem + second.key_pem + second.cert_pem,
    )
    report = inventory(tmp_path)
    assert len(report.identities) == 2
    assert {i.info.common_name for i in report.identities} == {"first", "second"}
    assert all(i.bundle_file == "both.pem" for i in report.identities)


def test_the_same_certificate_in_two_files_is_one_identity(
    client: Signed, tmp_path: Path
) -> None:
    _write(tmp_path, a_pem=client.key_pem + client.cert_pem, b_pem=client.cert_pem)
    report = inventory(tmp_path)
    [identity] = report.identities
    assert identity.bundle_file == "a.pem"
    # The second copy is a certificate with no key of its own, and nothing
    # more is claimed about it: it neither issues anything nor is a CA.
    [entry] = report.unpaired
    assert entry.name == "b.pem"
    assert entry.summary.endswith("with no matching key here")


def test_a_ca_false_certificate_is_not_a_trust_bundle(
    ca: Signed, tmp_path: Path
) -> None:
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(ca.cert.subject)
        .public_key(ca.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ca.cert.not_valid_before_utc)
        .not_valid_after(ca.cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca.key, hashes.SHA256())
    )
    _write(tmp_path, stray_pem=leaf.public_bytes(PEM))
    [entry] = inventory(tmp_path).unpaired
    assert "trust bundle" not in entry.summary


def test_pkcs12_with_two_identities_names_the_selector(
    dual_p12: bytes, tmp_path: Path
) -> None:
    # Two identities in one bundle: loading it needs a choice, and the
    # suggested call has to say so rather than look like a one-liner.
    _write(tmp_path, dual_p12=dual_p12)
    report = inventory(tmp_path, passwords=[P12_PASSWORD])
    assert len(report.identities) == 2
    assert all(
        "identity=httpx_pki.for_mtls" in identity.suggestion
        for identity in report.identities
    )


def test_pkcs12_names_a_chain_file(
    client_p12: bytes, ca: Signed, tmp_path: Path
) -> None:
    # The bundle holds no issuer, but the folder does: the report pairs them
    # and the issuer file stops being a mystery.
    _write(tmp_path, export_p12=client_p12, issuer_pem=ca.cert_pem)
    report = inventory(tmp_path, passwords=[P12_PASSWORD])
    [identity] = report.identities
    assert identity.chain_file == "issuer.pem"
    assert 'chain="issuer.pem"' in identity.suggestion
    assert not report.unpaired


# -- passwords, and files that cannot be read ----------------------------------


def test_a_single_password_need_not_be_a_list(
    client_p12: bytes, tmp_path: Path
) -> None:
    _write(tmp_path, export_p12=client_p12)
    assert inventory(tmp_path, passwords=P12_PASSWORD).usable
    # A None among several is dropped rather than counted as a position.
    report = inventory(tmp_path, passwords=[None, P12_PASSWORD])
    assert report.identities[0].password_index == 1


def test_oversized_file_is_named_not_read(tmp_path: Path) -> None:
    with open(tmp_path / "huge.pem", "wb") as handle:
        handle.truncate(10 * 1024 * 1024 + 1)
    report = inventory(tmp_path)
    assert [f.kind for f in report.files] == ["oversized"]
    assert any("huge.pem" in note and "too large" in note for note in report.notes)


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="needs POSIX permissions and a user that they apply to",
)
def test_unreadable_file_is_named(client: Signed, tmp_path: Path) -> None:
    path = tmp_path / "no-access.pem"
    path.write_bytes(client.cert_pem)
    path.chmod(0)
    report = inventory(tmp_path)
    assert [f.kind for f in report.files] == ["unreadable"]
    assert any("could not be read" in note for note in report.notes)


# -- text dumps ----------------------------------------------------------------


def test_dump_without_a_fingerprint(tmp_path: Path) -> None:
    # The certutil spelling, and nothing in it to match on.
    _write(tmp_path, info_txt=b"X509 Certificate:\nVersion: 3\nSerial Number: 01\n")
    report = inventory(tmp_path)
    assert [f.kind for f in report.files] == ["dump"]
    assert any("matches nothing here" in note for note in report.notes)


def test_dump_serial_number_is_not_mistaken_for_a_fingerprint(
    client: Signed, tmp_path: Path
) -> None:
    # Dumps print serial numbers in the same colon-separated byte pairs as
    # fingerprints. Only a digest-length run may be matched on -- claiming the
    # wrong file is worse than claiming none.
    serial = ":".join(f"{byte:02X}" for byte in range(17))  # 34 hex characters
    print_ = client.cert.fingerprint(hashes.SHA256()).hex(":").upper()
    _write(
        tmp_path,
        bundle_pem=client.key_pem + client.cert_pem,
        info_txt=f"Certificate:\n Serial: {serial}\n SHA256: {print_}\n".encode(),
    )
    report = inventory(tmp_path)
    assert any(
        "info.txt" in note and "matches bundle.pem" in note for note in report.notes
    )


def test_dump_naming_a_certificate_that_is_not_here(
    client: Signed, ca: Signed, tmp_path: Path
) -> None:
    absent = ca.cert.fingerprint(hashes.SHA256()).hex(":").upper()
    _write(
        tmp_path,
        bundle_pem=client.key_pem + client.cert_pem,
        info_txt=f"Certificate:\n    SHA256 Fingerprint={absent}\n".encode(),
    )
    report = inventory(tmp_path)
    assert any(
        "info.txt" in note and "matches nothing here" in note for note in report.notes
    )


# -- the laid-out report -------------------------------------------------------


def test_report_renders_every_section(
    client: Signed,
    client_p12: bytes,
    ca: Signed,
    server_cert: Signed,
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        export_p12=client_p12,
        issuer_pem=ca.cert_pem,
        old_ukey=_encrypted_key(client),
        stray_crt=server_cert.cert_pem,
        junk_bin=b"\x00\x01garbage",
    )
    (tmp_path / "archive").mkdir()
    report = inventory(tmp_path, passwords=[P12_PASSWORD])
    text = str(report)
    assert repr(report) == text  # the REPL shows the report, not a dataclass dump
    assert "chain         issuer.pem" in text
    assert "LOCKED" in text and "UNPAIRED" in text and "NOTES" in text
    assert "1 subdirectory not inventoried" in text
    (tmp_path / "archive-2019").mkdir()
    assert "2 subdirectories not inventoried" in str(
        inventory(tmp_path, passwords=[P12_PASSWORD])
    )


def test_expired_identity_is_labeled(tmp_path: Path) -> None:
    # The renewal nobody deleted: still loadable, and the report says plainly
    # that presenting it is pointless.
    stale = make_client_cert("old-client", ca=None, expired=True)
    _write(tmp_path, old_pem=stale.key_pem + stale.cert_pem)
    text = str(inventory(tmp_path))
    assert "EXPIRED" in text
    assert "expires" not in text


# -- the command line ----------------------------------------------------------


def test_cli_reports_an_unset_password_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NO_SUCH_INVENTORY_PW", raising=False)
    with pytest.raises(SystemExit, match="NO_SUCH_INVENTORY_PW is not set"):
        main(["inventory", str(tmp_path), "--password-env", "NO_SUCH_INVENTORY_PW"])


def test_cli_prompt_can_be_skipped(
    client: Signed,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Blank at the prompt means "I do not have it": the file stays locked and
    # the report is still printed.
    _write(tmp_path, old_ukey=_encrypted_key(client))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "")
    assert main(["inventory", str(tmp_path)]) == 1
    assert "LOCKED" in capsys.readouterr().out


def test_cli_error_on_a_missing_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["inventory", str(tmp_path / "nowhere")]) == 2
    assert "error:" in capsys.readouterr().err
