"""Finding the usable identities in a directory of certificate exports.

:func:`scan` is for the folder a CA hands over: a mix of PKCS#12 bundles,
extracted PEM halves, chain bundles, and issuance artifacts, under extensions
that promise nothing. It classifies every file by content, pairs private keys
with certificates across files (by public key, the way the loaders do), and
reports the constructor call each pairing amounts to -- the work otherwise
done by opening files one at a time in an editor.

Scan classifies and pairs; it does not audit. Once it names a source,
:func:`~httpx_pki.explain` is the tool for what would stop that source
working. And it never *builds* anything: a folder like this routinely holds
several identities, expired renewals, and stray trust bundles, so choosing
one silently is exactly the mistake the report exists to prevent.

Every file the scan touches lands in the report -- as an identity's part, or
as locked, unpaired, or a note. A file that a password fails to open is
reported as locked rather than skipped: silence about a file is the failure
mode this module exists to remove.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from ._audit import _key_description, _plural
from ._exceptions import CertificateLoadError
from ._material import (
    _PEM_BLOCK,
    CertInfo,
    Password,
    _spki,
    certificate_info,
    encode_password,
)
from ._pkcs12 import _Loaded, load_bundle

_WIDTH = 11  # the label column, matching the explain() report

# Beyond this size a file is not certificate material -- the largest honest
# inhabitant of such a folder is a full trust bundle, well under a megabyte.
_MAX_FILE_SIZE = 10 * 1024 * 1024

# A PFX header: SEQUENCE, then version INTEGER 3. The version sits right
# after the outer tag and length, so it appears in the first handful of
# bytes; the sniff keeps "wrong password" (a PKCS#12 nothing opens) apart
# from "not a PKCS#12 at all" without parsing either.
_PFX_VERSION = b"\x02\x01\x03"

_CSR_LABELS = (b"CERTIFICATE REQUEST", b"NEW CERTIFICATE REQUEST")


def _clean(text: str) -> str:
    """Strip control characters from an untrusted certificate string.

    Same rule as the explain() report: names inside certificates are
    attacker-controlled bytes that a terminal would otherwise act on.
    """
    return "".join(ch for ch in text if ch.isprintable() or ch == " ")


@dataclass(frozen=True)
class ScannedFile:
    """One file as the scan classified it.

    ``kind`` is a stable token (``"pkcs12"``, ``"pem"``, ``"certificates"``,
    ``"key"``, ``"csr"``, ``"dump"``, ``"locked"``, ``"unknown"``,
    ``"unreadable"``, ``"oversized"``); ``summary`` is the prose the report
    prints for it. ``password_index`` is the 1-based position of the password
    that opened the file, ``None`` when none was needed (or none worked).
    """

    name: str
    kind: str
    summary: str
    password_index: int | None = None


@dataclass(frozen=True)
class ScanIdentity:  # pylint: disable=too-many-instance-attributes
    """One presentable identity the directory holds, and how to load it.

    Exactly one of ``bundle_file`` (a self-contained source: a PKCS#12, or a
    PEM holding both halves) and the ``certificate_file``/``key_file`` pair
    is set. ``suggestion`` is the constructor call the parts amount to, with
    ``...`` standing where the password goes -- the report never repeats a
    password, it names its position.
    """

    info: CertInfo
    key_label: str
    bundle_file: str | None = None
    certificate_file: str | None = None
    key_file: str | None = None
    chain_file: str | None = None
    password_index: int | None = None
    needs_password: bool = False
    same_certificate_as: str | None = None
    suggestion: str = ""

    def lines(self) -> list[str]:
        """The identity as report rows (first row is the heading)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        validity = (
            f"EXPIRED {self.info.not_valid_after:%Y-%m-%d}"
            if self.info.not_valid_after < now
            else f"expires {self.info.not_valid_after:%Y-%m-%d}"
        )
        name = _clean(self.info.common_name or self.info.distinguished_name)
        rows = [f"{name}   {self.key_label}   {validity}"]
        opened = (
            f" (password #{self.password_index})"
            if self.password_index is not None
            else ""
        )
        if self.bundle_file is not None:
            rows.append(f"  bundle        {self.bundle_file}{opened}")
        else:
            rows.append(f"  certificate   {self.certificate_file}")
            state = (
                f" (encrypted — opened with password #{self.password_index})"
                if self.password_index is not None
                else " (encrypted)" if self.needs_password else ""
            )
            rows.append(f"  private key   {self.key_file}{state}")
        if self.chain_file is not None:
            rows.append(f"  chain         {self.chain_file}")
        if self.same_certificate_as is not None:
            rows.append(f"  same certificate as {self.same_certificate_as}")
        rows.append(f"  → {self.suggestion}")
        return rows


@dataclass(frozen=True)
class DirectoryScan:
    """What a directory of certificate files holds, and how to use it.

    Returned by :func:`~httpx_pki.scan`. ``print()`` it for the laid-out
    report; ``repr()`` is the same report, for the same reason
    :class:`~httpx_pki.X509Explanation` reads in a REPL. ``files`` carries
    every file touched, whatever became of it; the other lists are the
    report's sections.
    """

    directory: str
    files: list[ScannedFile] = field(default_factory=list)
    identities: list[ScanIdentity] = field(default_factory=list)
    locked: list[ScannedFile] = field(default_factory=list)
    unpaired: list[ScannedFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped_subdirs: int = 0

    @property
    def usable(self) -> bool:
        """Whether the directory yields at least one loadable identity."""
        return bool(self.identities)

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return "\n".join(self._lines())

    def _lines(self) -> list[str]:
        count = len(self.identities)
        found = "1 identity" if count == 1 else f"{count} identities"
        head = f"{_clean(self.directory)} — {_plural(len(self.files), 'file')}, {found}"
        out = ["SCANNED".ljust(_WIDTH) + head, ""]
        for identity in self.identities:
            out += _block("IDENTITY", identity.lines()) + [""]
        for label, rows in (
            ("LOCKED", [f.summary for f in self.locked]),
            ("UNPAIRED", [f.summary for f in self.unpaired]),
            ("NOTES", self.notes),
        ):
            block = _block(label, rows)
            if block:
                out += block + [""]
        if self.skipped_subdirs:
            skipped = (
                "1 subdirectory"
                if self.skipped_subdirs == 1
                else f"{self.skipped_subdirs} subdirectories"
            )
            out += [f"{skipped} not scanned — point scan at them directly", ""]
        while out and out[-1] == "":
            out.pop()
        return out


def _block(label: str, rows: list[str]) -> list[str]:
    """*rows* under a left-hand *label*, which appears on the first row only."""
    if not rows:
        return []
    pad = " " * _WIDTH
    head = label.ljust(_WIDTH)
    return [head + rows[0]] + [pad + row if row else "" for row in rows[1:]]


# -- per-file examination ----------------------------------------------------


@dataclass
class _Facts:  # pylint: disable=too-many-instance-attributes
    """Everything one file contributed, before cross-file assembly."""

    name: str
    kind: str
    password_index: int | None = None
    keys: list[tuple[bytes, bool]] = field(default_factory=list)  # (SPKI, encrypted)
    certs: list[x509.Certificate] = field(default_factory=list)
    p12_identities: list[_Loaded] = field(default_factory=list)
    p12_certs: list[x509.Certificate] = field(default_factory=list)
    csr_spkis: list[bytes] = field(default_factory=list)
    dump_prints: set[str] = field(default_factory=set)
    locked_summary: str | None = None
    note: str | None = None


def _try_pem_key(
    block: bytes, passwords: list[bytes]
) -> tuple[bytes | None, int | None, bool]:
    """(SPKI, password index, encrypted?) for a PEM key block, or all-``None``.

    Encrypted is decided by the no-password attempt: ``TypeError`` is
    cryptography saying "there is a key here and it wants a password", which
    is exactly the locked/broken distinction the report needs.
    """
    try:
        key = serialization.load_pem_private_key(block, None)
        return _spki(key.public_key()), None, False
    except TypeError:
        pass
    except ValueError:
        return None, None, False  # present but unreadable: not a password problem
    for index, password in enumerate(passwords, 1):
        try:
            key = serialization.load_pem_private_key(block, password)
            return _spki(key.public_key()), index, True
        except (ValueError, TypeError):
            continue
    return None, None, True


def _examine_pem(  # pylint: disable=too-many-branches
    facts: _Facts, data: bytes, passwords: list[bytes]
) -> _Facts:
    locked_keys = 0
    for match in _PEM_BLOCK.finditer(data):
        label = match.group(1)
        block = match.group(0)
        if b"PRIVATE KEY" in label:
            spki, index, encrypted = _try_pem_key(block, passwords)
            if spki is None and encrypted:
                locked_keys += 1
            elif spki is not None:
                facts.keys.append((spki, encrypted))
                if index is not None:
                    facts.password_index = index
        elif label == b"CERTIFICATE":
            try:
                facts.certs.append(x509.load_pem_x509_certificate(block))
            except ValueError:
                pass  # a broken block among good ones; the good ones count
        elif label == b"PKCS7":
            try:
                facts.certs.extend(pkcs7.load_pem_pkcs7_certificates(block))
            except ValueError:
                pass
        elif label in _CSR_LABELS:
            try:
                csr = x509.load_pem_x509_csr(block)
            except ValueError:
                continue
            facts.csr_spkis.append(
                csr.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    if locked_keys and not facts.keys and not facts.certs:
        facts.kind = "locked"
        facts.locked_summary = (
            f"{facts.name} — encrypted private key; "
            "none of the given passwords open it"
        )
    else:
        facts.kind = "pem"
    return facts


def _examine_pkcs12(facts: _Facts, data: bytes, passwords: list[bytes]) -> _Facts:
    # None and b"" first: an unprotected PKCS#12 spells "no password" both
    # ways depending on the tool that wrote it.
    candidates: list[tuple[int | None, bytes | None]] = [(None, None), (None, b"")]
    candidates += list(enumerate(passwords, 1))
    for index, password in candidates:
        try:
            bundle = load_bundle(data, password)
        except CertificateLoadError:
            continue
        facts.kind = "pkcs12"
        facts.password_index = index
        facts.p12_identities = list(bundle.identities)
        facts.p12_certs = list(bundle.certificates)
        return facts
    facts.kind = "locked"
    facts.locked_summary = (
        f"{facts.name} — encrypted PKCS#12; none of the given passwords open it"
    )
    return facts


def _examine_binary(  # pylint: disable=too-many-return-statements
    facts: _Facts, data: bytes, passwords: list[bytes]
) -> _Facts:
    if _PFX_VERSION in data[:8]:
        return _examine_pkcs12(facts, data, passwords)
    try:
        facts.certs.append(x509.load_der_x509_certificate(data))
        facts.kind = "certificates"
        return facts
    except ValueError:
        pass
    try:
        key = serialization.load_der_private_key(data, None)
        facts.keys.append((_spki(key.public_key()), False))
        facts.kind = "key"
        return facts
    except TypeError:
        # Encrypted DER PKCS#8: definitely a key, so the passwords get a try.
        for index, password in enumerate(passwords, 1):
            try:
                key = serialization.load_der_private_key(data, password)
            except (ValueError, TypeError):
                continue
            facts.keys.append((_spki(key.public_key()), True))
            facts.password_index = index
            facts.kind = "key"
            return facts
        facts.kind = "locked"
        facts.locked_summary = (
            f"{facts.name} — encrypted private key; "
            "none of the given passwords open it"
        )
        return facts
    except ValueError:
        pass
    try:
        certs = pkcs7.load_der_pkcs7_certificates(data)
    except ValueError:
        pass
    else:
        facts.certs.extend(certs)
        facts.kind = "certificates"
        return facts
    # The PFX sniff is a heuristic; a miss must not turn a real (if oddly
    # laid out) PKCS#12 into "unknown", so the full parse gets the last word.
    attempted = _examine_pkcs12(facts, data, passwords)
    if attempted.kind == "pkcs12":
        return attempted
    facts.kind = "unknown"
    facts.locked_summary = None
    facts.note = f"{facts.name} — not recognizable certificate material"
    return facts


# A fingerprint as dumps print one: colon/space-separated byte pairs, or a
# bare hex run the length of a SHA-1 or SHA-256 digest.
_HEX_RUN = re.compile(
    r"(?:[0-9A-Fa-f]{2}[:\s-]){15,}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{40,64}"
)


def _examine_dump(facts: _Facts, data: bytes) -> _Facts:
    """A human-readable certificate dump: not loadable, but labelable.

    The fingerprints such dumps print (NSS, Java, Windows styles all include
    one) are extracted so the report can say *which* encoded file the dump
    describes -- the one piece of information a text dump is still good for.
    """
    facts.kind = "dump"
    text = data.decode("utf-8", errors="replace")
    for run in _HEX_RUN.findall(text):
        normalized = "".join(ch for ch in run if ch.isalnum()).upper()
        if len(normalized) in (40, 64):  # SHA-1 / SHA-256
            facts.dump_prints.add(normalized)
    return facts


def _examine(name: str, data: bytes, passwords: list[bytes]) -> _Facts:
    facts = _Facts(name=name, kind="unknown")
    if b"-----BEGIN" in data:
        return _examine_pem(facts, data, passwords)
    stripped = data.lstrip()
    if stripped.startswith((b"Certificate:", b"X509 Certificate:")):
        return _examine_dump(facts, data)
    if stripped[:1] == b"\x30":
        return _examine_binary(facts, data, passwords)
    facts.note = f"{name} — not recognizable certificate material"
    return facts


# -- cross-file assembly -----------------------------------------------------


def _issuer_in(leaf: x509.Certificate, certs: list[x509.Certificate]) -> bool:
    return any(cert.subject == leaf.issuer for cert in certs)


def _chain_file_for(
    leaf: x509.Certificate,
    own_certs: list[x509.Certificate],
    cert_only: list[_Facts],
) -> str | None:
    """The first certificates-only file that holds *leaf*'s issuer, if the
    issuer is not already alongside the leaf in its own source."""
    if _issuer_in(leaf, own_certs) or _is_self_issued(leaf):
        return None
    for facts in cert_only:
        if _issuer_in(leaf, facts.certs):
            return facts.name
    return None


def _is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _all_ca(certs: list[x509.Certificate]) -> bool:
    for cert in certs:
        try:
            constraints = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        # DuplicateExtension included: this decides a hint's phrasing, and a
        # malformed certificate must not be able to crash the whole report.
        except (x509.ExtensionNotFound, x509.DuplicateExtension):
            return False
        if not constraints.ca:
            return False
    return bool(certs)


def _file_summary(facts: _Facts) -> str:
    """One line saying what the file turned out to be."""
    if facts.locked_summary is not None:
        return facts.locked_summary
    if facts.kind == "pkcs12":
        count = len(facts.p12_identities)
        inside = "1 identity" if count == 1 else f"{count} identities"
        return f"{facts.name} — PKCS#12, {inside}"
    if facts.kind in ("pem", "certificates", "key"):
        parts = []
        if facts.keys:
            parts.append(_plural(len(facts.keys), "private key"))
        if facts.certs:
            parts.append(_plural(len(facts.certs), "certificate"))
        if facts.csr_spkis:
            parts.append(_plural(len(facts.csr_spkis), "certificate request"))
        return f"{facts.name} — {', '.join(parts) or 'no recognizable blocks'}"
    if facts.kind == "dump":
        return f"{facts.name} — human-readable certificate dump"
    return facts.note or facts.name


def _normalize_passwords(
    passwords: Password | Sequence[Password] | None,
) -> list[bytes]:
    if passwords is None:
        return []
    if isinstance(passwords, (str, bytes)):
        passwords = [passwords]
    encoded = []
    for password in passwords:
        value = encode_password(password)
        if value is not None:
            encoded.append(value)
    return encoded


def scan(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    directory: str | Path,
    passwords: Password | Sequence[Password] | None = None,
) -> DirectoryScan:
    """Classify every file in *directory* and pair the identities it holds.

    *passwords* is one password or several: a folder accumulated over time is
    exactly where the PKCS#12 password and an extracted key's passphrase
    differ. Each is tried against each encrypted file; the report refers to
    them by position (``password #2``) and never repeats a value. A file
    nothing opens is reported as locked, not skipped.

    Top-level files only. Subdirectories are counted and named as skipped
    rather than descended into -- a CA export is flat, and whatever else a
    subtree holds, crawling it uninvited is not this function's call.
    """
    root = Path(directory)
    if not root.is_dir():
        raise CertificateLoadError(f"{str(directory)!r} is not a directory")
    encoded = _normalize_passwords(passwords)

    all_facts: list[_Facts] = []
    files: list[ScannedFile] = []
    notes: list[str] = []
    skipped_subdirs = 0
    for path in sorted(root.iterdir()):
        if path.is_dir():
            skipped_subdirs += 1
            continue
        if not path.is_file():
            continue
        name = path.name
        try:
            size = path.stat().st_size
            if size > _MAX_FILE_SIZE:
                files.append(
                    ScannedFile(name, "oversized", f"{name} — too large to scan")
                )
                notes.append(
                    f"{name} — {size // (1024 * 1024)} MiB, too large to be "
                    "certificate material; not scanned"
                )
                continue
            data = path.read_bytes()
        except OSError as exc:
            files.append(ScannedFile(name, "unreadable", f"{name} — {exc}"))
            notes.append(f"{name} — could not be read ({exc})")
            continue
        all_facts.append(_examine(name, data, encoded))

    # -- assemble identities ---------------------------------------------
    identities: list[ScanIdentity] = []
    seen_leaves: dict[bytes, str] = {}  # leaf DER -> file first offering it
    spki_to_source: dict[bytes, str] = {}  # identity SPKI -> file, for CSR notes
    cert_only = [
        f
        for f in all_facts
        if f.kind in ("pem", "certificates") and f.certs and not f.keys
    ]

    def leaf_note(cert: x509.Certificate, source: str) -> str | None:
        der = cert.public_bytes(serialization.Encoding.DER)
        if der in seen_leaves:
            return seen_leaves[der]
        seen_leaves[der] = source
        return None

    used_as_chain: set[str] = set()
    leaves: list[tuple[x509.Certificate, str]] = []  # leaf, file presenting it
    for facts in all_facts:
        if facts.kind != "pkcs12":
            continue
        several = len(facts.p12_identities) > 1
        needs_password = facts.password_index is not None
        for loaded in facts.p12_identities:
            cert = loaded.identity.certificate
            args = [f'"{facts.name}"']
            if needs_password:
                args.append("password=...")
            if several:
                args.append("identity=httpx_pki.for_mtls")
            chain_file = _chain_file_for(cert, facts.p12_certs, cert_only)
            if chain_file is not None:
                args.append(f'chain="{chain_file}"')
                used_as_chain.add(chain_file)
            spki_to_source.setdefault(_spki(cert.public_key()), facts.name)
            leaves.append((cert, facts.name))
            identities.append(
                ScanIdentity(
                    info=loaded.identity.info,
                    key_label=_key_description(cert),
                    bundle_file=facts.name,
                    chain_file=chain_file,
                    password_index=facts.password_index,
                    needs_password=needs_password,
                    same_certificate_as=leaf_note(cert, facts.name),
                    suggestion=f"PKIClient({', '.join(args)})",
                )
            )

    # Keys across files, first file offering a given key wins; every
    # certificate sharing its public key is one identity, as the loaders see
    # it (a renewal kept alongside its predecessor is two identities).
    keys: dict[bytes, tuple[_Facts, bool]] = {}
    for facts in all_facts:
        for spki, encrypted in facts.keys:
            keys.setdefault(spki, (facts, encrypted))

    matched_keys: set[bytes] = set()
    for spki, (key_facts, encrypted) in keys.items():
        seen_certs: set[bytes] = set()
        for cert_facts in all_facts:
            for cert in cert_facts.certs:
                if _spki(cert.public_key()) != spki:
                    continue
                der = cert.public_bytes(serialization.Encoding.DER)
                if der in seen_certs:
                    continue
                seen_certs.add(der)
                matched_keys.add(spki)
                spki_to_source.setdefault(spki, cert_facts.name)
                leaves.append((cert, cert_facts.name))
                password_arg = (
                    ", password=..." if encrypted else ""
                )
                chain_file = _chain_file_for(cert, cert_facts.certs, cert_only)
                chain_arg = (
                    f', chain="{chain_file}"' if chain_file is not None else ""
                )
                if chain_file is not None:
                    used_as_chain.add(chain_file)
                if cert_facts is key_facts:
                    suggestion = (
                        f'PKIClient("{key_facts.name}"{password_arg}{chain_arg})'
                    )
                    certificate_file = None
                    key_file = None
                    bundle_file: str | None = key_facts.name
                else:
                    suggestion = (
                        f'from_key_pair(certificate="{cert_facts.name}", '
                        f'private_key="{key_facts.name}"'
                        f"{password_arg}{chain_arg})"
                    )
                    certificate_file = cert_facts.name
                    key_file = key_facts.name
                    bundle_file = None
                identities.append(
                    ScanIdentity(
                        info=certificate_info(cert),
                        key_label=_key_description(cert),
                        bundle_file=bundle_file,
                        certificate_file=certificate_file,
                        key_file=key_file,
                        chain_file=chain_file,
                        password_index=(
                            key_facts.password_index if encrypted else None
                        ),
                        needs_password=encrypted,
                        same_certificate_as=leaf_note(
                            cert, bundle_file or f"{certificate_file}"
                        ),
                        suggestion=suggestion,
                    )
                )

    # -- the files nothing claimed -----------------------------------------
    locked: list[ScannedFile] = []
    unpaired: list[ScannedFile] = []
    identity_files: set[str] = set()
    for identity in identities:
        identity_files.update(
            name
            for name in (
                identity.bundle_file,
                identity.certificate_file,
                identity.key_file,
            )
            if name is not None
        )

    for facts in all_facts:
        entry = ScannedFile(
            facts.name, facts.kind, _file_summary(facts), facts.password_index
        )
        files.append(entry)
        if facts.kind == "locked":
            locked.append(entry)
            continue
        if facts.kind == "dump":
            described = _dump_subject(facts, all_facts)
            notes.append(
                f"{facts.name} — human-readable dump"
                + (
                    f"; fingerprint matches {described}"
                    if described
                    else "; matches nothing here"
                )
                + " (not loadable)"
            )
            continue
        if facts.kind == "unknown":
            if facts.note:
                notes.append(facts.note)
            continue
        if facts.csr_spkis and not facts.certs and not facts.keys:
            for spki in facts.csr_spkis:
                owner = spki_to_source.get(spki)
                what = (
                    f"for the key of {owner}"
                    if owner
                    else "matching nothing here"
                )
                notes.append(
                    f"{facts.name} — certificate request {what} "
                    "(issuance artifact, not loadable)"
                )
            continue
        if facts.kind == "pem" and not (facts.certs or facts.keys):
            notes.append(f"{facts.name} — PEM armor with no recognizable blocks")
            continue
        if facts.name in identity_files or facts.kind == "pkcs12":
            continue
        if facts.name in used_as_chain:
            continue
        if facts.certs and not facts.keys:
            # An unclaimed certificate file is not always a mystery: holding
            # an identity's issuer, it is an alternative chain=/verify=
            # source, and saying so beats leaving it as an accusation.
            issuer_of = next(
                (
                    source
                    for leaf, source in leaves
                    if _issuer_in(leaf, facts.certs)
                ),
                None,
            )
            if issuer_of is not None:
                suffix = (
                    f" (holds the issuer of {issuer_of} — usable as chain= "
                    "or verify=)"
                )
            elif _all_ca(facts.certs):
                suffix = " (all CA certificates — possibly a verify= trust bundle)"
            else:
                suffix = ""
            unpaired.append(
                ScannedFile(
                    facts.name,
                    facts.kind,
                    f"{facts.name} — {_plural(len(facts.certs), 'certificate')} "
                    f"with no matching key here{suffix}",
                    facts.password_index,
                )
            )
        elif facts.keys and not any(s in matched_keys for s, _ in facts.keys):
            unpaired.append(
                ScannedFile(
                    facts.name,
                    facts.kind,
                    f"{facts.name} — private key with no matching certificate "
                    "here",
                    facts.password_index,
                )
            )

    return DirectoryScan(
        directory=str(directory),
        files=files,
        identities=identities,
        locked=locked,
        unpaired=unpaired,
        notes=notes,
        skipped_subdirs=skipped_subdirs,
    )


def _dump_subject(facts: _Facts, all_facts: list[_Facts]) -> str | None:
    """The file whose certificate a text dump's fingerprint names, if any."""
    if not facts.dump_prints:
        return None
    for other in all_facts:
        for cert in [*other.certs, *other.p12_certs]:
            prints = {
                cert.fingerprint(hashes.SHA1()).hex().upper(),
                cert.fingerprint(hashes.SHA256()).hex().upper(),
            }
            if prints & facts.dump_prints:
                return other.name
    return None
