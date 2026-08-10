"""Laying out what a certificate source holds and whether it will work.

:func:`explain` takes the arguments :func:`~httpx_pki.build_ssl_context` takes
and reports what it *would* do instead of doing it -- a dry run. The findings
come from :mod:`httpx_pki._audit`, the same analyzer the construction-path
warnings use, so the report can never contradict the warning that sent someone
to it.

The audience is whoever was handed a ``.p12`` and told to use it. That shapes
two things. Nothing here raises for a file that is merely confusing: a bundle
holding several identities, or one whose password is missing, produces a report
saying so rather than an exception, because a caller who cannot yet load the
file is exactly the caller who needs to look inside it. And describing is kept
separate from faulting -- a chain that stops before its root is *normal*, and a
report where every line reads as an accusation teaches people to ignore all of
them.
"""

from __future__ import annotations

import datetime
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._audit import (
    AnchorStatus,
    ChainLink,
    ChainWalk,
    Problem,
    TrustSourceCerts,
    _is_self_signed,
    _plural,
    analyze_certificate,
    analyze_presented_chain,
    analyze_trust_sources,
    anchor_status,
    walk_chain,
)
from ._exceptions import (
    AmbiguousCertificateError,
    CertificateLoadError,
    CertificateNotFoundError,
    TLSConfigWarning,
)
from ._material import (
    CertInfo,
    CertSource,
    Material,
    Password,
    _load_certificate,
    certificate_info,
    encode_password,
    load_material,
    read_source,
    resolve_chain,
)
from ._pkcs12 import IdentitySelector, P12Identity, _walk_key_bags, list_identities
from ._select import UsageSelector
from ._ssl import VerifyTypes, _server_trust

if TYPE_CHECKING:  # imported for typing only -- _mixin imports this module
    from ._mixin import _PKIMixin

_WIDTH = 11  # the label column


def _clean(text: str) -> str:
    """Strip control characters from an untrusted certificate string.

    Subject names, friendly names, and AIA URLs are attacker-controlled when
    the file came from somewhere else, and X.509 text fields can carry
    arbitrary bytes -- including the escape sequences a terminal would act on.
    Everything rendered here goes through this first.
    """
    return "".join(ch for ch in text if ch.isprintable() or ch == " ")


@dataclass(frozen=True)
class TrustAnchor:
    """One resolved ``verify=`` entry, as the report presents it.

    ``anchors`` carries a :class:`~httpx_pki.AnchorStatus` per certificate --
    its key, and whether it can serve as an anchor at all -- and is empty for
    the curated stores, whose contents are not parsed.
    """

    label: str
    kind: str
    anchors: list[AnchorStatus] = field(default_factory=list)

    def __str__(self) -> str:
        return "\n".join(self.lines())

    def lines(self, name_width: int = 0, key_width: int = 0) -> list[str]:
        """The entry as a heading, then one indented line per anchor.

        The column widths are passed in so every anchor in the report lines up,
        rather than each source aligning only against itself.
        """
        if self.kind == "system":
            return ["the OS trust store"]
        if self.kind == "certifi":
            return ["the certifi bundle"]
        head = f"{_clean(self.label)} — {_plural(len(self.anchors), 'anchor')}"
        rows = [head]
        for anchor in self.anchors:
            name = _clean(anchor.info.common_name or anchor.info.distinguished_name)
            # Upper case for an anchor that cannot serve, matching the chain
            # diagram: the expiry of a working anchor is a fact, not a fault.
            state = (
                f"expires {anchor.info.not_valid_after:%Y-%m-%d}"
                if anchor.usable
                else f"UNUSABLE — {anchor.reason}"
            )
            rows.append(
                f"  {name.ljust(name_width)}  {anchor.key.ljust(key_width)}  {state}"
            )
        return rows

    def anchor_widths(self) -> tuple[int, int]:
        """The name and key column widths this entry needs."""
        if not self.anchors:
            return 0, 0
        return (
            max(
                len(_clean(a.info.common_name or a.info.distinguished_name))
                for a in self.anchors
            ),
            max(len(a.key) for a in self.anchors),
        )


@dataclass(frozen=True)
class X509Explanation:  # pylint: disable=too-many-instance-attributes
    """What a certificate source holds, what it would present, and what breaks.

    Returned by :func:`~httpx_pki.explain` and
    :meth:`~httpx_pki.PKIClient.explain`. ``print()`` it for the laid-out
    report; the fields are there so a test or a CI check can assert on the
    findings without matching prose -- see :class:`~httpx_pki.Problem` for why
    to match on ``code``::

        report = httpx_pki.explain("corp.p12", password=pw)
        assert not [p for p in report.problems if p.code.startswith("chain.")]

    ``presented`` is empty when the material could not be loaded at all --
    a bundle needing a password, or one holding several identities with no
    selector. ``identities`` is filled in whenever the source could be
    enumerated, which for a PKCS#12 still requires the password.
    """

    source: str
    summary: str
    identities: list[P12Identity] = field(default_factory=list)
    presented: CertInfo | None = None
    chain: list[ChainLink] = field(default_factory=list)
    trust: list[TrustAnchor] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether nothing is wrong with the material as configured."""
        return not self.problems

    def __repr__(self) -> str:
        """The full report.

        Deliberately the same as :meth:`__str__` rather than the short
        ``<X509Explanation ...>`` a value object would usually give. This
        object exists to be read in a REPL or a notebook, where the natural
        gesture is to evaluate it and not to wrap it in ``print()`` -- and both
        of those display through ``repr``. The cost is that a report inside a
        list or a log line takes several lines; the alternative was that the
        one thing it is for did not work.
        """
        return str(self)

    def __str__(self) -> str:
        return "\n".join(self._lines())

    def _lines(self) -> list[str]:
        out = [f"{_clean(self.source)} — {self.summary}", ""]
        out += self._identity_lines()
        out += self._chain_lines()
        out += self._trust_lines()
        out += self._problem_lines()
        return out

    def _identity_lines(self) -> list[str]:
        if self.presented is not None:
            return _block("PRESENTS", _describe_cert(self.presented)) + [""]
        if not self.identities:
            return []
        rows = []
        show_eku = any(i.info.extended_key_usage for i in self.identities)
        for identity in self.identities:
            label = _clean(identity.info.common_name or "<no CN>")
            extra = (
                f" ({_clean(identity.friendly_name)})" if identity.friendly_name else ""
            )
            usage = ",".join(sorted(identity.info.key_usage)) or "<none>"
            row = f"[{identity.index}] {label}{extra}  key_usage={usage}"
            # The extended usage decides whether an identity can do mTLS at
            # all, so it is shown whenever any of them carries one -- it is
            # what explains an identity=for_mtls miss.
            if show_eku:
                eku = ",".join(identity.info.extended_key_usage) or "<none>"
                row += f"  ext_key_usage={eku}"
            rows.append(
                f"{row}  expires={identity.info.not_valid_after:%Y-%m-%d}"
            )
        return _block("HOLDS", rows) + [""]

    def _chain_lines(self) -> list[str]:  # pylint: disable=too-many-branches
        if not self.chain:
            return []
        rows: list[str] = []
        for link in self.chain:
            if not link.on_path and rows and rows[-1] != "":
                # A blank line and the left margin: a stray hangs off nothing,
                # and the layout should say so before the note does.
                rows.append("")
            indent = "" if not link.on_path else "  " * link.depth
            arrow = "" if link.depth == 0 or not link.on_path else "└─ "
            name = _clean(link.info.common_name or link.info.distinguished_name)
            # Upper case marks a fault, lower case a neutral fact, so the
            # severity of a line is readable without parsing the English.
            notes = []
            if not link.on_path:
                notes.append("UNATTACHED")
                if link.trusted:
                    notes.append("already a trust anchor")
            elif not link.present:
                notes.append("NOT SUPPLIED")
                if link.trusted:
                    notes.append("trust anchor, need not be sent")
                elif link.aia_url:
                    notes.append(f"published at {_clean(link.aia_url)}")
            else:
                # Additive, not exclusive: a self-signed root that is also this
                # certificate's direct issuer has both facts worth stating, and
                # "we checked the signature" is the one that is easy to lose.
                if link.signature_verified is True:
                    notes.append("verified")
                elif link.signature_verified is False:
                    notes.append("BAD SIGNATURE")
                if link.self_signed:
                    notes.append(
                        "self-signed, trust anchor" if link.trusted else "self-signed"
                    )
                if link.sent_twice:
                    notes.append("SENT TWICE")
            note = f"   [{'; '.join(notes)}]" if notes else ""
            rows.append(f"{indent}{arrow}{name}{note}")
        return _block("CHAIN", rows) + [""]

    def _trust_lines(self) -> list[str]:
        if not self.trust:
            return []
        widths = [entry.anchor_widths() for entry in self.trust]
        name_width = max((w[0] for w in widths), default=0)
        key_width = max((w[1] for w in widths), default=0)
        rows: list[str] = []
        for entry in self.trust:
            rows += entry.lines(name_width, key_width)
        return _block("TRUSTS", rows) + [""]

    def _problem_lines(self) -> list[str]:
        if not self.problems:
            return _block("PROBLEMS", ["none"])
        rows = []
        for index, problem in enumerate(self.problems, 1):
            rows.append(f"{index}. [{problem.code}] {_clean(problem.message)}")
            rows.append(f"   → {_clean(problem.remedy)}")
        return _block("PROBLEMS", rows)


def _block(label: str, rows: list[str]) -> list[str]:
    """*rows* under a left-hand *label*, which appears on the first row only."""
    if not rows:
        return []
    pad = " " * _WIDTH
    head = label.ljust(_WIDTH)
    return [head + rows[0]] + [pad + row if row else "" for row in rows[1:]]


def _describe_cert(info: CertInfo) -> list[str]:
    rows = [_clean(info.common_name or info.distinguished_name)]
    issuer = info.issuer_common_name or info.issuer_distinguished_name
    rows.append(f"issued by  {_clean(issuer)}")
    rows.append(
        f"valid      {info.not_valid_before:%Y-%m-%d} → "
        f"{info.not_valid_after:%Y-%m-%d}{_remaining(info)}"
    )
    if info.key_usage:
        rows.append(f"usage      {', '.join(sorted(info.key_usage))}")
    if info.extended_key_usage:
        usable = "client_auth" in info.extended_key_usage
        marker = "" if usable else "   (NO CLIENT_AUTH)"
        rows.append(f"ext usage  {', '.join(info.extended_key_usage)}{marker}")
    if info.subject_alt_names:
        sans = ", ".join(_clean(name) for name in info.subject_alt_names)
        rows.append(f"SANs       {sans}")
    rows.append(f"SHA-256    {info.fingerprint_sha256}")
    return rows


def _remaining(info: CertInfo) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    if now > info.not_valid_after:
        return "   (EXPIRED)"
    if now < info.not_valid_before:
        return "   (NOT YET VALID)"
    return f"   ({(info.not_valid_after - now).days} days left)"


# -- assembly ---------------------------------------------------------------


def explain(  # pylint: disable=too-many-arguments,too-many-locals
    source: CertSource,
    password: Password = None,
    *,
    verify: VerifyTypes = True,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
    chain: CertSource | list[CertSource] | None = None,
    prune_chain: bool = False,
) -> X509Explanation:
    """Describe what a certificate source holds and whether it will work.

    Takes the arguments :func:`~httpx_pki.build_ssl_context` takes and reports
    what it *would* do rather than doing it::

        print(httpx_pki.explain("corp.p12", password="secret"))

    Nothing is fetched over the network. When a chain is incomplete the report
    names the URL the certificate itself gives for its issuer (its Authority
    Information Access extension) so you can retrieve it deliberately -- that
    URL comes from the file being inspected, which is untrusted input, so
    requesting it automatically would let whoever supplied the file choose a URL
    this process fetches.

    A source that is merely confusing does not raise: a PKCS#12 needing a
    password, or one holding several identities with no selector, comes back as
    a report saying so. A source that cannot be read at all
    (:class:`~httpx_pki.CertificateLoadError`) still raises -- there is nothing
    to describe.
    """
    data = read_source(source)
    label = source if isinstance(source, str) else str(source)
    if isinstance(source, bytes):
        label = f"<{len(source)} bytes>"

    encoded = encode_password(password)
    identities, load_problem = _identities(data, encoded)
    material, material_problem = _material(
        data, encoded, identity, key_usage, extended_key_usage, chain, prune_chain
    )
    trust, trust_sources = _trust(verify)

    problems = [p for p in (load_problem, material_problem) if p is not None]
    presented: CertInfo | None = None
    links: list[ChainLink] = []
    if material is not None:
        client_cert = _load_certificate(material.cert_pem)
        presented = certificate_info(client_cert)
        walk = walk_chain(
            client_cert,
            [_load_certificate(pem) for pem in material.ca_pems],
            verify_signatures=True,
        )
        links = _links_with_gap(walk, trust)
        problems += analyze_certificate(client_cert)
        problems += analyze_trust_sources(trust_sources, client_cert)
        # Re-derived rather than read off the walk above: the construction path
        # uses the cheap issuer test, and the report must show exactly the
        # findings it would have warned about.
        problems += analyze_presented_chain(
            client_cert, [_load_certificate(pem) for pem in material.ca_pems]
        )
    else:
        problems += analyze_trust_sources(trust_sources, None)

    return X509Explanation(
        source=label,
        summary=_summary(data, identities, material),
        identities=identities,
        presented=presented,
        chain=links,
        trust=trust,
        problems=problems,
    )


def _links_with_gap(
    walk: ChainWalk, trust: list[TrustAnchor] | None = None
) -> list[ChainLink]:
    """The walked links, plus a placeholder for the issuer nobody supplied.

    Each link is cross-referenced against the configured trust anchors, which
    is the whole reason a report that knows both halves beats one that knows
    only the file: a chain stopping at an issuer you already trust is the
    normal shape, and one stopping at an issuer you do not is the gap.
    """
    links = list(walk.links)
    if walk.missing_issuer is not None:
        depth = max((link.depth for link in links), default=0) + 1
        links.append(
            ChainLink(
                info=_placeholder(walk.missing_issuer),
                depth=depth,
                present=False,
                self_signed=False,
                aia_url=walk.missing_issuer_aia,
            )
        )
    # Strays last, and at the margin. They are on the wire, so leaving them out
    # would mean the diagram showed a certificate that is not sent (the missing
    # issuer) while hiding ones that are.
    links += [
        ChainLink(
            info=certificate_info(cert),
            depth=0,
            present=True,
            self_signed=_is_self_signed(cert),
            on_path=False,
        )
        for cert in walk.strays
    ]
    return [_marked(link, trust) for link in links]


def _marked(link: ChainLink, trust: list[TrustAnchor] | None) -> ChainLink:
    """*link* with ``trusted`` filled in from the resolved anchors."""
    if trust is None:
        return link
    # Only anchors that can actually serve: a link whose issuer is in the
    # trust store but expired is not one the server can be left to supply, so
    # calling it trusted would be the wrong reassurance.
    anchors = [
        anchor.info
        for entry in trust
        for anchor in entry.anchors
        if anchor.usable
    ]
    if not anchors and not any(e.kind in ("system", "certifi") for e in trust):
        return link
    if link.info.fingerprint_sha256:
        trusted = any(
            a.fingerprint_sha256 == link.info.fingerprint_sha256 for a in anchors
        )
    else:
        # A placeholder for a certificate we do not have: all we can match on
        # is the name its child gave for it.
        trusted = any(
            a.common_name == link.info.common_name
            or a.distinguished_name == link.info.distinguished_name
            for a in anchors
        )
    return ChainLink(
        info=link.info,
        depth=link.depth,
        present=link.present,
        self_signed=link.self_signed,
        signature_verified=link.signature_verified,
        aia_url=link.aia_url,
        trusted=trusted,
        on_path=link.on_path,
        sent_twice=link.sent_twice,
    )


def _placeholder(name: str) -> CertInfo:
    """A stand-in for a certificate we know the name of but do not have."""
    epoch = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
    return CertInfo(
        common_name=name,
        distinguished_name=name,
        issuer_common_name=None,
        issuer_distinguished_name="",
        serial_number=0,
        not_valid_before=epoch,
        not_valid_after=epoch,
        fingerprint_sha256="",
        fingerprint_sha1="",
        subject_alt_names=[],
    )


def _identities(
    data: bytes, password: bytes | None
) -> tuple[list[P12Identity], Problem | None]:
    """Every identity in the source, or the reason none could be read."""
    try:
        return list_identities(data, password), None
    except CertificateLoadError:
        pass
    if _looks_like_pkcs12(data):
        return [], Problem(
            code="source.password_required",
            message=(
                "this PKCS#12 bundle encrypts its certificates, so nothing in "
                "it can be read without the password. Unlike PEM, there is no "
                "part of it readable first."
            ),
            remedy="Supply password=, or check the one you have.",
        )
    return [], Problem(
        code="source.unreadable",
        message="this source is not readable as PKCS#12 or PEM.",
        remedy="Check the file and the password.",
    )


def _looks_like_pkcs12(data: bytes) -> bool:
    """Whether *data* is structurally a PKCS#12, password aside."""
    if b"-----BEGIN" in data:
        return False
    try:
        return bool(_walk_key_bags(data))
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _material(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    data: bytes,
    password: bytes | None,
    identity: IdentitySelector | None,
    key_usage: UsageSelector | None,
    extended_key_usage: UsageSelector | None,
    chain: CertSource | list[CertSource] | None,
    prune_chain: bool = False,
) -> tuple[Material | None, Problem | None]:
    """The material that would be presented, or why there is none."""
    try:
        loaded = load_material(
            data,
            password,
            identity=identity,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
        )
    except AmbiguousCertificateError:
        return None, Problem(
            code="source.ambiguous",
            message=(
                "this source holds several identities and no selector chooses "
                "between them."
            ),
            remedy=(
                "For mTLS, identity=httpx_pki.for_mtls picks the identity that "
                "is currently valid and usable for client authentication. "
                "Otherwise pass identity= (index, name, or fingerprint), "
                "key_usage=, or extended_key_usage=."
            ),
        )
    except CertificateNotFoundError as exc:
        # The constructors raise this, and should: a selector that matches
        # nothing is a caller error. A report is the wrong place to raise it,
        # though -- someone whose selector missed is exactly who needs to see
        # what the source holds.
        # Only the first line: the exception carries its own listing of what
        # the source holds, which the report has already shown under HOLDS.
        return None, Problem(
            code="source.no_match",
            message=str(exc).split("\n", 1)[0].rstrip(" :"),
            remedy=(
                "Choose from the identities listed above, or drop the selector "
                "to see them all."
            ),
        )
    except CertificateLoadError:
        return None, None  # already reported by _identities
    try:
        return resolve_chain(loaded, chain, prune=prune_chain), None
    except CertificateLoadError as exc:
        return loaded, Problem(
            code="chain.unreadable",
            message=f"the chain= source is not readable: {exc}",
            remedy="Check the path and that it holds certificates.",
        )


def _trust(verify: VerifyTypes) -> tuple[list[TrustAnchor], list[TrustSourceCerts]]:
    """What ``verify=`` resolves to, without building anything for real."""
    with warnings.catch_warnings():
        # A dry run must not emit the side-effect warnings of the real thing;
        # anything worth saying is said in the report instead.
        warnings.simplefilter("ignore", TLSConfigWarning)
        try:
            _ctx, sources = _server_trust(verify)
        except (CertificateLoadError, TypeError):
            return [], []
    return [
        TrustAnchor(
            label=source.label,
            kind=source.kind,
            anchors=[anchor_status(c) for c in source.certificates],
        )
        for source in sources
    ], sources


def _summary(
    data: bytes, identities: list[P12Identity], material: Material | None
) -> str:
    kind = "PEM" if b"-----BEGIN" in data else "PKCS#12"
    parts = [kind]
    if identities:
        noun = "identity" if len(identities) == 1 else "identities"
        parts.append(f"{len(identities)} {noun}")
    if material is not None:
        count = len(material.ca_pems)
        parts.append(
            "no chain certificates"
            if not count
            else _plural(count, "chain certificate")
        )
    return ", ".join(parts)


def explain_client(client: _PKIMixin) -> X509Explanation:
    """:func:`explain` for an already-built session.

    Backs :meth:`~httpx_pki.PKIClient.explain`. The client knows both halves --
    what it presents and what it trusts -- which is the pairing most of the
    confusion lives in, so this is the more useful entry point when there is a
    client to ask.
    """
    material: Material = client._material  # pylint: disable=protected-access
    verify = client._verify_policy  # pylint: disable=protected-access
    trust, trust_sources = _trust(verify)

    client_cert = _load_certificate(material.cert_pem)
    chain_certs = [_load_certificate(pem) for pem in material.ca_pems]
    walk = walk_chain(client_cert, chain_certs, verify_signatures=True)
    problems = [
        *analyze_certificate(client_cert),
        *analyze_trust_sources(trust_sources, client_cert),
        *analyze_presented_chain(client_cert, chain_certs),
    ]
    info = certificate_info(client_cert)
    return X509Explanation(
        source=f"<{type(client).__name__}>",
        summary=(
            "in use, "
            + (
                "no chain certificates"
                if not material.ca_pems
                else _plural(len(material.ca_pems), "chain certificate")
            )
        ),
        identities=[],
        presented=info,
        chain=_links_with_gap(walk, trust),
        trust=trust,
        problems=problems,
    )
