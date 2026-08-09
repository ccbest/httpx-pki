"""Analyzing certificate material that is loaded but cannot do its job.

Two silent misconfigurations, both of which produce a client that builds
cleanly and fails at handshake time with an OpenSSL error naming neither the
file nor the certificate at fault:

*Trust anchors that cannot anchor.* ``verify=`` accepting a list makes it easy
to pour every certificate on hand into it. A certificate that is not
self-signed is not a trust anchor: an intermediate short-circuits path
validation to the root that should have been checked, and a leaf anchors
nothing at all.

*Chain certificates that are not on the chain.* Certificates presented
alongside the client certificate are meant to connect it to its issuer. One
that does not is at best wasted handshake bytes and at worst a chain a strict
server rejects.

This module *finds* those; it does not report them. Every check produces
:class:`Problem` objects, which two consumers render:
:func:`emit_warnings` turns them into :class:`~httpx_pki.TLSConfigWarning`\\ s
on the construction path, and :mod:`httpx_pki._explain` lays them out in a
report. One analyzer, so a report can never contradict the warning that sent
someone to it.

Everything here is advisory and best-effort: it runs on material that has
already been loaded, never decides whether a load succeeds, and treats a
certificate it cannot parse as one it has nothing to say about. A warning it
cannot justify is worse than no warning, so the self-signed case -- a root CA,
and equally the self-signed server certificate a development setup pins -- is
silent, and the chain walk follows every path rather than one, so a
cross-signed certificate is not mistaken for a stray.
"""

from __future__ import annotations

import datetime
import warnings
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ._exceptions import TLSConfigWarning
from ._material import CertInfo, certificate_info

# Trust-source kinds whose contents are worth inspecting. The curated bundles
# are not where this mistake lives, and parsing certifi is both the most
# expensive check available and the least likely to find anything.
_AUDITED_KINDS = ("bundle", "directory")


@dataclass(frozen=True)
class Problem:
    """One thing wrong with the certificate material, and what to do about it.

    ``code`` is the stable identifier -- ``"chain.stray"``,
    ``"trust.intermediate"`` and so on. Match on it rather than on ``message``,
    which is prose and will be reworded. ``remedy`` is the actionable half, kept
    separate so a report can lay it out differently from the finding.
    """

    code: str
    message: str
    remedy: str
    certificates: list[CertInfo] = field(default_factory=list)

    def __str__(self) -> str:
        return f"[{self.code}] {self.message} {self.remedy}"


@dataclass(frozen=True)
class TrustSourceCerts:
    """The certificates one ``verify=`` entry contributed.

    ``kind`` is ``"system"``, ``"certifi"``, ``"bundle"``, or ``"directory"``.
    ``certificates`` is empty for the curated bundles, which are not parsed, and
    for anything OpenSSL accepted that ``cryptography`` would not.
    """

    label: str
    kind: str
    certificates: list[x509.Certificate] = field(default_factory=list)


@dataclass(frozen=True)
class ChainLink:
    """One certificate on the path from the client certificate upward.

    ``present`` is ``False`` for a link the chain refers to but does not carry
    -- the issuer named by a certificate that was not supplied. ``aia_url`` is
    then where the issuer says it is published, read from the Authority
    Information Access extension; httpx-pki never fetches it (the URL comes
    from the certificate being inspected, which is untrusted input, so
    requesting it would let whoever supplied the file choose a URL this process
    fetches).

    ``on_path`` is ``False`` for a certificate that is being *sent* but
    connects to nothing -- a stray. Those and the missing-issuer placeholder
    are the two ways a link is not an ordinary rung: between them the three
    states are (on the path and present), (on the path and missing), and (sent
    but off the path). All three belong in the diagram, because between them
    they account for every certificate that goes on the wire and every one the
    server will look for and not find.

    ``sent_twice`` marks the client certificate when a copy of it is also among
    the chain certificates.

    ``trusted`` says whether this certificate is among the anchors ``verify=``
    resolved to. It is what separates the two readings of a chain that stops
    early: a missing issuer you already trust need never be sent, while a
    missing issuer you do not trust is the gap the server will reject you for.
    ``None`` when there was no trust configuration to compare against.
    """

    info: CertInfo
    depth: int
    present: bool
    self_signed: bool
    signature_verified: bool | None = None
    aia_url: str | None = None
    trusted: bool | None = None
    on_path: bool = True
    sent_twice: bool = False


@dataclass(frozen=True)
class ChainWalk:
    """The structure of the certificates presented alongside the leaf."""

    links: list[ChainLink] = field(default_factory=list)
    strays: list[x509.Certificate] = field(default_factory=list)
    duplicates: list[x509.Certificate] = field(default_factory=list)
    missing_issuer: str | None = None
    missing_issuer_aia: str | None = None


# -- certificate predicates -------------------------------------------------


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Whether *cert* names itself as its own issuer.

    The subject/issuer comparison, not a signature check: this decides whether
    to *stay quiet*, so the cheap test is the right one -- a certificate that
    claims to be self-issued is at worst an odd trust anchor, not the mistake
    this module is looking for.
    """
    return cert.subject == cert.issuer


def _is_ca(cert: x509.Certificate) -> bool:
    """Whether *cert* asserts BasicConstraints CA."""
    try:
        return bool(
            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
    except x509.ExtensionNotFound:
        return False


def _describe(cert: x509.Certificate) -> str:
    """A certificate as one short phrase, for a message."""
    return _name(cert.subject)


def _name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not attrs:
        return name.rfc4514_string() or "<no subject>"
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _plural(count: int, noun: str) -> str:
    """``1 certificate`` / ``2 certificates`` -- never ``1 certificate(s)``."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _listing(certs: list[x509.Certificate]) -> str:
    return ", ".join(repr(_describe(cert)) for cert in certs)


def _infos(certs: list[x509.Certificate]) -> list[CertInfo]:
    return [certificate_info(cert) for cert in certs]


def ca_issuers_url(cert: x509.Certificate) -> str | None:
    """Where *cert* says its issuer's certificate is published, if it does.

    The ``caIssuers`` entry of the Authority Information Access extension,
    which enterprise CAs populate as a matter of course. Reporting it turns
    "the chain is incomplete" into a file the caller can go and fetch --
    themselves, deliberately. See :class:`ChainLink` for why not automatically.
    """
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
    except x509.ExtensionNotFound:
        return None
    ca_issuers = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
    for description in aia:
        if description.access_method != ca_issuers:
            continue
        location = description.access_location
        if isinstance(location, x509.UniformResourceIdentifier):
            return location.value
    return None


def _issued(candidate: x509.Certificate, child: x509.Certificate) -> bool:
    """Whether *candidate* could be the issuer of *child*.

    Names first, then the key identifiers when both carry them: matching
    AuthorityKeyIdentifier to SubjectKeyIdentifier is what tells two CA
    certificates with the same subject apart, which is exactly the situation a
    re-keyed or cross-signed CA creates.

    Deliberately *not* a signature check. This runs on every construction, and
    a warning that costs a public-key operation per candidate pair is not worth
    it. :func:`walk_chain` verifies signatures when asked, which is what
    ``explain()`` does -- there the cost does not matter and the stronger claim
    is worth making.
    """
    if candidate.subject != child.issuer:
        return False
    try:
        akid = child.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
        skid = candidate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound:
        return True  # nothing further to distinguish them by
    if akid is None:
        return True
    return akid == skid


def _verified(candidate: x509.Certificate, child: x509.Certificate) -> bool | None:
    """Whether *child*'s signature really is *candidate*'s, or ``None`` if the
    algorithm is one ``cryptography`` will not check."""
    try:
        child.verify_directly_issued_by(candidate)
    except (ValueError, TypeError, NotImplementedError):
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    return True


# -- the chain --------------------------------------------------------------


def walk_chain(  # pylint: disable=too-many-locals
    client_cert: x509.Certificate,
    chain: list[x509.Certificate],
    *,
    verify_signatures: bool = False,
) -> ChainWalk:
    """The structure of *chain* as seen from *client_cert*.

    Reachability from the leaf, following *every* path rather than one: a CA
    that has been cross-signed appears twice with the same subject, and both
    copies legitimately extend a path, so a walk that committed to the first
    match would report the other as a stray. A certificate nothing reaches is
    one the bundle should not be presenting.
    """
    leaf_fingerprint = client_cert.fingerprint(hashes.SHA256())
    duplicates = [
        cert for cert in chain if cert.fingerprint(hashes.SHA256()) == leaf_fingerprint
    ]
    remaining = [
        cert for cert in chain if cert.fingerprint(hashes.SHA256()) != leaf_fingerprint
    ]

    links = [
        ChainLink(
            info=certificate_info(client_cert),
            depth=0,
            present=True,
            self_signed=_is_self_signed(client_cert),
            sent_twice=bool(duplicates),
        )
    ]
    reached = {leaf_fingerprint}
    frontier = [(client_cert, 0)]
    while frontier:
        child, depth = frontier.pop(0)
        still_unreached: list[x509.Certificate] = []
        for candidate in remaining:
            if not _issued(candidate, child):
                still_unreached.append(candidate)
                continue
            fingerprint = candidate.fingerprint(hashes.SHA256())
            if fingerprint in reached:
                continue
            reached.add(fingerprint)
            links.append(
                ChainLink(
                    info=certificate_info(candidate),
                    depth=depth + 1,
                    present=True,
                    self_signed=_is_self_signed(candidate),
                    signature_verified=(
                        _verified(candidate, child) if verify_signatures else None
                    ),
                )
            )
            frontier.append((candidate, depth + 1))
        remaining = still_unreached

    # The topmost reached certificate that is not self-signed still names an
    # issuer nobody supplied -- that is the gap worth naming, with the URL the
    # certificate itself gives for it.
    missing = missing_aia = None
    tops = [link for link in links if not link.self_signed]
    if tops:
        deepest = max(tops, key=lambda link: link.depth)
        if not any(
            link.depth == deepest.depth + 1 for link in links
        ) and deepest.info.issuer_distinguished_name != deepest.info.distinguished_name:
            missing = deepest.info.issuer_common_name or (
                deepest.info.issuer_distinguished_name
            )
            for cert in [client_cert, *chain]:
                if certificate_info(cert).fingerprint_sha256 == (
                    deepest.info.fingerprint_sha256
                ):
                    missing_aia = ca_issuers_url(cert)
                    break

    return ChainWalk(
        links=links,
        strays=remaining,
        duplicates=duplicates,
        missing_issuer=missing,
        missing_issuer_aia=missing_aia,
    )


def analyze_presented_chain(
    client_cert: x509.Certificate, chain: list[x509.Certificate]
) -> list[Problem]:
    """Problems with the certificates presented alongside *client_cert*.

    Nothing is said about a chain that stops short of a self-signed root. That
    is the normal shape -- the root is what the server already has, and sending
    it is unnecessary rather than wrong -- and a certificate whose issuer is
    missing entirely is already reported here as the stray it is.
    """
    if not chain:
        return []
    walk = walk_chain(client_cert, chain)
    problems: list[Problem] = []

    if walk.duplicates:
        problems.append(
            Problem(
                code="chain.duplicate_leaf",
                message=(
                    "the client certificate is also in its own chain, so it is "
                    "sent twice."
                ),
                remedy="Remove it from chain=.",
                certificates=_infos(walk.duplicates),
            )
        )
    if not walk.strays:
        return problems

    presented = len(chain) - len(walk.duplicates)
    if walk.strays and len(walk.strays) == presented:
        issuer = _name(client_cert.issuer)
        remedy = "Supply the intermediates for this certificate."
        url = ca_issuers_url(client_cert)
        if url:
            remedy += f" Its issuer is published at {url}"
        problems.append(
            Problem(
                code="chain.disconnected",
                message=(
                    f"none of the {_plural(presented, 'presented certificate')} "
                    f"({_listing(walk.strays)}) reach the issuer {issuer!r}. The "
                    "server cannot build a path and will reject the handshake "
                    "with unknown_ca."
                ),
                remedy=remedy,
                certificates=_infos(walk.strays),
            )
        )
        return problems

    problems.append(
        Problem(
            code="chain.stray",
            message=(
                f"{len(walk.strays)} of {_plural(presented, 'presented certificate')} "
                f"({_listing(walk.strays)}) are not on this certificate's chain. "
                "They are sent for nothing, and a strict server may reject the "
                "chain."
            ),
            remedy="Remove them from chain=.",
            certificates=_infos(walk.strays),
        )
    )
    return problems


# -- the certificate itself -------------------------------------------------


def analyze_certificate(client_cert: x509.Certificate) -> list[Problem]:
    """Problems with the client certificate on its own terms.

    Validity and fitness for client authentication: the two ways a certificate
    that loaded perfectly still cannot do the job. Both are visible in the
    report's description as well, but describing is not the same as faulting --
    an expired certificate is not a neutral fact about the material, it is the
    reason the handshake will be rejected.

    Expiry is *also* warned about at construction, by the session's own
    validity check, which knows about ``warn_if_expires_within`` and
    ``strict_validity``. :func:`emit_warnings` therefore skips these rather
    than saying it twice; the report says it because the report is where
    someone goes to find out what is wrong.
    """
    info = certificate_info(client_cert)
    now = datetime.datetime.now(datetime.timezone.utc)
    problems: list[Problem] = []

    if now > info.not_valid_after:
        problems.append(
            Problem(
                code="certificate.expired",
                message=(
                    f"the client certificate expired on "
                    f"{info.not_valid_after:%Y-%m-%d}. Handshakes will be "
                    "rejected."
                ),
                remedy="Obtain a current certificate.",
                certificates=[info],
            )
        )
    elif now < info.not_valid_before:
        problems.append(
            Problem(
                code="certificate.not_yet_valid",
                message=(
                    f"the client certificate is not valid until "
                    f"{info.not_valid_before:%Y-%m-%d}."
                ),
                remedy="Check this machine's clock, then wait or reissue.",
                certificates=[info],
            )
        )

    # An absent ExtendedKeyUsage means "good for anything" and is not a fault;
    # only an EKU that is present and omits clientAuth says this certificate
    # was issued for something else.
    if info.extended_key_usage and "client_auth" not in info.extended_key_usage:
        usages = ", ".join(info.extended_key_usage)
        problems.append(
            Problem(
                code="certificate.no_client_auth",
                message=(
                    f"the client certificate's ExtendedKeyUsage is {usages}, "
                    "which omits client_auth. It was not issued for client "
                    "authentication and a server enforcing EKU will reject it."
                ),
                remedy=(
                    "Select the client-authentication certificate; in a "
                    "multi-identity bundle that is usually "
                    "key_usage='digital_signature'."
                ),
                certificates=[info],
            )
        )
    return problems


# -- trust anchors ----------------------------------------------------------


def analyze_trust_sources(
    sources: list[TrustSourceCerts], client_cert: x509.Certificate | None
) -> list[Problem]:
    """Problems with ``verify=`` entries that cannot serve as trust anchors.

    Grouped per source and per category rather than one problem per
    certificate: a bundle assembled wrongly is one mistake, and reporting it
    once with the names keeps a ten-certificate file from producing ten
    findings.
    """
    client_fingerprint = (
        client_cert.fingerprint(hashes.SHA256()) if client_cert is not None else None
    )
    problems: list[Problem] = []
    for source in sources:
        if source.kind not in _AUDITED_KINDS:
            continue
        own: list[x509.Certificate] = []
        intermediates: list[x509.Certificate] = []
        leaves: list[x509.Certificate] = []
        for cert in source.certificates:
            if (
                client_fingerprint is not None
                and cert.fingerprint(hashes.SHA256()) == client_fingerprint
            ):
                own.append(cert)
            elif _is_self_signed(cert):
                continue  # a root, or a pinned self-signed server certificate
            elif _is_ca(cert):
                intermediates.append(cert)
            else:
                leaves.append(cert)

        if own:
            problems.append(
                Problem(
                    code="trust.own_certificate",
                    message=(
                        f"verify={source.label!r} contains this client's own "
                        "certificate. verify= sets which CAs identify the "
                        "server, so this entry has no effect."
                    ),
                    remedy="Remove it from verify=.",
                    certificates=_infos(own),
                )
            )
        if intermediates:
            roots = ", ".join(
                sorted({repr(_name(cert.issuer)) for cert in intermediates})
            )
            problems.append(
                Problem(
                    code="trust.intermediate",
                    message=(
                        f"verify={source.label!r} contains "
                        f"{_plural(len(intermediates), 'intermediate CA certificate')} "
                        f"({_listing(intermediates)}). An intermediate is not a "
                        "trust anchor: trusting one accepts any server beneath "
                        "it without checking the root that issued it."
                    ),
                    remedy=(
                        f"Trust the root instead ({roots}), or pass them as "
                        "chain= to present them."
                    ),
                    certificates=_infos(intermediates),
                )
            )
        if leaves:
            problems.append(
                Problem(
                    code="trust.leaf",
                    message=(
                        f"verify={source.label!r} contains "
                        f"{_plural(len(leaves), 'certificate')} "
                        f"({_listing(leaves)}) that are neither self-signed nor "
                        "CAs. They cannot anchor a chain and have no effect on "
                        "server trust."
                    ),
                    remedy=(
                        "Trust their issuer instead, or pass them as chain= to "
                        "present them."
                    ),
                    certificates=_infos(leaves),
                )
            )
    return problems


# -- the warning consumer ---------------------------------------------------


# Findings the construction path already reports through a dedicated channel.
# The session's own validity check owns these: it knows about
# warn_if_expires_within and strict_validity, and says it better. Saying it
# twice would be worse than either.
_WARNED_ELSEWHERE = frozenset({"certificate.expired", "certificate.not_yet_valid"})


def emit_warnings(problems: list[Problem], stacklevel: int = 4) -> None:
    """Report *problems* as :class:`~httpx_pki.TLSConfigWarning`\\ s.

    The construction-path consumer, and a strict subset of what the report
    shows -- reporting more is not contradicting. Each warning ends by naming
    the call that lays the whole thing out, because a finding the reader cannot
    act on is only half of one.
    """
    for problem in problems:
        if problem.code in _WARNED_ELSEWHERE:
            continue
        warnings.warn(
            f"{problem.message} {problem.remedy} "
            "Run httpx_pki.explain() or client.explain() for the full chain.",
            TLSConfigWarning,
            stacklevel=stacklevel,
        )
