"""Warning about certificate material that is loaded but cannot do its job.

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

Everything here is advisory and best-effort: the audit runs on material that
has already been loaded, never decides whether a load succeeds, and treats a
certificate it cannot parse as one it has nothing to say about. A warning it
cannot justify is worse than no warning, so the self-signed case -- a root CA,
and equally the self-signed server certificate a development setup pins -- is
silent, and the chain walk follows every path rather than one, so a
cross-signed certificate is not mistaken for a stray.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ._exceptions import TLSConfigWarning


@dataclass(frozen=True)
class TrustSourceCerts:
    """The certificates a single ``verify=`` entry contributed.

    ``certificates`` is empty for an entry that was not parsed -- the curated
    bundles (``system``, ``certifi``), which are not where this mistake lives,
    and anything OpenSSL accepted that ``cryptography`` would not.
    """

    label: str
    certificates: list[x509.Certificate]


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
    """A certificate as one short phrase, for a warning message."""
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if attrs:
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")
    return cert.subject.rfc4514_string() or "<no subject>"


def _listing(certs: list[x509.Certificate]) -> str:
    return ", ".join(repr(_describe(cert)) for cert in certs)


def audit_trust_sources(
    sources: list[TrustSourceCerts], client_cert: x509.Certificate | None
) -> None:
    """Warn about ``verify=`` entries that cannot serve as trust anchors.

    Grouped per source and per category rather than one warning per
    certificate: a bundle assembled wrongly is one mistake, and reporting it
    once with the names keeps a ten-certificate file from producing ten
    warnings.
    """
    client_fingerprint = (
        client_cert.fingerprint(hashes.SHA256()) if client_cert is not None else None
    )
    for source in sources:
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
            warnings.warn(
                f"verify={source.label!r} contains this client's own "
                "certificate. verify= configures which CAs you trust to "
                "identify the *server*; your own certificate belongs in the "
                "source= argument, which it already is. This entry has no "
                "effect on server trust.",
                TLSConfigWarning,
                stacklevel=4,
            )
        if intermediates:
            warnings.warn(
                f"verify={source.label!r} contains {len(intermediates)} "
                f"intermediate CA certificate(s) ({_listing(intermediates)}), "
                "which are not self-signed. Trusting an intermediate as an "
                "anchor accepts any server below it without ever checking the "
                "root that issued it. Trust the root instead, or -- if you "
                "meant to *present* these to the server -- pass them as chain=.",
                TLSConfigWarning,
                stacklevel=4,
            )
        if leaves:
            warnings.warn(
                f"verify={source.label!r} contains {len(leaves)} certificate(s) "
                f"({_listing(leaves)}) that are neither self-signed nor CAs, so "
                "they cannot anchor a chain and have no effect on server "
                "trust. A leaf certificate here is usually one meant for "
                "chain=, or a file added to the list in the hope that "
                "something in it would help.",
                TLSConfigWarning,
                stacklevel=4,
            )


def _issued(candidate: x509.Certificate, child: x509.Certificate) -> bool:
    """Whether *candidate* could be the issuer of *child*.

    Names first, then the key identifiers when both carry them: matching
    AuthorityKeyIdentifier to SubjectKeyIdentifier is what tells two CA
    certificates with the same subject apart, which is exactly the situation a
    re-keyed or cross-signed CA creates. Signature verification would be the
    rigorous test and is deliberately not done -- this decides whether to warn,
    and a warning that costs a public-key operation per pair is not worth it.
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


def audit_presented_chain(
    client_cert: x509.Certificate, chain: list[x509.Certificate]
) -> None:
    """Warn about presented certificates that are not on the client's chain.

    Reachability from the leaf, following *every* path rather than one: a CA
    that has been cross-signed appears twice with the same subject, and both
    copies legitimately extend a path, so a walk that committed to the first
    match would report the other as a stray. A certificate nothing reaches is
    one the bundle should not be presenting.

    Nothing is said about a chain that stops short of a self-signed root. That
    is the normal shape -- the root is what the server already has, and sending
    it is unnecessary rather than wrong -- and a certificate whose issuer is
    missing entirely is already reported here as the stray it is.
    """
    if not chain:
        return
    leaf_fingerprint = client_cert.fingerprint(hashes.SHA256())
    # A copy of the client certificate inside its own chain is not a stray --
    # it is the start of the chain, sent twice. Distinct mistake, distinct
    # message, and it must not be counted among the certificates that fail to
    # connect the leaf to its issuer.
    duplicates = [
        cert for cert in chain if cert.fingerprint(hashes.SHA256()) == leaf_fingerprint
    ]
    if duplicates:
        warnings.warn(
            "the client certificate itself is also among the chain "
            "certificates presented alongside it, so it goes on the wire "
            "twice. Chain certificates are the intermediates between it and "
            "its issuer; drop it from that list.",
            TLSConfigWarning,
            stacklevel=4,
        )
    chain = [
        cert for cert in chain if cert.fingerprint(hashes.SHA256()) != leaf_fingerprint
    ]
    if not chain:
        return
    reached = {leaf_fingerprint}
    frontier = [client_cert]
    remaining = list(chain)
    while frontier:
        child = frontier.pop()
        still_unreached: list[x509.Certificate] = []
        for candidate in remaining:
            if _issued(candidate, child):
                fingerprint = candidate.fingerprint(hashes.SHA256())
                if fingerprint not in reached:
                    reached.add(fingerprint)
                    frontier.append(candidate)
            else:
                still_unreached.append(candidate)
        remaining = still_unreached

    if not remaining:
        return
    if len(remaining) == len(chain):
        warnings.warn(
            f"none of the {len(chain)} certificate(s) presented alongside the "
            f"client certificate ({_listing(remaining)}) connect it to its "
            f"issuer ({_describe_issuer(client_cert)}). The server will not be "
            "able to build a path and is likely to reject the handshake with "
            "an unknown-CA alert. Check that these are the intermediates for "
            "*this* certificate.",
            TLSConfigWarning,
            stacklevel=4,
        )
        return
    warnings.warn(
        f"{len(remaining)} of the {len(chain)} certificate(s) presented "
        f"alongside the client certificate ({_listing(remaining)}) are not on "
        "its chain -- nothing between the client certificate and its root is "
        "issued by them. They are presented to the server for nothing, and a "
        "server that validates the chain strictly may reject it.",
        TLSConfigWarning,
        stacklevel=4,
    )


def _describe_issuer(cert: x509.Certificate) -> str:
    attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not attrs:
        return repr(cert.issuer.rfc4514_string())
    value = attrs[0].value
    if isinstance(value, str):
        return repr(value)
    return repr(value.decode("utf-8", "replace"))
