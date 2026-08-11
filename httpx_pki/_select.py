"""Shared certificate-selection logic.

Three surfaces let a caller point at one certificate among several: a
multi-identity PKCS#12 file (:mod:`httpx_pki._pkcs12`), the Windows certificate
store (:mod:`httpx_pki._winstore`), and the macOS keychain
(:mod:`httpx_pki._keychain`). They differ in how the candidates are discovered
and in what names they carry -- a Windows friendly name, a keychain label, a
PKCS#12 bag name -- but the question is the same, so the vocabulary is shared:

* the *usage* selectors (``key_usage``, ``extended_key_usage``) and their
  spelling rules live here and behave identically everywhere;
* :func:`select_certificate` is the generic store selector, wrapped by each
  platform module with its concrete type
  (:func:`~httpx_pki._winstore.select_windows_certificate`,
  :func:`~httpx_pki._keychain.select_macos_certificate`);
* :data:`currently_valid` is the ready-made renewal selector, accepted
  anywhere an ``identity`` is.

Every selector **intersects**: each one given narrows the candidates further,
so a name and a key usage together mean "both", never "whichever is more
specific". Selecting the signing half of a dual key pair is exactly that
combination.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Protocol, TypeVar

from cryptography import x509

from ._exceptions import AmbiguousCertificateError, CertificateNotFoundError
from ._material import _EKU_NAMES, KEY_USAGE_NAMES, CertInfo

# One usage name or several; every named usage must be present to match.
UsageSelector = str | Iterable[str]


class _StoreCert(Protocol):
    """What the generic selector needs from a platform certificate record."""

    @property
    def subject_cn(self) -> str | None:
        """The certificate's subject common name."""

    @property
    def thumbprint(self) -> str:
        """The certificate's thumbprint as normalized uppercase hex."""

    @property
    def info(self) -> CertInfo | None:
        """The parsed certificate summary, if the record could be read."""

    @property
    def key_usage(self) -> frozenset[str]:
        """The asserted KeyUsage bits (empty when unknown)."""

    @property
    def extended_key_usage(self) -> list[str]:
        """The ExtendedKeyUsage entries (empty when unknown)."""


_C = TypeVar("_C", bound=_StoreCert)


class _CertDetails:
    """Usage accessors derived from a candidate's :class:`CertInfo`.

    Mixed into every selectable certificate type so one predicate reads the
    same whether it is filtering a PKCS#12 file, the Windows store, or the
    macOS keychain::

        identity=lambda c: "digital_signature" in c.key_usage

    Both accessors are empty rather than ``None`` when the certificate could
    not be read, so a predicate never has to guard against it -- such a
    candidate simply never matches a usage selector.
    """

    info: CertInfo | None

    @property
    def key_usage(self) -> frozenset[str]:
        """The asserted KeyUsage bits, by their attribute names."""
        return frozenset() if self.info is None else self.info.key_usage

    @property
    def extended_key_usage(self) -> list[str]:
        """The ExtendedKeyUsage entries, named where cryptography names them."""
        return [] if self.info is None else self.info.extended_key_usage


def normalize_thumbprint(value: str) -> str:
    """Normalize a thumbprint for comparison: strip colons/spaces, uppercase."""
    return value.replace(":", "").replace(" ", "").upper()


# -- the currently-valid selector -------------------------------------------


class _CurrentlyValid:
    """The ready-made "whichever certificate is valid right now" selector.

    See :data:`currently_valid`, its only instance.
    """

    def __call__(self, candidate: _StoreCert) -> bool:
        info = candidate.info
        if info is None:
            return False
        now = datetime.datetime.now(datetime.timezone.utc)
        return info.not_valid_before <= now <= info.not_valid_after

    @staticmethod
    def narrow(matches: Sequence[_C]) -> list[_C]:
        """Of several valid candidates, the one(s) with the latest window.

        Freshness can break a tie only between certificates that are otherwise
        interchangeable -- a renewal overlap, where the certificates differ in
        nothing but their validity window. Candidates that differ in subject or
        usage (the halves of a dual key pair, minted moments apart) are *not*
        interchangeable, so they are returned unchanged and the ambiguity
        surfaces, pointing at a usage selector.
        """
        profiles = {
            (
                m.info.distinguished_name,
                m.info.key_usage,
                tuple(sorted(m.info.extended_key_usage)),
            )
            for m in matches
            if m.info is not None
        }
        if len(profiles) != 1:
            return list(matches)
        latest = max(
            (m.info.not_valid_after, m.info.not_valid_before)
            for m in matches
            if m.info is not None
        )
        return [
            m
            for m in matches
            if m.info is not None
            and (m.info.not_valid_after, m.info.not_valid_before) == latest
        ]

    def __repr__(self) -> str:
        return "httpx_pki.currently_valid"

    def __reduce__(self) -> str:
        # Pickle by name, so an unpickled SourceRef holds this same instance.
        return "currently_valid"


class _ForMTLS:
    """The ready-made "the one I can actually do mTLS with" selector.

    See :data:`for_mtls`, its only instance.
    """

    def __call__(self, candidate: _StoreCert) -> bool:
        info = candidate.info
        if info is None:
            return False
        now = datetime.datetime.now(datetime.timezone.utc)
        if not info.not_valid_before <= now <= info.not_valid_after:
            return False
        # Two extensions have a say about client authentication, and an
        # *absent* one is permissive in X.509: it means "unconstrained", not
        # "forbidden".
        #
        # ExtendedKeyUsage decides first. Present and listing client_auth: yes.
        # Present and not listing it: no -- the CA said what this certificate
        # is for, and it is not this. Absent: no opinion, so fall through.
        if info.extended_key_usage:
            return "client_auth" in info.extended_key_usage
        # KeyUsage then has to allow the handshake signature. A TLS client
        # proves possession of its key by signing, so digital_signature is
        # required when KeyUsage is asserted at all. This is what separates the
        # halves of a dual key pair that carry no EKU: the encryption half
        # asserts only key_encipherment and cannot sign.
        return not info.key_usage or "digital_signature" in info.key_usage

    # A tie between candidates that are all usable is a renewal overlap, which
    # is exactly what currently_valid already resolves: prefer the latest
    # window, and only between certificates that are otherwise
    # interchangeable. The halves of a dual key pair never reach it -- the
    # encryption half is filtered out above.
    narrow = staticmethod(_CurrentlyValid.narrow)

    def __repr__(self) -> str:
        return "httpx_pki.for_mtls"

    def __reduce__(self) -> str:
        # Pickle by name, so an unpickled SourceRef holds this same instance.
        return "for_mtls"


currently_valid = _CurrentlyValid()
"""Selector for the certificate whose validity window contains *now*.

Usable anywhere an ``identity`` is -- ``identity=currently_valid`` for PKCS#12
and PEM bundles and for the platform stores alike. Built for
the renewal case -- a bundle or store holding the renewed certificate alongside
the one it replaces::

    PKIClient("corp.p12", password=pw, identity=currently_valid)

Not-yet-valid and expired candidates never match. During a renewal *overlap*,
when old and new are both valid, the tie resolves to the latest validity window
-- but only between certificates that are otherwise interchangeable (same
subject and usages). The halves of a dual key pair stay ambiguous: freshness
cannot tell a signing certificate from an encryption one, so combine with
``key_usage=`` instead -- or use :data:`for_mtls`, which applies both rules.
"""

for_mtls = _ForMTLS()
"""Selector for the identity you can actually authenticate with, right now.

**The one to reach for first.** It answers the question nearly every caller is
really asking -- *which of these should I be presenting?* -- and covers the two
situations that otherwise need different selectors, together::

    PKIClient("corp.p12", password=pw, identity=for_mtls)

A candidate qualifies when its validity window contains now **and** its usages
permit TLS client authentication: an ExtendedKeyUsage listing ``client_auth``,
or no ExtendedKeyUsage at all together with a KeyUsage that allows signing --
an absent extension is unconstrained in X.509, not forbidden. That is exactly
the signing half of a dual key pair, and exactly the current certificate of a
renewal pair. During a renewal
overlap, where both are usable, the later window wins -- the same tie-break
:data:`currently_valid` applies.

Usable anywhere an ``identity`` is, for PKCS#12 and PEM bundles and for the
platform stores alike. It is a filter like any other, so when nothing qualifies
it raises :class:`~httpx_pki.CertificateNotFoundError` listing what was there
-- an expired certificate or an encryption-only one is not silently presented.
"""


def _narrowed(selector: object, matches: list[_C]) -> list[_C]:
    """Apply a selector's tie-break, when it carries one and several match.

    A selector object may expose ``narrow(matches)`` returning the subset it
    considers best (:data:`currently_valid` keeps the latest validity window).
    It runs only after every filter has intersected, so it breaks ties the
    filters could not -- it never overrides an explicit selector.
    """
    narrow = getattr(selector, "narrow", None)
    if narrow is None or len(matches) < 2:
        return matches
    return narrow(matches) or matches


# -- usage vocabulary -------------------------------------------------------


def _squash(name: str) -> str:
    """Normalize a usage name: ``keyEncipherment`` == ``key_encipherment``."""
    return name.lower().replace("_", "").replace("-", "")


_KEY_USAGE_BY_SQUASHED = {_squash(name): name for name in KEY_USAGE_NAMES}
# X.509 renamed the nonRepudiation bit to contentCommitment, and cryptography
# follows the new name -- but CA documentation, openssl's own output, and the
# schemes that lean on the bit all still say nonRepudiation, so accept both.
_KEY_USAGE_BY_SQUASHED[_squash("non_repudiation")] = "content_commitment"
_EKU_BY_SQUASHED = {_squash(name): name for name in _EKU_NAMES.values()}


def _as_names(value: UsageSelector, what: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    try:
        names = list(value)
    except TypeError as exc:
        raise TypeError(
            f"{what} must be a string or an iterable of strings, got "
            f"{type(value).__name__}"
        ) from exc
    if not names:
        raise ValueError(f"{what} must name at least one usage")
    return names


def normalize_key_usages(value: UsageSelector) -> list[str]:
    """Canonical KeyUsage attribute names, rejecting anything unknown."""
    resolved = []
    for name in _as_names(value, "key_usage"):
        canonical = _KEY_USAGE_BY_SQUASHED.get(_squash(name))
        if canonical is None:
            raise ValueError(
                f"unknown key usage {name!r}; valid usages are "
                + ", ".join(KEY_USAGE_NAMES)
            )
        resolved.append(canonical)
    return resolved


def normalize_extended_key_usages(value: UsageSelector) -> list[str]:
    """Canonical extended key usage names; dotted OIDs are accepted as-is."""
    resolved = []
    for name in _as_names(value, "extended_key_usage"):
        canonical = _EKU_BY_SQUASHED.get(_squash(name))
        # More than two all-digit components: a dotted OID rather than a name.
        parts = name.split(".")
        if canonical is None and len(parts) > 2 and all(p.isdigit() for p in parts):
            # Name it if cryptography knows it, so it compares equal to what
            # CertInfo reports; otherwise keep the dotted form.
            canonical = _EKU_NAMES.get(x509.ObjectIdentifier(name), name)
        if canonical is None:
            raise ValueError(
                f"unknown extended key usage {name!r}; pass a dotted OID or "
                "one of " + ", ".join(sorted(_EKU_BY_SQUASHED.values()))
            )
        resolved.append(canonical)
    return resolved


def eku_object_identifier(name: str) -> x509.ObjectIdentifier:
    """The OID behind a canonical extended key usage name or dotted OID."""
    for oid, known in _EKU_NAMES.items():
        if known == name:
            return oid
    return x509.ObjectIdentifier(name)


def matches_usages(
    candidate: _StoreCert,
    key_usage: UsageSelector | None,
    extended_key_usage: UsageSelector | None,
) -> bool:
    """Whether *candidate* asserts every usage the selectors name.

    Shared by the store selector and the PKCS#12 one so the two never drift.
    Normalization happens here, so an unknown usage name raises rather than
    quietly matching nothing.
    """
    if key_usage is not None:
        wanted = normalize_key_usages(key_usage)
        if not all(usage in candidate.key_usage for usage in wanted):
            return False
    if extended_key_usage is not None:
        wanted = normalize_extended_key_usages(extended_key_usage)
        if not all(usage in candidate.extended_key_usage for usage in wanted):
            return False
    return True


# -- matching a textual identity= -------------------------------------------

# How a surface names its candidates, subject common name first: the Windows
# friendly name, the keychain label, the PKCS#12 bag name.
Aliases = Callable[[Any], "tuple[str | None, ...]"]


def matches_alias(candidate: _StoreCert, needle: str, aliases: Aliases) -> bool:
    """Match a string ``identity=`` against one candidate.

    One rule, wherever the candidate came from: a full-length hex digest is an
    exact fingerprint comparison (SHA-1 or SHA-256, with colons, spaces, and
    case ignored), and anything else is a case-insensitive substring of the
    candidate's names -- those *aliases* reports, plus the full subject DN,
    which every candidate has. That is what lets ``identity="ACME"`` mean the
    same thing whether the source is a ``.p12`` bundle, the Windows store, or
    the macOS keychain: one implementation, rather than two that have to be
    kept in step by hand.

    The subject is included here rather than left to each caller because
    ``identity=`` is the *portable* spelling, and a DN pasted out of
    ``openssl x509 -subject`` has to select the same certificate everywhere.
    The platform-flavored ``name=`` is a different question and keeps its own
    documented aliases -- it never comes through here.
    """
    target = normalize_thumbprint(needle)
    if len(target) in (40, 64) and all(c in "0123456789ABCDEF" for c in target):
        digests = {candidate.thumbprint}
        if candidate.info is not None:
            digests.add(candidate.info.fingerprint_sha256)
        return target in digests
    info = candidate.info
    subject = info.distinguished_name if info is not None else None
    lowered = needle.lower()
    return any(
        alias is not None and lowered in alias.lower()
        for alias in (*aliases(candidate), subject)
    )


# -- store selection --------------------------------------------------------


def select_certificate(  # pylint: disable=too-many-arguments
    candidates: Sequence[_C],
    *,
    name: str | None,
    thumbprint: str | None,
    identity: str | Callable[[_C], bool] | None,
    aliases: Callable[[_C], tuple[str | None, ...]],
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> _C:
    """Choose a single certificate from *candidates*.

    Every selector given must match: an ``identity`` (a name substring, an
    exact SHA-1/SHA-256 fingerprint, or a predicate callable), an exact
    ``thumbprint`` (compared normalized -- colons, spaces, and case are
    ignored), a case-insensitive ``name`` substring matched against the strings
    *aliases* extracts from each candidate, and the ``key_usage`` /
    ``extended_key_usage`` the certificate must assert. With no selector, all
    candidates qualify (handy when the store holds exactly one).
    ``identity=currently_valid`` picks the certificate whose validity window
    contains now, preferring the renewed one during a renewal overlap.

    *aliases* extracts a candidate's names, **subject common name first**;
    ``identity`` additionally matches the full subject DN (see
    :func:`matches_alias`).

    ``name``/``thumbprint`` are the unambiguous spellings; ``identity`` is the
    portable one, accepting exactly what a PKCS#12 or PEM bundle's ``identity``
    does apart from an integer position -- a store has no stable ordering, so
    that is rejected rather than silently indexing.

    Raises :class:`~httpx_pki.CertificateNotFoundError` if nothing matches and
    :class:`~httpx_pki.AmbiguousCertificateError` if more than one does.
    """
    if isinstance(identity, bool) or isinstance(identity, int):
        raise TypeError(
            "identity= cannot be an integer for a platform certificate store: "
            "a store has no stable ordering, so a position would select a "
            "different certificate from one run to the next. Use a name, a "
            "thumbprint, or a predicate."
        )
    matches = list(candidates)
    if thumbprint is not None:
        target = normalize_thumbprint(thumbprint)
        matches = [c for c in matches if c.thumbprint == target]
    if identity is not None:
        if isinstance(identity, str):
            needle = identity
            matches = [c for c in matches if matches_alias(c, needle, aliases)]
        else:
            matches = [c for c in matches if identity(c)]
    if name is not None:
        needle = name.lower()
        matches = [
            c
            for c in matches
            if any(
                alias is not None and needle in alias.lower()
                for alias in aliases(c)
            )
        ]
    if key_usage is not None or extended_key_usage is not None:
        matches = [
            c for c in matches if matches_usages(c, key_usage, extended_key_usage)
        ]
    if identity is not None:
        matches = _narrowed(identity, matches)

    selector = selector_repr(
        name=name,
        thumbprint=thumbprint,
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
    )
    # The common name comes first by the aliases convention, so anything after
    # it is the store's own label -- a Windows friendly name, a keychain label
    # -- which is often the only thing an operator recognizes.
    def nickname(candidate: Any) -> str | None:
        return next((a for a in aliases(candidate)[1:] if a), None)

    if not matches:
        raise CertificateNotFoundError(
            f"{selector} matched no certificate in the store, which holds:"
            f"\n{listing(candidates, nickname=nickname)}"
        )
    if len(matches) > 1:
        raise AmbiguousCertificateError(
            f"{selector} matched {len(matches)} certificates:"
            f"\n{listing(matches, nickname=nickname)}\n"
            "Narrow it with a more specific name, a key usage, or an exact "
            "thumbprint."
        )
    return matches[0]


def listing(
    candidates: Sequence[_StoreCert],
    *,
    prefix: Callable[[Any], str] = lambda _candidate: "",
    nickname: Callable[[Any], str | None] = lambda _candidate: None,
) -> str:
    """The candidates as one indented line each, for an error message.

    Everything that plausibly distinguishes two entries is on the line: the
    usage separates the halves of a dual key pair, and the expiry separates a
    renewed certificate from the one it replaces -- both of which a real store
    or bundle holds side by side. The extended usage appears when any candidate
    carries one, since that is what :data:`for_mtls` filters on and therefore
    what explains a miss.

    One layout for every surface, so the listing that explains a failed
    ``identity=`` reads the same wherever it came from. *prefix* is what a
    bundle puts in front of the name (its ``[index]``, the one thing a store
    has no equivalent of, having no stable ordering) and *nickname* the label
    the source attached, if any.
    """
    lines = []
    show_eku = any(c.extended_key_usage for c in candidates)
    for candidate in candidates:
        parts = [f"  {prefix(candidate)}{candidate.subject_cn or '<no CN>'}"]
        label = nickname(candidate)
        if label:
            parts.append(f"({label})")
        usage = ",".join(sorted(candidate.key_usage)) or "<none>"
        parts.append(f"key_usage={usage}")
        if show_eku:
            eku = ",".join(candidate.extended_key_usage) or "<none>"
            parts.append(f"ext_key_usage={eku}")
        if candidate.info is not None:
            parts.append(f"expires={candidate.info.not_valid_after:%Y-%m-%d}")
        parts.append(candidate.thumbprint)
        lines.append(" ".join(parts))
    return "\n".join(lines) if lines else "  (nothing)"


def selector_repr(  # pylint: disable=too-many-arguments
    *,
    name: str | None = None,
    thumbprint: str | None = None,
    identity: object = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> str:
    """The selectors that were given, as ``k=v + k=v``, for an error message."""
    described = []
    if thumbprint is not None:
        described.append(f"thumbprint={thumbprint!r}")
    if identity is not None:
        described.append(f"identity={identity!r}")
    if name is not None:
        described.append(f"name={name!r}")
    if key_usage is not None:
        described.append(f"key_usage={key_usage!r}")
    if extended_key_usage is not None:
        described.append(f"extended_key_usage={extended_key_usage!r}")
    return " + ".join(described) if described else "no selector"


def selector_from_string(value: str | None) -> Any:
    """A textual ``identity=`` selector as the object the selectors expect.

    Shared by the environment variables and the command line, which both have
    only strings to work with: a file position when it reads as an integer, the
    :data:`~httpx_pki.currently_valid` selector for that exact literal, and a
    name or fingerprint otherwise. One implementation so the two spellings
    cannot drift.
    """
    if not value:
        return None
    if value == "currently_valid":
        return currently_valid
    if value == "for_mtls":
        return for_mtls
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def usages_from_string(value: str | None) -> list[str] | None:
    """A comma-separated usage list, as the selectors expect it."""
    if not value:
        return None
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or None
