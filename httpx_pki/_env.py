"""Construct certificate material from environment variables.

Containerized / 12-factor deployments configure the client certificate through
the environment rather than code. Given a *prefix* (default ``HTTPX_PKI_``):

============================  ====================================================
``{prefix}CERT``              path to a PKCS#12 or PEM source (required)
``{prefix}PASSWORD``          password for the cert / key (optional)
``{prefix}KEY``               path to a separate private key; switches to the
                              ``from_key_pair`` path with ``CERT`` as the cert
``{prefix}CHAIN``             path to intermediate certificates to present to
                              the server, in addition to any carried by ``CERT``
``{prefix}CA``                CA bundle(s) used for *server* trust
                              (``verify=``): a path to a bundle or a
                              directory, or the literal ``system`` for the OS
                              trust store or ``certifi`` for the certifi
                              bundle. Several are separated by
                              :data:`os.pathsep` (``:`` on POSIX, ``;`` on
                              Windows) and their anchors combine, e.g.
                              ``system:/etc/pki/internal-root.pem``. Absent
                              means default trust (the OS trust store since
                              0.8)
``{prefix}IDENTITY``          which identity to present when ``CERT`` is a
                              PKCS#12 or PEM bundle holding several: a file
                              position (``0``), a name substring, a
                              fingerprint, or the literal ``currently_valid``
                              (see :data:`~httpx_pki.currently_valid`)
``{prefix}KEY_USAGE``         identity selector by key usage, comma-separated
                              (e.g. ``digital_signature``)
``{prefix}EXT_KEY_USAGE``     identity selector by extended key usage,
                              comma-separated (e.g. ``client_auth``)
============================  ====================================================
"""

from __future__ import annotations

import os
from typing import Any

from ._exceptions import CertificateLoadError
from ._material import (
    Material,
    encode_password,
    load_material,
    normalize_pem,
    read_source,
    resolve_chain,
)
from ._select import selector_from_string, usages_from_string
from ._ssl import TrustSource, VerifyTypes


def resolve_env_material(prefix: str) -> tuple[Material, VerifyTypes]:
    """Read the ``{prefix}*`` variables into material and a ``verify`` value."""
    cert = os.environ.get(f"{prefix}CERT")
    if not cert:
        raise CertificateLoadError(
            f"environment variable {prefix}CERT is not set"
        )
    password = os.environ.get(f"{prefix}PASSWORD")
    key = os.environ.get(f"{prefix}KEY")
    chain = os.environ.get(f"{prefix}CHAIN")
    ca = os.environ.get(f"{prefix}CA")

    # IDENTITY is a file position when it reads as an integer, currently_valid
    # or for_mtls for those exact literals, and a name (or fingerprint)
    # otherwise; the usage variables are comma-separated lists.
    selectors: dict[str, Any] = {
        "identity": selector_from_string(os.environ.get(f"{prefix}IDENTITY")),
        "key_usage": usages_from_string(os.environ.get(f"{prefix}KEY_USAGE")),
        "extended_key_usage": usages_from_string(
            os.environ.get(f"{prefix}EXT_KEY_USAGE")
        ),
    }
    if key:
        if any(value is not None for value in selectors.values()):
            raise CertificateLoadError(
                f"{prefix}IDENTITY / {prefix}KEY_USAGE / {prefix}EXT_KEY_USAGE "
                f"select an identity inside a PKCS#12 or PEM bundle, but "
                f"{prefix}KEY points at a separate private key; drop one or "
                "the other"
            )
        material = normalize_pem(cert, key, password, chain)
    else:
        material = resolve_chain(
            load_material(read_source(cert), encode_password(password), **selectors),
            chain,
        )

    return material, _env_verify(ca)


def _env_verify(ca: str | None) -> VerifyTypes:
    """The ``verify=`` value for a ``{prefix}CA`` variable.

    Several trust sources are separated by :data:`os.pathsep` -- ``:`` on
    POSIX, ``;`` on Windows -- the separator the platform already uses for
    lists of paths, and the one that cannot appear in a path on the platform
    that uses it. (The comma that separates the usage variables would be
    ambiguous here: a comma is a legal character in a filename everywhere.)
    A single value stays a single value rather than a one-element list, so
    what reaches ``verify=`` is exactly what the equivalent keyword would be::

        HTTPX_PKI_CA=system:/etc/pki/internal-root.pem
    """
    if not ca:
        return True
    parts: list[TrustSource] = [
        item.strip() for item in ca.split(os.pathsep) if item.strip()
    ]
    if not parts:
        return True
    if len(parts) == 1:
        return parts[0]
    return parts
