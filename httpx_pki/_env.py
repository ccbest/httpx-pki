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
``{prefix}CA``                path to a CA bundle used for *server* trust
                              (``verify=``), or the literal ``system`` for
                              the OS trust store; absent means default trust
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
from dataclasses import replace
from typing import Any

from ._exceptions import CertificateLoadError
from ._material import (
    Material,
    encode_password,
    load_chain_pems,
    load_material,
    normalize_pem,
    read_source,
)
from ._select import currently_valid
from ._ssl import VerifyTypes


def _env_selectors(prefix: str) -> dict[str, Any]:
    """Read the identity selectors from ``{prefix}IDENTITY`` and friends.

    ``IDENTITY`` is a file position when it reads as an integer, the
    :data:`~httpx_pki.currently_valid` selector when it is that exact literal,
    and a name (or fingerprint) otherwise; the usage variables are
    comma-separated lists.
    """
    identity: Any = os.environ.get(f"{prefix}IDENTITY") or None
    if identity == "currently_valid":
        identity = currently_valid
    elif isinstance(identity, str) and identity.lstrip("-").isdigit():
        identity = int(identity)
    return {
        "identity": identity,
        "key_usage": _env_list(f"{prefix}KEY_USAGE"),
        "extended_key_usage": _env_list(f"{prefix}EXT_KEY_USAGE"),
    }


def _env_list(name: str) -> list[str] | None:
    value = os.environ.get(name)
    if not value:
        return None
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or None


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

    selectors = _env_selectors(prefix)
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
        material = load_material(
            read_source(cert), encode_password(password), **selectors
        )
        if chain:
            material = replace(
                material, ca_pems=[*material.ca_pems, *load_chain_pems(chain)]
            )

    verify: VerifyTypes = ca if ca else True
    return material, verify
