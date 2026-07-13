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
                              (``verify=``); absent means default trust
============================  ====================================================
"""

from __future__ import annotations

import os
from dataclasses import replace

from ._exceptions import CertificateLoadError
from ._material import (
    Material,
    encode_password,
    load_chain_pems,
    load_material,
    normalize_pem,
    read_source,
)
from ._ssl import VerifyTypes


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

    if key:
        material = normalize_pem(cert, key, password, chain)
    else:
        material = load_material(read_source(cert), encode_password(password))
        if chain:
            material = replace(
                material, ca_pems=[*material.ca_pems, *load_chain_pems(chain)]
            )

    verify: VerifyTypes = ca if ca else True
    return material, verify
