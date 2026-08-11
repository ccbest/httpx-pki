"""Reloadable certificate sources.

Certificate rotation (see :meth:`~httpx_pki.PKIClient.reload`) needs to re-run
the same loading path the original constructor used. Each constructor records
its provenance as a :class:`SourceRef` -- a declarative descriptor (not a
closure, so pickling keeps working) that :func:`resolve_source` turns back into
fresh :class:`~httpx_pki._material.Material`.

The retained ``password`` deserves care: it is kept on the ref **only** when
the client opted into ``auto_reload`` (rotation must be unattended); otherwise
it is stripped, preserving the library's "password is never retained" default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._material import (
    CertSource,
    Material,
    Password,
    chain_sources,
    encode_password,
    load_material,
    normalize_pem,
    parse_pem_bundle,
    parse_pkcs12,
    read_source,
    resolve_chain,
)
from ._pkcs12 import IdentitySelector, material_from_store_export
from ._select import UsageSelector

# One (mtime_ns, size) entry per watched path; None for a path that can't be
# stat'ed (mid-rotation gap, deleted file). Any change in the tuple means the
# source changed on disk.
WatchSignature = tuple["tuple[int, int] | None", ...]


@dataclass(frozen=True)
class SourceRef:
    """Where a client's certificate material came from, for reloading.

    ``kind`` selects the loading path (mirroring the constructor used) and
    ``args`` carries that constructor's arguments verbatim. ``password`` is
    the encoded source password, retained only when ``auto_reload`` is on.
    """

    # "auto" | "pkcs12" | "pem" | "key_pair" | "env" | "winstore"
    # | "macos_keychain"
    kind: str
    args: dict[str, Any]
    password: bytes | None = None


# -- building refs ----------------------------------------------------------
#
# A ref is built by the constructor and then loaded by resolve_source() below,
# which is also what reload() calls. That is the point of these factories: the
# arguments of a construction path are written down once, and the material a
# client is built with comes from the same code that will later rotate it, so
# the two cannot drift.


def bundle_ref(  # pylint: disable=too-many-arguments
    kind: str,
    source: CertSource,
    password: Password = None,
    *,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
    chain: CertSource | list[CertSource] | None = None,
    prune_chain: bool = False,
) -> SourceRef:
    """A ref for the single-source kinds: ``auto``, ``pkcs12``, and ``pem``.

    They differ only in which parser reads the bytes -- content detection, or
    one encoding named outright -- so they take the same arguments and record
    the same *args*.
    """
    return SourceRef(
        kind,
        {
            "source": source,
            "identity": identity,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
            "chain": chain,
            "prune_chain": prune_chain,
        },
        encode_password(password),
    )


def key_pair_ref(
    certificate: CertSource,
    private_key: CertSource,
    password: Password = None,
    *,
    chain: CertSource | list[CertSource] | None = None,
    prune_chain: bool = False,
) -> SourceRef:
    """A ref for a separate certificate and private key.

    No identity selectors: naming the certificate *is* the selection.
    """
    return SourceRef(
        "key_pair",
        {
            "certificate": certificate,
            "private_key": private_key,
            "chain": chain,
            "prune_chain": prune_chain,
        },
        encode_password(password),
    )


def store_ref(kind: str, *, prune_chain: bool = False, **selector: Any) -> SourceRef:
    """A ref for a platform store: ``winstore`` or ``macos_keychain``.

    The *selector* is recorded verbatim and handed back to the store loader on
    every reload (see :func:`_store_args`, which keeps ``prune_chain`` -- a
    chain option, not a store one -- out of that call). No password is carried:
    a store exports under an internally generated single-use one.
    """
    return SourceRef(kind, {**selector, "prune_chain": prune_chain})


def _selectors(args: dict[str, Any]) -> dict[str, Any]:
    """The identity selectors recorded on a ref (PKCS#12 or PEM).

    ``.get`` rather than indexing: refs pickled before identity selection
    existed carry only the certificate arguments, and must keep reloading.
    """
    return {
        name: args.get(name)
        for name in ("identity", "key_usage", "extended_key_usage")
    }


def _store_args(args: dict[str, Any]) -> dict[str, Any]:
    """A platform-store ref's args, minus the ones the loader does not take.

    ``prune_chain`` is a chain option recorded alongside the selector, not
    something the store lookup knows about.
    """
    return {k: v for k, v in args.items() if k != "prune_chain"}


def resolve_source(  # pylint: disable=too-many-return-statements
    ref: SourceRef, password: bytes | None = None
) -> Material:
    """Load fresh material from *ref*, exactly as the constructor did.

    An explicit *password* overrides the one retained on the ref. It only ever
    reaches a kind that decrypts with one: the ``env`` kind re-reads the
    environment (including its own password variable) and the platform stores
    re-export under an internal single-use password, so
    :meth:`~httpx_pki.PKIClient.reload` refuses a password for those rather
    than passing one here to be ignored.
    """
    pw = password if password is not None else ref.password
    args = ref.args
    # .get: refs pickled before chain=/prune_chain= reached these constructors
    # carry no entry, and must keep reloading.
    chain = args.get("chain")
    prune = bool(args.get("prune_chain"))
    if ref.kind == "auto":
        return resolve_chain(
            load_material(read_source(args["source"]), pw, **_selectors(args)),
            chain,
            prune=prune,
        )
    if ref.kind == "pkcs12":
        return resolve_chain(
            parse_pkcs12(read_source(args["source"]), pw, **_selectors(args)),
            chain,
            prune=prune,
        )
    if ref.kind == "pem":
        return resolve_chain(
            parse_pem_bundle(read_source(args["source"]), pw, **_selectors(args)),
            chain,
            prune=prune,
        )
    if ref.kind == "key_pair":
        return resolve_chain(
            normalize_pem(
                args["certificate"], args["private_key"], pw, args["chain"]
            ),
            prune=prune,
        )
    if ref.kind == "env":
        from ._env import resolve_env_material

        material, _verify = resolve_env_material(args["prefix"])
        return material
    if ref.kind == "winstore":
        from ._winstore import load_windows_pkcs12

        pfx, pfx_password, chosen = load_windows_pkcs12(**_store_args(args))
        return resolve_chain(
            material_from_store_export(pfx, pfx_password, chosen), prune=prune
        )
    if ref.kind == "macos_keychain":
        from ._keychain import load_macos_pkcs12

        pfx, pfx_password, chosen = load_macos_pkcs12(**_store_args(args))
        return resolve_chain(
            material_from_store_export(pfx, pfx_password, chosen), prune=prune
        )
    raise ValueError(f"unknown source kind {ref.kind!r}")


def watch_paths(ref: SourceRef) -> list[Path]:
    """The filesystem paths whose change should trigger an auto-reload.

    Only path-typed sources are watchable; in-memory ``bytes`` entries are
    skipped (they can never change) and the Windows store has no file to
    watch. For the ``env`` kind the paths are resolved from the environment
    *now* -- i.e. at construction time.
    """
    args = ref.args
    candidates: list[Any]
    if ref.kind in ("auto", "pkcs12", "pem"):
        candidates = [args["source"], *chain_sources(args.get("chain"))]
    elif ref.kind == "key_pair":
        candidates = [
            args["certificate"],
            args["private_key"],
            *chain_sources(args["chain"]),
        ]
    elif ref.kind == "env":
        prefix = args["prefix"]
        candidates = [
            os.environ.get(f"{prefix}{name}") for name in ("CERT", "KEY", "CHAIN")
        ]
    else:  # winstore / macos_keychain -- nothing on disk to watch
        return []
    return [Path(c) for c in candidates if isinstance(c, (str, Path))]


def is_reloadable(ref: SourceRef) -> bool:
    """Whether :func:`resolve_source` can produce anything new for *ref*.

    ``env`` and platform-store sources always re-resolve; path-based sources
    re-read their files. A source built purely from in-memory bytes has
    nothing to re-read.
    """
    if ref.kind in ("env", "winstore", "macos_keychain"):
        return True
    return bool(watch_paths(ref))


def stat_signature(paths: list[Path]) -> WatchSignature:
    """A cheap fingerprint of *paths*: (mtime_ns, size) each, None if missing."""
    signature: list[tuple[int, int] | None] = []
    for path in paths:
        try:
            stat = path.stat()
            signature.append((stat.st_mtime_ns, stat.st_size))
        except OSError:
            signature.append(None)
    return tuple(signature)
