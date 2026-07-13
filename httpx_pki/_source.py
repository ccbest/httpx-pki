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
    Material,
    load_material,
    normalize_pem,
    parse_pem_bundle,
    parse_pkcs12,
    read_source,
)

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

    kind: str  # "auto" | "pkcs12" | "pem" | "key_pair" | "env" | "winstore"
    args: dict[str, Any]
    password: bytes | None = None


def resolve_source(  # pylint: disable=too-many-return-statements
    ref: SourceRef, password: bytes | None = None
) -> Material:
    """Load fresh material from *ref*, exactly as the constructor did.

    An explicit *password* overrides the one retained on the ref. The ``env``
    kind re-reads the environment (including its password variable); the
    ``winstore`` kind re-exports from the Windows store.
    """
    pw = password if password is not None else ref.password
    args = ref.args
    if ref.kind == "auto":
        return load_material(read_source(args["cert"]), pw)
    if ref.kind == "pkcs12":
        return parse_pkcs12(read_source(args["cert"]), pw)
    if ref.kind == "pem":
        return parse_pem_bundle(read_source(args["source"]), pw)
    if ref.kind == "key_pair":
        return normalize_pem(
            args["certificate"], args["private_key"], pw, args["chain"]
        )
    if ref.kind == "env":
        from ._env import resolve_env_material

        material, _verify = resolve_env_material(args["prefix"])
        return material
    if ref.kind == "winstore":
        from ._winstore import load_windows_pkcs12

        pfx, pfx_password = load_windows_pkcs12(**args)
        return parse_pkcs12(pfx, pfx_password)
    if ref.kind == "macos_keychain":
        from ._keychain import load_macos_pkcs12

        pfx, pfx_password = load_macos_pkcs12(**args)
        return parse_pkcs12(pfx, pfx_password)
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
    if ref.kind in ("auto", "pkcs12"):
        candidates = [args["cert"]]
    elif ref.kind == "pem":
        candidates = [args["source"]]
    elif ref.kind == "key_pair":
        chain = args["chain"]
        if chain is None:
            chain_list: list[Any] = []
        elif isinstance(chain, list):
            chain_list = list(chain)
        else:
            chain_list = [chain]
        candidates = [args["certificate"], args["private_key"], *chain_list]
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
