"""Resolve the HTTP backend: httpx2 when installed, httpx otherwise.

httpx development has continued under pydantic's stewardship as `httpx2
<https://github.com/pydantic/httpx2>`_, which is API-compatible with httpx.
httpx-pki works with either; every internal module imports the backend from
here (``from ._compat import httpx``) so the whole package binds to one
resolved backend, chosen at first import:

1. ``HTTPX_PKI_BACKEND=httpx`` or ``HTTPX_PKI_BACKEND=httpx2`` in the
   environment forces that backend (an escape hatch for environments where
   httpx2 arrives as a transitive dependency of something else but existing
   code still expects :class:`~httpx_pki.PKIClient` to subclass
   ``httpx.Client``).
2. Otherwise httpx2 is preferred when importable, falling back to httpx.

The resolution is import-time and process-wide; :data:`HTTP_BACKEND` reports
which backend won. Nothing here touches ``sys.modules`` -- a user's own
``import httpx`` is never redirected (that is ``httpx2.alias_httpx()``'s job,
and calling it is the application's decision, not this library's).

For type checkers the backend is always httpx: httpx2 is typed as a drop-in
replacement, so annotating against httpx stays correct on both.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx
else:
    _requested = os.environ.get("HTTPX_PKI_BACKEND")
    if _requested == "httpx":
        import httpx
    elif _requested == "httpx2":
        import httpx2 as httpx
    elif _requested:
        raise ImportError(
            f"HTTPX_PKI_BACKEND={_requested!r} is not a supported backend; "
            'set it to "httpx" or "httpx2", or unset it to prefer httpx2 '
            "when installed"
        )
    else:
        try:
            import httpx2 as httpx
        except ImportError:
            import httpx

# "httpx" or "httpx2" -- the module the session classes subclass from. (If the
# application called httpx2.alias_httpx() before importing httpx-pki, the
# fallback import of httpx also lands on httpx2, and this reports that.)
HTTP_BACKEND: str = httpx.__name__

__all__ = ["HTTP_BACKEND", "httpx"]
