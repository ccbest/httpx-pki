"""Shared certificate, pickle, and repr behavior for the session classes.

The mixin owns the canonical :class:`~httpx_pki._material.Material` and the
``verify`` policy. It never calls ``super().__init__`` directly; instead each
concrete client implements :meth:`_httpx_init` to forward to the right httpx
base class. This keeps the sync and async clients in lockstep and lets
:meth:`__setstate__` rebuild a client without re-running ``__init__``.
"""

from __future__ import annotations

import ssl
import warnings
from typing import Any, TypeVar

from ._material import CertInfo, Material, cert_info
from ._ssl import VerifyTypes, build_ssl_context

_S = TypeVar("_S", bound="_PKIMixin")


class _PKIMixin:
    _material: Material
    _verify_policy: VerifyTypes
    _httpx_kwargs: dict[str, Any]

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        """Forward to the concrete httpx base class. Overridden per client."""
        raise NotImplementedError

    def _apply_material(
        self,
        material: Material,
        *,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> None:
        self._material = material
        self._verify_policy = verify
        self._httpx_kwargs = kwargs
        context = build_ssl_context(material, verify)
        self._httpx_init(verify=context, **kwargs)

    @classmethod
    def _from_material(
        cls: type[_S],
        material: Material,
        *,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> _S:
        """Build an instance from ready material, bypassing ``__init__``.

        Shared by every alternate constructor (:meth:`from_key_pair`,
        :meth:`from_windows_cert_store`, ...).
        """
        self = cls.__new__(cls)
        self._apply_material(material, verify=verify, **kwargs)
        return self

    def cert_info(self) -> CertInfo:
        """Return subject, validity window, and SANs of the client certificate."""
        return cert_info(self._material.cert_pem)

    @property
    def CN(self) -> str | None:
        """The client certificate's subject Common Name (``None`` if absent)."""
        return cert_info(self._material.cert_pem).common_name

    @property
    def DN(self) -> str:
        """The client certificate's full subject Distinguished Name (RFC 4514)."""
        return cert_info(self._material.cert_pem).distinguished_name

    # -- pickling -----------------------------------------------------------
    #
    # Neither ssl.SSLContext nor httpx's live connection pool can be pickled, so
    # we serialize only the canonical material plus the construction config and
    # rebuild a fresh client on load. The pickle therefore contains the
    # decrypted private key -- store and transmit it as the secret it is.

    def __getstate__(self) -> dict[str, Any]:
        verify = self._verify_policy
        if isinstance(verify, ssl.SSLContext):
            warnings.warn(
                "a custom ssl.SSLContext passed as verify= cannot be pickled; "
                "the unpickled client falls back to default server verification.",
                stacklevel=2,
            )
            verify = True
        return {
            "material": self._material,
            "verify": verify,
            "httpx_kwargs": self._httpx_kwargs,
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        self._apply_material(
            state["material"],
            verify=state["verify"],
            **state["httpx_kwargs"],
        )

    def __repr__(self) -> str:
        info = cert_info(self._material.cert_pem)
        return (
            f"<{type(self).__name__} "
            f"cn={info.common_name!r} "
            f"expires={info.not_after:%Y-%m-%d}>"
        )
