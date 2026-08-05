"""Tests for the ``_init_state`` subclass hook.

The hook is the documented seam for subclasses that take extra constructor
keywords: it must run on every construction path (``__init__``, the ``from_*``
alternates, unpickling), must not run again on reload, and must leave the
remaining kwargs for httpx.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import pytest

from httpx_pki import AsyncPKIClient, PKIClient
from tests.conftest import CLIENT_CN, P12_PASSWORD, Signed

PROXY = "http://proxy.internal:3128"


class ProxiedClient(PKIClient):
    """A subclass with extra constructor keywords, claimed via _init_state."""

    def _init_state(self, kwargs: dict[str, Any]) -> None:
        self.proxy_url = kwargs.pop("proxy_url", None)
        self.do_not_proxy = kwargs.pop("do_not_proxy", ())
        self.hook_runs = getattr(self, "hook_runs", 0) + 1


class RegionClient(ProxiedClient):
    """A grandchild: chains to the parent hook with super()."""

    def _init_state(self, kwargs: dict[str, Any]) -> None:
        self.region = kwargs.pop("region", "us-east-1")
        super()._init_state(kwargs)


class AsyncProxiedClient(AsyncPKIClient):
    def _init_state(self, kwargs: dict[str, Any]) -> None:
        self.proxy_url = kwargs.pop("proxy_url", None)


def test_init_claims_kwargs(client_p12: bytes) -> None:
    with ProxiedClient(
        client_p12,
        password=P12_PASSWORD,
        proxy_url=PROXY,
        do_not_proxy=("localhost",),
    ) as session:
        assert session.proxy_url == PROXY
        assert session.do_not_proxy == ("localhost",)
        assert session.cert_info().common_name == CLIENT_CN


def test_init_defaults_when_absent(client_p12: bytes) -> None:
    with ProxiedClient(client_p12, password=P12_PASSWORD) as session:
        assert session.proxy_url is None
        assert session.do_not_proxy == ()


def test_alternate_constructor_runs_hook(client_p12: bytes) -> None:
    # from_* constructors bypass __init__ entirely; the hook must still run.
    with ProxiedClient.from_pkcs12(
        client_p12, P12_PASSWORD, proxy_url=PROXY
    ) as session:
        assert isinstance(session, ProxiedClient)
        assert session.proxy_url == PROXY


def test_alternate_constructor_defaults(client: Signed) -> None:
    with ProxiedClient.from_key_pair(
        certificate=client.cert_pem, private_key=client.key_pem
    ) as session:
        assert session.proxy_url is None
        assert session.do_not_proxy == ()


def test_leftover_kwargs_reach_httpx(client_p12: bytes) -> None:
    with ProxiedClient(
        client_p12,
        password=P12_PASSWORD,
        proxy_url=PROXY,
        base_url="https://service.internal",
    ) as session:
        assert session.base_url == "https://service.internal"


def test_unclaimed_kwarg_still_rejected(client_p12: bytes) -> None:
    # A keyword neither the hook nor httpx knows keeps failing loudly.
    with pytest.raises(TypeError):
        ProxiedClient(client_p12, password=P12_PASSWORD, bogus_option=1)


def test_pickle_round_trip_rebuilds_state(client_p12: bytes) -> None:
    session = ProxiedClient(client_p12, password=P12_PASSWORD, proxy_url=PROXY)
    try:
        restored = pickle.loads(pickle.dumps(session))
    finally:
        session.close()
    try:
        assert isinstance(restored, ProxiedClient)
        assert restored.proxy_url == PROXY
        assert restored.do_not_proxy == ()
    finally:
        restored.close()


def test_reload_does_not_rerun_hook(client_p12_file: Path) -> None:
    with ProxiedClient(
        client_p12_file, password=P12_PASSWORD, proxy_url=PROXY
    ) as session:
        assert session.hook_runs == 1
        session.reload(password=P12_PASSWORD)
        assert session.hook_runs == 1
        assert session.proxy_url == PROXY


def test_grandchild_chains_super(client_p12: bytes) -> None:
    with RegionClient.from_pkcs12(
        client_p12, P12_PASSWORD, proxy_url=PROXY, region="eu-west-1"
    ) as session:
        assert session.region == "eu-west-1"
        assert session.proxy_url == PROXY
        assert session.do_not_proxy == ()


async def test_async_hook(client_p12: bytes) -> None:
    async with AsyncProxiedClient(
        client_p12, password=P12_PASSWORD, proxy_url=PROXY
    ) as session:
        assert session.proxy_url == PROXY
    async with AsyncProxiedClient.from_pkcs12(client_p12, P12_PASSWORD) as session:
        assert session.proxy_url is None
