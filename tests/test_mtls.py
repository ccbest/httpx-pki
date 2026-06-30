"""Integration tests: a real mutual-TLS round trip against a localhost server."""

from __future__ import annotations

import pickle
import ssl

import httpx
import pytest

from httpx_pki import AsyncPKCSession, PKCSession
from tests.conftest import P12_PASSWORD, MTLSServer


def test_mtls_request_succeeds(mtls_server: MTLSServer, client_p12: bytes) -> None:
    with PKCSession(
        client_p12, password=P12_PASSWORD, verify=str(mtls_server.ca_file)
    ) as session:
        resp = session.get(mtls_server.url)
        assert resp.status_code == 200
        assert resp.text == "mtls-ok"


def test_mtls_rejects_without_client_cert(mtls_server: MTLSServer) -> None:
    # A plain client (no client certificate) must be rejected by the server.
    ctx = ssl.create_default_context(cafile=str(mtls_server.ca_file))
    with httpx.Client(verify=ctx) as client:
        with pytest.raises(httpx.TransportError):
            client.get(mtls_server.url)


def test_mtls_survives_pickle(mtls_server: MTLSServer, client_p12: bytes) -> None:
    session = PKCSession(
        client_p12, password=P12_PASSWORD, verify=str(mtls_server.ca_file)
    )
    restored = pickle.loads(pickle.dumps(session))
    session.close()
    with restored as client:
        resp = client.get(mtls_server.url)
        assert resp.status_code == 200
        assert resp.text == "mtls-ok"


async def test_mtls_async_request_succeeds(
    mtls_server: MTLSServer, client_p12: bytes
) -> None:
    async with AsyncPKCSession(
        client_p12, password=P12_PASSWORD, verify=str(mtls_server.ca_file)
    ) as session:
        resp = await session.get(mtls_server.url)
        assert resp.status_code == 200
        assert resp.text == "mtls-ok"
