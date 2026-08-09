"""TLS 1.3 post-handshake client authentication (RFC 8446 section 4.6.2).

A server that requires mTLS on only some routes cannot ask for the certificate
during the handshake -- it does not know the route yet. Through TLS 1.2 it
renegotiated; TLS 1.3 removed renegotiation, so it sends a bare
``CertificateRequest`` once the handshake is done instead. The client may only
be asked if it advertised willingness in its ClientHello, which is decided
before the connection carries anything, so every context httpx-pki builds
offers it.
"""

from __future__ import annotations

import pickle
import ssl
from pathlib import Path

import pytest

from httpx_pki import AsyncPKIClient, PKIClient, build_ssl_context
from tests.conftest import CLIENT_CN, P12_PASSWORD, PHAServer, Signed


def _peer_cn(peercert: object) -> str | None:
    if not isinstance(peercert, dict):
        return None
    subject = peercert.get("subject") or ()
    return dict(pair for rdn in subject for pair in rdn).get("commonName")


# -- the wire behavior ------------------------------------------------------


def test_server_can_ask_after_the_handshake(
    pha_server: PHAServer, client_p12: bytes
) -> None:
    """The whole point: a late CertificateRequest is answered."""
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(pha_server.ca_file)
    )
    seen = pha_server.exchange(ctx)

    assert "error" not in seen, seen["error"]
    # The handshake finished with no certificate -- that is what makes this
    # post-handshake auth rather than ordinary mTLS.
    assert not seen["before"]
    assert _peer_cn(seen["after"]) == CLIENT_CN


def test_without_the_extension_the_server_cannot_ask(
    pha_server: PHAServer, client_p12: bytes
) -> None:
    """The counterfactual, so the test above cannot pass vacuously.

    Turning the flag back off is exactly the pre-fix behavior: the server is
    protocol-barred from asking, and the connection dies on a handshake that
    appeared to succeed.
    """
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(pha_server.ca_file)
    )
    ctx.post_handshake_auth = False

    seen = pha_server.exchange(ctx)

    assert "EXTENSION_NOT_RECEIVED" in str(seen.get("error"))
    assert _peer_cn(seen.get("after")) is None


# -- every construction path offers it --------------------------------------


def test_build_ssl_context_offers_it(client_p12: bytes) -> None:
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD)
    assert ctx.post_handshake_auth is True


@pytest.mark.parametrize("cls", [PKIClient, AsyncPKIClient])
def test_clients_offer_it(cls: type, client_p12: bytes) -> None:
    client = cls(client_p12, password=P12_PASSWORD)
    assert client.ssl_context.post_handshake_auth is True


def test_from_key_pair_offers_it(client: Signed, tmp_path: Path) -> None:
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_bytes(client.cert_pem)
    key.write_bytes(client.key_pem)

    session = PKIClient.from_key_pair(cert, key)
    assert session.ssl_context.post_handshake_auth is True


def test_a_supplied_context_is_given_it_too(client_p12: bytes) -> None:
    """A caller-supplied ``verify=`` context has the certificate loaded into
    it in place, and is offered post-handshake auth on the same terms."""
    supplied = ssl.create_default_context()
    assert supplied.post_handshake_auth is False

    with pytest.warns(Warning):
        ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify=supplied)

    assert ctx is supplied
    assert supplied.post_handshake_auth is True


def test_it_survives_a_reload(client_p12_file: Path) -> None:
    """``reload()`` swaps material into the mounted context rather than
    rebuilding it, so the offer must still stand afterwards."""
    session = PKIClient(client_p12_file, password=P12_PASSWORD)
    session.reload(password=P12_PASSWORD)
    assert session.ssl_context.post_handshake_auth is True


def test_it_survives_a_pickle_round_trip(client_p12: bytes) -> None:
    session = PKIClient(client_p12, password=P12_PASSWORD)
    restored = pickle.loads(pickle.dumps(session))
    assert restored.ssl_context.post_handshake_auth is True
