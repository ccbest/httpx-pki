"""Shared fixtures: an in-memory test CA, client material, and an mTLS server."""

from __future__ import annotations

import datetime
import hashlib
import http.server
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from httpx_pki.testing import CertBundle, make_client_cert, make_pkcs12

P12_PASSWORD = "secret"
CLIENT_CN = "test-client"


@dataclass
class Signed:
    key: rsa.RSAPrivateKey
    cert: x509.Certificate

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _make_ca() -> Signed:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "httpx-pki test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # keyCertSign/cRLSign required for a CA under OpenSSL 3.x (Python 3.13+).
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return Signed(key, cert)


def _sign(
    ca: Signed, common_name: str, sans: list[x509.GeneralName] | None = None
) -> Signed:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    cert = builder.sign(ca.key, hashes.SHA256())
    return Signed(key, cert)


@pytest.fixture(scope="session")
def ca() -> Signed:
    return _make_ca()


@pytest.fixture(scope="session")
def ca_file(ca: Signed, tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("ca") / "ca.pem"
    path.write_bytes(ca.cert_pem)
    return path


@pytest.fixture(scope="session")
def client(ca: Signed) -> Signed:
    sans = [x509.DNSName("test-client.example.com")]
    return _sign(ca, CLIENT_CN, sans)


@pytest.fixture(scope="session")
def client_p12(client: Signed) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        name=b"client",
        key=client.key,
        cert=client.cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            P12_PASSWORD.encode()
        ),
    )


@pytest.fixture(scope="session")
def client_p12_file(
    client_p12: bytes, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    path = tmp_path_factory.mktemp("p12") / "client.p12"
    path.write_bytes(client_p12)
    return path


@pytest.fixture(scope="session")
def ca_bundle(ca: Signed) -> CertBundle:
    """The test CA as a :class:`CertBundle`, for the testing-module helpers."""
    return CertBundle(key=ca.key, cert=ca.cert)


@pytest.fixture(scope="session")
def dual_identities(ca_bundle: CertBundle) -> tuple[CertBundle, CertBundle]:
    """A dual key pair: same subject, one signing and one encryption identity.

    What a CA that escrows the encryption key issues -- the two certificates
    differ only in their key usage (and, here, their extended key usage), which
    is exactly the case identity selection exists for.
    """
    signing = make_client_cert(
        CLIENT_CN,
        ca=ca_bundle,
        key_usage=["digital_signature"],
        extended_key_usage=["client_auth"],
    )
    encryption = make_client_cert(
        CLIENT_CN,
        ca=ca_bundle,
        key_usage=["key_encipherment"],
        extended_key_usage=["email_protection"],
    )
    return signing, encryption


@pytest.fixture(scope="session")
def dual_p12(dual_identities: tuple[CertBundle, CertBundle]) -> bytes:
    """The dual key pair as one password-protected PKCS#12 bundle."""
    signing, encryption = dual_identities
    return make_pkcs12(
        [(signing, "Signature"), (encryption, "Encryption")],
        password=P12_PASSWORD,
    )


@pytest.fixture(scope="session")
def server_cert(ca: Signed) -> Signed:
    sans = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    return _sign(ca, "localhost", sans)


@dataclass
class PHAServer:
    """A TLS 1.3 server that asks for the client certificate *after* the
    handshake, the way a route-scoped mTLS server does.

    Not an HTTP server: the exchange under test is the TLS one, and httpx
    contributes nothing to it beyond handing the ``ssl.SSLContext`` down to
    the socket. Speaking the three messages directly keeps the test off
    keep-alive timing, which is what decides whether the server gets a second
    read to process the client's certificate on.

    ``exchange()`` runs one connection to completion and reports what the
    server saw: ``before`` and ``after`` are the peer certificate as of the
    end of the handshake and after the post-handshake request, and ``error``
    is set instead when the server could not ask at all.
    """

    host: str
    ca_file: Path
    _context: ssl.SSLContext

    def exchange(self, client_context: ssl.SSLContext) -> dict[str, object]:
        """Connect with *client_context* and return what the server observed."""
        seen: dict[str, object] = {}

        def serve(listener: socket.socket) -> None:
            conn, _ = listener.accept()
            try:
                with self._context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(4096)  # the client's opening bytes
                    seen["before"] = tls.getpeercert()
                    # Ask now. The request rides out with the next write, and
                    # the client's certificate arrives on the read after that.
                    tls.verify_client_post_handshake()
                    tls.sendall(b"ASK")
                    tls.recv(4096)
                    seen["after"] = tls.getpeercert()
            except (ssl.SSLError, OSError) as exc:
                seen["error"] = f"{type(exc).__name__}: {exc}"

        with socket.create_server((self.host, 0)) as listener:
            port = listener.getsockname()[1]
            thread = threading.Thread(target=serve, args=(listener,), daemon=True)
            thread.start()
            try:
                with socket.create_connection((self.host, port)) as sock:
                    with client_context.wrap_socket(
                        sock, server_hostname="localhost"
                    ) as tls:
                        tls.sendall(b"HELLO")
                        try:
                            tls.recv(4096)
                            tls.sendall(b"DONE")
                        except OSError as exc:
                            # The server hung up mid-exchange -- which is the
                            # symptom under test, so record it and let the
                            # assertions read `seen`.
                            seen["client_error"] = type(exc).__name__
            finally:
                thread.join(timeout=10)
        return seen


@pytest.fixture
def pha_server(
    ca: Signed,
    server_cert: Signed,
    ca_file: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> PHAServer:
    cert_path = tmp_path_factory.mktemp("pha") / "server.pem"
    cert_path.write_bytes(server_cert.cert_pem + server_cert.key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert_path))
    ctx.load_verify_locations(str(ca_file))
    # OPTIONAL, not REQUIRED: the whole point is that the handshake completes
    # without a certificate and the server asks for one afterwards.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.post_handshake_auth = True
    return PHAServer(host="127.0.0.1", ca_file=ca_file, _context=ctx)


@dataclass
class MTLSServer:
    url: str
    ca_file: Path


@pytest.fixture(scope="session")
def mtls_server(
    ca: Signed,
    server_cert: Signed,
    ca_file: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> object:
    cert_path = tmp_path_factory.mktemp("server") / "server.pem"
    cert_path.write_bytes(server_cert.cert_pem + server_cert.key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(str(ca_file))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            # Report which client certificate the server actually saw, so a
            # test can prove the selected identity is the one presented.
            peer = self.connection.getpeercert(binary_form=True) or b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header(
                "X-Client-Fingerprint", hashlib.sha256(peer).hexdigest().upper()
            )
            self.end_headers()
            self.wfile.write(b"mtls-ok")

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield MTLSServer(url=f"https://localhost:{port}", ca_file=ca_file)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
