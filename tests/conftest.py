"""Shared fixtures: an in-memory test CA, client material, and an mTLS server."""

from __future__ import annotations

import datetime
import http.server
import ipaddress
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
def server_cert(ca: Signed) -> Signed:
    sans = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    return _sign(ca, "localhost", sans)


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
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
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
