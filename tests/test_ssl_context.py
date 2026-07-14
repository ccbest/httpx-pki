"""Tests for the public build_ssl_context() helper."""

from __future__ import annotations

import os
import ssl
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from httpx_pki import (
    CertificateLoadError,
    PKIClient,
    TLSConfigWarning,
    build_ssl_context,
)
from tests.conftest import P12_PASSWORD, Signed


def test_build_ssl_context_returns_context(client_p12: bytes) -> None:
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD)
    assert isinstance(ctx, ssl.SSLContext)


def test_passed_context_is_mutated_in_place_with_warning(client_p12: bytes) -> None:
    # A caller-supplied context is reused as-is and gets the client cert loaded
    # into it; we warn so a shared context is not surprising.
    ctx = ssl.create_default_context()
    with pytest.warns(TLSConfigWarning, match="pre-built ssl.SSLContext"):
        out = build_ssl_context(client_p12, password=P12_PASSWORD, verify=ctx)
    assert out is ctx


def test_build_ssl_context_autodetects_pem(client_p12: bytes) -> None:
    # PEM source works too (auto-detected by content).
    from httpx_pki.testing import make_ca, make_client_cert

    bundle = make_client_cert("c", ca=make_ca())
    ctx = build_ssl_context(bundle.pem)
    assert isinstance(ctx, ssl.SSLContext)


def test_sslkeylogfile_enables_key_logging(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Contexts we build come from ssl.create_default_context, which honors
    # SSLKEYLOGFILE; lock that in as documented behavior.
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD)
    assert ctx.keylog_filename == str(keylog)


def test_sslkeylogfile_leaves_caller_context_alone(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A caller-supplied context (built raw, so the stdlib hasn't applied
    # SSLKEYLOGFILE to it either) must not have key logging switched on by us.
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with pytest.warns(TLSConfigWarning, match="pre-built ssl.SSLContext"):
        out = build_ssl_context(client_p12, password=P12_PASSWORD, verify=ctx)
    assert out.keylog_filename is None


def test_build_ssl_context_mounts_on_plain_httpx_client(
    mtls_server: object, client_p12: bytes
) -> None:
    # The whole point: use the context with a vanilla httpx.Client, no PKIClient.
    server = mtls_server  # MTLSServer(url, ca_file)
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(server.ca_file)  # type: ignore[attr-defined]
    )
    with httpx.Client(verify=ctx) as client:
        resp = client.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert resp.text == "mtls-ok"


# -- verify="system" (OS trust store via the optional truststore package) ----


def test_verify_system_returns_truststore_context(client_p12: bytes) -> None:
    truststore = pytest.importorskip("truststore")
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify="system")
    # The truststore context (with the client cert already loaded) is handed
    # back directly; PROTOCOL_TLS_CLIENT keeps hostname checking on.
    assert isinstance(ctx, truststore.SSLContext)
    assert ctx.check_hostname is True


def test_verify_system_without_truststore_raises(
    client_p12: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A None entry in sys.modules makes `import truststore` raise ImportError,
    # simulating an environment without the [system] extra.
    monkeypatch.setitem(sys.modules, "truststore", None)
    with pytest.raises(ImportError, match=r"httpx-pki\[system\]"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify="system")


def test_verify_system_rejects_private_ca_server(
    mtls_server: object, client_p12: bytes
) -> None:
    # The test server's certificate is signed by the throwaway test CA, which
    # no OS trusts -- so a failed handshake proves the OS trust store (not
    # certifi, not the test CA bundle) is really making the decision. The
    # verification-failure message wording varies by platform verifier, so
    # only the error type is asserted.
    pytest.importorskip("truststore")
    server = mtls_server
    with PKIClient(client_p12, password=P12_PASSWORD, verify="system") as session:
        with pytest.raises(httpx.ConnectError):
            session.get(server.url)  # type: ignore[attr-defined]


def test_verify_system_honors_sslkeylogfile(
    client_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # create_default_context applies SSLKEYLOGFILE itself; the "system" branch
    # applies it manually so key-logging behavior stays uniform.
    pytest.importorskip("truststore")
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify="system")
    assert ctx.keylog_filename == str(keylog)


# -- memfd staging: the decrypted key stays off disk on Linux ----------------

linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="memfd staging is Linux-only"
)
# os.memfd_create is missing from some redistributed interpreter builds even
# on Linux (it depends on the glibc the interpreter was built against).
memfd_required = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "memfd_create"),
    reason="requires a Linux interpreter built with os.memfd_create",
)


@memfd_required
def test_memfd_is_used_on_linux(
    mtls_server: object, client_p12: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real_memfd_create = os.memfd_create

    def spying_memfd_create(name: str, flags: int = 0) -> int:
        calls.append(name)
        return real_memfd_create(name, flags)

    monkeypatch.setattr(os, "memfd_create", spying_memfd_create)
    server = mtls_server
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(server.ca_file)  # type: ignore[attr-defined]
    )
    assert calls == ["httpx-pki-client-cert"]
    with httpx.Client(verify=ctx) as client:
        assert client.get(server.url).status_code == 200  # type: ignore[attr-defined]


@memfd_required
def test_key_never_touches_disk_on_linux(
    mtls_server: object, client_p12: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With mkstemp booby-trapped, a full mTLS round trip still succeeding
    # proves the decrypted key was staged entirely in memory.
    def boom(*args: object, **kwargs: object) -> tuple[int, str]:
        raise AssertionError("client-cert material touched the disk")

    monkeypatch.setattr("tempfile.mkstemp", boom)
    server = mtls_server
    with PKIClient(
        client_p12,
        password=P12_PASSWORD,
        verify=str(server.ca_file),  # type: ignore[attr-defined]
    ) as session:
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]


@linux_only
def test_memfd_failure_falls_back_to_temp_file(
    mtls_server: object, client_p12: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A seccomp-style denial of memfd_create must degrade to the temp-file
    # path, not fail -- and the context must still complete a handshake.
    def denied(name: str, flags: int = 0) -> int:
        raise OSError("memfd_create blocked")

    # raising=False: also valid on interpreter builds missing memfd_create,
    # where the patch (rather than the real thing) is what the code probes.
    monkeypatch.setattr(os, "memfd_create", denied, raising=False)
    server = mtls_server
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=str(server.ca_file)  # type: ignore[attr-defined]
    )
    with httpx.Client(verify=ctx) as client:
        assert client.get(server.url).status_code == 200  # type: ignore[attr-defined]


# -- verify= with a PKCS#7 (.p7b) CA bundle ----------------------------------


@pytest.mark.parametrize("encoding", [Encoding.DER, Encoding.PEM])
def test_verify_pkcs7_ca_bundle_round_trip(
    mtls_server: object,
    ca: Signed,
    client_p12: bytes,
    tmp_path: Path,
    encoding: Encoding,
) -> None:
    # OpenSSL's cafile cannot read PKCS#7, so a successful handshake proves
    # the fallback converted the bundle and trusted exactly its contents.
    server = mtls_server
    p7b = tmp_path / "ca.p7b"
    p7b.write_bytes(pkcs7.serialize_certificates([ca.cert], encoding))
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(p7b))
    with httpx.Client(verify=ctx) as client:
        assert client.get(server.url).status_code == 200  # type: ignore[attr-defined]


def test_verify_garbage_ca_bundle_raises(client_p12: bytes, tmp_path: Path) -> None:
    # Unparseable CA-bundle content must not be mistaken for PKCS#7 -- the
    # original "could not load CA bundle" error is re-raised.
    bad = tmp_path / "ca.pem"
    bad.write_bytes(b"not a certificate at all")
    with pytest.raises(CertificateLoadError, match="could not load CA bundle"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(bad))


def test_verify_path_named_system_is_a_file(client_p12: bytes) -> None:
    # The literal str "system" selects the OS store; a Path("system") is the
    # escape hatch for a CA bundle actually named "system" (here: missing).
    with pytest.raises(CertificateLoadError, match="could not load CA bundle"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=Path("system"))
