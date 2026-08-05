"""Tests for certificate rotation: reload(), auto_reload, strict_validity."""

from __future__ import annotations

import datetime
import os
import pickle
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from httpx_pki import (
    AsyncPKIClient,
    CertificateExpiredError,
    CertificateLoadError,
    CertificateValidityWarning,
    PicklingWarning,
    PKIClient,
)
from httpx_pki._source import SourceRef
from httpx_pki.testing import CertBundle, make_client_cert, make_pkcs12
from tests.conftest import P12_PASSWORD, Signed, _sign


def _pem(signed: Signed) -> bytes:
    return signed.key_pem + signed.cert_pem


def _p12(signed: Signed, password: str) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        name=b"c",
        key=signed.key,
        cert=signed.cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode()
        ),
    )


def _rotate(path: Path, content: bytes) -> None:
    """Overwrite *path* and force a strictly newer mtime.

    Two writes can land in the same filesystem timestamp tick; bumping the
    mtime explicitly keeps the stat-signature comparison deterministic.
    """
    before = path.stat()
    path.write_bytes(content)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))


@pytest.fixture()
def cert_file(ca: Signed, tmp_path: Path) -> Path:
    """A PEM bundle for CN=rot-a, signed by the CA the mTLS server trusts."""
    path = tmp_path / "client.pem"
    path.write_bytes(_pem(_sign(ca, "rot-a")))
    return path


def test_manual_reload_end_to_end(
    ca: Signed, cert_file: Path, mtls_server: object
) -> None:
    # The core rotation proof: after reload() the same session (same mounted
    # context, same transport) presents the rotated certificate on a live
    # mTLS handshake.
    server = mtls_server  # MTLSServer(url, ca_file)
    with PKIClient(cert_file, verify=str(server.ca_file)) as session:  # type: ignore[attr-defined]
        assert session.cn == "rot-a"
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]

        _rotate(cert_file, _pem(_sign(ca, "rot-b")))
        session.reload()
        assert session.cn == "rot-b"
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]


def test_reload_failure_keeps_old_cert(
    cert_file: Path, mtls_server: object
) -> None:
    server = mtls_server
    with PKIClient(cert_file, verify=str(server.ca_file)) as session:  # type: ignore[attr-defined]
        _rotate(cert_file, b"this is not a certificate")
        with pytest.raises(CertificateLoadError):
            session.reload()
        # The swap is atomic: the previous certificate keeps serving.
        assert session.cn == "rot-a"
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]


def test_reload_on_bytes_source_raises(client_p12: bytes) -> None:
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        with pytest.raises(TypeError, match="in-memory bytes"):
            session.reload()


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("winstore", "Windows certificate store"),
        ("macos_keychain", "macOS keychain"),
    ],
)
def test_reload_rejects_a_password_for_a_platform_store(
    client_p12: bytes, kind: str, expected: str
) -> None:
    # A store export uses an internal single-use password, so a caller-supplied
    # one has nothing to decrypt. Refuse it instead of discarding it silently.
    # The source is faked so this runs off-platform; only the reload argument
    # check is under test, and it runs before anything touches the store.
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        session._source = SourceRef(kind, {"name": "ACME"})
        with pytest.raises(TypeError, match=expected) as excinfo:
            session.reload(password="pw")
        assert "single-use" in str(excinfo.value)


def test_auto_reload_on_bytes_source_rejected_at_construction(
    client_p12: bytes,
) -> None:
    with pytest.raises(TypeError, match="auto_reload requires"):
        PKIClient(client_p12, password=P12_PASSWORD, auto_reload=True)


def test_auto_reload_rejects_bad_type(cert_file: Path) -> None:
    with pytest.raises(TypeError, match="auto_reload must be"):
        PKIClient(cert_file, auto_reload=5)  # type: ignore[arg-type]


def test_auto_reload_picks_up_rotation(
    ca: Signed, cert_file: Path, mtls_server: object
) -> None:
    server = mtls_server
    with PKIClient(
        cert_file,
        verify=str(server.ca_file),  # type: ignore[attr-defined]
        auto_reload=datetime.timedelta(0),  # check on every request
    ) as session:
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]
        assert session.cn == "rot-a"

        _rotate(cert_file, _pem(_sign(ca, "rot-b")))
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]
        assert session.cn == "rot-b"


def test_rotation_landing_mid_reload_is_not_lost(
    ca: Signed, cert_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A rotation that lands between reload()'s file read and its fingerprint
    # bookkeeping must be picked up by the next preflight, not absorbed.
    import httpx_pki._mixin as mixin

    real_resolve = mixin.resolve_source
    raced = []

    def racy_resolve(ref: object, password: bytes | None = None) -> object:
        material = real_resolve(ref, password)  # type: ignore[arg-type]
        if not raced:  # rotate again, exactly once, mid-reload
            raced.append(True)
            _rotate(cert_file, _pem(_sign(ca, "rot-c")))
        return material

    monkeypatch.setattr(mixin, "resolve_source", racy_resolve)
    with PKIClient(cert_file, auto_reload=datetime.timedelta(0)) as session:
        _rotate(cert_file, _pem(_sign(ca, "rot-b")))
        session._preflight()  # reloads rot-b; rot-c lands during the reload
        assert session.cn == "rot-b"
        session._preflight()  # must notice the mid-reload rotation
        assert session.cn == "rot-c"


def test_auto_reload_is_throttled(ca: Signed, cert_file: Path) -> None:
    # With a long interval the construction-time check window is still open,
    # so a rotation is deliberately not noticed yet.
    with PKIClient(
        cert_file, auto_reload=datetime.timedelta(hours=1)
    ) as session:
        _rotate(cert_file, _pem(_sign(ca, "rot-b")))
        session._preflight()  # what send() runs
        assert session.cn == "rot-a"


def test_auto_reload_retains_password(ca: Signed, tmp_path: Path) -> None:
    p12_path = tmp_path / "client.p12"
    p12_path.write_bytes(_p12(_sign(ca, "rot-a"), "pw"))
    with PKIClient(p12_path, password="pw", auto_reload=True) as session:
        assert session._source is not None
        assert session._source.password == b"pw"
        _rotate(p12_path, _p12(_sign(ca, "rot-b"), "pw"))
        session.reload()  # decrypts with the retained password
        assert session.cn == "rot-b"


def test_password_not_retained_without_auto_reload(
    ca: Signed, tmp_path: Path
) -> None:
    p12_path = tmp_path / "client.p12"
    p12_path.write_bytes(_p12(_sign(ca, "rot-a"), "pw"))
    with PKIClient(p12_path, password="pw") as session:
        assert session._source is not None
        assert session._source.password is None
        _rotate(p12_path, _p12(_sign(ca, "rot-b"), "pw"))
        with pytest.raises(CertificateLoadError):
            session.reload()  # encrypted source, no password available
        session.reload(password="pw")  # supplied explicitly instead
        assert session.cn == "rot-b"


def test_from_env_reload(
    ca: Signed, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "client.pem"
    path.write_bytes(_pem(_sign(ca, "env-a")))
    monkeypatch.setenv("HTTPX_PKI_CERT", str(path))
    with PKIClient.from_env() as session:
        assert session.cn == "env-a"
        _rotate(path, _pem(_sign(ca, "env-b")))
        session.reload()  # re-resolves the environment
        assert session.cn == "env-b"


def test_strict_validity_raises_before_sending() -> None:
    bundle = make_client_cert("old", expired=True)
    with pytest.warns(CertificateValidityWarning, match="expired"):
        session = PKIClient(
            bundle.pkcs12(),
            password=b"",
            strict_validity=True,
            # A closed port: reaching it would fail with a connect error, so a
            # CertificateExpiredError proves no connection was even attempted.
            base_url="https://127.0.0.1:1",
        )
    with session:
        with pytest.raises(CertificateExpiredError):
            session.get("/")


def test_strict_validity_passes_for_valid_cert(
    cert_file: Path, mtls_server: object
) -> None:
    server = mtls_server
    with PKIClient(
        cert_file,
        verify=str(server.ca_file),  # type: ignore[attr-defined]
        strict_validity=True,
    ) as session:
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]


def test_pickle_preserves_rotation_config(ca: Signed, cert_file: Path) -> None:
    with PKIClient(cert_file, auto_reload=True) as session:
        restored = pickle.loads(pickle.dumps(session))
    with restored:
        assert restored._auto_reload == datetime.timedelta(seconds=1)
        assert restored._source == session._source
        _rotate(cert_file, _pem(_sign(ca, "rot-b")))
        restored.reload()
        assert restored.cn == "rot-b"


def test_unpicklable_source_dropped_with_warning(cert_file: Path) -> None:
    with PKIClient(cert_file) as session:
        session._source = SourceRef("winstore", {"predicate": lambda c: True})
        with pytest.warns(PicklingWarning, match="not be reloadable"):
            restored = pickle.loads(pickle.dumps(session))
    with restored:
        assert restored._source is None
        with pytest.raises(TypeError, match="no.*source to reload"):
            restored.reload()


async def test_async_auto_reload(
    ca: Signed, cert_file: Path, mtls_server: object
) -> None:
    server = mtls_server
    async with AsyncPKIClient(
        cert_file,
        verify=str(server.ca_file),  # type: ignore[attr-defined]
        auto_reload=datetime.timedelta(0),
    ) as session:
        resp = await session.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert session.cn == "rot-a"

        _rotate(cert_file, _pem(_sign(ca, "rot-b")))
        resp = await session.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert session.cn == "rot-b"


def _dual_p12(ca_bundle: CertBundle, *, encryption_first: bool = False) -> bytes:
    """A fresh dual key pair, optionally with the identities swapped in file order."""
    signing = make_client_cert(
        "rot-dual",
        ca=ca_bundle,
        key_usage=["digital_signature"],
        extended_key_usage=["client_auth"],
    )
    encryption = make_client_cert(
        "rot-dual", ca=ca_bundle, key_usage=["key_encipherment"]
    )
    entries = [(signing, "Signature"), (encryption, "Encryption")]
    if encryption_first:
        entries.reverse()
    return make_pkcs12(entries, password=P12_PASSWORD)


def test_reload_keeps_the_selected_identity(
    ca_bundle: CertBundle, tmp_path: Path
) -> None:
    path = tmp_path / "dual.p12"
    path.write_bytes(_dual_p12(ca_bundle))
    with PKIClient(
        path, password=P12_PASSWORD, key_usage="digital_signature"
    ) as session:
        before = session.certificate.serial_number
        # The rotated file lists the identities the other way round: a client
        # that fell back to "whichever comes first" would now present the
        # encryption certificate.
        _rotate(path, _dual_p12(ca_bundle, encryption_first=True))
        session.reload(password=P12_PASSWORD)
        assert session.certificate.serial_number != before
        assert session.cert_info().key_usage == frozenset({"digital_signature"})


def test_reload_keeps_the_selected_pem_identity(
    ca_bundle: CertBundle, tmp_path: Path
) -> None:
    signing = make_client_cert(
        "rot-dual-pem", ca=ca_bundle, key_usage=["digital_signature"]
    )
    encryption = make_client_cert(
        "rot-dual-pem", ca=ca_bundle, key_usage=["key_encipherment"]
    )
    path = tmp_path / "dual.pem"
    path.write_bytes(
        signing.key_pem
        + signing.cert_pem
        + encryption.key_pem
        + encryption.cert_pem
    )
    with PKIClient.from_pem(path, key_usage="digital_signature") as session:
        before = session.certificate.serial_number
        # The rotated file lists the pairs the other way round: a client that
        # fell back to "whichever key comes first" would now present the
        # encryption certificate.
        _rotate(
            path,
            encryption.key_pem
            + encryption.cert_pem
            + signing.key_pem
            + signing.cert_pem,
        )
        session.reload()
        assert session.certificate.serial_number == before
        assert session.cert_info().key_usage == frozenset({"digital_signature"})


def test_auto_reload_keeps_the_selected_identity(
    ca_bundle: CertBundle, tmp_path: Path, mtls_server: object
) -> None:
    server = mtls_server
    path = tmp_path / "dual.p12"
    path.write_bytes(_dual_p12(ca_bundle))
    with PKIClient(
        path,
        password=P12_PASSWORD,
        key_usage="digital_signature",
        verify=str(server.ca_file),  # type: ignore[attr-defined]
        auto_reload=datetime.timedelta(0),
    ) as session:
        assert session.get(server.url).status_code == 200  # type: ignore[attr-defined]
        _rotate(path, _dual_p12(ca_bundle, encryption_first=True))
        resp = session.get(server.url)  # type: ignore[attr-defined]
        assert resp.status_code == 200
        assert session.cert_info().key_usage == frozenset({"digital_signature"})
        # The presented certificate is the reloaded signing one.
        assert (
            resp.headers["X-Client-Fingerprint"]
            == session.cert_info().fingerprint_sha256
        )
