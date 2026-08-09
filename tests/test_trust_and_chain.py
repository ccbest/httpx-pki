"""Combining trust sources, presenting extra intermediates, and the audit.

Three features that arrived together and interlock: ``verify=`` taking a list
of trust sources, ``chain=`` reaching the constructors that lacked it, and the
warnings that fire when either is given certificates that cannot do the job
asked of them.
"""

from __future__ import annotations

import ssl
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from httpx_pki import (
    CertificateLoadError,
    PKIClient,
    TLSConfigWarning,
    build_ssl_context,
    cert_info,
)
from httpx_pki.testing import CertBundle, make_ca, make_client_cert
from tests.conftest import P12_PASSWORD, Signed


def _anchors(ctx: ssl.SSLContext) -> set[str]:
    """The subject common names loaded into *ctx* as extra trust anchors.

    Read from the inner ``ssl.SSLContext`` when the context is truststore's
    wrapper -- whose own ``get_ca_certs()`` raises ``NotImplementedError`` --
    because the inner one is what truststore hands the platform verifier
    (``sslobj.context``), and therefore the exact object whose contents decide
    whether an extra CA is honored on macOS and Windows. For a truststore
    context this reports only the extras: the system anchors come from the
    platform, not from OpenSSL's store.
    """
    names = set()
    for entry in getattr(ctx, "_ctx", ctx).get_ca_certs():
        for rdn in entry.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    names.add(value)
    return names


# -- verify= taking a list --------------------------------------------------


def test_a_single_element_list_matches_the_scalar(
    client_p12: bytes, ca_file: Path
) -> None:
    scalar = build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(ca_file))
    listed = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=[str(ca_file)]
    )
    assert _anchors(scalar) == _anchors(listed)


def test_two_bundles_combine(client_p12: bytes, ca_file: Path, tmp_path: Path) -> None:
    other = make_ca("Second Root")
    other_file = tmp_path / "other.pem"
    other_file.write_bytes(other.cert_pem)

    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=[str(ca_file), str(other_file)]
    )
    anchors = _anchors(ctx)
    assert "httpx-pki test CA" in anchors
    assert "Second Root" in anchors


def test_system_plus_a_private_root(client_p12: bytes, ca_file: Path) -> None:
    """The headline case: the OS store *and* an internal CA.

    The private root must be visible to the platform verifier, which
    truststore reaches through ``get_ca_certs()`` -- so asserting it is present
    there is asserting the thing that actually matters on macOS and Windows.
    """
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=["system", str(ca_file)]
    )
    assert "httpx-pki test CA" in _anchors(ctx)


def test_naming_a_bundle_alone_still_replaces_default_trust(
    client_p12: bytes, ca_file: Path
) -> None:
    # Without "system" in the list the OS defaults must stay out, which is the
    # pre-existing meaning of naming a bundle.
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify=[str(ca_file)])
    assert _anchors(ctx) == {"httpx-pki test CA"}


def test_certifi_combines_with_a_private_root(
    client_p12: bytes, ca_file: Path
) -> None:
    ctx = build_ssl_context(
        client_p12, password=P12_PASSWORD, verify=["certifi", str(ca_file)]
    )
    anchors = _anchors(ctx)
    assert "httpx-pki test CA" in anchors
    assert len(anchors) > 10  # certifi's public roots came along


def test_a_directory_of_certificates(
    client_p12: bytes, ca: Signed, tmp_path: Path
) -> None:
    """A ConfigMap-shaped directory: plain names, not c_rehash hashes."""
    d = tmp_path / "ca.d"
    d.mkdir()
    (d / "internal-root.crt").write_bytes(ca.cert_pem)
    (d / "second.crt").write_bytes(make_ca("Second Root").cert_pem)
    # Non-certificate clutter is skipped rather than fatal.
    (d / "README").write_text("these are our CAs\n")
    (d / "subdir").mkdir()

    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify=[str(d)])
    assert _anchors(ctx) == {"httpx-pki test CA", "Second Root"}


def test_a_directory_with_no_certificates_raises(
    client_p12: bytes, tmp_path: Path
) -> None:
    d = tmp_path / "empty.d"
    d.mkdir()
    (d / "notes.txt").write_text("nothing here")
    with pytest.raises(CertificateLoadError, match="no certificates"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=[str(d)])


def test_a_der_bundle_now_loads(client_p12: bytes, ca: Signed, tmp_path: Path) -> None:
    der = tmp_path / "ca.der"
    der.write_bytes(ca.cert.public_bytes(serialization.Encoding.DER))
    ctx = build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(der))
    assert _anchors(ctx) == {"httpx-pki test CA"}


def test_verify_false_cannot_be_combined(client_p12: bytes, ca_file: Path) -> None:
    with pytest.raises(TypeError, match="cannot be combined"):
        build_ssl_context(
            client_p12, password=P12_PASSWORD, verify=[False, str(ca_file)]
        )


def test_a_context_cannot_be_combined(client_p12: bytes, ca_file: Path) -> None:
    with pytest.raises(TypeError, match="cannot be combined"):
        build_ssl_context(
            client_p12,
            password=P12_PASSWORD,
            verify=[ssl.create_default_context(), str(ca_file)],
        )


def test_an_empty_list_raises(client_p12: bytes) -> None:
    with pytest.raises(TypeError, match="no trust sources"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=[])


def test_a_nonsense_entry_raises(client_p12: bytes) -> None:
    with pytest.raises(TypeError, match="each entry"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=[42])  # type: ignore[list-item]


def test_the_list_survives_pickling(client_p12: bytes, ca_file: Path) -> None:
    import pickle

    session = PKIClient(
        client_p12, password=P12_PASSWORD, verify=["system", str(ca_file)]
    )
    restored = pickle.loads(pickle.dumps(session))
    assert "httpx-pki test CA" in _anchors(restored.ssl_context)


# -- chain= on the constructors that lacked it ------------------------------


def test_chain_on_the_auto_constructor(ca_bundle: CertBundle, tmp_path: Path) -> None:
    """The motivating case: a PKCS#12 exported without its chain."""
    leaf = make_client_cert("svc", ca=ca_bundle)
    from cryptography.hazmat.primitives.serialization import pkcs12

    bare = pkcs12.serialize_key_and_certificates(
        b"svc", leaf.key, leaf.cert, None, serialization.NoEncryption()
    )
    p12 = tmp_path / "bare.p12"
    p12.write_bytes(bare)
    chain = tmp_path / "chain.pem"
    chain.write_bytes(ca_bundle.cert_pem)

    with PKIClient(p12, password=b"", chain=chain) as session:
        assert [cert_info(p).common_name for p in session._material.ca_pems] == [
            "httpx-pki test CA"
        ]


def test_chain_on_from_pkcs12(client_p12: bytes, ca: Signed) -> None:
    with PKIClient.from_pkcs12(
        client_p12, password=P12_PASSWORD, chain=ca.cert_pem
    ) as session:
        assert session._material.ca_pems == [ca.cert_pem]


def test_chain_on_from_pem(client: Signed, ca: Signed) -> None:
    with PKIClient.from_pem(
        client.key_pem + client.cert_pem, chain=[ca.cert_pem]
    ) as session:
        assert session._material.ca_pems == [ca.cert_pem]


def test_chain_on_build_ssl_context(client_p12: bytes, ca: Signed) -> None:
    # No exception and no audit warning: the chain is the real issuer.
    with warnings.catch_warnings():
        warnings.simplefilter("error", TLSConfigWarning)
        build_ssl_context(client_p12, password=P12_PASSWORD, chain=ca.cert_pem)


def test_chain_is_reapplied_on_reload(
    client_p12_file: Path, ca: Signed, tmp_path: Path
) -> None:
    chain = tmp_path / "chain.pem"
    chain.write_bytes(ca.cert_pem)
    session = PKIClient(client_p12_file, password=P12_PASSWORD, chain=chain)
    assert session._material.ca_pems == [ca.cert_pem]
    session.reload(password=P12_PASSWORD)
    assert session._material.ca_pems == [ca.cert_pem]


def test_chain_files_are_watched_for_auto_reload(
    client_p12_file: Path, ca: Signed, tmp_path: Path
) -> None:
    chain = tmp_path / "chain.pem"
    chain.write_bytes(ca.cert_pem)
    session = PKIClient(
        client_p12_file, password=P12_PASSWORD, chain=chain, auto_reload=True
    )
    assert chain in session._watch_paths


# -- the audit: verify= entries that cannot anchor --------------------------


def test_an_intermediate_in_verify_warns(
    client_p12: bytes, ca_bundle: CertBundle, tmp_path: Path
) -> None:
    intermediate = _make_intermediate("Issuing CA", ca_bundle)
    path = tmp_path / "inter.pem"
    path.write_bytes(intermediate.cert_pem)

    with pytest.warns(TLSConfigWarning, match="intermediate CA"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(path))


def test_a_leaf_in_verify_warns(
    client_p12: bytes, ca_bundle: CertBundle, tmp_path: Path
) -> None:
    # Somebody else's leaf -- not this client's own, which has its own message.
    other = make_client_cert("some-other-service", ca=ca_bundle)
    path = tmp_path / "leaf.pem"
    path.write_bytes(other.cert_pem)
    with pytest.warns(TLSConfigWarning, match="cannot anchor a chain"):
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(path))


def test_the_clients_own_certificate_in_verify_warns(
    client_p12: bytes, client: Signed, ca_file: Path, tmp_path: Path
) -> None:
    own = tmp_path / "own.pem"
    own.write_bytes(client.cert_pem)
    with pytest.warns(TLSConfigWarning, match="own certificate"):
        build_ssl_context(
            client_p12, password=P12_PASSWORD, verify=[str(ca_file), str(own)]
        )


def test_a_self_signed_root_is_silent(client_p12: bytes, ca_file: Path) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", TLSConfigWarning)
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(ca_file))


def test_a_pinned_self_signed_server_cert_is_silent(
    client_p12: bytes, tmp_path: Path
) -> None:
    """The common development shape: trust exactly one self-signed server."""
    selfsigned = make_client_cert("dev.example.com", extended_key_usage=["server_auth"])
    path = tmp_path / "dev.pem"
    path.write_bytes(selfsigned.cert_pem)
    with warnings.catch_warnings():
        warnings.simplefilter("error", TLSConfigWarning)
        build_ssl_context(client_p12, password=P12_PASSWORD, verify=str(path))


def test_certifi_and_system_are_not_audited(client_p12: bytes) -> None:
    # Curated bundles are not where this mistake lives, and parsing certifi is
    # both the most expensive check and the least likely to find anything.
    with warnings.catch_warnings():
        warnings.simplefilter("error", TLSConfigWarning)
        build_ssl_context(
            client_p12, password=P12_PASSWORD, verify=["system", "certifi"]
        )


# -- the audit: chain certificates that do not belong -----------------------


def test_an_unrelated_chain_certificate_warns(client_p12: bytes, ca: Signed) -> None:
    # The real issuer plus a stranger: the chain is usable, but one entry has
    # no business being there.
    stranger = make_ca("Unrelated Root")
    with pytest.warns(TLSConfigWarning, match="not on this certificate's chain"):
        build_ssl_context(
            client_p12,
            password=P12_PASSWORD,
            chain=[ca.cert_pem, stranger.cert_pem],
        )


def test_an_entirely_wrong_chain_says_so_differently(client_p12: bytes) -> None:
    stranger = make_ca("Unrelated Root")
    other = make_ca("Also Unrelated")
    with pytest.warns(TLSConfigWarning, match="reach the issuer"):
        build_ssl_context(
            client_p12,
            password=P12_PASSWORD,
            chain=[stranger.cert_pem, other.cert_pem],
        )


def test_the_correct_chain_is_silent(client_p12: bytes, ca: Signed) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", TLSConfigWarning)
        build_ssl_context(client_p12, password=P12_PASSWORD, chain=ca.cert_pem)


def test_a_cross_signed_ca_is_not_a_stray(ca_bundle: CertBundle) -> None:
    """The false positive the graph walk exists to avoid.

    A CA cross-signed by a second root gives the leaf two valid paths, and
    presenting both is legitimate -- older clients need the cross-signed copy.
    A walk that committed to the first match would report the other as not
    belonging.
    """
    other_root = make_ca("Other Root")
    intermediate = _make_intermediate("Shared CA", ca_bundle)
    cross = _cross_sign(intermediate, other_root)
    leaf = make_client_cert("svc", ca=intermediate)

    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        build_ssl_context(
            leaf.key_pem + leaf.cert_pem,
            chain=[intermediate.cert_pem, cross, ca_bundle.cert_pem],
        )
    strays = [w for w in rec if "chain" in str(w.message)]
    assert not strays, [str(w.message) for w in strays]


def test_the_audit_cannot_break_a_load(client_p12: bytes, ca: Signed) -> None:
    # Even with warnings escalated to errors, a warning is a warning -- but the
    # audit itself must never raise through. Simulate a broken audit.
    import httpx_pki._ssl as ssl_module

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit exploded")

    original = ssl_module.analyze_presented_chain
    ssl_module.analyze_presented_chain = boom  # type: ignore[assignment]
    try:
        ctx = build_ssl_context(client_p12, password=P12_PASSWORD, chain=ca.cert_pem)
        assert isinstance(ctx, ssl.SSLContext)
    finally:
        ssl_module.analyze_presented_chain = original  # type: ignore[assignment]


# -- helpers ----------------------------------------------------------------


def _ca_cert(
    subject: x509.Name, key: object, issuer: CertBundle
) -> x509.Certificate:
    """A CA certificate for *subject*/*key*, signed by *issuer*."""
    from cryptography.hazmat.primitives import hashes

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())  # type: ignore[attr-defined]
        .serial_number(x509.random_serial_number())
        .not_valid_before(issuer.cert.not_valid_before_utc)
        .not_valid_after(issuer.cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),  # type: ignore[attr-defined]
            critical=False,
        )
        .sign(issuer.key, hashes.SHA256())
    )


def _make_intermediate(common_name: str, issuer: CertBundle) -> CertBundle:
    """A real intermediate CA: CA=true, and able to sign leaves of its own."""
    base = make_client_cert(common_name, ca=issuer, key_usage=["key_cert_sign"])
    return CertBundle(
        key=base.key, cert=_ca_cert(base.cert.subject, base.key, issuer), issuer=issuer
    )


def _cross_sign(intermediate: CertBundle, other_root: CertBundle) -> bytes:
    """The same subject and key as *intermediate*, signed by a different root.

    Same SubjectKeyIdentifier too, since that is derived from the key -- which
    is what makes this indistinguishable from the original by the identifiers
    the chain walk matches on, and therefore a real test of it.
    """
    cert = _ca_cert(intermediate.cert.subject, intermediate.key, other_root)
    return cert.public_bytes(serialization.Encoding.PEM)
