"""Tests for PKCS#12 bundles holding several identities: listing and selecting.

A "dual key pair" -- one subject, a signing key pair and an encryption key pair
in the same file -- is what a CA issues when it escrows the encryption key. The
fixtures in ``conftest`` mint one; these tests cover enumerating it, choosing
between the identities, and keeping one identity's certificate out of the other's
chain.
"""

from __future__ import annotations

import datetime
import pickle
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from httpx_pki import (
    AmbiguousCertificateError,
    AsyncPKIClient,
    CertificateLoadError,
    CertificateNotFoundError,
    PKIClient,
    build_ssl_context,
    cert_info,
    currently_valid,
    list_identities,
    list_pkcs12_identities,
)
from httpx_pki._pkcs12 import _walk_key_bags, material_from_store_export
from httpx_pki.testing import CertBundle, make_client_cert, make_pkcs12
from tests.conftest import CLIENT_CN, P12_PASSWORD


def _serial(identities: tuple[CertBundle, ...], index: int) -> int:
    """The certificate serial of one of the minted identities."""
    return identities[index].cert.serial_number


# -- enumeration ------------------------------------------------------------


def test_lists_every_identity_in_file_order(
    dual_p12: bytes, dual_identities: tuple[CertBundle, CertBundle]
) -> None:
    signing, encryption = dual_identities
    identities = list_pkcs12_identities(dual_p12, P12_PASSWORD)
    assert [i.index for i in identities] == [0, 1]
    assert [i.info.serial_number for i in identities] == [
        signing.cert.serial_number,
        encryption.cert.serial_number,
    ]


def test_lists_friendly_names_and_usages(dual_p12: bytes) -> None:
    signing, encryption = list_pkcs12_identities(dual_p12, P12_PASSWORD)
    assert signing.friendly_name == "Signature"
    assert encryption.friendly_name == "Encryption"
    assert signing.info.key_usage == frozenset({"digital_signature"})
    assert encryption.info.key_usage == frozenset({"key_encipherment"})
    assert signing.info.extended_key_usage == ["client_auth"]
    assert encryption.info.extended_key_usage == ["email_protection"]
    # Both halves of a dual key pair carry the same subject -- the usage is the
    # only thing telling them apart.
    assert signing.subject_cn == encryption.subject_cn == CLIENT_CN


def test_listing_does_not_expose_private_keys(dual_p12: bytes) -> None:
    for identity in list_pkcs12_identities(dual_p12, P12_PASSWORD):
        assert not hasattr(identity, "key")
        assert "PRIVATE" not in repr(identity)


def test_lists_from_a_path(dual_p12: bytes, tmp_path: Path) -> None:
    path = tmp_path / "dual.p12"
    path.write_bytes(dual_p12)
    assert len(list_pkcs12_identities(path, P12_PASSWORD)) == 2


def test_single_identity_bundle_lists_one(client_p12: bytes) -> None:
    identities = list_pkcs12_identities(client_p12, P12_PASSWORD)
    assert len(identities) == 1
    assert identities[0].index == 0
    assert identities[0].subject_cn == CLIENT_CN


def test_wrong_password_raises_load_error(dual_p12: bytes) -> None:
    with pytest.raises(CertificateLoadError):
        list_pkcs12_identities(dual_p12, "not-the-password")


# -- the ambiguity guard ----------------------------------------------------


def test_no_selector_raises_and_lists_the_identities(dual_p12: bytes) -> None:
    with pytest.raises(AmbiguousCertificateError) as excinfo:
        PKIClient(dual_p12, password=P12_PASSWORD)
    message = str(excinfo.value)
    assert "2 identities" in message
    assert "Signature" in message and "Encryption" in message
    assert "digital_signature" in message and "key_encipherment" in message
    # The message must say how to fix it.
    assert "identity=" in message and "key_usage=" in message


def test_single_identity_still_needs_no_selector(client_p12: bytes) -> None:
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        assert session.cn == CLIENT_CN


# -- selection --------------------------------------------------------------


def test_select_by_index(
    dual_p12: bytes, dual_identities: tuple[CertBundle, ...]
) -> None:
    with PKIClient(dual_p12, password=P12_PASSWORD, identity=1) as session:
        assert session.certificate.serial_number == _serial(dual_identities, 1)


def test_select_by_negative_index(
    dual_p12: bytes, dual_identities: tuple[CertBundle, ...]
) -> None:
    with PKIClient(dual_p12, password=P12_PASSWORD, identity=-1) as session:
        assert session.certificate.serial_number == _serial(dual_identities, 1)


def test_select_by_friendly_name_is_case_insensitive(
    dual_p12: bytes, dual_identities: tuple[CertBundle, ...]
) -> None:
    with PKIClient(dual_p12, password=P12_PASSWORD, identity="signat") as session:
        assert session.certificate.serial_number == _serial(dual_identities, 0)


def test_select_by_fingerprint(dual_p12: bytes) -> None:
    wanted = list_pkcs12_identities(dual_p12, P12_PASSWORD)[1]
    # Colons and lowercase are normalized away, as for a store thumbprint.
    spaced = ":".join(
        wanted.thumbprint[i : i + 2] for i in range(0, len(wanted.thumbprint), 2)
    ).lower()
    with PKIClient(dual_p12, password=P12_PASSWORD, identity=spaced) as session:
        assert session.cert_info().fingerprint_sha1 == wanted.thumbprint
    with PKIClient(
        dual_p12, password=P12_PASSWORD, identity=wanted.info.fingerprint_sha256
    ) as session:
        assert session.cert_info().fingerprint_sha1 == wanted.thumbprint


def test_select_by_predicate(dual_p12: bytes) -> None:
    with PKIClient(
        dual_p12,
        password=P12_PASSWORD,
        identity=lambda i: i.friendly_name == "Encryption",
    ) as session:
        assert session.cert_info().key_usage == frozenset({"key_encipherment"})


def test_select_by_key_usage(dual_p12: bytes) -> None:
    with PKIClient(
        dual_p12, password=P12_PASSWORD, key_usage="digital_signature"
    ) as session:
        assert session.cert_info().key_usage == frozenset({"digital_signature"})


def test_select_by_extended_key_usage(dual_p12: bytes) -> None:
    with PKIClient(
        dual_p12, password=P12_PASSWORD, extended_key_usage=["email_protection"]
    ) as session:
        assert session.cert_info().key_usage == frozenset({"key_encipherment"})


def test_select_by_extended_key_usage_oid(dual_p12: bytes) -> None:
    # clientAuth, spelled as the dotted OID.
    with PKIClient(
        dual_p12, password=P12_PASSWORD, extended_key_usage="1.3.6.1.5.5.7.3.2"
    ) as session:
        assert session.cert_info().extended_key_usage == ["client_auth"]


def test_usage_names_accept_camel_case(dual_p12: bytes) -> None:
    with PKIClient(
        dual_p12, password=P12_PASSWORD, key_usage="keyEncipherment"
    ) as session:
        assert session.cert_info().key_usage == frozenset({"key_encipherment"})


def test_selectors_intersect(dual_p12: bytes) -> None:
    # Identity 0 is the signing one, so asking for it *and* key encipherment
    # must find nothing rather than falling back to either half.
    with pytest.raises(CertificateNotFoundError):
        PKIClient(
            dual_p12, password=P12_PASSWORD, identity=0, key_usage="key_encipherment"
        )


def test_selector_matching_several_is_ambiguous(dual_p12: bytes) -> None:
    # Both identities share the subject common name.
    with pytest.raises(AmbiguousCertificateError) as excinfo:
        PKIClient(dual_p12, password=P12_PASSWORD, identity=CLIENT_CN)
    assert "matched 2 identities" in str(excinfo.value)


def test_selector_matching_nothing_raises(dual_p12: bytes) -> None:
    with pytest.raises(CertificateNotFoundError) as excinfo:
        PKIClient(dual_p12, password=P12_PASSWORD, identity="nonexistent")
    assert "matched no identity" in str(excinfo.value)


def test_unknown_key_usage_is_rejected(dual_p12: bytes) -> None:
    with pytest.raises(ValueError, match="unknown key usage"):
        PKIClient(dual_p12, password=P12_PASSWORD, key_usage="digital-signatures")


def test_unknown_extended_key_usage_is_rejected(dual_p12: bytes) -> None:
    with pytest.raises(ValueError, match="unknown extended key usage"):
        PKIClient(dual_p12, password=P12_PASSWORD, extended_key_usage="clientauthx")


def test_empty_usage_selector_is_rejected(dual_p12: bytes) -> None:
    with pytest.raises(ValueError, match="at least one usage"):
        PKIClient(dual_p12, password=P12_PASSWORD, key_usage=[])


def test_bool_identity_is_rejected(dual_p12: bytes) -> None:
    with pytest.raises(TypeError):
        PKIClient(dual_p12, password=P12_PASSWORD, identity=True)


# -- the chain --------------------------------------------------------------


def test_chain_excludes_the_other_identity(
    dual_p12: bytes, ca_bundle: CertBundle
) -> None:
    with PKIClient(
        dual_p12, password=P12_PASSWORD, key_usage="digital_signature"
    ) as session:
        # The CA is presented; the encryption identity's leaf is not.
        assert session._material.ca_pems == [ca_bundle.cert_pem]


def test_chain_of_a_single_identity_bundle_is_unchanged(
    client_p12: bytes, client: object
) -> None:
    # A plain bundle keeps presenting exactly what it always did: the leaf and
    # whatever certificates came with it (here, none).
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        assert session._material.ca_pems == []


def test_single_identity_bundle_keeps_its_ca_chain(ca_bundle: CertBundle) -> None:
    bundle = make_client_cert("chained", ca=ca_bundle)
    with PKIClient(bundle.pkcs12("pw"), password="pw") as session:
        assert session._material.ca_pems == [ca_bundle.cert_pem]


# -- other entry points -----------------------------------------------------


def test_from_pkcs12_takes_a_selector(dual_p12: bytes) -> None:
    with PKIClient.from_pkcs12(
        dual_p12, P12_PASSWORD, key_usage="digital_signature"
    ) as session:
        assert session.cert_info().key_usage == frozenset({"digital_signature"})


async def test_async_client_takes_a_selector(dual_p12: bytes) -> None:
    async with AsyncPKIClient(
        dual_p12, password=P12_PASSWORD, identity="Encryption"
    ) as session:
        assert session.cert_info().key_usage == frozenset({"key_encipherment"})


def test_build_ssl_context_takes_a_selector(dual_p12: bytes) -> None:
    import ssl

    context = build_ssl_context(
        dual_p12, P12_PASSWORD, key_usage="digital_signature"
    )
    # Built without raising. (Not get_ca_certs(): the default context is
    # truststore-backed since 0.8, which does not implement that method.)
    assert isinstance(context, ssl.SSLContext)
    with pytest.raises(AmbiguousCertificateError):
        build_ssl_context(dual_p12, P12_PASSWORD)


def test_pem_bundle_selector_applies(client: object) -> None:
    # A PEM bundle holds one identity; a selector still has to match it rather
    # than being silently ignored.
    bundle = make_client_cert("pemmed", key_usage=["digital_signature"])
    blob = bundle.key_pem + bundle.cert_pem
    with PKIClient(blob, key_usage="digital_signature") as session:
        assert session.cn == "pemmed"
    with pytest.raises(CertificateNotFoundError):
        PKIClient(blob, key_usage="key_encipherment")


# -- PEM bundles holding several identities ---------------------------------


def _dual_pem(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> bytes:
    """The dual key pair as one PEM blob: two key+cert pairs plus the CA."""
    signing, encryption = dual_identities
    return (
        signing.key_pem
        + signing.cert_pem
        + encryption.key_pem
        + encryption.cert_pem
        + ca_bundle.cert_pem
    )


def test_pem_dual_bundle_lists_identities(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    signing, encryption = dual_identities
    identities = list_identities(_dual_pem(dual_identities, ca_bundle))
    assert [i.index for i in identities] == [0, 1]
    assert [i.info.serial_number for i in identities] == [
        signing.cert.serial_number,
        encryption.cert.serial_number,
    ]
    # PEM has no bag attributes, so there is no label to carry.
    assert [i.friendly_name for i in identities] == [None, None]


def test_list_identities_detects_pkcs12(dual_p12: bytes) -> None:
    # The content-detecting entry point agrees with the PKCS#12-only one.
    assert list_identities(dual_p12, P12_PASSWORD) == list_pkcs12_identities(
        dual_p12, P12_PASSWORD
    )


def test_pem_dual_bundle_without_selector_is_ambiguous(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    with pytest.raises(AmbiguousCertificateError, match="PEM data"):
        PKIClient(_dual_pem(dual_identities, ca_bundle))


def test_pem_dual_bundle_select_by_key_usage(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    signing, _encryption = dual_identities
    blob = _dual_pem(dual_identities, ca_bundle)
    with PKIClient.from_pem(blob, key_usage="digital_signature") as session:
        assert session.certificate.serial_number == signing.cert.serial_number
        # The encryption identity's certificate is a leaf of its own, not a
        # chain certificate; the CA stays in the chain.
        assert session._material.ca_pems == [ca_bundle.cert_pem]


def test_pem_dual_bundle_select_by_index(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    _signing, encryption = dual_identities
    blob = _dual_pem(dual_identities, ca_bundle)
    with PKIClient.from_pem(blob, identity=1) as session:
        assert session.certificate.serial_number == encryption.cert.serial_number


def test_pem_dual_bundle_autodetected_with_selector(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    # The content-detecting constructor path applies the selector too.
    _signing, encryption = dual_identities
    blob = _dual_pem(dual_identities, ca_bundle)
    with PKIClient(blob, key_usage="key_encipherment") as session:
        assert session.certificate.serial_number == encryption.cert.serial_number


def test_build_ssl_context_pem_dual_bundle(
    dual_identities: tuple[CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    blob = _dual_pem(dual_identities, ca_bundle)
    with pytest.raises(AmbiguousCertificateError):
        build_ssl_context(blob)
    build_ssl_context(blob, key_usage="digital_signature")


# -- file layouts -----------------------------------------------------------


def test_unencrypted_bundle(
    dual_identities: tuple[CertBundle, CertBundle]
) -> None:
    signing, encryption = dual_identities
    blob = make_pkcs12([(signing, "Signature"), (encryption, "Encryption")])
    assert len(list_pkcs12_identities(blob)) == 2


@pytest.mark.parametrize(
    "options",
    [
        {"encrypt_certs": False},
        {"mac": False},
        {"encrypt_certs": False, "mac": False},
    ],
)
def test_layout_variants_all_enumerate(
    dual_identities: tuple[CertBundle, CertBundle], options: dict[str, bool]
) -> None:
    signing, encryption = dual_identities
    blob = make_pkcs12(
        [(signing, "Signature"), (encryption, "Encryption")],
        password=P12_PASSWORD,
        **options,
    )
    assert len(list_pkcs12_identities(blob, P12_PASSWORD)) == 2


def test_keys_inside_the_encrypted_safe_fall_back(
    dual_identities: tuple[CertBundle, CertBundle]
) -> None:
    # The documented limitation: with the key bags hidden inside the encrypted
    # portion there is nothing to enumerate, so the file loads the way it did
    # before identity selection existed -- first identity, no error.
    signing, encryption = dual_identities
    blob = make_pkcs12(
        [(signing, "Signature"), (encryption, "Encryption")],
        password=P12_PASSWORD,
        keys_in_encrypted_safe=True,
    )
    identities = list_pkcs12_identities(blob, P12_PASSWORD)
    assert len(identities) == 1
    # The consequence of that fallback is visible: the identity that could not
    # be enumerated is left looking like a chain certificate, and the chain
    # audit reports it (chain.stray, report-only) rather than letting it go
    # unremarked onto the wire.
    session = PKIClient(blob, password=P12_PASSWORD)
    with session:
        assert (
            session.certificate.serial_number == signing.cert.serial_number
        )
        assert "chain.stray" in {p.code for p in session.explain().problems}


def test_three_identities(ca_bundle: CertBundle) -> None:
    bundles = [make_client_cert(f"id-{n}", ca=ca_bundle) for n in range(3)]
    blob = make_pkcs12(bundles, password=P12_PASSWORD)
    identities = list_pkcs12_identities(blob, P12_PASSWORD)
    assert [i.subject_cn for i in identities] == ["id-0", "id-1", "id-2"]
    with PKIClient(blob, password=P12_PASSWORD, identity="id-2") as session:
        assert session.cn == "id-2"
        # Neither of the other two leaves is presented as chain.
        assert [cert_info(pem).common_name for pem in session._material.ca_pems] == [
            "httpx-pki test CA"
        ]


# -- robustness -------------------------------------------------------------


@pytest.mark.parametrize(
    "blob",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x30\x80\x00\x00", id="indefinite-length"),
        pytest.param(b"\x30\x05\x02\x01\x03", id="truncated"),
        pytest.param(b"\x30\x84\xff\xff\xff\xff", id="length-past-end"),
        pytest.param(b"\x31\x03\x02\x01\x00", id="not-a-pfx"),
    ],
)
def test_structure_walk_gives_up_quietly(blob: bytes) -> None:
    # Anything the walk can't make sense of yields no key bags, so the caller
    # falls back to cryptography's view instead of failing a load that worked
    # before. It must never raise.
    assert _walk_key_bags(blob) == []


def test_certs_only_bundle_reports_a_missing_key(ca_bundle: CertBundle) -> None:
    blob = pkcs12.serialize_key_and_certificates(
        name=None,
        key=None,
        cert=None,
        cas=[ca_bundle.cert],
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(CertificateLoadError, match="no private key"):
        PKIClient(blob)
    assert list_pkcs12_identities(blob) == []


def test_unsupported_selector_type_is_rejected(dual_p12: bytes) -> None:
    with pytest.raises(TypeError, match="identity must be"):
        PKIClient(dual_p12, password=P12_PASSWORD, identity=1.5)  # type: ignore[arg-type]


def test_usage_selector_must_be_strings(dual_p12: bytes) -> None:
    with pytest.raises(TypeError, match="iterable of strings"):
        PKIClient(dual_p12, password=P12_PASSWORD, key_usage=7)  # type: ignore[arg-type]


# -- one key, several certificates (renewal) --------------------------------


def _renewed(bundle: CertBundle, ca_bundle: CertBundle) -> CertBundle:
    """A fresh certificate over *bundle*'s existing key pair -- a renewal."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(bundle.cert.subject)
        .issuer_name(ca_bundle.cert.subject)
        .public_key(bundle.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_bundle.key, hashes.SHA256())
    )
    return CertBundle(key=bundle.key, cert=cert, issuer=ca_bundle)


@pytest.fixture()
def renewal_p12(ca_bundle: CertBundle) -> tuple[bytes, CertBundle, CertBundle]:
    expiring = make_client_cert("renewed-user", ca=ca_bundle, expired=True)
    renewed = _renewed(expiring, ca_bundle)
    blob = make_pkcs12(
        [(expiring, "old"), (renewed, "renewed")], password=P12_PASSWORD
    )
    return blob, expiring, renewed


def test_two_certificates_over_one_key_are_two_identities(
    renewal_p12: tuple[bytes, CertBundle, CertBundle]
) -> None:
    # Renewing (rather than rekeying) a certificate leaves both certificates in
    # the file under a single key pair. They are two identities to choose
    # between, not one identity plus a stray chain certificate.
    blob, expiring, renewed = renewal_p12
    identities = list_pkcs12_identities(blob, P12_PASSWORD)
    assert [i.info.serial_number for i in identities] == [
        expiring.cert.serial_number,
        renewed.cert.serial_number,
    ]
    assert [i.friendly_name for i in identities] == ["old", "renewed"]


def test_renewal_is_ambiguous_and_the_message_shows_the_expiry(
    renewal_p12: tuple[bytes, CertBundle, CertBundle]
) -> None:
    blob, expiring, renewed = renewal_p12
    with pytest.raises(AmbiguousCertificateError) as excinfo:
        PKIClient(blob, password=P12_PASSWORD)
    message = str(excinfo.value)
    # Nothing but the validity window tells these two apart, so it has to be in
    # the listing for the message to be actionable.
    assert f"expires={expiring.cert.not_valid_after_utc:%Y-%m-%d}" in message
    assert f"expires={renewed.cert.not_valid_after_utc:%Y-%m-%d}" in message


def test_renewal_selecting_the_valid_certificate(
    renewal_p12: tuple[bytes, CertBundle, CertBundle], ca_bundle: CertBundle
) -> None:
    blob, _expiring, renewed = renewal_p12
    now = datetime.datetime.now(datetime.timezone.utc)
    with PKIClient(
        blob, password=P12_PASSWORD, identity=lambda i: i.info.not_valid_after > now
    ) as session:
        assert session.certificate.serial_number == renewed.cert.serial_number
        assert not session.is_expired
        # The certificate it replaces is not presented as a chain certificate.
        assert session._material.ca_pems == [ca_bundle.cert_pem]


def test_pem_renewal_is_two_identities(ca_bundle: CertBundle) -> None:
    # The PEM shape of the renewal case: one key block, the old and the new
    # certificate concatenated after it.
    expiring = make_client_cert("pem-renewed", ca=ca_bundle, expired=True)
    renewed = _renewed(expiring, ca_bundle)
    blob = (
        expiring.key_pem
        + expiring.cert_pem
        + renewed.cert_pem
        + ca_bundle.cert_pem
    )
    identities = list_identities(blob)
    assert [i.info.serial_number for i in identities] == [
        expiring.cert.serial_number,
        renewed.cert.serial_number,
    ]
    with pytest.raises(AmbiguousCertificateError):
        PKIClient(blob)
    with PKIClient(blob, identity=currently_valid) as session:
        assert session.certificate.serial_number == renewed.cert.serial_number
        # The replaced certificate is not presented as a chain certificate.
        assert session._material.ca_pems == [ca_bundle.cert_pem]


# -- currently_valid --------------------------------------------------------


def test_currently_valid_skips_the_expired_certificate(
    renewal_p12: tuple[bytes, CertBundle, CertBundle]
) -> None:
    blob, _expiring, renewed = renewal_p12
    with PKIClient(
        blob, password=P12_PASSWORD, identity=currently_valid
    ) as session:
        assert session.certificate.serial_number == renewed.cert.serial_number
        assert not session.is_expired


def test_currently_valid_skips_the_not_yet_valid_certificate(
    ca_bundle: CertBundle,
) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    current = make_client_cert("future-user", ca=ca_bundle)
    # Post-dated, with the later window: the tie-break must never resurrect a
    # candidate the validity filter excluded.
    future = make_client_cert(
        "future-user",
        ca=ca_bundle,
        not_valid_before=now + datetime.timedelta(days=30),
        not_valid_after=now + datetime.timedelta(days=400),
    )
    blob = make_pkcs12([(current, "now"), (future, "next")], password=P12_PASSWORD)
    with PKIClient(
        blob, password=P12_PASSWORD, identity=currently_valid
    ) as session:
        assert session.certificate.serial_number == current.cert.serial_number


def test_currently_valid_prefers_the_renewed_during_overlap(
    ca_bundle: CertBundle,
) -> None:
    # Both certificates are valid (the old one has not expired yet) and carry
    # the same subject and usages, so freshness is the only difference -- the
    # tie resolves to the later window.
    now = datetime.datetime.now(datetime.timezone.utc)
    old = make_client_cert(
        "overlap-user", ca=ca_bundle, not_valid_after=now + datetime.timedelta(days=20)
    )
    new = make_client_cert("overlap-user", ca=ca_bundle)
    blob = make_pkcs12([(old, "old"), (new, "new")], password=P12_PASSWORD)
    with PKIClient(
        blob, password=P12_PASSWORD, identity=currently_valid
    ) as session:
        assert session.certificate.serial_number == new.cert.serial_number


def test_currently_valid_keeps_a_dual_pair_ambiguous(dual_p12: bytes) -> None:
    # Both halves are valid right now, and their windows differ only by mint
    # time. Freshness cannot tell a signing certificate from an encryption
    # one, so this must stay ambiguous rather than picking one arbitrarily.
    with pytest.raises(AmbiguousCertificateError):
        PKIClient(dual_p12, password=P12_PASSWORD, identity=currently_valid)


def test_currently_valid_intersects_with_a_usage_selector(
    dual_p12: bytes, dual_identities: tuple[CertBundle, CertBundle]
) -> None:
    signing, _encryption = dual_identities
    with PKIClient(
        dual_p12,
        password=P12_PASSWORD,
        identity=currently_valid,
        key_usage="digital_signature",
    ) as session:
        assert session.certificate.serial_number == signing.cert.serial_number


def test_currently_valid_with_nothing_valid_raises(ca_bundle: CertBundle) -> None:
    first = make_client_cert("dead-user", ca=ca_bundle, expired=True)
    second = make_client_cert("dead-user", ca=ca_bundle, expired=True)
    blob = make_pkcs12([(first, "a"), (second, "b")], password=P12_PASSWORD)
    with pytest.raises(CertificateNotFoundError):
        PKIClient(blob, password=P12_PASSWORD, identity=currently_valid)


def test_currently_valid_pickles_to_the_same_singleton() -> None:
    # A SourceRef holding the selector must round-trip through pickle.
    assert pickle.loads(pickle.dumps(currently_valid)) is currently_valid


def test_non_repudiation_is_accepted_as_content_commitment(
    ca_bundle: CertBundle
) -> None:
    # X.509 renamed the bit to contentCommitment, but CA documentation and
    # openssl still say nonRepudiation -- both spellings must select.
    signing = make_client_cert(
        "qualified",
        ca=ca_bundle,
        key_usage=["digital_signature", "content_commitment"],
    )
    encryption = make_client_cert(
        "qualified", ca=ca_bundle, key_usage=["key_encipherment"]
    )
    blob = make_pkcs12(
        [(signing, "Signature"), (encryption, "Encryption")], password=P12_PASSWORD
    )
    for spelling in ("content_commitment", "non_repudiation", "nonRepudiation"):
        with PKIClient(blob, password=P12_PASSWORD, key_usage=spelling) as session:
            assert session.certificate.serial_number == signing.cert.serial_number


# -- non-strict DER from platform exporters ----------------------------------


def _loose_der_bundle(ca_bundle: CertBundle) -> tuple[bytes, str]:
    """A bundle encoded the way some platform exporters write one.

    Returns the blob and its certificate's thumbprint, taken from the
    certificate rather than by parsing the blob -- reading it back would itself
    warn, which would mask what these tests are checking.
    """
    bundle = make_client_cert("loose-der", ca=ca_bundle)
    blob = make_pkcs12(
        [(bundle, "loose")], password=P12_PASSWORD, strict_der=False
    )
    return blob, cert_info(bundle.cert_pem).fingerprint_sha1


def test_non_strict_der_still_loads(ca_bundle: CertBundle) -> None:
    blob, _ = _loose_der_bundle(ca_bundle)
    with pytest.warns(UserWarning, match="could not be parsed as DER"):
        with PKIClient(blob, password=P12_PASSWORD) as session:
            assert session.cn == "loose-der"


def test_non_strict_der_warns_for_caller_supplied_files(
    ca_bundle: CertBundle,
) -> None:
    # A file the caller handed us: the warning is actionable (re-export it),
    # so it must reach them.
    blob, _ = _loose_der_bundle(ca_bundle)
    with pytest.warns(UserWarning, match="could not be parsed as DER"):
        list_pkcs12_identities(blob, P12_PASSWORD)


def test_platform_store_exports_do_not_warn(ca_bundle: CertBundle) -> None:
    # The same bytes arriving from a platform store: generated by the OS,
    # consumed here, never written down. There is nothing the caller could do
    # about the encoding, so the warning is suppressed on that path only.
    blob, thumbprint = _loose_der_bundle(ca_bundle)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning fails the test
        material = material_from_store_export(
            blob, P12_PASSWORD.encode(), thumbprint
        )
    assert cert_info(material.cert_pem).common_name == "loose-der"


def test_store_export_suppression_is_narrow(
    ca_bundle: CertBundle, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only the DER/BER warning is silenced. Anything else raised while the
    # filter is installed must still reach the caller, so make the parse itself
    # warn about something unrelated and check it survives the round trip.
    blob, thumbprint = _loose_der_bundle(ca_bundle)
    real = pkcs12.load_pkcs12

    def noisy(data: bytes, password: bytes | None) -> object:
        warnings.warn("an unrelated concern", UserWarning, stacklevel=2)
        return real(data, password)

    monkeypatch.setattr("httpx_pki._pkcs12.pkcs12.load_pkcs12", noisy)
    with pytest.warns(UserWarning, match="an unrelated concern"):
        material_from_store_export(blob, P12_PASSWORD.encode(), thumbprint)


def test_identities_are_hashable(dual_p12: bytes) -> None:
    # CertInfo holds lists, so a frozen dataclass including it in __eq__ hashes
    # to a TypeError. Anyone deduping enumerated certificates would hit it.
    identities = list_pkcs12_identities(dual_p12, P12_PASSWORD)
    assert len(set(identities)) == 2
    assert len({identities[0], identities[0]}) == 1


# -- for_mtls: the 95% selector ---------------------------------------------


def test_for_mtls_picks_the_signing_half_of_a_dual_key_pair(
    dual_p12: bytes, dual_identities: tuple[CertBundle, ...]
) -> None:
    """The question nearly every caller is actually asking."""
    from httpx_pki import for_mtls

    with PKIClient(dual_p12, password=P12_PASSWORD, identity=for_mtls) as session:
        assert session.certificate.serial_number == _serial(dual_identities, 0)
        assert session.cert_info().extended_key_usage == ["client_auth"]


def test_for_mtls_picks_the_current_certificate_of_a_renewal_pair(
    ca_bundle: CertBundle,
) -> None:
    from httpx_pki import for_mtls
    from httpx_pki.testing import make_pkcs12

    now = datetime.datetime.now(datetime.timezone.utc)
    old = make_client_cert(
        "svc",
        ca=ca_bundle,
        not_valid_before=now - datetime.timedelta(days=300),
        not_valid_after=now + datetime.timedelta(days=10),
    )
    new = make_client_cert(
        "svc",
        ca=ca_bundle,
        not_valid_before=now - datetime.timedelta(days=5),
        not_valid_after=now + datetime.timedelta(days=360),
    )
    blob = make_pkcs12([old, new], password=P12_PASSWORD)
    with PKIClient(blob, password=P12_PASSWORD, identity=for_mtls) as session:
        assert session.certificate.serial_number == new.cert.serial_number


def test_for_mtls_does_both_at_once(ca_bundle: CertBundle) -> None:
    """The reason it exists rather than two selectors: identity= holds one
    value, so 'currently valid' and 'client auth' could not be combined."""
    from httpx_pki import for_mtls
    from httpx_pki.testing import make_pkcs12

    now = datetime.datetime.now(datetime.timezone.utc)
    expired_signing = make_client_cert(
        "svc", ca=ca_bundle, expired=True, extended_key_usage=["client_auth"]
    )
    current_encryption = make_client_cert(
        "svc",
        ca=ca_bundle,
        key_usage=["key_encipherment"],
        extended_key_usage=["email_protection"],
    )
    current_signing = make_client_cert(
        "svc",
        ca=ca_bundle,
        not_valid_before=now - datetime.timedelta(days=1),
        extended_key_usage=["client_auth"],
    )
    blob = make_pkcs12(
        [expired_signing, current_encryption, current_signing],
        password=P12_PASSWORD,
    )
    with PKIClient(blob, password=P12_PASSWORD, identity=for_mtls) as session:
        assert session.certificate.serial_number == current_signing.cert.serial_number


def test_for_mtls_accepts_a_certificate_with_no_extended_key_usage(
    ca_bundle: CertBundle,
) -> None:
    """An absent extension is unconstrained in X.509, not forbidden."""
    from httpx_pki import for_mtls

    plain = make_client_cert("svc", ca=ca_bundle, extended_key_usage=[])
    with PKIClient(plain.pem, identity=for_mtls) as session:
        assert session.cn == "svc"


def test_for_mtls_rejects_an_encryption_only_certificate_without_eku(
    ca_bundle: CertBundle,
) -> None:
    """With no EKU to go on, KeyUsage decides: a key that cannot sign cannot
    authenticate a TLS client."""
    from httpx_pki import for_mtls

    encryption = make_client_cert(
        "svc", ca=ca_bundle, key_usage=["key_encipherment"], extended_key_usage=[]
    )
    with pytest.raises(CertificateNotFoundError):
        PKIClient(encryption.pem, identity=for_mtls)


def test_for_mtls_raises_when_nothing_qualifies(ca_bundle: CertBundle) -> None:
    """It is a filter like any other: an expired or encryption-only identity is
    never silently presented."""
    from httpx_pki import for_mtls

    expired = make_client_cert("svc", ca=ca_bundle, expired=True)
    with pytest.raises(CertificateNotFoundError) as excinfo:
        PKIClient(expired.pem, identity=for_mtls)
    assert "for_mtls" in str(excinfo.value)


def test_a_for_mtls_miss_explains_itself(ca_bundle: CertBundle) -> None:
    """The listing must show the extended usage -- it is what was filtered on,
    so without it the message cannot explain the miss."""
    from httpx_pki import for_mtls

    wrong = make_client_cert(
        "svc", ca=ca_bundle, extended_key_usage=["email_protection"]
    )
    with pytest.raises(CertificateNotFoundError) as excinfo:
        PKIClient(wrong.pem, identity=for_mtls)
    assert "ext_key_usage=email_protection" in str(excinfo.value)


def test_for_mtls_pickles_by_name(dual_p12: bytes) -> None:
    from httpx_pki import for_mtls

    session = PKIClient(dual_p12, password=P12_PASSWORD, identity=for_mtls)
    restored = pickle.loads(pickle.dumps(session))
    assert restored._source is not None
    assert restored._source.args["identity"] is for_mtls
    session.close()
    restored.close()


def test_for_mtls_is_spelled_the_same_in_the_environment(
    dual_p12: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "dual.p12"
    path.write_bytes(dual_p12)
    monkeypatch.setenv("HTTPX_PKI_CERT", str(path))
    monkeypatch.setenv("HTTPX_PKI_PASSWORD", P12_PASSWORD)
    monkeypatch.setenv("HTTPX_PKI_IDENTITY", "for_mtls")
    with PKIClient.from_env() as session:
        assert session.cert_info().extended_key_usage == ["client_auth"]
