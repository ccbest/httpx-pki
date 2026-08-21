"""``explain()``, ``client.explain()``, and the ``python -m httpx_pki`` CLI.

The report exists for whoever was handed a ``.p12`` and told to use it, so the
cases that matter most are the ones where the file cannot be loaded: those must
produce a report saying why, not an exception.
"""

from __future__ import annotations

import datetime
import socket
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from httpx_pki import (
    CertificateLoadError,
    PKIClient,
    TLSConfigWarning,
    X509Explanation,
    explain,
)
from httpx_pki.__main__ import main
from httpx_pki.testing import CertBundle, make_ca, make_client_cert, make_pkcs12
from tests.conftest import P12_PASSWORD, Signed

AIA_URL = "http://pki.corp.example/CorpIssuingCA.crt"


def _codes(report: X509Explanation) -> set[str]:
    return {problem.code for problem in report.problems}


@pytest.fixture
def intermediate(ca_bundle: CertBundle) -> CertBundle:
    base = make_client_cert(
        "Corp Issuing CA", ca=ca_bundle, key_usage=["key_cert_sign"]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(base.cert.subject)
        .issuer_name(ca_bundle.cert.subject)
        .public_key(base.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ca_bundle.cert.not_valid_before_utc)
        .not_valid_after(ca_bundle.cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(base.key.public_key()),
            critical=False,
        )
        .sign(ca_bundle.key, hashes.SHA256())
    )
    return CertBundle(key=base.key, cert=cert, issuer=ca_bundle)


@pytest.fixture
def leaf_with_aia(intermediate: CertBundle) -> CertBundle:
    """A leaf whose AIA extension names where its issuer is published."""
    base = make_client_cert("svc-client", ca=intermediate)
    cert = (
        x509.CertificateBuilder()
        .subject_name(base.cert.subject)
        .issuer_name(intermediate.cert.subject)
        .public_key(base.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(base.cert.not_valid_before_utc)
        .not_valid_after(base.cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(AIA_URL),
                    )
                ]
            ),
            critical=False,
        )
        .sign(intermediate.key, hashes.SHA256())
    )
    return CertBundle(key=base.key, cert=cert, issuer=intermediate)


def _p12(bundle: CertBundle, cas: list[x509.Certificate] | None = None) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        b"svc", bundle.key, bundle.cert, cas, serialization.NoEncryption()
    )


# -- the cases the report exists for ----------------------------------------


def test_a_confusing_bundle_reports_rather_than_raises(dual_p12: bytes) -> None:
    """Several identities and no selector: a client cannot be built, but the
    whole point is to look inside before you can."""
    report = explain(dual_p12, P12_PASSWORD)
    assert "source.ambiguous" in _codes(report)
    assert [i.index for i in report.identities] == [0, 1]
    assert report.presented is None
    assert "Signature" in str(report) and "Encryption" in str(report)


def test_a_missing_password_reports_rather_than_raises(dual_p12: bytes) -> None:
    report = explain(dual_p12)
    assert "source.password_required" in _codes(report)
    assert report.identities == []
    # It must say *why* nothing can be shown, since a PKCS#12 -- unlike PEM --
    # has no part that can be read first.
    assert "encrypts its certificates" in str(report)


def test_an_unreadable_source_still_raises(tmp_path: Path) -> None:
    with pytest.raises(CertificateLoadError):
        explain(tmp_path / "nope.p12")


def test_garbage_reports_unreadable() -> None:
    report = explain(b"\x00\x01not a certificate at all")
    assert "source.unreadable" in _codes(report)


# -- the chain --------------------------------------------------------------


def test_a_missing_issuer_names_where_to_get_it(leaf_with_aia: CertBundle) -> None:
    """The payoff: 'fix your inputs' becomes a URL to fetch."""
    report = explain(_p12(leaf_with_aia))
    rendered = str(report)
    assert "Corp Issuing CA" in rendered
    assert "NOT SUPPLIED" in rendered
    assert AIA_URL in rendered


def test_the_aia_url_is_never_fetched(
    leaf_with_aia: CertBundle, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The URL comes from the certificate being inspected -- untrusted input --
    so requesting it would let whoever supplied the file choose a URL this
    process fetches. Nothing here may open a socket."""

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("explain() attempted a network connection")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    report = explain(_p12(leaf_with_aia))
    assert AIA_URL in str(report)


def test_a_complete_chain_verifies_signatures(
    client_p12: bytes, ca: Signed
) -> None:
    report = explain(client_p12, P12_PASSWORD, chain=ca.cert_pem)
    assert "[verified" in str(report)
    assert not report.problems


def test_signature_failure_is_distinguished_from_a_name_match(
    intermediate: CertBundle,
) -> None:
    """``explain()`` verifies signatures where the audit only matches names.

    The impostor carries no SubjectKeyIdentifier, so the cheap issuer test the
    construction path uses has nothing to reject it by -- the subject name
    matches. Only the signature check catches it, which is the whole reason
    the report does one and the hot path does not.
    """
    leaf = make_client_cert("svc", ca=intermediate)
    other_key = make_client_cert("throwaway").key
    impostor = (
        x509.CertificateBuilder()
        .subject_name(intermediate.cert.subject)  # same name...
        .issuer_name(intermediate.cert.subject)
        .public_key(other_key.public_key())  # ...different key
        .serial_number(x509.random_serial_number())
        .not_valid_before(intermediate.cert.not_valid_before_utc)
        .not_valid_after(intermediate.cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)

    report = explain(leaf.key_pem + leaf.cert_pem, chain=impostor)
    assert "BAD SIGNATURE" in str(report)


def test_strays_and_trust_problems_are_reported(
    client_p12: bytes, ca: Signed, tmp_path: Path
) -> None:
    stranger = make_ca("Unrelated Root")
    report = explain(
        client_p12,
        P12_PASSWORD,
        chain=[ca.cert_pem, stranger.cert_pem],
    )
    assert "chain.stray" in _codes(report)


def test_problem_codes_are_what_you_match_on(client_p12: bytes) -> None:
    stranger = make_ca("Unrelated Root")
    report = explain(client_p12, P12_PASSWORD, chain=stranger.cert_pem)
    problem = next(p for p in report.problems if p.code == "chain.disconnected")
    assert problem.remedy  # the actionable half is a separate field
    assert problem.certificates and problem.certificates[0].common_name


# -- trust ------------------------------------------------------------------


def test_trust_is_shown_alongside_what_is_presented(
    client_p12: bytes, ca_file: Path
) -> None:
    report = explain(client_p12, P12_PASSWORD, verify=["system", str(ca_file)])
    rendered = str(report)
    assert "the OS trust store" in rendered
    assert "httpx-pki test CA" in rendered


def test_a_trusted_missing_issuer_is_reassuring_not_alarming(
    client_p12: bytes, ca_file: Path
) -> None:
    """A chain stopping at an issuer you already trust is the normal shape, and
    the report must say so rather than flagging it."""
    report = explain(client_p12, P12_PASSWORD, verify=str(ca_file))
    assert "trust anchor, need not be sent" in str(report)
    assert not report.problems


def test_an_untrusted_missing_issuer_gets_no_reassurance(
    client_p12: bytes, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "other.pem"
    elsewhere.write_bytes(make_ca("Somewhere Else").cert_pem)
    report = explain(client_p12, P12_PASSWORD, verify=str(elsewhere))
    assert "trust anchor, need not be sent" not in str(report)


# -- the client method ------------------------------------------------------


def test_client_explain_agrees_with_the_warning_it_raised(
    client_p12: bytes,
) -> None:
    """One analyzer: a report can never contradict the warning that sent
    someone to it. Uses chain.disconnected, one of the findings that still
    warns at construction because it predicts a failing handshake."""
    stranger = make_ca("Unrelated Root")
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        session = PKIClient(client_p12, password=P12_PASSWORD, chain=stranger.cert_pem)
    warned = [str(w.message) for w in rec if issubclass(w.category, TLSConfigWarning)]

    with session:
        report = session.explain()
    assert "chain.disconnected" in _codes(report)
    assert any("reach the issuer" in message for message in warned)
    # And the warning points at the call that lays it out.
    assert any("explain()" in message for message in warned)


def test_client_explain_knows_both_halves(client_p12: bytes, ca_file: Path) -> None:
    with PKIClient(client_p12, password=P12_PASSWORD, verify=str(ca_file)) as session:
        rendered = str(session.explain())
    assert "PRESENTS" in rendered and "TRUSTS" in rendered


def test_the_report_is_inspectable_not_just_printable(client_p12: bytes) -> None:
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        report = session.explain()
    assert report.ok is True
    assert report.presented is not None
    assert report.presented.common_name == "test-client"
    assert isinstance(report, X509Explanation)


# -- rendering safety -------------------------------------------------------


def test_control_characters_are_stripped_from_untrusted_names(
    ca_bundle: CertBundle,
) -> None:
    """Subject names are attacker-controlled and X.509 text fields can carry
    escape sequences a terminal would act on."""
    key = make_client_cert("placeholder", ca=ca_bundle).key
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil\x1b[31mred")])
        )
        .issuer_name(ca_bundle.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ca_bundle.cert.not_valid_before_utc)
        .not_valid_after(ca_bundle.cert.not_valid_after_utc)
        .sign(ca_bundle.key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    bundle = CertBundle(key=key, cert=cert, issuer=ca_bundle)
    rendered = str(explain(bundle.key_pem + pem))
    assert "\x1b" not in rendered
    assert "evil[31mred" in rendered


# -- the CLI ----------------------------------------------------------------


def test_cli_exit_codes(
    tmp_path: Path, client_p12: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    clean = tmp_path / "clean.p12"
    clean.write_bytes(client_p12)
    monkeypatch.setenv("PKI_PW", P12_PASSWORD)
    assert main(["explain", str(clean), "--password-env", "PKI_PW"]) == 0

    broken = tmp_path / "dual.p12"
    signing = make_client_cert("u", key_usage=["digital_signature"])
    encryption = make_client_cert("u", key_usage=["key_encipherment"])
    broken.write_bytes(
        make_pkcs12([(signing, "Sig"), (encryption, "Enc")], password=P12_PASSWORD)
    )
    assert main(["explain", str(broken), "--password-env", "PKI_PW"]) == 1

    assert main(["explain", str(tmp_path / "missing.p12")]) == 2


def test_cli_refuses_a_password_argument(tmp_path: Path) -> None:
    """A password on argv lands in shell history and every process listing."""
    with pytest.raises(SystemExit):
        main(["explain", str(tmp_path / "x.p12"), "--password", "secret"])


def test_cli_reports_an_unset_password_env(tmp_path: Path, client_p12: bytes) -> None:
    path = tmp_path / "c.p12"
    path.write_bytes(client_p12)
    with pytest.raises(SystemExit, match="is not set"):
        main(["explain", str(path), "--password-env", "DEFINITELY_UNSET_VAR"])


# -- the report is what a REPL shows ----------------------------------------


def test_repr_is_the_report(client_p12: bytes) -> None:
    """The object exists to be read in a REPL or notebook, and both display
    through ``repr`` -- a short one would defeat the whole feature."""
    with PKIClient(client_p12, password=P12_PASSWORD) as session:
        report = session.explain()
    assert repr(report) == str(report)
    assert "PRESENTS" in repr(report)


# -- the certificate's own problems -----------------------------------------


def test_an_expired_certificate_is_a_problem_not_just_a_description(
    ca_bundle: CertBundle,
) -> None:
    """It shows in the validity line either way, but an expired certificate is
    not a neutral fact about the material -- it is why the handshake fails."""
    expired = make_client_cert("stale", ca=ca_bundle, expired=True)
    report = explain(expired.key_pem + expired.cert_pem)
    assert "certificate.expired" in _codes(report)
    assert "(EXPIRED)" in str(report)


def test_a_not_yet_valid_certificate_is_a_problem(ca_bundle: CertBundle) -> None:
    import datetime

    soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)
    future = make_client_cert(
        "early", ca=ca_bundle, not_valid_before=soon, not_valid_after=soon
    )
    report = explain(future.key_pem + future.cert_pem)
    assert "certificate.not_yet_valid" in _codes(report)


def test_a_certificate_without_client_auth_is_a_problem(
    ca_bundle: CertBundle,
) -> None:
    wrong = make_client_cert(
        "mailbox", ca=ca_bundle, extended_key_usage=["email_protection"]
    )
    report = explain(wrong.key_pem + wrong.cert_pem)
    assert "certificate.no_client_auth" in _codes(report)
    assert "NO CLIENT_AUTH" in str(report)


def test_an_absent_extended_key_usage_is_not_a_problem(
    ca_bundle: CertBundle, tmp_path: Path
) -> None:
    """No EKU at all means 'good for anything', which is not a fault."""
    key = make_client_cert("any-purpose", ca=ca_bundle).key
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "any-purpose")])
        )
        .issuer_name(ca_bundle.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ca_bundle.cert.not_valid_before_utc)
        .not_valid_after(ca_bundle.cert.not_valid_after_utc)
        .sign(ca_bundle.key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    report = explain(key_pem + pem)
    assert "certificate.no_client_auth" not in _codes(report)


def test_expiry_is_not_warned_about_twice(ca_bundle: CertBundle) -> None:
    """The session's own validity check owns that channel -- it knows about
    warn_if_expires_within and says it better."""
    expired = make_client_cert("stale", ca=ca_bundle, expired=True)
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        PKIClient(expired.key_pem + expired.cert_pem).close()
    expiry = [w for w in rec if "expired on" in str(w.message)]
    assert len(expiry) == 1


# -- CLI selectors ----------------------------------------------------------


def test_cli_can_select_an_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without this a multi-identity bundle could be listed from the shell but
    never inspected."""
    path = tmp_path / "dual.p12"
    signing = make_client_cert(
        "corp-user", key_usage=["digital_signature"], extended_key_usage=["client_auth"]
    )
    encryption = make_client_cert(
        "corp-user",
        key_usage=["key_encipherment"],
        extended_key_usage=["email_protection"],
    )
    path.write_bytes(
        make_pkcs12([(signing, "Sig"), (encryption, "Enc")], password=P12_PASSWORD)
    )
    monkeypatch.setenv("PKI_PW", P12_PASSWORD)

    # No selector: listed, and ambiguous.
    assert main(["explain", str(path), "--password-env", "PKI_PW"]) == 1
    assert "source.ambiguous" in capsys.readouterr().out

    # With one: described.
    main(
        [
            "explain",
            str(path),
            "--password-env",
            "PKI_PW",
            "--key-usage",
            "digital_signature",
        ]
    )
    out = capsys.readouterr().out
    assert "PRESENTS" in out and "digital_signature" in out


def test_cli_identity_accepts_an_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "dual.p12"
    a = make_client_cert("first")
    b = make_client_cert("second")
    path.write_bytes(make_pkcs12([(a, "A"), (b, "B")], password=P12_PASSWORD))
    monkeypatch.setenv("PKI_PW", P12_PASSWORD)
    main(["explain", str(path), "--password-env", "PKI_PW", "--identity", "1"])
    assert "second" in capsys.readouterr().out


def test_cli_verify_and_chain_are_reachable(
    tmp_path: Path, client_p12: bytes, ca_file: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "c.p12"
    path.write_bytes(client_p12)
    monkeypatch.setenv("PKI_PW", P12_PASSWORD)
    main(
        [
            "explain",
            str(path),
            "--password-env",
            "PKI_PW",
            "--verify",
            "system",
            "--verify",
            str(ca_file),
        ]
    )
    out = capsys.readouterr().out
    assert "the OS trust store" in out and "httpx-pki test CA" in out


# -- the diagram accounts for everything on the wire ------------------------


def test_a_stray_appears_in_the_diagram(client_p12: bytes, ca: Signed) -> None:
    """It is *sent*, so leaving it out meant the diagram showed a certificate
    that is not on the wire (the missing issuer) while hiding one that is."""
    stranger = make_ca("Unrelated Root")
    report = explain(
        client_p12, P12_PASSWORD, chain=[ca.cert_pem, stranger.cert_pem]
    )
    names = [link.info.common_name for link in report.chain]
    assert "Unrelated Root" in names
    assert "UNATTACHED" in str(report)


def test_a_stray_is_marked_off_the_path(client_p12: bytes, ca: Signed) -> None:
    stranger = make_ca("Unrelated Root")
    report = explain(
        client_p12, P12_PASSWORD, chain=[ca.cert_pem, stranger.cert_pem]
    )
    off = [link for link in report.chain if not link.on_path]
    assert [link.info.common_name for link in off] == ["Unrelated Root"]
    # It is on the wire, unlike the missing-issuer placeholder.
    assert all(link.present for link in off)


def test_a_stray_sits_at_the_margin_with_no_connector(
    client_p12: bytes, ca: Signed
) -> None:
    """Attached to nothing is the point, so the layout says it before the note
    does: no tree connector, and back at the left margin."""
    stranger = make_ca("Unrelated Root")
    rendered = str(
        explain(client_p12, P12_PASSWORD, chain=[ca.cert_pem, stranger.cert_pem])
    )
    line = next(ln for ln in rendered.splitlines() if "Unrelated Root" in ln)
    assert "└─" not in line
    assert line.startswith(" " * 11 + "Unrelated Root")


def test_a_trusted_stray_says_so(
    client_p12: bytes, ca_file: Path, tmp_path: Path
) -> None:
    stranger = make_ca("Unrelated Root")
    anchors = tmp_path / "anchors.pem"
    anchors.write_bytes(Path(ca_file).read_bytes() + stranger.cert_pem)
    report = explain(
        client_p12,
        P12_PASSWORD,
        chain=[Path(ca_file).read_bytes(), stranger.cert_pem],
        verify=str(anchors),
    )
    assert "already a trust anchor" in str(report)


def test_a_duplicated_leaf_is_marked_on_the_leaf_line(
    client_p12: bytes, ca: Signed, client: Signed
) -> None:
    report = explain(
        client_p12, P12_PASSWORD, chain=[ca.cert_pem, client.cert_pem]
    )
    leaf = report.chain[0]
    assert leaf.sent_twice is True
    assert "SENT TWICE" in str(report)


def test_a_correct_chain_marks_nothing_off_the_path(
    client_p12: bytes, ca: Signed
) -> None:
    report = explain(client_p12, P12_PASSWORD, chain=ca.cert_pem)
    assert all(link.on_path for link in report.chain)
    assert not any(link.sent_twice for link in report.chain)


# -- trust anchors: what parsing alone can prove ----------------------------


def _root(
    cn: str,
    *,
    nb_days: int = 1,
    valid_days: int = 3650,
    bits: int = 2048,
    cert_sign: bool = True,
) -> x509.Certificate:
    from cryptography.hazmat.primitives.asymmetric import rsa

    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    usage = x509.KeyUsage(
        digital_signature=not cert_sign,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    start = now - datetime.timedelta(days=nb_days)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(usage, critical=True)
        .sign(key, hashes.SHA256())
    )


def _pem(*certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def test_an_only_anchor_that_is_expired_is_fatal(
    client_p12: bytes, tmp_path: Path
) -> None:
    """Verified against a real handshake: an expired anchor is rejected."""
    path = tmp_path / "expired.pem"
    path.write_bytes(_pem(_root("Old Root", nb_days=4000, valid_days=100)))
    report = explain(client_p12, P12_PASSWORD, verify=str(path))
    assert "trust.no_usable_anchor" in _codes(report)
    assert "UNUSABLE" in str(report)


def test_one_expired_anchor_beside_a_good_one_is_silent(
    client_p12: bytes, tmp_path: Path
) -> None:
    """The noise case, and the reason the check is set-wide.

    A bundle carrying a dead cross-signing root through a transition is normal,
    and verification simply uses the live one -- confirmed by handshake.
    """
    path = tmp_path / "mixed.pem"
    path.write_bytes(
        _pem(_root("Old Root", nb_days=4000, valid_days=100), _root("Live Root"))
    )
    report = explain(client_p12, P12_PASSWORD, verify=str(path))
    assert "trust.no_usable_anchor" not in _codes(report)
    # ...but the expired one is still *described*, which is the point.
    assert "UNUSABLE" in str(report)


def test_expired_anchors_are_silent_when_the_os_store_is_also_trusted(
    client_p12: bytes, tmp_path: Path
) -> None:
    path = tmp_path / "expired.pem"
    path.write_bytes(_pem(_root("Old Root", nb_days=4000, valid_days=100)))
    report = explain(client_p12, P12_PASSWORD, verify=["system", str(path)])
    assert "trust.no_usable_anchor" not in _codes(report)


def test_a_not_yet_valid_anchor_is_unusable(
    client_p12: bytes, tmp_path: Path
) -> None:
    path = tmp_path / "future.pem"
    path.write_bytes(_pem(_root("Future Root", nb_days=-30)))
    report = explain(client_p12, P12_PASSWORD, verify=str(path))
    assert "trust.no_usable_anchor" in _codes(report)


def test_a_ca_without_key_cert_sign_is_reported(
    client_p12: bytes, tmp_path: Path
) -> None:
    """OpenSSL rejects this as an invalid CA regardless of what else is
    trusted, so it is reported per entry rather than only set-wide."""
    path = tmp_path / "nocertsign.pem"
    path.write_bytes(_pem(_root("Broken CA", cert_sign=False)))
    report = explain(client_p12, P12_PASSWORD, verify=str(path))
    assert "trust.not_a_ca" in _codes(report)


def test_a_ca_with_no_key_usage_at_all_is_fine(
    client_p12: bytes, tmp_path: Path
) -> None:
    """An absent KeyUsage is unconstrained, not forbidden -- confirmed by
    handshake. Flagging it would break a working configuration."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bare CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "bare.pem"
    path.write_bytes(_pem(cert))
    report = explain(client_p12, P12_PASSWORD, verify=str(path))
    assert not report.problems


def test_the_trust_block_breaks_down_every_anchor(
    client_p12: bytes, tmp_path: Path
) -> None:
    path = tmp_path / "two.pem"
    path.write_bytes(
        _pem(_root("Live Root"), _root("Old Root", nb_days=4000, valid_days=100))
    )
    rendered = str(explain(client_p12, P12_PASSWORD, verify=str(path)))
    assert "RSA-2048" in rendered
    assert "expires " in rendered
    assert "UNUSABLE" in rendered


def test_anchor_status_is_inspectable(client_p12: bytes, tmp_path: Path) -> None:
    path = tmp_path / "mixed.pem"
    path.write_bytes(
        _pem(_root("Live Root"), _root("Old Root", nb_days=4000, valid_days=100))
    )
    report = explain(client_p12, P12_PASSWORD, verify=str(path))
    anchors = report.trust[0].anchors
    assert [a.usable for a in anchors] == [True, False]
    assert anchors[0].key == "RSA-2048"
    assert anchors[1].reason is not None and "expired" in anchors[1].reason


def test_an_unusable_anchor_does_not_count_as_trusted_for_the_chain(
    client_p12: bytes, tmp_path: Path
) -> None:
    """A chain gap whose issuer you 'trust' only via an expired anchor is not
    one the server can be left to fill."""
    expired_ca = tmp_path / "expired-ca.pem"
    expired_ca.write_bytes(_pem(_root("Old Root", nb_days=4000, valid_days=100)))
    report = explain(client_p12, P12_PASSWORD, verify=str(expired_ca))
    assert "need not be sent" not in str(report)
