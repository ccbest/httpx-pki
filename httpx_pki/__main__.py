"""``python -m httpx_pki`` -- inspect a certificate source from a shell.

The entry points reachable by somebody who has been handed certificate files
and has not written any code yet, which is exactly the audience the reports
are for. Thin wrappers over :func:`~httpx_pki.explain` (one source: what it
holds and what would stop it working) and :func:`~httpx_pki.inventory` (a whole
directory: what each file is and which files pair up): everything they know
comes from there, and this module adds only argument parsing, password
prompts, and exit codes.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from ._exceptions import PKIError
from ._explain import explain
from ._inventory import inventory
from ._select import selector_from_string, usages_from_string


def _password(args: argparse.Namespace, needs_one: bool) -> str | None:
    """The password to use, asked for only when the source turns out to need it.

    Never taken from the command line. An argument lands in shell history and
    in every process listing on the machine, which for the one secret this
    library exists to protect is not a trade worth offering -- so it is an
    environment variable or an interactive prompt.
    """
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            raise SystemExit(
                f"environment variable {args.password_env} is not set"
            )
        return value
    if needs_one and sys.stdin.isatty():
        return getpass.getpass("Password (blank if none): ") or None
    return None


def _selectors(args: argparse.Namespace) -> dict[str, object]:
    """The ``explain()`` keywords the flags map to.

    ``--identity`` is normalized by the same helper the environment variables
    use, so an index, a name, a fingerprint, and ``currently_valid`` mean the
    same thing whichever way they are spelled.
    """
    return {
        "identity": selector_from_string(args.identity),
        "key_usage": usages_from_string(args.key_usage),
        "extended_key_usage": usages_from_string(args.extended_key_usage),
        "chain": list(args.chain) or None,
        "prune_chain": args.prune_chain,
        "verify": list(args.verify) if args.verify else True,
    }


def _explain(args: argparse.Namespace) -> int:
    selectors = _selectors(args)
    report = explain(
        args.source, _password(args, needs_one=False), **selectors  # type: ignore[arg-type]
    )
    if any(p.code == "source.password_required" for p in report.problems):
        password = _password(args, needs_one=True)
        if password is not None:
            report = explain(args.source, password, **selectors)  # type: ignore[arg-type]
    print(report)
    # Non-zero when something is wrong, so this is usable as a CI check.
    return 1 if report.problems else 0


def _inventory_passwords(args: argparse.Namespace) -> list[str]:
    """The passwords named by the repeated ``--password-env`` flags."""
    passwords = []
    for var in args.password_env:
        value = os.environ.get(var)
        if value is None:
            raise SystemExit(f"environment variable {var} is not set")
        passwords.append(value)
    return passwords


def _inventory(args: argparse.Namespace) -> int:
    passwords = _inventory_passwords(args)
    report = inventory(args.directory, passwords=passwords or None)
    # One prompt per locked file, skippable, then a single re-read: a password
    # typed for one file is tried against all of them, since a folder's .p12
    # and its extracted key routinely share a passphrase.
    if report.locked and sys.stdin.isatty():
        entered = []
        for item in report.locked:
            value = getpass.getpass(f"Password for {item.name} (blank to skip): ")
            if value:
                entered.append(value)
        if entered:
            report = inventory(args.directory, passwords=[*passwords, *entered])
    print(report)
    # Non-zero only when nothing here is loadable: locked and unpaired files
    # are the normal lint of such a folder, not a failure of the inventory.
    return 0 if report.usable else 1


def main(argv: list[str] | None = None) -> int:
    """Parse *argv* and run the named subcommand; returns the exit status."""
    parser = argparse.ArgumentParser(
        prog="python -m httpx_pki",
        description="Inspect certificate material for mTLS.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    explain_parser = sub.add_parser(
        "explain",
        help="describe a certificate source and what would stop it working",
    )
    explain_parser.add_argument(
        "source", help="a PKCS#12 or PEM file (the encoding is read from the bytes)"
    )
    explain_parser.add_argument(
        "--password-env",
        metavar="VAR",
        help=(
            "read the password from this environment variable instead of "
            "prompting. There is no --password: it would land in shell history "
            "and in every process listing"
        ),
    )
    explain_parser.add_argument(
        "--identity",
        metavar="SELECTOR",
        help=(
            "select an identity: 'for_mtls' (the currently valid, "
            "client-auth-capable one -- usually what you want), a position, a "
            "name substring, a fingerprint, or 'currently_valid'. Without one, "
            "a multi-identity bundle is listed rather than described"
        ),
    )
    explain_parser.add_argument(
        "--key-usage",
        metavar="NAMES",
        help="select an identity by key usage, comma-separated "
        "(e.g. digital_signature)",
    )
    explain_parser.add_argument(
        "--extended-key-usage",
        metavar="NAMES",
        help="select an identity by extended key usage, comma-separated "
        "(e.g. client_auth)",
    )
    explain_parser.add_argument(
        "--chain",
        metavar="SOURCE",
        action="append",
        default=[],
        help="intermediates to present alongside the certificate; repeatable",
    )
    explain_parser.add_argument(
        "--prune-chain",
        action="store_true",
        help="drop chain certificates that are not on this certificate's path",
    )
    explain_parser.add_argument(
        "--verify",
        metavar="SOURCE",
        action="append",
        default=[],
        help=(
            "a server-trust source: 'system', 'certifi', or a CA bundle or "
            "directory. Repeatable; they combine. Defaults to the OS store"
        ),
    )
    explain_parser.set_defaults(func=_explain)

    inventory_parser = sub.add_parser(
        "inventory",
        help="classify a directory of certificate files and pair its identities",
    )
    inventory_parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="the directory to inventory (top-level files only; default: here)",
    )
    inventory_parser.add_argument(
        "--password-env",
        metavar="VAR",
        action="append",
        default=[],
        help=(
            "read a password from this environment variable; repeatable, since "
            "a folder of exports routinely spans several passwords. There is "
            "no --password: it would land in shell history and in every "
            "process listing. Files still locked are prompted for, one each"
        ),
    )
    inventory_parser.set_defaults(func=_inventory)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except PKIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
