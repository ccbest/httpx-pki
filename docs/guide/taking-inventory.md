# Taking inventory of a folder

Certificates rarely arrive as one file. What usually lands in your hands is a folder —
a `.p12` next to the PEM halves somebody extracted from it, a chain bundle, a
CSR nobody deleted, a text dump of a certificate that may or may not be one of
the others, and last year's renewal. The extensions promise nothing, several
of the files want passwords, and you do not yet know which two of them go
together.

`inventory()` reads the folder and tells you: what each file is, which files
pair into a usable identity, and the constructor call each pairing amounts to.

```console
$ python -m httpx_pki inventory ./corp-export
```

```python
import httpx_pki

print(httpx_pki.inventory("./corp-export"))
```

## What the report says

With no passwords yet, nothing has opened — and the report is already useful:

```text
INVENTORY  corp-export — 7 files, 0 identities

LOCKED     corp.p12 — encrypted PKCS#12; none of the given passwords open it
           old-2025.pem — 1 certificate, plus 1 encrypted private key none of the given passwords open
           svc-client.key — 1 encrypted private key; none of the given passwords open it

UNPAIRED   corp-issuing-ca.crt — 2 certificates with no matching key here (all CA certificates — possibly a verify= trust bundle)
           svc-client.pem — 1 certificate with no matching key here

NOTES      cert-details.txt — human-readable dump; fingerprint matches svc-client.pem (not loadable)
           svc-client.csr — certificate request matching nothing here (issuance artifact, not loadable)

1 subdirectory not inventoried — point inventory() at them directly
```

Every file in the folder appears exactly once. Nothing was skipped for being
unrecognizable, unreadable, or shut — a file the report says nothing about is
the failure this exists to remove, so there is no such file.

Note what it already knows without a single password: `corp-issuing-ca.crt`
holds only CA certificates and is probably a trust bundle; `cert-details.txt`
is prose *about* `svc-client.pem` rather than anything loadable; the CSR is an
issuance artifact. Classification is done on content, never on the extension.

## Passwords, plural

A folder accumulated over time spans several passwords — the export password
and the passphrase on the key somebody extracted from it are routinely
different. So `inventory()` takes a list, and tries each against each
encrypted file:

```python
print(httpx_pki.inventory("./corp-export", passwords=[p12_password, key_password]))
```

```text
INVENTORY  corp-export — 7 files, 2 identities

IDENTITY   svc-client   RSA-2048   expires 2027-01-15
             bundle        corp.p12 (password #1)
             chain         corp-issuing-ca.crt
             → PKIClient("corp.p12", password=..., chain="corp-issuing-ca.crt")

IDENTITY   svc-client   RSA-2048   expires 2027-01-15
             certificate   svc-client.pem
             private key   svc-client.key (encrypted — opened with password #2)
             chain         corp-issuing-ca.crt
             same certificate as corp.p12
             → from_key_pair(certificate="svc-client.pem", private_key="svc-client.key", password=..., chain="corp-issuing-ca.crt")

LOCKED     old-2025.pem — 1 certificate, plus 1 encrypted private key none of the given passwords open

NOTES      cert-details.txt — human-readable dump; fingerprint matches corp.p12 (not loadable)
           svc-client.csr — certificate request for the key of corp.p12 (issuance artifact, not loadable)

1 subdirectory not inventoried — point inventory() at them directly
```

The folder holds **one** certificate reachable **two** ways, and the report
says so rather than presenting two mysteries: the second identity is marked
`same certificate as corp.p12`. Either call works; the `.p12` is one file
instead of two.

:::{important}
The report names passwords **by position** — `password #2` — and never repeats
a value. That is deliberate.
:::

`old-2025.pem` stays locked, and that is the last year's renewal nobody could
open. It is still named, still counted, and still on the list of things to ask
somebody about.

## What each section means

**`IDENTITY`** — a private key and its certificate, matched by public key, the
same rule the loaders use. One heading line (subject, key type, expiry), the
files it is made of, and the call that loads it. An expired certificate says
`EXPIRED 2026-01-15` in place of `expires`.

**`LOCKED`** — a file holding key material that none of your passwords opened.
A file that opened *in part* — a PEM whose certificate is readable and whose
key is not, which is what `openssl pkcs12 -out client.pem` writes — appears
here too, because the shut key is the part worth another password.

**`UNPAIRED`** — a certificate with no matching key in this folder, or a key
with no matching certificate. Not always a mystery: a file holding an
identity's issuer is annotated as an alternative `chain=` or `verify=` source,
and a file of nothing but CA certificates is called out as a probable trust
bundle.

**`NOTES`** — everything that is not loadable and not a half: CSRs, text
dumps, unrecognizable files, files too large to be certificate material, and
files that could not be read. CSRs and dumps are matched back to the file they
describe, by public key and by fingerprint respectively.

## From a shell

```console
$ python -m httpx_pki inventory ./corp-export
$ python -m httpx_pki inventory                    # the current directory
```

Passwords come from the environment, repeatably:

```console
$ python -m httpx_pki inventory ./corp-export \
      --password-env P12_PASSWORD --password-env KEY_PASSWORD
```

Anything still locked after that is prompted for, one file at a time, and each
prompt can be skipped with a blank line. A password typed for one file is
tried against all of them, since a folder's `.p12` and its extracted key
routinely share one.

There is deliberately no `--password` flag, for the same reason
[`explain`](inspecting-a-certificate.md#from-a-shell) does not have one: an
argument lands in shell history and in every process listing on the machine.

The command exits non-zero only when the folder yields **nothing loadable**.
Locked and unpaired files are the normal lint of such a folder, not a failure
of the inventory, so a directory with one usable identity and four mysteries
exits `0`.

## What it will not do

**It will not build a session.** A folder like this routinely holds several
identities, expired renewals, and a stray trust bundle, so silently choosing
one is precisely the mistake the report exists to prevent. It hands you the
call and lets you make it.

**It will not descend into subdirectories.** A CA export is flat. Whatever
else a subtree holds, crawling it uninvited is not this function's job — so
subdirectories are counted and named, and you point the tool at them yourself.
Symlinks to files *are* followed, under the name they wear in this folder:
somebody linked it in on purpose.

**It will not audit.** `inventory()` classifies and pairs. Once it names a
source, [`explain()`](inspecting-a-certificate.md#explaining-a-whole-configuration)
is the tool for what would stop that source working — validity, chain,
trust, key usage, and the problems that only show up on a handshake:

```console
$ python -m httpx_pki inventory ./corp-export     # which file, and how
$ python -m httpx_pki explain corp-export/corp.p12   # and what is wrong with it
```

**It will not touch the network**, or anything outside the directory you name.

## In code

`inventory()` returns a {class}`~httpx_pki.DirectoryInventory`. `print()` gives the report above; the attributes give the same thing as data:

```python
report = httpx_pki.inventory("./corp-export", passwords=[p12_password])

if not report.usable:
    raise SystemExit("nothing loadable in that folder")

for identity in report.identities:
    print(identity.info.common_name, identity.info.not_valid_after)
    print("   ", identity.suggestion)

for entry in report.locked:
    print("still need a password for", entry.name)
```

`identities` holds {class}`~httpx_pki.InventoryIdentity` objects — `info` is
the usual {class}`~httpx_pki.CertInfo`, and `bundle_file` or the
`certificate_file`/`key_file` pair names what to load. `files` carries every
file the inventory saw as an {class}`~httpx_pki.InventoryEntry`, whatever
became of it; `locked`, `unpaired`, and `notes` are the report's other
sections.

## Next steps

- [](loading-certificates.md) — making the call the report suggested
- [](inspecting-a-certificate.md) — `explain()`, for a source the inventory
  has named
- [](choosing-a-certificate.md) — when one of those files holds several
  identities
- [](server-trust.md) — what to do with the trust bundle it found
