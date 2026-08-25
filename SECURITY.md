# Security policy

## Reporting a vulnerability

Please use GitHub's [private vulnerability reporting][pvr] on this repository
rather than opening a public issue. That gives us a private thread and a CVE if
one is warranted.

[pvr]: https://github.com/LiamVisionary/passbook/security/advisories/new

Include what you did, what happened, and what you expected. A proof of concept
helps enormously; a working exploit is not required.

We will acknowledge within a week and keep you updated as we work. If you would
like credit in the advisory, say so and name how you want to be listed.

## What is in scope

Anything that lets code read a credential it should not, that weakens the
encryption, or that makes an access invisible in the ledger. Concretely:

- opening a sealed store without a factor
- extracting the data key from a running broker
- getting the broker to serve a key its policy forbids
- forging, editing or truncating a row in the access chain without detection
- a `verified` verdict from `passbook_peer` for code that is not signed

## What is out of scope, by design

These are documented limits, not bugs. Reporting them is welcome as a
documentation issue, but they will not be treated as vulnerabilities.

**Code running as you can read what you can read.** While the vault is open, any
process running under your account can ask the broker for a key, exactly as it
could have read the plaintext file. The broker makes that *recorded and
policy-checked*, not impossible. Preventing it needs the operating system to
vouch for a caller's identity, which `passbook_peer` does only for signed
bundles on macOS.

**Key names are not secret.** They sit in the clear next to their ciphertext, so
that a locked machine can still say what it holds instead of claiming it is
empty. If a key's *name* is sensitive, do not put it in a shared store.

**A device factor is weaker on purpose.** It hands the opening key to the OS
keystore so unattended jobs can start. Anything running as you can then open the
vault without a password. That is the trade it exists to make, and it is opt-in.

**Public-prefix values are left readable.** `NEXT_PUBLIC_*` and friends are
compiled into browser bundles by the frameworks that define them. They are
public before this project touches them.

**An offline attack on a weak vault password.** The vault file is designed to be
copied around; `scrypt` at n=2^16 is what stands between a copied file and a
guessed password. Choose accordingly.

## Supported versions

The latest released version. This project has not yet reached the point of
backporting fixes.
