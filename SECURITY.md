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

**The stale-copy record holds hashes of values.** To find old copies of a replaced key by value
(`passbook stale`), each machine keeps `retired.json` beside the store. It is owner-only, never synced, and holds
a salted HMAC of each credential-shaped value (no whitespace or `@`, and at least 24 characters of two kinds or
16 of three), with the salt in the same file. Hashing all of them, not only the replaced ones, is what lets the
next look notice a value replaced on another machine or by hand. For a randomly generated key, a hash next to its
salt reveals nothing usable. For a guessable value that still fits that shape, it is an offline check of a guess,
and it shows which keys share a value. Delete the file to forget all of it; the next look starts again.

**An offline attack on a weak vault password.** The vault file is designed to be
copied around; `scrypt` at n=2^16 is what stands between a copied file and a
guessed password. Choose accordingly.

## Supported versions

The latest released version. This project has not yet reached the point of
backporting fixes.
