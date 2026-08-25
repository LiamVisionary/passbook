# PassBook, the app

A native window over the credential store this machine shares: which keys are
here, how each one is answered, who has borrowed them, and a tamper-evident
record of every read. Apple's Passwords app is the reference — a list you scan,
not a dashboard you study.

```bash
cd src-tauri && cargo tauri dev
```

## It is not a dependency

Nothing on this machine needs the app installed to use the store. An app that
vendors `passbook.py` reads it directly; the CLI works alone; a policy has no
force without the broker. This is the surface with the strongest guarantees, not
a gate in front of everything else — and there are tests in `packages/passbook`
that fail if that stops being true.

Approvals in particular are deliberately answerable from three places: here, the
CLI (`passbook approve`), and the studio. A product that is the sole approver has
made itself a prerequisite for every other app's credentials.

## It holds no logic

Every question and every change goes through the PassBook CLI — the same code
path a script or a terminal uses. Reimplementing any of it in Rust would create
a second source of truth about who may read what, and the first time the two
disagreed the disagreement would be invisible.

That makes the CLI this app's API, with one sharp edge: a non-zero exit is shown
to the user as a failure, so a command that does its job and then dies printing
the result looks like a broken feature. `tests/test_passbook_app_contract.py`
pins the exit code and the shape of every call this app makes.

Values never cross the boundary. `passbook state` returns key names, modes,
unlocks and receipts; the store's contents are read by the process that needs
them, never by a window someone might be screen-sharing. Adding a key is the one
action carrying a secret, and it goes to the CLI on **stdin** — an argument would
be visible to `ps` for as long as the process lived.

## Signing

It cannot be distributed yet: this machine has no Developer ID Application
certificate. See `packages/passbook/SIGNING.md`, which also explains why this
app — being a bundle — is the only PassBook surface whose identity can ever be
*enforced* rather than merely claimed.
