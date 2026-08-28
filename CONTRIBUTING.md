# Contributing

## The shape of the thing

PassBook is a **standard first** and an implementation second. `docs/SPEC.md` is the
contract; `passbook.py` and `passbook.mjs` are two implementations of it that
must stay byte-compatible with each other. A change that makes them disagree is
a bug in whichever one moved.

Two rules follow from that, and they are the ones most likely to trip you up:

1. **`passbook.py` has no dependencies and imports nothing from its host.** It
   is meant to be copied into a project as a single file. Everything optional —
   encryption, the broker, linking, the ledger — lives in a separate module that
   `passbook.py` imports lazily and works without.

2. **Nothing else may become required.** If a change means a machine now needs a
   daemon running, a package installed, or a key present in order to read a
   credential it could read before, that change is wrong regardless of what it
   adds.

## Setup

```bash
python -m pip install pytest cryptography
python -m pytest tests -q
```

That is the whole thing. There is no build step.

## Tests

Every behavioural claim in this repository has a test, and the tests are written
to say *why* a behaviour exists rather than restate what the code does. A few
worth reading before you add more:

- `tests/test_passbook_vault.py` — the headline property is the first test: a
  sealed store, read by someone without a factor, yields nothing.
- `tests/test_passbook_vault_broker.py` — the same claim end to end, with a real
  broker over a real store.
- `tests/test_passbook_app_contract.py` — the CLI *is* the desktop app's API, so
  exit codes are part of the contract.

If you find a bug, the fix comes with a test that fails without it. Several
tests here exist because something shipped broken; the comment above them says
what, which is worth more than a ticket number.

## What tends to get rejected

- Adding a required dependency to `passbook.py`.
- Making an optional feature load-bearing.
- Widening what a status surface returns to include values. Every diagnostic in
  this project returns key **names**; `reveal` is the single, deliberate
  exception and it stamps a distinct row.
- Security claims the code does not support. If something is tamper-*evident*,
  do not call it tamper-proof. The README has a "What it does not claim"
  section for a reason.

## Commits

Explain why, not what — the diff already says what. If a change fixes something
that shipped, say what it broke.
