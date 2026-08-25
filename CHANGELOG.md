# Changelog

All notable changes to PassBook are recorded here. Dates are ISO-8601.

## [1.0.0] — 2026-08-26

First public release.

### The store
- One credential store per machine at `$HIVE_HOME`, else `~/.hivemindos/.env`,
  resolved the same way by every app that opts in (`SPEC.md`).
- `ensure()` provisions or links in one idempotent call; `request()` is the
  narrow door that names what it needs and leaves a receipt.

### Encryption and sign-in
- **Vault (v2)** — values are sealed under a per-profile data key that is never
  written down. The key is wrapped by one or more factors: a password
  (`hashlib.scrypt`), a passkey (WebAuthn PRF), or optionally the machine's own
  keystore. Changing a password rewraps 32 bytes rather than re-encrypting every
  value.
- The data key lives only inside a signed-in broker process. Callers receive
  values, never the key, so a compromised client cannot decrypt the store on its
  own or pass the key on.
- `passbook secure` does profile, seal, broker and sign-in in one prompt.
- `passbook unseal` puts everything back. An encryption you cannot reverse is
  one nobody turns on.
- Values behind a framework's public prefix (`NEXT_PUBLIC_`, `VITE_`,
  `REACT_APP_`, `PUBLIC_`, `EXPO_PUBLIC_`, `GATSBY_`, `NUXT_PUBLIC_`) are left
  readable by default: a build inlines them into a browser bundle long before
  anybody could sign in, so sealing one protects nothing and breaks the build.

### Access control and audit
- Per-app, per-key modes: `always`, `ask`, `window`, `never`, with time-boxed
  unlocks.
- A broker that serves every request over a `0600` socket and stamps it.
- Hash-chained access receipts, wire-compatible with GitLawb proof chains.
- On macOS, a caller that is a signed bundle can be identified by asking the
  kernel. The verdict is three-valued — `verified`, `unsigned`, `unknown` — and
  an `unknown` is never treated as a `verified`.

### Portability
- The vault is `hashlib` and AES-GCM only, so it opens the same way on macOS,
  Windows and Linux. OS keystores are an optional convenience, never the floor.
