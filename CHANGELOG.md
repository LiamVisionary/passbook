# Changelog

All notable changes to PassBook are recorded here. Dates are ISO-8601.

## [Unreleased]

### Sign-ins
- **OAuth grants are a thing PassBook understands** (`passbook oauth`). A grant
  knows which keys hold it, when it expires and how to renew — so a store stops
  seeing three unrelated strings where an account is.
- **The broker renews on read.** Anything asking for a grant's access token gets
  a live one; the broker refreshes, writes back and hands it over. The broker
  runs whenever a credential can be read at all, so a grant no longer dies
  because the app that created it is closed.
- `get_oauth_token` over MCP, so an agent never implements refresh.
- Several accounts per provider — `google:personal` and `google:work` coexist,
  each with its own store keys.
- Tokens live in the store under ordinary key names: sealed with everything
  else, held to the same audiences, in the same record. Only the grant's
  description sits beside it, readable on purpose.
- No vendor client id ships in the provider table, and a test enforces it.

### Agents
- **An MCP server** (`passbook mcp`). Any MCP client — and, through ACP's MCP
  passthrough, any ACP editor — learns on connect what this machine holds, what
  it may read, and how to ask. `list_credentials` returns names and groups and
  never values; `get_credential` returns exactly one, checked and recorded.
- The agent's name arrives as a claim in the handshake and is used for policy
  and the ledger, never as authentication. Documented as such.
- A copy-and-paste block in the README that sets a machine up end to end through
  whatever agent you already use.

### Organising a large store
- **Groups**, inferred from the names you already use, because tagging three
  hundred keys by hand never finishes. A family becomes a group once two keys
  share it; anything set by hand wins.
- **Audiences** — `all` (the default), `include`, or `exclude` — answering "who
  is this key for" rather than "how is this app handled". An audience is a bound
  that outranks every mode, unlock and approval.
- **`passbook matrix`**, every key against every agent that has actually asked,
  read out of the ledger rather than only the ones you configured.

### Fixed
- `write_policy` listed its sections literally and so dropped anything new: an
  audience was printed, written without, and gone on the next read. Both the
  read and write paths now carry sections they do not recognise, so an older
  PassBook sharing a store cannot delete a newer one's data.
- The MCP server enforces audiences itself. `passbook.request()` falls back to
  reading the file when no broker is running — right for a plaintext store on a
  machine with no daemon, and wrong at that door, where it would have handed an
  agent a key the owner had excluded.

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
