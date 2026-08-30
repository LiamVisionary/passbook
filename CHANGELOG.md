# Changelog

All notable changes to PassBook are recorded here. Dates are ISO-8601.

## [1.3.0] — 2026-08-30

### A credential can be used without ever being shown

Every surface here answered one question: may this caller HAVE this value. For
an agent that is the wrong question. An agent writes what it observes into a
transcript that is stored, replayed and sent to a model — so a value it reads
has left the machine whatever it intended, and putting a policy in front of the
read does not change that. It makes the copy authorised.

Three holes were found by testing rather than reasoning, and each is closed:

- `passbook get` printed the value. `passbook reveal` printed it and was, by
  design, not policy-gated at all — the same key that `get --app x` blocked
  under an `ask` rule came back instantly from `reveal`.
- `passbook run` handed the child **every** key in the store, not the ones it
  needed, and its output was never filtered.
- the MCP `get_credential` tool put values directly into an agent's context.

**The rule is now provenance, not identity.** Values go only into processes the
broker starts itself. Identity could never carry this: a script, a CLI and an
agent all run through the same interpreter and present the same signature, as
`passbook_peer` has always said. "Did this process descend from a spawn I
performed, holding a key set I chose?" has an exact answer.

- **`passbook run`** now streams through the broker when a guarded key is
  involved or reads are sealed. The child gets the real value; the output comes
  back with it removed. `--only NAME` hands over named keys instead of all 301.
- **`run_with_credentials`** and **`proxy_request`** replace reading, for agents.
  The first runs a command holding the keys; the second fills `{{KEY_NAME}}`
  into one HTTPS request. Both return results, never values.
- **`passbook guard NAME --to host --into 'cmd *'`** binds a key to where it may
  go. A guarded key is never printed — not by `get`, not by `reveal`, not to an
  agent — and is refused for any command or host outside its binding.
- **`passbook policy --reads sealed`** applies that to every key at once.
- **`passbook grants`** shows what holds credentials right now.
- A new `use` row in the record, distinct from `read`, because a row saying
  `read` would assert the one thing that did not happen.

Redaction covers the raw value, all three base64 alignments, hex, URL and JSON
escaping — and holds across chunk boundaries, so a secret split by a pipe does
not pass through as two clean halves. Two real bugs were caught proving it: the
first version missed `echo $S | base64` entirely (the newline shifts the tail),
and the second emitted a form straddling its own buffer cut before redacting it.

### The debugger hole, which turned out not to need custom code

The caveat above was written as "a caller willing to write custom code could
read a value out of process memory". Measured, it cost one command:

    $ lldb -p <broker pid>
    Process 51698 stopped

`lldb` ships with macOS and carries the debugger entitlement, so it attaches to
an unsigned same-uid process without ceremony — the broker holding the data key,
and every child holding a credential in its environment.

- **`ptrace(PT_DENY_ATTACH)`** in the broker before it opens its socket, and in
  every spawned child between fork and exec. `lldb` now gets `attach failed` and
  the target survives. Verified against `lldb` in the test suite, with a control
  case, because a denied attach on a machine where nothing attaches proves
  nothing. Linux gets `prctl(PR_SET_DUMPABLE, 0)`; Windows says it cannot.
- The flag **survives exec**, which is why a child works at all — `wrangler` and
  `npm` are protected without knowing PassBook exists.
- **`passbook harden`** reports what is actually protected. **`--install`**
  locks PassBook's installed tree **in place** — `chown -R root:wheel` — and
  starts the broker from a root-owned LaunchAgent, closing the last user-space
  gap: PassBook's own code being writable by anything running as you. Updating
  it needs root afterwards, which for the code holding a machine's credentials
  is the right way round rather than a cost; `passbook update` says so instead
  of surfacing a bare permission error from `uv`.

  This first copied PassBook to a root-owned `/usr/local/libexec` and ran the
  daemon from the copy. That was wrong, and worth recording: `passbook update`
  runs `uv tool install --force` into the *user's* tree, so the daemon would
  have gone on running whatever it was installed with — indefinitely, silently,
  and invisibly to a version check reading the copy the user updated. A
  credential broker quietly executing last month's redactor is a worse failure
  than the writable directory it was meant to fix. One tree, locked where it is.

A LaunchAgent rather than the service account first sketched here. A daemon
under its own uid has no login keychain, no GUI session for Touch ID, and no
read access to a store in the user's home — and a store it owned could strand
the machine, which this project's spec explicitly forbids a policy from doing.
The Agent runs as you and keeps all three, while the code and the thing that
starts it stop being yours to edit.

### Approved agents, so `always` does not have to mean everyone

`always` for everything is the setting people actually run, because `ask` for
everything asks forty times a day and gets switched off within a week. The
useful middle is a default of `ask` with a named set that does not have to.

- **`passbook approved`** lists every agent this machine can name and what each
  one gets. Three sources: runtimes installed on the disk (`passbook brief`
  already knows fifteen), names that have actually asked (from the ledger, the
  only source reflecting what happens rather than what is installed), and fleet
  peers over Tailscale. Every source is optional — a machine with none of them
  shows an empty list and the command still works.
- **`--add` / `--remove`**, and **`--only`** to make unapproved agents ask.
  An automation that runs at 3am keeps running; a coding agent that has never
  asked for anything has to check in.

Two things this is careful to say rather than imply. An agent's name is a claim
— the same claim `caller()` has always documented — so the list contains an
accident and makes an unfamiliar caller visible; it does not stop something that
decides to call itself one of these. And a policy is enforced *by* the broker,
so on a plaintext store with reads open the list is written down and not in the
path: `passbook run` resolves from the file and asks nobody. That was found by
running it, not by reading it — an unapproved agent ran unattended against a
perfectly correct policy — and the command now says **NOT ENFORCED** with the
two ways to fix it.

### The shortest way in was neither of those

Refusing a debugger and owning the code both assume an attacker has to subvert
something. On the machine this was written, nothing needed subverting:

    $ security find-generic-password -s hive-env-vault -w
    <44 bytes of vault key material>

That is the **device factor** — an opt-in that exists so a headless job can open
the vault with nobody there to type a password. `passbook_keystore` has always
said what it costs, in its own docstring: "anything running as you can open the
vault." It was on, and it was the whole attack.

- **`passbook harden`** now checks for it and reports it first, above the
  debugger and the code, because it is the cheapest of the three to exploit.
- **`--keychain-prompt`** rewrites the item with an empty trusted-application
  list, so every read asks a person. An agent cannot answer that prompt.

It is offered, never applied. The prompt breaks the exact thing the device
factor is for, and only the owner knows whether anything here runs unattended —
a watchdog that silently stops surviving reboots is a worse outcome than the
exposure it was traded for.

### Known

- **Root defeats all of it.** That is the ceiling of any user-space mechanism.
- **`--install` was not verified end to end.** It needs root, which the author
  could not exercise from the session that wrote it; the unprivileged paths,
  the plan output and the refusal are tested, the privileged run is not.
- **A command can still send what it was given anywhere**, unless the key is
  guarded. Redaction scrubs our output, not the network.
- **Values under six characters cannot be redacted** from output without
  wrecking it. This is reported per key rather than assumed.
- `reads` defaults to `open`, so upgrading changes nothing until you seal it.

## [1.2.0] — 2026-08-29

### The agents on this machine are told PassBook is here

PassBook installed 46 commands and an MCP server and told nobody. An agent on a
PassBook machine knew only whatever some other installer had taught it, which on
a HivemindOS box meant `hive-env-check` and `hive-env-run` — both of which work,
and neither of which knows the word "sealed".

That gap looked like a PassBook bug from the outside. On a sealed store
`hive-env-run` correctly DROPS the values it cannot open, so an agent asking
after a key saw it as missing, said so, and sometimes offered to add it again —
over a credential that was there the whole time behind a locked vault.

- **`passbook brief`** writes a short block into the context file each coding
  agent already reads: what the store is, how to ask, never print a value, and
  the three states that matter — absent (`passbook add`), sealed with the vault
  locked (`passbook signin`), and refused by policy (`passbook umbrella`).
  Reporting a sealed or refused key as missing is the mistake it exists to stop.
- **Fifteen runtimes**: Claude Code, Codex, Gemini CLI, Amp, opencode, Cursor,
  Windsurf, Cline, Qwen, Continue, Goose, Crush, Hermes, OpenClaw and AEON.
  Written only where a runtime has left a footprint under `$HOME`.
- **The MCP server is registered** with the nine that keep an editable server
  list, so an agent gets `list_credentials`, `check_credentials`,
  `get_credential`, `vault_status` and the OAuth pair as tools rather than
  commands to shell out to.
- **However PassBook arrived.** `passbook install` and `install.sh` do it, the
  desktop app does it in its setup hook, and — because `uv tool install` puts 46
  commands on PATH and executes none of them — the first command anybody types
  does it too. That notice goes to stderr, never stdout: `passbook get` prints
  `KEY=value` and people pipe it into `eval`.
- `brief remove` takes it back out. `PASSBOOK_NO_BRIEF=1` is the escape hatch.
  The broker and the MCP server never brief, because a daemon editing
  `~/.claude/CLAUDE.md` after the terminal closed is not a thing to ship.

Every one of these files belongs to another tool and several already carry a
HivemindOS block, so the text lives between markers, only that span is
rewritten, a backup is left beside the original, and the write is atomic.

There is no `~/AGENTS.md`, which is worth saying because it is the obvious
guess. AGENTS.md is a real standard and it is PROJECT scoped — repo root,
nested files for subprojects, nearest wins. Global context is per-runtime
convention; the nearest thing to a universal one is Amp's `~/.config/AGENTS.md`.

### Known

Six of the fifteen runtimes were verified on a machine that has them. The other
nine come from documentation: their context paths are low risk, but if one keeps
its MCP servers in a shape other than a root `mcpServers` object, registration
writes a key that runtime ignores. Nothing breaks — the write is additive and
backed up — it simply would not take effect.

## [1.1.1] — 2026-08-28

### `passbook update`, and knowing what you are running

PassBook installs from a git URL, which resolves once and then never moves.
HivemindOS's setup script made that permanent: it returned the moment a
`passbook` was on PATH, so a machine kept the version it was set up with and
every later update confirmed it was "already installed".

That is how a dead end fixed before 1.0.0 was still being hit weeks after the
fix shipped — `add` on a sealed store sending you to `signin`, which refused
because no broker was running. Nothing on the machine could say what it was
running, and nothing could move it.

- **`passbook update`** moves this copy to the newest release, pinned to the
  tag rather than the branch: an update that lands on an untested commit is
  worse than no update. `--check` reports without installing; `--json` for
  scripts.
- **`passbook --version`**, which costs nothing — no network, no store, no
  policy. A copy that cannot name itself cannot be diagnosed.
- The upgrade asks the interpreter whether it has pip rather than assuming.
  `uv venv` creates environments without it, so the obvious
  `python -m pip install --upgrade` failed on exactly the machines most likely
  to have uv; it falls back to `uv pip` there.
- Versions compare as numbers, so `1.10.0` is newer than `1.9.0` rather than
  older.

A copy older than this release has no `update` command to run, so it cannot
lift itself. The fix for those is a reinstall, or a HivemindOS setup run:
`install_passbook` refreshes every time now, and keeps the working copy when
the refresh cannot reach the network.

## [1.1.0] — 2026-08-28

### Umbrellas

An umbrella covers projects and holds keys, so one credential serves several
checkouts without going machine-wide.

```
ai apps (umbrella, tags: llm, media)
  ├── ami          (project)
  ├── hivemindos   (project)
  └── ansem        (project)
```

- **`passbook umbrella`** — `new`, `add`/`remove` keys, `cover`/`uncover`
  projects, `reach`, `show-agents`, `open`, `close`, `tag`, `delete`.
- **Closed from the moment it exists**, not from the moment somebody finishes
  filling it in — that window is exactly when a person is interrupted. An
  umbrella covering nothing grants nothing and says so, rather than presenting
  as a key that has gone missing.
- **Reach and visibility are two switches.** An umbrella an agent can see but
  may not use teaches it "there is a media umbrella and it is not mine", which
  one boolean could not express.
- **Deliberately not called a group.** Groups are inferred from key names so a
  large store can be read, and every key falls into one — gating on that would
  put a whole store behind rules nobody wrote. A key's group arranges a listing;
  a key's umbrella bounds a read. `passbook group` is unchanged and still
  decides nothing.
- **A contradiction is reported when the rule is written.** An umbrella covering
  a project whose key is scoped to another workspace, or fenced by a per-key
  rule, reads as a grant and behaves as a refusal. It now says so at the
  keyboard instead of surfacing later as an outage.
- Resolved at `decide_key`, the one place scope, projects and audience already
  meet, so the broker, the MCP server and `passbook matrix` inherit it.

### Add to PassBook

- A platform's API page can hand the key it just minted straight to the app.
  The value travels in a loopback request body — never in a URL or an argv — and
  the window shows which keys, which workspace, and asks for approval before
  anything is written.
- The embed, and a block to paste into an agent that sets it up for you, are in
  the README.

### Importing a `.env`

- `passbook import` gained `--dry-run --json`, `--only` and `--as`, and the
  window gained a drop target. Names are listed without values; a clash offers
  replace or keep-both, and the suggested name climbs (`KEY_2`, `KEY_3`) rather
  than nesting.

### Also

- A documentation site at `docs/`.
- Refusals say which of three things happened — refused, encrypted, or absent —
  because "sign in" over a key that was refused by policy sends you to a repair
  that fixes nothing.
- The modules moved to `src/`, so a test can no longer import the working copy
  in place of a broken install.

## [1.0.0] — 2026-08-28

First public release.

### Windows

Windows was a build target rather than a platform. A signed installer was
produced for it and nothing that came out of that installer worked.

- **The app carries the CLI it depends on.** The window holds no logic of its
  own and asks the command line everything, and the command line was never
  shipped with it. On Windows, which has no system Python, a fresh install
  opened onto "Could not run PassBook: program not found" and the only
  documented setup was `install.sh`, a shell script Windows cannot run. The
  installer now brings a private Python, the modules, and every `passbook`
  command, and puts them on PATH.
- **The broker exists on Windows.** It was a Unix socket or nothing, so
  `passbook signin` raised `AttributeError` on `socket.AF_UNIX` before it began.
  With no broker there is nowhere to hold a data key, which meant a sealed
  store could not be opened on Windows by any route. There is a named pipe
  there now, restricted by a DACL to the account that created it, and it names
  the calling process the way the socket did.
- **The broker outlives the command that started it.** `start_new_session` is
  POSIX, and Windows accepts it and does nothing, so a sign-in lasted exactly
  as long as the terminal that asked for one.
- **`passbook install` installs something Windows can run.** It wrote
  `#!/bin/sh` files with no extension into `~/.local/bin`, which is on nobody's
  PATH there. Now it writes `.cmd` shims into `%LOCALAPPDATA%\PassBook\bin`.
- **The application binary is signed, not only the installer.** Signing ran on
  the bundler's output, by which point the binary was already sealed inside the
  installer. It is signed before it is wrapped, and the release now checks both.
- The publisher reads `Rizzma, Inc.` rather than `hivemindos`, which Windows had
  been deriving from the bundle identifier while the signature said otherwise.
- The app looks for `USERPROFILE` as well as `HOME`, which Windows does not set.
- Broker tests no longer skip themselves on Windows. That skip is why all of
  the above shipped green.

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

### The store
- One credential store per machine at `$HIVE_HOME`, else `~/.hivemindos/.env`,
  resolved the same way by every app that opts in (`docs/SPEC.md`).
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
