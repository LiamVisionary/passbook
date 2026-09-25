# Changelog

All notable changes to PassBook are recorded here. Dates are ISO-8601.

## [Unreleased]

### `passbook run` no longer calls an open vault locked

- **The false alarm.** `run --only NAME` decided whether the vault was locked
  after `--only` had narrowed the environment. A name the store does not hold,
  such as a typo or `--only A,B` (read as one key called "A,B"), left nothing
  resolved. `run` then printed "The credential store is encrypted and locked …
  Sign in first: passbook signin" on a signed-in machine and ran the command
  with neither key. The command failed against its service, and agents that
  saw both messages told the owner to sign in again, about ten times across
  sessions. The lock is now judged on the whole store before `--only` applies.
- **`--only A,B` is two keys**, the same as `--only A --only B`.
- **Names are named.** A requested key the store lacks gets "Not in the store:
  NAME. Nothing is locked". A requested key that is present but encrypted and
  unreadable gets its own line with the sign-in hint. A store that really is
  shut still says locked.
- **The brief has a fifth state**, "rejected by its service": set and
  delivered, but the service answers 401 or "invalid token". The fix is a new
  key, not a sign-in. It also says to ask for `passbook signin` only when
  `passbook vault` says locked. The brief's size cap went from 2750 to 3000 for
  it.

## [1.10.0] — 2026-09-25

### Connect GitHub and send keys to it as secrets

- **`passbook github connect`** (or `passbook connect github`) connects an
  account three ways, none of them silent. You can copy your `gh` login after a
  yes, paste a token (hidden prompt, or `--token-stdin`), or use a device-flow
  code with your own OAuth app's client id. The token is checked against GitHub
  before anything is saved. It is stored as `PASSBOOK_GITHUB_TOKEN` (encrypted
  on a sealed store) and the connection is listed beside the other sign-ins.
  `status`, `disconnect`. On a machine that seals reads, connecting binds the
  token to api.github.com, so lookups go through the broker's proxy.
- **`passbook github push`** asks for what it isn't told: keys, repository or
  organisation, environment, and each secret's name (defaults to the key's
  name). It checks GitHub's naming rules and shows which names already exist
  and when they were updated. Replacing one needs a yes or `--overwrite`. Then
  it shows a review and sends. `--repo/--env/--org/--visibility/--name KEY=NAME`
  do the same by flags; `--plan-stdin` is the window's form.
- **`passbook push KEY --to gh:owner/repo[:NAME] [--env E]`** and
  `gh-org:ORG[:NAME] --visibility …` go through the connection when there is one
  (and through `gh` as before when there isn't). Each value is sealed on this
  machine to the target's public key, a libsodium sealed box built from
  `cryptography`'s X25519 and Poly1305 plus XSalsa20. It matches libsodium byte
  for byte. The push is recorded under the chosen name, so `rotate` sends there
  again.
- **The window**: a GitHub group on Sign-ins (connect, disconnect), and **Send to
  GitHub** on selected keys. It goes connect, place, names (with replace
  ticks), review, and shows a result per key. Values never enter the page, and
  a pasted token goes straight to the CLI's stdin.

### Fixed

- Error text in the window's sheets (a request, an import, the sign-in gate)
  used colour variables that were never defined, so errors showed in plain
  ink. They are red now.

## [1.9.0] — 2026-09-25

### PassBook remembers where each key went, and rotates it everywhere

`passbook services` could already push a replaced key to every service holding
it, but the list was empty on the machine it was built for. The only way to
fill it was `passbook services attach`, typed by hand after the fact. Keys were
reaching Workers and GitHub through `passbook run` the whole time, and PassBook
threw that information away.

- **`passbook run` records pushes it recognises.** With `--only KEY`,
  `wrangler secret put` / `versions secret put` / `secret bulk` /
  `pages secret put` / `secrets-store secret create`, `gh secret set`,
  `gh variable set` (flagged as not secret), `vercel env add` and
  `fly secrets set` are recorded after the command exits 0, directly or inside
  `sh -c`. When it can't tell which key went where, nothing is recorded and the
  run says so. The recorded command pushes on stdin or in `$KEY`, never on
  argv. The worker comes from `wrangler.toml`, the repo from the git remote.
- **`passbook run --used-in WHERE [--push-command CMD --push-stdin]`** records
  a place or a push for a script PassBook can't read.
- **`passbook push KEY --to SINK`** pushes and records in one step
  (`wrangler:`, `wrangler-pages:`, `gh:`, `gh-env:`, `gh-org:`, `gh-var:`,
  `vercel:`, `fly:`, `cf-secrets-store:`). Without `--to` it pushes to
  everywhere already recorded. Cloudflare Secrets Store goes through the new
  `passbook sink cf-secrets-store`, which finds the secret by name over the API.
- **`passbook used-in KEY add|remove|list`** notes places nothing can push to.
  They show in `services list`, `history KEY` and `rotate`.
- **`passbook rotate KEY`** takes the new value (hidden, asked twice, or
  `--stdin`), replaces it, pushes to every recorded service, prints a result per
  service and lists the places to update by hand. The previous value is kept,
  as the store held it (ciphertext on a sealed store), until `--confirm`.
  `--rollback` restores it and pushes it back to every service that got the new
  one.
- Every push is a `use` row in the access record, named after the service.
- MCP: `list_services` (names and commands, no values) and `record_used_in` (a
  place, never a command: a command recorded by an agent would run during the
  owner's next rotation holding the new value). A successful
  `run_with_credentials` is recorded the same way `run` is.

### Fixed in the existing push path

- **A stale environment was pushed over the new value.** `services update` and
  `retry` read the value with the process environment winning. An agent started
  by `passbook run` holds the launch-time value, and pushed that. They now read
  the store.
- **On a machine that seals reads, pushes said the key "is not set here".** It
  was set and encrypted: the wrong one of the four states, and the wrong fix. A
  push now re-runs under a grant for that one key, the way sync does.
- **The record could be wiped.** It was read through the environment (a
  `passbook run` child carries a launch-time copy), and a sealed copy read as
  empty. Either way, the next attach wrote a one-entry record over the whole
  thing. It is now read from the store files, and a record this process cannot
  open refuses the change and names the fix. `seal` and the broker's
  seal-on-write leave both records readable. They hold names and commands, not
  values, and no longer count as readable secrets in `status`.
- **Changes to the record never replicated.** It was written without the age
  sync compares, and sync never overwrites a copy of unknown age. So the first
  version reached other machines and nothing after it did. Writes are dated now.
- **`add --replace --update-services all` exited 0 when a push failed.** A
  script read that as "rotated everywhere". It now exits 1.
- **Correcting a failed service's command made `retry` forget it.** The service
  still held the old value. A failed status now survives the correction.
- **Pushes that ran for minutes wrote back an old copy of the record,** undoing
  anything recorded meanwhile. The record is re-read before the results go in.
- **Re-running under a grant from a checkout failed** with "Exec format error":
  `passbook_cli.py` is executable but has no interpreter line. It now runs
  through Python.

Service labels may now contain `:` `/` `@` `+` (`github:owner/repo@production`).
Leading slashes, `..` and shell characters are still refused.

### The brief tells agents not to list process environments

`passbook run` hands secrets to child processes through their environment, and
other processes of the same user can read it. The text written into agents'
instructions now says never to use `ps e`, `ps -E`, `ps eww` or
`/proc/*/environ`, and to use `pgrep -f` for pids. Agents pick up the new text
the next time any `passbook` command runs.

## [1.8.5] — 2026-09-24

### The key list refreshes while you search

The window stopped refreshing whenever a text field had the caret, so it would
not wipe half-typed text, and the search box counted as one. A key added while
the caret sat in "Search keys" was searched for against a list from before it
existed, and the search said there was nothing. The list now keeps refreshing
while you search (your text, caret and focus stay put), and while you type in
any other field the data still refreshes; only the repaint waits.

## [1.8.4] — 2026-09-24

### A lone key from a well-known vendor gets its own heading

A single `ANTHROPIC_API_KEY` was filed under "Ungrouped", a pile of 72 keys at
the bottom of the list, because a family only became a group once two keys
shared it. It looked as if the key had not been saved. Well-known vendors
(Anthropic, OpenAI, OpenRouter, Stripe and others) now keep their own heading
with one key; an unknown one-off prefix still collects under "Ungrouped".
OpenRouter and DeepSeek headings are spelled the way those vendors write them.

## [1.8.3] — 2026-09-24

### Every password prompt shows bullets, or says why it cannot

- `passbook link web` asked for the workspace password with the stdlib prompt,
  which echoes nothing. It now shows a bullet per character, like `passbook add`
  and `passbook signin` (bullets since 1.8.0).
- Where bullets cannot be drawn (input is not a terminal, or the terminal will
  not leave line mode), the prompt now says `(input hidden)` instead of showing
  nothing and looking hung.

## [1.8.2] — 2026-09-24

### A workspace without a password is not offered for a web link

Linking a browser is confirmed with the workspace's password. A workspace that
has none was still listed, and choosing it could only fail as "The password was
not accepted". It now shows as "(no password)" and cannot be picked, the window
says so when no workspace can be linked, `passbook link web` leaves it out, and
a request for one is refused as `workspace-unprotected` before anything is sent.

### A broker left over from before an update is named, not "could not be linked"

`passbook update` replaces the files, not the broker already running from them.
A broker started under 1.7.1 answers app connections but has no web links, so it
refused a link from HivemindOS on the web as "not connected", and the app could
only say "This browser could not be linked".

- A web link now checks the broker offers web links before sending the request,
  and says to run `passbook broker restart` when it does not.
- The broker reports its version, and `passbook update` says when the one still
  running is older than what it just installed.

## [1.8.1] — 2026-09-24

### The app no longer piles up `passbook state` processes

`passbook state` read the whole access record several times to show its last
rows and each key's usage. The record only grows (one machine's reached 1.2GB in
four weeks), so a call took 83 seconds, and the app starts one every five
seconds. About a dozen ran at once, each slowing the others down, and a link
from HivemindOS on the web waited behind them.

- `read_stamps` reads backwards from the end, so it costs the rows asked for,
  not the size of the record.
- Usage per key is checkpointed next to the record
  (`credential-access-usage.json`, owner-only): later calls fold in only the rows
  appended since. A record that no longer matches the checkpoint is counted
  again from the start. Counts now cover the whole record, not the newest
  100,000 rows.
- The app polls once at a time: a tick is skipped while the last one is still
  running.

On that machine `passbook state` went from 83 seconds to about 1.2.

## [1.8.0] — 2026-09-24

### Connected apps can list every workspace, by name

`credential-names` now also answers `workspaceStores`: each workspace's id, its
label, the names of the keys it holds, and whether it is the one the app is
connected to. Values never leave. HivemindOS uses this to show every PassBook
workspace next to its own. The fields that were already there are unchanged,
so older apps see the same answer as before.

### HivemindOS on the web links to a workspace

A browser on hivemindos.app can now hold a workspace's keys. It links the way a
second machine does, with the same protocol (`passbook_link`), so nothing about
what a link is or promises changed:

- The browser makes its own device identity (WebCrypto, non-extractable keys)
  and a pairing token, registers it with the HivemindOS relay, and opens
  `passbook://link?request=<id>&relay=<origin>`.
- PassBook shows who is asking and the browser's code. Linking needs the
  workspace password and a tick that the codes match: the fingerprint check, as
  its own step. The browser shows PassBook's code back when it is done.
- The browser receives every key in the chosen workspace, sealed to it. While
  the workspace is open here, the broker re-seals it every 15 minutes, so a key
  added or changed reaches the browser on its next visit. A locked workspace is
  skipped, never forced open.
- The relay carries a public token one way and an envelope it cannot open the
  other. PassBook contacts only relays on an allowlist (`PASSBOOK_WEB_RELAYS`
  adds more). A browser accepts envelopes only from the PassBook it linked with.
- Unlinking in HivemindOS or with `passbook link web-unlink` stops the next
  envelope, not the last one: keys already sent stay with that browser.

Terminal: `passbook link web <link>`, `web-list`, `web-sync`, `web-unlink`.
Window: the `passbook://link` sheet (`app/ui/weblink.js`, `weblink.rs`).
Tests: `tests/test_passbook_web_link.py` (password and code both required
before anything is sent; the real `accept` opens every envelope; sync on open,
skip on locked, stop on unlink; foreign relays refused). The browser half is
proven against this implementation from the HivemindOS side
(`scripts/test-passbook-web-link-interop.mts`).

### A service can keep one key while the vault is locked

On 2026-09-23 the vault was locked after the broker restarted. Every overnight
service on the machine lost its X credential at once: three study arms stopped
polling for ten hours and a watcher got 401s. The only way to prevent that was
`passbook vault --stay-open on`, which lets anything running as you open the
whole vault with nobody present. Most services need one key, not all of them.

`passbook standing add KEY --app NAME` grants exactly that, and asks for the
vault password because it widens access. The key's current value is sealed a
second time, under an escrow key in the OS keystore (or `PASSBOOK_STANDING_KEY`
where there is none), and written to `standing.json`. When a request for a
sealed key arrives while the vault is locked, and the asking app is on that
key's list, the broker opens the escrow copy. It does this after the same
policy, guard and pin checks every read goes through. `passbook standing` lists
what is kept and whether it still matches the store, and `passbook standing
remove` takes access away.

The escrow records a digest of the store's own sealed value. A key that has
changed since it was kept is refused rather than served stale, and it heals
itself: any read with the vault open re-seals the new value, and a sign-in
refreshes every kept key at once. A key removed from the store stops being
served. Names that any unnamed caller gets (`passbook-run`, `unknown`, `*`) are
refused. The ledger gains `standing` for a use while locked, and `keep` and
`release` for grants and removals, each recorded against the app. The window
has words for all three.

`passbook run --only KEY` now asks the broker for only the keys it names. It
used to request every sealed key in the store and discard the rest before the
child saw them. That still opened, and recorded, keys no command had asked for.

The cost is stated in the command and the README. Anything running as you can
fetch the escrow key, so the kept keys are exposed the way the device factor
exposes the vault, but only those keys.

### A grant says when it was issued

A process started by `passbook run` holds the store as it was at that moment,
and `passbook get` inside it answers from that environment rather than from the
store. That is right for a service using its own credential. It was wrong for
anything passing those values on: the HivemindOS collector runs under
`passbook run`, and on 2026-09-23 it served a pre-rotation credit token under
the store's current timestamp, so every peer took the dead token as the newest
copy. The rotation undid itself three times in one morning.

Every grant now carries `PASSBOOK_GRANT_ISSUED_AT`, the Unix time its
environment was built, at full precision. A caller that replicates can serve a
value only when the store has not changed that key since then, and withhold it
otherwise. An inherited or caller-supplied stamp is replaced, so a nested grant
is dated by its own issue.

### Replacing a key can push it to the services already holding it

Replacing a credential in the store was only ever half a rotation. The copies
already sitting on a Worker, a VPS, a CI secret store or a hosting provider went
on serving the old value until somebody pushed the new one to each of them by
hand, and the list of where those copies were lived in somebody's head. A
rotation got remembered as finished while several services were still holding a
dead key, and the way that surfaced was an outage somewhere else.

PassBook now keeps that list beside the key, with the exact command that put it
there:

    passbook services attach API_KEY cloudflare-worker \
      --command 'wrangler secret put API_KEY --name my-worker' --stdin
    passbook services                       # everything, and how each one last went
    passbook services update API_KEY        # push the current value again
    passbook services update API_KEY --only 1,3
    passbook services retry                 # only the ones that did not land

Replacing a key that has services recorded against it now asks whether they
should follow, and takes `all`, a selection like `1,3` or a service name, or
`no`. The push is sequential, prints each service as it goes, and one failure
never stops the rest: the point is to get as many onto the new value as possible
and leave a list of the ones that did not. That list survives the run, so
`passbook services retry` tomorrow picks up exactly what failed today.

Three things this deliberately does NOT do. It never asks when nobody is there
to answer: a script piping a new value in is told what it could run and pushes
nothing, because writing to a dozen live services is not something to do to
somebody who did not request it. It never puts the value on a command line,
where `ps` would show it to every process on the box — the command receives it
in its environment as `$KEY`, and on stdin when the binding asks for it, and a
command that tries to interpolate the value itself is refused. And it holds no
secret of its own: a binding is a service name and a command.

The record is itself a store key, `PASSBOOK_SERVICE_BINDINGS`, so it replicates
between machines on the sync that already exists rather than needing a new wire
and a matching change in every collector before machines could agree.


### Typing a secret shows bullets instead of nothing

`getpass` echoes nothing at all. On a typed password that is merely austere; on
a PASTED one — which is what a credential store asks for almost every time — the
screen is dead, and the honest reading of a dead screen is "did that work?".
People answer that by pasting again, or by pasting somewhere visible first to
check, which is the one place a secret must never go.

Every prompt that takes a secret now draws one `•` per character: `passbook add
KEY`, the vault password and its confirmation, and `passbook connect`'s
create/unlock pair. The characters themselves are still never echoed, the
bullets are written to the terminal rather than stdout so a redirected stdout
stays clean, and nothing reaches argv or the shell history.

Backspace, Ctrl-U and Ctrl-W erase bullets as they erase characters; a pasted
value arrives in one read rather than crawling in; an arrow key is swallowed
instead of leaving `[C` inside the key; and a multi-byte character draws one
bullet rather than one per byte. Ctrl-C and Ctrl-D behave as before, because the
terminal keeps ISIG rather than being put into raw mode.

Anything that is not a terminal — a pipe, CI, a test — falls straight through to
`getpass.getpass` unchanged, and so does a terminal that will not enter cbreak
mode. A nicer prompt is not worth failing to read a password.

New module `passbook_prompt` (and `py-modules`, without which the installed CLI
would not have it). Driven in tests through a real pseudo-terminal, because a
test that stubs the terminal away would pass just as happily on the version that
showed nothing.

## [1.7.1] — 2026-09-08

### 2026-09-08 — Cross-platform release verification

- Preserve exact service-definition bytes during installation and rollback on
  Windows. Newline translation previously defeated repeated-install detection
  and could change the original file when rolling back. Ordinary credential
  writes keep their existing newline behavior.
- Apply the same exact-byte preservation to original vault metadata during
  failed installation and interrupted recovery, including existing CRLF files.
- Give managed operations a bounded 35-second response deadline instead of the
  two-second broker availability probe. Password-based recovery and HTTPS calls
  could otherwise finish after their caller had already reported a false
  disconnection. The native authorization transport retains its 40-second bound.
- The 1.7.0 build remained a draft after Windows CI found these issues; 1.7.1
  supersedes it without changing the existing source tag.
- Validation: the local candidate passes 1,127 tests with two Windows-only
  skips in 112.27 seconds. Real CLI recovery and a delayed broker pass 17
  focused tests; Windows newline emulation also verifies the rollback paths.

### 2026-09-08 — Preserve credential boundaries during inheritance and import

- Refuse legacy reads, process injection, and proxy requests for credentials
  inherited from a managed workspace. Classify the owning store after local
  overrides, and recognize alternate workspace IDs pointing at the same file.
  Disconnecting a host does not reopen legacy access; unrelated local keys and
  genuine local overrides continue to work.
- Route `link accept` through the same encrypted writer as app and CLI saves.
  Keep an encrypted receiver encrypted, preserve its selected workspace and
  replacement policy, and record changes for synchronization. A locked receiver
  refuses a replacement without consuming the envelope, allowing a later retry.
  A saved value whose metadata update fails is reported as a partial save.
- Initial local release gate: 1,122 Python 3.12 tests pass, with two Windows-only
  skips, in 111.86 seconds. Apple Python 3.9 link and onboarding tests pass all
  64 cases; the inheritance fix passes 396 affected tests on Python 3.12.

### 2026-09-08 — App key replacements participate in fleet sync

- Record a fresh per-key sync timestamp after successful app/CLI additions,
  replacements, and owner imports, including writes sealed by the broker.
  Previously the value changed while its old timestamp stayed in place, so
  newest-wins reconciliation could ignore an edited key indefinitely.
- Stamp the actual destination workspace and only keys that were written.
  Locked, invalid, and kept entries do not acquire a newer timestamp. Serialize
  metadata updates with the existing sidecar lock so concurrent writers retain
  each other's entries.
- Report a partial save if the value was stored but its sync timestamp could
  not be recorded, without exposing values or exception details. This uses the
  existing sync schedule and permissions; it does not force an immediate push
  or resolve pre-existing conflicts by guessing which device is authoritative.
- Validation: the app's `add --stdin --replace` entry path reproduced the
  missing timestamp before the fix. Regression coverage includes a real locked
  then unlocked broker, encrypted addition/replacement, receiver selection of
  the new value, workspace isolation, kept/invalid writes, metadata-write
  failure reporting, and concurrent timestamps. The complete Python 3.12 suite
  passes 1,109 tests with two Windows-only skips in 93.59 seconds; the affected
  Apple Python 3.9 suites pass 211 tests. Included in the 1.7.1 release.

### 2026-09-08 — Apple Python password compatibility

- Fix password vault initialization and encrypted backups on Apple's Python
  3.9 builds that omit `hashlib.scrypt`. Use the existing cryptography dependency
  only when that function is absent, with identical scrypt parameters, 32-byte
  keys, ciphertext formats, and the existing memory ceilings.
- Verify the RFC 7914 test vector, opening vaults and backups across providers,
  wrong-password refusal, and invalid or excessive costs before allocation.
- Honor the host's standard `SSL_CERT_FILE` and `SSL_CERT_DIR` settings for
  managed HTTPS on Apple LibreSSL, which ignores them while loading default
  trust. Keep certificate and hostname verification enabled; untrusted or
  mismatched certificates and invalid trust configuration remain refused.

### 2026-09-08 — Managed application connections

- Connect a verified host to an encrypted workspace with one owner setup flow;
  preserve the desktop's selected workspace and reuse the first existing store.
- Add durable operation requests, authenticated owner decisions, scoped agent
  grants, encrypted key entry, pause/disconnect, and retry-safe HTTPS use.
- Resume approved background access through its own device factor; install
  login startup without interrupting the current broker. Report missing startup
  or locked access accurately and repair removed factors during owner reconnect.
- Provide safe managed MCP tools and owner-approved encrypted peer snapshots.
  Refuse plaintext and arbitrary-process tools on managed workspaces.
- Recover a selected workspace whose encrypted entries arrived without a local
  vault profile. Stage bounded encrypted peer batches, require both owners'
  authorization, verify the replacement, and retain original bytes in a private
  password-encrypted archive before committing the local vault.
- Support 30-day owner-approved peer update permissions. Pin receiving host and
  device identities, check fresh signed refresh proofs, and recheck scope and
  policy on each transfer. Default to exact keys; future keys require separate
  consent. Keep local changes and source removals, and never automatically
  overwrite entries an initial snapshot preserved.
- Preserve committed import receipts across retries and broker restarts. Serialize
  cooperating credential writers and check ciphertext versions before an incoming
  update. Document the remaining cross-file crash/reconciliation limit.
- Preserve explicit workspace context through reads, writes, OAuth refresh,
  grants, and access receipts. Redact provider echoes in header names and short
  values as well as ordinary response data.
- Authorize HivemindOS in the PassBook window with a matching installation
  code, a chosen workspace, and one password confirmation. Signed, expiring
  requests keep the password out of the host's result; the native transport
  bounds output and time, and an expired request can be closed.
- Replace older receiving permissions when owners renew a device connection.
  Repeated updates remain conflict-free, local edits stay intact, and retrying
  a stopped permission cannot reactivate it.

Validation: 1,103 Python tests passed in 91.37 seconds with isolated home, store,
and GPG directories; two Windows-only tests were skipped on macOS. This adds
193 passing tests over the 910-test baseline. The additional Apple Python 3.9
run passed 1,094 tests, skipped ten, and retained one debugger-control failure
that also reproduces in the unchanged checkout: its ordinary Python process
cannot be attached by the debugger, so that interpreter cannot demonstrate the
hardening difference. The vault, backup, and managed HTTPS tests pass on both
interpreters; the three TLS refusal cases send no credentials to the provider.
Installed-wheel setup and the real HivemindOS/WebKit → CLI → broker → HTTPS path
were exercised with synthetic credentials. This evidence was collected from the 1.7.0 development builds.
An installed development wheel also passed isolated setup, broker startup,
authorization, encrypted key creation, reconnect, and disconnect on a physical
Apple M2 Max. An approved HTTPS request ran through its real broker with provider
authentication, response redaction, and idempotent replay. Untrusted certificates
and wrong hostnames were refused before credentials were sent. Both temporary
brokers and their directory were removed; no real store, keychain, login service,
or global certificate settings were used.
Real CLI tests also cover two isolated brokers, 70-key multipart recovery, and a
subsequent password-free encrypted key rotation. Host fleet transport and OS
isolation from unrestricted same-user agents remain separate delivery gates.
Both authorization UI surfaces passed through real owner routes and the broker;
native IPC and operating-system app activation were simulated. Rust checks
compiled the native bridge and its tests; a packaged app, real push delivery,
and keystore access across login or reboot were not verified.
Deletion propagation, bidirectional conflict resolution, automatic lease renewal,
and forced replacement of a running older broker are not implemented; see
`docs/MANAGED_PROTOCOL.md`.

### `policy --reads` no longer pretends to take a scope

`passbook policy --app hivemindos --key PLAID_CLIENT_ID --reads open` exited 0,
printed "Reads are open", and recorded nothing for the app it named. The scope
flags were parsed and then dropped: the reads branch ran first and returned, so
a command that read as touching one key on one app flipped the store-wide switch
for every key on the machine — and left no policy row behind, so `passbook
policy` afterwards showed nothing and the person went looking for a rule that
had never been written. `--mode` was discarded the same way whenever `--reads`
was present.

The combination is refused now rather than made to work, because there is no
scoped `--reads` to implement. A per-app exemption to sealed reads is the list
1.3.0 deliberately removed: an app name is a claim, and anything can call itself
the exempted app. The refusal says that, says nothing was changed, and names the
two flags the person was probably reaching for — `--mode` to govern who may have
a key, `passbook run` to use one without printing it. `--reads` alone still sets
the store's posture in both directions, and `--learn --mode … --reads sealed`
still works, since `--learn` consumes the mode before the seal is applied.

### A revealed credential is drawn, and the window it is drawn in cannot be captured

1.3.0 stopped values reaching callers the broker did not start. It did not stop
them reaching the one caller that is supposed to have them and then leaks anyway:
the window. A revealed key sat in an `<input>`, which meant two things nobody
could undo afterwards.

**It was text, so it was published to the accessibility tree.** `AXUIElement` on
macOS and UI Automation on Windows read it with no screenshot involved — the same
path a screen reader uses, and the path an agent with computer use takes first,
because it is cheaper and more reliable than OCR. Hiding the window from capture
would have protected nothing here.

**It was a JavaScript string, so it could not be erased.** `delete` drops a
reference; the bytes go back to the allocator un-overwritten. And one reveal was
never one copy — escaping, the row template, the page concatenation and
`innerHTML` each made another, so a value left on screen while somebody typed one
letter in the search box minted a fresh set every repaint, none of them erasable.

Neither has a fix on the window's side of the boundary, so the value stopped
crossing it.

- **`reveal_key` returns a token, not a value.** The credential is held in the
  app, rasterised there, and the window fetches a PNG of it from the loopback
  server it already runs. No command in the app hands a credential to the webview
  any more, which is checkable by reading the signatures — and is, by a test.
- **The window is excluded from screen capture.** `NSWindowSharingType::None` on
  macOS, `WDA_EXCLUDEFROMCAPTURE` on Windows, both through tao. Linux has no
  equivalent and gets none; the app's Security page reports which protections
  this platform actually gave it rather than claiming all of them.
- **Copying happens in the app.** `navigator.clipboard.writeText` takes a string,
  so copy was the one path that re-materialised in the window everything else
  avoids — on the row's most-used button.
- **A revealed value hides itself after 30 seconds**, and the app overwrites its
  own copy then rather than at the end of the 45-second hold. The two clocks are
  deliberately unequal and a test pins which one wins.
- **Editing a value became replacing one.** The box opens empty. Pre-filling it
  would have put the old value back into the exact element this change exists to
  empty, and nobody amends the fourteenth character of an API key.
- **`Zeroizing` on the app side.** The three unerased copies `Command::output`
  used to leave behind are overwritten now. That was invisible while the value
  was on its way to a webview that could not erase anything either.

**`reads: sealed` did not cover `reveal`.** It checked the guard list and never
`reads_mode`, so `passbook reveal KEY --confirm KEY` printed values on a machine
whose own refusal message said it does not print them — and `--confirm` skipped
the terminal check that was the only other thing in the way. That is the exact
command an agent reaches for. It is refused now, and the refusal names both ways
through: `passbook run` for a program, and the window for the person whose
credential it is.

**Under a seal the app draws through the broker.** The window is not a process
the broker started, so it no longer reads the value: it asks the broker to spawn
this same binary in a `--draw` mode with no window, which is handed the value the
way every brokered child is, draws it, and writes a PNG the app reads back and
unlinks. The picture comes back through a file rather than the child's stdout
because `passbook run` decodes a child's output as UTF-8 with replacement, which
would destroy every non-UTF-8 byte of a PNG. Copy is refused outright on a sealed
machine: the clipboard is readable by every process on it.

The font is the system's, found by path — nothing is bundled, for the same reason
the icon set is drawn by hand. A machine with no monospace font PassBook can draw
with refuses to reveal rather than falling back to text, which would have quietly
undone all of this on exactly the machines least able to notice.

**What it does not buy** is in the README under *What it does not claim*: the
plaintext is in the app while the hold lasts, capture exclusion is the compositor
cooperating rather than hardware, and none of it touches code running as you that
asks the store directly without opening the window.

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

### Sealing reads without migrating the whole machine in one evening

`--reads sealed` refused every caller the broker did not start, which is the
guarantee — and on a real machine it meant moving twenty callers at once,
fleet env replication among them. So an **approved** app may still read
directly while it is being converted, and the list shrinks as each one moves
to `passbook run`.

This is a migration path and not a second boundary, which is worth saying
plainly: the app name is a claim, so anything can call itself an approved one
and read what that app reads. **No exemption reaches a guarded key** — a guard
refuses every caller, approved or not, which is why the money-movers are
guarded rather than left to this.

- **A toggle in the window**, under Security, beside the state it reports.
  Sealing does not ask twice; un-sealing does, because that hands values back
  to every program running as you.

### A broker no longer outlives the store it was serving

Ported from a worktree that never landed. A throwaway `HIVE_HOME` — a test tree,
a `mktemp -d`, a container layer — is deleted far more often than it is shut
down, and the broker went on running: listening on a socket in a directory that
no longer existed, so unreachable by anything, and still holding the data key of
a store that was gone. Four were found on one machine, the oldest hours old.

- The serve loop checks, on every accept and every couple of seconds besides,
  that the socket at its path is still the one it bound — **by inode, not by
  name**, so a broker that has been replaced leaves without deleting its
  replacement's socket. Verified: a store deleted under a running broker stands
  it down in about half a second.
- **`passbook broker stop`** sends SIGTERM, which used to end the process where
  it stood: no shutdown, so the data key was never zeroed and the socket was
  left for `stop` to sweep up. Handled now, so every shutdown leaves through the
  same door and zeroes the key on the way out.
- **`passbook broker strays`** finds the older population through the process
  table, since a stray's store is exactly what went missing. `--clear` stops the
  ones it can place and leaves the ones it cannot, naming the command that will
  identify them.
- `broker start` records its store on the command line, which is what makes a
  stray placeable at all — and fixes `start(root=X)` watching X while the child
  bound whatever the environment said.

The Windows pipe has no equivalent failure: its namespace is not a directory and
cannot go missing this way, so the listener reports that it cannot tell and the
check is skipped rather than guessed at.

### Manual sign-in after a reboot, by default, with a switch

Two things had been conflated, and the conflation is why nobody could say what
the machine did. A **device factor** makes `passbook signin --device` work with
no password. **Auto-opening** is something running that sign-in at boot. The
first without the second is what this machine had — and nothing ran it at boot:
no LaunchAgent started the broker, and `serve()` never opened anything. So every
reboot already left the store shut until a person signed in. The exposure was
real; the convenience it was traded for was not being collected.

- **`passbook vault --stay-open`** reports both halves separately, because they
  fail separately and one-without-the-other is the confusing case.
- **`--stay-open on`** enrols the factor and installs a per-user LaunchAgent
  running `broker run --open-with-device`. It states the cost — the opening key
  sits in the OS keystore where any program running as you can fetch it — and
  refuses without `--yes`.
- **`--stay-open off`** removes both and forgets the keystore item.
- **`passbook broker run --open-with-device`** is the flag that does it. A flag
  rather than a behaviour: a broker that opens the vault with nobody present is
  a decision, not a default. If the factor is gone it warns and starts shut,
  because a broker that refuses to start over a missing factor is an outage.

Off is the default and is not a new restriction — it is what the machine was
already doing.

### A capability that could be granted and not taken back

`passbook profile trust-device` stores a wrapping key in the OS keystore so a
job can open the vault at boot with nobody there. Its own warning is blunt about
the cost — "A device factor lets ANY program running as you open the vault
without asking" — and it demands the vault password plus `--yes` before it will.

There was no way to undo it. `remove_factor` had been in `passbook_vault` all
along, exported, correct, and wired to nothing; the only route back was
`passbook profile remove`, which destroys the profile and everything it sealed.
So the one factor whose whole purpose is to remove a human from the loop was
also the one that could not be revoked.

- **`passbook profile untrust-device`** removes it, forgets the keystore item,
  and states the three things that stop working before it will act.

Found by restarting the broker on a machine that had one: the vault locked, and
reopening it took `passbook signin --device` and no password at all. Nothing was
broken — that is precisely what the factor does — but it is not a property
anybody should rediscover by accident.

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
