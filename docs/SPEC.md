# The PassBook standard, v1

One credential store per machine, shared by every app that opts in.

## PassBook and the hive env

**PassBook** is this standard and its drop-in implementations. It is deliberately
not branded to any one product, because its whole value is that unrelated
projects can adopt it and land on the same store.

**The hive env** is what that store is called on a machine running HivemindOS:
`~/.hivemindos/.env`, with `hive-env-check`, `hive-env-run` and `hive-env-add`
already built around it. PassBook resolves exactly that file. It does not
introduce a second store, wrap it, or migrate it — it agrees with it, so
`passbook-check FOO` and `hive-env-check FOO` are answering from one file.

On a machine with no HivemindOS, PassBook creates that same canonical path, so
installing HivemindOS later adopts what PassBook made rather than starting over.

## The problem it exists to solve

Ship three apps and you get three credential stores. The user pastes the same
OpenAI key three times, revokes it in one place and wonders why the other two
still work, and every app has its own idea of where "the env" lives. Installing
a fourth app makes it worse, not better.

The fix is not a synchronisation protocol. It is agreeing on one path.

## The rule

Every participating app resolves the same canonical file with the same rule.
Because the path is agreed, **provisioning and linking are the same operation**:
the first app that needs the env creates the canonical one, and every app after
it — including the HivemindOS desktop app — finds that same file and adopts it.
Nothing forks, so nothing has to be merged later.

An app that follows this spec never creates a private env of its own.

## Layout

```
$HIVE_HOME  or  ~/.hivemindos/         mode 0700   the hive root
  .env                                 mode 0600   the canonical credential store
  apps.json                            mode 0600   who participates (names only)
```

`HIVE_HOME` overrides the location for the whole machine. It exists for tests,
for portable installs, and for hosts whose home directory is not writable. When
it is set, every participating app must honour it.

## Format

`.env` is a flat `KEY=value` file, one pair per line.

- `#` begins a comment line.
- A leading `export ` is tolerated and ignored.
- Surrounding single or double quotes are stripped from the value.
- Keys match `[A-Za-z_][A-Za-z0-9_]*`.
- Later lines win, so an appended key supersedes an earlier one.

This is deliberately the same shape a shell would source, so the file stays
readable and repairable by hand.

## Precedence

When an app resolves a credential, the first hit wins:

1. the **process environment** — an explicit export, a CI secret, a launcher
2. the app's own **project env** files, if it has any
3. the **canonical hive env**

The hive env is a fleet-wide *default*, never an override. Setting a key in one
project must not change what another project sees, and an app that wants its own
value simply sets it locally.

## Writing

Writes are additive and non-destructive:

- an existing key is **never** replaced unless the caller explicitly asks
- the file is written atomically — write a temporary file in the same
  directory, then rename over the target — so a crash mid-write cannot
  truncate the store
- the file is created `0600` and the root `0700`; existing modes are
  tightened, never loosened
- comments, ordering, and unrelated keys are preserved

## Disclosure

Key **names** are public; key **values** are not. Every status and diagnostic
surface in this spec returns names only. An implementation must not log, print,
or return a value from any of them, and must not put one in an error message.

There is exactly one exception, and its shape matters: **a deliberate reveal**,
for the owner, of one named key. A credential manager that cannot show you your
own credential is not one — keys are kept in order to be pasted somewhere
eventually — but that path must be:

1. **its own call**, never a flag on a status or load function, so that "does
   this return secrets?" stays answerable by reading the signature
2. **recorded**, under its own operation, so a person looking at their own key
   is legible as that rather than indistinguishable from an app consuming it
3. **not policy-gated**. Refusing to show an owner their own key would be
   theatre; they can read the file. Recording it is the honest control.

An implementation that instead adds values to its status output has not gained
a feature, it has lost the property that made the rest of the surface safe.

There is one exception to (3), and it is narrow. Where an owner has explicitly
bound a key so that it is used and never printed, reveal may refuse it. That is
not the theatre (3) rules out, for two reasons: the owner asked for it by name,
and the owner can lift it by name — so what the refusal costs is a deliberate
second act, not access. It also stops being theatre in fact rather than only in
intent, because on a store where values are sealed and resolved through a
broker, "they can read the file" is no longer true; the file is ciphertext.

An implementation must not extend this to keys the owner has not bound. A blanket
refusal to show an owner their own credentials is the theatre, and it is also how
a person ends up copying values somewhere less careful.

## Participation

`apps.json` records which apps use the store:

```json
{
  "version": 1,
  "apps": [
    {"id": "hivemind-content-studio", "name": "Hivemind Content Studio",
     "first_seen": "2026-08-25T11:20:00Z", "last_seen": "2026-08-25T11:41:00Z"}
  ]
}
```

It is a registry, not a lock. Nothing reads it to decide access — it exists so a
person can answer "what is using my keys?" and so an installer can say "3 apps
already share this store" instead of silently adopting it. A corrupt or missing
`apps.json` is not an error; participation is re-recorded on next start.

## Containers and sandboxes

Inside a macOS App Sandbox, `~` resolves to
`~/Library/Containers/<bundle-id>/Data`, so a sandboxed app that follows this
spec naively would create a second, invisible store inside its own container —
exactly the forking this standard exists to prevent.

An implementation must detect that case and report it rather than write there.
The caller then decides: request the entitlement, ship unsandboxed, or run with
an explicit `HIVE_HOME`. Failing loudly is required because the alternative
looks like missing credentials rather than a packaging mistake.

## Linking (optional)

Linking is not required for conformance; an implementation that omits it is
still conformant. Where it is offered it must hold to these properties, because
each one is load-bearing and a partial version is worse than none:

1. reachability grants nothing — authorization is a human act on the owning
   machine, never network membership
2. an out-of-band fingerprint comparison is required to approve, and a
   non-interactive caller must not be able to skip it
3. the same comparison is required the first time a machine accepts from an
   issuer — an envelope that merely opens proves who it was sealed *to*, never
   who sealed it, so accepting an unknown issuer would let anyone who saw a
   pairing token plant their own values for real keys
4. values are sealed to the receiving device, so the transport is untrusted
5. a grant names specific keys, carries an expiry, and cannot be replayed
6. the signed grant, not the sealed payload, decides which keys land
7. revocation reports the keys that must still be rotated, rather than implying
   that revoking recalls them

Reference implementation: `passbook_link.py`. Grants are UCAN-shaped
(`iss`/`aud`/`att`/`exp`) and identities are `did:key`, so a receiver verifies
from the envelope alone with nothing to look up.

## Brokering (optional)

Not required for conformance. An implementation that offers it must be honest
about what it is, because the failure mode is someone relying on a boundary that
was never there:

1. a broker records every request it serves, granted or refused, so the record
   does not depend on each client opting in
2. a refused key never reaches the caller
3. an unreadable or missing policy grants rather than refuses — a parse error
   that silently denied everything would take a machine down and look like a
   credential fault the whole time
4. a client falls back to reading the stores when no broker answers, so stopping
   one degrades the record rather than the machine
5. an explicitly named store list bypasses the broker, since naming files is how
   a test or a sandbox declares it is not on the machine's store
6. every surface that reports on the broker also reports its limits

The limits are not incidental. Without the operating system vouching for the
caller, any process running as the user can claim to be any app; the stores
remain readable directly; and stopping the broker restores full access. A broker
is therefore an audit boundary and a blast-radius limiter, never an access
control against a determined attacker, and must not be described as one.

Reference implementation: `passbook_broker.py`.

## Using without reading (optional)

Not required for conformance. Reading a credential and *using* one are different
acts, and an implementation may offer the second without the first. This matters
for one caller in particular: an agent writes everything it observes into a
transcript that is stored and sent onward, so a value an agent reads has been
copied out of the machine whatever it intended. Approving that read does not
change where the value went — it only makes the copy authorised.

An implementation that offers this must hold to all of:

1. the value is resolved by the broker and placed into a process the **broker**
   started; it is never returned to the caller that asked
2. output returned to the caller has every injected value removed from it, in
   each encoding the value could plausibly appear in — the caller chooses the
   command, so a caller that chooses `printenv` is the case this is *for*, not
   an abuse of it
3. redaction that cannot cover a value reports that it could not, rather than
   implying coverage it does not have
4. a process the broker started may serve itself from the environment it was
   given, and may not obtain anything beyond the key set it was started with
5. a key may be bound to the commands it may enter and the hosts it may be sent
   to; where no host is bound, sending it to one is refused rather than allowed,
   because an unbound outbound path is an exfiltration primitive
6. using a key is recorded distinctly from reading one — a record that said
   `read` would assert the single thing that did not happen
7. neither the record nor any status surface may echo a value back, including
   one the caller wrote into its own command line

The limits, again stated rather than implied. This does not confine what a
command does with what it was given: a command free to make network calls can
send its credential anywhere, and only the bindings in (5) constrain that. And
because the broker and the caller run as the same user, a caller willing to
write custom code can read a value out of the memory of the broker or of the
child it spawned. Closing that needs a privilege boundary — a separate service
account, an OS keychain ACL naming signed callers — which is a property of an
installation, not of this standard.

What it does buy is that the ordinary path stops leaking: the value is not in
the caller's output, not in its transcript, and not in the record.

Reference implementation: `passbook_grant.py`.

## Nothing else may become required

Every optional part of this standard — stamping, sealing, linking, brokering,
access modes, using without reading — must leave a bare implementation working
on its own. Concretely:

1. an app that vendors only the store implementation resolves credentials with
   no daemon, no companion module and no other application installed
2. a policy is enforced *by* a broker, so a machine with no broker is never
   locked out by one — writing a policy must not be able to strand the apps on
   a box that cannot enforce it
3. resolving a credential with no broker running costs no socket timeout; the
   common case must not pay for the rare one
4. where a decision needs a person, **more than one surface** can carry it. A
   product that is the sole approver has made itself a dependency of every app
   on the machine, whatever the marketing says

The fourth is the one that erodes quietly. It is tempting to route approval
through the strongest surface only — a signed application whose identity the
system can vouch for — and that is a real security gain. But it converts an
optional product into a prerequisite for every other app's credentials, which
is the opposite of what agreeing on a path was for. Offer it as a setting an
owner turns on, never as the shape of the thing.

## Conformance

An implementation conforms if it:

1. resolves `HIVE_HOME` then `~/.hivemindos`, and nothing else
2. parses and writes the format above
3. applies the precedence above, filling only variables the process lacks
4. creates the canonical store when absent rather than a private one
5. never replaces an existing key without an explicit request
6. writes atomically, with `0600`/`0700`
7. returns key names, never values
8. detects a sandbox container and refuses to provision inside it

Where an implementation supports workspaces, reads layer machine store then
workspace store, and **writes target the workspace**. Writing to the machine
store from a workspace-scoped process would put a key where every sibling can
read it, which makes `"inherit": false` decorative. Implementations that
disagree here hand different keys to different processes on one machine, and the
disagreement surfaces as a provider that works in one and fails in the other.

Reference implementations: `passbook.py` (Python 3.9+) and `passbook.mjs`
(Node 18+). Both are single files with no dependencies, meant to be copied into
a project as-is. The optional halves — sealing and linking — do need a crypto
library, which is why they are separate files and separate commands: a project
that vendors the store must not inherit a dependency it did not ask for.

## Command line

`bin/passbook` ships with the reference implementation and is the same code the
library uses, so the CLI and an app can never disagree about what is stored.
`passbook install` symlinks the hyphenated aliases onto `PATH`.

```
passbook-check KEY...        set or missing, never the value; exit 1 if any is unset
passbook-add KEY[=value]     additive; a bare KEY prompts without echo
passbook-remove KEY...       delete; the one operation that can break another app
passbook-run -- cmd ...      run cmd with the store as a base, process env winning
passbook-list                key names
passbook-status              path, count, workspace, participating apps
passbook-access              the tamper-evident record of reads
passbook-seal                encrypt every plaintext value in place
```

A bare `passbook-add KEY` is the form to prefer. `KEY=value` on the command line
lands in shell history and is briefly visible to `ps`; the prompt is not.
