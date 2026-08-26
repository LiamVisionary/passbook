# Drop-in agent prompt: adopt PassBook

Copy everything below the line into any coding agent working on a project that
needs API keys. It teaches the agent the one rule, hands it the two reference
files, and stops it inventing a fourth credential store.

Replace `<APP_ID>` and `<APP NAME>` before sending, or leave them and the agent
will ask.

---

## Task: put this project on PassBook

This machine keeps **one** credential store that every PassBook app shares. Your
job is to make this project use it, and to make sure it never creates a private
one.

### The rule

Resolve `$HIVE_HOME`, else `~/.hivemindos/.env`. That is the store. It is a
fleet-wide **default**, never an override — the process environment wins, then
the project's own env files, then the hive env.

Because every app resolves the same path with the same rule, **provisioning and
linking are the same operation**. The first app that needs the store creates it;
every app after that — including the HivemindOS desktop app — finds it and
adopts it. Nothing forks, so nothing ever has to be merged.

### What to do

1. Copy `passbook.py` (Python) and/or `passbook.mjs` (Node) into this project.
   Both are single files with no dependencies. Do not rewrite them; do not
   reimplement the path rule by hand.

   Do not add `cryptography` or any other package for this. The vendored file
   needs nothing; sealing and linking are separate commands with their own
   runtime, set up by `passbook install`, and are not this project's problem.

2. At startup, once, before anything reads a credential:

   ```python
   import passbook
   passbook.ensure(app="<APP_ID>", name="<APP NAME>")   # idempotent
   passbook.apply()                                     # fill missing vars
   ```

   ```js
   import { ensure, apply } from './passbook.mjs';
   ensure({ app: '<APP_ID>', name: '<APP NAME>' });
   apply();
   ```

3. Read credentials from the process environment as normal
   (`os.environ["OPENAI_API_KEY"]`). Do not read the file yourself.

4. Delete any private `.env` bootstrap this project already has, and any code
   that writes credentials somewhere else. If the project holds keys that are
   not in the shared store yet, pass them once as `seed=` — existing keys are
   never overwritten.

5. Tell the difference between a key that is **missing** and one that is
   **locked**. `passbook check` says which:

       set      readable right now
       locked   in the store, encrypted — `passbook signin` opens it
       missing  genuinely not there

   A locked key is not a lost key. Do NOT run `passbook add` on one: that
   overwrites a working credential with whatever you paste. If `list` shows a
   key that you cannot read, the store is sealed and nobody has signed in —
   say so and stop, rather than re-creating it.

6. Where a key is missing, say which key and where it goes:
   *"OPENAI_API_KEY is not set — run `passbook-add OPENAI_API_KEY`"*. Never
   print a value, ever, including in errors.

   Never tell anyone to `pip install` into their system Python. Homebrew,
   Debian and Ubuntu refuse it (PEP 668), so the advice fails for most people
   and fails with an error about their OS. `passbook install` is the answer.

### Rules you must not break

- **Never create a second store.** No `~/.myapp/.env`. If you think you need
  one, you have misread the standard.
- **Never overwrite an existing key** without being explicitly asked. Another
  app on this machine is probably using it.
- **Never log, print, or return a value.** Key *names* are fine to show; values
  are not. Every status surface in the reference implementation returns names.
- **Never widen permissions.** The store is `0600`, its directory `0700`.
- **Never write into a sandbox container.** `ensure()` returns `ok: false` with
  a reason when `~` is an app container; surface that as a packaging problem,
  because writing there creates an invisible second store.

### Workspaces

If this project acts for a specific workspace, set `HIVE_WORKSPACE`. Reads layer
the machine store then the workspace store; **writes go to the workspace**, so a
key added while scoped never appears machine-wide. A workspace marked
`"inherit": false` in `~/.hivemindos/workspaces.json` sees only its own — use
that for anything holding someone else's credentials.

### Limits you may be held to

A key can be limited beyond "is it set". If a read comes back refused, the
reason names which bound stopped it, and none of them is a bug to work around:

- **Projects.** `passbook projects` says which keys are limited to which
  checkouts. Your project is `PASSBOOK_PROJECT`, else the basename of the
  nearest git root. If a key is limited to a project that is not this one, it is
  not this project's key — say so and stop. Do not set `PASSBOOK_PROJECT` to
  something else to get past it.
- **Agents.** `passbook agents` says which agents a key is for.
- **Changes may need a person.** If `passbook confirm` shows `add`, `modify` or
  `delete` set to ask, writing waits for the owner to approve it in the PassBook
  window. That is not a hang; do not retry in a loop, and do not look for
  another way to write the file.

### Moving a store

`passbook export FILE` writes the whole store encrypted under a passphrase, and
`passbook import FILE` reads one back. Both are recorded. Never suggest
`--plain` unless the person asked for a readable file and understands that it is
every credential they own in the clear.

### When you are done

Report: which files you added, where the startup call went, what you deleted,
and the output of `passbook.describe()` — which is a count and a path, not
secrets. Do not paste the store's contents.
