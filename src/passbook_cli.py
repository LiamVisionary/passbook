# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook on the command line.

One store per machine, shared by every app that speaks PassBook. This is the
same store the library reads, so `passbook-check FOO` and an app's own lookup
of FOO always agree — there is no second source of truth to drift from.

On a machine running HivemindOS the store is the hive env, and these commands
are interchangeable with `hive-env-check` / `hive-env-add` / `hive-env-run`.
The difference is that these work on a machine that has no HivemindOS at all,
which is the point of the standard.

Invoked either way:

    passbook check OPENAI_API_KEY
    passbook-check OPENAI_API_KEY

The hyphenated forms are generated shims, or console scripts when PassBook is
installed as a package; either way the name it was called by picks the
subcommand.

No command in here prints a credential. `check` reports set, locked or
missing — three answers, because a sealed store makes two of them a lie —
`list` reports names, and `run` hands values to a child process without ever
putting them on a terminal or in the ledger.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook  # noqa: E402

# `passbook-check` and friends are symlinks to this file. Dispatching on the
# invoked name is what lets one implementation serve both spellings without a
# wrapper script per command going stale.
# Names that do not match their verb one for one.
ALIAS_SYNONYMS = {"passbook-set": "add", "passbook-delete": "remove"}

_ALIASES: dict[str, str] | None = None


def aliases() -> dict[str, str]:
    """Every `passbook-<verb>` name, derived from the parser itself.

    This used to be a hand-written dict, and it went stale: the help text
    promised "every subcommand is also available hyphenated" while thirteen of
    them were not — `unseal`, `signin` and `secure` among them, so the documented
    way to reach the rollback did not exist. Deriving it means a new verb is
    hyphenated the moment somebody adds one.
    """
    global _ALIASES
    if _ALIASES is None:
        subcommands = next(
            action.choices for action in build_parser()._actions
            if getattr(action, "choices", None)
        )
        _ALIASES = {f"passbook-{verb}": verb for verb in subcommands}
        _ALIASES.update(ALIAS_SYNONYMS)
    return _ALIASES


def _fail(message: str, remedy: str = "") -> int:
    # stdout is block-buffered when piped while stderr is not, so without this
    # the error lands above the lines it is explaining.
    sys.stdout.flush()
    print(message, file=sys.stderr)
    if remedy:
        print(remedy, file=sys.stderr)
    return 1


def _use_broker_for_sealed_values(app: str, reason: str) -> None:
    """Let this process read a sealed store by asking the broker to open it.

    The data key stays inside the broker; what comes back are values it decided
    this caller may have, and every one of them lands in the ledger. So this is
    not a way around the vault — it is the way through it, for the commands
    whose whole job is to hand credentials to something else.

    `request()` is the door an app should use directly. This exists for `run`,
    which has to fill an environment for a program that has never heard of
    PassBook and cannot be rewritten to ask.
    """
    try:
        import passbook_broker
    except ImportError:
        return

    def unseal(values: dict[str, str]) -> dict[str, str]:
        sealed = [name for name, value in values.items() if str(value).startswith("hive-sealed:")]
        if not sealed:
            return values
        granted = passbook_broker.request_through_broker(sealed, app=app, reason=reason) or {}
        opened = {name: value for name, value in values.items()
                  if not str(value).startswith("hive-sealed:")}
        opened.update(granted)
        return opened

    passbook.set_unsealer(unseal)


def _store_values() -> dict[str, str]:
    """Everything the store holds, for a child process. Never for a terminal."""
    return passbook.load()


def caller(default: str, args: argparse.Namespace | None = None) -> str:
    """Who is asking, in the order the answer should be trusted.

    Every access decision this project makes — audiences, per-app modes,
    projects — is keyed on this name, and until now only `passbook get` could
    be told it. `run` is the command an agent actually uses to get an
    environment, and it always called itself `passbook-run`, so no policy could
    ever name the agent behind it and every agent on a machine was one
    indistinguishable row in the record.

      1. `--app`, which is this call, said on purpose.
      2. `PASSBOOK_APP`, which is this process tree. An agent harness sets it
         once and everything it spawns is attributed without threading a flag
         through code it does not own — including whatever `run` execs, since
         the child inherits the environment.
      3. the command's own name, which means you, at a terminal.

    It is a claim in every case, exactly as an agent's MCP name is. It decides
    policy and fills the record; it is not a password, and a process that can
    set an environment variable could equally pass a flag.
    """
    said = str(getattr(args, "app", "") or "").strip()
    if said:
        return said
    ambient = os.environ.get("PASSBOOK_APP", "").strip()
    return ambient or default


# ── commands ───────────────────────────────────────────────────────────────


def cmd_check(args: argparse.Namespace) -> int:
    """Presence, never contents. Three answers, because there are three.

    This used to have two — set or missing — and a sealed store made it lie. A
    key that was present, encrypted and perfectly readable through the broker
    reported `missing`, and then advised `passbook-add`, which would have
    overwritten a working credential with whatever the reader pasted. Being
    wrong is bad; being wrong while recommending the destructive fix is worse.

    So: **set** is readable here and now, **locked** is in the store but shut,
    and **missing** is genuinely absent. Each gets the remedy that matches, and
    only one of them is `add`.
    """
    _use_broker_for_sealed_values(caller("passbook-check", args), "presence check")
    values = _store_values()
    held = set(passbook.key_names())

    refused = _refusals([k for k in args.keys if k in held], caller("passbook-check", args))
    missing, locked = [], []
    for key in args.keys:
        value = values.get(key, "")
        if value and key not in refused:
            detail = f" ({len(value)} chars)" if args.length else ""
            if not args.quiet:
                print(f"{key}: set{detail}")
        elif key in refused:
            if not args.quiet:
                print(f"{key}: refused — {refused[key]}")
        elif key in held:
            locked.append(key)
            if not args.quiet:
                print(f"{key}: locked")
        else:
            missing.append(key)
            if not args.quiet:
                print(f"{key}: missing")

    if refused and not missing and not locked:
        return _fail(
            f"\nRefused by this machine's policy: {', '.join(refused)}",
            "Nothing is wrong with them and nothing needs re-adding.\n"
            "See what governs them:  passbook group list",
        )
    if locked and not missing:
        return _fail(
            f"\nIn the store but encrypted: {', '.join(locked)}",
            "Nothing is wrong with them — sign in to read them:  passbook signin",
        )
    if missing:
        remedy = f"Add with: passbook-add {missing[0]}"
        if locked:
            remedy += (f"\nSeparately, these are encrypted rather than absent: "
                       f"{', '.join(locked)} — run `passbook signin`.")
        if refused:
            remedy += (f"\nSeparately, these are refused rather than absent: "
                       f"{', '.join(refused)} — see `passbook group list`.")
        return _fail(f"\nNot set: {', '.join(missing)}", remedy)
    return 0 if not refused else 1


def _write_values(values, *, overwrite: bool, exact: bool = False,
                  app: str = "passbook-cli") -> dict | None:
    """Write values, keeping a sealed store sealed. None means it was refused.

    A store is either encrypted or it is not; half of each is a state nobody
    chose and nothing reports. Before this, writing to a sealed store put
    plaintext beside the ciphertext, because only the broker holds the key and
    `set_values` writes what it is handed.

    So: sealed store and an open vault seals on the way in. Sealed store and a
    shut vault REFUSES, rather than quietly writing the one value in this store
    that anybody can read.
    """
    if not _sealed_store_present():
        return passbook.set_values(values, overwrite=overwrite, exact=exact)
    try:
        import passbook_broker
    except ImportError:
        return passbook.set_values(values, overwrite=overwrite, exact=exact)

    held = set(passbook.key_names())
    answer = passbook_broker.seal_values(values, app=app)
    if answer.get("ok"):
        sealed = answer.get("sealed") or []
        # `set_values` distinguishes these and callers print them; the sealing
        # path has to say the same thing or a new key reads as "replaced".
        return {"path": answer.get("path", ""),
                "added": sorted(k for k in sealed if k not in held),
                "updated": sorted(k for k in sealed if k in held),
                "kept": [], "sealed": sorted(sealed)}
    _fail(
        "This store is encrypted, and the value could not be sealed: "
        + str(answer.get("error", "the vault is shut")),
        "Sign in first, so the new value is stored the same way as the rest:  passbook signin")
    return None


def _confirm_change(kind: str, keys, *, reason: str = "", app: str = "") -> bool:
    """Stop and ask, when the policy says this kind of change needs asking.

    True means go ahead — including when confirmation is switched off, which is
    the default and the common case.

    The check is cheap and local; only when a toggle is ON does anything reach
    the broker. And when it is on and there is no broker, this refuses rather
    than proceeding: a toggle whose enforcement vanishes with a daemon is not a
    toggle, it is a suggestion.
    """
    try:
        import passbook_access as access
    except ImportError:
        return True
    try:
        policy = access.read_policy()
    except Exception:  # noqa: BLE001 — an unreadable policy must not block a write
        return True
    if not access.needs_confirmation(kind, policy):
        return True
    # The person clicking in the PassBook window has already said yes; asking
    # them again in the same window would be the app confirming with itself.
    if os.environ.get("PASSBOOK_APPROVED") == "1":
        return True
    try:
        import passbook_broker
    except ImportError:
        return True
    names = sorted({str(k) for k in keys})
    print(f"Waiting for you to approve this {kind} in PassBook…", file=sys.stderr)
    sys.stderr.flush()
    # The same name the write itself is recorded under. These were resolved
    # separately, so the notification asked about one caller and the record
    # then named a different one for the very change it approved.
    answer = passbook_broker.confirm_change(
        kind, names, app=app or os.environ.get("PASSBOOK_APP", "").strip() or "passbook-cli",
        reason=reason or f"{kind} {', '.join(names[:4])}")
    if answer.get("ok"):
        return True
    decision = answer.get("decision", "deny")
    detail = {
        "timeout": "Nobody answered, so nothing was changed.",
        "unavailable": "No broker is running, so that change could not be confirmed. "
                       "Start it with:  passbook broker start",
    }.get(decision, "That change was declined; nothing was written.")
    _fail(detail)
    return False


def cmd_confirm(args: argparse.Namespace) -> int:
    """Which changes stop and ask before they happen."""
    import passbook_access as access

    policy = access.read_policy()
    if args.op:
        required = not args.off
        try:
            access.set_confirmation(args.op, required, policy)
        except ValueError as error:
            return _fail(str(error))
        access.write_policy(policy)
    current = access.confirmations(policy)
    if args.json:
        print(json.dumps(current, indent=2))
        return 0
    words = {"add": "adding a key", "modify": "changing a key's value",
             "delete": "removing a key"}
    for op in access.CONFIRM_OPS:
        print(f"  {op:<7} {'asks first' if current[op] else 'happens straight away'}"
              f"   ({words[op]})")
    if not any(current.values()):
        print("\nNothing asks. Turn one on with:  passbook confirm delete")
    else:
        print("\nA change that asks waits for you in the PassBook window, and shows "
              "a notification.")
        print("Nothing is written until you answer.")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Add or replace keys. Additive unless --replace is given.

    A bare KEY prompts without echo, which is the form to prefer: a value passed
    as KEY=value is visible in shell history and, briefly, to `ps`.
    """
    values: dict[str, str] = {}
    if args.stdin:
        text = sys.stdin.read()
        values.update(passbook.parse_env_text(text))
        if not values:
            return _fail("Nothing on stdin looked like KEY=value.")
    for item in args.pairs:
        if "=" in item:
            key, _, value = item.partition("=")
            values[key.strip()] = value.strip()
            continue
        key = item.strip()
        if not sys.stdin.isatty():
            return _fail(
                f"No value given for {key}.",
                f"Pass {key}=value, or run this on a terminal to be prompted.",
            )
        try:
            entered = getpass.getpass(f"{key}: ")
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return _fail("Cancelled; nothing was written.")
        if not entered.strip():
            return _fail(f"No value given for {key}; nothing was written.")
        values[key] = entered.strip()

    if not values:
        return _fail("Nothing to add.", "Usage: passbook-add KEY=value | passbook-add KEY")
    # Adding a key and changing one are different questions, so they are asked
    # separately: a machine that wants to be told before a credential CHANGES
    # usually does not want a dialog for every new one.
    held = set(passbook.key_names())
    fresh = [k for k in values if k not in held]
    existing = [k for k in values if k in held]
    who = caller("passbook-add", args)
    if fresh and not _confirm_change("add", fresh, reason="add a new credential", app=who):
        return 1
    if existing and args.replace and not _confirm_change(
            "modify", existing, reason="replace an existing credential", app=who):
        return 1
    try:
        result = _write_values(values, overwrite=args.replace, app=who)
        if result is None:
            return 1
    except passbook.ContainerisedHomeError as error:
        return _fail(str(error))
    except ValueError as error:
        return _fail(str(error))

    for name, label in (("added", "added"), ("updated", "replaced"), ("kept", "already set, unchanged")):
        if result[name]:
            print(f"{label}: {', '.join(result[name])}")
    if result["kept"] and not args.replace:
        sys.stdout.flush()
        print("\nPass --replace to overwrite a key another app may be using.", file=sys.stderr)
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    """Delete keys. The one operation that can break another app on this box."""
    if not _confirm_change("delete", args.keys, reason="remove a credential",
                           app=caller("passbook-delete", args)):
        return 1
    try:
        result = passbook.remove_values(args.keys)
    except passbook.ContainerisedHomeError as error:
        return _fail(str(error))
    if result["removed"]:
        print(f"removed: {', '.join(result['removed'])}")
    if result["absent"]:
        print(f"not in the store: {', '.join(result['absent'])}")
    return 0


def _sealed_run(command: list[str], who: str, args: argparse.Namespace) -> int | None:
    """Run under a grant, with the child's output scrubbed as it streams.

    Returns None when this machine has no reason to — no grants installed, no
    guarded key in the store, and reads left open — in which case `run` execs
    the child directly as it always has. Filtering a stream costs a pipe and two
    threads where an exec costs nothing, and imposing that on a machine that has
    not asked for the guarantee would be paying for a promise nobody made.

    When it does apply, the child still gets real values: this changes where the
    output goes, not what the process holds. `printenv` returns markers, and
    `wrangler deploy` deploys.
    """
    try:
        import passbook_access as access
        import passbook_broker
        import passbook_grant
    except ImportError:
        return None

    policy = access.read_policy()
    sealed = passbook_broker.reads_mode(policy) == "sealed"
    guarded = set(passbook_grant.guarded(policy))
    wanted = list(args.only or []) or passbook.key_names()
    involved = guarded.intersection(wanted)
    if not sealed and not involved:
        return None
    if not passbook_broker.running():
        # Without a broker there is nobody to hold the values on our behalf, and
        # doing it here would mean this process reads them — which is the thing
        # sealed mode exists to stop. Saying so beats running the command with
        # no credentials and letting it fail as an auth error.
        return _fail("This machine seals credential reads, but no broker is running.",
                     "Start one:  passbook broker start")

    # The broker spawns the child and keeps the values. We get bytes it has
    # already scrubbed, which is why this is a socket round trip rather than the
    # `os.execvpe` below: an exec would need the values in THIS process first.
    answer = passbook_broker.spawn_streaming(
        command, wanted, app=who, reason=f"run {Path(command[0]).name}",
        project=passbook.project())
    if answer is None:
        return _fail("The broker did not answer.", "Check it:  passbook broker start")
    if not answer.get("ok"):
        return _fail(answer.get("error", "could not run it"))
    begin = answer.get("begin") or {}
    for key, why in (begin.get("why") or {}).items():
        print(f"note: {key} was withheld — {why}", file=sys.stderr)
    unscrubbed = [name for name, ok in (begin.get("redacted") or {}).items() if not ok]
    if unscrubbed:
        # Saying so beats implying a completeness that is not there. A value
        # under six characters cannot be searched for without wrecking the
        # output, and the person running this should hear it from us rather
        # than discover it in a log.
        print(f"note: {', '.join(sorted(unscrubbed))} "
              f"{'is' if len(unscrubbed) == 1 else 'are'} too short to redact from output.",
              file=sys.stderr)
    return int(answer.get("exit_code") or 0)


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command with the store loaded as a base. The process env wins."""
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        return _fail("Nothing to run.", "Usage: passbook-run -- your-command --flags")
    who = caller("passbook-run", args)
    sealed = _sealed_run(command, who, args)
    if sealed is not None:
        return sealed
    _use_broker_for_sealed_values(who, f"run {Path(command[0]).name}")
    child = dict(_store_values())
    if args.only:
        # Named keys only. `run` handing over the whole store was the reason an
        # app that needed three credentials held three hundred, and every one of
        # those was a key some dependency could read, log or ship in a crash
        # report. The default stays "everything" for compatibility; this is how
        # a caller says what it actually needs.
        keep = set(args.only)
        child = {name: value for name, value in child.items()
                 if name in keep or name not in set(passbook.key_names())}
    # `load()` merges the process environment, so an empty result never happens.
    # The question that matters is whether the STORE's own keys resolved: if it
    # lists keys and not one of them came back, the vault is shut rather than the
    # machine being empty. Saying so here saves the child failing later with an
    # auth error that names the wrong problem.
    stored = passbook.key_names()
    if stored and not any(child.get(name) for name in stored):
        print("The credential store is encrypted and locked; running without it.", file=sys.stderr)
        print("Sign in first:  passbook signin", file=sys.stderr)
    child.update({key: value for key, value in os.environ.items() if value})
    # Hand the name down. Whatever this runs may call PassBook itself — a test
    # script asking for one key, a tool that shells out — and those reads belong
    # to whoever asked for this environment, not to `passbook-run`. Set after
    # the merge so an explicit --app beats an inherited variable.
    child["PASSBOOK_APP"] = who
    # Windows has no exec. `os.execvpe` is emulated there by spawning and
    # exiting, so this process returns before the child has written anything
    # and whoever captured our output gets an empty string and a success code.
    # Wait for it instead, and hand its exit code back as our own.
    if os.name == "nt":
        try:
            return subprocess.run(command, env=child).returncode
        except FileNotFoundError:
            return _fail(f"{command[0]}: command not found")
    try:
        os.execvpe(command[0], command, child)
    except FileNotFoundError:
        return _fail(f"{command[0]}: command not found")
    except OSError as error:
        return _fail(f"Could not run {command[0]}: {error}")
    return 0  # unreachable; execvpe replaces this process


def _refusals(keys: list[str], app: str) -> dict[str, str]:
    """Which of these the policy refuses, and in whose words.

    A key that is present, unsealed, and still did not arrive was REFUSED, and
    that is a third state beside "encrypted" and "missing". Reporting it as
    either sends the reader to the wrong repair: `passbook signin` unlocks
    nothing that was not locked, and `passbook add` overwrites a credential that
    was never gone. The reason is already computed by the thing that refused it,
    so it is quoted rather than guessed at.
    """
    try:
        import passbook_access as access
        import passbook_broker
    except ImportError:
        return {}
    # A bound is something the BROKER enforces. With none running, a caller
    # reads the file and the policy is not in the path at all — so reporting a
    # refusal here would be describing a machine other than this one.
    try:
        if not passbook_broker.running():
            return {}
    except Exception:  # noqa: BLE001
        return {}
    try:
        policy = access.read_policy()
        project = passbook.project()
    except Exception:  # noqa: BLE001 — a policy we cannot read refuses nothing
        return {}
    found = {}
    for key in keys:
        try:
            verdict = access.decide_key(app, key, policy, project=project)
        except Exception:  # noqa: BLE001
            continue
        if verdict.get("outcome") == "refuse":
            found[key] = str(verdict.get("why") or "refused by this machine's policy")
    return found


def _report_withheld(absent: list[str], app: str) -> None:
    """Say which of three things happened to each key that did not arrive."""
    held = set(passbook.key_names())
    gone = [key for key in absent if key not in held]
    present = [key for key in absent if key in held]
    refused = _refusals(present, app)
    locked = [key for key in present if key not in refused]

    if gone:
        print(f"Not in this store: {', '.join(gone)}", file=sys.stderr)
        print(f"Add with:  passbook add {gone[0]}", file=sys.stderr)
    for key, why in refused.items():
        print(f"Refused: {key} — {why}", file=sys.stderr)
    if refused:
        print("See:  passbook group list", file=sys.stderr)
    if locked:
        print(f"In the store but encrypted: {', '.join(locked)}", file=sys.stderr)
        print("Sign in to read them:  passbook signin", file=sys.stderr)


def _sealed_refusal(keys: list[str]) -> str:
    """Why these keys may not be printed, or "" if they may.

    Two reasons, and they read differently on purpose. A guarded key is refused
    on a machine that is otherwise wide open, because somebody bound that
    specific key and meant it. Sealed reads refuse everything, because somebody
    decided this machine does not hand values to callers it did not start.
    """
    try:
        import passbook_access as access
        import passbook_broker
        import passbook_grant
    except ImportError:
        return ""
    if os.environ.get(passbook_grant.GRANT_ENV):
        # Already inside a grant: this process was given these on purpose and
        # printing them changes nothing about where they have got to.
        return ""
    policy = access.read_policy()
    guarded = set(passbook_grant.guarded(policy)).intersection(keys)
    if guarded:
        return (f"{', '.join(sorted(guarded))} "
                f"{'is' if len(guarded) == 1 else 'are'} guarded and never printed.")
    if passbook_broker.reads_mode(policy) == "sealed":
        return "This machine does not print credential values."
    return ""


def cmd_get(args: argparse.Namespace) -> int:
    """Named values, as JSON, for a script that cannot ask the broker itself.

    Deliberately named keys rather than "everything": a script that says what it
    needs leaves a receipt that says the same, and gets held to a policy that
    can be written about it. `run` fills a whole environment because it has to;
    this does not.
    """
    wanted = [key.strip() for key in args.keys if key.strip()]
    if not wanted:
        return _fail("Which keys?", "Usage: passbook get --json KEY [KEY …]")
    blocked = _sealed_refusal(wanted)
    if blocked:
        return _fail(blocked, "Run what needs it instead:  passbook run -- <command>")
    granted = passbook.request(wanted, app=caller("passbook-get", args),
                               reason=args.reason or "read by a script")
    if args.json:
        print(json.dumps(granted, indent=2 if args.pretty else None))
    else:
        for key in wanted:
            if key in granted:
                print(f"{key}={granted[key]}")
    absent = [key for key in wanted if key not in granted]
    if absent:
        # Same three answers as `check`. "Not available" over a key that is
        # present but shut sends a reader off to re-create a credential that
        # was never gone.
        _report_withheld(absent, caller("passbook-get", args))
        return 1
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """Key names. Safe to paste anywhere."""
    names = passbook.key_names()
    if args.json:
        print(json.dumps(names, indent=2))
    else:
        for name in names:
            print(name)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state = passbook.status()
    if args.json:
        print(json.dumps(state, indent=2))
        return 0 if not state["home_is_container"] else 1
    print(passbook.describe())
    print(f"workspace: {state['workspace'] or 'main'}")
    if state["workspaces"]:
        print(f"workspaces: {', '.join(state['workspaces'])}")
    if not state["inherits_machine_store"]:
        print("this workspace does not inherit the machine store")
    if state["writes_to"] != state["path"]:
        print(f"writes to: {state['writes_to']}")
    # The vault is the current answer; the v1 module only knows about its own
    # sealing and would call a v2-sealed value "plaintext on disk".
    vault_module = _vault()
    if vault_module is not None:
        vault_state = vault_module.status()
        print(f"at rest: {vault_state['detail']}")
        if vault_state["profiles"]:
            import passbook_broker

            live = passbook_broker.vault_status()
            print(f"vault: {'open' if live.get('unlocked') else 'locked'}"
                  f" ({len(vault_state['profiles'])} profile"
                  f"{'' if len(vault_state['profiles']) == 1 else 's'})")
    else:
        try:
            import passbook_seal

            print(f"at rest: {passbook_seal.status()['detail']}")
        except ImportError:
            pass
    # Whether the optional half is usable is the question `status` is asked
    # right before someone tries to seal or link and finds out the hard way.
    ready = _has_crypto(sys.executable)
    print(f"sealing and linking: {'ready' if ready else 'not set up — run `passbook install`'}")

    # `uv tool install` and `pipx install` put the commands on PATH and run
    # nothing, so an install that never went through `passbook install` or the
    # app has told no agent that any of this exists. Said here rather than fixed
    # here: writing into a person's ~/.claude/CLAUDE.md as a side effect of
    # asking for status is the kind of thing that makes people stop trusting a
    # tool, and this is the command they run to find out what is wrong.
    brief = _brief()
    if brief is not None:
        try:
            unbriefed = [entry for entry in brief.status() if not entry["current"]]
        except Exception:  # noqa: BLE001 — a status line must not be able to fail
            unbriefed = []
        if unbriefed:
            names = ", ".join(entry["label"] for entry in unbriefed[:4])
            more = f" and {len(unbriefed) - 4} more" if len(unbriefed) > 4 else ""
            print(f"agents:    {len(unbriefed)} not briefed ({names}{more})")
            print("           they will report a sealed key as missing:  passbook brief install")

    # A duplicate makes two readers disagree about one key, so say so here —
    # with the fix, not just the complaint.
    duplicates = passbook.duplicate_keys()
    if duplicates:
        if getattr(args, "repair", False):
            result = passbook.drop_duplicate_lines()
            print(result["detail"])
        else:
            for key, where in sorted(duplicates.items()):
                print(f"duplicate: {key} on lines {', '.join(str(n) for n in where)}"
                      f" — readers that take the first match see line {where[0]}")
            print("Fix with:  passbook status --repair")
    if state["home_is_container"]:
        return _fail(f"\n{state['detail']}")
    return 0


def cmd_access(args: argparse.Namespace) -> int:
    """Who read which key. Names, times and apps — never values."""
    try:
        import passbook_stamp
    except ImportError:
        return _fail("Access stamping is not installed on this machine.")
    verification = passbook_stamp.verify_chain()
    if args.verify:
        print(verification["detail"])
        return 0 if verification["ok"] else 1
    for row in passbook_stamp.read_stamps(limit=args.limit):
        keys = ", ".join(row.get("keys") or []) or "—"
        # `ask` is a question, and the verdict is its own row a moment later.
        # Marking it DENIED would read as two refusals for one request.
        flag = "" if row.get("granted", True) or row.get("op") == "ask" else "  DENIED"
        print(f"{row.get('at', '?')}  {row.get('app', '?'):<28} {row.get('op', '?'):<10} {keys}{flag}")
    print(f"\n{verification['detail']}")
    return 0 if verification["ok"] else 1


def _vault():
    try:
        import passbook_vault

        return passbook_vault
    except ImportError:
        return None


def _vault_or_fail():
    module = _vault()
    if module is None:
        return None
    ok, why = module.available()
    if not ok:
        print(f"The vault needs a runtime that setup has not provided yet ({why}).", file=sys.stderr)
        print("Run:  passbook install", file=sys.stderr)
        return None
    return module


def _ask_password(prompt: str = "Vault password: ", *, confirm: bool = False,
                  from_stdin: bool = False) -> str:
    """Read a password without echoing it, and never from argv.

    A password on a command line lands in the shell history, in `ps` output, and
    in any process listing anyone on the machine can read, so there is no flag
    here that takes one — only `--password-stdin`, which is how the app and any
    other caller hands one over out of sight.
    """
    if from_stdin:
        supplied = sys.stdin.readline().rstrip("\n")
        if not supplied:
            raise ValueError("No password arrived on stdin")
        return supplied
    first = getpass.getpass(prompt)
    if not confirm:
        return first
    again = getpass.getpass("Again: ")
    if first != again:
        raise ValueError("Those did not match")
    return first


def _open_vault(module, profile: str, *, from_stdin: bool = False,
                workspace: str = "") -> tuple[bytes, str] | None:
    """Get a data key for a maintenance command, by asking the person running it."""
    root = module.workspace_root(workspace) if workspace else None
    profile = profile or module.active_profile_id(root=root)
    if not profile:
        print("There is no profile yet.", file=sys.stderr)
        print("Run:  passbook profile create <name>", file=sys.stderr)
        return None
    try:
        password = _ask_password(from_stdin=from_stdin)
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return None
    try:
        return module.unlock_with_password(profile, password, root=root), profile
    except module.VaultError as error:
        print(str(error), file=sys.stderr)
        return None


def cmd_seal(args: argparse.Namespace) -> int:
    module = _vault_or_fail()
    if module is None:
        return _fail("Encryption at rest is not installed on this machine.", "Run:  passbook install")

    if args.status:
        state = module.status()
        if getattr(args, "json", False):
            print(json.dumps(state, indent=2))
            return 0
        print(state["detail"])
        for profile in state["profiles"]:
            marker = "*" if profile["active"] else " "
            print(f"  {marker} {profile['label']}  ({', '.join(profile['kinds']) or 'no factors'})")
        return 0

    if not module.profiles():
        return _fail("There is no profile to seal under.",
                     "Run:  passbook profile create <name>")
    opened = _open_vault(module, getattr(args, "profile", ""),
                         from_stdin=getattr(args, "password_stdin", False))
    if opened is None:
        return 1
    dek, profile = opened
    result = module.seal_store(dek, profile_id=profile, skip=getattr(args, "skip", []) or [])
    print(result.get("detail", ""))
    if result.get("skipped"):
        print(f"Left readable: {', '.join(result['skipped'])}")
    if result.get("ok") and result.get("sealed"):
        print("Values are now unreadable until something signs in.")
        print("Undo with:  passbook unseal")
    return 0 if result.get("ok") else 1


def cmd_secure(args: argparse.Namespace) -> int:
    """Turn this machine's store from readable to signed-in, in one step.

    Creating a profile, sealing, starting a broker and signing in are four
    commands that are never useful apart, and asking for the same password four
    times is how a security feature earns a reputation for being annoying. This
    is the whole thing, once.
    """
    module = _vault_or_fail()
    if module is None:
        return _fail("The vault is not installed on this machine.", "Run:  passbook install")
    import passbook_broker

    existing = module.profiles()
    names = passbook.key_names()
    if not names:
        return _fail("There is nothing in the store to secure.")

    skip = list(module.DEFAULT_SKIP) + list(getattr(args, "skip", []) or [])
    exposed = sorted(n for n in names if module.matches_skip(n, skip))

    print(f"{len(names)} key(s) in {passbook.env_path()}")
    if exposed:
        print(f"{len(exposed)} will stay readable — they are compiled into client")
        print("code or read before sign-in, so encrypting them protects nothing:")
        for name in exposed:
            print(f"   {name}")
    print()

    if existing:
        profile = args.profile or module.active_profile_id()
        print(f"Signing in to {next((p['label'] for p in existing if p['id'] == profile), profile)}.")
        opened = _open_vault(module, profile, from_stdin=getattr(args, "password_stdin", False))
        if opened is None:
            return 1
        dek, profile = opened
        password = None
    else:
        print("Choose a password for this machine's vault. It is the only thing")
        print("that opens these credentials, and nothing else on this machine")
        print("stores it — so pick something you will not lose.")
        try:
            password = _ask_password("New vault password: ", confirm=True,
                                     from_stdin=getattr(args, "password_stdin", False))
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        except ValueError as error:
            return _fail(str(error))
        try:
            made = module.create_profile(args.profile_name or "Owner", password=password)
        except module.VaultError as error:
            return _fail(str(error))
        profile = made["id"]
        dek = module.unlock_with_password(profile, password)
        print(f"Created profile {made['label']}.")

    result = module.seal_store(dek, profile_id=profile, skip=skip)
    if not result.get("ok"):
        return _fail(result.get("detail", "Sealing failed."))
    print(result["detail"])

    started = passbook_broker.start()
    if not started.get("ok"):
        print("The broker would not start, so nothing can read the store yet.", file=sys.stderr)
        print(f"Start it by hand:  passbook broker start   ({started.get('detail', '')})", file=sys.stderr)
        return 1
    if password is None:
        print("Now sign in so apps can read it again:  passbook signin")
        return 0
    answer = passbook_broker.signin(profile=profile, password=password, duration=args.duration)
    if not answer.get("ok"):
        print(f"Sealed, but signing in failed: {answer.get('error', '')}", file=sys.stderr)
        print("Try:  passbook signin", file=sys.stderr)
        return 1
    print(answer.get("detail", "Signed in."))
    print()
    print("Done. The store is encrypted and apps read it through the broker.")
    print("  passbook signout   lock it now")
    print("  passbook unseal    put everything back in the clear")
    return 0


def cmd_unseal(args: argparse.Namespace) -> int:
    """The way back. A security feature you cannot reverse is one people refuse."""
    module = _vault_or_fail()
    if module is None:
        return _fail("The vault is not installed on this machine.", "Run:  passbook install")
    opened = _open_vault(module, getattr(args, "profile", ""),
                         from_stdin=getattr(args, "password_stdin", False))
    if opened is None:
        return 1
    dek, profile = opened
    result = module.unseal_store(dek, profile_id=profile, only=getattr(args, "only", []) or [])
    print(result.get("detail", ""))
    if result.get("opened") and getattr(args, "only", None):
        print("They will stay readable through future seals.")
    if result.get("absent"):
        print(f"Not in this store: {', '.join(result['absent'])}", file=sys.stderr)
    if result.get("stuck"):
        print(f"Still sealed: {', '.join(result['stuck'])}", file=sys.stderr)
        print("Those were sealed under a different profile.", file=sys.stderr)
    return 0 if result.get("ok") else 1


def cmd_profile(args: argparse.Namespace) -> int:
    module = _vault_or_fail()
    if module is None:
        return _fail("The vault is not installed on this machine.", "Run:  passbook install")
    where = getattr(args, "workspace", "") or ""
    listed = module.profiles(root=module.workspace_root(where) if where else None)
    if getattr(args, "json", False):
        print(json.dumps(listed, indent=2))
        return 0
    if not listed:
        print("No profiles yet.")
        print("Create one with:  passbook profile create <name>")
        return 0
    for profile in listed:
        marker = "*" if profile["active"] else " "
        factors = ", ".join(f"{f['kind']}:{f['label']}" for f in profile["factors"])
        print(f" {marker} {profile['label']}")
        print(f"     {factors or 'no factors'}")
    return 0


def cmd_profile_create(args: argparse.Namespace) -> int:
    module = _vault_or_fail()
    if module is None:
        return _fail("The vault is not installed on this machine.", "Run:  passbook install")
    try:
        password = _ask_password("New vault password: ", confirm=True,
                                 from_stdin=getattr(args, "password_stdin", False))
    except (EOFError, KeyboardInterrupt):
        print()
        return 1
    except ValueError as error:
        return _fail(str(error))
    where = getattr(args, "workspace", "") or ""
    try:
        # A workspace's key lives beside its own store. Naming one here is how a
        # workspace stops sharing the machine's vault and gets its own.
        root = module.workspace_root(where) if where else None
        if root is not None:
            root.mkdir(parents=True, exist_ok=True)
        made = module.create_profile(args.label, password=password, root=root,
                                     make_active=getattr(args, "use", False))
    except module.VaultError as error:
        return _fail(str(error))
    except (OSError, ValueError) as error:
        return _fail(str(error))
    print(f"Created profile {made['label']}" + (f" in {where}." if where else "."))
    if made["active"]:
        print(f"It is now the profile you sign in to.")
    else:
        # Its data key opens nothing that is already sealed, so switching to it
        # is a separate decision with consequences worth seeing first.
        print(f"You are still signed in to whatever you were. To use it:  "
              f"passbook profile use {made['label']}")
    print("Nothing is encrypted yet. Seal the store with:  passbook seal")
    return 0


def cmd_profile_use(args: argparse.Namespace) -> int:
    module = _vault_or_fail()
    if module is None:
        return 1
    wanted = args.label
    match = next((p for p in module.profiles()
                  if p["id"] == wanted or p["label"] == wanted), None)
    if match is None:
        return _fail(f"No such profile: {wanted}")
    module.set_active_profile(match["id"])
    print(f"Active profile is now {match['label']}.")
    return 0


def cmd_profile_remove(args: argparse.Namespace) -> int:
    module = _vault_or_fail()
    if module is None:
        return 1
    match = next((p for p in module.profiles()
                  if p["id"] == args.label or p["label"] == args.label), None)
    if match is None:
        return _fail(f"No such profile: {args.label}")
    if not args.yes:
        print(f"Removing {match['label']} makes everything it sealed unreadable, permanently.")
        print("Re-run with --yes if that is what you want.")
        return 1
    module.remove_profile(match["id"])
    print(f"Removed {match['label']}.")
    return 0


def cmd_profile_device(args: argparse.Namespace) -> int:
    """Let this machine open the vault unattended. Weaker, and says so."""
    module = _vault_or_fail()
    if module is None:
        return 1
    import passbook_keystore

    if not passbook_keystore.available():
        return _fail(f"This machine has {passbook_keystore.describe()}.",
                     "A device factor needs one. Sign in with a password instead.")
    opened = _open_vault(module, getattr(args, "profile", ""),
                         from_stdin=getattr(args, "password_stdin", False))
    if opened is None:
        return 1
    dek, profile = opened
    if not args.yes:
        print("A device factor lets ANY program running as you open the vault")
        print(f"without asking, by way of {passbook_keystore.describe()}.")
        print("It exists so jobs can start at boot. Re-run with --yes to accept that.")
        return 1
    try:
        made = module.add_device_factor(profile, dek=dek)
    except module.VaultError as error:
        return _fail(str(error))
    print(f"This machine can now open the vault unattended ({made['backend']}).")
    return 0


def cmd_vault(args: argparse.Namespace) -> int:
    """Locked or open, which profiles exist, and what the store still exposes.

    One call, because a sign-in screen needs all of it at once and asking three
    commands would let the answers disagree with each other mid-render.
    """
    module = _vault()
    import passbook_broker

    if module is None:
        answer = {"supported": False, "unlocked": False, "profiles": [], "running": False,
                  "detail": "The vault is not installed on this machine."}
    else:
        state = module.status()
        live = passbook_broker.vault_status()
        answer = {
            "supported": state["supported"],
            "running": bool(live.get("running")),
            "unlocked": bool(live.get("unlocked")),
            "signed_in_profile": live.get("profile", ""),
            "factor": live.get("factor", ""),
            "expires_in": live.get("expires_in", 0),
            # How many sealed values the held key opens. "Unlocked" says a key
            # is held; this says whether it is the right one.
            "opens": live.get("opens", 0),
            # Which workspaces have a key held for them right now, so the
            # picker can say which are open without asking one by one.
            "unlocked_workspaces": live.get("unlocked_workspaces", []),
            "workspace": live.get("workspace", ""),
            "profiles": state["profiles"],
            "active": state["active"],
            "sealed": state["sealed"],
            "legacy_v1": state["legacy_v1"],
            "plaintext": state["plaintext"],
            "fully_sealed": state["fully_sealed"],
            "keystore": _keystore_note(),
            "detail": state["detail"],
        }
    if getattr(args, "json", False):
        print(json.dumps(answer, indent=2))
        return 0
    print(answer["detail"])
    if answer.get("supported"):
        print("Vault is open." if answer["unlocked"] else "Vault is locked.")
    return 0


def _keystore_note() -> dict[str, Any]:
    try:
        import passbook_keystore

        return {"available": passbook_keystore.available(),
                "describe": passbook_keystore.describe(),
                "backend": passbook_keystore.backend()}
    except ImportError:
        return {"available": False, "describe": "not installed", "backend": ""}


def cmd_passkey(args: argparse.Namespace) -> int:
    """List the passkeys that can open a profile."""
    module = _vault_or_fail()
    if module is None:
        return 1
    listed = module.profiles()
    if getattr(args, "json", False):
        print(json.dumps([{"profile": p["label"],
                           "passkeys": [f for f in p["factors"] if f["kind"] == "passkey"]}
                          for p in listed], indent=2))
        return 0
    for profile in listed:
        keys = [f for f in profile["factors"] if f["kind"] == "passkey"]
        print(f"{profile['label']}: {len(keys)} passkey{'' if len(keys) == 1 else 's'}")
        for factor in keys:
            print(f"   {factor['label']}  added {factor['created_at']}")
    return 0


def cmd_passkey_enrol(args: argparse.Namespace) -> int:
    """Wrap the data key with a passkey's PRF output.

    The PRF secret arrives on stdin, base64url, because it is key material and
    an argument would put it in every process listing on the machine. It is used
    once and never stored — storing it would make the ceremony decorative.

    The ceremony itself belongs in a browser: HivemindOS and Hivemind Content
    Studio already run one, and WebAuthn's PRF extension returns the same 32
    bytes for the same credential and salt on macOS, Windows, Linux and iOS.
    That is why the passkey factor is portable while an OS keystore is not.
    """
    module = _vault_or_fail()
    if module is None:
        return 1
    supplied = sys.stdin.readline().strip()
    if not supplied:
        return _fail("No PRF secret arrived on stdin.",
                     "Pipe the base64url PRF output from the WebAuthn ceremony.")
    try:
        prf = base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4))
    except Exception:  # noqa: BLE001
        return _fail("That is not base64url.")
    where = getattr(args, "workspace", "") or ""
    opened = _open_vault(module, getattr(args, "profile", ""), workspace=where,
                         from_stdin=getattr(args, "password_stdin", False))
    if opened is None:
        return 1
    dek, profile = opened
    try:
        made = module.add_passkey_factor(
            profile, dek=dek, credential_id=args.credential_id, prf_secret=prf,
            label=args.label or "passkey", rp_id=args.rp_id,
            root=module.workspace_root(where) if where else None)
    except module.VaultError as error:
        return _fail(str(error))
    print(f"Enrolled {made['label']}. It can now open this profile on any device it syncs to.")
    return 0


def _oauth():
    try:
        import passbook_oauth

        return passbook_oauth
    except ImportError:
        return None


def cmd_oauth(args: argparse.Namespace) -> int:
    """Every sign-in this machine holds, and whether it still works."""
    module = _oauth()
    if module is None:
        return _fail("Sign-ins are not installed on this machine.", "Run:  passbook install")
    listed = module.describe()
    if getattr(args, "json", False):
        print(json.dumps(listed, indent=2))
        return 0
    if not listed:
        print("No sign-ins yet.")
        print("Add one with:  passbook oauth add google --client-id <id>")
        return 0
    for entry in listed:
        marker = {"connected": " ", "expiring": "!", "expired": "!",
                  "no-refresh": "!", "disconnected": "x"}.get(entry["state"], " ")
        print(f" {marker} {entry['id']}")
        print(f"     {entry['detail']}")
    return 0


def cmd_oauth_add(args: argparse.Namespace) -> int:
    module = _oauth()
    if module is None:
        return 1
    secret = ""
    if args.client_secret_stdin:
        secret = sys.stdin.readline().strip()
        if not secret:
            return _fail("No client secret arrived on stdin.")
    try:
        made = module.add_grant(
            args.provider, args.label, client_id=args.client_id, client_secret=secret,
            authorize_url=args.authorize_url, token_url=args.token_url,
            scope=args.scope, key_prefix=args.key_prefix, redirect_port=args.redirect_port)
    except module.GrantError as error:
        return _fail(str(error))
    print(f"Added {made['id']}.")
    print("Its tokens will live in this store as:")
    for role, name in sorted(made["keys"].items()):
        print(f"   {name}   ({role.replace('_', ' ')})")
    print(f"\nConnect it with:  passbook oauth connect {made['id']}")
    return 0


def cmd_oauth_connect(args: argparse.Namespace) -> int:
    """Open the provider's sign-in page and catch the callback."""
    module = _oauth()
    if module is None:
        return 1
    try:
        grant = module.find_grant(args.id)
    except module.GrantError as error:
        return _fail(str(error))

    port = args.port or int(grant.get("redirect_port") or 0)
    try:
        server, actual_port = _callback_server(port)
    except OSError as error:
        return _fail(f"Could not listen for the callback: {error}",
                     "Another process may already own that port — a vendor CLI mid-login, usually.")
    redirect_uri = f"http://localhost:{actual_port}{_CALLBACK_PATH}"
    started = module.authorize_url(args.id, redirect_uri=redirect_uri)

    print(f"Opening {grant['provider']} to sign in.")
    print("If a browser does not open, paste this:\n")
    print(f"  {started['url']}\n")
    if not args.no_browser:
        import webbrowser

        webbrowser.open(started["url"])

    print(f"Waiting for the callback on {redirect_uri} …")
    # This command then blocks on a person. Anyone piping it to a log would see
    # nothing at all until it finished, including the URL they were meant to
    # paste, so the buffer has to go out now rather than at exit.
    sys.stdout.flush()
    result = _await_callback(server, expect_state=started["state"], timeout=args.timeout)
    if not result.get("code"):
        return _fail(result.get("error") or "No authorization code arrived.",
                     "Nothing was stored. Run the command again to retry.")
    try:
        module.complete_login(args.id, code=result["code"], verifier=started["verifier"],
                              redirect_uri=redirect_uri)
    except module.GrantError as error:
        return _fail(str(error))
    print(f"Connected {args.id}.")
    print("Agents reading its access token now get a live one; the broker renews it.")
    return 0


_CALLBACK_PATH = "/auth/callback"


def _callback_server(port: int):
    """A loopback listener that answers on IPv4 *and* IPv6.

    `localhost` resolves to ::1 first on macOS, so a server bound only to
    127.0.0.1 is never reached and the login hangs on a page that never loads.
    Binding a dual-stack socket and then refusing anything that is not loopback
    keeps the reach identical while actually working.
    """
    import http.server
    import socket

    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET
        allow_reuse_address = True
        captured: dict = {}

        def server_bind(self):
            if self.address_family == socket.AF_INET6:
                try:
                    self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            super().server_bind()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):  # noqa: D102 — no request logging, ever
            pass

        def do_GET(self):  # noqa: N802
            client = self.client_address[0]
            if client not in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}:
                self.send_error(403, "loopback only")
                return
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != _CALLBACK_PATH:
                self.send_error(404)
                return
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            self.server.captured.update(query)
            body = (b"<!doctype html><meta charset=utf-8>"
                    b"<title>PassBook</title>"
                    b"<body style='font:15px system-ui;padding:3rem'>"
                    b"<h1>Signed in.</h1><p>You can close this tab and go back to your terminal.</p>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # A dual-stack bind on :: succeeds even when another process already owns
    # the IPv4 loopback for this port — they are different addresses. The login
    # would then appear to start, and a browser that resolved `localhost` to
    # 127.0.0.1 would hand the authorization code to whatever that other process
    # is. Refusing beats half-listening.
    if port:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(1.0)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise OSError(f"port {port} is already served on 127.0.0.1 by another process")
        finally:
            probe.close()

    host = "::" if (socket.has_ipv6 and Server.address_family == socket.AF_INET6) else "0.0.0.0"
    server = Server((host, port), Handler)
    return server, server.server_address[1]


def _await_callback(server, *, expect_state: str, timeout: float) -> dict:
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if server.captured:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        return {"error": "Cancelled."}
    finally:
        server.shutdown()
        server.server_close()

    captured = dict(server.captured)
    if not captured:
        return {"error": f"Nothing arrived within {int(timeout)}s."}
    if captured.get("error"):
        return {"error": f"{captured['error']}: {captured.get('error_description', '')}".strip(": ")}
    if captured.get("state") != expect_state:
        # The state is the only thing tying this callback to the request we
        # made. A mismatch means it belongs to a different login, so it is not
        # ours to use.
        return {"error": "The callback did not match this login. Nothing was stored."}
    return {"code": captured.get("code", "")}


def cmd_oauth_refresh(args: argparse.Namespace) -> int:
    module = _oauth()
    if module is None:
        return 1
    try:
        grant = module.find_grant(args.id)
        keys = module.grant_keys(grant)
        values = module.token_values(grant, app="passbook-cli")
        fresh = module.exchange_refresh(grant, values.get(keys["refresh_token"], ""))
    except module.GrantError as error:
        return _fail(str(error), "Sign in again:  passbook oauth connect " + args.id)
    passbook.set_values(fresh, overwrite=True)
    state = module.status(grant, module.token_values(grant, app="passbook-cli"))
    print(f"Renewed {grant['id']}. {state['detail']}")
    return 0


def cmd_oauth_remove(args: argparse.Namespace) -> int:
    module = _oauth()
    if module is None:
        return 1
    if not args.yes:
        print(f"Removing {args.id} forgets its tokens; you would have to sign in again.")
        print("Re-run with --yes if that is what you want.")
        return 1
    try:
        gone = module.remove_grant(args.id, forget_tokens=not args.keep_tokens)
    except module.GrantError as error:
        return _fail(str(error))
    print(f"Removed {gone['removed']}." + (f" Forgot {len(gone['forgot'])} key(s)." if gone["forgot"] else ""))
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Speak MCP on stdio, so any agent can find these credentials."""
    try:
        import passbook_mcp
    except ImportError:
        return _fail("MCP support is not installed on this machine.", "Run:  passbook install")
    return passbook_mcp.serve()


def _catalog():
    try:
        import passbook_catalog

        return passbook_catalog
    except ImportError:
        return None


def cmd_group(args: argparse.Namespace) -> int:
    """How the store is arranged, and what it suggests arranging."""
    catalog = _catalog()
    if catalog is None:
        return _fail("Grouping is not installed on this machine.", "Run:  passbook install")
    import passbook_access as access

    policy = access.read_policy()
    names = passbook.key_names()
    arranged = catalog.groups(names, policy)
    if getattr(args, "json", False):
        print(json.dumps(arranged, indent=2))
        return 0
    loose = arranged.get(catalog.UNGROUPED, [])
    named = {g: m for g, m in arranged.items() if g != catalog.UNGROUPED}
    for group, members in named.items():
        print(f"{group}  ({len(members)})")
        if args.verbose:
            for name in members:
                print(f"    {name}")
    if loose:
        print(f"\n{catalog.UNGROUPED}  ({len(loose)})")
        if args.verbose:
            for name in loose:
                print(f"    {name}")
    print(f"\n{len(names)} keys in {len(named)} groups"
          + (f", {len(loose)} ungrouped" if loose else ""))
    return 0


def cmd_group_set(args: argparse.Namespace) -> int:
    catalog = _catalog()
    if catalog is None:
        return 1
    import passbook_access as access

    policy = access.read_policy()
    held = set(passbook.key_names())
    missing = [k for k in args.keys if k not in held]
    if missing:
        return _fail(f"Not in this store: {', '.join(missing)}")
    for key in args.keys:
        catalog.set_group(key, args.group, policy)
    access.write_policy(policy)
    where = args.group or "inferred from the name"
    print(f"{len(args.keys)} key(s) -> {where}")
    return 0


def _umbrella_policy():
    import passbook_access as access
    return access, access.read_policy()


def _show_umbrella(record: dict, policy=None) -> None:
    reach = "every project" if record["reach"] == "everyone" else "its own projects"
    seen = "agents can see it" if record["listed"] else "not shown to agents"
    print(f"{record['label']}  ({reach}, {seen})")
    if record["tags"]:
        print(f"    tags:     {', '.join(record['tags'])}")
    if record["note"]:
        print(f"    note:     {record['note']}")
    if record["projects"]:
        print(f"    projects: {', '.join(record['projects'])}")
    elif record["reach"] != "everyone":
        print("    projects: none yet — so nothing can read its keys")
    if policy is not None:
        import passbook_access as access
        held = access.umbrella_keys(record["id"], policy)
        print(f"    keys:     {len(held)}" + (f"  ({', '.join(held[:4])}"
              + (" ..." if len(held) > 4 else "") + ")" if held else ""))


def _warn_conflicts(access, record, policy) -> None:
    """Say where another bound already refuses what this umbrella promises."""
    try:
        import passbook
        here = passbook.workspace()
    except Exception:  # noqa: BLE001
        here = ""
    clashes = access.umbrella_conflicts(record["id"], policy, workspace=here)
    if not clashes:
        return
    # stderr is unbuffered and stdout is not, so without this the warning
    # arrives above the thing it is warning about.
    sys.stdout.flush()
    print("\nThese will not do what this umbrella says:", file=sys.stderr)
    for clash in clashes:
        print(f"  {clash['why']}", file=sys.stderr)


def cmd_umbrella(args: argparse.Namespace) -> int:
    """Every umbrella, what it covers, and how far it reaches."""
    access, policy = _umbrella_policy()
    records = sorted(access.read_umbrellas(policy).values(), key=lambda r: r["id"])
    if getattr(args, "json", False):
        print(json.dumps([{**r, "keys": access.umbrella_keys(r["id"], policy)}
                          for r in records], indent=2))
        return 0
    if not records:
        print("No umbrellas yet.  passbook umbrella new \"<name>\"")
        return 0
    for record in records:
        _show_umbrella(record, policy)
    return 0


def cmd_umbrella_new(args: argparse.Namespace) -> int:
    access, policy = _umbrella_policy()
    try:
        record = access.create_umbrella(
            args.name, policy, tags=args.tag or (), note=args.note or "",
            reach="everyone" if args.everyone else access.DEFAULT_REACH,
            listed=bool(args.listed))
    except ValueError as error:
        return _fail(str(error))
    access.write_policy(policy)
    _show_umbrella(record, policy)
    if record["reach"] != "everyone":
        print(f"\nClosed from now, not from when you finish. Nothing reads its keys until"
              f" it covers a project:\n  passbook umbrella cover {record['id']} <project>")
    return 0


def cmd_umbrella_cover(args: argparse.Namespace) -> int:
    """Put a project under an umbrella."""
    access, policy = _umbrella_policy()
    try:
        record = access.add_umbrella_projects(args.umbrella, args.projects, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    _show_umbrella(record, policy)
    _warn_conflicts(access, record, policy)
    return 0


def cmd_umbrella_uncover(args: argparse.Namespace) -> int:
    access, policy = _umbrella_policy()
    try:
        record = access.remove_umbrella_projects(args.umbrella, args.projects, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    _show_umbrella(record, policy)
    return 0


def cmd_umbrella_add(args: argparse.Namespace) -> int:
    """Put keys under an umbrella. Says what it did to them."""
    access, policy = _umbrella_policy()
    held = set(passbook.key_names())
    missing = [k for k in args.keys if k not in held]
    if missing:
        return _fail(f"Not in this store: {', '.join(missing)}")
    try:
        record = access.put_under_umbrella(args.umbrella, args.keys, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    print(f"{len(args.keys)} key(s) under {record['label']}")
    if record["reach"] == "everyone":
        print("Every project can read them.")
    elif record["projects"]:
        print(f"They now read from {', '.join(record['projects'])} and nowhere else.")
    else:
        print(f"{record['label']} covers no projects, so NOTHING can read them now."
              f"\n  passbook umbrella cover {record['id']} <project>"
              f"\n  passbook umbrella remove {' '.join(args.keys[:3])}"
              f"{' ...' if len(args.keys) > 3 else ''}   # to undo")
    _warn_conflicts(access, record, policy)
    return 0


def cmd_umbrella_remove(args: argparse.Namespace) -> int:
    access, policy = _umbrella_policy()
    freed = access.take_from_umbrella(args.keys, policy)
    if not freed:
        return _fail("None of those were under an umbrella.")
    access.write_policy(policy)
    print(f"Out from under: {', '.join(freed)}")
    return 0


def cmd_umbrella_reach(args: argparse.Namespace) -> int:
    """Who may USE it. Separate from whether agents can see it."""
    access, policy = _umbrella_policy()
    try:
        record = access.set_umbrella_reach(args.umbrella, args.reach, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    _show_umbrella(record, policy)
    return 0


def cmd_umbrella_show_agents(args: argparse.Namespace) -> int:
    """Whether agents are told it exists. Separate from who may use it."""
    access, policy = _umbrella_policy()
    try:
        record = access.set_umbrella_listed(args.umbrella, not args.hide, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    _show_umbrella(record, policy)
    if record["listed"] and record["reach"] != "everyone":
        print("\nAgents can see this umbrella and will be told they may not use it, "
              "which is more useful to them than seeing nothing.")
    return 0


def cmd_umbrella_open(args: argparse.Namespace) -> int:
    """The common corner: every project, and agents can see it."""
    access, policy = _umbrella_policy()
    try:
        access.set_umbrella_reach(args.umbrella, "everyone", policy)
        record = access.set_umbrella_listed(args.umbrella, True, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    _show_umbrella(record, policy)
    return 0


def cmd_umbrella_close(args: argparse.Namespace) -> int:
    """The other corner: its own projects, and not advertised."""
    access, policy = _umbrella_policy()
    try:
        access.set_umbrella_reach(args.umbrella, "members", policy)
        record = access.set_umbrella_listed(args.umbrella, False, policy)
    except ValueError as error:
        return _fail(str(error), "See:  passbook umbrella")
    access.write_policy(policy)
    _show_umbrella(record, policy)
    return 0


def cmd_umbrella_tag(args: argparse.Namespace) -> int:
    access, policy = _umbrella_policy()
    existing = access.umbrella_record(args.umbrella, policy)
    if not existing:
        return _fail(f"there is no umbrella called {args.umbrella!r}", "See:  passbook umbrella")
    wanted = sorted(set(existing["tags"]) | {t for t in (args.tag or []) if t.strip()})
    record = access.set_umbrella_tags(args.umbrella, wanted, policy, note=args.note)
    access.write_policy(policy)
    _show_umbrella(record, policy)
    return 0


def cmd_umbrella_delete(args: argparse.Namespace) -> int:
    access, policy = _umbrella_policy()
    try:
        gone = access.delete_umbrella(args.umbrella, policy)
    except ValueError as error:
        return _fail(str(error))
    if not gone:
        return _fail(f"there is no umbrella called {args.umbrella!r}", "See:  passbook umbrella")
    access.write_policy(policy)
    print(f"{args.umbrella} removed. Its keys are no longer limited by it.")
    return 0


# ── keeping this copy current ───────────────────────────────────────────────
#
# PassBook installs from a git URL, which resolves once and then never moves.
# HivemindOS's setup script made that worse by design: `install_passbook` skips
# when a `passbook` is already on PATH, so a machine set up months ago keeps the
# version it was set up with for as long as it exists, and every later update
# confirms it is "already installed".
#
# The cost is not abstract. A dead end fixed before 1.0.0 — `add` on a sealed
# store sending you to `signin`, which refused because no broker was running —
# was still being hit on a machine whose CLI predated the fix. Nothing on that
# machine could say so: there was no version to print and no way to move.

REPOSITORY = "https://github.com/LiamVisionary/passbook"
RELEASES_API = "https://api.github.com/repos/LiamVisionary/passbook/releases/latest"


def installed_version() -> str:
    """What THIS copy is, from the metadata its installer wrote.

    `importlib.metadata` answers about a distribution on `sys.path`, which is
    not necessarily the one that got imported: run a checkout on a machine that
    also has PassBook installed and it cheerfully reports the installed copy's
    version for code that did not come from it. Reporting a different copy's
    version is worse than reporting none, because it is the number somebody
    will put in a bug report.
    """
    try:
        from importlib.metadata import version

        found = version("passbook")
    except Exception:  # noqa: BLE001 — a checkout has no metadata, and that is fine
        return ""
    # Only trust it when the module actually came from an installed location.
    return found if "site-packages" in str(Path(passbook.__file__).resolve()) else ""


def latest_version(*, timeout: float = 10.0) -> tuple[str, str]:
    """The newest published release, as (version, tag). Empty when unreachable.

    Anonymous: this is a public repository, and a self-update that needed a
    token would be one nobody could run.
    """
    import urllib.request

    try:
        request = urllib.request.Request(
            RELEASES_API, headers={"Accept": "application/vnd.github+json",
                                   "User-Agent": "passbook-update"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 — offline is not an error worth a traceback
        return "", ""
    tag = str(payload.get("tag_name") or "").strip()
    return tag.lstrip("v"), tag


def _as_numbers(text: str) -> tuple:
    parts = []
    for chunk in str(text).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def install_method() -> tuple[str, list[str]]:
    """How this copy got here, and the command that would replace it.

    Asked of the path the module actually loaded from rather than of the
    machine, because a box can have uv AND pipx AND a pip install, and
    upgrading the one this process is not running from would report success
    and change nothing.
    """
    here = str(Path(passbook.__file__).resolve())
    source = os.environ.get("PASSBOOK_SOURCE", f"git+{REPOSITORY}")

    if "/uv/tools/" in here:
        return "uv tool", ["uv", "tool", "install", "--force", source]
    if "/pipx/venvs/" in here:
        return "pipx", ["pipx", "install", "--force", source]
    # The app carries its own copy under `cli/`, beside a private runtime. That
    # one is replaced when the app is, and pip would write into the bundle.
    if f"{os.sep}cli{os.sep}" in here or ".app/Contents/" in here:
        return "bundled with the app", []
    # A checkout on PYTHONPATH is somebody's working copy and `git pull` is its
    # update. Anything that reached site-packages was installed by something and
    # can be replaced in place.
    if "site-packages" not in here:
        return "a checkout", []
    # `uv venv` does not put pip in the environment it makes, so the obvious
    # `python -m pip install --upgrade` fails there with "No module named pip"
    # on exactly the machines most likely to have uv. Ask this interpreter
    # whether it has pip rather than assuming every environment does.
    has_pip = subprocess.run([sys.executable, "-c", "import pip"],
                             capture_output=True).returncode == 0
    if has_pip:
        return "pip", [sys.executable, "-m", "pip", "install", "--upgrade", source]
    if shutil.which("uv"):
        return "uv", ["uv", "pip", "install", "--python", sys.executable, source]
    return "pip", [sys.executable, "-m", "pip", "install", "--upgrade", source]


def cmd_update(args: argparse.Namespace) -> int:
    """Say what this copy is, what the newest one is, and move to it."""
    current = installed_version()
    newest, tag = latest_version()
    method, command = install_method()

    if getattr(args, "json", False):
        print(json.dumps({"installed": current, "latest": newest, "tag": tag,
                          "method": method, "can_update": bool(command),
                          "behind": bool(current and newest
                                         and _as_numbers(current) < _as_numbers(newest))},
                         indent=2))
        return 0

    print(f"installed: {current or 'unknown (installed from a checkout)'}")
    if not newest:
        print("latest:    could not reach GitHub")
    else:
        print(f"latest:    {newest}")
    print(f"installed by: {method}")

    if not newest:
        return _fail("Could not check for a newer version.",
                     f"Update by hand:  uv tool install --force git+{REPOSITORY}")
    if current and _as_numbers(current) >= _as_numbers(newest):
        print("\nThis is the newest release.")
        return 0
    if args.check:
        print(f"\n{newest} is available.  passbook update")
        return 0
    if not command:
        return _fail(
            f"This copy is {method}, so it is not this command's to replace.",
            "Update the app itself; the command line inside it comes with it."
            if "app" in method else
            f"From a checkout:  git pull\nOr install it properly:  uv tool install --force git+{REPOSITORY}")

    # Pinned to the release rather than to the branch: the tag is the build that
    # was tested and published, and `update` that lands on an untested commit is
    # a worse thing to have than no `update` at all.
    pinned = [part if not part.startswith("git+") else f"{part}@{tag}" for part in command]
    print(f"\nUpdating to {newest} ...")
    done = subprocess.run(pinned, capture_output=True, text=True)
    if done.returncode != 0:
        return _fail("The update did not go through.",
                     (done.stderr or done.stdout).strip()[:400]
                     or f"Run it by hand:  {' '.join(pinned)}")
    print(f"Updated to {newest}.")
    return 0


def _brief():
    try:
        import passbook_brief
        return passbook_brief
    except ImportError:
        return None


def _chosen_runtimes(brief, only: str = ""):
    found = brief.detected()
    if not only:
        return found
    wanted = {w.strip().lower() for w in only.split(",") if w.strip()}
    known = {r.id for r in brief.RUNTIMES}
    unknown = wanted - known
    if unknown:
        raise ValueError(f"not a runtime this knows about: {', '.join(sorted(unknown))}\n"
                         f"Known: {', '.join(sorted(known))}")
    # Named explicitly means brief it whether or not it left a footprint —
    # somebody naming a runtime knows better than the probe does.
    return [r for r in brief.RUNTIMES if r.id in wanted]


def cmd_brief(args: argparse.Namespace) -> int:
    """Which agents on this machine have been told PassBook is here."""
    brief = _brief()
    if brief is None:
        return _fail("Briefing is not installed on this machine.", "Run:  passbook install")
    found = brief.status()
    if getattr(args, "json", False):
        print(json.dumps(found, indent=2))
        return 0
    if not found:
        print("No agent runtimes found on this machine.")
        print("Briefing writes into a runtime's own context file, so there is")
        print("nothing to write into until one is installed.")
        return 0
    for entry in found:
        mark = "current" if entry["current"] else ("out of date" if entry["briefed"] else "not briefed")
        tools = "tools" if entry.get("mcp") else ("no tools" if entry.get("mcp_possible")
                                                  else "brief only")
        print(f"{entry['label']:<18} {mark:<12} {tools:<11} {entry['path']}")
    stale = [e for e in found if not e["current"]]
    if stale:
        print(f"\n{len(stale)} runtime(s) to brief:  passbook brief install")
    return 0


def cmd_brief_install(args: argparse.Namespace) -> int:
    brief = _brief()
    if brief is None:
        return _fail("Briefing is not installed on this machine.", "Run:  passbook install")
    try:
        runtimes = _chosen_runtimes(brief, getattr(args, "only", "") or "")
    except ValueError as error:
        return _fail(str(error))
    if not runtimes:
        print("No agent runtimes found on this machine; nothing to brief.")
        return 0
    for entry in brief.install(runtimes):
        print(f"  {entry['state']:<16} {entry['path']}")
    if not getattr(args, "no_mcp", False):
        print("\nMCP server:")
        for entry in brief.register(runtimes):
            where = entry["path"] or "—"
            print(f"  {entry['state']:<20} {where}")
    print(f"\n{len(runtimes)} runtime(s). Agents read this at the start of a session, "
          f"so open a new one to pick it up.")
    return 0


def cmd_brief_remove(args: argparse.Namespace) -> int:
    brief = _brief()
    if brief is None:
        return 1
    try:
        runtimes = _chosen_runtimes(brief, getattr(args, "only", "") or "")
    except ValueError as error:
        return _fail(str(error))
    gone = brief.remove(runtimes)
    for entry in gone:
        print(f"  removed  {entry['path']}")
    for entry in brief.register(runtimes, remove=True):
        if entry["state"] == "unregistered":
            print(f"  removed  {entry['path']} (MCP server)")
    if not gone:
        print("Brief removed where present.")
    return 0


def cmd_agents(args: argparse.Namespace) -> int:
    """Who each key is for. The inverse of `policy`, which is per-app."""
    catalog = _catalog()
    import passbook_access as access

    policy = access.read_policy()
    names = passbook.key_names()
    if args.key:
        if args.key not in names:
            return _fail(f"Not in this store: {args.key}")
        rule = access.audience_for(args.key, policy)
        if getattr(args, "json", False):
            print(json.dumps(rule, indent=2))
            return 0
        if rule["mode"] == "all":
            print(f"{args.key}: every app")
        else:
            print(f"{args.key}: {rule['mode']} {', '.join(rule['agents'])}")
        return 0

    restricted = [(n, access.audience_for(n, policy)) for n in names]
    restricted = [(n, r) for n, r in restricted if r["mode"] != "all"]
    if getattr(args, "json", False):
        print(json.dumps({n: r for n, r in restricted}, indent=2))
        return 0
    if not restricted:
        print(f"All {len(names)} keys are readable by every app (the default).")
        print("Narrow one with:  passbook apps set KEY --only APP")
        return 0
    for name, rule in restricted:
        print(f"  {name}: {rule['mode']} {', '.join(rule['agents'])}")
    print(f"\n{len(restricted)} of {len(names)} keys are restricted.")
    return 0


def cmd_agents_set(args: argparse.Namespace) -> int:
    import passbook_access as access

    policy = access.read_policy()
    if args.key not in passbook.key_names():
        return _fail(f"Not in this store: {args.key}")
    if args.everyone:
        mode, agents = "all", []
    elif args.only:
        mode, agents = "include", args.only
    elif args.block:
        mode, agents = "exclude", args.block
    else:
        return _fail("Say who.", "Use --everyone, --only APP [...], or --block APP [...]")
    try:
        rule = access.set_audience(args.key, mode, agents, policy)
    except ValueError as error:
        return _fail(str(error))
    access.write_policy(policy)
    if rule["mode"] == "all":
        print(f"{args.key}: every app")
    else:
        print(f"{args.key}: {rule['mode']} {', '.join(rule['agents'])}")
    return 0


SCOPE_WORDS = {
    "workspace": "this workspace only",
    "machine": "every workspace on this machine",
    "tailnet": "every workspace here, and lendable to linked machines",
}


def cmd_scope(args: argparse.Namespace) -> int:
    """How far each key reaches, and who decides."""
    import passbook_access as access

    policy = access.read_policy()
    here = passbook.workspace()
    names = passbook.key_names()
    if args.key:
        if args.key not in names:
            return _fail(f"Not in this store: {args.key}")
        names = [args.key]

    rows = []
    for name in names:
        rule = access.scope_for(name, policy)
        rows.append({"key": name, **rule,
                     "may_change": access.may_change_scope(here, name, policy)["allowed"]})
    if getattr(args, "json", False):
        print(json.dumps({"workspace": here, "scopes": list(access.SCOPES), "keys": rows}, indent=2))
        return 0

    print(f"acting for workspace: {here or '(none configured)'}\n")
    narrowed = [r for r in rows if r["explicit"]] if not args.key else rows
    if not narrowed:
        print(f"Every key is scoped to {SCOPE_WORDS[access.DEFAULT_SCOPE]} (the default).")
        print("Narrow one with:  passbook scope set KEY --workspace")
        return 0
    for row in narrowed:
        lock = "" if row["may_change"] else f"   (owned by {row['owner']})"
        print(f"  {row['key']}: {SCOPE_WORDS[row['scope']]}{lock}")
    return 0


def cmd_scope_set(args: argparse.Namespace) -> int:
    """Set the reach of one key or many. A refused key does not stop the rest."""
    import passbook_access as access

    policy = access.read_policy()
    here = passbook.workspace()
    held = set(passbook.key_names())
    scope = ("workspace" if args.workspace else "machine" if args.machine
             else "tailnet" if args.tailnet else "")
    if not scope:
        return _fail("How far?", "Use --workspace, --machine or --tailnet.")

    changed, missing, refused = [], [], []
    for name in args.keys:
        if name not in held:
            missing.append(name)
            continue
        try:
            access.set_scope(name, scope, policy, workspace=here)
            changed.append(name)
        except PermissionError as error:
            refused.append((name, str(error)))
        except ValueError as error:
            return _fail(str(error))
    if changed:
        access.write_policy(policy)

    if changed:
        print(f"{len(changed)} key(s) -> {SCOPE_WORDS[scope]}")
        for name in changed:
            print(f"   {name}")
    for name, why in refused:
        print(f"{name}: {why}", file=sys.stderr)
    if missing:
        print(f"Not in this store: {', '.join(missing)}", file=sys.stderr)
    if refused:
        print("A key's reach is decided by the workspace it came from.", file=sys.stderr)
    return 0 if changed and not refused and not missing else (0 if changed else 1)


def _export_values(app: str, reason: str) -> dict[str, str] | None:
    """Every value this scope can read, opened, or None if the vault is shut.

    Goes through the broker like any other read, so an export is policy-checked
    and lands in the ledger. An export is the largest read anybody ever does
    here; it would be a strange one to leave out of the record.
    """
    _use_broker_for_sealed_values(app, reason)
    values = _store_values()
    stored = passbook.key_names()
    readable = {name: values[name] for name in stored if values.get(name)}
    if stored and not readable:
        _fail("The store is encrypted and locked, so there is nothing to export.",
              "Sign in first:  passbook signin")
        return None
    return readable


def cmd_projects(args: argparse.Namespace) -> int:
    """Which projects each key is for."""
    import passbook_access as access

    policy = access.read_policy()
    names = sorted(passbook.key_names())
    here = passbook.project()
    rows = [(name, access.project_for(name, policy)) for name in names]
    if args.json:
        print(json.dumps({
            "project": here,
            "modes": list(access.PROJECT_MODES),
            "seen": access.projects_seen(policy),
            "keys": [{"key": name, **rule} for name, rule in rows],
        }, indent=2))
        return 0
    print(f"working in project: {here or '(none — no git root, and PASSBOOK_PROJECT is unset)'}\n")
    limited = [(name, rule) for name, rule in rows if rule["mode"] != "all"]
    if not limited:
        print("Every key is readable from every project.")
        print("Narrow one with:  passbook projects set KEY --only <project>")
        return 0
    for name, rule in limited:
        word = "only" if rule["mode"] == "include" else "all except"
        print(f"  {name}\n      {word} {', '.join(rule['projects'])}")
    print(f"\n{len(rows) - len(limited)} other key(s) are readable from every project.")
    return 0


def cmd_projects_set(args: argparse.Namespace) -> int:
    """Limit a key to named projects, or exclude named projects from it."""
    import passbook_access as access

    if args.every:
        mode, names = "all", []
    elif args.only:
        mode, names = "include", args.only
    elif args.without:
        mode, names = "exclude", args.without
    else:
        return _fail("Which projects?",
                     "Use --every, --only <project>… or --without <project>…")
    policy = access.read_policy()
    changed = []
    for key in args.keys:
        try:
            access.set_projects(key, mode, names, policy)
        except ValueError as error:
            return _fail(str(error))
        changed.append(key)
    access.write_policy(policy)
    if mode == "all":
        print(f"{len(changed)} key(s) are readable from every project again.")
    else:
        word = "only" if mode == "include" else "all except"
        print(f"{len(changed)} key(s): {word} {', '.join(sorted(names))}.")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Write the store to a file: encrypted by default, GPG or plain on request."""
    try:
        import passbook_backup
    except ImportError:
        return _fail("Export is not installed on this machine.", "Run:  passbook install")

    target = Path(args.file).expanduser()
    values = _export_values("passbook-export", f"export to {target.name}")
    if values is None:
        return 1
    if not values:
        return _fail("There is nothing in this store to export.")

    meta = {"workspace": passbook.workspace(), "machine": platform.node(),
            "note": args.note or ""}
    try:
        if args.plain:
            # Two separate acts of consent. "Export" reads like "back up", and a
            # plaintext backup is a copy of every credential you own — so the
            # flag that chooses the shape is not also the flag that accepts what
            # the shape means.
            if not args.i_understand:
                return _fail(
                    "A plaintext export puts every value in the clear in that file.",
                    "If that is what you want:  passbook export --plain --i-understand "
                    f"{args.file}")
            text = passbook_backup.plain(values, path=str(target))
        elif args.gpg or args.recipient:
            passphrase = ""
            if not args.recipient:
                passphrase = _ask_password("Passphrase for the export: ", confirm=True,
                                           from_stdin=args.password_stdin)
            text = passbook_backup.gpg_encrypt(values, recipient=args.recipient,
                                               passphrase=passphrase, **meta)
        else:
            passphrase = _ask_password("Passphrase for the export: ", confirm=True,
                                       from_stdin=args.password_stdin)
            text = passbook_backup.encrypt(values, passphrase, **meta)
        written = passbook_backup.write_private(target, text)
    except passbook_backup.BackupError as error:
        return _fail(str(error))
    except (EOFError, KeyboardInterrupt):
        print()
        return 1
    except ValueError as error:
        return _fail(str(error))
    except OSError as error:
        return _fail(f"Could not write {target}: {error}")

    _record_export("export", sorted(values), str(written))
    shape = "plaintext" if args.plain else ("GPG" if (args.gpg or args.recipient) else "encrypted")
    print(f"Exported {len(values)} key(s) to {written} ({shape}).")
    if args.plain:
        print("Every value in that file is readable. Move it and destroy it.", file=sys.stderr)
    return 0



def free_name(name: str, taken: set[str]) -> str:
    """A name like `name` that nothing is using yet.

    `OPENAI_API_KEY` becomes `OPENAI_API_KEY_2`, then `_3`. Numbering rather
    than a word like `_NEW`, because the second import of the same file would
    then collide with the first and there would be nowhere left to go.
    """
    if name not in taken:
        return name
    stem, suffix = name, 2
    # An earlier `_2` should become `_3`, not `_2_2`.
    if "_" in name:
        head, _, tail = name.rpartition("_")
        if tail.isdigit() and head:
            stem, suffix = head, int(tail) + 1
    while f"{stem}_{suffix}" in taken:
        suffix += 1
    return f"{stem}_{suffix}"


def cmd_import(args: argparse.Namespace) -> int:
    """Read an export of any shape into this store."""
    try:
        import passbook_backup
    except ImportError:
        return _fail("Import is not installed on this machine.", "Run:  passbook install")

    source = Path(args.file).expanduser()
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as error:
        return _fail(f"Could not read {source}: {error}")

    shape = passbook_backup.detect(text)
    passphrase = ""
    if shape in ("encrypted", "gpg"):
        needs = shape == "encrypted" or args.password_stdin or not args.recipient_key
        if needs:
            try:
                passphrase = _ask_password(f"Passphrase for {source.name}: ",
                                           from_stdin=args.password_stdin)
            except (EOFError, KeyboardInterrupt):
                print()
                return 1
    try:
        document = passbook_backup.read(text, passphrase=passphrase)
        incoming = passbook_backup.keys_of(document)
    except passbook_backup.BackupError as error:
        return _fail(str(error))

    if not incoming:
        return _fail("That export has no keys in it.")

    held = set(passbook.key_names())

    # `--json` describes the file and changes nothing. The window uses this to
    # draw the list, so it carries names, not values: a file the person is
    # about to import is still a file full of credentials.
    if args.dry_run and getattr(args, "json", False):
        taken = set(held)
        rows = []
        for name in sorted(incoming):
            clashes_here = name in held
            suggested = free_name(name, taken) if clashes_here else name
            if clashes_here:
                # Reserve it, so two clashing keys cannot be offered the same
                # replacement name.
                taken.add(suggested)
            rows.append({"key": name, "clashes": clashes_here, "suggested": suggested})
        print(json.dumps({
            "shape": shape,
            "file": str(source),
            "name": source.name,
            "keys": rows,
            "held": len(held),
        }, indent=2))
        return 0

    wanted = getattr(args, "only", None)
    if wanted:
        asked = {name.strip() for name in wanted if name.strip()}
        unknown = sorted(asked - set(incoming))
        if unknown:
            return _fail(f"Not in that file: {', '.join(unknown)}")
        incoming = {name: value for name, value in incoming.items() if name in asked}
        if not incoming:
            return _fail("Nothing was selected to import.")

    # `--as OLD=NEW` is how a key gets kept alongside the one already here,
    # rather than overwriting it.
    for pair in (getattr(args, "rename", None) or []):
        old_name, _, new_name = pair.partition("=")
        old_name, new_name = old_name.strip(), new_name.strip()
        if not old_name or not new_name:
            return _fail(f"--as wants OLD=NEW, not {pair!r}")
        if old_name not in incoming:
            return _fail(f"Not in that file: {old_name}")
        if not passbook._KEY.match(new_name):
            return _fail(f"{new_name} is not a usable key name.")
        if new_name in incoming:
            return _fail(f"{new_name} is already coming in from that file.")
        incoming[new_name] = incoming.pop(old_name)

    clashes = sorted(name for name in incoming if name in held)
    fresh = sorted(name for name in incoming if name not in held)

    if args.dry_run:
        where = document.get("machine") or ""
        made = document.get("exported_at") or "at an unknown time"
        print(f"{source} is a {shape} export of {len(incoming)} key(s), made {made}"
              + (f" on {where}" if where else "") + ".")
        if fresh:
            print(f"\nWould add {len(fresh)}:")
            for name in fresh:
                print(f"  + {name}")
        if clashes:
            print(f"\n{len(clashes)} already here"
                  f"{' and would be overwritten' if args.overwrite else ', and would be kept'}:")
            for name in clashes:
                print(f"  {'~' if args.overwrite else '='} {name}")
        return 0

    if clashes and not args.overwrite:
        print(f"{len(clashes)} key(s) are already in this store and were kept. "
              f"Use --overwrite to replace them.", file=sys.stderr)

    try:
        result = _write_values(incoming, overwrite=args.overwrite, exact=True,
                               app="passbook-import")
        if result is None:
            return 1
    except (ValueError, OSError, passbook.ContainerisedHomeError) as error:
        return _fail(str(error))

    _record_export("import", sorted(incoming), str(source))
    added, updated = result.get("added", []), result.get("updated", [])
    print(f"Imported into {result.get('path')}: {len(added)} added, "
          f"{len(updated)} updated, {len(result.get('kept', []))} kept.")
    if result.get("sealed"):
        print(f"They went in sealed, like the rest of this store.")
    return 0


def _sealed_store_present() -> bool:
    try:
        import passbook_vault

        return bool(passbook_vault.status().get("sealed"))
    except Exception:
        return False


def _record_export(op: str, names: list[str], where: str) -> None:
    """Note the largest read (or write) anyone does, by name, never by value."""
    try:
        import passbook_stamp

        passbook_stamp.stamp(op=op, keys=names, app=f"passbook-{op}",
                             reason=f"{op} {len(names)} key(s) — {Path(where).name}",
                             granted=True)
    except Exception:
        # A record that cannot be written must not stop the thing it records;
        # the alternative is an export that fails because of its own audit line.
        pass


def cmd_recovery(args: argparse.Namespace) -> int:
    """Mint a recovery code that can open this vault without the password.

    The one thing a password-only vault cannot survive is a forgotten password:
    the data key is wrapped by the password and by nothing else, so the store is
    gone. A recovery code is a second wrapping, with enough entropy that it does
    not need a slow KDF to be safe, and it is shown exactly once.
    """
    module = _vault_module()
    if module is None:
        return 1
    opened = _open_vault(module, args.profile, from_stdin=args.password_stdin)
    if opened is None:
        return 1
    dek, profile_id = opened
    try:
        code, factor = module.add_recovery_factor(profile_id, dek=dek, label=args.label)
    except module.VaultError as error:
        return _fail(str(error))

    _record_export("recovery", [], f"profile {profile_id}")
    print("Write this down and put it somewhere this machine is not.\n")
    print(f"    {code}\n")
    print("It opens the vault on its own, so it is as good as the password.")
    print("It is shown once — PassBook keeps only what it needs to check it.")
    print(f"\nUse it with:  passbook signin --recovery")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    """Stop counting a tailnet machine as holding this store."""
    module = _link_or_fail()
    if module is None:
        return 1
    try:
        result = module.forget(args.host)
    except module.LinkError as error:
        return _fail(str(error))
    print(f"{args.host} is no longer recorded as holding this store.")
    if result.get("rotate"):
        print("\nThis does not unsend anything. That machine still has these "
              "until they are changed at the provider:", file=sys.stderr)
        for key in result["rotate"][:12]:
            print(f"  {key}", file=sys.stderr)
        if len(result["rotate"]) > 12:
            print(f"  ... and {len(result['rotate']) - 12} more", file=sys.stderr)
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    """What replication would do, or does, between this machine and its peers.

    Dry by default. This replaces a path that has been running unattended for
    months; a verb that shows its working before it acts is the difference
    between adopting it and finding out afterwards.
    """
    try:
        import passbook_fleet
        import passbook_sync
    except ImportError:
        return _fail("Fleet sync is not installed on this machine.",
                     "Run:  passbook install")

    peers = passbook_fleet.reachable()
    if not peers:
        ok, detail = passbook_fleet.available()
        if not ok:
            return _fail(f"No tailnet here: {detail}")
        print("No peers on this tailnet are running a collector.")
        return 0

    store = passbook.env_path()
    raw = passbook._read_raw(store) if hasattr(passbook, "_read_raw") else \
        passbook.parse_env_text(store.read_text(encoding="utf-8"))
    local_meta = passbook_sync.read_meta(store)

    # Open what this machine can, so comparison is between secrets rather than
    # representations. A value that will not open is marked, never guessed at.
    import passbook_vault

    sealed = [k for k, v in raw.items() if passbook_vault.is_sealed(v)]
    opened = {}
    if sealed:
        opened = passbook.request(sealed, app="passbook-sync",
                                  reason="compare against a peer") or {}
    local = {k: (opened.get(k) or passbook_sync.UNOPENED)
             if passbook_vault.is_sealed(v) else v for k, v in raw.items()}

    payloads = []
    unreachable = []
    for peer in peers:
        got = passbook_sync.fetch(peer["host"], peer["port"], address=peer["address"])
        if got is None:
            unreachable.append(peer["host"])
        else:
            payloads.append((peer["host"], got))

    plan = passbook_sync.plan_pull(local, local_meta, payloads)
    allowed, withheld = passbook_sync.sendable({k: "" for k in raw})

    # A peer holding OUR ciphertext cannot open it, now or ever: the data key
    # never leaves this machine. Push-missing cannot fix that — the peer has
    # the key, so nothing is missing — so repair is its own verb and overwrites.
    repairs: dict[str, dict] = {}
    if args.repair:
        openable = {k: v for k, v in local.items()
                    if isinstance(v, str) and not passbook_vault.is_sealed(v)}
        for host, got in payloads:
            fix = passbook_sync.plan_repair(got, openable)
            if fix["broken"]:
                repairs[host] = fix

    # Record the machines that receive this store, so the Machines page stops
    # saying "no linked machines" while four of them hold it. Recorded as
    # `tailnet` rather than as grants: no fingerprint was compared, and the
    # page must not imply one was.
    adopted = []
    if not args.no_adopt:
        try:
            import passbook_link

            for peer in peers:
                if peer["host"] in unreachable:
                    continue
                passbook_link.adopt(peer["host"], keys=sorted(allowed), node=peer["port"])
                adopted.append(peer["host"])
        except Exception as error:  # noqa: BLE001 — never fail a dry run on bookkeeping
            notice = f"could not record the machines: {error}"
            print(notice, file=sys.stderr)

    if args.json:
        print(json.dumps({
            "peers": [p["host"] for p in peers],
            "unreachable": unreachable,
            "wouldPull": sorted(plan["apply"]),
            "skippedUnknownAge": plan["skippedUnknownAge"],
            "skippedSealedShut": plan["skippedSealedShut"],
            "refusedSealedFromPeer": plan["refusedSealedFromPeer"],
            "mayReplicate": len(allowed),
            "withheldByReach": sorted(withheld),
            "adopted": adopted,
            "repairs": {host: {"broken": len(fix["broken"]),
                               "repairable": len(fix["repair"]),
                               "cannotOpen": len(fix["cannotOpen"])}
                        for host, fix in repairs.items()},
        }, indent=2))
        return 0

    print(f"peers with a collector: {len(peers)}")
    for peer in peers:
        mark = "unreachable" if peer["host"] in unreachable else "ok"
        print(f"  {peer['host']}  ({mark})")
    print()
    print(f"would pull: {len(plan['apply'])} key(s)")
    for key in sorted(plan["apply"])[:20]:
        print(f"  + {key}  (from {plan['sources'][key]})")
    for label, names in (("held back, local age unknown", plan["skippedUnknownAge"]),
                         ("held back, sealed and the vault is shut", plan["skippedSealedShut"]),
                         ("refused, peer served ciphertext", plan["refusedSealedFromPeer"])):
        if names:
            print(f"\n{label}: {len(names)}")
            for key in sorted(names)[:10]:
                print(f"  - {key}")
    if args.repair:
        if not repairs:
            print("\nNo peer is holding unopenable ciphertext.")
        for host, fix in sorted(repairs.items()):
            print(f"\n{host}: {len(fix['broken'])} key(s) held as ciphertext it cannot open")
            print(f"  repairable from here : {len(fix['repair'])}")
            if fix["cannotOpen"]:
                print(f"  this machine cannot open either: {len(fix['cannotOpen'])}")
            if fix["withheldByPolicy"]:
                print(f"  withheld by reach    : {len(fix['withheldByPolicy'])}")
            if not args.apply:
                continue
            peer = next(p for p in peers if p["host"] == host)
            ok, why = passbook_sync.push(host, peer["port"], fix["repair"],
                                         address=peer["address"])
            if ok:
                print(f"  repaired {len(fix['repair'])} key(s) on {host}")
            else:
                print(f"  could not repair {host}: {why}", file=sys.stderr)
        if repairs and not args.apply:
            print("\nNothing was sent. Add --apply to repair.")

    if adopted:
        print(f"\nrecorded on the Machines page: {len(adopted)} machine(s)")
    print(f"\nreach: {len(allowed)} key(s) may replicate, {len(withheld)} withheld")
    for key, why in sorted(withheld.items())[:10]:
        print(f"  - {key}: {why}")
    if not args.apply:
        print("\nNothing was changed. Add --apply to pull what is listed above.")
        return 0

    if not plan["apply"]:
        return 0

    # Writing back. If the store is sealed the incoming values must be sealed
    # too, and if they cannot be, NOTHING is written — a peer's value landing
    # as plaintext beside encrypted ones is the outcome this whole path exists
    # to prevent, and there is deliberately no fallback that does it anyway.
    store_sealed = any(passbook_vault.is_sealed(v) for v in raw.values())
    if store_sealed:
        import passbook_broker

        answer = passbook_broker.seal_values(plan["apply"], app="passbook-sync",
                                             workspace_id=passbook.workspace())
        if not answer.get("ok"):
            return _fail(
                f"Held back {len(plan['apply'])} key(s): {answer.get('error', 'could not seal')}",
                "Sign in so they can be written encrypted:  passbook signin")
        written = answer.get("written") or sorted(plan["apply"])
    else:
        result = passbook.set_values(plan["apply"], overwrite=True, exact=True)
        written = sorted({*result.get("added", []), *result.get("updated", [])})

    # Stamp what arrived so the next pass compares ages correctly. Without this
    # the key looks older than every peer's copy and the write undoes itself.
    if written:
        passbook_sync.touch_meta(store, written)
    print(f"\nPulled {len(written)} key(s).")
    return 0


def cmd_workspace(args: argparse.Namespace) -> int:
    """Which workspace this machine is acting for, and what else it has."""
    here = passbook.workspace()
    names = passbook.workspaces()
    if args.json:
        print(json.dumps({
            "active": here,
            "pinned": passbook.workspace_pinned(),
            "workspaces": [{"id": name, "label": passbook.workspace_label(name),
                            "active": name == here,
                            "inherits": passbook.workspace_inherits(name)}
                           for name in names],
        }, indent=2))
        return 0
    if passbook.workspace_pinned():
        print(f"acting for: {here}  (pinned by HIVE_WORKSPACE, not the manifest)")
    else:
        print(f"acting for: {here or '(none configured)'}")
    for name in names:
        label = passbook.workspace_label(name)
        mark = "*" if name == here else " "
        extra = "" if passbook.workspace_inherits(name) else "  (does not inherit the machine store)"
        print(f" {mark} {name}{'' if label == name else f'  — {label}'}{extra}")
    if not names:
        print("This machine has no workspaces; everything lives in the machine store.")
    return 0


def cmd_workspace_use(args: argparse.Namespace) -> int:
    """Switch the machine's active workspace."""
    try:
        was = passbook.set_active_workspace(args.name)
    except ValueError as error:
        known = ", ".join(passbook.workspaces()) or "none"
        return _fail(str(error), f"On this machine: {known}")
    except OSError as error:
        return _fail(f"Could not write the workspace manifest: {error}")
    if was == args.name:
        print(f"Already acting for {args.name}.")
    else:
        print(f"Now acting for {args.name}{f' (was {was})' if was else ''}.")
    if passbook.workspace_pinned():
        # Saying nothing here would leave someone staring at a command that
        # reported success while this shell went on using the old workspace.
        print("HIVE_WORKSPACE is set in this environment, so THIS shell still acts for "
              f"{passbook.workspace()}. Unset it to follow the manifest.", file=sys.stderr)
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    """Which apps can read which keys, as a grid you can actually scan."""
    catalog = _catalog()
    if catalog is None:
        return _fail("The matrix needs the catalogue module.", "Run:  passbook install")
    import passbook_access as access

    policy = access.read_policy()
    names = passbook.key_names()
    agents = args.agent or catalog.agents_seen(policy=policy)
    if not agents:
        print("No apps have asked for a credential yet, and none are configured.")
        print("Name one to preview:  passbook matrix --app claude-code")
        return 0
    if args.group:
        names = [n for n in names if catalog.group_of(n, policy).lower() == args.group.lower()]
    grid = catalog.matrix(names, agents, policy)
    if getattr(args, "json", False):
        print(json.dumps(grid, indent=2))
        return 0

    width = max([len(n) for n in grid["keys"]] + [3])
    width = min(width, 38)
    header = " " * (width + 2) + "  ".join(a[:10].ljust(10) for a in grid["agents"])
    print(header)
    print("-" * len(header))
    shown = 0
    for row in grid["rows"]:
        if args.restricted and row["audience"]["mode"] == "all" and all(
                c["outcome"] == "grant" for c in row["agents"].values()):
            continue
        cells = []
        for agent in grid["agents"]:
            outcome = row["agents"][agent]["outcome"]
            cells.append({"grant": "yes", "refuse": "NO", "ask": "ask"}[outcome].ljust(10))
        print(f"{row['key'][:width].ljust(width)}  " + "  ".join(cells))
        shown += 1
    if not shown:
        print("(every key is readable by every app — nothing is restricted yet)")
    print(f"\n{shown} key(s) x {len(grid['agents'])} app(s).  yes = granted, "
          f"ask = waits for you, NO = refused")
    return 0


def cmd_signin(args: argparse.Namespace) -> int:
    import passbook_broker

    # Signing in *means* "hold my key in the broker", so a missing broker is a
    # step in that job rather than a reason to refuse it. This sent people away
    # to run one command so they could come back and run this one, and the app's
    # own sign-in card had been claiming for weeks that signing in starts it.
    if not passbook_broker.running():
        started = passbook_broker.start()
        if not started.get("ok"):
            return _fail("No broker is running, and one would not start.",
                         f"Start it by hand:  passbook broker start"
                         f"   ({started.get('detail', '')})".rstrip())
        print(f"Started the broker on {started['path']} (pid {started['pid']}).")
    if args.passkey:
        supplied = sys.stdin.readline().strip()
        if not supplied:
            return _fail("No PRF secret arrived on stdin.")
        answer = passbook_broker.signin(
            profile=args.profile, workspace=args.workspace, credential_id=args.passkey,
            prf_secret=base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4)),
            duration=args.duration)
    elif args.device:
        answer = passbook_broker.signin(profile=args.profile, workspace=args.workspace,
                                        device=True, duration=args.duration)
    elif getattr(args, "recovery", False):
        try:
            code = _ask_password("Recovery code: ",
                                 from_stdin=getattr(args, "password_stdin", False))
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        except ValueError as error:
            return _fail(str(error))
        answer = passbook_broker.signin(profile=args.profile, workspace=args.workspace,
                                        recovery=code, duration=args.duration)
    else:
        try:
            password = _ask_password(from_stdin=getattr(args, "password_stdin", False))
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        except ValueError as error:
            return _fail(str(error))
        answer = passbook_broker.signin(profile=args.profile, workspace=args.workspace,
                                        password=password, duration=args.duration)
    if not answer.get("ok"):
        error = answer.get("error", "Sign-in failed.")
        # The broker is long-running, so it can be older than the command
        # talking to it: `always` means "no expiry" to this CLI and is not a
        # duration to a broker that started before that existed. It reads as a
        # typo, and the fix is nothing to do with what you typed.
        if "is not a duration" in error and str(args.duration).strip().lower() \
                in getattr(passbook_broker, "FOREVER_WORDS", frozenset()):
            return _fail(error,
                         "That broker started before this option existed. "
                         "Restart it:  passbook broker restart")
        return _fail(error)
    print(answer.get("detail", "Signed in."))
    return 0


def cmd_signout(args: argparse.Namespace) -> int:
    import passbook_broker

    answer = passbook_broker.signout(workspace=getattr(args, "workspace", ""),
                                     everything=getattr(args, "all", False))
    if not answer.get("ok"):
        return _fail(answer.get("error", "Could not lock the vault."))
    where = answer.get("workspace") or ""
    if not answer.get("was_unlocked"):
        print("Already locked.")
    elif where:
        print(f"Locked {where}.")
    else:
        print("Locked every workspace.")
    return 0


def _link():
    try:
        import passbook_link
    except ImportError:
        return None
    return passbook_link


def _link_or_fail():
    module = _link()
    if module is None:
        print("Machine linking is not installed on this machine.", file=sys.stderr)
        print("Run:  passbook install", file=sys.stderr)
        return None
    if not module.available():
        # Do NOT send anyone to `pip install` here: on Homebrew, Debian and
        # Ubuntu that is refused outright (PEP 668), so the advice would fail
        # for most people and blame their OS while doing it. `passbook install`
        # provisions a private runtime instead, which always works.
        print("Machine linking needs a runtime that setup has not provided yet.", file=sys.stderr)
        print("Run:  passbook install", file=sys.stderr)
        return None
    return module


def _read_blob(source: str) -> str:
    """A token or envelope, given as a path, as `-` for stdin, or inline."""
    text = source.strip()
    if text == "-":
        return sys.stdin.read().strip()
    # An inline envelope is longer than a filename may be, and asking the
    # filesystem about it raises ENAMETOOLONG rather than answering "no".
    if text.startswith(("passbook-pair:", "passbook-env:")):
        return text
    try:
        candidate = Path(text).expanduser()
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return text


def cmd_link(args: argparse.Namespace) -> int:
    """This machine's link identity, and what it has lent or borrowed."""
    module = _link_or_fail()
    if module is None:
        return 1
    me = module.describe_identity()
    if args.json:
        # The human layout prints "fingerprint" on more than one line, which
        # makes it a trap to grep. Anything scripting this wants the object.
        print(json.dumps({**me, **module.grants()}, indent=2))
        return 0
    print(f"this machine: {me['did']}")
    print(f"fingerprint:  {me['fingerprint']}")
    state = module.grants()
    for role, label in (("lent", "lent to"), ("borrowed", "borrowed from")):
        for entry in state[role]:
            status = "active" if entry["active"] else ("revoked" if entry["revoked"] else "expired")
            print(f"\n{label} {entry['did']}  [{status}]")
            if entry["fingerprint"]:
                print(f"  fingerprint: {entry['fingerprint']}")
            print(f"  keys:        {', '.join(entry['keys']) or '—'}")
            print(f"  expires:     {entry['expires']}")
    if not state["lent"] and not state["borrowed"]:
        print("\nno links yet")
    return 0


def cmd_link_request(args: argparse.Namespace) -> int:
    """Run on the machine that WANTS keys. Hand the token to the one that has them."""
    module = _link_or_fail()
    if module is None:
        return 1
    pairing = module.pairing_token(ttl_seconds=args.ttl)
    print("Give this token to the machine that holds the keys:\n")
    print(pairing["token"])
    print(f"\nfingerprint: {pairing['fingerprint']}")
    print(f"expires:     {pairing['expires']}")
    print("\nThe other machine will show a fingerprint before it sends anything.")
    print("If it does not match the one above, stop — the token was swapped.")
    return 0


def cmd_link_approve(args: argparse.Namespace) -> int:
    """Run on the machine that HAS the keys. Approves a device for named keys."""
    module = _link_or_fail()
    if module is None:
        return 1
    try:
        peer = module.read_pairing_token(_read_blob(args.token))
    except module.LinkError as error:
        return _fail(str(error))

    confirm = args.confirm
    if not confirm:
        # The fingerprint is the second factor; a non-interactive run cannot
        # perform it, so it must be supplied rather than skipped.
        if not sys.stdin.isatty():
            return _fail(
                "This approval needs the fingerprint confirmed.",
                f"Re-run with --confirm {peer['fingerprint']} only if the joining machine shows that.",
            )
        print(f"That machine says its fingerprint is:\n\n    {peer['fingerprint']}\n")
        print("Check it against the other machine's screen, then type it back.")
        try:
            confirm = input("fingerprint: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return _fail("Cancelled; nothing was granted.")

    keys = [key for item in args.keys for key in item.split(",") if key.strip()]
    try:
        result = module.grant(
            _read_blob(args.token), keys,
            confirm_fingerprint=confirm, workspace=args.workspace, days=args.days,
        )
    except module.LinkError as error:
        return _fail(str(error))

    print(f"\ngranted to {result['did']}")
    print(f"keys:    {', '.join(result['keys'])}")
    print(f"expires: {result['expires']}")
    print(f"\nTHIS machine's fingerprint is {result['issuer_fingerprint']}.")
    print("The other machine will ask for it before it accepts.")
    if args.out:
        target = Path(args.out).expanduser()
        target.write_text(result["envelope"] + "\n", encoding="utf-8")
        os.chmod(target, 0o600)
        print(f"\nenvelope written to {target}")
    else:
        print("\nSend this envelope to that machine:\n")
        print(result["envelope"])
    print("\nIt is sealed to that device — no one else can open it, on any transport.")
    return 0


def cmd_link_accept(args: argparse.Namespace) -> int:
    """Run on the machine that asked. Opens an envelope and stores the keys."""
    module = _link_or_fail()
    if module is None:
        return 1
    blob = _read_blob(args.envelope)
    confirm = args.confirm
    if not confirm:
        try:
            issuer = module.envelope_issuer(blob)
        except module.LinkError as error:
            return _fail(str(error))
        if not module.known_issuer(issuer["did"]):
            if not sys.stdin.isatty():
                return _fail(
                    "This envelope is from a machine this one has not accepted from before.",
                    f"Its fingerprint is {issuer['fingerprint']} — re-run with --confirm "
                    "and that value only if the sending machine shows it.",
                )
            print(f"That envelope says it is from:\n\n    {issuer['fingerprint']}\n")
            print(f"It offers: {', '.join(issuer['keys'])}")
            print("\nCheck the fingerprint against the sending machine, then type it back.")
            try:
                confirm = input("fingerprint: ").strip()
            except (EOFError, KeyboardInterrupt):
                print(file=sys.stderr)
                return _fail("Cancelled; nothing was stored.")
    try:
        result = module.accept(blob, confirm_fingerprint=confirm, overwrite=args.replace)
    except module.LinkError as error:
        return _fail(str(error))
    except passbook.ContainerisedHomeError as error:
        return _fail(str(error))
    print(f"accepted from {result['from']}")
    for name, label in (("added", "added"), ("updated", "replaced"), ("kept", "already set, unchanged")):
        if result[name]:
            print(f"{label}: {', '.join(result[name])}")
    print(f"grant expires: {result['expires']}")
    return 0


def cmd_link_revoke(args: argparse.Namespace) -> int:
    module = _link_or_fail()
    if module is None:
        return 1
    result = module.revoke(args.did)
    print(result["detail"])
    if result["rotate"]:
        print("\nRotate these at the provider — revoking cannot unsend them:")
        for key in result["rotate"]:
            print(f"  {key}")
    return 0 if result["ok"] else 1


def _broker():
    try:
        import passbook_broker
    except ImportError:
        return None
    return passbook_broker


LIMITS = """
  What this does and does not do:
    It records every read that goes through it, and holds each app to the keys
    its policy names. It does NOT stop a determined attacker. Three reasons, all
    of them by design:
      - anything running as you can connect and claim to be any app; nothing in
        a request proves otherwise
      - the store file is still there to be read directly
      - stopping the broker restores full access, and apps keep working
    That last one is deliberate: a broker that could take the machine down by
    stopping would not survive a real week. Read "denied" in the record as "an
    app asked for something it is not set up to need", not as "an intruder was
    turned away"."""


def _access():
    try:
        import passbook_access
    except ImportError:
        return None
    return passbook_access


def _workspace_factors(name: str) -> dict:
    """Which ways into one workspace exist. Never a secret, only their kinds."""
    blank = {"has_vault": False, "has_password": False, "has_passkey": False,
             "has_device": False, "profiles": 0}
    try:
        import passbook_vault
    except ImportError:
        return blank
    try:
        path = passbook_vault.workspace_vault_path(name)
        if not path.is_file():
            return blank
        held = passbook_vault.profiles(root=path.parent)
    except Exception:  # noqa: BLE001 — a picker must render on a broken vault
        return blank
    kinds = {str(f.get("kind")) for profile in held for f in profile.get("factors") or []}
    return {"has_vault": bool(held), "profiles": len(held),
            "has_password": "password" in kinds, "has_passkey": "passkey" in kinds,
            "has_device": "device" in kinds}


def machine_state(*, verify: bool = False) -> dict:
    """Everything a management surface needs, in one call, with no values.

    A native app or a web panel should not have to know which optional modules
    are installed on a given machine, nor make six round trips to find out. Each
    section reports its own availability, so a surface renders what is there and
    says plainly what is not — rather than showing an empty panel that looks like
    a bug.

    Verifying the hash chain is not part of it. This runs every five seconds
    behind an open window, and re-hashing a six-megabyte ledger at that rate is
    not what makes the ledger trustworthy — it is just the most expensive thing
    left in the call. `verify=True` (`passbook state --verify`) does it, and the
    Record page asks for it when somebody is actually looking at the chain.
    """
    state: dict = {"store": passbook.status(), "spec_version": passbook.SPEC_VERSION}
    # The window offers to write an export somewhere, and has no other way to
    # propose a path a person would recognise.
    state["home"] = str(Path.home())

    # Ask the v2 vault, not the v1 module.
    #
    # `passbook_seal` predates `hive-sealed:v2:` and does not recognise it, so on
    # a v2-sealed store it reported every encrypted value as plaintext — this
    # machine had 261 sealed keys and this field said 0 sealed, 280 readable.
    # The window prefers `vault` where it has it and falls back to this, so the
    # fallback was the one that lied, on the screen whose whole job is saying
    # whether anything is encrypted.
    try:
        import passbook_vault

        state["sealing"] = passbook_vault.status()
    except ImportError:
        try:
            import passbook_seal

            state["sealing"] = passbook_seal.status()
        except ImportError:
            state["sealing"] = {"supported": False,
                                "detail": "Encryption at rest is not installed."}

    try:
        import passbook_access

        policy = passbook_access.read_policy()
        state["access"] = {
            "available": True,
            "default_mode": policy["default"].get("mode", passbook_access.DEFAULT_MODE),
            "modes": list(passbook_access.GRANT_MODES),
            "presets": list(passbook_access.DURATION_PRESETS),
            "apps": policy["apps"],
            "sessions": passbook_access.sessions(),
        }
        try:
            import passbook_broker
            import passbook_grant

            # Which keys are never printed, and whether this machine returns
            # values to callers it did not start. The window needs both to say
            # why an eye icon is missing — "no reason given" is what makes
            # somebody go looking for the store file instead.
            state["access"]["reads"] = passbook_broker.reads_mode(policy)
            state["access"]["guarded"] = {
                name: {"commands": passbook_grant.commands_for(name, policy),
                       "destinations": passbook_grant.destinations_for(name, policy)}
                for name in passbook_grant.guarded(policy)
            }
        except ImportError:
            state["access"]["reads"] = "open"
            state["access"]["guarded"] = {}
    except ImportError:
        state["access"] = {"available": False, "detail": "Access modes are not installed."}

    try:
        import passbook_access
        import passbook_catalog

        policy = passbook_access.read_policy()
        names = passbook.key_names()
        # Only the restricted keys travel. Every key's audience would be 279
        # identical "all" entries, which is a payload the surface has to filter
        # before it can render anything.
        restricted = {}
        for name in names:
            rule = passbook_access.audience_for(name, policy)
            if rule["mode"] != "all":
                restricted[name] = rule
        here = passbook.workspace()
        scopes = {}
        for name in names:
            rule = passbook_access.scope_for(name, policy)
            scopes[name] = {
                **rule,
                "may_change": passbook_access.may_change_scope(here, name, policy)["allowed"],
            }
        state["catalog"] = {
            "available": True,
            "workspace": here,
            "workspaces": passbook.workspaces(),
            # The window offers to switch workspaces, so it needs the names a
            # person recognises and whether switching would do anything at all.
            "workspace_rows": [
                {"id": name, "label": passbook.workspace_label(name),
                 "active": name == here, "inherits": passbook.workspace_inherits(name),
                 # What the picker needs to know before it asks for anything:
                 # whether this workspace has a key of its own at all, and which
                 # ways in it offers. A tile that offered a passkey button for a
                 # workspace with no passkey could only ever refuse.
                 **_workspace_factors(name)}
                for name in passbook.workspaces()
            ],
            "workspace_pinned": passbook.workspace_pinned(),
            "scopes": scopes,
            "scope_options": list(passbook_access.SCOPES),
            "default_scope": passbook_access.DEFAULT_SCOPE,
            "ungrouped": passbook_catalog.UNGROUPED,
            "groups": passbook_catalog.groups(names, policy),
            "group_of": passbook_catalog.effective_groups(names, policy),
            "audiences": restricted,
            "projects": {name: rule for name in names
                         if (rule := passbook_access.project_for(name, policy))["mode"] != "all"},
            "project_modes": list(passbook_access.PROJECT_MODES),
            "confirm": passbook_access.confirmations(policy),
            "confirm_ops": list(passbook_access.CONFIRM_OPS),
            "projects_seen": passbook_access.projects_seen(policy),
            "project": passbook.project(),
            "agents": passbook_catalog.agents_seen(policy=policy),
            # How often each has asked, so a one-off from a test is
            # distinguishable from a daemon that asks every minute.
            "agent_activity": passbook_catalog.agent_activity(),
            "modes": list(passbook_access.AUDIENCE_MODES),
        }
    except ImportError:
        state["catalog"] = {"available": False, "groups": {}, "group_of": {},
                            "audiences": {}, "agents": [],
                            "detail": "Grouping is not installed."}

    try:
        import passbook_broker

        broker = passbook_broker.status()
        state["broker"] = {"available": True, **broker}
    except ImportError:
        state["broker"] = {"available": False, "running": False,
                           "detail": "The broker is not installed."}

    try:
        import passbook_link

        if passbook_link.available():
            state["links"] = {"available": True, **passbook_link.grants(),
                              "fingerprint": passbook_link.describe_identity()["fingerprint"]}
        else:
            state["links"] = {"available": False, "lent": [], "borrowed": [],
                              "detail": "Machine linking needs a runtime setup has not provided yet."}
    except ImportError:
        state["links"] = {"available": False, "lent": [], "borrowed": [],
                          "detail": "Machine linking is not installed."}

    # Machines that hold this store WITHOUT a PassBook grant.
    #
    # Reported separately from `links` and never merged into them: a linked
    # machine is trusted because both ends compared a fingerprint, a tailnet
    # peer is trusted because it is on the tailnet, and showing them as one
    # list would be the more comfortable lie. The Machines page said "no linked
    # machines" while six machines held the store.
    try:
        import passbook_fleet

        state["fleet"] = passbook_fleet.describe()
    except ImportError:
        state["fleet"] = {"available": False, "peers": [], "replicating": 0,
                          "detail": "Fleet discovery is not installed."}
    except Exception as error:  # noqa: BLE001 — never fail the whole window on it
        state["fleet"] = {"available": False, "peers": [], "replicating": 0,
                          "detail": f"Could not read the tailnet: {error}"}

    try:
        import passbook_stamp

        state["record"] = {"available": True, "intact": None,
                           "detail": "The chain has not been checked in this call.",
                           "rows": _record_rows(passbook_stamp)}
        if verify:
            verification = passbook_stamp.verify_chain()
            state["record"]["intact"] = verification["ok"]
            state["record"]["detail"] = verification["detail"]
        # Summarised here rather than fetched per key: a list of several hundred
        # keys should not mean several hundred round trips to render.
        state["usage"] = _usage_summary(passbook_stamp)
    except ImportError:
        state["record"] = {"available": False, "intact": None, "rows": [],
                           "detail": "No access record is kept."}
        state["usage"] = {}

    return state


# The window renders the last forty rows of the record and three fields of the
# usage summary. It used to be sent a hundred rows and everything else besides:
# 501KB of record and 81KB of usage in a 632KB payload, parsed on the window's
# main thread every five seconds to draw a page that was usually not even open.
RECORD_ROWS_SENT = 40
RECORD_KEYS_PER_ROW = 12


def _record_rows(stamps) -> list[dict]:
    """The tail of the record, with long key lists cut short.

    One bulk read stamps every key it touched, so a single row on this machine
    carried 281 names and the hundred rows carried 501KB between them. The row
    already says how many keys it was; the names past the first few are for a
    person who is going to open the key's own history anyway.
    """
    rows = []
    for row in stamps.read_stamps(limit=RECORD_ROWS_SENT):
        keys = row.get("keys") or []
        if len(keys) > RECORD_KEYS_PER_ROW:
            row = {**row, "keys": list(keys[:RECORD_KEYS_PER_ROW])}
        rows.append(row)
    return rows


def _usage_summary(stamps) -> dict[str, dict]:
    """Last used, by what, how often — the three things a key row shows.

    `usage_by_key` also collects every app that has ever asked for each key,
    which nothing renders and which grows with the ledger.
    """
    return {
        name: {"count": entry.get("count", 0), "last": entry.get("last", ""),
               "last_app": entry.get("last_app", "")}
        for name, entry in stamps.usage_by_key().items()
    }


def cmd_history(args: argparse.Namespace) -> int:
    """Everything the record holds about one key, with its proofs."""
    try:
        import passbook_stamp
    except ImportError:
        return _fail("No access record is kept on this machine.")
    rows = passbook_stamp.history_for_key(args.key, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        return _fail(f"Nothing recorded for {args.key} yet.")
    for row in rows:
        flag = "" if row["granted"] else "  DENIED"
        print(f"{row['at']}  {row['app']:<28} {row['op']:<8}{flag}")
        if row["reason"]:
            print(f"    {row['reason']}")
        print(f"    proof {row['proof']}")
    verification = passbook_stamp.verify_chain()
    print(f"\n{verification['detail']}")
    return 0 if verification["ok"] else 1


def cmd_reveal(args: argparse.Namespace) -> int:
    """Print one value. The only command in here that does.

    Kept separate from `list`, `status` and `state` on purpose: a surface that
    sometimes returns secrets is one nobody can reason about. Every use is
    stamped as a `reveal`, so looking at your own key is visible in the record
    rather than indistinguishable from an app consuming it.
    """
    # `reveal` is the one command whose entire job is printing a secret, so it
    # is the one an agent reaches for. What separates a person from an agent
    # here is not a name — that is a claim — but whether anybody is actually
    # sitting there: an agent captures stdout to read it, and a captured stream
    # is not a terminal. Refusing that case costs a person nothing and costs an
    # agent the whole command.
    try:
        import passbook_grant

        forbidden = args.key in set(passbook_grant.guarded(_access().read_policy()))
    except Exception:  # noqa: BLE001 — no policy is the common case
        forbidden = False
    if forbidden:
        return _fail(f"{args.key} is guarded and is never printed.",
                     "Use it instead:  passbook run --only "
                     f"{args.key} -- <command>")
    # `--confirm` carries a proof collected somewhere else — the app asks in its
    # own window and passes what the person typed. It is a hurdle, not a
    # boundary, and pretending otherwise would be the exact overstatement this
    # project keeps refusing to make: a process that can run this command can
    # pass this flag. What actually stops a determined caller is the guard check
    # above, which no flag reaches.
    if str(getattr(args, "confirm", "") or "") != args.key:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return _fail(
                "reveal needs a terminal; this output is being captured.",
                "If a program needs the value, give it the value rather than "
                "the output:  passbook run -- <command>")
        print(f"This prints {args.key} in the clear, and records that it happened.")
        try:
            if input("Type the key's name to continue: ").strip() != args.key:
                return _fail("Not revealed.")
        except (EOFError, KeyboardInterrupt):
            print()
            return _fail("Not revealed.")

    value = passbook.reveal(args.key, app=caller("passbook-cli", args), reason=args.reason)
    if not value:
        # Three answers, not two — the same three `check` and `get` give. A key
        # that is present but encrypted is not a key that is missing, and
        # "is not set" over one of those sends a reader off to re-create a
        # credential that was never gone, usually pasting a new value over the
        # good one.
        if args.key in set(passbook.key_names()):
            return _fail(f"{args.key} is in this store, but encrypted and the vault is shut.",
                         "Sign in to read it:  passbook signin")
        return _fail(f"{args.key} is not set.", "See what is:  passbook-list")
    print(value)
    return 0


def cmd_guard(args: argparse.Namespace) -> int:
    """Bind a key to the commands that may hold it and the hosts it may reach.

    The difference between "this key is not printed" and "this key cannot leave"
    — the second needs somebody to say where it is allowed to go, because only
    its owner knows.
    """
    module = _access()
    if module is None:
        return _fail("Access policy is not installed on this machine.", "Run:  passbook install")
    import passbook_grant

    policy = module.read_policy()
    if not args.key:
        bound = passbook_grant.guarded(policy)
        if not bound:
            print("No keys are guarded.")
            print('Bind one with:  passbook guard KEY --to api.example.com')
            print("                passbook guard KEY --into 'wrangler *'")
            return 0
        for name in bound:
            commands = passbook_grant.commands_for(name, policy)
            hosts = passbook_grant.destinations_for(name, policy)
            print(name)
            print(f"   commands: {', '.join(commands) if commands else 'any'}")
            print(f"   hosts:    {', '.join(hosts) if hosts else 'none — cannot be proxied'}")
        return 0

    if args.key not in set(passbook.key_names()):
        return _fail(f"{args.key} is not in this store.", "See what is:  passbook list")

    if args.clear:
        if not module.clear_guard(args.key, policy):
            print(f"{args.key} was not guarded.")
            return 0
        module.write_policy(policy)
        print(f"{args.key} is no longer guarded.")
        return 0

    if not args.to and not args.into:
        return _fail("Guard it how?",
                     f"passbook guard {args.key} --to api.example.com   (may be sent there)\n"
                     f"passbook guard {args.key} --into 'wrangler *'    (may be injected into that)")

    rule = module.set_guard(args.key, policy, commands=args.into or None,
                            destinations=args.to or None, replace=args.replace)
    module.write_policy(policy)
    print(f"{args.key} is guarded.")
    if rule.get("commands"):
        print(f"   may be injected into: {', '.join(rule['commands'])}")
    if rule.get("destinations"):
        print(f"   may be sent to:       {', '.join(rule['destinations'])}")
    print("   it is never printed, by get, by reveal, or to an agent.")
    return 0


def cmd_grants(args: argparse.Namespace) -> int:
    """What is holding credentials right now, and how this machine answers reads."""
    try:
        import passbook_broker
    except ImportError:
        return _fail("The broker is not installed on this machine.")
    if not passbook_broker.running():
        return _fail("No broker is running, so nothing holds a grant.",
                     "Start one:  passbook broker start")
    answer = passbook_broker._ask({"op": "grants"}) or {}
    if args.json:
        print(json.dumps(answer, indent=2))
        return 0
    mode = answer.get("reads", "open")
    print(f"reads: {mode}" + ("  — values go only into processes the broker started"
                              if mode == "sealed" else
                              "  — callers may still read values directly"))
    grants = answer.get("grants") or []
    if not grants:
        print("Nothing is holding credentials right now.")
        return 0
    for row in grants:
        age = row.get("age_seconds", 0)
        print(f"{row.get('app', '?')}  pid {row.get('pid') or '—'}  {age:.0f}s ago")
        print(f"   {' '.join(row.get('command') or []) [:80]}")
        print(f"   holding: {', '.join(row.get('keys') or []) or 'nothing'}")
    return 0


def cmd_harden(args: argparse.Namespace) -> int:
    """What protects this machine's credentials at the OS level, and what does not."""
    try:
        import passbook_harden
    except ImportError:
        return _fail("Process hardening is not installed on this machine.")

    if args.undo:
        answer = passbook_harden.undo()
        if answer.get("needs_root"):
            return _fail("That removes root-owned files.",
                         "Run:  sudo passbook harden --undo")
        if not answer.get("ok"):
            return _fail(answer.get("why", "could not undo it"))
        for path in answer.get("removed", []):
            print(f"removed {path}")
        print("The broker is yours again. Start one:  passbook broker start")
        return 0

    if args.keychain_prompt:
        exposure = passbook_harden.keychain_exposure()
        if not exposure.get("exposed"):
            print(exposure.get("why", "nothing to tighten."))
            return 0
        print("This makes every read of the vault key ask a person.")
        print(f"Cost: {exposure['cost']}")
        try:
            if input("Type 'prompt' to continue: ").strip() != "prompt":
                return _fail("Left alone.")
        except (EOFError, KeyboardInterrupt):
            print()
            return _fail("Left alone.")
        answer = passbook_harden.require_keychain_prompt()
        if not answer.get("ok"):
            return _fail(answer.get("why", "could not tighten it"))
        print(f"\nDone. {answer['note']}")
        return 0

    if args.install:
        answer = passbook_harden.install()
        if answer.get("needs_root"):
            # Deliberately not re-running under sudo. A tool that escalates on
            # its own behalf teaches people to let tools escalate, and this one
            # is asking to own a path everything else will trust.
            print("This needs root: it writes to /usr/local/libexec and /Library/LaunchAgents.")
            print("\nIt will:")
            for step in passbook_harden.plan():
                print(f"  · {step['what']}")
                print(f"      {step['why']}")
            print("\nRun:  sudo passbook harden --install")
            print("Undo: sudo passbook harden --undo")
            return 1
        if not answer.get("ok"):
            return _fail(answer.get("why", "could not install it"))
        print(f"PassBook now runs from {answer['runtime']}, owned by root.")
        print(f"Started by {answer['plist']}, also owned by root.")
        print("\nCheck it:  passbook harden")
        return 0

    state = passbook_harden.posture()
    if args.json:
        print(json.dumps(state, indent=2))
        return 0
    if args.plan:
        for step in passbook_harden.plan():
            print(f"  · {step['what']}")
            print(f"      {step['why']}")
        return 0

    debugger = state["debugger"]
    print(f"debugger:    {'refused by ' + debugger['how'] if debugger['supported'] else 'CANNOT be refused on ' + state['code']['path']}")
    print(f"code:        {state['code']['path']}")
    print(f"             {'writable by you' if state['code']['writable_by_you'] else 'not writable by you'}")
    print(f"broker start:{' installed, root-owned' if state['daemon']['installed'] else ' by hand'}")
    if state["gaps"]:
        print("\nStill open:")
        for gap in state["gaps"]:
            print(f"  · {gap}")
        print("\nClose them:  sudo passbook harden --install")
        print("See exactly what that does, first:  passbook harden --plan")
    else:
        print("\nNothing further this machine can do in user space.")
    print(f"\n{state['always']}")
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    """One JSON object describing this machine's PassBook. Never a value."""
    print(json.dumps(machine_state(verify=getattr(args, "verify", False)),
                     indent=2 if args.pretty else None))
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    """Hold the door open for a stated period, then let it shut by itself.

    This is the answer to being asked forty times an hour, which is how a policy
    gets switched off for good. Approve once, say for how long, and everything
    the unlock covers stops asking until it expires.
    """
    module, broker = _access(), _broker()
    if module is None:
        return _fail("Access modes are not installed on this machine.")
    keys = [key for item in (args.keys or []) for key in item.split(",") if key.strip()]
    try:
        if broker is not None and broker.running():
            answer = broker._ask({"op": "unlock", "duration": args.duration,
                                  "keys": keys, "app": args.app, "reason": args.reason})
            if not answer or not answer.get("ok"):
                return _fail((answer or {}).get("error") or "Could not open the unlock.")
            unlock = answer["session"]
        else:
            unlock = module.open_session(duration=args.duration, keys=keys,
                                         app=args.app, reason=args.reason)
    except ValueError as error:
        return _fail(str(error), f"Presets: {', '.join(module.DURATION_PRESETS)}")

    scope = ", ".join(unlock["keys"]) if unlock["keys"] else "every key"
    where = f" for {unlock['app']}" if unlock["app"] else ""
    print(f"Unlocked {scope}{where} for {module.describe_duration(unlock['duration_seconds'])}.")
    print(f"It closes on its own at {unlock['expires']}. End it early with:  passbook lock")
    if not unlock["keys"] and not unlock["app"]:
        # Say the quiet part. This is the mode where anything running as this
        # user can use every key without being asked, and that is the point of
        # it — but it should never be something someone did without noticing.
        print("\nWhile it is open, anything running as you can use any key without asking.")
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    module, broker = _access(), _broker()
    if module is None:
        return _fail("Access modes are not installed on this machine.")
    if broker is not None and broker.running():
        answer = broker._ask({"op": "lock", "id": args.id}) or {}
        result = {"closed": answer.get("closed", 0), "remaining": answer.get("remaining", 0)}
    else:
        result = module.close_session(args.id)
    if not result["closed"]:
        print("Nothing was unlocked.")
        return 0
    print(f"Closed {result['closed']} unlock(s)." + (f" {result['remaining']} still open." if result["remaining"] else ""))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    """Answer the requests waiting on a person."""
    module = _broker()
    if module is None:
        return _fail("The broker is not installed on this machine.")
    if not module.running():
        return _fail("The broker is not running, so nothing is waiting.",
                     "Requests only wait when a policy says `ask`.")
    waiting = (module._ask({"op": "pending"}) or {}).get("pending", [])
    if not args.id:
        if not waiting:
            print("Nothing is waiting.")
            return 0
        for item in waiting:
            print(f"{item['id']}  {item['app']:<28} {', '.join(item['keys'])}")
            if item.get("reason"):
                print(f"          {item['reason']}")
        print("\nApprove with:  passbook approve <id> [--for 1h]")
        print("Decline with:  passbook approve <id> --deny")
        return 0

    answer = module._ask({"op": "resolve", "id": args.id, "approve": not args.deny,
                          "remember": args.remember, "by": "owner"}) or {}
    if not answer.get("ok"):
        return _fail(answer.get("detail") or "That request is no longer waiting.")
    if args.deny:
        print("Declined.")
        return 0
    print("Approved." + (f" Held open for {args.remember}." if args.remember else " This once."))
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    """Show, set, or derive how each key is answered."""
    module = _access()
    if module is None:
        return _fail("Access modes are not installed on this machine.")

    if args.learn:
        broker = _broker()
        if broker is None:
            return _fail("The broker is not installed on this machine.")
        derived = broker.learn_policy(mode=args.mode or "always")
        module.write_policy(derived)
        print(f"policy written to {module.policy_path()}")
        print("\nDerived from what the record shows these apps have already asked for.")
        print("Check it before relying on it — anything an app has not needed yet is")
        print("not in here, and will fall to the default.\n")
        args = argparse.Namespace(**{**vars(args), "mode": "", "learn": False})

    policy = module.read_policy()

    if getattr(args, "reads", ""):
        # The machine-wide switch: whether a caller this broker did not start
        # may receive a value at all. Written here rather than as its own
        # command because it is a policy, and somebody looking for it will look
        # where the other answers live.
        policy["reads"] = args.reads
        module.write_policy(policy)
        if args.reads == "sealed":
            print("Reads are sealed. Values now go only into processes the broker starts.")
            print("Anything that needs a credential runs through:  passbook run -- <command>")
            print("\nCheck nothing broke:  passbook grants")
        else:
            print("Reads are open. Callers may read values directly again.")
        return 0

    if args.mode:
        entry = policy["apps"].setdefault(args.app or "*", {})
        rule: dict = {"mode": args.mode}
        if args.mode == "window":
            if not args.window_from or not args.window_to:
                return _fail("A window needs --from and --to, as HH:MM.")
            rule["window"] = {"from": args.window_from, "to": args.window_to}
            if args.days:
                rule["window"]["days"] = [day for item in args.days for day in item.split(",") if day.strip()]
        if args.key:
            entry.setdefault("keys", {})[args.key] = rule
        else:
            entry["default"] = rule
        module.write_policy(policy)
        target = f"{args.key or 'every key'} for {args.app or 'every app'}"
        print(f"{target}: {args.mode}")
        if args.mode == "ask":
            print("Requests will wait for you. Answer them with:  passbook approve")
        return 0

    print(f"default: {policy['default'].get('mode', module.DEFAULT_MODE)}")
    for app, entry in sorted(policy["apps"].items()):
        fallback = (entry.get("default") or {}).get("mode", "—")
        print(f"\n{app}: {fallback}")
        for key, rule in sorted((entry.get("keys") or {}).items()):
            detail = f"  ({module.describe_window(rule)})" if rule.get("mode") == "window" else ""
            print(f"  {key}: {rule.get('mode')}{detail}")
    live = module.sessions()
    if live:
        print("\nopen unlocks:")
        for item in live:
            scope = ", ".join(item["keys"]) if item["keys"] else "every key"
            print(f"  {item['id']}  {scope}  {module.describe_duration(item['remaining_seconds'])} left")
    return 0


def cmd_broker(args: argparse.Namespace) -> int:
    """Whether the broker is up, what it would decide, and what that is worth."""
    module = _broker()
    if module is None:
        return _fail("The broker is not installed on this machine.")
    state = module.status()
    if args.json:
        print(json.dumps(state, indent=2))
        return 0 if state["running"] else 1
    print(f"broker:  {'running' if state['running'] else 'not running'}")
    print(f"socket:  {state['path']}")
    print(f"default: {state['mode']}")
    for item in state.get("sessions") or []:
        scope = ", ".join(item["keys"]) if item["keys"] else "every key"
        print(f"unlock:  {scope} — {item['remaining_seconds']}s left")
    if state.get("pending"):
        print(f"waiting: {len(state['pending'])} request(s) — answer with `passbook approve`")
    print(f"policy:  {state['policy_path']}")
    if state["apps"]:
        print(f"apps:    {', '.join(state['apps'])}")
    if not state["running"]:
        print("\nStart it with:  passbook broker start")
    print(LIMITS)
    return 0


def cmd_broker_start(args: argparse.Namespace) -> int:
    module = _broker()
    if module is None:
        return _fail("The broker is not installed on this machine.")
    result = module.start()
    if not result.get("ok"):
        return _fail(result.get("detail") or "The broker did not start.")
    if result.get("already"):
        print("Already running.")
        return 0
    policy = module.read_policy()
    default = policy["default"].get("mode", "always")
    print(f"Broker running on {result['path']} (pid {result['pid']}), default {default}.")
    if default == "always":
        print("\nEvery read is now recorded. Once your apps have run a while:")
        print("  passbook policy --learn      then set the modes you want")
    print(LIMITS)
    return 0


def cmd_broker_stop(args: argparse.Namespace) -> int:
    module = _broker()
    if module is None:
        return _fail("The broker is not installed on this machine.")
    result = module.stop()
    print(result.get("detail", ""))
    # Stopping is not a failure state worth an exit code: apps fall back to the
    # files by design, so nothing breaks — the record simply goes back to being
    # only as complete as each app chooses to be.
    return 0


def cmd_broker_restart(args: argparse.Namespace) -> int:
    """Stop it and start it again — after an upgrade, mostly.

    The broker is a long-running daemon, so a new PassBook on disk is not a new
    broker in memory: it goes on answering `unknown operation` to anything added
    since it started, which reads as a broken feature rather than a stale
    process.

    Restarting drops the data key, by design — it lives in memory and nowhere
    else. So this says plainly that a sign-in is needed next, rather than
    leaving someone to discover it when the next read comes back empty.
    """
    module = _broker()
    if module is None:
        return _fail("The broker is not installed on this machine.")
    was_open = False
    try:
        import passbook_vault  # noqa: F401

        was_open = bool(module.vault_status().get("unlocked"))
    except Exception:  # noqa: BLE001 — the restart matters more than the notice
        pass

    module.stop()
    result = module.start()
    if not result.get("ok"):
        return _fail(result.get("detail") or "The broker did not come back up.",
                     "Start it by hand:  passbook broker start")
    print(f"Broker restarted on {result['path']} (pid {result['pid']}).")
    if was_open:
        print("\nThe vault was open, and the key it held did not survive the restart —")
        print("it lives in memory and nowhere else. Nothing on this machine can read a")
        print("sealed value until you sign in again:")
        print("  passbook signin")
    return 0


def cmd_broker_run(args: argparse.Namespace) -> int:
    """Run in the foreground, for launchd, systemd, or watching it work."""
    module = _broker()
    if module is None:
        return _fail("The broker is not installed on this machine.")
    try:
        module.serve()
    except RuntimeError as error:
        return _fail(str(error))
    except KeyboardInterrupt:
        pass
    return 0


# ── setup ──────────────────────────────────────────────────────────────────
#
# Sealing and linking need `cryptography`, which is not in the standard library
# and cannot be installed into a system Python on most machines: Homebrew,
# Debian and Ubuntu all mark theirs externally managed (PEP 668) and refuse.
# Telling a first-time user to "just pip install it" therefore fails for most
# of them, and fails with an error about their operating system rather than
# about PassBook.
#
# So setup provisions its own interpreter instead of asking. It never installs
# into, or modifies, any Python the machine already relies on.
#
# The library never does any of this. Only this command, only when run.

RUNTIME_DIRNAME = "passbook-runtime"


def runtime_root() -> Path:
    return passbook.root() / RUNTIME_DIRNAME


def _interpreter_in(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")


def _has_crypto(interpreter: str | Path) -> bool:
    try:
        return subprocess.run(
            [str(interpreter), "-c", "import cryptography"],
            capture_output=True, timeout=60,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _provision_runtime(quiet: bool = False) -> tuple[Path | None, str]:
    """Build an isolated interpreter that has `cryptography`. Never touches the system one."""
    venv = runtime_root()
    interpreter = _interpreter_in(venv)
    if interpreter.exists() and _has_crypto(interpreter):
        return interpreter, "already provisioned"

    def say(message: str) -> None:
        if not quiet:
            print(message)

    uv = shutil.which("uv")
    steps: list[list[str]] = []
    if uv:
        steps = [[uv, "venv", str(venv)], [uv, "pip", "install", "--python", str(interpreter), "cryptography"]]
        say("provisioning a private runtime with uv…")
    else:
        steps = [
            [sys.executable, "-m", "venv", str(venv)],
            [str(interpreter), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "cryptography"],
        ]
        say("provisioning a private runtime…")

    for step in steps:
        try:
            done = subprocess.run(step, capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as error:
            return None, f"could not run {Path(step[0]).name}: {error}"
        if done.returncode != 0:
            detail = (done.stderr or done.stdout or "").strip().splitlines()
            return None, (detail[-1] if detail else f"{Path(step[0]).name} failed")

    if not _has_crypto(interpreter):
        return None, "the runtime was created but `cryptography` is still not importable"
    return interpreter, "provisioned"


def resolve_interpreter(*, provision: bool, quiet: bool = False) -> tuple[str, str]:
    """Which interpreter the installed commands should run under, and why."""
    if _has_crypto(sys.executable):
        return sys.executable, "this Python already has everything"
    existing = _interpreter_in(runtime_root())
    if existing.exists() and _has_crypto(existing):
        return str(existing), "using the private runtime"
    if not provision:
        return sys.executable, "no runtime yet; sealing and linking are unavailable"
    interpreter, detail = _provision_runtime(quiet=quiet)
    if interpreter is None:
        return sys.executable, detail
    return str(interpreter), detail


SHIM = """#!/bin/sh
# PassBook — generated by `passbook install`. Safe to delete; re-run to restore.
PASSBOOK_INVOKED_AS="${0##*/}" \
PYTHONPATH="%(package)s${PYTHONPATH:+%(sep)s$PYTHONPATH}" \
exec "%(python)s" -m passbook_cli "$@"
"""

# The same shim for a shell that is not a shell. Kept ASCII, because a .cmd is
# read in whatever codepage the console is in.
#
# `setlocal` matters: without it a .cmd's `set` lands in the calling prompt, so
# running `passbook` once would leave PYTHONPATH pointing at the checkout for
# everything else typed afterwards. `exit /b` matters for the same reason
# `passbook run` had to stop using `os.execvpe` here — the exit code is the
# answer for anything scripting this.
SHIM_WINDOWS = """@echo off
REM PassBook - generated by `passbook install`. Safe to delete; re-run to restore.
setlocal
set "PASSBOOK_INVOKED_AS=%(name)s"
if defined PYTHONPATH (set "PYTHONPATH=%(package)s;%%PYTHONPATH%%") else (set "PYTHONPATH=%(package)s")
"%(python)s" -m passbook_cli %%*
exit /b %%ERRORLEVEL%%
"""


def default_prefix() -> str:
    """Where the commands go, by the convention of the platform.

    `~/.local/bin` is a POSIX habit and is on nobody's PATH on Windows, so
    installing there produced 44 files that could not be run and a closing
    message explaining how to add a directory to PATH with `export`.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return str(Path(base) / "PassBook" / "bin")
    return "~/.local/bin"


def cmd_install(args: argparse.Namespace) -> int:
    """Set PassBook up end to end: a runtime, the commands, and the store."""
    target = Path(args.prefix).expanduser()
    package = Path(__file__).resolve().parent

    interpreter, why = resolve_interpreter(provision=not args.no_runtime)
    sealing_ready = _has_crypto(interpreter)

    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        return _fail(f"Could not create {target}: {error}")

    windows = os.name == "nt"
    body = None if windows else SHIM % {
        "package": package, "python": interpreter, "sep": os.pathsep}
    written, refused = [], []
    for name in ["passbook", *sorted(aliases())]:
        # Windows resolves a bare `passbook` through PATHEXT, and an extensionless
        # file is not on it. The shim has to carry its own name, too: there is no
        # `$0` to read it back out of.
        shim = target / (f"{name}.cmd" if windows else name)
        if windows:
            body = SHIM_WINDOWS % {
                "name": name, "package": package, "python": interpreter}
        # Never clobber something that is not ours. A stray `passbook` binary
        # from elsewhere is the user's, and silently replacing it is the kind of
        # installer behaviour that makes people distrust installers.
        if shim.exists() and not shim.is_symlink():
            try:
                if "generated by `passbook install`" not in shim.read_text(encoding="utf-8"):
                    refused.append(name)
                    continue
            except (OSError, UnicodeDecodeError):
                refused.append(name)
                continue
        shim.unlink(missing_ok=True)
        if windows:
            shim.write_bytes(body.replace("\n", "\r\n").encode("ascii"))
        else:
            shim.write_text(body, encoding="utf-8")
            shim.chmod(0o755)
        written.append(name)

    joined = passbook.ensure(app="passbook-cli", name="PassBook")

    print(f"\ncommands:  {len(written)} installed in {target}")
    # The shims point back at this directory, so it is load-bearing: moving or
    # deleting the checkout breaks them. Naming it here is cheaper than the
    # confusion later. `uv tool install` has no such coupling.
    print(f"           running from {package}")
    if refused:
        print(f"           skipped (not ours): {', '.join(refused)}")
    print(f"runtime:   {interpreter}")
    print(f"           {why}")
    print(f"store:     {passbook.describe()}")
    if joined.get("provisioned"):
        print("           created — a HivemindOS install later will adopt this same store")
    print(f"sealing and linking: {'ready' if sealing_ready else 'UNAVAILABLE'}")
    if not sealing_ready:
        print("\n  `passbook seal` and `passbook link` need cryptography, and setup could not")
        print(f"  provide it: {why}.")
        print("  Everything else works. Re-run `passbook install` to try again.")

    on_path = any(
        Path(entry) == target
        for entry in os.environ.get("PATH", "").split(os.pathsep) if entry
    )
    if not on_path:
        print(f"\n{target} is not on your PATH yet.")
        if os.name == "nt":
            # `setx` writes the user's environment for good, which is what the
            # shell profile line does on the other platforms. It does not change
            # the session running now, so say that rather than let it look
            # broken in the very next command.
            print("Add it for good:\n")
            print(f'    setx PATH "%PATH%;{target}"')
            print("\nThen open a new terminal; `setx` does not touch this one.")
        else:
            print("Add this to your shell profile:\n")
            print(f'    export PATH="{target}:$PATH"')
    else:
        print("\nTry:  passbook-check OPENAI_API_KEY")

    # The commands are on PATH now, and nothing on the machine knows it. An
    # agent that has not been told about sealing reports a locked key as
    # missing and offers to add it again, which is how a working credential
    # gets a second copy written over the top of it.
    if not getattr(args, "no_agents", False):
        brief = _brief()
        if brief is not None:
            runtimes = brief.detected()
            if runtimes:
                written = brief.install(runtimes)
                if not getattr(args, "no_mcp", False):
                    brief.register(runtimes)
                changed = [w for w in written if w["state"] in ("briefed", "updated")]
                if changed:
                    print(f"\nagents:    briefed {len(changed)} runtime(s) — "
                          f"{', '.join(w['id'] for w in changed)}")
                    print("           they read it at the start of a session")
    return 0


# ── argument parsing ───────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passbook",
        description="One credential store per machine, shared by every app that opts in.",
        epilog="Every subcommand is also available hyphenated: passbook-check, passbook-add, ...",
    )
    subs = parser.add_subparsers(dest="command", required=True)

    check = subs.add_parser(
        "check", help="report whether keys are set, locked or missing (never their values)",
        description="Set means readable here and now. Locked means it is in the store "
                    "but encrypted, and `passbook signin` will open it — it is not gone, "
                    "and adding it again would overwrite a working credential. Missing "
                    "means genuinely absent.")
    check.add_argument("keys", nargs="+")
    check.add_argument("--length", action="store_true", help="also show each value's length")
    check.add_argument("--quiet", "-q", action="store_true", help="exit code only")
    check.add_argument("--app", default="", help="who is asking; recorded")
    check.set_defaults(func=cmd_check)

    add = subs.add_parser("add", help="add keys; a bare KEY prompts without echo")
    add.add_argument("pairs", nargs="*", metavar="KEY[=value]")
    add.add_argument("--replace", action="store_true", help="overwrite a key that is already set")
    add.add_argument("--stdin", action="store_true", help="read KEY=value lines from stdin")
    add.add_argument("--app", default="", help="who is asking; recorded")
    add.set_defaults(func=cmd_add)

    remove = subs.add_parser("remove", aliases=["delete"], help="delete keys from the store")
    remove.add_argument("keys", nargs="+")
    remove.add_argument("--app", default="", help="who is asking; recorded")
    remove.set_defaults(func=cmd_remove)

    run = subs.add_parser("run", help="run a command with the store loaded as a base")
    run.add_argument("--app", default="", help="who is asking; recorded")
    run.add_argument("--only", action="append", metavar="KEY", default=[],
                     help="hand the child only these keys; repeatable")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    get_cmd = subs.add_parser("get", help="print named values, for a script that needs them")
    get_cmd.add_argument("keys", nargs="+", metavar="KEY")
    get_cmd.add_argument("--json", action="store_true", help="as a JSON object")
    get_cmd.add_argument("--pretty", action="store_true")
    get_cmd.add_argument("--app", default="", help="who is asking; recorded")
    get_cmd.add_argument("--reason", default="", help="why; recorded")
    get_cmd.set_defaults(func=cmd_get)

    listing = subs.add_parser("list", help="list key names")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(func=cmd_list)

    status = subs.add_parser("status", help="where the store is, how many keys, which apps")
    status.add_argument("--json", action="store_true")
    status.add_argument("--repair", action="store_true",
                        help="remove shadowed duplicate lines, keeping the last")
    status.set_defaults(func=cmd_status)

    access = subs.add_parser("access", help="the tamper-evident record of credential reads")
    access.add_argument("--limit", type=int, default=40)
    access.add_argument("--verify", action="store_true", help="check the chain and exit")
    access.set_defaults(func=cmd_access)

    seal = subs.add_parser("seal", help="encrypt every plaintext value in the store")
    seal.add_argument("--profile", default="", help="seal under this profile; omit for the active one")
    seal.add_argument("--json", action="store_true")
    seal.add_argument("--skip", nargs="+", default=[], metavar="KEY",
                      help="leave these readable — feature flags read before sign-in")
    seal.add_argument("--password-stdin", dest="password_stdin",
        action="store_true", help="read the password from stdin instead of prompting")

    unseal = subs.add_parser("unseal", help="put the store back to plaintext — the way out of sealing")
    unseal.add_argument("--profile", default="", help="which profile sealed it; omit for the active one")
    unseal.add_argument("--only", nargs="+", default=[], metavar="KEY",
                        help="release just these, and remember to leave them readable")
    unseal.add_argument("--password-stdin", dest="password_stdin",
        action="store_true", help="read the password from stdin instead of prompting")
    unseal.set_defaults(func=cmd_unseal)

    secure = subs.add_parser("secure",
                             help="encrypt the store and sign in — the whole thing, once")
    secure.add_argument("--profile-name", default="", help="name for a new profile")
    secure.add_argument("--profile", default="", help="use an existing profile")
    secure.add_argument("--skip", nargs="+", default=[], metavar="KEY",
                        help="extra keys to leave readable, on top of the public-prefix defaults")
    secure.add_argument("--for", dest="duration", default="", metavar="DURATION")
    secure.add_argument("--password-stdin", dest="password_stdin", action="store_true")
    secure.set_defaults(func=cmd_secure)

    profile_cmd = subs.add_parser("profile", help="who can open a workspace's vault")
    profile_cmd.add_argument("--json", action="store_true")
    profile_cmd.add_argument("--workspace", default="",
                             help="which workspace's profiles; omit for the active one")
    profile_cmd.set_defaults(func=cmd_profile)
    profile_subs = profile_cmd.add_subparsers(dest="profile_command")

    profile_create = profile_subs.add_parser("create", help="create a profile with a vault password")
    profile_create.add_argument("label", help="what to call it")
    profile_create.add_argument("--use", action="store_true",
                                help="also make it the profile you sign in to")
    profile_create.add_argument("--workspace", default="",
                                help="give this workspace a key of its own")
    profile_create.add_argument("--password-stdin", dest="password_stdin",
        action="store_true", help="read the password from stdin instead of prompting")
    profile_create.set_defaults(json=False, func=cmd_profile_create)

    profile_use = profile_subs.add_parser("use", help="make a profile the active one")
    profile_use.add_argument("label")
    profile_use.set_defaults(json=False, func=cmd_profile_use)

    profile_remove = profile_subs.add_parser("remove", help="forget a profile and everything it sealed")
    profile_remove.add_argument("label")
    profile_remove.add_argument("--yes", action="store_true", help="confirm the loss")
    profile_remove.set_defaults(json=False, func=cmd_profile_remove)

    profile_device = profile_subs.add_parser(
        "trust-device", help="let this machine open the vault unattended (weaker)")
    profile_device.add_argument("--profile", default="")
    profile_device.add_argument("--yes", action="store_true", help="accept the trade-off")
    profile_device.add_argument("--password-stdin", dest="password_stdin",
        action="store_true", help="read the password from stdin instead of prompting")
    profile_device.set_defaults(json=False, func=cmd_profile_device)

    signin = subs.add_parser("signin", help="open the vault so apps can read credentials")
    signin.add_argument("--profile", default="", help="which profile; omit for the active one")
    signin.add_argument("--workspace", default="",
                        help="which workspace to open; omit for the active one")
    signin.add_argument("--for", dest="duration", default="", metavar="DURATION",
                        help="how long to stay open: 8h, 2d, or `always`. Omit it and "
                             "the workspace keeps whatever it is already on, or `always` "
                             "if it is not open yet")
    signin.add_argument("--device", action="store_true",
                        help="use this machine's device factor instead of a password")
    signin.add_argument("--passkey", default="", metavar="CREDENTIAL_ID",
                        help="sign in with a passkey; its PRF secret is read from stdin")
    signin.add_argument("--recovery", action="store_true",
                        help="sign in with a recovery code instead of the password")
    signin.add_argument("--password-stdin", dest="password_stdin",
        action="store_true", help="read the password from stdin instead of prompting")
    signin.set_defaults(func=cmd_signin)

    vault_cmd = subs.add_parser("vault", help="is the vault open, and who can open it")
    vault_cmd.add_argument("--json", action="store_true")
    vault_cmd.set_defaults(func=cmd_vault)

    passkey_cmd = subs.add_parser("passkey", help="passkeys that can open a profile")
    passkey_cmd.add_argument("--json", action="store_true")
    passkey_cmd.set_defaults(func=cmd_passkey)
    passkey_subs = passkey_cmd.add_subparsers(dest="passkey_command")

    passkey_enrol = passkey_subs.add_parser(
        "enrol", aliases=["enroll", "add"],
        help="add a passkey, reading its PRF secret from stdin")
    passkey_enrol.add_argument("--credential-id", required=True,
                               help="the WebAuthn credential id it belongs to")
    passkey_enrol.add_argument("--label", default="passkey")
    passkey_enrol.add_argument("--rp-id", default="", help="the relying party it was made for")
    passkey_enrol.add_argument("--profile", default="")
    passkey_enrol.add_argument("--workspace", default="",
                               help="which workspace's vault; omit for the active one")
    passkey_enrol.add_argument("--password-stdin", dest="password_stdin", action="store_true",
                               help="read the vault password from stdin, after the PRF secret")
    passkey_enrol.set_defaults(json=False, func=cmd_passkey_enrol)

    oauth = subs.add_parser("oauth", help="sign-ins this machine holds, kept alive")
    oauth.add_argument("--json", action="store_true")
    oauth.set_defaults(func=cmd_oauth)
    oauth_subs = oauth.add_subparsers(dest="oauth_command")

    oauth_add = oauth_subs.add_parser("add", help="describe a sign-in (does not connect it)")
    oauth_add.add_argument("provider", help="google, github, microsoft, or custom")
    oauth_add.add_argument("label", nargs="?", default="", help="e.g. work — lets you hold several")
    oauth_add.add_argument("--client-id", required=True, help="the client you registered")
    oauth_add.add_argument("--client-secret-stdin", action="store_true",
                           help="read a confidential client's secret from stdin")
    oauth_add.add_argument("--authorize-url", default="", help="for a custom provider")
    oauth_add.add_argument("--token-url", default="", help="for a custom provider")
    oauth_add.add_argument("--scope", default="")
    oauth_add.add_argument("--key-prefix", default="", help="names the store keys; derived if omitted")
    oauth_add.add_argument("--redirect-port", type=int, default=0,
                           help="fixed port, when the provider registered one")
    oauth_add.set_defaults(json=False, func=cmd_oauth_add)

    oauth_connect = oauth_subs.add_parser("connect", help="sign in through the browser")
    oauth_connect.add_argument("id")
    oauth_connect.add_argument("--port", type=int, default=0)
    oauth_connect.add_argument("--timeout", type=float, default=180.0)
    oauth_connect.add_argument("--no-browser", action="store_true")
    oauth_connect.set_defaults(json=False, func=cmd_oauth_connect)

    oauth_refresh = oauth_subs.add_parser("refresh", help="renew now, without waiting for expiry")
    oauth_refresh.add_argument("id")
    oauth_refresh.set_defaults(json=False, func=cmd_oauth_refresh)

    oauth_remove = oauth_subs.add_parser("remove", aliases=["disconnect"], help="forget a sign-in")
    oauth_remove.add_argument("id")
    oauth_remove.add_argument("--yes", action="store_true")
    oauth_remove.add_argument("--keep-tokens", action="store_true",
                              help="forget the sign-in but leave its keys in the store")
    oauth_remove.set_defaults(json=False, func=cmd_oauth_remove)

    parser.add_argument("--version", action="store_true",
                        help="print the installed version and exit")

    brief_cmd = subs.add_parser(
        "brief", help="tell the coding agents on this machine that PassBook is here")
    brief_cmd.add_argument("--json", action="store_true")
    brief_cmd.set_defaults(func=cmd_brief)
    brief_subs = brief_cmd.add_subparsers(dest="brief_command")

    brief_install = brief_subs.add_parser(
        "install", help="write the brief into every runtime found here")
    brief_install.add_argument("--only", default="",
                               help="comma-separated runtime ids instead of every one found")
    brief_install.add_argument("--no-mcp", action="store_true",
                               help="write the brief but do not register the MCP server")
    brief_install.set_defaults(json=False, func=cmd_brief_install)

    brief_remove = brief_subs.add_parser("remove", help="take the brief back out")
    brief_remove.add_argument("--only", default="")
    brief_remove.set_defaults(json=False, func=cmd_brief_remove)

    update_cmd = subs.add_parser("update", help="move this copy to the newest release")
    update_cmd.add_argument("--check", action="store_true",
                            help="say whether one is available and stop")
    update_cmd.add_argument("--json", action="store_true")
    update_cmd.set_defaults(func=cmd_update)

    mcp = subs.add_parser("mcp", help="speak MCP on stdio so any agent can find these credentials")
    mcp.set_defaults(func=cmd_mcp)

    umbrella_cmd = subs.add_parser(
        "umbrella", help="cover several projects with one set of keys")
    umbrella_cmd.add_argument("--json", action="store_true")
    umbrella_cmd.set_defaults(func=cmd_umbrella)
    u_subs = umbrella_cmd.add_subparsers(dest="umbrella_command")

    u_new = u_subs.add_parser("new", help="create one; closed and unlisted by default")
    u_new.add_argument("name")
    u_new.add_argument("--tag", action="append", metavar="TAG",
                       help="what it is for; agents read these when it is shown to them")
    u_new.add_argument("--note", default="", help="one line an agent can read")
    u_new.add_argument("--everyone", action="store_true", help="usable from every project")
    u_new.add_argument("--listed", action="store_true", help="agents are told it exists")
    u_new.set_defaults(json=False, func=cmd_umbrella_new)

    u_cover = u_subs.add_parser("cover", help="put a project under it")
    u_cover.add_argument("umbrella")
    u_cover.add_argument("projects", nargs="+", metavar="PROJECT")
    u_cover.set_defaults(json=False, func=cmd_umbrella_cover)

    u_uncover = u_subs.add_parser("uncover", help="take a project out")
    u_uncover.add_argument("umbrella")
    u_uncover.add_argument("projects", nargs="+", metavar="PROJECT")
    u_uncover.set_defaults(json=False, func=cmd_umbrella_uncover)

    u_add = u_subs.add_parser("add", help="put keys under it")
    u_add.add_argument("umbrella")
    u_add.add_argument("keys", nargs="+", metavar="KEY")
    u_add.set_defaults(json=False, func=cmd_umbrella_add)

    u_rm = u_subs.add_parser("remove", help="take keys out from under it")
    u_rm.add_argument("keys", nargs="+", metavar="KEY")
    u_rm.set_defaults(json=False, func=cmd_umbrella_remove)

    u_reach = u_subs.add_parser("reach", help="who may USE it")
    u_reach.add_argument("umbrella")
    u_reach.add_argument("reach", choices=("members", "everyone"))
    u_reach.set_defaults(json=False, func=cmd_umbrella_reach)

    u_show = u_subs.add_parser("show-agents", help="whether agents are told it exists")
    u_show.add_argument("umbrella")
    u_show.add_argument("--hide", action="store_true", help="stop telling them")
    u_show.set_defaults(json=False, func=cmd_umbrella_show_agents)

    u_open = u_subs.add_parser("open", help="every project, and agents can see it")
    u_open.add_argument("umbrella")
    u_open.set_defaults(json=False, func=cmd_umbrella_open)

    u_close = u_subs.add_parser("close", help="its own projects, and not advertised")
    u_close.add_argument("umbrella")
    u_close.set_defaults(json=False, func=cmd_umbrella_close)

    u_tag = u_subs.add_parser("tag", help="what it is for")
    u_tag.add_argument("umbrella")
    u_tag.add_argument("--tag", action="append", metavar="TAG")
    u_tag.add_argument("--note", default=None)
    u_tag.set_defaults(json=False, func=cmd_umbrella_tag)

    u_del = u_subs.add_parser("delete", help="remove it; its keys stop being limited")
    u_del.add_argument("umbrella")
    u_del.set_defaults(json=False, func=cmd_umbrella_delete)

    group_cmd = subs.add_parser("group", help="how the store is arranged")
    group_cmd.add_argument("--json", action="store_true")
    group_cmd.add_argument("-v", "--verbose", action="store_true", help="list the keys in each group")
    group_cmd.set_defaults(func=cmd_group)
    group_subs = group_cmd.add_subparsers(dest="group_command")
    group_set = group_subs.add_parser("set", help="pin keys to a group; empty group returns to inference")
    group_set.add_argument("group")
    group_set.add_argument("keys", nargs="+", metavar="KEY")
    group_set.set_defaults(json=False, verbose=False, func=cmd_group_set)

    # No positional on the parent: an optional positional beside subparsers makes
    # `apps set KEY` ambiguous, and argparse resolves it by trying to parse the
    # key as a subcommand.
    #
    # `agents` is the name this had when the page was called Agents, and the
    # things it lists turned out to be daemons, command lines and builds. The
    # alias stays because someone's script says `agents`, and breaking that to
    # win a naming argument is not worth it.
    apps_cmd = subs.add_parser("apps", aliases=["agents"], help="who each key is for")
    apps_cmd.add_argument("--json", action="store_true")
    apps_cmd.set_defaults(key="", func=cmd_agents)
    agents_subs = apps_cmd.add_subparsers(dest="apps_command")

    agents_show = agents_subs.add_parser("show", help="the audience for one key")
    agents_show.add_argument("key")
    agents_show.set_defaults(json=False, func=cmd_agents)
    agents_set = agents_subs.add_parser("set", help="limit or open up one key")
    agents_set.add_argument("key")
    agents_set.add_argument("--everyone", action="store_true", help="the default: every app")
    agents_set.add_argument("--only", nargs="+", metavar="APP", help="only these apps")
    agents_set.add_argument("--block", nargs="+", metavar="APP", help="every app except these")
    agents_set.set_defaults(json=False, func=cmd_agents_set)

    # No positional on the parent — an optional one beside subparsers makes
    # `scope set KEY` parse the key as a subcommand. Same trap as `apps`.
    scope_cmd = subs.add_parser("scope", help="how far each key reaches across workspaces")
    scope_cmd.add_argument("--json", action="store_true")
    scope_cmd.set_defaults(key="", func=cmd_scope)
    scope_subs = scope_cmd.add_subparsers(dest="scope_command")
    scope_show = scope_subs.add_parser("show", help="one key's reach")
    scope_show.add_argument("key")
    scope_show.set_defaults(json=False, func=cmd_scope)
    scope_set = scope_subs.add_parser("set", help="set the reach of one key or many")
    scope_set.add_argument("keys", nargs="+", metavar="KEY")
    scope_set.add_argument("--workspace", action="store_true", help="this workspace only")
    scope_set.add_argument("--machine", action="store_true", help="every workspace on this machine")
    scope_set.add_argument("--tailnet", action="store_true",
                           help="as machine, and lendable to linked machines")
    scope_set.set_defaults(json=False, key="", func=cmd_scope_set)

    confirm_cmd = subs.add_parser("confirm", help="which changes stop and ask first")
    confirm_cmd.add_argument("op", nargs="?", default="", choices=["", "add", "modify", "delete"],
                             help="the change to turn on (or off, with --off)")
    confirm_cmd.add_argument("--off", action="store_true", help="turn it off instead")
    confirm_cmd.add_argument("--json", action="store_true")
    confirm_cmd.set_defaults(func=cmd_confirm)

    projects_cmd = subs.add_parser("projects", help="which projects each key is for")
    projects_cmd.add_argument("--json", action="store_true")
    projects_cmd.set_defaults(func=cmd_projects)
    projects_subs = projects_cmd.add_subparsers(dest="projects_command")
    projects_show = projects_subs.add_parser("show", help="every key's projects")
    projects_show.add_argument("--json", action="store_true")
    projects_show.set_defaults(func=cmd_projects)
    projects_set = projects_subs.add_parser("set", help="limit one key or many to projects")
    projects_set.add_argument("keys", nargs="+", metavar="KEY")
    projects_set.add_argument("--every", action="store_true", help="readable from every project")
    projects_set.add_argument("--only", nargs="+", default=[], metavar="PROJECT",
                              help="readable ONLY from these projects")
    projects_set.add_argument("--without", nargs="+", default=[], metavar="PROJECT",
                              help="readable from every project EXCEPT these")
    projects_set.set_defaults(json=False, func=cmd_projects_set)

    export_cmd = subs.add_parser("export", help="write this store to a file")
    export_cmd.add_argument("file")
    export_cmd.add_argument("--plain", action="store_true",
                            help="readable KEY=value lines (needs --i-understand)")
    export_cmd.add_argument("--i-understand", dest="i_understand", action="store_true",
                            help="acknowledge that a plaintext export is every value in the clear")
    export_cmd.add_argument("--gpg", action="store_true", help="armoured GPG instead")
    export_cmd.add_argument("--recipient", default="",
                            help="GPG recipient key id; without one, GPG is symmetric")
    export_cmd.add_argument("--note", default="", help="a line to carry with the export")
    export_cmd.add_argument("--password-stdin", dest="password_stdin", action="store_true",
                            help="read the passphrase from stdin instead of prompting")
    export_cmd.set_defaults(func=cmd_export)

    import_cmd = subs.add_parser("import", help="read an export into this store")
    import_cmd.add_argument("file")
    import_cmd.add_argument("--overwrite", action="store_true",
                            help="replace keys this store already holds")
    import_cmd.add_argument("--dry-run", dest="dry_run", action="store_true",
                            help="say what would change, and change nothing")
    import_cmd.add_argument("--recipient-key", dest="recipient_key", action="store_true",
                            help="a GPG export encrypted to your key, so gpg-agent has the passphrase")
    import_cmd.add_argument("--password-stdin", dest="password_stdin", action="store_true")
    import_cmd.add_argument("--json", action="store_true",
                            help="with --dry-run, describe the file as JSON")
    import_cmd.add_argument("--only", nargs="+", metavar="KEY", default=None,
                            help="import just these keys, not everything in the file")
    import_cmd.add_argument("--as", dest="rename", nargs="+", metavar="OLD=NEW", default=None,
                            help="import OLD under the name NEW, to keep both")
    import_cmd.set_defaults(func=cmd_import)

    recovery_cmd = subs.add_parser("recovery", help="mint a code that opens the vault without the password")
    recovery_cmd.add_argument("--profile", default="")
    recovery_cmd.add_argument("--label", default="recovery code")
    recovery_cmd.add_argument("--password-stdin", dest="password_stdin", action="store_true")
    recovery_cmd.set_defaults(func=cmd_recovery)

    forget_cmd = subs.add_parser("forget", help="stop counting a tailnet machine as holding this store")
    forget_cmd.add_argument("host")
    forget_cmd.set_defaults(func=cmd_forget)

    sync_cmd = subs.add_parser("sync", help="what replication would move between this machine and its peers")
    sync_cmd.add_argument("--apply", action="store_true",
                          help="actually pull what the plan lists (default is a dry run)")
    sync_cmd.add_argument("--repair", action="store_true",
                          help="find peers holding ciphertext they cannot open, and offer to replace it")
    sync_cmd.add_argument("--no-adopt", dest="no_adopt", action="store_true",
                          help="do not record the peers on the Machines page")
    sync_cmd.add_argument("--json", action="store_true")
    sync_cmd.set_defaults(func=cmd_sync)

    workspace_cmd = subs.add_parser("workspace", help="which workspace this machine acts for")
    workspace_cmd.add_argument("--json", action="store_true")
    workspace_cmd.set_defaults(func=cmd_workspace)
    workspace_subs = workspace_cmd.add_subparsers(dest="workspace_command")
    workspace_list = workspace_subs.add_parser("list", help="every workspace on this machine")
    workspace_list.add_argument("--json", action="store_true")
    workspace_list.set_defaults(func=cmd_workspace)
    workspace_show = workspace_subs.add_parser("show", help="the active workspace")
    workspace_show.add_argument("--json", action="store_true")
    workspace_show.set_defaults(func=cmd_workspace)
    workspace_use = workspace_subs.add_parser("use", help="switch the active workspace")
    workspace_use.add_argument("name")
    workspace_use.set_defaults(json=False, func=cmd_workspace_use)

    matrix = subs.add_parser("matrix", help="which apps can read which keys")
    matrix.add_argument("--app", "--agent", nargs="+", default=[], dest="agent",
                        metavar="APP", help="only these apps")
    matrix.add_argument("--group", default="", help="only this group")
    matrix.add_argument("--restricted", action="store_true", help="hide rows where everything is granted")
    matrix.add_argument("--json", action="store_true")
    matrix.set_defaults(func=cmd_matrix)

    signout = subs.add_parser("signout", help="lock the vault; credentials go dark again")
    signout.add_argument("--workspace", default="",
                         help="which workspace to lock; omit for the active one")
    signout.add_argument("--all", action="store_true",
                         help="lock every workspace this machine has open")
    signout.set_defaults(func=cmd_signout)
    seal.add_argument("--status", action="store_true", help="report without changing anything")
    seal.set_defaults(func=cmd_seal)

    link = subs.add_parser("link", help="lend named keys to another machine")
    link.add_argument("--json", action="store_true", help="machine-readable identity and grants")
    link.set_defaults(func=cmd_link)
    link_subs = link.add_subparsers(dest="link_command")

    request = link_subs.add_parser("request", help="on the machine that wants keys: print a pairing token")
    request.add_argument("--ttl", type=int, default=600, help="seconds the token stays valid")
    request.set_defaults(json=False, func=cmd_link_request)

    approve = link_subs.add_parser("approve", help="on the machine that has the keys: approve a device")
    approve.add_argument("token", help="the pairing token, a file holding it, or - for stdin")
    approve.add_argument("--keys", nargs="+", required=True, metavar="KEY", help="which keys to lend")
    approve.add_argument("--confirm", default="", metavar="FINGERPRINT",
                         help="the fingerprint shown on the joining machine")
    approve.add_argument("--days", type=int, default=30, help="how long the grant lasts")
    approve.add_argument("--workspace", default="", help="scope the grant to one workspace")
    approve.add_argument("--out", default="", metavar="FILE", help="write the envelope to a file")
    approve.set_defaults(json=False, func=cmd_link_approve)

    accept = link_subs.add_parser("accept", help="open an envelope and store the keys it carries")
    accept.add_argument("envelope", help="the envelope, a file holding it, or - for stdin")
    accept.add_argument("--confirm", default="", metavar="FINGERPRINT",
                        help="the sending machine's fingerprint, required the first time")
    accept.add_argument("--replace", action="store_true", help="overwrite keys already set here")
    accept.set_defaults(json=False, func=cmd_link_accept)

    revoke = link_subs.add_parser("revoke", help="stop lending to a machine")
    revoke.add_argument("did")
    revoke.set_defaults(json=False, func=cmd_link_revoke)

    history_cmd = subs.add_parser("history", help="what the record holds about one key")
    history_cmd.add_argument("key")
    history_cmd.add_argument("--limit", type=int, default=50)
    history_cmd.add_argument("--json", action="store_true")
    history_cmd.set_defaults(func=cmd_history)

    reveal_cmd = subs.add_parser("reveal", help="print one value — the only command that does")
    reveal_cmd.add_argument("key")
    reveal_cmd.add_argument("--app", default="", help="who is asking; recorded")
    reveal_cmd.add_argument("--reason", default="", help="recorded alongside the reveal")
    reveal_cmd.add_argument("--confirm", default="",
                            help="the key's own name, typed by a person somewhere "
                                 "that is not a terminal (the app's own window)")
    reveal_cmd.set_defaults(func=cmd_reveal)

    guard_cmd = subs.add_parser("guard", help="bind a key to where it may go; it is never printed")
    guard_cmd.add_argument("key", nargs="?", default="", metavar="KEY")
    guard_cmd.add_argument("--to", action="append", default=[], metavar="HOST",
                           help="a host this key may be sent to; .example.com covers subdomains")
    guard_cmd.add_argument("--into", action="append", default=[], metavar="PATTERN",
                           help="a command this key may be injected into, e.g. 'wrangler *'")
    guard_cmd.add_argument("--replace", action="store_true",
                           help="replace what is bound rather than adding to it")
    guard_cmd.add_argument("--clear", action="store_true", help="unguard this key")
    guard_cmd.set_defaults(func=cmd_guard)

    grants_cmd = subs.add_parser("grants", help="what is holding credentials right now")
    grants_cmd.add_argument("--json", action="store_true")
    grants_cmd.set_defaults(func=cmd_grants)

    harden_cmd = subs.add_parser("harden", help="what protects credentials at the OS level")
    harden_cmd.add_argument("--install", action="store_true",
                            help="install PassBook as root-owned code with a root-owned start")
    harden_cmd.add_argument("--undo", action="store_true", help="put the machine back")
    harden_cmd.add_argument("--keychain-prompt", action="store_true",
                            dest="keychain_prompt",
                            help="make every read of the vault key ask a person")
    harden_cmd.add_argument("--plan", action="store_true", help="show exactly what --install does")
    harden_cmd.add_argument("--json", action="store_true")
    harden_cmd.set_defaults(func=cmd_harden)

    state_cmd = subs.add_parser("state", help="everything a management surface needs, as JSON")
    state_cmd.add_argument("--pretty", action="store_true")
    state_cmd.add_argument("--verify", action="store_true",
                           help="also re-hash the whole access record to check the chain")
    state_cmd.set_defaults(func=cmd_state)

    unlock = subs.add_parser("unlock", help="hold access open for a stated period")
    unlock.add_argument("--for", dest="duration", default="1h", metavar="DURATION",
                        help="15m, 1h, 4h, 8h, 24h, or any duration up to 7d")
    unlock.add_argument("--keys", nargs="+", default=[], metavar="KEY",
                        help="only these keys; omit to cover every key")
    unlock.add_argument("--app", default="", help="only this app; omit to cover every app")
    unlock.add_argument("--reason", default="", help="recorded alongside the unlock")
    unlock.set_defaults(func=cmd_unlock)

    lock = subs.add_parser("lock", help="end an unlock early")
    lock.add_argument("id", nargs="?", default="", help="one unlock; omit to close all")
    lock.set_defaults(func=cmd_lock)

    approve = subs.add_parser("approve", help="answer requests that are waiting on you")
    approve.add_argument("id", nargs="?", default="", help="omit to list what is waiting")
    approve.add_argument("--deny", action="store_true", help="decline instead")
    approve.add_argument("--for", dest="remember", default="", metavar="DURATION",
                         help="also hold it open for this long")
    approve.set_defaults(func=cmd_approve)

    policy_cmd = subs.add_parser("policy", help="how each key is answered: always, ask, window or never")
    policy_cmd.add_argument("--app", default="", help="which app; omit for every app")
    policy_cmd.add_argument("--key", default="", help="which key; omit for the app's default")
    policy_cmd.add_argument("--mode", choices=["always", "ask", "window", "never"], default="")
    policy_cmd.add_argument("--from", dest="window_from", default="", metavar="HH:MM")
    policy_cmd.add_argument("--to", dest="window_to", default="", metavar="HH:MM")
    policy_cmd.add_argument("--days", nargs="+", default=[], metavar="DAY", help="mon tue wed …")
    policy_cmd.add_argument("--reads", choices=["open", "sealed"], default="",
                            help="whether callers the broker did not start may receive values")
    policy_cmd.add_argument("--learn", action="store_true",
                            help="derive a starting policy from what the record shows apps have asked for")
    policy_cmd.set_defaults(func=cmd_policy)

    broker = subs.add_parser("broker", help="one door for credential reads, and a record of them")
    broker.add_argument("--json", action="store_true")
    broker.set_defaults(func=cmd_broker)
    broker_subs = broker.add_subparsers(dest="broker_command")

    broker_start = broker_subs.add_parser("start", help="start the broker in the background")
    broker_start.set_defaults(json=False, func=cmd_broker_start)

    broker_stop = broker_subs.add_parser("stop", help="stop the broker; apps fall back to the files")
    broker_stop.set_defaults(json=False, func=cmd_broker_stop)

    broker_restart = broker_subs.add_parser(
        "restart", help="stop and start it again, e.g. after upgrading PassBook")
    broker_restart.set_defaults(json=False, func=cmd_broker_restart)

    broker_run = broker_subs.add_parser("run", help="run in the foreground, for launchd or systemd")
    broker_run.set_defaults(json=False, func=cmd_broker_run)


    install = subs.add_parser("install", help="set up PassBook: runtime, commands, and store")
    install.add_argument("--prefix", default=default_prefix())
    install.add_argument("--no-agents", action="store_true",
                         help="do not write the brief into agent context files")
    install.add_argument("--no-mcp", action="store_true",
                         help="do not register the MCP server with the agents found here")
    install.add_argument("--no-runtime", action="store_true",
                         help="do not provision a private interpreter for sealing and linking")
    install.set_defaults(func=cmd_install)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # A generated shim cannot change what Python sees as argv[0], so it names
    # itself here instead. Console scripts and symlinks fall through to the
    # basename, which is already their own name.
    invoked = os.environ.get("PASSBOOK_INVOKED_AS") or Path(sys.argv[0]).name
    known = aliases()
    if invoked in known:
        argv.insert(0, known[invoked])
    # `uv tool install` runs nothing, so the first command anybody types is the
    # first time PassBook executes on this machine. Doing it here rather than
    # only in `install` is what makes "the agents know" true however PassBook
    # arrived.
    #
    # On stderr, never stdout: `passbook get` prints KEY=value and people pipe
    # that into `eval` and into `--json` parsers. A helpful line on the wrong
    # stream is a corrupted credential.
    # Only for a command somebody typed. `broker` and `mcp` are the two that
    # run as background processes — the broker is detached and outlives the
    # shell, the MCP server is spawned BY an agent — and neither is a sensible
    # thing to have writing into agent config files. A daemon quietly editing
    # ~/.claude/CLAUDE.md minutes after the terminal closed is exactly the
    # behaviour that makes people uninstall something.
    _SILENT = {"brief", "broker", "mcp"}
    if not os.environ.get("PASSBOOK_NO_BRIEF") and not (argv and argv[0] in _SILENT):
        brief = _brief()
        if brief is not None:
            try:
                changed = brief.brief_once()
            except Exception:  # noqa: BLE001 — never fail a command over this
                changed = []
            if changed:
                names = ", ".join(entry["id"] for entry in changed)
                print(f"passbook: briefed {len(changed)} coding agent(s) about this "
                      f"machine's credentials ({names})", file=sys.stderr)
                print("passbook: they read it at the start of a session; "
                      "`passbook brief remove` undoes it", file=sys.stderr)

    # Handled before dispatch, because `--version` has no subcommand and every
    # other path here requires one.
    if argv and argv[0] in ("--version", "-V"):
        print(installed_version() or "unknown (running from a checkout)")
        return 0
    args = build_parser().parse_args(argv)
    if getattr(args, "version", False):
        print(installed_version() or "unknown (running from a checkout)")
        return 0
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
