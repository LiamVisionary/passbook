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

No command in here prints a credential. `check` reports set or missing, `list`
reports names, and `run` hands values to a child process without ever putting
them on a terminal or in the ledger.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import shutil
import subprocess
import sys
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


# ── commands ───────────────────────────────────────────────────────────────


def cmd_check(args: argparse.Namespace) -> int:
    """Presence, never contents. Exit 1 if any requested key is unset."""
    values = _store_values()
    missing = []
    for key in args.keys:
        value = values.get(key, "")
        if value:
            detail = f" ({len(value)} chars)" if args.length else ""
            if not args.quiet:
                print(f"{key}: set{detail}")
        else:
            missing.append(key)
            if not args.quiet:
                print(f"{key}: missing")
    if missing:
        return _fail(
            f"\nNot set: {', '.join(missing)}",
            f"Add with: passbook-add {missing[0]}",
        )
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
    try:
        result = passbook.set_values(values, overwrite=args.replace)
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
    try:
        result = passbook.remove_values(args.keys)
    except passbook.ContainerisedHomeError as error:
        return _fail(str(error))
    if result["removed"]:
        print(f"removed: {', '.join(result['removed'])}")
    if result["absent"]:
        print(f"not in the store: {', '.join(result['absent'])}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command with the store loaded as a base. The process env wins."""
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        return _fail("Nothing to run.", "Usage: passbook-run -- your-command --flags")
    _use_broker_for_sealed_values("passbook-run", f"run {Path(command[0]).name}")
    child = dict(_store_values())
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
    try:
        os.execvpe(command[0], command, child)
    except FileNotFoundError:
        return _fail(f"{command[0]}: command not found")
    except OSError as error:
        return _fail(f"Could not run {command[0]}: {error}")
    return 0  # unreachable; execvpe replaces this process


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
    granted = passbook.request(wanted, app=args.app or "passbook-get",
                               reason=args.reason or "read by a script")
    if args.json:
        print(json.dumps(granted, indent=2 if args.pretty else None))
    else:
        for key in wanted:
            if key in granted:
                print(f"{key}={granted[key]}")
    missing = [key for key in wanted if key not in granted]
    if missing:
        print(f"Not available: {', '.join(missing)}", file=sys.stderr)
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


def _open_vault(module, profile: str, *, from_stdin: bool = False) -> tuple[bytes, str] | None:
    """Get a data key for a maintenance command, by asking the person running it."""
    profile = profile or module.active_profile_id()
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
        return module.unlock_with_password(profile, password), profile
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
    result = module.unseal_store(dek, profile_id=profile)
    print(result.get("detail", ""))
    if result.get("stuck"):
        print(f"Still sealed: {', '.join(result['stuck'])}", file=sys.stderr)
        print("Those were sealed under a different profile.", file=sys.stderr)
    return 0 if result.get("ok") else 1


def cmd_profile(args: argparse.Namespace) -> int:
    module = _vault_or_fail()
    if module is None:
        return _fail("The vault is not installed on this machine.", "Run:  passbook install")
    listed = module.profiles()
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
    try:
        made = module.create_profile(args.label, password=password)
    except module.VaultError as error:
        return _fail(str(error))
    print(f"Created profile {made['label']}.")
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
    opened = _open_vault(module, getattr(args, "profile", ""),
                         from_stdin=getattr(args, "password_stdin", False))
    if opened is None:
        return 1
    dek, profile = opened
    try:
        made = module.add_passkey_factor(
            profile, dek=dek, credential_id=args.credential_id, prf_secret=prf,
            label=args.label or "passkey", rp_id=args.rp_id)
    except module.VaultError as error:
        return _fail(str(error))
    print(f"Enrolled {made['label']}. It can now open this profile on any device it syncs to.")
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
            print(f"{args.key}: every agent")
        else:
            print(f"{args.key}: {rule['mode']} {', '.join(rule['agents'])}")
        return 0

    restricted = [(n, access.audience_for(n, policy)) for n in names]
    restricted = [(n, r) for n, r in restricted if r["mode"] != "all"]
    if getattr(args, "json", False):
        print(json.dumps({n: r for n, r in restricted}, indent=2))
        return 0
    if not restricted:
        print(f"All {len(names)} keys are readable by every agent (the default).")
        print("Narrow one with:  passbook agents set KEY --only AGENT")
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
        return _fail("Say who.", "Use --everyone, --only AGENT [...], or --block AGENT [...]")
    try:
        rule = access.set_audience(args.key, mode, agents, policy)
    except ValueError as error:
        return _fail(str(error))
    access.write_policy(policy)
    if rule["mode"] == "all":
        print(f"{args.key}: every agent")
    else:
        print(f"{args.key}: {rule['mode']} {', '.join(rule['agents'])}")
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    """Which agents can read which keys, as a grid you can actually scan."""
    catalog = _catalog()
    if catalog is None:
        return _fail("The matrix needs the catalogue module.", "Run:  passbook install")
    import passbook_access as access

    policy = access.read_policy()
    names = passbook.key_names()
    agents = args.agent or catalog.agents_seen(policy=policy)
    if not agents:
        print("No agents have asked for a credential yet, and none are configured.")
        print("Name one to preview:  passbook matrix --agent claude-code")
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
        print("(every key is readable by every agent — nothing is restricted yet)")
    print(f"\n{shown} key(s) x {len(grid['agents'])} agent(s).  yes = granted, "
          f"ask = waits for you, NO = refused")
    return 0


def cmd_signin(args: argparse.Namespace) -> int:
    import passbook_broker

    if not passbook_broker.running():
        return _fail("No broker is running, so there is nothing to sign in to.",
                     "Run:  passbook broker start")
    if args.passkey:
        supplied = sys.stdin.readline().strip()
        if not supplied:
            return _fail("No PRF secret arrived on stdin.")
        answer = passbook_broker.signin(
            profile=args.profile, credential_id=args.passkey,
            prf_secret=base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4)),
            duration=args.duration)
    elif args.device:
        answer = passbook_broker.signin(profile=args.profile, device=True, duration=args.duration)
    else:
        try:
            password = _ask_password(from_stdin=getattr(args, "password_stdin", False))
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        except ValueError as error:
            return _fail(str(error))
        answer = passbook_broker.signin(profile=args.profile, password=password,
                                        duration=args.duration)
    if not answer.get("ok"):
        return _fail(answer.get("error", "Sign-in failed."))
    print(answer.get("detail", "Signed in."))
    return 0


def cmd_signout(args: argparse.Namespace) -> int:
    import passbook_broker

    answer = passbook_broker.signout()
    if not answer.get("ok"):
        return _fail(answer.get("error", "Could not lock the vault."))
    print("Locked." if answer.get("was_unlocked") else "Already locked.")
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


def machine_state() -> dict:
    """Everything a management surface needs, in one call, with no values.

    A native app or a web panel should not have to know which optional modules
    are installed on a given machine, nor make six round trips to find out. Each
    section reports its own availability, so a surface renders what is there and
    says plainly what is not — rather than showing an empty panel that looks like
    a bug.
    """
    state: dict = {"store": passbook.status(), "spec_version": passbook.SPEC_VERSION}

    try:
        import passbook_seal

        state["sealing"] = passbook_seal.status()
    except ImportError:
        state["sealing"] = {"supported": False, "detail": "Encryption at rest is not installed."}

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
        state["catalog"] = {
            "available": True,
            "ungrouped": passbook_catalog.UNGROUPED,
            "groups": passbook_catalog.groups(names, policy),
            "group_of": passbook_catalog.effective_groups(names, policy),
            "audiences": restricted,
            "agents": passbook_catalog.agents_seen(policy=policy),
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

    try:
        import passbook_stamp

        verification = passbook_stamp.verify_chain()
        state["record"] = {"available": True, "intact": verification["ok"],
                           "detail": verification["detail"],
                           "rows": passbook_stamp.read_stamps(limit=100)}
        # Summarised here rather than fetched per key: a list of several hundred
        # keys should not mean several hundred round trips to render.
        state["usage"] = passbook_stamp.usage_by_key()
    except ImportError:
        state["record"] = {"available": False, "rows": [], "detail": "No access record is kept."}
        state["usage"] = {}

    return state


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
    value = passbook.reveal(args.key, app="passbook-cli", reason=args.reason)
    if not value:
        return _fail(f"{args.key} is not set.", "See what is:  passbook-list")
    print(value)
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    """One JSON object describing this machine's PassBook. Never a value."""
    print(json.dumps(machine_state(), indent=2 if args.pretty else None))
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

    body = SHIM % {"package": package, "python": interpreter, "sep": os.pathsep}
    written, refused = [], []
    for name in ["passbook", *sorted(aliases())]:
        shim = target / name
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

    if str(target) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"\n{target} is not on your PATH yet. Add this to your shell profile:")
        print(f'\n    export PATH="{target}:$PATH"')
    else:
        print("\nTry:  passbook-check OPENAI_API_KEY")
    return 0


# ── argument parsing ───────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passbook",
        description="One credential store per machine, shared by every app that opts in.",
        epilog="Every subcommand is also available hyphenated: passbook-check, passbook-add, ...",
    )
    subs = parser.add_subparsers(dest="command", required=True)

    check = subs.add_parser("check", help="report whether keys are set (never their values)")
    check.add_argument("keys", nargs="+")
    check.add_argument("--length", action="store_true", help="also show each value's length")
    check.add_argument("--quiet", "-q", action="store_true", help="exit code only")
    check.set_defaults(func=cmd_check)

    add = subs.add_parser("add", help="add keys; a bare KEY prompts without echo")
    add.add_argument("pairs", nargs="*", metavar="KEY[=value]")
    add.add_argument("--replace", action="store_true", help="overwrite a key that is already set")
    add.add_argument("--stdin", action="store_true", help="read KEY=value lines from stdin")
    add.set_defaults(func=cmd_add)

    remove = subs.add_parser("remove", aliases=["delete"], help="delete keys from the store")
    remove.add_argument("keys", nargs="+")
    remove.set_defaults(func=cmd_remove)

    run = subs.add_parser("run", help="run a command with the store loaded as a base")
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

    profile_cmd = subs.add_parser("profile", help="who can open this machine's vault")
    profile_cmd.add_argument("--json", action="store_true")
    profile_cmd.set_defaults(func=cmd_profile)
    profile_subs = profile_cmd.add_subparsers(dest="profile_command")

    profile_create = profile_subs.add_parser("create", help="create a profile with a vault password")
    profile_create.add_argument("label", help="what to call it")
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
    signin.add_argument("--for", dest="duration", default="", metavar="DURATION",
                        help="how long to stay open, e.g. 8h; omit for the default")
    signin.add_argument("--device", action="store_true",
                        help="use this machine's device factor instead of a password")
    signin.add_argument("--passkey", default="", metavar="CREDENTIAL_ID",
                        help="sign in with a passkey; its PRF secret is read from stdin")
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
    passkey_enrol.add_argument("--password-stdin", dest="password_stdin", action="store_true",
                               help="read the vault password from stdin, after the PRF secret")
    passkey_enrol.set_defaults(json=False, func=cmd_passkey_enrol)

    mcp = subs.add_parser("mcp", help="speak MCP on stdio so any agent can find these credentials")
    mcp.set_defaults(func=cmd_mcp)

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
    # `agents set KEY` ambiguous, and argparse resolves it by trying to parse the
    # key as a subcommand.
    agents_cmd = subs.add_parser("agents", help="who each key is for")
    agents_cmd.add_argument("--json", action="store_true")
    agents_cmd.set_defaults(key="", func=cmd_agents)
    agents_subs = agents_cmd.add_subparsers(dest="agents_command")

    agents_show = agents_subs.add_parser("show", help="the audience for one key")
    agents_show.add_argument("key")
    agents_show.set_defaults(json=False, func=cmd_agents)
    agents_set = agents_subs.add_parser("set", help="limit or open up one key")
    agents_set.add_argument("key")
    agents_set.add_argument("--everyone", action="store_true", help="the default: every agent")
    agents_set.add_argument("--only", nargs="+", metavar="AGENT", help="only these agents")
    agents_set.add_argument("--block", nargs="+", metavar="AGENT", help="every agent except these")
    agents_set.set_defaults(json=False, func=cmd_agents_set)

    matrix = subs.add_parser("matrix", help="which agents can read which keys")
    matrix.add_argument("--agent", nargs="+", default=[], help="only these agents")
    matrix.add_argument("--group", default="", help="only this group")
    matrix.add_argument("--restricted", action="store_true", help="hide rows where everything is granted")
    matrix.add_argument("--json", action="store_true")
    matrix.set_defaults(func=cmd_matrix)

    signout = subs.add_parser("signout", help="lock the vault; credentials go dark again")
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
    reveal_cmd.add_argument("--reason", default="", help="recorded alongside the reveal")
    reveal_cmd.set_defaults(func=cmd_reveal)

    state_cmd = subs.add_parser("state", help="everything a management surface needs, as JSON")
    state_cmd.add_argument("--pretty", action="store_true")
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

    broker_run = broker_subs.add_parser("run", help="run in the foreground, for launchd or systemd")
    broker_run.set_defaults(json=False, func=cmd_broker_run)


    install = subs.add_parser("install", help="set up PassBook: runtime, commands, and store")
    install.add_argument("--prefix", default="~/.local/bin")
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
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
