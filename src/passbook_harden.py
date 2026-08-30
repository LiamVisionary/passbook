# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook process hardening — the boundary the other modules could not draw.

Optional companion to `passbook_broker.py`. Everything else in this project is
policy: it decides what a caller may have, and enforces that at a door the
caller has to knock on. This module is about the wall beside the door.

## The hole this closes, measured rather than assumed

`passbook_grant` moved credentials out of callers' output, and the honest
caveat in its docstring was that the broker and the caller run as the same user,
so a caller willing to write custom code could read a value out of the memory of
the broker or of the child it spawned.

That is not theoretical, and the cost is not "write custom code". On a stock
macOS with no extra tooling:

    $ lldb -p <broker pid>
    Process 51698 stopped

`lldb` ships with the OS and carries the debugger entitlement, so it attaches to
an unsigned, same-uid process without ceremony. Anything holding a credential in
memory — the broker, and every child it spawns — was readable that way.

## What fixes it, and why it is one syscall rather than a service account

macOS has `ptrace(PT_DENY_ATTACH)`: a process asks the kernel to refuse
debugger attachment to itself, from that point on. It needs no root, no code
signature and no installation. Measured on the same machine as above, `lldb`
goes from attaching to `error: attach failed` and the target survives.

**It also survives `exec`.** That matters more than the broker's own case: the
broker's memory holds the data key, but the *child* holds the credential it was
spawned with, in its environment, for as long as it runs. Setting the flag
between fork and exec hardens a child whose binary knows nothing about PassBook
— `wrangler`, `npm`, anything.

Linux gets the same property from `prctl(PR_SET_DUMPABLE, 0)`, which makes a
process non-dumpable and, under the default `ptrace_scope`, un-attachable by
another process of the same user. Windows has no equivalent that does not
require a driver, and says so rather than pretending.

## What it does not close

**Root still wins,** everywhere, always. This raises the bar from "any process
running as you" to "root", which is the whole of what a user-space mechanism
can do.

**The code is still writable,** until you lock it. PassBook lands under the
user's own home, so a caller that can write a file can edit the redactor out of
`passbook_grant` and never need a debugger at all. `install()` below locks the
installed tree **in place** and starts the broker from a root-owned plist. Until
it is run, `posture()` lists this as an open gap rather than implying otherwise.

**A process that already had a debugger attached** when it called this is not
retroactively protected. The flag is applied as early as possible for that
reason: in the broker before it opens its socket, and in a child before its
`exec`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from typing import Any

__all__ = ["available", "deny_debugger", "describe", "install", "posture",
           "preexec", "runtime_root", "undo"]

# <sys/ptrace.h>: PT_DENY_ATTACH is 31 on Darwin. Spelled out because the
# constant is not exposed by any Python module and importing it from a header
# at runtime is not a thing.
_PT_DENY_ATTACH = 31

# <sys/prctl.h>: PR_SET_DUMPABLE. A non-dumpable process cannot be attached by
# a same-uid process under the default Yama ptrace_scope, and produces no core.
_PR_SET_DUMPABLE = 4


def available() -> bool:
    """Whether this platform can refuse a debugger at all."""
    return sys.platform in ("darwin", "linux")


def describe() -> str:
    if sys.platform == "darwin":
        return "ptrace(PT_DENY_ATTACH)"
    if sys.platform == "linux":
        return "prctl(PR_SET_DUMPABLE, 0)"
    return "not available on this platform"


def deny_debugger() -> dict[str, Any]:
    """Ask the kernel to refuse debugger attachment to THIS process.

    Returns what happened rather than raising. A machine that cannot do this is
    a machine that runs with the older guarantee, which is a smaller thing than
    a broker that refuses to start — and a credential daemon that will not come
    up is an outage, while one that comes up slightly less hardened is a note in
    `status`.
    """
    if sys.platform == "darwin":
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int,
                                    ctypes.c_void_p, ctypes.c_int]
            libc.ptrace.restype = ctypes.c_int
            result = libc.ptrace(_PT_DENY_ATTACH, 0, None, 0)
        except (OSError, AttributeError, ValueError) as error:
            return {"ok": False, "how": describe(), "why": str(error)}
        if result != 0:
            return {"ok": False, "how": describe(),
                    "why": f"ptrace returned {result} (errno {ctypes.get_errno()})"}
        return {"ok": True, "how": describe()}

    if sys.platform == "linux":
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            result = libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
        except (OSError, AttributeError, ValueError) as error:
            return {"ok": False, "how": describe(), "why": str(error)}
        if result != 0:
            return {"ok": False, "how": describe(),
                    "why": f"prctl returned {result} (errno {ctypes.get_errno()})"}
        return {"ok": True, "how": describe()}

    return {"ok": False, "how": describe(),
            "why": f"{sys.platform} has no user-space way to refuse a debugger"}


def preexec() -> None:
    """Harden a child between fork and exec. For `subprocess(preexec_fn=…)`.

    The child is the process that actually holds the credential — in its
    environment, for as long as it runs — so hardening the broker and not its
    children would protect the key and leave the secret.

    Deliberately silent. This runs after fork in a process that is about to
    become something else; there is nowhere to report to, and raising here would
    turn "could not harden" into "could not run your command", which is the
    wrong trade for a machine that was working a moment ago.
    """
    try:
        deny_debugger()
    except Exception:  # noqa: BLE001 — see above: never fail the exec
        pass


def status() -> dict[str, Any]:
    """What a machine can say about this without changing itself.

    Separate from `deny_debugger` because calling it to find out is a one-way
    door: once this process refuses debuggers it cannot stop, so a status
    surface must be able to answer without doing it.
    """
    return {
        "supported": available(),
        "how": describe(),
        "platform": sys.platform,
        # Whether the CURRENT process did it is not knowable after the fact —
        # the kernel offers no way to read the flag back — so callers that need
        # to know track their own call rather than asking here.
        "note": ("Root can still read any process. This raises the bar from "
                 "anything running as you to root."),
    }


# ── locking the code, in place ──────────────────────────────────────────────
#
# Refusing a debugger protects what the broker HOLDS. It does nothing about what
# the broker IS. PassBook installs under the user's own home — on the machine
# this was written, `site-packages` was `drwxr-xr-x liam:staff` — so a caller
# that can write a file can edit the redactor out of `passbook_grant` and every
# guarantee above evaporates with no debugger involved.
#
# The first version of this copied PassBook to a root-owned `/usr/local/libexec`
# and ran the daemon from the copy. That was wrong, and wrong in a way worth
# recording: `passbook update` runs `uv tool install --force` into the user's
# own tree, so the daemon would have gone on running whatever it was installed
# with — indefinitely, silently, and invisibly to a version check that reads the
# copy the user updated. A credential broker quietly executing last month's
# redactor is a worse failure than the writable directory it was meant to fix.
#
# So: one tree, locked where it already is. Updating it needs root afterwards,
# which for the code that holds a machine's credentials is the right way round
# rather than a cost.
#
# A LaunchAgent, not a LaunchDaemon under its own uid. A daemon has no login
# keychain, no GUI session for Touch ID, and no read access to a store in the
# user's home — and a store it owned could strand the machine, which this
# project's own spec forbids a policy from doing. The Agent runs AS the user and
# keeps all three, while the code and the thing that starts it stop being the
# user's to edit. That is the half that was still open; `deny_debugger` already
# covers the isolation half.

import plistlib  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

LABEL = "com.rizzma.passbook.broker"
RUNTIME = Path("/usr/local/libexec/passbook")
AGENT_PLIST = Path("/Library/LaunchAgents") / f"{LABEL}.plist"


def _is_root() -> bool:
    """Whether this process can write to root-owned paths.

    `os.geteuid` does not exist on Windows, so asking for it there is an
    AttributeError rather than a False — which is how `undo()` crashed on the
    Windows runners instead of politely declining.
    """
    getter = getattr(os, "geteuid", None)
    return getter is not None and getter() == 0


def _writable_by_user(path: Path) -> bool:
    """Could this user modify it? The question integrity turns on."""
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def runtime_root() -> Path | None:
    """The installed tree PassBook's modules actually load from.

    Found by walking up from the loaded module rather than by guessing a path,
    because a machine can carry a uv tool install, a pipx one and a checkout at
    once, and locking the one this process is not running from would report
    success and protect nothing.

    None for a checkout, which has no `bin`/`lib` pair — and which must not be
    locked: it is somebody's working tree, and chowning it to root would be a
    surprising way to end their afternoon.
    """
    try:
        import passbook

        here = Path(passbook.__file__).resolve()
    except Exception:  # noqa: BLE001 — no passbook is not our problem here
        return None
    for parent in here.parents:
        if (parent / "bin").is_dir() and (parent / "lib").is_dir():
            return parent
    return None


def interpreter_root() -> Path | None:
    """Where the real interpreter lives, when it is outside the runtime tree.

    A uv tool's `bin/python` is a symlink into uv's shared python store, so
    locking the tool tree locks the link and leaves the binary it points at
    writable — and anything that can replace that binary owns the broker
    whatever else is protected.

    Reported separately because locking it is a wider blow than locking one
    tool: uv manages that store for every tool on the machine.
    """
    real = Path(sys.executable).resolve()
    tree = runtime_root()
    if tree is not None and str(real).startswith(str(tree)):
        return None
    for parent in real.parents:
        if (parent / "bin").is_dir() and (parent / "lib").is_dir():
            return parent
    return real.parent


def posture(*, runtime: Path | None = None, plist: Path | None = None) -> dict[str, Any]:
    """What is actually protected on this machine, and what is not.

    Reports rather than reassures. Every field here is something a person could
    check by hand; the value of gathering them is that nobody does.
    """
    plist = Path(plist) if plist else AGENT_PLIST
    tree = Path(runtime) if runtime else runtime_root()
    interpreter = interpreter_root()

    findings = {
        "debugger": {"supported": available(), "how": describe()},
        "code": {
            "path": str(tree) if tree else str(Path(__file__).resolve().parent),
            "is_an_installed_tree": tree is not None,
            "writable_by_you": _writable_by_user(tree) if tree
                               else _writable_by_user(Path(__file__).resolve().parent),
        },
        "interpreter": {
            "path": str(interpreter) if interpreter else "inside the runtime tree",
            "writable_by_you": _writable_by_user(interpreter) if interpreter else False,
        },
        "daemon": {"installed": plist.exists(), "plist": str(plist)},
    }
    findings["code"]["protected"] = (
        findings["code"]["is_an_installed_tree"] and not findings["code"]["writable_by_you"])

    # Checked last and reported first, because on the machine this was written
    # it was the shortest way in by a wide margin: one command, no prompt.
    findings["keychain"] = keychain_exposure()

    gaps = []
    if findings["keychain"].get("exposed"):
        gaps.append("vault key material comes back from `security "
                    "find-generic-password` with no prompt, so anything running "
                    "as you can open the vault without a debugger or an edit")
    if not findings["code"]["is_an_installed_tree"]:
        gaps.append("this is running from a checkout rather than an installed "
                    "copy, so there is no tree to lock")
    elif findings["code"]["writable_by_you"]:
        gaps.append("anything running as you can edit PassBook's own code, "
                    "including the part that removes secrets from output")
    if findings["interpreter"]["writable_by_you"]:
        gaps.append("anything running as you can replace the interpreter it runs on")
    if not findings["daemon"]["installed"]:
        gaps.append("the broker is started by hand, so what starts it is also editable")
    if not available():
        gaps.append(f"{sys.platform} cannot refuse a debugger, so process memory is readable")
    findings["gaps"] = gaps
    # Never absent, and never softened: this is the one every layer here shares.
    findings["always"] = "Root can defeat all of this. Nothing in user space cannot be."
    return findings


def agent_plist(program: Path, *, label: str = LABEL) -> dict[str, Any]:
    """The LaunchAgent that starts the broker, as a plist dictionary.

    `RunAtLoad` plus `KeepAlive` because a credential broker that quietly stays
    down turns every read into a policy refusal, and the machine looks broken in
    a way nothing points at the broker.
    """
    return {
        "Label": label,
        "ProgramArguments": [str(program), "broker", "run"],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
    }


def plan(*, runtime: Path | None = None, plist: Path | None = None,
         interpreter: bool = False) -> list[dict[str, str]]:
    """Exactly what `install` would do, as steps a person can read and refuse.

    Returned rather than printed so the CLI, a test and a dry run all describe
    the same operation. A privileged installer that cannot be inspected before
    it runs is one people run blind or not at all.
    """
    plist = Path(plist) if plist else AGENT_PLIST
    tree = Path(runtime) if runtime else runtime_root()
    if tree is None:
        return [{"what": "nothing", "why": "this is a checkout, not an installed "
                                           "copy; there is no tree to lock"}]
    steps = [
        {"what": f"chown -R root:wheel {tree}",
         "why": "the code the broker runs stops being yours — or any agent's — to edit"},
        {"what": f"chmod -R go-w {tree}",
         "why": "and stops being group-writable, which chown alone does not settle"},
        {"what": f"write {plist} as root:wheel 0644",
         "why": "what starts the broker must not be editable either"},
        {"what": f"launchctl bootstrap gui/$(id -u) {plist}",
         "why": "start it now and at every login, as you — so the keychain, "
                "Touch ID and your store all keep working"},
    ]
    if interpreter:
        where = interpreter_root()
        if where is not None:
            steps.insert(1, {
                "what": f"chown -R root:wheel {where}",
                "why": "the interpreter too — but this is uv's shared python store, "
                       "so every uv tool on the machine needs sudo to update after"})
    steps.append({
        "what": "from now on:  sudo passbook update",
        "why": "updating a locked tree needs root, which is the point rather "
               "than a side effect"})
    return steps


def install(*, runtime: Path | None = None, plist: Path | None = None,
            interpreter: bool = False, launch: bool = True) -> dict[str, Any]:
    """Lock the installed tree in place, and start the broker from it.

    Locked **in place** rather than copied somewhere root-owned, which is what
    this did first. A second copy is a second version: `passbook update` runs
    `uv tool install --force` into the user's tree and would leave the daemon
    running whatever it was installed with, indefinitely and silently. A
    credential broker quietly executing last month's redactor is a worse
    outcome than the writable directory this was meant to fix.

    One tree, owned by root, and updating it needs root. That is the trade, and
    for the code that holds a machine's credentials it is the right way round.
    """
    plist = Path(plist) if plist else AGENT_PLIST
    tree = Path(runtime) if runtime else runtime_root()

    if sys.platform != "darwin":
        return {"ok": False, "why": "the LaunchAgent shape is macOS-only"}
    if tree is None:
        return {"ok": False, "why": "this is running from a checkout, not an "
                                    "installed copy. Install it first, then lock that."}
    if not _is_root():
        return {"ok": False, "needs_root": True,
                "why": f"this changes the owner of {tree} and writes to /Library/LaunchAgents"}

    try:
        subprocess.run(["chown", "-R", "root:wheel", str(tree)], check=True)
        subprocess.run(["chmod", "-R", "go-w", str(tree)], check=True)
        if interpreter:
            where = interpreter_root()
            if where is not None:
                subprocess.run(["chown", "-R", "root:wheel", str(where)], check=True)
                subprocess.run(["chmod", "-R", "go-w", str(where)], check=True)

        plist.parent.mkdir(parents=True, exist_ok=True)
        with plist.open("wb") as handle:
            plistlib.dump(agent_plist(tree / "bin" / "passbook"), handle)
        os.chown(plist, 0, 0)
        os.chmod(plist, 0o644)
        if launch:
            subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)],
                           capture_output=True)
    except subprocess.CalledProcessError as error:
        return {"ok": False, "why": f"{error.cmd[0]} failed: "
                                    f"{(error.stderr or b'').decode()[:200]}"}
    except OSError as error:
        return {"ok": False, "why": str(error)}
    return {"ok": True, "locked": str(tree), "plist": str(plist)}


def undo(*, runtime: Path | None = None, plist: Path | None = None,
         owner: str = "") -> dict[str, Any]:
    """Give the tree back and remove the agent. Every installer owes one.

    The owner has to be named or worked out, because `chown -R` in the wrong
    direction is how a fix becomes an outage: handing a credential runtime to
    the wrong account leaves it unreadable by the person who needs it.
    """
    plist = Path(plist) if plist else AGENT_PLIST
    tree = Path(runtime) if runtime else runtime_root()
    if sys.platform != "darwin":
        return {"ok": False, "why": "the LaunchAgent shape is macOS-only"}
    if not _is_root():
        return {"ok": False, "needs_root": True, "why": "this removes root-owned files"}

    # SUDO_USER is who invoked sudo — the account the tree belonged to. Falling
    # back to the tree's parent's owner covers `sudo -i` and a root shell.
    who = owner or os.environ.get("SUDO_USER", "")
    if not who and tree is not None:
        try:
            import pwd

            who = pwd.getpwuid(tree.parent.stat().st_uid).pw_name
        except Exception:  # noqa: BLE001
            who = ""
    if tree is not None and not who:
        return {"ok": False, "why": "could not work out who to give it back to; "
                                    "pass --owner <you>"}

    undone = []
    if plist.exists():
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(plist)],
                       capture_output=True)
        plist.unlink()
        undone.append(f"removed {plist}")
    if tree is not None:
        subprocess.run(["chown", "-R", f"{who}:staff", str(tree)], check=False)
        undone.append(f"gave {tree} back to {who}")
    return {"ok": True, "undone": undone}


# ── the keychain item, which turned out to be the shortest way in ───────────
#
# The device factor exists so a headless job can open the vault with nobody
# there to type a password. `passbook_keystore` is blunt about the cost in its
# own docstring — "anything running as you can open the vault" — and on the
# machine this was written that was not a footnote, it was the whole attack:
#
#     $ security find-generic-password -s hive-env-vault -w
#     <44 bytes of key material>
#
# No debugger, no edited module, no prompt. Refusing a debugger and owning the
# code do nothing about it, because nothing is being subverted — the key is
# simply being asked for, by a caller the keychain has no reason to doubt.
#
# macOS can doubt it. A keychain item carries an access control list naming the
# programs allowed to read it without asking, and an item created with an EMPTY
# list prompts for every reader. A person clicks Allow; an agent cannot.
#
# The cost is exactly the thing the device factor was for. A prompt means no
# headless open, so this is offered and reported, never applied on somebody's
# behalf — a watchdog that silently stops surviving reboots is a worse outcome
# than the exposure, and only the owner knows which they have.

KEYCHAIN_SERVICE = "hive-env-vault"


def keychain_exposure(*, service: str = KEYCHAIN_SERVICE) -> dict[str, Any]:
    """Whether vault key material can be fetched without anyone being asked.

    Reads the item to find out, which is the only honest test — an item that
    exists but prompts is not exposed, and nothing short of asking for it
    distinguishes the two. The value is never returned, kept, or logged; only
    whether one arrived.
    """
    if sys.platform != "darwin":
        return {"applies": False, "why": "the keychain check is macOS-only"}
    try:
        found = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", service, "-w"],
            capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        return {"applies": True, "exposed": False, "why": f"could not check: {error}"}

    if found.returncode != 0:
        return {"applies": True, "exposed": False,
                "why": "no vault key is stored in the keychain on this machine"}
    # Length only. The value is deliberately not bound to a name anywhere here.
    got = len(found.stdout.strip())
    return {
        "applies": True,
        "exposed": got > 0,
        "service": service,
        "why": (f"{got} bytes of vault key material came back with no prompt, so "
                f"anything running as you can open the vault"),
        "fix": "passbook harden --keychain-prompt",
        "cost": ("every reader is then asked, including a headless job — which is "
                 "the whole reason the device factor exists. Remove the factor "
                 "instead if nothing here runs unattended."),
    }


def require_keychain_prompt(*, service: str = KEYCHAIN_SERVICE) -> dict[str, Any]:
    """Rewrite the item so every reader must be approved by a person.

    Re-created rather than modified: `security` offers no way to narrow an
    existing item's access list, so the value is read once, deleted, and written
    back with an empty trusted-application list. That read is the reason this
    refuses to run when it cannot verify it got something — writing back an
    empty value would destroy the device factor rather than protect it.
    """
    if sys.platform != "darwin":
        return {"ok": False, "why": "macOS-only"}
    account = None
    try:
        # -g puts the value on stderr and the attributes on stdout, which is how
        # the account name comes back alongside it.
        shown = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", service, "-g"],
            capture_output=True, text=True, timeout=10)
        if shown.returncode != 0:
            return {"ok": False, "why": "no such keychain item; nothing to tighten"}
        for line in shown.stdout.splitlines():
            if line.strip().startswith('"acct"'):
                account = line.split("=", 1)[1].strip().strip('"')
        secret = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", service, "-w"],
            capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        return {"ok": False, "why": f"could not read the item: {error}"}

    if not secret or not account:
        # Refusing here is the whole safety of this function. Continuing would
        # delete a working device factor and write back nothing.
        return {"ok": False,
                "why": "could not read the existing item, so it was left alone"}

    try:
        subprocess.run(["/usr/bin/security", "delete-generic-password",
                        "-s", service, "-a", account],
                       capture_output=True, timeout=10, check=True)
        # No -T at all: an empty trusted-application list, so every reader is
        # asked. -U updates in place if anything raced us to recreate it.
        subprocess.run(["/usr/bin/security", "add-generic-password", "-U",
                        "-s", service, "-a", account, "-w", secret],
                       capture_output=True, timeout=10, check=True)
    except subprocess.CalledProcessError as error:
        return {"ok": False,
                "why": f"security failed: {(error.stderr or b'').decode()[:160]}"}
    finally:
        del secret
    return {"ok": True, "service": service,
            "note": "every read of this item now asks a person. Headless opens "
                    "will stop working; that is the trade."}
