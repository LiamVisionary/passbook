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

**The code is still writable,** until you install the daemon. PassBook lands
under the user's own home, so a caller that can write a file can edit the
redactor out of `passbook_grant` and never need a debugger at all. `install()`
below is the answer to that one: root-owned code, a root-owned plist, and a
broker that still runs as you so the keychain and your store keep working.
Until it is run, `posture()` lists this as an open gap rather than implying it
is handled.

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

__all__ = ["available", "deny_debugger", "describe", "preexec"]

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


# ── the daemon: root-owned code, and a start that is not the user's to edit ──
#
# Refusing a debugger protects what the broker HOLDS. It does nothing about what
# the broker IS. PassBook installs under the user's own home — on the machine
# this was written, `site-packages` is `drwxr-xr-x liam:staff` — so a caller
# that can write a file can edit the redactor out of `passbook_grant.py` and
# every guarantee above evaporates with no debugger involved.
#
# That is the remaining hole, and it is not closed by a syscall. It is closed by
# the code living somewhere the user's own processes cannot write.
#
# Why a root-owned LaunchAgent rather than a service account under its own uid,
# which is where this was first heading: a separate uid would also isolate the
# process, but the broker needs the login keychain (the device factor), the
# GUI session (passkey and Touch ID unlock) and read access to a store in the
# user's home. A daemon has none of those. Worse, a store owned by a service
# account can strand the machine when the daemon will not start, and this
# project's own spec says a policy must never be able to do that. A LaunchAgent
# whose plist and code are root-owned runs AS the user — keychain, biometrics
# and store all keep working — while the thing an attacker would need to modify
# stops being theirs. It buys the integrity half, which is the half still open,
# and skips the isolation half, which `deny_debugger` already covers.

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


def posture(*, runtime: Path | None = None, plist: Path | None = None) -> dict[str, Any]:
    """What is actually protected on this machine, and what is not.

    Reports rather than reassures. Every field here is something a person could
    check by hand; the value of gathering them is that nobody does.
    """
    runtime = Path(runtime) if runtime else RUNTIME
    plist = Path(plist) if plist else AGENT_PLIST
    here = Path(__file__).resolve().parent

    running_from_protected = str(here).startswith(str(runtime))
    findings = {
        "debugger": {
            "supported": available(),
            "how": describe(),
        },
        "code": {
            "path": str(here),
            "writable_by_you": _writable_by_user(here),
            "protected": running_from_protected and not _writable_by_user(here),
        },
        "interpreter": {
            "path": sys.executable,
            "writable_by_you": _writable_by_user(Path(sys.executable).resolve().parent),
        },
        "daemon": {
            "installed": plist.exists(),
            "plist": str(plist),
            "plist_writable_by_you": _writable_by_user(plist) if plist.exists() else True,
        },
        "runtime_installed": runtime.exists(),
    }

    # Checked last and reported first, because on the machine this was written
    # it was the shortest way in by a wide margin: one command, no prompt.
    findings["keychain"] = keychain_exposure()

    gaps = []
    if findings["keychain"].get("exposed"):
        gaps.append("vault key material comes back from `security "
                    "find-generic-password` with no prompt, so anything running "
                    "as you can open the vault without a debugger or an edit")
    if findings["code"]["writable_by_you"]:
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
         source: Path | None = None) -> list[dict[str, str]]:
    """Exactly what `install` would do, as steps a person can read and refuse.

    Returned rather than printed so the CLI, a test and a dry run all describe
    the same operation. A privileged installer that cannot be inspected before
    it runs is one people run blind or not at all.
    """
    runtime = Path(runtime) if runtime else RUNTIME
    plist = Path(plist) if plist else AGENT_PLIST
    source = Path(source) if source else Path(__file__).resolve().parent
    program = runtime / "bin" / "passbook"
    return [
        {"what": f"create {runtime}",
         "why": "a place for PassBook's code that your own processes cannot write"},
        {"what": f"build a virtual environment there with {sys.executable.split('/')[-1]}",
         "why": "so the interpreter and cryptography live there too, not in your home"},
        {"what": f"install PassBook into it from {source}",
         "why": "the code the broker actually runs"},
        {"what": f"chown -R root:wheel {runtime} && chmod -R go-w {runtime}",
         "why": "this is the step that closes the hole; everything else is arrangement"},
        {"what": f"write {plist} as root:wheel 0644",
         "why": "what starts the broker must not be editable either"},
        {"what": f"launchctl bootstrap gui/$(id -u) {plist}",
         "why": "start it now, and at every login, as you — so the keychain, "
                "Touch ID and your store all keep working"},
    ]


def install(*, runtime: Path | None = None, plist: Path | None = None,
            source: Path | None = None, launch: bool = True) -> dict[str, Any]:
    """Do it. Requires root, and says so rather than half-finishing.

    Deliberately not attempted with `sudo` from inside: a tool that escalates on
    its own behalf teaches people to let tools escalate, and this one is asking
    to own a path that everything else on the machine will trust.
    """
    runtime = Path(runtime) if runtime else RUNTIME
    plist = Path(plist) if plist else AGENT_PLIST
    source = Path(source) if source else Path(__file__).resolve().parent

    if sys.platform != "darwin":
        return {"ok": False, "why": "the LaunchAgent shape is macOS-only"}
    if not _is_root():
        return {"ok": False, "needs_root": True,
                "why": "this writes to /usr/local/libexec and /Library/LaunchAgents"}

    try:
        runtime.parent.mkdir(parents=True, exist_ok=True)
        if runtime.exists():
            shutil.rmtree(runtime)
        subprocess.run([sys.executable, "-m", "venv", str(runtime)],
                       check=True, capture_output=True)
        pip = runtime / "bin" / "pip"
        subprocess.run([str(pip), "install", "--quiet", str(source.parent)],
                       check=True, capture_output=True)

        # The whole point of the exercise, and the only step whose failure means
        # the rest was pointless — so it is checked rather than assumed.
        subprocess.run(["chown", "-R", "root:wheel", str(runtime)], check=True)
        subprocess.run(["chmod", "-R", "go-w", str(runtime)], check=True)
        if _writable_by_user(runtime):  # pragma: no cover - would mean chown lied
            return {"ok": False, "why": f"{runtime} is still writable after chown"}

        plist.parent.mkdir(parents=True, exist_ok=True)
        with plist.open("wb") as handle:
            plistlib.dump(agent_plist(runtime / "bin" / "passbook"), handle)
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
    return {"ok": True, "runtime": str(runtime), "plist": str(plist)}


def undo(*, runtime: Path | None = None, plist: Path | None = None) -> dict[str, Any]:
    """Put the machine back. Every privileged installer owes one of these."""
    runtime = Path(runtime) if runtime else RUNTIME
    plist = Path(plist) if plist else AGENT_PLIST
    if sys.platform != "darwin":
        return {"ok": False, "why": "the LaunchAgent shape is macOS-only"}
    if not _is_root():
        return {"ok": False, "needs_root": True, "why": "this removes root-owned files"}
    removed = []
    if plist.exists():
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(plist)],
                       capture_output=True)
        plist.unlink()
        removed.append(str(plist))
    if runtime.exists():
        shutil.rmtree(runtime)
        removed.append(str(runtime))
    return {"ok": True, "removed": removed}


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
