# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook broker — one door for credential reads, and a complete record of them.

Optional companion to `passbook.py`. Everything works without it; this closes
the holes in the audit trail and adds per-app least privilege.

## Read this before you trust it

**This does not stop malware.** A process running as you can connect to the
socket and claim to be any app it likes. There is nothing in the request that
proves otherwise, and any secret an app could use to prove itself would sit on
the same disk the attacker can already read. Verifying a caller's identity needs
the operating system to vouch for it — a code-signed binary and a keychain ACL
on macOS, something different again on Linux and Windows — and that is a
signing-and-distribution project, not this file.

So do not read "denied" in the ledger as "an attacker was stopped".

## What it actually buys you

**The audit stops being voluntary.** Without a broker, each app has to opt into
stamping its own reads. This one does; a vendored `passbook.py` in someone
else's project does not. The ledger therefore has holes shaped exactly like the
apps least likely to be careful. The broker stamps every request it serves,
whether or not the client ever heard of stamping.

**Least privilege for honest code.** The far more common accident is not malware
but a tool that reads the whole environment because that was the easy call —
and then logs it, or ships it in a crash report. An app granted three keys gets
three, and the other 270 never enter its process.

**A policy you can derive rather than guess.** `audit` mode grants everything
and records it; `passbook broker policy --learn` turns what it saw into a
starting policy; `deny` mode then holds apps to it. Writing a policy first, from
imagination, is how these things end up permanently in audit mode.

## Shape

A newline-delimited JSON request on a `0600` Unix socket. The socket's mode is
the only access control there is: your user account, and nothing else on the
machine. Values are read from the store per request rather than held in memory,
so a key added a moment ago is visible and a long-lived process is not sitting
on a copy of everything.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

import passbook
import passbook_access as access

__all__ = [
    "POLICY_FILENAME",
    "signin",
    "signout",
    "vault_status",
    "SOCKET_FILENAME",
    "learn_policy",
    "pending",
    "resolve",
    "read_policy",
    "request_through_broker",
    "running",
    "serve",
    "start",
    "status",
    "stop",
    "write_policy",
]

SOCKET_FILENAME = "broker.sock"
PID_FILENAME = "broker.pid"
POLICY_FILENAME = access.POLICY_FILENAME
SPEC_VERSION = 1

CONNECT_TIMEOUT = 2.0
# A request in `ask` mode is waiting on a person, so the client has to outlast
# the broker's own patience or it would hang up on an approval that was coming.
REQUEST_TIMEOUT = 120.0
MAX_REQUEST_BYTES = 64 * 1024


# Which door this platform can offer. Everything below the transport — the
# protocol, the policy, the ledger, the sessions — is the same either way; only
# the thing that carries the bytes differs.
_WINDOWS = os.name == "nt"
if _WINDOWS:  # pragma: no cover - selected by platform
    import passbook_pipe
else:
    passbook_pipe = None

# From Windows' CreateProcess flags. Spelled out rather than imported, because
# `subprocess.DETACHED_PROCESS` does not exist on the platforms that never need
# it, and this module has to import everywhere.
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200

# What OpenProcess answers for a pid that is not running, which is how Windows
# says what POSIX says with ProcessLookupError.
_ERROR_INVALID_PARAMETER = 87

_BIND_LOCK = threading.Lock()

# AF_UNIX paths are capped by the kernel — 104 bytes on macOS, 108 on Linux —
# and it is the *path*, not the directory, that has to fit. A deep HIVE_HOME
# (a test tree, a container mount, anything under a long home) therefore fails
# at bind with "path too long" and no hint that the socket is the problem.
_SOCKET_PATH_LIMIT = 96


@contextlib.contextmanager
def _bindable(path: Path):
    """Yield a name short enough to bind or connect, from the socket's directory.

    Binding a bare filename from inside the directory keeps the path under the
    limit however deep the directory is. `chdir` is process-wide, so it is held
    for the syscall only and behind a lock.
    """
    if len(str(path).encode("utf-8")) < _SOCKET_PATH_LIMIT:
        yield str(path)
        return
    with _BIND_LOCK:
        previous = os.getcwd()
        os.chdir(str(path.parent))
        try:
            yield path.name
        finally:
            os.chdir(previous)


def socket_path(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else passbook.root()) / SOCKET_FILENAME


def pid_path(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else passbook.root()) / PID_FILENAME


def store_root(root: Path | None = None) -> Path:
    return Path(root) if root is not None else passbook.root()


def endpoint(root: Path | None = None) -> str:
    """Where the broker listens, in the form this platform names it.

    A path to a socket file on macOS and Linux; a pipe name on Windows, where
    the namespace is machine-wide rather than a directory. Anything that only
    wants to *show* the address asks this, so nothing has to know which.
    """
    if _WINDOWS:
        return passbook_pipe.pipe_name(store_root(root))
    return str(socket_path(root))


class _UnixListener:
    """The AF_UNIX server, behind the same two calls the pipe server offers."""

    def __init__(self, server: socket.socket, path: Path) -> None:
        self._server = server
        self._path = path

    def accept(self):
        connection, _ = self._server.accept()
        return connection

    def close(self) -> None:
        self._server.close()
        self._path.unlink(missing_ok=True)


def _listen(root: Path | None):
    """Open the door, as narrowly as this platform allows."""
    if _WINDOWS:
        # The pipe carries its own DACL; there is no file to chmod.
        return passbook_pipe.PipeServer(endpoint(root))

    path = socket_path(root)
    if path.exists():
        path.unlink()  # a stale socket from a process that did not clean up
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Create it unreachable, then narrow — never briefly world-connectable.
    previous_umask = os.umask(0o177)
    try:
        with _bindable(path) as name:
            server.bind(name)
    finally:
        os.umask(previous_umask)
    os.chmod(path, 0o600)
    server.listen(16)
    return _UnixListener(server, path)


# ── policy, delegated ──────────────────────────────────────────────────────
#
# The decision itself lives in `passbook_access.py`, which needs no daemon and
# can be reasoned about on its own. What is left here is the part that genuinely
# needs a live process: holding a request open while a person answers it.

read_policy = access.read_policy
write_policy = access.write_policy
policy_path = access.policy_path


def learn_policy(*, root: Path | None = None, mode: str = "always") -> dict[str, Any]:
    """Build a policy from what the ledger shows apps have actually asked for.

    Deriving it beats writing one: a policy invented up front is wrong in ways
    that only show up as a broken app later, which is how a machine ends up
    parked in permissive mode forever.
    """
    try:
        import passbook_stamp
    except ImportError:
        return {"version": access.POLICY_VERSION, "default": {"mode": "never"}, "apps": {}}
    seen: dict[str, set[str]] = {}
    for row in passbook_stamp.read_stamps(limit=100000, root=root):
        if row.get("op") not in {"read", "denied"}:
            continue
        app = str(row.get("app") or "").strip()
        if not app:
            continue
        seen.setdefault(app, set()).update(str(key) for key in row.get("keys") or [])
    return {
        "version": access.POLICY_VERSION,
        # Everything an app was seen to need becomes explicit; anything else
        # falls to the machine default, which the caller chooses.
        "default": {"mode": "never"},
        "apps": {
            app: {"default": {"mode": "never"},
                  "keys": {key: {"mode": mode} for key in sorted(keys)}}
            for app, keys in sorted(seen.items())
        },
    }


# ── approvals ──────────────────────────────────────────────────────────────
#
# `ask` only works if someone can answer, so the broker keeps a queue a person
# (or a UI, or a passkey ceremony) can see and act on. Requests wait here rather
# than failing immediately, because a credential read that fails the instant you
# step away from the keyboard is a policy nobody keeps switched on.

def _approval_timeout() -> float:
    """How long a request waits for a person before it gives up.

    Read per call rather than frozen at import so a test — or a machine where a
    minute is the wrong answer — can set it without restarting anything.
    """
    try:
        return max(1.0, float(os.environ.get("PASSBOOK_APPROVAL_TIMEOUT", "60")))
    except ValueError:
        return 60.0

_PENDING: dict[str, dict[str, Any]] = {}
_PENDING_LOCK = threading.Lock()


def pending() -> list[dict[str, Any]]:
    """Requests waiting on a person. Key names, never values."""
    with _PENDING_LOCK:
        return [{key: value for key, value in item.items() if key != "event"}
                for item in _PENDING.values()]


def _queue(app: str, keys: list[str], reason: str,
           kind: str = "read") -> tuple[str, threading.Event]:
    request_id = secrets.token_hex(4)
    event = threading.Event()
    with _PENDING_LOCK:
        _PENDING[request_id] = {
            "id": request_id, "app": app, "keys": sorted(keys), "reason": reason,
            "kind": kind,
            "asked": access._stamp(access._now()), "decision": "", "event": event,
        }
    notify(kind, app, sorted(keys))
    return request_id, event


APP_BUNDLE_ID = "app.hivemindos.passbook"


def _wake_the_window() -> bool:
    """Start PassBook without bringing it forward. True if it is now running.

    Nothing else can answer a held request. `passbook approve` exists, but the
    notification says "waiting for you", and the place that waiting ends is the
    window — so if it is not open, the useful thing to do about a request that
    needs a person is to open it, not to describe it into an empty room.

    `-g` leaves the focus where it is and `-j` starts it hidden, so a request
    that arrives mid-sentence does not take the keyboard away from whatever you
    were typing into. The notification is what brings it forward, when you ask.
    """
    if os.environ.get("PASSBOOK_NO_LAUNCH"):
        return False
    try:
        done = subprocess.run(["open", "-g", "-j", "-b", APP_BUNDLE_ID],
                              capture_output=True, timeout=8)
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def notify(kind: str, app: str, keys: list[str]) -> None:
    """Put the request in front of the person, outside the app window.

    The PassBook window is usually not the one you are looking at, and a
    request that waits three minutes in a window nobody has open is a request
    that times out. Never raises and never blocks for long: a machine with no
    notifier is a machine that still has to work.

    On macOS the window posts the banner and this only makes sure there is a
    window to post it. `osascript -e 'display notification'` used to do it from
    here, and it cannot be made to look right: `osascript` is a Script Editor
    helper, so the banner carried an AppleScript icon and clicking it opened
    Script Editor's open-a-file panel. A notification about credentials has to
    come from the app that holds them, and it has to open that app.

    Key NAMES only. A notification banner is drawn by the OS, may be logged by
    it, and is visible to anyone glancing at the screen.
    """
    if os.environ.get("PASSBOOK_NO_NOTIFY"):
        return
    named = ", ".join(keys[:3]) + (f" and {len(keys) - 3} more" if len(keys) > 3 else "")
    verb = {"add": "wants to add", "modify": "wants to change",
            "delete": "wants to remove"}.get(kind, "wants to read")
    body = f"{app} {verb} {named or 'a credential'}"
    try:
        if sys.platform == "darwin":
            if _wake_the_window():
                return
            # No PassBook on this machine — a CLI-only install, where the
            # answer comes from `passbook approve`. Say it however we can.
            script = ('display notification {} with title "PassBook" subtitle {}'
                      .format(json.dumps(body), json.dumps("Waiting for you")))
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        elif sys.platform.startswith("linux"):
            subprocess.run(["notify-send", "PassBook", body], capture_output=True, timeout=5)
        elif sys.platform.startswith("win"):
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "[reflection.assembly]::LoadWithPartialName('System.Windows.Forms');"
                 f"[System.Windows.Forms.MessageBox]::Show({json.dumps(body)},'PassBook')"],
                capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def resolve(request_id: str, *, approve: bool, remember: str = "", approved_by: str = "owner") -> dict[str, Any]:
    """Answer one waiting request, optionally holding the door open afterwards."""
    with _PENDING_LOCK:
        item = _PENDING.get(str(request_id))
        if item is None:
            return {"ok": False, "detail": "No request is waiting under that id."}
        item["decision"] = "approve" if approve else "deny"
        item["approved_by"] = approved_by
        event = item["event"]

    unlock = None
    if approve and remember:
        unlock = access.open_session(
            duration=remember, keys=item["keys"], app=item["app"],
            reason=f"approved: {item['reason']}"[:200], approved_by=approved_by)
    event.set()
    return {"ok": True, "decision": item["decision"], "session": (unlock or {}).get("id", "")}


def _await_decision(request_id: str, event: threading.Event) -> str:
    granted = event.wait(_approval_timeout())
    with _PENDING_LOCK:
        item = _PENDING.pop(request_id, {})
    if not granted:
        return "timeout"
    return item.get("decision") or "deny"


# ── serving ────────────────────────────────────────────────────────────────


def _record(op: str, keys: Iterable[str], *, app: str, granted: bool, reason: str) -> None:
    """Stamp a decision. The reason this whole thing exists, so it is not optional
    in the sense of being skipped — only in the sense of being absent entirely."""
    try:
        import passbook_stamp

        passbook_stamp.stamp(op=op, keys=keys, app=app, granted=granted, reason=reason)
    except ValueError:
        # An op the ledger does not know is a bug here, not a runtime condition,
        # and swallowing it silently drops the row a later audit would look for.
        # It cost one already: `signin` went unrecorded until a test caught it.
        raise
    except Exception:  # noqa: BLE001 — a failed receipt must not fail a read
        pass


def _caller(connection: "socket.socket") -> dict[str, Any]:
    """Who is on the other end, as far as the system will say.

    Best effort by design: most honest software on a machine is unsigned, so an
    unverifiable caller is ordinary rather than suspicious. What matters is that
    the record says which it was, instead of implying a check that never ran.
    """
    try:
        import passbook_peer
    except ImportError:
        return {"status": "unknown", "reason": "caller identification is not installed"}
    try:
        return passbook_peer.peer_identity(connection, team=os.environ.get("PASSBOOK_TEAM_ID", ""))
    except Exception as error:  # noqa: BLE001 — identification must never fail a read
        return {"status": "unknown", "reason": f"could not identify the caller: {error}"}


# ── the signed-in vault ────────────────────────────────────────────────────
#
# A v2 store is opened by a data key derived from a password or a passkey. That
# key lives here, in this process's memory, and is never written down and never
# sent back over the socket. Callers ask for VALUES; they never receive the key
# that opens them, so a client that is later compromised cannot decrypt the
# store on its own or hand the key to anything else.
#
# Deriving inside the broker also keeps the password itself from ever reaching
# disk: it crosses one 0600 socket, becomes a key, and is dropped.

_VAULT_LOCK = threading.Lock()
# One open session per WORKSPACE, keyed by its id.
#
# There used to be exactly one, because there used to be one vault for the
# machine — so "which workspace am I in" and "whose key opens it" were
# unrelated questions and only the second could be asked. A workspace is
# already a separate store; giving it its own vault makes them one question,
# and this is the half that has to hold more than one answer at a time. Agents
# pinned to different workspaces run at the same time, and signing in to one
# must not close another.
_VAULT_STATE: dict[str, dict[str, Any]] = {}


def _here(root: Path | None = None) -> str:
    """The workspace this call is about. Never blank: `main` is the default."""
    import passbook

    try:
        return passbook.workspace() or passbook.ROOT_WORKSPACE_ID
    except Exception:  # noqa: BLE001 — an unreadable manifest is not locked
        return passbook.ROOT_WORKSPACE_ID


def _vault_root(workspace: str = "") -> Path | None:
    """Where one workspace's vault and store live, together."""
    try:
        import passbook_vault

        return passbook_vault.workspace_root(workspace or _here())
    except Exception:  # noqa: BLE001
        return None

# A sign-in that does not end until somebody ends it.
#
# The old default closed the vault after eight hours, on the reasoning that a
# walked-away-from laptop should close itself. That reasoning is about a person
# at a desk, and it is wrong for what this machine actually does: agents read
# credentials overnight and at weekends, and a vault that locks itself at 2am
# does not protect anything — it stops the work and teaches whoever owns it to
# stop sealing the store.
#
# Nothing is weakened by it that was not already true. The data key lives in
# this process and nowhere else, so it goes when the broker does, and it never
# survives a reboot however long the session was for. What ends now is the
# timer, not the boundary.
SESSION_FOREVER = 0
DEFAULT_SESSION_SECONDS = SESSION_FOREVER

# What somebody types to ask for it, on the command line or in the window.
FOREVER_WORDS = frozenset({"always", "forever", "never", "none", "0", "no-expiry"})


def _forget_dek(workspace: str = "") -> bool:
    """Drop one workspace's key, or every one. True if anything was held.

    Overwrites the bytes we are allowed to overwrite before dropping them.
    """
    names = [workspace] if workspace else list(_VAULT_STATE)
    dropped = False
    for name in names:
        session = _VAULT_STATE.pop(name, None)
        if session is None:
            continue
        dropped = True
        holder = session.get("dek")
        if isinstance(holder, bytearray):
            for index in range(len(holder)):
                holder[index] = 0
    return dropped


def _held_dek(workspace: str = "") -> tuple[bytes | None, str]:
    """The data key for one workspace, or (None, "") when locked or expired.

    An `expires` of zero is a session with no end, not one that ended in 1970.
    There is no state where the key is held and the field is missing: it is
    written by the same update that puts the key there.
    """
    name = workspace or _here()
    with _VAULT_LOCK:
        session = _VAULT_STATE.get(name)
        if not session:
            return None, ""
        expires = float(session.get("expires", 0))
        if expires and time.time() >= expires:
            _forget_dek(name)
            return None, ""
        return bytes(session["dek"]), str(session.get("profile", ""))


def _unsealer(values: dict[str, str]) -> dict[str, str]:
    """Installed into `passbook` so every read through this process can open."""
    try:
        import passbook_vault
    except ImportError:
        return values
    dek, profile = _held_dek(_here())
    return passbook_vault.unseal_mapping(values, dek, profile_id=profile)


def _seal_values(payload: Mapping[str, Any], root: Path | None,
                 caller: Mapping[str, Any] | None) -> dict[str, Any]:
    """Write named values into the store, sealed with the data key held here.

    The gap this fills: a sealed store had no way to accept a new value and stay
    sealed. `set_values` writes what it is given, and only the broker holds the
    key, so anything writing to a sealed store wrote plaintext beside the
    ciphertext and left the store half and half — a state nobody chose and
    nothing reports.

    That is not a theoretical wart. Fleet env replication writes peer values
    straight into the file, so a machine that sealed its store had it quietly
    unsealed one key at a time by its own peers.

    Values arrive over the same 0600 socket a sign-in uses and leave as
    ciphertext. Refused when the vault is shut, because sealing without the key
    would mean inventing one.
    """
    try:
        import passbook_vault
    except ImportError:
        return {"ok": False, "error": "this build has no vault support"}

    incoming = payload.get("values")
    if not isinstance(incoming, dict) or not incoming:
        return {"ok": False, "error": "no values to seal"}

    dek, profile = _held_dek(_here())
    if dek is None:
        return {"ok": False, "error": "the vault is shut, so nothing can be sealed"}

    app = str(payload.get("app") or "passbook")
    sealed: dict[str, str] = {}
    for name, value in incoming.items():
        name = str(name)
        if not isinstance(value, str) or not value:
            continue
        # Already sealed by someone else's key is not something to re-wrap: it
        # would be wrapped around a blob rather than a secret.
        if passbook_vault.is_sealed(value) or passbook_vault.is_sealed_v1(value):
            continue
        sealed[name] = passbook_vault.seal_value(name, value, dek, profile_id=profile)
    if not sealed:
        return {"ok": True, "sealed": [], "detail": "nothing needed sealing"}

    try:
        result = passbook.set_values(sealed, overwrite=True, exact=True,
                                     workspace_id=str(payload.get("workspace") or ""))
    except Exception as error:  # noqa: BLE001 — surface, never crash the daemon
        return {"ok": False, "error": str(error)}

    _record("write", sorted(sealed), app=app, granted=True,
            reason=f"sealed {len(sealed)} value(s) on write")
    return {"ok": True, "sealed": sorted(sealed), "path": result.get("path", "")}


def _confirm(payload: Mapping[str, Any], root: Path | None,
             caller: Mapping[str, Any] | None) -> dict[str, Any]:
    """Hold a CHANGE until a person approves it.

    The read path asks when a key's mode says `ask`. This is the same machinery
    pointed at writes: a store whose values cannot be read is a different
    property from a store whose contents cannot change quietly, and only the
    second one catches an agent helpfully "fixing" a credential.

    The broker does not perform the change. It answers yes or no and the caller
    does the work, which keeps one writer rather than two.
    """
    kind = str(payload.get("kind") or "").strip().lower()
    if kind not in access.CONFIRM_OPS:
        return {"ok": False, "error": f"{kind or 'that'} is not a change this can confirm"}
    policy = read_policy(root)
    if not access.needs_confirmation(kind, policy):
        return {"ok": True, "decision": "approve", "why": "confirmation is not required"}

    app = str(payload.get("app") or "unknown")
    keys = sorted({str(k).strip() for k in (payload.get("keys") or []) if str(k).strip()})
    reason = str(payload.get("reason") or "")[:200]
    request_id, event = _queue(app, keys, reason, kind=kind)
    decision = _await_decision(request_id, event)
    granted = decision == "approve"
    _record("approve" if granted else "denied", keys or ["*"], app=app, granted=granted,
            reason=f"{kind}: {decision}")
    if decision == "timeout":
        return {"ok": False, "decision": "timeout",
                "error": "Nobody answered in time, so nothing was changed."}
    return {"ok": granted, "decision": decision,
            "error": "" if granted else "That change was declined."}


def _signin(payload: Mapping[str, Any], root: Path | None,
            caller: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        import passbook_vault
    except ImportError:
        return {"ok": False, "error": "this build has no vault support"}

    # The workspace decides which vault this is about. `root` is the machine's
    # store directory and stays what it always was; a workspace's own vault
    # sits beside its own `.env`, which for `main` is the same place.
    workspace = str(payload.get("workspace") or "").strip() or _here()
    try:
        vault_root = passbook_vault.workspace_root(workspace)
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "error": f"no such workspace: {workspace} ({error})"}
    if root is not None and workspace == _here():
        vault_root = root
    profile = str(payload.get("profile") or "").strip() \
        or passbook_vault.active_profile_id(root=vault_root)
    if not profile:
        return {"ok": False,
                "error": f"{workspace} has no key of its own yet — create one first"}
    asked = str(payload.get("duration") or "").strip().lower()
    try:
        if not asked:
            # No duration named means "same as this workspace is already on".
            # Without that, signing in again — to switch profile, or after
            # adding a passkey — silently turned a session somebody had
            # deliberately time-boxed to an hour into one that never ends.
            with _VAULT_LOCK:
                held = _VAULT_STATE.get(workspace) or {}
                seconds = held.get("asked", DEFAULT_SESSION_SECONDS)
        elif asked in FOREVER_WORDS:
            seconds = SESSION_FOREVER
        else:
            seconds = access.parse_duration(asked)
    except ValueError as error:
        return {"ok": False, "error": str(error)}

    try:
        if payload.get("password"):
            dek = passbook_vault.unlock_with_password(profile, str(payload["password"]),
                                                      root=vault_root)
            factor = "password"
        elif payload.get("prf_secret"):
            dek = passbook_vault.unlock_with_passkey(
                profile, credential_id=str(payload.get("credential_id") or ""),
                prf_secret=base64.urlsafe_b64decode(
                    str(payload["prf_secret"]) + "=" * (-len(str(payload["prf_secret"])) % 4)),
                root=vault_root)
            factor = "passkey"
        elif payload.get("device"):
            dek = passbook_vault.unlock_with_device(profile, root=vault_root)
            factor = "device"
        elif payload.get("recovery"):
            dek = passbook_vault.unlock_with_recovery(profile, str(payload["recovery"]),
                                                      root=vault_root)
            factor = "recovery"
        else:
            return {"ok": False, "error": "no factor offered"}
    except passbook_vault.VaultError as error:
        # A failed sign-in is exactly the row an audit wants, and the reason is
        # safe to record: it names a factor, never a secret.
        _record("signin", ["*"], app=str(payload.get("app") or "passbook"), granted=False,
                reason=f"refused: {error}")
        return {"ok": False, "error": str(error)}

    with _VAULT_LOCK:
        # Only this workspace's previous session is replaced. Signing in to one
        # used to close every other, which on a machine where agents are pinned
        # to different workspaces meant opening yours broke theirs.
        _forget_dek(workspace)
        _VAULT_STATE[workspace] = {
            "dek": bytearray(dek), "profile": profile, "factor": factor,
            "workspace": workspace, "opened_at": time.time(),
            "expires": (time.time() + seconds) if seconds else SESSION_FOREVER,
            # What was asked for, not what is left of it: a sign-in that
            # inherits the remaining time would shrink the session every time
            # somebody signed in again.
            "asked": seconds,
        }
    span = access.describe_duration(seconds) if seconds else "until it is locked"
    _record("signin", ["*"], app=str(payload.get("app") or "passbook"), granted=True,
            reason=f"{factor} sign-in to {workspace} for {span} "
                   f"[{(caller or {}).get('status', 'unknown')} caller]")
    return {"ok": True, "profile": profile, "factor": factor, "workspace": workspace,
            "expires_in": seconds,
            "detail": f"Signed in for {span}." if seconds
                      else "Signed in. It stays open until you lock it or the broker stops."}


def _opens_how_many(dek: bytes | None, profile: str, root: Path | None) -> int:
    """How many of the sealed values this session's key can actually open.

    "Unlocked" only ever meant "a data key is held here", and that is not the
    same claim as "the store is readable". Every profile has its own key and
    the profile id is bound into each value, so signing in to the wrong profile
    holds a perfectly good key that opens nothing — and the window said Open
    over a store where every single value stayed unreadable.

    This is the same failure the vault screen already had once, from the other
    direction, and the answer is the same: count it, do not assume it.
    """
    if dek is None:
        return 0
    try:
        import passbook
        import passbook_vault

        target = passbook.env_path() if root is None else Path(root) / ".env"
        raw = passbook.parse_env_text(target.read_text(encoding="utf-8"))
        sealed = {name: value for name, value in raw.items()
                  if passbook_vault.is_sealed(value)}
        if not sealed:
            return 0
        return len(passbook_vault.unseal_mapping(sealed, dek, profile_id=profile))
    except Exception:  # noqa: BLE001 — a status call must not fail the window
        return 0


def _vault_status(root: Path | None) -> dict[str, Any]:
    try:
        import passbook_vault
    except ImportError:
        return {"ok": True, "supported": False, "unlocked": False}
    here = _here()
    dek, profile = _held_dek(here)
    with _VAULT_LOCK:
        session = _VAULT_STATE.get(here) or {}
        expires = float(session.get("expires", 0))
        factor = str(session.get("factor", ""))
        # Which workspaces are open right now, so the picker can say so on the
        # tiles rather than making somebody click one to find out.
        open_now = sorted(name for name, held in _VAULT_STATE.items()
                          if not (held.get("expires") and time.time() >= held["expires"]))
    state = passbook_vault.status(root=root)
    return {"ok": True, "supported": True, "unlocked": dek is not None, "profile": profile,
            "workspace": here, "unlocked_workspaces": open_now,
            "factor": factor, "expires_in": max(0, int(expires - time.time())) if expires else 0,
            # Not "is a key held" but "does the key held here open anything".
            "opens": _opens_how_many(dek, profile, root),
            "sealed_count": len(state["sealed"]),
            "store": {k: state[k] for k in ("sealed", "legacy_v1", "plaintext", "fully_sealed", "detail")},
            "profiles": state["profiles"], "active": state["active"]}


# ── keeping sign-ins alive ─────────────────────────────────────────────────
#
# An OAuth access token dies on a timer. Whatever created the grant usually
# refreshes it — while that thing is running. The broker is running whenever any
# app on this machine can read a credential at all, which makes it the one place
# where "the token is always live" can actually be true.
#
# So a request that names a grant's access-token key renews it first, if it is
# close enough to expiry to matter. The caller gets a working token and never
# learns that anything happened.

_REFRESH_LOCK = threading.Lock()
_REFRESHING: dict[str, threading.Event] = {}


def _refresh_if_needed(wanted: Iterable[str], root: Path | None) -> list[str]:
    """Renew any grant whose access token was asked for and is about to die."""
    try:
        import passbook_oauth
    except ImportError:
        return []

    asked = {str(key) for key in wanted}
    renewed: list[str] = []
    for grant in passbook_oauth.read_grants(root=root).get("grants", []):
        if not isinstance(grant, dict) or not grant.get("key_prefix"):
            continue
        try:
            keys = passbook_oauth.grant_keys(grant)
        except passbook_oauth.GrantError:
            continue
        if keys["access_token"] not in asked:
            continue
        if _renew_one(grant, keys, root):
            renewed.append(grant.get("id", ""))
    return renewed


def _renew_one(grant: Mapping[str, Any], keys: Mapping[str, str], root: Path | None) -> bool:
    import passbook_oauth

    identifier = str(grant.get("id") or "")
    # One refresh per grant at a time. Two agents asking at once would otherwise
    # both spend the refresh token, and a provider that rotates them invalidates
    # the loser — disconnecting a grant that was working a second ago.
    with _REFRESH_LOCK:
        running = _REFRESHING.get(identifier)
        if running is None:
            running = threading.Event()
            _REFRESHING[identifier] = running
            leader = True
        else:
            leader = False
    if not leader:
        running.wait(timeout=HTTP_REFRESH_WAIT)
        return False

    try:
        values = {name: value for name, value in passbook.load().items() if name in set(keys.values())}
        if not passbook_oauth.needs_refresh(grant, values):
            return False
        refresh_token = values.get(keys["refresh_token"], "")
        fresh = passbook_oauth.exchange_refresh(grant, refresh_token, root=root)
        passbook.set_values(fresh, overwrite=True)
        _record("refresh", [keys["access_token"]], app="passbook-oauth", granted=True,
                reason=f"renewed {identifier}")
        return True
    except Exception as error:  # noqa: BLE001 — a dead grant must not fail the read
        # The caller still gets whatever is stored; a stale token failing at the
        # provider is a better outcome than the whole request erroring here, and
        # the row says which grant needs signing in again.
        _record("refresh", [keys.get("access_token", "*")], app="passbook-oauth", granted=False,
                reason=f"{identifier}: {str(error)[:120]}")
        return False
    finally:
        with _REFRESH_LOCK:
            _REFRESHING.pop(identifier, None)
        running.set()


HTTP_REFRESH_WAIT = 30.0


def _handle(payload: Mapping[str, Any], root: Path | None = None,
            caller: Mapping[str, Any] | None = None) -> dict[str, Any]:
    operation = str(payload.get("op") or "").strip().lower()
    if operation == "ping":
        return {"ok": True, "pid": os.getpid(), "spec_version": SPEC_VERSION}
    if operation == "status":
        # Names only, like every other status surface in this standard.
        policy = read_policy(root)
        _ = caller
        return {"ok": True, "default": policy["default"], "apps": sorted(policy["apps"]),
                "keys": passbook.key_names(), "workspace": passbook.workspace(),
                "sessions": access.sessions(root=root), "pending": pending()}
    if operation == "pending":
        return {"ok": True, "pending": pending()}
    if operation == "resolve":
        return {"ok": True, **resolve(
            str(payload.get("id") or ""), approve=bool(payload.get("approve")),
            remember=str(payload.get("remember") or ""),
            approved_by=str(payload.get("by") or "owner"))}
    if operation == "unlock":
        try:
            unlock = access.open_session(
                duration=str(payload.get("duration") or "1h"),
                keys=payload.get("keys") or [], app=str(payload.get("app") or ""),
                reason=str(payload.get("reason") or ""),
                approved_by=str(payload.get("by") or "owner"), root=root)
        except ValueError as error:
            return {"ok": False, "error": str(error)}
        _record("unlock", unlock["keys"] or ["*"], app=unlock["app"] or "any app",
                granted=True, reason=f"unlocked for {access.describe_duration(unlock['duration_seconds'])}")
        return {"ok": True, "session": unlock}
    if operation == "lock":
        closed = access.close_session(str(payload.get("id") or ""), root=root)
        if closed["closed"]:
            _record("lock", ["*"], app="passbook-cli", granted=True, reason="unlock ended early")
        return {"ok": True, **closed}
    if operation == "seal_values":
        return _seal_values(payload, root, caller)
    if operation == "confirm":
        return _confirm(payload, root, caller)
    if operation == "signin":
        return _signin(payload, root, caller)
    if operation == "signout":
        # Named workspace, or every one. "Everything" is what the lock screen's
        # agent-access switch means, and it has to be sayable in one call — a
        # loop over workspaces would leave a window where some are still open.
        wanted = str(payload.get("workspace") or "").strip()
        every = bool(payload.get("all")) or (not wanted and bool(payload.get("everything")))
        target = "" if every else (wanted or _here())
        with _VAULT_LOCK:
            was = _forget_dek("" if every else target)
        if was:
            _record("signout", ["*"], app="passbook", granted=True,
                    reason=f"locked {'every workspace' if every else target}")
        return {"ok": True, "locked": True, "was_unlocked": was,
                "workspace": "" if every else target}
    if operation == "vault":
        return _vault_status(root)
    if operation != "request":
        return {"ok": False, "error": "unknown operation"}

    app = str(payload.get("app") or "").strip() or "unknown"
    reason = str(payload.get("reason") or "")[:200]
    # The app NAME is a claim. The caller status is what the kernel would say
    # about it, and the two are recorded separately on purpose: conflating them
    # is exactly the overstatement this whole feature exists to avoid.
    status = (caller or {}).get("status", "unknown")
    reason = f"{reason} [{status} caller]".strip() if reason else f"[{status} caller]"
    policy = read_policy(root)
    # Whose workspace is asking, not this daemon's.
    asking_workspace = str(payload.get("workspace") or "")
    # A claim the caller makes, like its app name. The broker cannot verify it
    # and does not pretend to; what it does is hold the caller to it.
    asking_project = str(payload.get("project") or "")
    wanted = [str(key).strip() for key in (payload.get("keys") or []) if str(key).strip()]

    allowed, refused, asked = [], [], []
    for key in wanted:
        verdict = access.decide_key(app, key, policy, root=root,
                                    workspace=asking_workspace, project=asking_project)
        if verdict["outcome"] == "grant":
            allowed.append(key)
        elif verdict["outcome"] == "refuse":
            refused.append((key, verdict["why"]))
        else:
            asked.append(key)

    if asked:
        # One prompt for the whole batch. Asking per key would train anyone into
        # approving without reading, which is worse than not asking at all.
        request_id, event = _queue(app, asked, reason)
        _record("ask", asked, app=app, granted=False, reason=reason or "waiting on approval")
        decision = _await_decision(request_id, event)
        if decision == "approve":
            allowed.extend(asked)
        else:
            refused.extend((key, "declined" if decision == "deny" else "no answer in time")
                           for key in asked)

    if allowed:
        # Before reading: renew any sign-in among these keys that is about to
        # expire, so what the caller receives actually works.
        _refresh_if_needed(allowed, root)
    available = passbook.load()
    granted = {key: available[key] for key in allowed if available.get(key)}
    missing = [key for key in allowed if key not in granted]

    if allowed:
        _record("read", allowed, app=app, granted=not missing, reason=reason)
    if refused:
        # A refusal is the interesting row: an app asked for something its policy
        # does not cover, which is either a policy to widen or a dependency doing
        # something nobody asked it to.
        _record("denied", [key for key, _ in refused], app=app, granted=False,
                reason="; ".join(sorted({why for _, why in refused}))[:200])

    return {"ok": True, "granted": granted, "denied": sorted(key for key, _ in refused),
            "missing": sorted(missing),
            "why": {key: why for key, why in refused}}


def _serve_one(connection: socket.socket, root: Path | None) -> None:
    try:
        connection.settimeout(CONNECT_TIMEOUT)
        chunks, total = [], 0
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_REQUEST_BYTES:
                connection.sendall(b'{"ok":false,"error":"request too large"}\n')
                return
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        raw = b"".join(chunks).decode("utf-8").strip()
        if not raw:
            return
        answer = _handle(json.loads(raw), root, _caller(connection))
    except (OSError, ValueError, UnicodeDecodeError):
        answer = {"ok": False, "error": "bad request"}
    except Exception as error:  # noqa: BLE001 — see below
        # Any unhandled failure in here used to end the thread without replying,
        # and the client then sat out its entire timeout — two minutes of
        # nothing, for a malformed policy file. Answering with the failure lets
        # the client fall back to the stores immediately, which is the same
        # thing it does when no broker is running at all.
        answer = {"ok": False, "error": f"broker failed to answer: {type(error).__name__}"}
    try:
        connection.sendall((json.dumps(answer, separators=(",", ":")) + "\n").encode("utf-8"))
    except OSError:
        pass
    finally:
        try:
            connection.close()
        except OSError:
            pass


def serve(*, root: Path | None = None, ready: threading.Event | None = None) -> None:
    """Run the broker in the foreground until interrupted."""
    store_root(root).mkdir(parents=True, exist_ok=True)
    if running(root=root):
        raise RuntimeError(f"A broker is already listening on {endpoint(root)}")

    server = _listen(root)

    pid_path(root).write_text(str(os.getpid()), encoding="utf-8")
    if not _WINDOWS:
        # Windows has no mode bits to set here; the file sits inside a profile
        # directory the account already owns.
        os.chmod(pid_path(root), 0o600)

    # From here on, reads inside THIS process can open a sealed store once
    # somebody signs in. No other process installs this, which is what makes
    # the broker the only door rather than merely the polite one.
    passbook.set_unsealer(_unsealer)
    if ready is not None:
        ready.set()

    try:
        while True:
            try:
                connection = server.accept()
            except OSError:
                break
            threading.Thread(target=_serve_one, args=(connection, root), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        pid_path(root).unlink(missing_ok=True)


# ── talking to it ──────────────────────────────────────────────────────────


@contextlib.contextmanager
def _dial(root: Path | None, timeout: float):
    """A connection to the broker, however this platform reaches one.

    Raises `FileNotFoundError` when nothing is listening, which `_ask` turns
    into None — "there is no broker", which is a different answer from "the
    broker said no" and must not be confused with it.
    """
    if _WINDOWS:
        name = passbook_pipe.pipe_name(store_root(root))
        if not passbook_pipe.is_listening(name):
            raise FileNotFoundError(name)
        client = passbook_pipe.connect(name, timeout)
        try:
            yield client
        finally:
            client.close()
        return

    path = socket_path(root)
    if not path.exists():
        raise FileNotFoundError(str(path))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        with _bindable(path) as name:
            client.connect(name)
        yield client


def _ask(payload: Mapping[str, Any], *, root: Path | None = None, timeout: float | None = None):
    if timeout is None:
        timeout = REQUEST_TIMEOUT if payload.get("op") == "request" else CONNECT_TIMEOUT
    try:
        with _dial(root, timeout) as client:
            client.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))
            chunks = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        return json.loads(b"".join(chunks).decode("utf-8").strip())
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def running(*, root: Path | None = None) -> bool:
    answer = _ask({"op": "ping"}, root=root, timeout=1.0)
    return bool(answer and answer.get("ok"))


def request_through_broker(
    keys: Iterable[str],
    *,
    app: str,
    reason: str = "",
    workspace_id: str = "",
    root: Path | None = None,
) -> dict[str, str] | None:
    """Ask the broker. Returns None when there is no broker to ask.

    None means "not available", never "denied" — those are different answers and
    a caller that conflated them would fail open on a refusal.
    """
    # The project is worked out here rather than asked for, so every caller
    # that already reaches the broker is held to it without changing its code.
    try:
        import passbook

        here = passbook.project()
    except Exception:  # noqa: BLE001 — no project is the common case
        here = ""
    answer = _ask({
        "op": "request", "app": app, "keys": list(keys),
        "reason": reason, "workspace": workspace_id, "project": here,
    }, root=root)
    if not answer or not answer.get("ok"):
        return None
    granted = answer.get("granted")
    return granted if isinstance(granted, dict) else {}


def seal_values(values: Mapping[str, str], *, app: str = "passbook",
                workspace_id: str = "", root: Path | None = None) -> dict[str, Any]:
    """Write values into the store sealed, using the key the broker holds.

    Returns `{"ok": False, ...}` when there is no broker or the vault is shut,
    and a caller must treat that as "could not seal" rather than "did not need
    to" — writing the plaintext instead is exactly the bug this exists to stop.
    """
    answer = _ask({"op": "seal_values", "app": app, "workspace": workspace_id,
                   "values": dict(values)}, root=root, timeout=30.0)
    if answer is None:
        return {"ok": False, "error": "no broker is running, so nothing could be sealed"}
    return answer


def confirm_change(kind: str, keys: Iterable[str], *, app: str, reason: str = "",
                   root: Path | None = None) -> dict[str, Any]:
    """Ask the person to approve a change. Returns the decision, or None-ish.

    A broker that is not running means confirmation cannot be obtained. That is
    reported as `unavailable` rather than as approval: a toggle whose enforcement
    disappears when a daemon stops is not a toggle, it is a suggestion.
    """
    answer = _ask({
        "op": "confirm", "kind": kind, "app": app,
        "keys": [str(k) for k in keys], "reason": reason,
    }, root=root, timeout=_approval_timeout() + 5.0)
    if answer is None:
        return {"ok": False, "decision": "unavailable",
                "error": "No broker is running, so that change could not be confirmed."}
    return answer


def signin(
    *,
    profile: str = "",
    password: str = "",
    recovery: str = "",
    credential_id: str = "",
    prf_secret: bytes = b"",
    device: bool = False,
    duration: str = "",
    workspace: str = "",
    app: str = "passbook",
    root: Path | None = None,
) -> dict[str, Any]:
    """Open the vault in the broker. The data key never comes back over the wire.

    The factor crosses one 0600 socket and is turned into a key on the far side;
    what returns is a yes or a no. A caller therefore cannot cache the key, leak
    it, or pass it on, because it never had it.
    """
    payload: dict[str, Any] = {"op": "signin", "profile": profile, "app": app}
    if workspace:
        payload["workspace"] = workspace
    if duration:
        payload["duration"] = duration
    if password:
        payload["password"] = password
    elif recovery:
        payload["recovery"] = recovery
    elif prf_secret:
        payload["prf_secret"] = base64.urlsafe_b64encode(prf_secret).decode("ascii").rstrip("=")
        payload["credential_id"] = credential_id
    elif device:
        payload["device"] = True
    answer = _ask(payload, root=root, timeout=30.0)
    if answer is None:
        return {"ok": False, "error": "no broker is running to sign in to"}
    return answer


def signout(*, workspace: str = "", everything: bool = False,
            root: Path | None = None) -> dict[str, Any]:
    """Lock a workspace, or every one. The keys are dropped and overwritten."""
    payload: dict[str, Any] = {"op": "signout"}
    if everything:
        payload["all"] = True
    elif workspace:
        payload["workspace"] = workspace
    answer = _ask(payload, root=root)
    if answer is None:
        return {"ok": False, "error": "no broker is running"}
    return answer


def vault_status(*, root: Path | None = None) -> dict[str, Any]:
    """Locked or open, which profile, how long left, and what the store holds."""
    answer = _ask({"op": "vault"}, root=root)
    if answer is None:
        return {"ok": False, "running": False, "unlocked": False,
                "error": "no broker is running"}
    return {**answer, "running": True}


# ── lifecycle ──────────────────────────────────────────────────────────────


def start(*, root: Path | None = None, wait: float = 5.0) -> dict[str, Any]:
    """Start the broker in the background."""
    if running(root=root):
        return {"ok": True, "already": True, "path": endpoint(root)}
    package = Path(__file__).resolve().parent
    # Outliving the command that started it is the entire point: the broker
    # holds the data key for the session that follows. `start_new_session` is
    # the POSIX spelling and Windows ignores it silently, so there the broker
    # stayed in its parent's console and died with it — a sign-in that lasted
    # exactly as long as the process that asked for it.
    if _WINDOWS:
        detach = {"creationflags": _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP}
    else:
        detach = {"start_new_session": True}
    process = subprocess.Popen(
        [sys.executable, "-m", "passbook_broker", "--serve"],
        cwd=str(package), **detach,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(package), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep)},
    )
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if running(root=root):
            return {"ok": True, "already": False, "pid": process.pid, "path": endpoint(root)}
        if process.poll() is not None:
            detail = (process.stderr.read().decode("utf-8", "replace").strip() if process.stderr else "")
            return {"ok": False, "detail": detail.splitlines()[-1] if detail else "the broker exited at once"}
        time.sleep(0.05)
    return {"ok": False, "detail": f"the broker did not start within {wait:g}s"}


def _forget_socket(root: Path | None) -> None:
    """Remove the socket file, where there is one.

    A named pipe is not a file: it exists only while a process holds it, so
    there is nothing left behind to tidy up on Windows.
    """
    if not _WINDOWS:
        socket_path(root).unlink(missing_ok=True)


def _already_gone(root: Path | None) -> dict[str, Any]:
    """Tidy up after a broker that is not there any more."""
    _forget_socket(root)
    pid_path(root).unlink(missing_ok=True)
    return {"ok": True, "detail": "The broker was already gone; cleaned up after it."}


def stop(*, root: Path | None = None) -> dict[str, Any]:
    try:
        pid = int(pid_path(root).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        _forget_socket(root)
        return {"ok": False, "detail": "No broker is running."}
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        return _already_gone(root)
    except OSError as error:
        # Windows does not raise ProcessLookupError here. `os.kill` opens the
        # process first, and OpenProcess on a pid that is not running fails
        # with ERROR_INVALID_PARAMETER, so a broker that had already exited
        # came back as "Could not stop the broker: [WinError 87] The parameter
        # is incorrect" — which reads like a bug in the caller rather than the
        # ordinary case of a stale pid file.
        if getattr(error, "winerror", None) == _ERROR_INVALID_PARAMETER:
            return _already_gone(root)
        return {"ok": False, "detail": f"Could not stop the broker: {error}"}
    for _ in range(40):
        if not running(root=root):
            break
        time.sleep(0.05)
    _forget_socket(root)
    pid_path(root).unlink(missing_ok=True)
    return {"ok": True, "detail": "Stopped."}


def status(*, root: Path | None = None) -> dict[str, Any]:
    """Whether it is up, and what it would decide. Never a value."""
    policy = read_policy(root)
    live = _ask({"op": "status"}, root=root)
    return {
        "running": bool(live and live.get("ok")),
        "path": endpoint(root),
        "policy_path": str(policy_path(root)),
        "mode": policy["default"].get("mode", access.DEFAULT_MODE),
        "apps": sorted(policy["apps"]),
        "sessions": access.sessions(root=root),
        "pending": (live or {}).get("pending", []),
        "keys": (live or {}).get("keys", []),
        # Stated here so it reaches anything that renders this, not only someone
        # who read the docstring.
        "limits": (
            "Any process running as you can connect and claim to be any app, the "
            "store file is still readable directly, and stopping the broker "
            "restores full access. This makes reads recorded and narrow, not "
            "unauthorised reads impossible."
        ),
    }


if __name__ == "__main__":
    if "--serve" in sys.argv:
        serve()
