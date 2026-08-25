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


def _queue(app: str, keys: list[str], reason: str) -> tuple[str, threading.Event]:
    request_id = secrets.token_hex(4)
    event = threading.Event()
    with _PENDING_LOCK:
        _PENDING[request_id] = {
            "id": request_id, "app": app, "keys": sorted(keys), "reason": reason,
            "asked": access._stamp(access._now()), "decision": "", "event": event,
        }
    return request_id, event


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
_VAULT_STATE: dict[str, Any] = {}

# Long enough to work through, short enough that a walked-away-from laptop
# closes itself. The owner can say otherwise per sign-in.
DEFAULT_SESSION_SECONDS = 8 * 3600


def _forget_dek() -> None:
    """Drop the data key, overwriting the bytes we are allowed to overwrite."""
    holder = _VAULT_STATE.get("dek")
    if isinstance(holder, bytearray):
        for index in range(len(holder)):
            holder[index] = 0
    _VAULT_STATE.clear()


def _held_dek() -> tuple[bytes | None, str]:
    """The data key and its profile, or (None, "") when locked or expired."""
    with _VAULT_LOCK:
        if not _VAULT_STATE:
            return None, ""
        if time.time() >= float(_VAULT_STATE.get("expires", 0)):
            _forget_dek()
            return None, ""
        return bytes(_VAULT_STATE["dek"]), str(_VAULT_STATE.get("profile", ""))


def _unsealer(values: dict[str, str]) -> dict[str, str]:
    """Installed into `passbook` so every read through this process can open."""
    try:
        import passbook_vault
    except ImportError:
        return values
    dek, profile = _held_dek()
    return passbook_vault.unseal_mapping(values, dek, profile_id=profile)


def _signin(payload: Mapping[str, Any], root: Path | None,
            caller: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        import passbook_vault
    except ImportError:
        return {"ok": False, "error": "this build has no vault support"}

    profile = str(payload.get("profile") or "").strip() or passbook_vault.active_profile_id(root=root)
    if not profile:
        return {"ok": False, "error": "there is no profile to sign in to"}
    try:
        seconds = access.parse_duration(str(payload.get("duration") or "")) if payload.get("duration") \
            else DEFAULT_SESSION_SECONDS
    except ValueError as error:
        return {"ok": False, "error": str(error)}

    try:
        if payload.get("password"):
            dek = passbook_vault.unlock_with_password(profile, str(payload["password"]), root=root)
            factor = "password"
        elif payload.get("prf_secret"):
            dek = passbook_vault.unlock_with_passkey(
                profile, credential_id=str(payload.get("credential_id") or ""),
                prf_secret=base64.urlsafe_b64decode(
                    str(payload["prf_secret"]) + "=" * (-len(str(payload["prf_secret"])) % 4)),
                root=root)
            factor = "passkey"
        elif payload.get("device"):
            dek = passbook_vault.unlock_with_device(profile, root=root)
            factor = "device"
        else:
            return {"ok": False, "error": "no factor offered"}
    except passbook_vault.VaultError as error:
        # A failed sign-in is exactly the row an audit wants, and the reason is
        # safe to record: it names a factor, never a secret.
        _record("signin", ["*"], app=str(payload.get("app") or "passbook"), granted=False,
                reason=f"refused: {error}")
        return {"ok": False, "error": str(error)}

    with _VAULT_LOCK:
        _forget_dek()
        _VAULT_STATE.update({
            "dek": bytearray(dek), "profile": profile, "factor": factor,
            "opened_at": time.time(), "expires": time.time() + seconds,
        })
    _record("signin", ["*"], app=str(payload.get("app") or "passbook"), granted=True,
            reason=f"{factor} sign-in for {access.describe_duration(seconds)} "
                   f"[{(caller or {}).get('status', 'unknown')} caller]")
    return {"ok": True, "profile": profile, "factor": factor,
            "expires_in": seconds, "detail": f"Signed in for {access.describe_duration(seconds)}."}


def _vault_status(root: Path | None) -> dict[str, Any]:
    try:
        import passbook_vault
    except ImportError:
        return {"ok": True, "supported": False, "unlocked": False}
    dek, profile = _held_dek()
    with _VAULT_LOCK:
        expires = float(_VAULT_STATE.get("expires", 0)) if _VAULT_STATE else 0.0
        factor = str(_VAULT_STATE.get("factor", "")) if _VAULT_STATE else ""
    state = passbook_vault.status(root=root)
    return {"ok": True, "supported": True, "unlocked": dek is not None, "profile": profile,
            "factor": factor, "expires_in": max(0, int(expires - time.time())) if expires else 0,
            "store": {k: state[k] for k in ("sealed", "legacy_v1", "plaintext", "fully_sealed", "detail")},
            "profiles": state["profiles"], "active": state["active"]}


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
    if operation == "signin":
        return _signin(payload, root, caller)
    if operation == "signout":
        with _VAULT_LOCK:
            was = bool(_VAULT_STATE)
            _forget_dek()
        if was:
            _record("signout", ["*"], app="passbook", granted=True, reason="vault locked")
        return {"ok": True, "locked": True, "was_unlocked": was}
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
    wanted = [str(key).strip() for key in (payload.get("keys") or []) if str(key).strip()]

    allowed, refused, asked = [], [], []
    for key in wanted:
        verdict = access.decide_key(app, key, policy, root=root)
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
    path = socket_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if running(root=root):
            raise RuntimeError(f"A broker is already listening on {path}")
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

    pid_path(root).write_text(str(os.getpid()), encoding="utf-8")
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
                connection, _ = server.accept()
            except OSError:
                break
            threading.Thread(target=_serve_one, args=(connection, root), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        path.unlink(missing_ok=True)
        pid_path(root).unlink(missing_ok=True)


# ── talking to it ──────────────────────────────────────────────────────────


def _ask(payload: Mapping[str, Any], *, root: Path | None = None, timeout: float | None = None):
    if timeout is None:
        timeout = REQUEST_TIMEOUT if payload.get("op") == "request" else CONNECT_TIMEOUT
    path = socket_path(root)
    if not path.exists():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            with _bindable(path) as name:
                client.connect(name)
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
    answer = _ask({
        "op": "request", "app": app, "keys": list(keys),
        "reason": reason, "workspace": workspace_id,
    }, root=root)
    if not answer or not answer.get("ok"):
        return None
    granted = answer.get("granted")
    return granted if isinstance(granted, dict) else {}


def signin(
    *,
    profile: str = "",
    password: str = "",
    credential_id: str = "",
    prf_secret: bytes = b"",
    device: bool = False,
    duration: str = "",
    app: str = "passbook",
    root: Path | None = None,
) -> dict[str, Any]:
    """Open the vault in the broker. The data key never comes back over the wire.

    The factor crosses one 0600 socket and is turned into a key on the far side;
    what returns is a yes or a no. A caller therefore cannot cache the key, leak
    it, or pass it on, because it never had it.
    """
    payload: dict[str, Any] = {"op": "signin", "profile": profile, "app": app}
    if duration:
        payload["duration"] = duration
    if password:
        payload["password"] = password
    elif prf_secret:
        payload["prf_secret"] = base64.urlsafe_b64encode(prf_secret).decode("ascii").rstrip("=")
        payload["credential_id"] = credential_id
    elif device:
        payload["device"] = True
    answer = _ask(payload, root=root, timeout=30.0)
    if answer is None:
        return {"ok": False, "error": "no broker is running to sign in to"}
    return answer


def signout(*, root: Path | None = None) -> dict[str, Any]:
    """Lock the vault. The key is dropped and its bytes overwritten."""
    answer = _ask({"op": "signout"}, root=root)
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
        return {"ok": True, "already": True, "path": str(socket_path(root))}
    package = Path(__file__).resolve().parent
    process = subprocess.Popen(
        [sys.executable, "-m", "passbook_broker", "--serve"],
        cwd=str(package), start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(package), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep)},
    )
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if running(root=root):
            return {"ok": True, "already": False, "pid": process.pid, "path": str(socket_path(root))}
        if process.poll() is not None:
            detail = (process.stderr.read().decode("utf-8", "replace").strip() if process.stderr else "")
            return {"ok": False, "detail": detail.splitlines()[-1] if detail else "the broker exited at once"}
        time.sleep(0.05)
    return {"ok": False, "detail": f"the broker did not start within {wait:g}s"}


def stop(*, root: Path | None = None) -> dict[str, Any]:
    try:
        pid = int(pid_path(root).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        socket_path(root).unlink(missing_ok=True)
        return {"ok": False, "detail": "No broker is running."}
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        socket_path(root).unlink(missing_ok=True)
        pid_path(root).unlink(missing_ok=True)
        return {"ok": True, "detail": "The broker was already gone; cleaned up after it."}
    except OSError as error:
        return {"ok": False, "detail": f"Could not stop the broker: {error}"}
    for _ in range(40):
        if not running(root=root):
            break
        time.sleep(0.05)
    socket_path(root).unlink(missing_ok=True)
    pid_path(root).unlink(missing_ok=True)
    return {"ok": True, "detail": "Stopped."}


def status(*, root: Path | None = None) -> dict[str, Any]:
    """Whether it is up, and what it would decide. Never a value."""
    policy = read_policy(root)
    live = _ask({"op": "status"}, root=root)
    return {
        "running": bool(live and live.get("ok")),
        "path": str(socket_path(root)),
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
