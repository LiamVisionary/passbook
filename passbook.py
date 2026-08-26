# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The PassBook standard, v1 — Python reference implementation.

One credential store per machine, shared by every app that opts in. See SPEC.md.

Single file, standard library only, meant to be copied into a project as-is.
Nothing here imports from the app that hosts it.

The whole trick is that every app resolves the SAME path with the SAME rule, so
"provision if absent" and "link to the existing one" are one operation:

    import passbook
    passbook.ensure(app="my-app", name="My App")   # idempotent, converges
    passbook.apply()                               # fill missing process vars
    key = os.environ.get("OPENAI_API_KEY", "")

Values never leave this module except through `load()` and `apply()`, which put
them in the process environment where the caller asked for them. Every status
and diagnostic surface returns key NAMES.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

__all__ = [
    "SPEC_VERSION",
    "ContainerisedHomeError",
    "apply",
    "describe",
    "drop_duplicate_lines",
    "duplicate_keys",
    "ensure",
    "env_path",
    "key_names",
    "link",
    "load",
    "parse_env_text",
    "remove_values",
    "reveal",
    "request",
    "root",
    "set_recorder",
    "set_unsealer",
    "set_values",
    "status",
    "target_path",
]

SPEC_VERSION = 1

ROOT_ENV_VAR = "HIVE_HOME"
WORKSPACE_ENV_VAR = "HIVE_WORKSPACE"
DEFAULT_ROOT_NAME = ".hivemindos"
ENV_FILENAME = ".env"
APPS_FILENAME = "apps.json"
WORKSPACES_DIRNAME = "workspaces"
WORKSPACES_MANIFEST = "workspaces.json"
# HivemindOS's own name for the store at the root of the hive.
ROOT_WORKSPACE_ID = "main"

ROOT_MODE = 0o700
FILE_MODE = 0o600

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WORKSPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ContainerisedHomeError(RuntimeError):
    """The home directory is a sandbox container, so `~` is not the real home.

    Provisioning here would create a second store invisible to every other app
    — the exact forking this standard exists to prevent. The caller decides what
    to do: request the entitlement, ship unsandboxed, or set HIVE_HOME.
    """


# ── location ───────────────────────────────────────────────────────────────


def root(environ: Mapping[str, str] | None = None) -> Path:
    """The hive root: `$HIVE_HOME`, else `~/.hivemindos`."""
    source = os.environ if environ is None else environ
    configured = str(source.get(ROOT_ENV_VAR, "")).strip()
    if configured:
        return Path(configured).expanduser()
    return Path(source.get("HOME") or Path.home()).expanduser() / DEFAULT_ROOT_NAME


def env_path(environ: Mapping[str, str] | None = None) -> Path:
    """The canonical credential store, whether or not it exists yet."""
    return root(environ) / ENV_FILENAME


def apps_path(environ: Mapping[str, str] | None = None) -> Path:
    return root(environ) / APPS_FILENAME


def workspace_manifest(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """HivemindOS's own workspace manifest, when the machine has one.

    This standard does not invent a second registry. `workspaces.json` already
    maps workspace ids to env paths and names the active one, so an app that
    follows this spec sees exactly the workspaces HivemindOS shows the user.
    """
    path = root(environ) / WORKSPACES_MANIFEST
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def workspace(environ: Mapping[str, str] | None = None) -> str:
    """The workspace this process acts for.

    `HIVE_WORKSPACE` overrides the manifest's active workspace, so one agent can
    be pinned to a client's workspace without changing what the desktop app
    shows anyone else.
    """
    source = os.environ if environ is None else environ
    name = str(source.get(WORKSPACE_ENV_VAR, "")).strip()
    if not name:
        name = str(workspace_manifest(environ).get("activeWorkspaceId") or "").strip()
    if not name:
        return ""
    if not _WORKSPACE.match(name):
        raise ValueError(f"{name!r} is not a valid workspace id")
    return name


def workspace_env_path(name: str, environ: Mapping[str, str] | None = None) -> Path:
    """Where one workspace's store lives, per the manifest when it says.

    `main` is the hive root itself — that is HivemindOS's existing layout, and
    reproducing it here is what stops a second store appearing beside it.
    """
    if not _WORKSPACE.match(name):
        raise ValueError(f"{name!r} is not a valid workspace id")
    for entry in workspace_manifest(environ).get("workspaces") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "") == name:
            declared = str(entry.get("envPath") or "").strip()
            if declared:
                return Path(declared).expanduser()
    if name == ROOT_WORKSPACE_ID:
        return env_path(environ)
    return root(environ) / WORKSPACES_DIRNAME / name / ENV_FILENAME


def workspaces(environ: Mapping[str, str] | None = None) -> list[str]:
    """Every workspace on this machine: the manifest's, plus any on disk."""
    named = {
        str(entry.get("id"))
        for entry in workspace_manifest(environ).get("workspaces") or []
        if isinstance(entry, dict) and entry.get("id")
    }
    base = root(environ) / WORKSPACES_DIRNAME
    try:
        named.update(item.name for item in base.iterdir() if (item / ENV_FILENAME).is_file())
    except OSError:
        pass
    return sorted(named)


PROJECT_ENV_VAR = "PASSBOOK_PROJECT"
_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def project(environ: Mapping[str, str] | None = None, *, cwd: Path | None = None) -> str:
    """Which project this process is working in.

    `PASSBOOK_PROJECT` if it is set; otherwise the name of the nearest enclosing
    git repository; otherwise nothing.

    Deliberately a claim, not a proof — the same standing an agent name has. A
    process can set the variable to anything, and this file does not pretend
    otherwise. What it buys is still real: a key limited to one project is not
    handed to an agent running in a different checkout, so an instruction
    smuggled into one repository cannot spend another repository's credentials.
    The threat it addresses is a confused agent, not a determined attacker who
    already runs code as you — and against that one, nothing on this side of the
    broker would help either.

    A name that is not a plausible directory name is dropped rather than raised
    on: an odd checkout name should not take down every credential read on the
    machine.
    """
    source = os.environ if environ is None else environ
    declared = str(source.get(PROJECT_ENV_VAR, "")).strip()
    if declared:
        return declared if _PROJECT.match(declared) else ""
    here = Path(cwd) if cwd is not None else Path.cwd()
    try:
        here = here.resolve()
    except OSError:
        return ""
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            name = candidate.name
            return name if _PROJECT.match(name) else ""
    return ""


def set_active_workspace(name: str, environ: Mapping[str, str] | None = None) -> str:
    """Point the machine's active workspace at `name`, and say what it was.

    Written into HivemindOS's own `workspaces.json`, not a PassBook-side copy —
    for the same reason `workspace_manifest` reads it rather than inventing a
    registry. Two records of which workspace is active would disagree the first
    time either app changed one, and the disagreement would be invisible: each
    app would be showing the truth as it knew it.

    `HIVE_WORKSPACE` still wins for a process that sets it. An agent pinned to a
    client's workspace is pinned for a reason, and a person switching the
    desktop app's workspace should not silently re-point that agent.
    """
    name = str(name or "").strip()
    if not _WORKSPACE.match(name):
        raise ValueError(f"{name!r} is not a valid workspace id")
    known = set(workspaces(environ)) | {ROOT_WORKSPACE_ID}
    if name not in known:
        raise ValueError(f"There is no workspace called {name!r} on this machine.")
    payload = dict(workspace_manifest(environ))
    was = str(payload.get("activeWorkspaceId") or "").strip()
    if was == name:
        return was
    payload["activeWorkspaceId"] = name
    path = root(environ) / WORKSPACES_MANIFEST
    _atomic_write(path, json.dumps(payload, indent=2) + "\n")
    return was


def workspace_pinned(environ: Mapping[str, str] | None = None) -> bool:
    """Is this process pinned by `HIVE_WORKSPACE` rather than the manifest?

    A surface that offers to switch workspaces has to know, or it offers a
    control that appears to do nothing: the manifest changes, and the pinned
    process goes on acting for the workspace it was pinned to.
    """
    source = os.environ if environ is None else environ
    return bool(str(source.get(WORKSPACE_ENV_VAR, "")).strip())


def workspace_label(name: str, environ: Mapping[str, str] | None = None) -> str:
    """The human name HivemindOS gave a workspace, else the id itself."""
    for entry in workspace_manifest(environ).get("workspaces") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "") == name:
            label = str(entry.get("name") or entry.get("label") or "").strip()
            if label:
                return label
    return name


def workspace_inherits(name: str, environ: Mapping[str, str] | None = None) -> bool:
    """Does this workspace also see the machine-wide store?

    Default true, which is what an unmarked workspace has always done. A
    workspace holding someone else's credentials should set `"inherit": false`
    in the manifest so an agent scoped to it cannot read the machine's keys.
    """
    for entry in workspace_manifest(environ).get("workspaces") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "") == name:
            return bool(entry.get("inherit", True))
    return True


def target_path(workspace_id: str = "", environ: Mapping[str, str] | None = None) -> Path:
    """Where a write lands: the named workspace, else the active one.

    Reads layer machine store then workspace store; writes must pick exactly
    one, and the only defensible pick is the scope the process is acting for.
    An agent pinned to a client's workspace that adds a key must not have it
    appear machine-wide — that is precisely the leak `"inherit": false` exists
    to prevent, and defaulting writes to the machine store would reopen it
    behind the user's back.

    With no workspace, or with `main`, this is the machine store, so a machine
    that never used workspaces sees no change at all.
    """
    name = workspace_id or workspace(environ)
    if not name:
        return env_path(environ)
    return workspace_env_path(name, environ)


def _scoped_paths(environ: Mapping[str, str] | None = None) -> tuple[Path, ...]:
    """The stores that feed this process, least specific first.

    The machine store is the fleet-wide default; a workspace store is more
    specific, so it wins. A workspace never sees a sibling's keys.
    """
    name = workspace(environ)
    machine = env_path(environ)
    if not name:
        return (machine,)
    scoped = workspace_env_path(name, environ)
    if scoped == machine:
        return (machine,)
    return (machine, scoped) if workspace_inherits(name, environ) else (scoped,)


def container_home_reason(environ: Mapping[str, str] | None = None) -> str:
    """Why `~` cannot be trusted here, or "" when it can.

    An explicit HIVE_HOME is always trusted: naming the path is the documented
    way out of a container.
    """
    source = os.environ if environ is None else environ
    if str(source.get(ROOT_ENV_VAR, "")).strip():
        return ""
    if source.get("APP_SANDBOX_CONTAINER_ID"):
        return (
            "this process runs inside a macOS App Sandbox, so ~ is the app's private "
            "container rather than the real home directory"
        )
    home = str(source.get("HOME") or Path.home())
    if "/Library/Containers/" in home:
        return f"HOME points inside a sandbox container ({home})"
    return ""


# ── format ─────────────────────────────────────────────────────────────────


def parse_env_text(text: str) -> dict[str, str]:
    """Parse the Hive Env format. Later lines win."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            quote, value = value[0], value[1:-1]
            # Double quotes carry escapes, single quotes are literal — the same
            # split a shell makes, so a hand-edited file behaves as it looks.
            if quote == '"':
                value = re.sub(r"\\(.)", r"\1", value)
        if _KEY.match(key) and value:
            values[key] = value
    return values


def _read(path: Path) -> dict[str, str]:
    try:
        values = parse_env_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {}
    return _unseal(values)


_UNSEALER: Callable[[dict[str, str]], dict[str, str]] | None = None


def set_unsealer(unsealer: Callable[[dict[str, str]], dict[str, str]] | None) -> None:
    """Install the thing that can open sealed values.

    A v2 store is opened by a data key that only exists inside a signed-in
    broker, so the broker installs an unsealer and nothing else can. A process
    that has not signed in has no hook, reads ciphertext, and correctly sees no
    credentials at all — which is the point of sealing rather than a failure of
    it.
    """
    global _UNSEALER
    _UNSEALER = unsealer


def _unseal(values: dict[str, str]) -> dict[str, str]:
    """Decrypt any sealed values, if this process is allowed to.

    Sealing is optional and gradual, so this is a no-op on a plaintext store and
    on a machine without the companion module. Callers never learn which of the
    two they are reading, which is what lets a project adopt encryption at rest
    without touching a single call site.
    """
    if not any(str(value).startswith("hive-sealed:") for value in values.values()):
        return values
    if _UNSEALER is not None:
        try:
            return _UNSEALER(dict(values))
        except Exception:  # noqa: BLE001 — a broken unsealer must read as "shut", not crash
            pass
    try:
        import passbook_seal

        values = passbook_seal.unseal_all(values)
    except ImportError:
        pass
    except Exception:  # noqa: BLE001 — this machine cannot unseal this store
        pass
    # Degrade to "no credentials", never to ciphertext and never to a crash.
    # A sealed store on a machine without its key is exactly the stolen-file
    # case: the names stay listable, the values are simply not there.
    return {name: value for name, value in values.items() if not str(value).startswith("hive-sealed:")}


def _format_line(key: str, value: str) -> str:
    """Quote only when the value would not survive a shell round trip."""
    if value and not re.search(r"[\s#\"'$`\\]", value):
        return f"{key}={value}"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{key}="{escaped}"'


# ── reading ────────────────────────────────────────────────────────────────


def load(
    *,
    project_files: Iterable[str | Path] = (),
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Every credential visible here, in precedence order.

    Process environment beats project files, which beat the hive env. The hive
    env is a fleet-wide default and never an override.
    """
    source = os.environ if environ is None else environ
    values: dict[str, str] = {}
    for store in _scoped_paths(source):
        values.update(_read(store))
    for project_file in project_files:
        values.update(_read(Path(project_file).expanduser()))
    values.update({key: value for key, value in source.items() if value})
    return values


def apply(*, project_files: Iterable[str | Path] = ()) -> set[str]:
    """Fill variables the process lacks. Returns the key NAMES that were set.

    Only missing keys are filled, so an explicit export always wins and calling
    this repeatedly is free.
    """
    source: dict[str, str] = {}
    for store in _scoped_paths():
        source.update(_read(store))
    for project_file in project_files:
        source.update(_read(Path(project_file).expanduser()))
    filled: set[str] = set()
    for key, value in source.items():
        if value and key not in os.environ:
            os.environ[key] = value
            filled.add(key)
    return filled


def request(
    keys: Iterable[str],
    *,
    app: str,
    reason: str = "",
    workspace_id: str = "",
    actor_did: str = "",
    record: Callable[..., None] | None = None,
    stores: Iterable[str | Path] | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Ask for specific credentials, by name. The narrow door.

    This is the call an app should make. `apply()` hands a process EVERY key in
    the store, which makes enumeration the normal thing an app does and leaves
    no record of what it actually needed. `request` names what it wants, gets
    only that, and leaves a receipt.

    The distinction is not cosmetic. With no broker running, both read the same
    file and this grants no less than `apply` does. With one running, this call
    goes through it — recorded, and held to the app's policy — while `apply`
    still helps itself. That is why the shape matters: the upgrade is a running
    process, not a rewrite of every call site.

    Missing keys are simply absent from the result; asking is not an error.
    """
    wanted = [str(key).strip() for key in keys if str(key).strip()]
    source = os.environ if environ is None else environ

    # A broker, when one is running, is the whole point of asking rather than
    # helping yourself: it records the request and holds the app to its policy.
    # `stores` means the caller named its own files — a test, a sandbox, a second
    # instance — and reaching a real broker from there would be exactly the leak
    # that parameter exists to prevent.
    if stores is None and not source.get("HIVE_ENV_FILES"):
        # Send which workspace is asking. A key can be scoped to the workspace
        # it came from, and that has to be judged by the caller's workspace —
        # the broker is a daemon with a workspace of its own, and letting it
        # answer for itself would grant or refuse on the wrong question.
        try:
            asking = workspace_id or workspace(source)
        except ValueError:
            asking = workspace_id
        brokered = _ask_broker(wanted, app=app, reason=reason, workspace_id=asking)
        if brokered is not None:
            return brokered

    available: dict[str, str] = {}
    # `stores` lets the hosting app name exactly which files count — its own
    # override, its own test isolation. Without it, the scope rule applies.
    for store in (Path(item).expanduser() for item in stores) if stores is not None else _scoped_paths(source):
        available.update(_read(store))
    available.update({key: value for key, value in source.items() if value})

    granted = {key: available[key] for key in wanted if available.get(key)}
    missing = [key for key in wanted if key not in granted]
    if record is None:
        record = _RECORDER
    if record is not None:
        # Names only — there is no parameter here that could carry a value.
        record(op="read", keys=wanted, granted=not missing, reason=reason)
    return granted


def _ask_broker(
    wanted: list[str], *, app: str, reason: str, workspace_id: str,
) -> dict[str, str] | None:
    """Route through the broker if there is one. None means there is not.

    The broker is optional and absent by default, so every failure here — not
    installed, not running, socket gone mid-call — has to fall through to the
    files rather than deny. A broker that could take the machine down by
    stopping would not survive first contact with a real week.
    """
    try:
        import passbook_broker
    except ImportError:
        return None
    try:
        return passbook_broker.request_through_broker(
            wanted, app=app, reason=reason, workspace_id=workspace_id)
    except Exception:  # noqa: BLE001 — never fail a read because the broker misbehaved
        return None


_RECORDER: Callable[..., None] | None = None


def set_recorder(record: Callable[..., None] | None) -> None:
    """Install the access recorder every `request` reports to.

    Left unset, nothing is written and the standard behaves exactly as before —
    stamping is opt-in, so a project can take the store without taking a ledger.
    """
    global _RECORDER
    _RECORDER = record


def reveal(key: str, *, app: str = "passbook", reason: str = "") -> str:
    """One value, for its owner, on purpose — and recorded as such.

    Every other surface in this standard returns names. This is the single
    exception, and it exists because a credential manager that cannot show you
    your own credential is not one: you keep keys in order to paste them
    somewhere eventually.

    It is deliberately its own function rather than a flag on `status()` or
    `load()`, so that "does this code path return secrets?" stays answerable by
    reading the call, and it stamps a distinct `reveal` op so a person looking
    at their own key is legible in the record as exactly that — not confused
    with an app consuming it.

    It is not policy-gated. Refusing to show an owner their own key would be
    theatre: they can read the file. Recording it is the honest control.
    """
    name = str(key).strip()
    if not name:
        return ""
    values = {}
    for store in _scoped_paths():
        values.update(_read(store))
    found = values.get(name, "")
    if not found and _sealed_on_disk(name):
        # The value is there, encrypted, and this process holds no key. The
        # broker does, so ask it rather than telling the owner their key is
        # missing when it is merely shut.
        found = _ask_broker([name], app=app, reason=reason or "shown to the owner",
                            workspace_id="") or {}
        found = found.get(name, "")
    if _RECORDER is not None:
        _RECORDER(op="reveal", keys=[name], granted=bool(found), reason=reason or "shown to the owner")
    else:
        try:
            import passbook_stamp

            passbook_stamp.stamp(op="reveal", keys=[name], app=app, granted=bool(found),
                                 reason=reason or "shown to the owner")
        except Exception:  # noqa: BLE001 — a receipt must never fail the read
            pass
    return found


def _sealed_on_disk(name: str) -> bool:
    """Is this key present in the store but encrypted? Names only, no opening."""
    for store in _scoped_paths():
        try:
            raw = parse_env_text(Path(store).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if str(raw.get(name, "")).startswith("hive-sealed:"):
            return True
    return False


def key_names(environ: Mapping[str, str] | None = None) -> list[str]:
    """The keys this scope holds. Names only — values never leave.

    Reads the file without opening anything, so a sealed store still lists what
    it holds. That is the whole reason names are left in the clear: a locked
    machine should say "these keys are here, shut" rather than "no keys", which
    would send someone off to re-paste credentials they already have.
    """
    seen: set[str] = set()
    for store in _scoped_paths(environ):
        try:
            seen.update(parse_env_text(Path(store).read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return sorted(seen)


# ── writing ────────────────────────────────────────────────────────────────


def duplicate_keys(path: Path | str | None = None, environ: Mapping[str, str] | None = None) -> dict[str, list[int]]:
    """Key names that appear on more than one line, and where.

    A duplicate is worse than untidy. `parse_env_text` takes the last line, and
    so does every conforming reader — but a tool that regexes the file for one
    name takes the FIRST match, and the two then disagree about the same key.
    One appeared here for real: a writer that could not open a sealed store
    appended rather than replaced, and a boot hook went on reading the stale
    line above.
    """
    target = Path(path).expanduser() if path is not None else env_path(environ)
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return {}
    seen: dict[str, list[int]] = {}
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if _KEY.match(key):
            seen.setdefault(key, []).append(number)
    return {key: where for key, where in seen.items() if len(where) > 1}


def drop_duplicate_lines(path: Path | str | None = None, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Keep the last line for each key and remove the earlier ones.

    The last line is what every conforming reader already used, so this changes
    no value — it only stops a first-match reader seeing something different.
    """
    target = Path(path).expanduser() if path is not None else env_path(environ)
    duplicates = duplicate_keys(target)
    if not duplicates:
        return {"path": str(target), "removed": {}, "detail": "No duplicate keys."}
    doomed = {line for where in duplicates.values() for line in where[:-1]}
    lines = target.read_text(encoding="utf-8").splitlines()
    kept = [raw for number, raw in enumerate(lines, start=1) if number not in doomed]
    before = parse_env_text("\n".join(lines))
    after = parse_env_text("\n".join(kept))
    if before != after:
        # Refuse rather than change a value while claiming to tidy the file.
        raise ValueError("removing the earlier lines would change a value; nothing was written")
    _atomic_write(target, "\n".join(kept) + "\n")
    _tighten(target, 0o600)
    return {"path": str(target),
            "removed": {key: where[:-1] for key, where in duplicates.items()},
            "detail": f"Removed {len(doomed)} shadowed line(s) for {len(duplicates)} key(s)."}


def _key_names_on_disk(path: Path) -> set[str]:
    """Every key name the file holds, opened or not."""
    try:
        return set(parse_env_text(Path(path).read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError):
        return set()


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _tighten(path.parent, ROOT_MODE)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".hive-env-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, FILE_MODE)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _tighten(path: Path, mode: int) -> None:
    """Narrow permissions to `mode`, never widen them."""
    try:
        current = path.stat().st_mode & 0o777
        if current & ~mode:
            path.chmod(current & mode)
    except OSError:
        pass


def set_values(
    values: Mapping[str, str],
    *,
    overwrite: bool = False,
    workspace_id: str = "",
    environ: Mapping[str, str] | None = None,
    exact: bool = False,
) -> dict[str, Any]:
    """Add credentials to the store this scope writes to, preserving the rest.

    An existing key is kept unless `overwrite=True`; the file's comments,
    ordering and unrelated keys survive. Returns key NAMES by outcome, and the
    `path` written — worth surfacing, because "which store did that land in"
    is the question a workspace makes ambiguous.

    Values are trimmed, because the usual caller is a person pasting a key and
    a stray newline is not part of it. `exact=True` turns that off for callers
    that are moving a value rather than setting one — decrypting a store back
    to plaintext must return exactly what was encrypted, including whitespace
    somebody may have put there on purpose.
    """
    reason = container_home_reason(environ)
    if reason:
        raise ContainerisedHomeError(
            f"Refusing to write the hive env: {reason}. "
            f"Set {ROOT_ENV_VAR} to the real store, or ship the app unsandboxed."
        )
    for key in values:
        if not _KEY.match(key):
            raise ValueError(f"{key!r} is not a valid environment key")

    path = target_path(workspace_id, environ)
    existing = _read(path)
    # Whether a key is already in the file is a question about NAMES, and
    # `_read` answers with values — dropping any it cannot open. A process
    # writing to a sealed store it cannot read therefore saw every sealed key as
    # absent and APPENDED a second line for it, leaving the sealed one orphaned
    # above. `parse_env_text` takes the last line so PassBook still read the new
    # value, but a consumer that regexes the file takes the FIRST match and read
    # the stale sealed one instead. Two readers, two answers, from one file.
    present = _key_names_on_disk(path)
    added, updated, kept = [], [], []
    for key, value in values.items():
        text = str(value) if exact else str(value).strip()
        if not text.strip():
            continue
        if key not in present:
            added.append(key)
        elif overwrite and existing.get(key) != text:
            updated.append(key)
        else:
            kept.append(key)

    if not added and not updated:
        return {"path": str(path), "added": [], "updated": [], "kept": sorted(kept)}

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        lines = [
            "# Hive Env — the shared credential store for this machine.",
            f"# One store, every app. Spec v{SPEC_VERSION}.",
            "# Values are secret; key names are not. Mode 0600.",
        ]

    def _text(key: str) -> str:
        raw = str(values[key])
        return raw if exact else raw.strip()

    replacing = {key: _text(key) for key in updated}
    rewritten: list[str] = []
    for raw_line in lines:
        stripped = raw_line.strip()
        body = stripped[len("export ") :].strip() if stripped.startswith("export ") else stripped
        key = body.split("=", 1)[0].strip() if "=" in body else ""
        if key in replacing:
            rewritten.append(_format_line(key, replacing.pop(key)))
        else:
            rewritten.append(raw_line)
    for key, value in replacing.items():
        rewritten.append(_format_line(key, value))
    for key in added:
        rewritten.append(_format_line(key, _text(key)))

    _atomic_write(path, "\n".join(rewritten).rstrip("\n") + "\n")
    return {"path": str(path), "added": sorted(added), "updated": sorted(updated), "kept": sorted(kept)}


def remove_values(
    keys: Iterable[str],
    *,
    workspace_id: str = "",
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Delete keys from the canonical store. Returns key NAMES by outcome.

    Removal is the one operation that can break another app on this machine, so
    it is deliberately not part of `set_values` and never happens implicitly.
    Comments, ordering and unrelated keys survive; a key that was not there is
    reported as absent rather than raised, because "make sure this is gone" is
    the usual intent and it already is.
    """
    reason = container_home_reason(environ)
    if reason:
        raise ContainerisedHomeError(
            f"Refusing to write the hive env: {reason}. "
            f"Set {ROOT_ENV_VAR} to the real store, or ship the app unsandboxed."
        )

    path = target_path(workspace_id, environ)
    wanted = {str(key).strip() for key in keys if str(key).strip()}
    existing = _read(path)
    removed = sorted(wanted & set(existing))
    absent = sorted(wanted - set(existing))
    if not removed:
        return {"path": str(path), "removed": [], "absent": absent}

    kept_lines: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        body = stripped[len("export ") :].strip() if stripped.startswith("export ") else stripped
        key = body.split("=", 1)[0].strip() if "=" in body and not stripped.startswith("#") else ""
        if key and key in wanted:
            continue
        kept_lines.append(raw_line)
    _atomic_write(path, "\n".join(kept_lines).rstrip("\n") + "\n")
    return {"path": str(path), "removed": removed, "absent": absent}


# ── participation ──────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_apps(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    apps = payload.get("apps") if isinstance(payload, dict) else None
    return [item for item in apps or [] if isinstance(item, dict) and item.get("id")]


def link(app: str, *, name: str = "", environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Record that `app` uses this store. A registry, never a lock.

    Failing to register is never worth failing a launch over, so a read-only or
    unwritable root is reported rather than raised.
    """
    identifier = str(app).strip()
    if not identifier:
        raise ValueError("An app id is required to link to the hive env")
    path = apps_path(environ)
    apps = _read_apps(path)
    now = _now()
    for entry in apps:
        if entry.get("id") == identifier:
            entry["last_seen"] = now
            if name:
                entry["name"] = name
            break
    else:
        apps.append({"id": identifier, "name": name or identifier, "first_seen": now, "last_seen": now})
    try:
        _atomic_write(path, json.dumps({"version": SPEC_VERSION, "apps": apps}, indent=2) + "\n")
    except OSError as exc:
        return {"linked": False, "reason": str(exc), "apps": [entry["id"] for entry in apps]}
    return {"linked": True, "apps": [entry["id"] for entry in apps]}


def participants(environ: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    return _read_apps(apps_path(environ))


# ── the one call an app makes at startup ───────────────────────────────────


def ensure(
    *,
    app: str,
    name: str = "",
    seed: Mapping[str, str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Join the machine's hive env, creating the canonical store if absent.

    Idempotent and convergent: the first app to call this creates
    `~/.hivemindos/.env`, and every app after it — including the HivemindOS
    desktop app — finds that same file and adopts it. No app ever gets a private
    store, so there is never anything to merge.

    `seed` is for values the app already holds and would otherwise keep to
    itself; existing keys are never overwritten.
    """
    reason = container_home_reason(environ)
    if reason:
        return {
            "ok": False,
            "provisioned": False,
            "linked": False,
            "path": str(env_path(environ)),
            "reason": reason,
            "remedy": (
                f"Set {ROOT_ENV_VAR} to the real store (for example ~/.hivemindos), or ship "
                "this app without the App Sandbox so it can reach the shared credential store."
            ),
        }

    path = env_path(environ)
    existed = path.is_file()
    if not existed:
        _atomic_write(
            path,
            "\n".join(
                [
                    "# Hive Env — the shared credential store for this machine.",
                    "# Created by: " + (name or app),
                    "#",
                    "# Every HivemindOS-compatible app reads this one file, so a key added",
                    "# here is available to all of them. Installing another app links it to",
                    f"# this store rather than creating another. Spec v{SPEC_VERSION}.",
                    "#",
                    "# KEY=value, one per line. Values are secret; key names are not.",
                    "",
                ]
            ),
        )
    if seed:
        set_values(seed, environ=environ)
    registry = link(app, name=name, environ=environ)
    _tighten(root(environ), ROOT_MODE)
    _tighten(path, FILE_MODE)
    return {
        "ok": True,
        "provisioned": not existed,
        "adopted": existed,
        "linked": bool(registry.get("linked")),
        "path": str(path),
        "keys": key_names(environ),
        "apps": registry.get("apps", []),
    }



def status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Everything a diagnostic needs, and no secrets.

    Safe to print, log, or return over an API: key names only.
    """
    path = env_path(environ)
    reason = container_home_reason(environ)
    active = workspace(environ)
    return {
        "spec_version": SPEC_VERSION,
        "root": str(root(environ)),
        "path": str(path),
        "workspace": active,
        "workspaces": workspaces(environ),
        "stores": [str(item) for item in _scoped_paths(environ)],
        "inherits_machine_store": (not active) or workspace_inherits(active, environ),
        "exists": path.is_file(),
        "writes_to": str(target_path("", environ)),
        "keys": key_names(environ) if path.is_file() else [],
        "apps": [entry.get("id") for entry in participants(environ)],
        "home_is_container": bool(reason),
        "detail": reason or ("Shared hive env is in place." if path.is_file() else "No shared hive env on this machine yet."),
    }


def describe(environ: Mapping[str, str] | None = None) -> str:
    """One line for a doctor or a first-run screen."""
    state = status(environ)
    if state["home_is_container"]:
        return f"hive env unreachable — {state['detail']}"
    if not state["exists"]:
        return f"no hive env yet at {state['path']}"
    apps = ", ".join(state["apps"]) or "no apps registered"
    return f"{len(state['keys'])} keys at {state['path']} ({apps})"
