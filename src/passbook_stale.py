# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""No stale copy of a replaced key is left in an env file on this machine.

Liam, 2026-11-25, after the Ami rotation: "when a key is updated in passbook it must propagate. period... users
shouldn't have a stale issue." The keys were rotated and pushed to every target PassBook knew. A second checkout,
`~/ami-stream-build/.env.local`, was never attached, so all 26 rotated values stayed stale there and another
machine's agent hit 401 on the dead OpenRouter key.

So copies are found by VALUE, never by name. A name scan of one machine found 35 same-name mismatches, nearly
all files that rightly hold a different key under the same name (the Ami `.env.local`'s ELEVENLABS_API_KEY is
the store's AMI_ELEVENLABS_API_KEY, not its ELEVENLABS_API_KEY). Instead:

- **Every value replaced is remembered as a salted hash, never the value** (`retired.json` beside the store,
  owner-only, never synced). However a value changes (`rotate`, `add --replace`, a pull from another machine, a
  write by hand), the next look notices: each key's last value hash is kept, and a different one retires it.
  A value too short to be told from ordinary settings ("true", a port) is never retired.
- **A sweep** reads every env-like file (`.env`, `.env.*`, `.dev.vars`, and any added by hand) under the home
  folder and on every attached env-file target, and hashes each line's value. A line holding a retired value
  gets the key's current value in place: only the value changes (quotes, `export`, comments and line endings
  stay), the file keeps its permissions, its previous version is kept owner-only beside the store for 30 days,
  and the file is attached as an env-file target so the next rotation pushes there directly.
- **Never rewritten:** a backup or snapshot (`*.bak*`, `state-snapshots`, `*.tmp.*`) is reported, as is a value
  some key still holds (a copy is not stale while any key uses it), and a line whose new value would need
  quoting the file's own style cannot give.
- **Each machine sweeps itself**: on `rotate` and `add --replace` (which is how another machine's push lands on a
  sealed store), after a `sync` pull that changed anything, and once a day from the same `sync` maintenance pass
  the collectors run every ten minutes. Nothing about a value is sent anywhere.

Reports name a file and a variable, never a value.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

FILE = "retired.json"
BACKUPS = "stale-backups"
LOCK = "stale.lock"
VERSION = 1
MIN_LENGTH = 16
BACKUP_DAYS = 30
FULL_EVERY = 86400
#: PassBook's own records live in the store as keys; they are bookkeeping, not credentials.
RECORDS = {"PASSBOOK_SERVICE_BINDINGS", "PASSBOOK_USED_IN"}
#: Folders never walked: dependencies, the system's own, history and trash, and anything that is an app.
SKIP_DIRS = {"node_modules", "Library", ".git", ".Trash", ".venv", "venv", "site-packages", "__pycache__"}
#: Copies kept on purpose. Reported, never rewritten.
SNAPSHOT_PATTERNS = ("*.bak*", "state-snapshots", "*.tmp.*", "*.orig", "*~")


# ── the record ──────────────────────────────────────────────────────────────


def root() -> Path:
    import passbook

    return Path(passbook.root())


def path(where: Path | None = None) -> Path:
    return Path(where or root()) / FILE


def read(where: Path | None = None) -> dict[str, Any]:
    try:
        data = json.loads(path(where).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {"version": VERSION, "salt": str(data.get("salt") or ""),
            "seen": data.get("seen") if isinstance(data.get("seen"), dict) else {},
            "retired": data.get("retired") if isinstance(data.get("retired"), dict) else {},
            "files": data.get("files") if isinstance(data.get("files"), list) else [],
            "extra": data.get("extra") if isinstance(data.get("extra"), list) else [],
            "lastFull": float(data.get("lastFull") or 0), "lastSweep": float(data.get("lastSweep") or 0)}


def write(record: Mapping[str, Any], where: Path | None = None) -> None:
    target = path(where)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(f".{os.getpid()}.tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(dict(record), handle, indent=1, sort_keys=True)
    os.replace(temporary, target)


def _salt(record: dict) -> bytes:
    if not record.get("salt"):
        record["salt"] = secrets.token_hex(32)
    return bytes.fromhex(record["salt"])


def mark(record: dict, value: str) -> str:
    """The salted hash a value is remembered by. Never reversible to the value for a real key."""
    return hmac.new(_salt(record), value.encode("utf-8"), hashlib.sha256).hexdigest()[:40]


def retirable(value: str) -> bool:
    """Long enough to be a credential and not a setting: a copy of "true" or "8080" is not a stale key."""
    text = str(value or "")
    return (len(text) >= MIN_LENGTH and not text.startswith("hive-sealed:") and not text.isdigit()
            and not any(ch in text for ch in "\n\r"))


def _raw_mark(record: dict, stored: str) -> str:
    return mark(record, "raw\0" + str(stored))


def changed(record: dict, raw: Mapping[str, str]) -> list[str]:
    """Keys whose stored text is not what was last noticed: the only ones that need opening."""
    seen = record["seen"]
    return sorted(key for key, stored in raw.items() if (seen.get(key) or {}).get("r") != _raw_mark(record, stored))


def notice(record: dict, values: Mapping[str, str], raw: Mapping[str, str], *, now: float | None = None) -> list[str]:
    """Remember each opened key's value hash. A key whose value is not the one last noticed retires that one.
    Returns the keys that retired a value. A value that is current again (a rollback) stops being retired."""
    when = time.time() if now is None else now
    gone: list[str] = []
    for key, value in values.items():
        if not value or str(value).startswith("hive-sealed:") or key not in raw or key in RECORDS:
            continue
        current = mark(record, value) if retirable(value) else ""
        before = (record["seen"].get(key) or {}).get("h") or ""
        if before and before != current:
            record["retired"][before] = {"key": key, "at": when}
            gone.append(key)
        record["seen"][key] = {"r": _raw_mark(record, raw[key]), "h": current}
    held = {item.get("h") for item in record["seen"].values() if item.get("h")}
    for hashed in [hashed for hashed in record["retired"] if hashed in held]:
        record["retired"].pop(hashed)
    return gone


def retire(record: dict, key: str, value: str, *, now: float | None = None) -> bool:
    """Retire one value directly (a rotation's previous value, known before it is replaced)."""
    if not retirable(value):
        return False
    hashed = mark(record, value)
    if hashed in {item.get("h") for name, item in record["seen"].items() if name != key}:
        return False  # another key still holds it: not stale
    record["retired"][hashed] = {"key": key, "at": time.time() if now is None else now}
    return True


# ── finding copies ──────────────────────────────────────────────────────────


def env_like(name: str) -> bool:
    if name.endswith((".json", ".lock", ".lockb")):
        return False
    return name in (".env", ".dev.vars") or name.startswith((".env.", ".dev.vars."))


def is_snapshot(file: Path) -> bool:
    return any(fnmatch.fnmatch(part, pattern) for part in file.parts for pattern in SNAPSHOT_PATTERNS)


def roots() -> list[Path]:
    given = os.environ.get("PASSBOOK_STALE_ROOTS", "").strip()
    if given:
        return [Path(part).expanduser() for part in given.split(os.pathsep) if part.strip()]
    return [Path.home()]


def _never_touched() -> set[str]:
    """The store's own files and PassBook's backups."""
    import passbook

    out = {str(Path(root()) / BACKUPS)}
    try:
        for workspace in passbook.workspaces():
            out.add(os.path.realpath(passbook.target_path(workspace)))
        out.update(os.path.realpath(item) for item in passbook._scoped_paths())
        out.add(os.path.realpath(passbook.env_path()))
    except Exception:  # noqa: BLE001
        pass
    return out


def discover(where: Iterable[Path] | None = None) -> tuple[list[str], list[str]]:
    """Every env-like file under the roots, and the folders that could not be read (never "clean")."""
    found: list[str] = []
    unreadable: list[str] = []
    skip = _never_touched()
    for start in (list(where) if where is not None else roots()):
        for folder, dirs, files in os.walk(start, onerror=lambda error: unreadable.append(str(getattr(error, "filename", "")))):
            dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not name.endswith(".app")
                       and not os.path.islink(os.path.join(folder, name))
                       and not os.path.exists(os.path.join(folder, name, "pyvenv.cfg"))
                       and os.path.join(folder, name) not in skip]
            for name in files:
                full = os.path.join(folder, name)
                if env_like(name) and os.path.realpath(full) not in skip:
                    found.append(full)
    return sorted(set(found)), sorted(set(item for item in unreadable if item))


def attached_files() -> list[str]:
    """Files the env-file targets already push to: their own `path`, or a path in a recorded command."""
    try:
        import passbook_services as services

        registry = services.read()
    except Exception:  # noqa: BLE001
        return []
    out = []
    for items in registry.get("bindings", {}).values():
        for item in items:
            if item.get("path"):
                out.append(str(item["path"]))
            elif str(item.get("service", "")).startswith("env-file:"):
                out.extend(token for token in str(item.get("command", "")).split()
                           if token.startswith("/") and env_like(os.path.basename(token)))
    return sorted(set(out))


_ASSIGN = re.compile(r"^(?P<lead>\s*(?:export\s+)?)(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)(?P<eq>\s*=\s*)(?P<rest>.*)$")


def split_value(rest: str) -> tuple[str, str, str, str] | None:
    """(quote, value, closing quote, the rest of the line after the value) or None if unreadable."""
    if rest[:1] in ("'", '"'):
        quote = rest[0]
        end = rest.find(quote, 1)
        if end < 0:
            return None
        return quote, rest[1:end], quote, rest[end + 1:]
    found = re.search(r"\s+#", rest)
    value = rest[:found.start()] if found else rest
    stripped = value.rstrip()
    return "", stripped, "", value[len(stripped):] + (rest[found.start():] if found else "")


def _requote(quote: str, value: str) -> tuple[str, str] | None:
    """How the new value can be written in the old one's place, or None when it cannot without changing
    what the line means."""
    if "\n" in value or "\r" in value:
        return None
    if quote == "'":
        return ("'", "'") if "'" not in value else None
    if quote == '"':
        return ('"', '"') if not any(ch in value for ch in '"\\$`') else None
    if not value or any(ch in value for ch in " \t#'\"\\$`"):
        return ('"', '"') if not any(ch in value for ch in '"\\$`') and value else None
    return "", ""


def scan(file: str, record: dict) -> list[dict]:
    """The lines of FILE whose value is a retired one: their line number, variable and the key retired."""
    try:
        text = Path(file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    retired = record["retired"]
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        matched = _ASSIGN.match(line)
        if not matched or line.lstrip().startswith("#"):
            continue
        split = split_value(matched.group("rest"))
        if not split or not retirable(split[1]):
            continue
        hashed = mark(record, split[1])
        if hashed in retired:
            hits.append({"line": number, "var": matched.group("name"), "key": retired[hashed]["key"]})
    return hits


def _rewrite(file: str, hits: list[dict], current: Mapping[str, str], record: dict) -> tuple[list[dict], list[dict]]:
    """Put each hit's current value in place, keeping everything else byte for byte. Returns (done, not)."""
    real = os.path.realpath(file)
    data = Path(real).read_bytes()
    lines = data.decode("utf-8").splitlines(keepends=True)
    done, refused = [], []
    for hit in hits:
        new = current.get(hit["key"]) or ""
        line = lines[hit["line"] - 1]
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        matched = _ASSIGN.match(body)
        split = split_value(matched.group("rest")) if matched else None
        if not new or new.startswith("hive-sealed:") or not split or mark(record, split[1]) not in record["retired"]:
            refused.append({**hit, "why": "the new value could not be opened here"})
            continue
        quotes = _requote(split[0], new)
        if quotes is None:
            refused.append({**hit, "why": "the new value needs quoting this line cannot take; change it by hand"})
            continue
        lines[hit["line"] - 1] = (f"{matched.group('lead')}{matched.group('name')}{matched.group('eq')}"
                                  f"{quotes[0]}{new}{quotes[1]}{split[3]}{ending}")
        done.append(hit)
    if done:
        mode = os.stat(real).st_mode & 0o7777
        temporary = f"{real}.passbook-{os.getpid()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write("".join(lines).encode("utf-8"))
        os.chmod(temporary, mode)
        try:
            stat = os.stat(real)
            os.chown(temporary, stat.st_uid, stat.st_gid)
        except (OSError, AttributeError):
            pass
        os.replace(temporary, real)
    return done, refused


def backup(file: str, *, now: float | None = None) -> str:
    """The file as it was, owner-only, beside the store; kept BACKUP_DAYS days. It holds other live values
    too, so it is never under the home folder's own files, never swept and never synced."""
    when = time.time() if now is None else now
    folder = Path(root()) / BACKUPS / time.strftime("%Y%m%dT%H%M%S", time.gmtime(when))
    folder.mkdir(parents=True, exist_ok=True)
    for made in (folder.parent, folder):
        os.chmod(made, 0o700)
    tag = hashlib.sha256(os.path.realpath(file).encode("utf-8")).hexdigest()[:10]
    target = folder / f"{tag}-{os.path.basename(file)}"
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(Path(os.path.realpath(file)).read_bytes())
    return str(target)


def prune_backups(*, now: float | None = None) -> None:
    folder = Path(root()) / BACKUPS
    oldest = (time.time() if now is None else now) - BACKUP_DAYS * 86400
    for item in folder.glob("*") if folder.exists() else []:
        try:
            if item.is_dir() and item.stat().st_mtime < oldest:
                shutil.rmtree(item)
        except OSError:
            pass


def display(file: str) -> str:
    home = str(Path.home())
    real = os.path.realpath(file)
    return ("~" + real[len(home):]) if real.startswith(home + os.sep) else real


def attach(file: str, var: str, key: str) -> str | None:
    """Make FILE an env-file target of KEY, unless a target already writes there. Returns the service name."""
    import passbook_services as services

    real = os.path.realpath(file)
    registry = services.read()
    for item in services.bindings(key, registry):
        if item.get("path") == real and item.get("var") == var:
            return None
        command = str(item.get("command", ""))
        if real in command and var in command.split():
            return None
    shown = display(real).lstrip("~").lstrip(os.sep)
    service = re.sub(r"[^A-Za-z0-9 ._:/@+-]", "_", f"env-file:{shown}:{var}")[:96]
    import shlex

    command = " ".join(shlex.quote(part) for part in ("passbook", "sink", "env-file", real, var))
    registry = services.attach(key, service, command, registry=registry, source="stale sweep",
                               extra={"kind": "env-file", "path": real, "var": var})
    registry = services.record(key, service, ok=True, registry=registry)
    services.write(registry)
    return service


def sweep(record: dict, current: Mapping[str, str], *, files: Iterable[str], fix: bool,
          now: float | None = None) -> list[dict]:
    """Every copy of a retired value in FILES, fixed when `fix`. Each item: file (as shown), var, key, and
    what happened: fixed, snapshot (never rewritten), refused (with why), found (not fixing). A value some key
    still holds is never retired (`notice`), so it never matches."""
    report: list[dict] = []
    seen_real: set[str] = set()
    for file in files:
        real = os.path.realpath(file)
        if real in seen_real or not os.path.isfile(real):
            continue
        seen_real.add(real)
        hits = scan(real, record)
        if not hits:
            continue
        shown = display(file)
        if is_snapshot(Path(file)) or is_snapshot(Path(real)):
            report.extend({**hit, "file": shown, "status": "snapshot"} for hit in hits)
            continue
        if not fix:
            report.extend({**hit, "file": shown, "status": "found"} for hit in hits)
            continue
        if not os.access(real, os.W_OK):
            report.extend({**hit, "file": shown, "status": "refused", "why": "the file is not writable"} for hit in hits)
            continue
        kept = backup(real, now=now)
        try:
            done, refused = _rewrite(real, hits, current, record)
        except (OSError, UnicodeDecodeError) as error:
            report.extend({**hit, "file": shown, "status": "refused", "why": str(error)[:120]} for hit in hits)
            continue
        if not done:
            Path(kept).unlink(missing_ok=True)
        for hit in done:
            service = None
            try:
                service = attach(real, hit["var"], hit["key"])
            except Exception:  # noqa: BLE001 — the file is fixed; the target is the extra
                pass
            report.append({**hit, "file": shown, "status": "fixed", "backup": kept, "attached": service})
        report.extend({**hit, "file": shown, "status": "refused"} for hit in refused)
    return report


def holders(keys_retired: Mapping[str, float]) -> list[dict]:
    """Running processes the broker handed a retired key to before it was replaced: they still hold the old
    value. PassBook has no way to restart them, so they are named for the owner."""
    try:
        import passbook_broker

        if not passbook_broker.running():
            return []
        answer = passbook_broker._ask({"op": "grants"}) or {}
    except Exception:  # noqa: BLE001
        return []
    out = []
    now = time.time()
    for row in answer.get("grants") or []:
        started = now - float(row.get("age_seconds") or 0)
        stale = sorted(key for key in row.get("keys") or [] if key in keys_retired and started < keys_retired[key])
        if stale:
            out.append({"app": row.get("app") or "?", "pid": row.get("pid"), "keys": stale,
                        "command": " ".join(row.get("command") or [])[:80]})
    return out


def due(record: Mapping[str, Any], *, now: float | None = None) -> bool:
    return (time.time() if now is None else now) - float(record.get("lastFull") or 0) >= FULL_EVERY


def off() -> bool:
    return os.environ.get("PASSBOOK_STALE", "").strip().lower() in ("off", "0", "no")


def set_var(file: str, var: str, value: str, *, now: float | None = None) -> str:
    """Write VAR=value into an env file in place: the first assignment of VAR gets the value (its quoting,
    `export` and comment kept), or a line is added at the end. The file keeps its permissions and its previous
    version is backed up as a sweep's is. Returns "updated", "added" or "unchanged"."""
    real = os.path.realpath(file)
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*$", var or ""):
        raise ValueError(f"{var!r} is not a variable name.")
    if not os.path.exists(real):
        raise FileNotFoundError(f"{display(real)} does not exist.")
    lines = Path(real).read_bytes().decode("utf-8").splitlines(keepends=True)
    result = "added"
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        matched = _ASSIGN.match(body)
        if not matched or matched.group("name") != var or body.lstrip().startswith("#"):
            continue
        split = split_value(matched.group("rest"))
        if split and split[1] == value:
            return "unchanged"
        quotes = _requote(split[0] if split else "", value)
        if not split or quotes is None:
            raise ValueError(f"{var} in {display(real)} cannot take this value without changing its quoting.")
        lines[index] = (f"{matched.group('lead')}{var}{matched.group('eq')}{quotes[0]}{value}{quotes[1]}"
                        f"{split[3]}{line[len(body):]}")
        result = "updated"
        break
    else:
        quotes = _requote("", value)
        if quotes is None:
            raise ValueError(f"This value cannot be written into {display(real)} as one line.")
        ending = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += ending
        lines.append(f"{var}={quotes[0]}{value}{quotes[1]}{ending}")
    backup(real, now=now)
    mode = os.stat(real).st_mode & 0o7777
    temporary = f"{real}.passbook-{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write("".join(lines).encode("utf-8"))
    os.chmod(temporary, mode)
    os.replace(temporary, real)
    return result
