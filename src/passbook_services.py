"""Which services hold a key, and how it got there.

Replacing a credential in the store is half the job. The copies that already
live on a Worker, a VPS, a CI secret store or a hosting provider go on being the
old value until somebody pushes the new one to each of them by hand, and the
list of where those copies are lived in people's heads. A rotation is therefore
remembered as "done" while several services are still holding a dead key.

This keeps the list beside the key, with the exact command that put it there, so
replacing a value can offer to push it everywhere it already went.

## Why a store key and not a file

The record is itself a store key, `PASSBOOK_SERVICE_BINDINGS`, holding JSON.
The store already replicates between machines with last-writer-wins timestamps
and tombstones, and the key is not local-only, so the record reaches every
machine with no new wire and no collector change. A sidecar file beside
`.env.meta.json` would have needed the collector on every machine to learn a new
field first, and until the last one did, machines would silently disagree.

## Nothing here holds a secret

A binding is a service name and a command. The value reaches that command
through its ENVIRONMENT, and through stdin when the binding asks for it, never
on its argv where `ps` would show it to every process on the box. A command is
rejected outright if it looks like it is trying to interpolate the value itself.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Any, Iterable, Mapping

REGISTRY_KEY = "PASSBOOK_SERVICE_BINDINGS"
VERSION = 1
DEFAULT_TIMEOUT = 180.0

#: A service name is a label, not a path or a shell fragment.
SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
#: A store key, matching what `passbook add` accepts.
KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
#: A command that writes the value into itself would put the secret on a command
#: line. The value arrives in the environment; say `$KEY`, not the value.
INTERPOLATION = re.compile(r"\{\{\s*(?:value|secret)\s*\}\}|\$\{\s*PASSBOOK_VALUE\s*\}", re.I)

Binding = dict[str, Any]


class ServiceError(ValueError):
    """Something about a binding is wrong. The message is for a person."""


# ── the record ─────────────────────────────────────────────────────────────

def _blank() -> dict[str, Any]:
    return {"version": VERSION, "bindings": {}}


def parse(raw: str | None) -> dict[str, Any]:
    """The registry from its stored text. Unreadable text is an empty registry
    rather than an error: a corrupted record must not stop anyone adding a key."""
    if not raw:
        return _blank()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return _blank()
    if not isinstance(data, dict) or not isinstance(data.get("bindings"), dict):
        return _blank()
    clean: dict[str, list[Binding]] = {}
    for key, items in data["bindings"].items():
        if not isinstance(key, str) or not isinstance(items, list):
            continue
        kept = [item for item in items
                if isinstance(item, dict) and isinstance(item.get("service"), str)
                and isinstance(item.get("command"), str)]
        if kept:
            clean[key] = kept
    return {"version": VERSION, "bindings": clean}


def dump(registry: Mapping[str, Any]) -> str:
    """Stable ONE-LINE text.

    Stable so an unchanged registry does not look changed to sync and start
    pushing itself around the fleet for nothing. One line because the store is a
    `KEY=value` file: a pretty-printed blob ends at its first newline and the
    record comes back empty, which is exactly how this was first written.
    """
    bindings = {key: sorted(items, key=lambda item: str(item.get("service", "")))
                for key, items in sorted(registry.get("bindings", {}).items()) if items}
    return json.dumps({"version": VERSION, "bindings": bindings},
                      separators=(",", ":"), sort_keys=True)


def read(*, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    import passbook

    return parse(passbook.load(environ=environ).get(REGISTRY_KEY))


def write(registry: Mapping[str, Any], *, app: str = "passbook-services") -> None:
    import passbook

    passbook.set_values({REGISTRY_KEY: dump(registry)}, overwrite=True)
    del app  # recorded by the store itself; named here for callers' clarity


def bindings(key: str, registry: Mapping[str, Any] | None = None) -> list[Binding]:
    source = registry if registry is not None else read()
    return list(source.get("bindings", {}).get(key, []))


def keys_with_bindings(registry: Mapping[str, Any] | None = None) -> list[str]:
    source = registry if registry is not None else read()
    return sorted(key for key, items in source.get("bindings", {}).items() if items)


# ── changing it ────────────────────────────────────────────────────────────

def attach(key: str, service: str, command: str, *, stdin: bool = False, cwd: str = "",
           registry: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Record that `service` holds `key`, and how to put it there again.

    Replaces an existing binding with the same service name, so re-running this
    with a corrected command is the way to fix one rather than a second entry.
    """
    if not KEY.match(key or ""):
        raise ServiceError(f"{key!r} is not a key name.")
    if not SERVICE.match(service or ""):
        raise ServiceError("A service name is letters, digits, spaces, dot, dash or underscore.")
    command = (command or "").strip()
    if not command:
        raise ServiceError("Give the command that puts the key on that service.")
    if INTERPOLATION.search(command):
        raise ServiceError(
            "Do not interpolate the value into the command: it would be visible to `ps`. "
            f"The command runs with ${key} in its environment, and with --stdin it also "
            "receives the value on stdin.")
    working = parse(dump(registry if registry is not None else read()))
    items = [item for item in working["bindings"].get(key, [])
             if str(item.get("service")) != service]
    items.append({
        "service": service,
        "command": command,
        "stdin": bool(stdin),
        "cwd": str(cwd or ""),
        "addedAt": time.time(),
        "lastRunAt": 0.0,
        "lastStatus": "never",
        "lastError": "",
    })
    working["bindings"][key] = items
    return working


def detach(key: str, service: str, registry: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
    working = parse(dump(registry if registry is not None else read()))
    items = working["bindings"].get(key, [])
    kept = [item for item in items if str(item.get("service")) != service]
    if len(kept) == len(items):
        return working, False
    if kept:
        working["bindings"][key] = kept
    else:
        working["bindings"].pop(key, None)
    return working, True


def record(key: str, service: str, *, ok: bool, error: str = "",
           registry: Mapping[str, Any] | None = None, when: float | None = None) -> dict[str, Any]:
    """Stamp what happened, so a failure survives the run that caused it and can
    be retried tomorrow by somebody who was not watching."""
    working = parse(dump(registry if registry is not None else read()))
    for item in working["bindings"].get(key, []):
        if str(item.get("service")) == service:
            item["lastRunAt"] = time.time() if when is None else float(when)
            item["lastStatus"] = "ok" if ok else "failed"
            item["lastError"] = "" if ok else str(error)[:500]
    return working


def failures(registry: Mapping[str, Any] | None = None) -> list[tuple[str, Binding]]:
    """Every binding whose last push did not land, oldest failure first."""
    source = registry if registry is not None else read()
    out = [(key, item) for key, items in source.get("bindings", {}).items()
           for item in items if str(item.get("lastStatus")) == "failed"]
    out.sort(key=lambda pair: float(pair[1].get("lastRunAt") or 0))
    return out


# ── putting the value there ────────────────────────────────────────────────

def redact(text: str, value: str) -> str:
    """The value must not come back to us in a log line we then store or print."""
    if not value or len(value) < 6:
        return text
    return text.replace(value, "••••••")


def _detail(result: subprocess.CompletedProcess[str], value: str) -> str:
    """One readable line from whatever the command said, value removed."""
    for stream in (result.stderr, result.stdout):
        text = redact((stream or "").strip(), value)
        if text:
            last = [line for line in text.splitlines() if line.strip()]
            if last:
                return last[-1][:300]
    return f"exit status {result.returncode}"


def run_binding(key: str, value: str, binding: Mapping[str, Any], *,
                timeout: float = DEFAULT_TIMEOUT, runner=subprocess.run) -> tuple[bool, str]:
    """Put `value` on one service. Returns (landed, one line about it).

    The value goes in the environment as `key`, and on stdin when the binding
    asked for it — which is what `wrangler secret put` and friends read. It is
    never placed on the command line.
    """
    command = str(binding.get("command", ""))
    environment = dict(os.environ)
    environment[key] = value
    environment["PASSBOOK_KEY"] = key
    environment["PASSBOOK_SERVICE"] = str(binding.get("service", ""))
    cwd = str(binding.get("cwd") or "") or None
    try:
        result = runner(
            command, shell=True, env=environment, cwd=cwd,
            input=(value if binding.get("stdin") else ""),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {int(timeout)}s"
    except OSError as error:
        return False, redact(str(error), value)[:300]
    return (result.returncode == 0), _detail(result, value)


def update(key: str, value: str, chosen: Iterable[Mapping[str, Any]], *,
           timeout: float = DEFAULT_TIMEOUT, runner=subprocess.run,
           on_result=None) -> list[dict[str, Any]]:
    """Push `value` to each chosen service IN ORDER, and report each one.

    Sequential on purpose: these are writes to other people's systems, and a
    parallel fan-out makes a partial failure much harder to reason about. One
    service failing never stops the rest — the whole point is to get as many
    onto the new value as possible and leave a list of the ones that did not.
    """
    results: list[dict[str, Any]] = []
    for binding in chosen:
        service = str(binding.get("service", ""))
        ok, detail = run_binding(key, value, binding, timeout=timeout, runner=runner)
        entry = {"service": service, "ok": ok, "detail": detail}
        results.append(entry)
        if on_result:
            on_result(entry)
    return results


def select(items: list[Binding], choice: str) -> list[Binding]:
    """The bindings a person picked, from `1,3` or `all` or a service name.

    Out-of-range numbers and unknown names raise rather than being skipped: a
    typo that silently pushed to fewer services than intended would leave the
    rotation half done and look like it had finished.
    """
    text = (choice or "").strip()
    if not text or text.lower() in {"all", "*"}:
        return list(items)
    picked: list[Binding] = []
    for part in re.split(r"[,\s]+", text):
        if not part:
            continue
        if part.isdigit():
            index = int(part)
            if not 1 <= index <= len(items):
                raise ServiceError(f"There is no service {index}; pick between 1 and {len(items)}.")
            candidate = items[index - 1]
        else:
            matches = [item for item in items if str(item.get("service")) == part]
            if not matches:
                raise ServiceError(f"No service here is called {part!r}.")
            candidate = matches[0]
        if candidate not in picked:
            picked.append(candidate)
    if not picked:
        raise ServiceError("Nothing was picked.")
    return picked
