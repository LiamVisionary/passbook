# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Where a key was just sent, worked out from the command that sent it.

`passbook services` has been able to push a replaced key to every service that
holds it since it was written, and on the machine it was written for it held
nothing: the only way in was `passbook services attach KEY SERVICE --command
'…'`, typed by hand, after the fact, by somebody who remembered. Nobody did.
The keys were going to Workers and CI secrets through `passbook run` the whole
time, so the information was passing through PassBook and being thrown away.

This reads the command a `run` is about to start and says which of its keys it
is putting where, so the run can write that down once the command succeeds. It
also turns a short sink spec (`wrangler:my-worker`, `gh:owner/repo`) into the
same thing, for `passbook push`.

## Recognise, never guess

Only shapes that unambiguously put a named secret on a named service are
recognised: `wrangler secret put`, `gh secret set`, `vercel env add`, `fly
secrets set` and a handful more, directly or inside `sh -c '…'`. When it is not
clear which of the run's keys went there, nothing is recorded and the run says
so — a wrong record is worse than none, because rotating would then push a
key to a service that never held it.

## The command that is recorded is not the command that ran

What is kept is a command that does the same push again with the value on
stdin (or in `$KEY`), never on the command line. A person who ran
`gh secret set X --body "$X"` put the value in their argv, where `ps` shows it;
the rotation that replays it later should not. Every part taken from the
original command is shell-quoted, so a worker called `$(rm -rf ~)` is a name,
not an instruction.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: A component of a sink spec or of a recognised command: a worker, a repo, an
#: app, a store id, a secret name. Deliberately narrow; everything is quoted as
#: well, but a spec is typed by a person and this catches the typo early.
PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}$")
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
#: How a JS tool is started without being installed. Kept so the recorded push
#: starts wrangler the same way the person did, from the same directory.
LAUNCHERS = (("npx", "--yes"), ("npx", "-y"), ("npx",), ("pnpm", "exec"), ("pnpm", "dlx"),
             ("pnpx",), ("bunx",), ("bun", "x"), ("yarn", "dlx"), ("yarn",), ("npm", "exec", "--"))

CF_API = "https://api.cloudflare.com/client/v4"
CF_TOKEN_KEY = "CLOUDFLARE_API_TOKEN"
CF_ACCOUNT_KEY = "CLOUDFLARE_ACCOUNT_ID"

Sink = dict  # {key, kind, service, command, stdin, cwd, secretName, nonSecret, warning}


class SinkError(ValueError):
    """A sink spec that cannot be read. The message is for a person."""


def _q(parts: Iterable[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def _sink(key: str, kind: str, service: str, command: str, *, stdin: bool = True,
          cwd: str = "", secret_name: str = "", non_secret: bool = False,
          warning: str = "") -> Sink:
    return {"key": key, "kind": kind, "service": service[:96], "command": command,
            "stdin": stdin, "cwd": cwd, "secretName": secret_name or key,
            "nonSecret": non_secret, "warning": warning}


def binding_fields(sink: Mapping[str, Any]) -> dict[str, Any]:
    """The extra fields a recorded binding carries, beyond service and command."""
    return {"kind": sink.get("kind", "custom"), "secretName": sink.get("secretName", ""),
            "nonSecret": bool(sink.get("nonSecret"))}


# ── labels ──────────────────────────────────────────────────────────────────

def _label(prefix: str, target: str, secret_name: str, key: str) -> str:
    """`worker:api`, or `worker:api/OTHER_NAME` when it is stored under a
    different name there. One key can go to one place under two names."""
    label = f"{prefix}:{target}"
    if secret_name and secret_name != key:
        label += f"/{secret_name}"
    return label


# ── configuration the command did not spell out ─────────────────────────────

def _wrangler_name(cwd: str, config: str = "") -> str:
    """The worker a bare `wrangler secret put` would target, from its config."""
    base = Path(cwd or ".")
    candidates = [base / config] if config else [
        base / "wrangler.toml", base / "wrangler.jsonc", base / "wrangler.json"]
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if path.suffix == ".toml":
            for line in text.splitlines():
                if line.strip().startswith("["):
                    break  # only the top-level name is the worker's
                found = re.match(r"\s*name\s*=\s*[\"']([^\"']+)[\"']", line)
                if found:
                    return found.group(1)
        else:
            found = re.search(r"\"name\"\s*:\s*\"([^\"]+)\"", text)
            if found:
                return found.group(1)
    return ""


def _fly_app(cwd: str, config: str = "") -> str:
    path = Path(cwd or ".") / (config or "fly.toml")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    found = re.search(r"^\s*app\s*=\s*[\"']([^\"']+)[\"']", text, re.M)
    return found.group(1) if found else ""


def _git_repo(cwd: str) -> str:
    """owner/repo from the origin remote, which is what `gh` would use."""
    try:
        url = subprocess.run(["git", "-C", cwd or ".", "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    found = re.search(r"github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?/?$", url)
    return found.group(1) if found else ""


def _tool(*names: str) -> list[str]:
    """How to start a tool here: itself if installed, else through npx."""
    for name in names:
        if shutil.which(name):
            return [name]
    return ["npx", names[0]] if names[0] == "wrangler" else [names[0]]


# ── argv parsing ────────────────────────────────────────────────────────────

def _options(args: Sequence[str], valued: set[str]) -> tuple[list[str], dict[str, str], set[str]]:
    """Positionals, `--flag value` options, and bare flags, in one pass."""
    positional: list[str] = []
    options: dict[str, str] = {}
    flags: set[str] = set()
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positional.extend(args[index + 1:])
            break
        if token.startswith("-") and len(token) > 1:
            name, eq, value = token.partition("=")
            if eq:
                options[name] = value
            elif name in valued and index + 1 < len(args):
                options[name] = args[index + 1]
                index += 1
            else:
                flags.add(name)
        else:
            positional.append(token)
        index += 1
    return positional, options, flags


def _opt(options: Mapping[str, str], *names: str) -> str:
    for name in names:
        if options.get(name):
            return options[name]
    return ""


def _strip_launcher(argv: list[str]) -> tuple[list[str], list[str]]:
    """(launcher, the tool's own argv): `npx wrangler secret put X` → (["npx"], [...])."""
    for launcher in LAUNCHERS:
        size = len(launcher)
        if tuple(argv[:size]) == launcher and len(argv) > size:
            return list(launcher), argv[size:]
    return [], argv


def _strip_prefixes(argv: list[str]) -> list[str]:
    """`env A=b`, `exec`, `command`, and leading `VAR=value` assignments."""
    out = list(argv)
    while out:
        head = out[0]
        if head in {"exec", "command", "time", "nohup"}:
            out = out[1:]
        elif head == "env":
            out = out[1:]
            while out and ("=" in out[0] or out[0].startswith("-")):
                out = out[1:]
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head):
            out = out[1:]
        else:
            break
    return out


def _segments(script: str) -> list[tuple[list[str], str]]:
    """A shell script as simple commands, each with the text of its pipeline.

    Good enough for the one-liners people wrap in `sh -c`; anything it cannot
    split is simply not recognised, which is the safe direction.
    """
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    pipelines: list[list[list[str]]] = [[[]]]
    for token in tokens:
        if token == "|":
            pipelines[-1].append([])
        elif token in {";", "&&", "||", "&", "\n"} or set(token) <= set(";&|"):
            pipelines.append([[]])
        else:
            pipelines[-1][-1].append(token)
    out = []
    for pipeline in pipelines:
        text = " ".join(" ".join(part) for part in pipeline)
        for command in pipeline:
            if command:
                out.append((command, text))
    return out


def _referenced(text: str, keys: Iterable[str]) -> list[str]:
    return [key for key in keys if re.search(r"\$\{?" + re.escape(key) + r"\b", text)]


# ── recognising one command ────────────────────────────────────────────────

def _which_key(dest: str, keys: Sequence[str], context: str, *, direct: bool) -> str:
    """Which of the run's keys went to `dest`. "" when it cannot be told.

    With no keys at all (a run without `--only`) the answer is the destination
    name, so the caller can still say where the command put something.
    """
    if not keys:
        return dest
    if dest in keys:
        return dest
    mentioned = _referenced(context, keys)
    if len(mentioned) == 1:
        return mentioned[0]
    if direct and len(keys) == 1:
        return keys[0]
    return ""


def _recognise(argv: list[str], keys: Sequence[str], cwd: str, context: str,
               direct: bool) -> tuple[list[Sink], list[str]]:
    argv = _strip_prefixes(argv)
    launcher, tool_argv = _strip_launcher(argv)
    if not tool_argv:
        return [], []
    tool = Path(tool_argv[0]).name
    rest = tool_argv[1:]
    if tool == "wrangler":
        return _wrangler(launcher + [tool_argv[0]], rest, keys, cwd, context, direct)
    if tool == "gh":
        return _gh(rest, keys, cwd, context, direct)
    if tool == "vercel":
        return _vercel(launcher + [tool_argv[0]], rest, keys, cwd, context, direct)
    if tool in {"fly", "flyctl"}:
        return _fly(tool_argv[0], rest, keys, cwd, context, direct)
    if tool in {"passbook", "passbook-sink"}:
        positional, options, _ = _options(rest, {"--account-key", "--token-key", "--scopes"})
        if positional[:2] == ["sink", "cf-secrets-store"] and len(positional) >= 4:
            return _cf_store(positional[2], positional[3], keys, context, direct)
    return [], []


def _unmapped(dest: str, where: str) -> str:
    return (f"{dest} went to {where}, but not which of this run's keys it was. "
            f"Nothing was recorded; say it with --used-in \"{where}\".")


def _wrangler(prefix: list[str], rest: list[str], keys, cwd, context, direct):
    valued = {"--name", "--env", "-e", "--config", "-c", "--cwd", "--project-name",
              "--project", "--scopes", "--comment", "--secret-id", "--value", "--branch"}
    positional, options, _ = _options(rest, valued)
    config = _opt(options, "--config", "-c")
    run_in = _opt(options, "--cwd") or cwd
    env = _opt(options, "--env", "-e")
    tail = (["--env", env] if env else []) + (["--config", config] if config else [])

    def worker_sinks(names: list[str], versions: bool) -> tuple[list[Sink], list[str]]:
        worker = _opt(options, "--name") or _wrangler_name(run_in, config)
        target = (worker or Path(run_in).name) + (f"@{env}" if env else "")
        sinks, notes = [], []
        for dest in names:
            key = _which_key(dest, keys, context, direct=direct)
            if not key:
                notes.append(_unmapped(dest, f"worker:{target}"))
                continue
            verb = ["versions", "secret", "put"] if versions else ["secret", "put"]
            command = _q(prefix + verb + [dest] + (["--name", worker] if worker else []) + tail)
            sinks.append(_sink(key, "wrangler-secret", _label("worker", target, dest, key),
                               command, cwd=run_in, secret_name=dest))
        return sinks, notes

    if positional[:2] == ["secret", "put"] and len(positional) >= 3:
        return worker_sinks([positional[2]], False)
    if positional[:3] == ["versions", "secret", "put"] and len(positional) >= 4:
        return worker_sinks([positional[3]], True)
    if positional[:2] == ["secret", "bulk"]:
        # A bulk upload names its secrets inside a JSON file or stdin, not on
        # the command line. The keys this run holds and mentions are the ones
        # it could have put there; each is recorded as its own `secret put`,
        # which is the same push one key at a time.
        mentioned = _referenced(context, keys) or (list(keys) if direct else [])
        if not mentioned:
            return [], [_unmapped("a bulk upload", "a worker")]
        return worker_sinks(mentioned, False)
    if positional[:3] == ["pages", "secret", "put"] and len(positional) >= 4:
        dest = positional[3]
        project = _opt(options, "--project-name", "--project")
        key = _which_key(dest, keys, context, direct=direct)
        target = project or Path(run_in).name
        if not key:
            return [], [_unmapped(dest, f"pages:{target}")]
        command = _q(prefix + ["pages", "secret", "put", dest]
                     + (["--project-name", project] if project else []) + tail)
        return [_sink(key, "wrangler-pages-secret", _label("pages", target, dest, key),
                      command, cwd=run_in, secret_name=dest)], []
    if positional[:3] == ["secrets-store", "secret", "create"] and len(positional) >= 4:
        dest = _opt(options, "--name")
        if not dest:
            return [], []
        return _cf_store(positional[3], dest, keys, context, direct,
                         scopes=_opt(options, "--scopes") or "workers")
    return [], []


def _gh(rest, keys, cwd, context, direct):
    valued = {"--repo", "-R", "--env", "-e", "--org", "-o", "--app", "-a", "--body", "-b",
              "--visibility", "-v", "--repos", "-r", "--env-file", "-f"}
    positional, options, flags = _options(rest, valued)
    if len(positional) < 3 or positional[0] not in {"secret", "variable"} or positional[1] != "set":
        return [], []
    if _opt(options, "--env-file", "-f"):
        return [], ["gh read its names from an env file, so which key went where is not "
                    "on the command line. Nothing was recorded; use --used-in."]
    variable = positional[0] == "variable"
    dest = positional[2]
    key = _which_key(dest, keys, context, direct=direct)
    repo = _opt(options, "--repo", "-R")
    org = _opt(options, "--org", "-o")
    env = _opt(options, "--env", "-e")
    user = "--user" in flags or "-u" in flags
    if not repo and not org and not user:
        repo = _git_repo(cwd)
    prefix = "github-var" if variable else ("github-org" if org else "github-user" if user else "github")
    target = (org or ("me" if user else (repo or Path(cwd).name))) + (f"@{env}" if env else "")
    if not key:
        return [], [_unmapped(dest, f"{prefix}:{target}")]
    parts = ["gh", positional[0], "set", dest]
    if repo:
        parts += ["--repo", repo]
    if org:
        parts += ["--org", org]
        visibility = _opt(options, "--visibility", "-v")
        if visibility:
            parts += ["--visibility", visibility]
        repos = _opt(options, "--repos", "-r")
        if repos:
            parts += ["--repos", repos]
    if user:
        parts += ["--user"]
    if env:
        parts += ["--env", env]
    app = _opt(options, "--app", "-a")
    if app and not variable:
        parts += ["--app", app]
    warning = ""
    if _opt(options, "--body", "-b"):
        warning = ("the value went on the command line (--body), where other processes can "
                   "see it; the recorded push sends it on stdin instead")
    if variable:
        warning = (warning + "; " if warning else "") + (
            "a GitHub variable is not secret: anyone who can read the repository can read it")
    return [_sink(key, "gh-variable" if variable else "gh-secret",
                  _label(prefix, target, dest, key), _q(parts), cwd=cwd, secret_name=dest,
                  non_secret=variable, warning=warning)], []


def _vercel(prefix, rest, keys, cwd, context, direct):
    valued = {"--scope", "-S", "--cwd", "--token", "-t", "--value", "-A", "--local-config",
              "-Q", "--global-config"}
    positional, options, flags = _options(rest, valued)
    if positional[:2] != ["env", "add"] or len(positional) < 3:
        return [], []
    dest = positional[2]
    environments = positional[3:5]
    run_in = _opt(options, "--cwd") or cwd
    key = _which_key(dest, keys, context, direct=direct)
    target = Path(run_in).name + (f"@{environments[0]}" if environments else "")
    if not key:
        return [], [_unmapped(dest, f"vercel:{target}")]
    parts = prefix + ["env", "add", dest, *environments, "--force"]
    scope = _opt(options, "--scope", "-S")
    if scope:
        parts += ["--scope", scope]
    for flag in ("--sensitive", "--no-sensitive"):
        if flag in flags:
            parts.append(flag)
    warning = ("the value went on the command line (--value); the recorded push sends it on "
               "stdin instead") if _opt(options, "--value") else ""
    return [_sink(key, "vercel-env", _label("vercel", target, dest, key), _q(parts),
                  cwd=run_in, secret_name=dest, warning=warning)], []


def _fly_push(binary: str, dest: str, key: str, app: str, config: str) -> str:
    # `fly secrets set NAME=value` puts the value on the command line. `import`
    # reads NAME=value lines from stdin; printf is a shell builtin, so the value
    # never becomes anybody's argv.
    target = (["--app", app] if app else []) + (["--config", config] if config else [])
    return f"printf '%s=%s\\n' {shlex.quote(dest)} \"${key}\" | {_q([binary, 'secrets', 'import', *target])}"


def _fly(binary, rest, keys, cwd, context, direct):
    positional, options, _ = _options(rest, {"--app", "-a", "--config", "-c"})
    if positional[:1] != ["secrets"] or len(positional) < 2:
        return [], []
    config = _opt(options, "--config", "-c")
    app = _opt(options, "--app", "-a") or _fly_app(cwd, config)
    target = app or Path(cwd).name
    sinks, notes = [], []
    if positional[1] == "set":
        for pair in positional[2:]:
            dest, eq, value = pair.partition("=")
            if not eq or not NAME.match(dest):
                continue
            key = _which_key(dest, keys, value, direct=False) or (
                dest if dest in keys else "")
            if not key:
                notes.append(_unmapped(dest, f"fly:{target}"))
                continue
            sinks.append(_sink(key, "fly-secret", _label("fly", target, dest, key),
                               _fly_push(binary, dest, key, app, config), stdin=False,
                               cwd=cwd, secret_name=dest,
                               warning="the value went on the command line; the recorded "
                                       "push sends it through stdin instead"))
    elif positional[1] == "import":
        mentioned = _referenced(context, keys) or (list(keys) if direct and len(keys) == 1 else [])
        if not mentioned:
            notes.append(_unmapped("an import", f"fly:{target}"))
        for key in mentioned:
            sinks.append(_sink(key, "fly-secret", _label("fly", target, key, key),
                               _fly_push(binary, key, key, app, config), stdin=False,
                               cwd=cwd, secret_name=key))
    return sinks, notes


def _cf_store(store: str, dest: str, keys, context, direct, scopes: str = "workers"):
    if not PART.match(store) or not PART.match(dest):
        return [], []
    key = _which_key(dest, keys, context, direct=direct)
    target = f"{store}/{dest}"
    if not key:
        return [], [_unmapped(dest, f"cf-secrets-store:{target}")]
    return [_sink(key, "cf-secrets-store", f"cf-secrets-store:{target}"[:96],
                  cf_store_command(store, dest, scopes=scopes), stdin=False,
                  secret_name=dest)], []


def cf_store_command(store: str, dest: str, *, scopes: str = "workers") -> str:
    """The push for a Secrets Store secret, through `passbook sink`.

    Wrapped in `passbook run --only` for the account's own token and id, so the
    push works on a sealed store where this process cannot read them itself.
    The value to push arrives as `$KEY`, named by `$PASSBOOK_KEY`.
    """
    inner = ["passbook", "sink", "cf-secrets-store", store, dest]
    if scopes and scopes != "workers":
        inner += ["--scopes", scopes]
    return _q(["passbook", "run", "--only", CF_TOKEN_KEY, "--only", CF_ACCOUNT_KEY, "--", *inner])


# ── the public entry points ────────────────────────────────────────────────

def detect(command: Sequence[str], keys: Sequence[str], *, cwd: str = "") -> tuple[list[Sink], list[str]]:
    """The sinks `command` pushes `keys` to, and notes on what could not be told.

    `keys` is what the run hands over (`--only`). An empty list still finds
    sinks, with `key` left empty, so a caller can say "name the key and this
    would have been recorded".
    """
    argv = [str(part) for part in command]
    cwd = cwd or os.getcwd()
    keys = [key for key in keys if key]
    probe = keys
    head = _strip_prefixes(argv)
    candidates: list[tuple[list[str], str, bool]] = []
    if head and Path(head[0]).name in SHELLS:
        script = ""
        for index, token in enumerate(head[1:], start=1):
            if token.startswith("-") and "c" in token.lstrip("-") and not token.startswith("--"):
                script = head[index + 1] if index + 1 < len(head) else ""
                break
        for segment, pipeline in _segments(script):
            candidates.append((segment, pipeline, False))
    else:
        candidates.append((argv, " ".join(argv), True))

    sinks: list[Sink] = []
    notes: list[str] = []
    for segment, context, direct in candidates:
        found, said = _recognise(segment, probe, cwd, context, direct)
        sinks.extend(found)
        notes.extend(said)
    if not keys:
        for sink in sinks:
            sink["key"] = ""
        notes = []
    seen: set[tuple[str, str]] = set()
    unique = []
    for sink in sinks:
        marker = (sink["key"], sink["service"])
        if marker not in seen:
            seen.add(marker)
            unique.append(sink)
    return unique, notes


SPEC_HELP = """\
  wrangler:WORKER[:NAME]              a Worker secret (wrangler secret put)
  wrangler-pages:PROJECT[:NAME]       a Pages secret
  gh:OWNER/REPO[:NAME]                a GitHub Actions secret
  gh-env:OWNER/REPO:ENV[:NAME]        ... for one deployment environment
  gh-org:ORG[:NAME]                   an organisation secret
  gh-var:OWNER/REPO[:NAME]            a GitHub variable (not secret)
  vercel:ENVIRONMENT[:NAME]           a Vercel env var, for the project in this directory
  fly:APP[:NAME]                      a Fly.io secret
  cf-secrets-store:STORE_ID[:NAME]    a Cloudflare Secrets Store secret
NAME defaults to the key's own name."""


def parse_spec(spec: str, key: str, *, cwd: str = "") -> Sink:
    """`wrangler:my-worker` → the sink `passbook push KEY --to` pushes to."""
    cwd = cwd or os.getcwd()
    kind, _, rest = str(spec or "").partition(":")
    parts = [part for part in rest.split(":")] if rest else []
    if not kind or not parts or not all(PART.match(part) for part in parts):
        raise SinkError(f"Cannot read the sink {spec!r}. One of:\n{SPEC_HELP}")

    def name_at(index: int) -> str:
        dest = parts[index] if len(parts) > index else key
        if not NAME.match(dest):
            raise SinkError(f"{dest!r} is not a secret name.")
        return dest

    def exactly(most: int) -> None:
        if len(parts) > most:
            raise SinkError(f"Too many parts in {spec!r}. One of:\n{SPEC_HELP}")

    if kind == "wrangler":
        exactly(2)
        worker, dest = parts[0], name_at(1)
        return _sink(key, "wrangler-secret", _label("worker", worker, dest, key),
                     _q(_tool("wrangler") + ["secret", "put", dest, "--name", worker]),
                     cwd=cwd, secret_name=dest)
    if kind == "wrangler-pages":
        exactly(2)
        project, dest = parts[0], name_at(1)
        return _sink(key, "wrangler-pages-secret", _label("pages", project, dest, key),
                     _q(_tool("wrangler") + ["pages", "secret", "put", dest,
                                             "--project-name", project]),
                     cwd=cwd, secret_name=dest)
    if kind in {"gh", "gh-var"}:
        exactly(2)
        repo, dest = parts[0], name_at(1)
        if repo.count("/") != 1:
            raise SinkError(f"{kind}: needs OWNER/REPO, not {repo!r}.")
        variable = kind == "gh-var"
        sink = _sink(key, "gh-variable" if variable else "gh-secret",
                     _label("github-var" if variable else "github", repo, dest, key),
                     _q(["gh", "variable" if variable else "secret", "set", dest, "--repo", repo]),
                     cwd=cwd, secret_name=dest, non_secret=variable)
        if variable:
            sink["warning"] = "a GitHub variable is not secret: anyone who can read the repository can read it"
        return sink
    if kind == "gh-env":
        exactly(3)
        if len(parts) < 2:
            raise SinkError("gh-env: needs OWNER/REPO:ENVIRONMENT.")
        repo, env, dest = parts[0], parts[1], name_at(2)
        return _sink(key, "gh-secret", _label("github", f"{repo}@{env}", dest, key),
                     _q(["gh", "secret", "set", dest, "--repo", repo, "--env", env]),
                     cwd=cwd, secret_name=dest)
    if kind == "gh-org":
        exactly(2)
        org, dest = parts[0], name_at(1)
        return _sink(key, "gh-secret", _label("github-org", org, dest, key),
                     _q(["gh", "secret", "set", dest, "--org", org]), cwd=cwd, secret_name=dest)
    if kind == "vercel":
        exactly(2)
        env, dest = parts[0], name_at(1)
        return _sink(key, "vercel-env", _label("vercel", f"{Path(cwd).name}@{env}", dest, key),
                     _q(["vercel", "env", "add", dest, env, "--force"]), cwd=cwd, secret_name=dest)
    if kind == "fly":
        exactly(2)
        app, dest = parts[0], name_at(1)
        binary = "fly" if shutil.which("fly") or not shutil.which("flyctl") else "flyctl"
        return _sink(key, "fly-secret", _label("fly", app, dest, key),
                     _fly_push(binary, dest, key, app, ""), stdin=False, cwd=cwd, secret_name=dest)
    if kind == "cf-secrets-store":
        exactly(2)
        store, dest = parts[0], name_at(1)
        return _sink(key, "cf-secrets-store", f"cf-secrets-store:{store}/{dest}"[:96],
                     cf_store_command(store, dest), stdin=False, secret_name=dest)
    raise SinkError(f"Unknown sink {kind!r}. One of:\n{SPEC_HELP}")


# ── Cloudflare Secrets Store, which has no put-by-name command ─────────────

def _cf_call(method: str, url: str, token: str, body: Any = None, *, opener=None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "User-Agent": "passbook"})
    try:
        with (opener or urllib.request.urlopen)(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as error:
        try:
            return json.loads(error.read().decode("utf-8") or "{}")
        except (ValueError, OSError):
            return {"success": False, "errors": [{"message": f"HTTP {error.code}"}]}


def _cf_error(answer: Mapping[str, Any]) -> str:
    errors = answer.get("errors") or []
    messages = [str(item.get("message", "")) for item in errors if isinstance(item, dict)]
    return "; ".join(message for message in messages if message) or "Cloudflare refused it"


def cf_store_put(store: str, name: str, value: str, *, account: str, token: str,
                 scopes: Sequence[str] = ("workers",), opener=None) -> tuple[bool, str]:
    """Create or replace one Secrets Store secret by NAME. (landed, one line).

    The API edits a secret by id, and wrangler's `update` needs that id too, so
    a push by name has to look it up first: list the store, PATCH the match,
    or create it when there is none.
    """
    base = f"{CF_API}/accounts/{account}/secrets_store/stores/{store}/secrets"
    found = ""
    page = 1
    while not found:
        listing = _cf_call("GET", f"{base}?per_page=100&page={page}", token, opener=opener)
        if not listing.get("success"):
            return False, _cf_error(listing)
        for item in listing.get("result") or []:
            if isinstance(item, dict) and item.get("name") == name:
                found = str(item.get("id") or "")
                break
        info = listing.get("result_info") or {}
        if found or page >= int(info.get("total_pages") or 1):
            break
        page += 1
    if found:
        answer = _cf_call("PATCH", f"{base}/{found}", token, {"value": value}, opener=opener)
        return (bool(answer.get("success")), "updated" if answer.get("success") else _cf_error(answer))
    answer = _cf_call("POST", base, token, [{"name": name, "value": value, "scopes": list(scopes),
                                             "comment": "set by passbook"}], opener=opener)
    return (bool(answer.get("success")), "created" if answer.get("success") else _cf_error(answer))
