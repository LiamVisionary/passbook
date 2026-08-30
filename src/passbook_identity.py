# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What code is a command about to run, as a string that can be compared later.

Optional companion to `passbook_grant.py`.

## Why this is not "block unsigned programs"

The obvious feature is a switch that refuses to hand credentials to anything
without a signature. It was measured before it was built, and on a normal
developer machine it fails in both directions at once:

  * With a permissive requirement (`anchor apple generic`, which is what
    `passbook_peer` falls back to when no team is named), `/bin/sh`,
    `/usr/bin/python3` and every `node` all pass. Those are the three programs
    an attacker would reach for first, so the switch stops nothing that matters.

  * With a strict requirement naming one Developer ID team, the only things that
    pass are that vendor's own binaries — including a bundled `node`, which will
    happily run `node -e '<anything>'`. Meanwhile `/bin/sh` is refused, and so
    is PassBook's own interpreter: a uv-managed CPython is ad-hoc signed and
    carries no team at all.

So the strict setting refuses the tool doing the enforcing and admits the one
binary that grants arbitrary code execution. Neither end of that dial is worth
shipping.

The mistake is the question. A signature says *who compiled this*, which an
interpreter makes vacuous — the signature covers `node`, never the script. The
question worth asking is **is this the same code you approved**, and that has an
answer for interpreters too, because a script is a file with contents.

## What an identity is here

The strongest available statement about a file, and nothing stronger:

    signed:HX7739G8FX:node     a Developer ID team and the identifier it signed
    apple:com.apple.sh         shipped and signed by Apple itself
    sha256:1f3a…               no authority to lean on, so the bytes themselves

Authority first, because that is what should survive an upgrade. Pinning
`node` by content would break on every patch release and train its owner to
re-approve without looking, which is worse than not pinning it. Pinning it by
team keeps working across versions and still refuses a different vendor's
binary appearing under the same name.

Content for everything else, because an unsigned program has nobody to vouch
for it, and because a *script* has no signature to check however its interpreter
was signed. `node server.js` is identified as both: the interpreter by team, the
script by hash. That pair is the thing signatures could never express.

## The case with no answer

`node -e '…'`, `sh -c '…'`, a script arriving on stdin: the code is in the
argument list or the pipe, and there is no file to identify. This module says
`ambiguous` rather than falling back to the interpreter's identity, because
"signed:…:node" for an inline program would be a true statement that answers a
different question — the same overstatement this module exists to avoid.

What a caller does with `ambiguous` is a policy decision and lives in
`passbook_grant`. The rule there is the one `host_allowed` already uses: where
the identity cannot be seen, the default is closed.

## The window this does not close

The file is identified by path, and then `exec` re-opens that path. Between
those two moments it can be replaced. That window is real and is not closed
here.

It is worth being exact about what it costs, because `passbook_peer` warns
against exactly this pattern and is right to for the question *it* asks. Asking
"who is calling me" about an already-running process must go to the kernel; a
path lookup would describe a file rather than the caller. But "what am I about
to run" is a question about a file, because a file is what `exec` will read.

The honest limit is the threat model, not the race: a pin catches code that
*changed* — a dependency that took a compromised update and kept its access. It
does not stop somebody who can already write to that path at the instant we
look, and it is not offered as protection against them.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

__all__ = [
    "INTERPRETERS",
    "content_id",
    "is_interpreter",
    "describe",
    "identify",
    "program_id",
    "resolve",
    "signature",
]


# Programs whose identity says nothing about what they will do, because what
# they do arrives as an argument. The list decides whether we admit we cannot
# see the code — it is not a security boundary, and must not be read as one. A
# name missing from it means an interpreter gets pinned by its own identity
# alone, which is weaker than pinning its script and is recorded as such; it
# never means something is let through that would otherwise be refused.
INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh",
    "node", "nodejs", "deno", "bun", "ts-node", "tsx",
    "python", "python2", "python3", "pypy", "pypy3",
    "ruby", "perl", "perl5", "php", "lua", "luajit", "tclsh", "expect",
    "osascript", "awk", "gawk", "mawk", "Rscript", "julia",
    "pwsh", "powershell", "powershell.exe", "pwsh.exe", "cmd", "cmd.exe",
    "java", "scala", "groovy", "elixir", "erl",
    "env", "xargs", "nohup", "timeout", "stdbuf", "nice", "time",
})

# Flags after which the next argument — or the flag's own tail — is source code
# rather than a path. Consulted only when the program is already known to be an
# interpreter, so `tar -c` and `make -e` never reach this.
INLINE_FLAGS = frozenset({
    "-c", "-e", "--eval", "--command", "--execute", "-E", "--exec", "-Command",
})

# A single dash is stdin by near-universal convention.
STDIN_ARGS = frozenset({"-", "/dev/stdin"})


# Identifying a file means hashing it and, on macOS, forking `codesign`. Both
# are done once per (path, inode, size, mtime) for the life of the process. The
# cache key is deliberately not a security claim: anything able to rewrite a
# file while preserving all four could equally have rewritten it before we
# looked, which is the window the module docstring declines to claim it closes.
_CACHE: dict[tuple, dict[str, Any]] = {}


def _stat_key(path: Path) -> tuple | None:
    try:
        info = path.stat()
    except OSError:
        return None
    return (str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def content_id(path: str | Path) -> str:
    """`sha256:` and the file's digest, or "" if it cannot be read."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return f"sha256:{digest.hexdigest()}"
    except OSError:
        return ""


def signature(path: str | Path) -> dict[str, Any]:
    """Who signed this file, three-valued, never a bare bool.

        signed      a Developer ID team, named in `team`
        apple       Apple's own signing chain; no team exists to report
        unsigned    ad-hoc or absent — a signature nobody is accountable for
        unknown     this platform cannot answer

    Ad-hoc is `unsigned` on purpose. `codesign -v` passes on one, and minting
    one costs a single command with no account, no certificate and no review, so
    treating it as a signature would put a green tick on anything at all.
    """
    if sys.platform == "darwin":
        return _darwin_signature(path)
    if os.name == "nt":
        return _windows_signature(path)
    return {"status": "unknown", "team": "", "identifier": "", "authority": "",
            "reason": "code signatures are not a platform concept here"}


def _darwin_signature(path: str | Path) -> dict[str, Any]:
    try:
        done = subprocess.run(  # noqa: S603 — fixed argv, no shell
            ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
            capture_output=True, text=True, timeout=20, errors="replace")
    except (OSError, subprocess.SubprocessError) as error:
        return {"status": "unknown", "team": "", "identifier": "", "authority": "",
                "reason": f"could not ask codesign: {error}"}

    fields: dict[str, list[str]] = {}
    for line in (done.stderr or "").splitlines():
        name, sep, value = line.partition("=")
        if sep:
            fields.setdefault(name.strip(), []).append(value.strip())

    identifier = (fields.get("Identifier") or [""])[0]
    authorities = fields.get("Authority") or []
    team = (fields.get("TeamIdentifier") or [""])[0]
    if team.lower() in {"", "not set"}:
        team = ""

    # No authority line at all is the ad-hoc and unsigned case together: there
    # is a hash of the file and nobody standing behind it.
    if not authorities:
        return {"status": "unsigned", "team": "", "identifier": identifier, "authority": "",
                "reason": "ad-hoc or unsigned; no certificate chain"}
    if team:
        return {"status": "signed", "team": team, "identifier": identifier,
                "authority": authorities[0], "reason": f"signed by {authorities[0]}"}
    return {"status": "apple", "team": "", "identifier": identifier,
            "authority": authorities[0], "reason": f"signed by {authorities[0]}"}


def _windows_signature(path: str | Path) -> dict[str, Any]:
    """Authenticode, through PowerShell, because there is no smaller way in.

    Only a `Valid` status counts. Windows reports `UnknownError` for a signature
    whose root is not trusted here and `NotSigned` for the ordinary case, and
    folding either into "signed" would mean a chain this machine rejects still
    satisfying a pin.
    """
    script = (
        "$ErrorActionPreference='Stop';"
        f"$s=Get-AuthenticodeSignature -LiteralPath '{str(path)}';"
        "Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Subject)"
    )
    try:
        done = subprocess.run(  # noqa: S603 — fixed argv, no shell
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=30, errors="replace")
    except (OSError, subprocess.SubprocessError) as error:
        return {"status": "unknown", "team": "", "identifier": "", "authority": "",
                "reason": f"could not ask Authenticode: {error}"}

    status, _, subject = (done.stdout or "").strip().partition("|")
    if status != "Valid":
        return {"status": "unsigned", "team": "", "identifier": "", "authority": "",
                "reason": f"Authenticode says {status or 'nothing'}"}
    # The CN is the accountable name; the rest of the DN is address noise that
    # changes when a company moves office.
    common = subject
    for part in subject.split(","):
        if part.strip().upper().startswith("CN="):
            common = part.strip()[3:]
            break
    return {"status": "signed", "team": common, "identifier": Path(path).name,
            "authority": subject, "reason": f"Authenticode: {common}"}


def program_id(path: str | Path) -> dict[str, Any]:
    """The strongest available identity for one file, with how it was reached."""
    target = Path(path)
    key = _stat_key(target)
    if key is None:
        return {"id": "", "kind": "missing", "reason": f"no such file: {target}"}
    cached = _CACHE.get(key)
    if cached is not None:
        return dict(cached)

    signed = signature(target)
    if signed["status"] == "signed":
        answer = {"id": f"signed:{signed['team']}:{signed['identifier']}", "kind": "signed",
                  "authority": signed["authority"], "team": signed["team"],
                  "reason": signed["reason"]}
    elif signed["status"] == "apple":
        answer = {"id": f"apple:{signed['identifier']}", "kind": "apple",
                  "authority": signed["authority"], "team": "",
                  "reason": signed["reason"]}
    else:
        digest = content_id(target)
        if not digest:
            return {"id": "", "kind": "unreadable", "reason": f"could not read {target}"}
        answer = {"id": digest, "kind": "content", "authority": "", "team": "",
                  "reason": signed.get("reason") or "identified by contents"}

    _CACHE[key] = answer
    return dict(answer)


_VERSION_TAIL = re.compile(r"[0-9]+(?:\.[0-9]+)*$")


def is_interpreter(name: str) -> bool:
    """Whether this program's behaviour comes from an argument rather than itself.

    Version suffixes are stripped before the lookup. `python3` on this machine
    is a symlink to `python3.14`, and matching only the literal name meant a
    resolved interpreter stopped looking like one: a bare `python3` reading a
    script from stdin came back `identified`, pinned as though it were a fixed
    program. Anything this over-matches is merely treated with more caution,
    which is the safe direction for a list that decides what we admit we cannot
    see.
    """
    base = str(name).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base in INTERPRETERS or _VERSION_TAIL.sub("", base) in INTERPRETERS


def resolve(program: str, *, cwd: str = "", path: str = "") -> Path | None:
    """The file `exec` will actually open for this argv[0].

    `subprocess` resolves a bare name against the PATH of the environment it is
    *given*, not the one this process happens to have, so the caller passes the
    child's. Getting this wrong would identify one file and run another, which
    is a worse failure than not checking at all.
    """
    name = str(program)
    if not name:
        return None
    base = Path(cwd) if cwd else Path.cwd()
    if os.sep in name or (os.altsep and os.altsep in name):
        candidate = Path(name)
        candidate = candidate if candidate.is_absolute() else base / candidate
    else:
        found = shutil.which(name, path=path or os.environ.get("PATH"))
        if not found:
            return None
        candidate = Path(found)
    try:
        # Follow symlinks: `/usr/local/bin/node` pointing into a version manager
        # should be identified as the file that runs, not as the link.
        return candidate.resolve()
    except OSError:
        return candidate


def _script_argument(argv: Sequence[str], *, cwd: str) -> tuple[str, Path | None]:
    """For an interpreter, the file it will run — or why there isn't one.

    Returns `(verdict, path)` where verdict is "found", "inline" or "stdin".
    """
    base = Path(cwd) if cwd else Path.cwd()
    index = 1
    while index < len(argv):
        argument = str(argv[index])
        if argument in STDIN_ARGS:
            return "stdin", None
        if argument in INLINE_FLAGS:
            return "inline", None
        # `-e'code'` and `-c"code"` written without a space are the same thing.
        if any(argument.startswith(flag) and len(argument) > len(flag)
               for flag in INLINE_FLAGS):
            return "inline", None
        if argument.startswith("-"):
            index += 1
            continue
        candidate = Path(argument)
        candidate = candidate if candidate.is_absolute() else base / candidate
        if candidate.is_file():
            return "found", candidate
        # A non-flag that is not a file is a subcommand or a bare argument —
        # `npm run dev`, `python -m module`. Keep looking rather than deciding.
        index += 1
    return "stdin", None


def identify(command: Sequence[str], *, cwd: str = "", path: str = "") -> dict[str, Any]:
    """What this command will run, as a comparable set of identity strings.

        identified   every part that decides behaviour has an identity
        ambiguous    an interpreter with its code inline or on stdin
        unknown      the program could not be found or read

    `identities` is a set, not a sequence: a pin is satisfied when everything
    the command brings is already trusted, and the order argv happened to use
    is not part of that.
    """
    argv = [str(part) for part in command if str(part) != ""]
    if not argv:
        return {"status": "unknown", "identities": [], "program": "",
                "reason": "no command"}

    target = resolve(argv[0], cwd=cwd, path=path)
    if target is None:
        return {"status": "unknown", "identities": [], "program": argv[0],
                "reason": f"command not found: {argv[0]}"}

    found = program_id(target)
    if not found["id"]:
        return {"status": "unknown", "identities": [], "program": str(target),
                "reason": found["reason"]}

    record: dict[str, Any] = {
        "status": "identified",
        "program": str(target),
        "program_id": found["id"],
        "kind": found["kind"],
        "authority": found.get("authority", ""),
        "identities": [found["id"]],
        "script": "",
        "reason": found["reason"],
    }

    # Both names, because either can be the interpreter: `node` may resolve
    # into a version manager's directory, and `/usr/bin/python3` resolves to a
    # differently named real binary.
    if not (is_interpreter(target.name) or is_interpreter(Path(argv[0]).name)):
        return record

    verdict, script = _script_argument(argv, cwd=cwd)
    if verdict == "found" and script is not None:
        digest = content_id(script)
        if not digest:
            record["status"] = "unknown"
            record["reason"] = f"could not read {script}"
            return record
        record["script"] = str(script)
        record["identities"] = [found["id"], digest]
        record["script_id"] = digest
        record["reason"] = f"{found['reason']}, running {script.name}"
        return record

    # Emptied deliberately. A caller that checks `set(identities) <= pinned`
    # without reading `status` must refuse this, not admit it on the strength of
    # the interpreter alone — which is the exact overstatement this module is
    # written to avoid.
    record["identities"] = []
    record["status"] = "ambiguous"
    record["reason"] = (
        f"{target.name} was given its code "
        + ("on stdin" if verdict == "stdin" else "as an argument")
        + ", so there is no file to identify"
    )
    return record


def describe(record: Mapping[str, Any]) -> str:
    """One line for a record or a panel. Never overstates what was proven."""
    status = record.get("status")
    if status == "ambiguous":
        return f"cannot be identified — {record.get('reason', '')}"
    if status != "identified":
        return f"unidentified — {record.get('reason', 'unknown')}"
    where = Path(str(record.get("program") or "")).name
    if record.get("script"):
        return f"{where} running {Path(str(record['script'])).name} ({record.get('program_id')})"
    return f"{where} ({record.get('program_id')})"
