# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook grants — using a credential without ever seeing it.

Optional companion to `passbook_broker.py`. Everything else in this project
answers the question "may this caller *have* this value?". This module answers a
different one: "may this caller cause this value to be *used*?" — and then does
the using itself, so the answer never has to travel.

## The problem this exists for

An agent is a process that turns text into actions and writes everything it
learns into a transcript. That transcript is persisted, replayed, and sent to a
model. So the moment a credential reaches an agent, it has reached a log file
and a network service, whatever the agent intended.

`passbook get` and the MCP `get_credential` tool both hand a value to exactly
that kind of caller. Gating them with a policy does not fix it: an approved read
still lands the plaintext in the transcript. `ask` converts a silent leak into
an approved one.

The fix is not a better lock on the value. It is to stop moving the value.

## The rule

**Values flow only into processes the broker started itself.**

The broker resolves the keys, forks the child holding them, and hands the caller
back streams and an exit code. Nothing in the reply contains a credential. A
process the broker did not start cannot obtain one at all — which is the agent's
own shell, and is the whole point.

Provenance, not identity, is what carries this. Identity cannot: a script, a CLI
and an agent are all run by the same interpreter and present the same signature,
as `passbook_peer` explains at length. But "did this process descend from a
spawn I performed, holding a key set I chose?" is a question with an exact
answer, and it is the one that matters.

## Why redaction is part of the guarantee, not a nicety

The caller chooses the command. So the caller can choose `printenv`, and the
guarantee would last exactly as long as it took somebody to notice. Because the
broker knows precisely which values it injected, it can remove them from
anything it streams back, and it does. `printenv` returns `[redacted:NAME]`.

That closes the return path. It does not close the *outbound* one — a command is
free to send what it was given anywhere it likes, and no amount of scrubbing our
own stdout changes that. Which is why:

## Guarded keys

A key can be bound to the commands that may receive it and the hosts it may be
sent to. For a bound key, `wrangler deploy` works and `curl evil.example` does
not, because the binding is policy written by the owner and the caller cannot
edit it.

Binding is opt-in per key, and that is a deliberate trade rather than laziness.
Requiring it everywhere would mean 300 policy lines before anything ran, which
is how a security feature gets switched off wholesale. Unbound keys still get
the large win — no plaintext in a transcript, every use recorded — and the
handful that move money get the strict one. `passbook guard` is how a key is
promoted, and `guarded()` is what reports which are.

## What this still does not buy

The broker and the caller share a uid. A caller determined to write custom code
can attach a debugger to the broker or to the child it spawned, and read the
value out of memory. Closing *that* needs a privilege boundary — the broker
under its own service account, the data key bound in the keychain to signed
callers — and that is an installation-shaped project, not a module.

So this raises the cost of reading a credential from "type one command" to
"write a debugger harness, against a process that is recording you". It does not
make it impossible, and nothing that runs as the same user could.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "GRANT_ENV",
    "MIN_REDACTABLE",
    "REDACTION",
    "commands_for",
    "destinations_for",
    "guarded",
    "host_allowed",
    "command_allowed",
    "proxy",
    "redact",
    "redactions_for",
    "spawn",
    "stream",
    "Scrubber",
]

# The marker a spawned child carries. Its presence tells `passbook.request` that
# this process was born holding what it needs and must not ask the broker again
# — the broker would refuse it, correctly, for not being a grant-backed caller.
GRANT_ENV = "PASSBOOK_GRANT"

REDACTION = "[redacted:{name}]"

# Below this length, a value is not distinctive enough to search for. Redacting
# "1" or "true" would replace half of every line of output with a marker and
# teach everyone to turn redaction off, which costs more than it saves.
#
# The honest consequence: a genuinely short secret cannot be scrubbed from
# output. Short secrets are rare (`HIVEMINDOS_TIP_BOT_AUTOSTART` is a boolean,
# not a credential) and a four-character secret has bigger problems than this.
# `redactions_for` reports what it will and will not cover so a caller can say
# so rather than assume.
MIN_REDACTABLE = 6

# How long a spawned command may run before the broker gives up on it. The
# socket's own client timeout is shorter than most builds, so anything genuinely
# long-running wants `detach`, which returns as soon as the child is up.
DEFAULT_TIMEOUT = 90.0

# Output beyond this is truncated. A build that prints 40MB should not be able
# to hold a broker thread or blow up a JSON reply.
MAX_OUTPUT = 256 * 1024


# ── redaction ──────────────────────────────────────────────────────────────


def _base64_fragments(raw: bytes) -> list[str]:
    """Substrings that appear in the base64 of ANY stream containing this value.

    Encoding the value on its own is not enough and the difference is not
    academic: `echo $SECRET | base64` appends a newline first, which changes
    every character from the tail backwards, and a redactor that only knew the
    bare encoding would hand the secret straight back. That exact command got
    through the first version of this function.

    Base64 packs three bytes into four characters, so where the value sits in
    the surrounding stream shifts its encoding — but only in one of three ways.
    Encode it at each of the three alignments, then drop the four characters at
    each end that mix with whatever came before and after. What is left is a run
    that must appear verbatim, wherever the value falls and whatever follows it.
    """
    fragments = []
    for pad in range(3):
        encoded = base64.b64encode(bytes(pad) + raw).decode("ascii")
        core = encoded[4:-4]
        if len(core) >= MIN_REDACTABLE:
            fragments.append(core)
    return fragments


def _encodings(value: str) -> list[str]:
    """The forms one value can take in output, so all of them get scrubbed.

    A command does not have to print a secret verbatim to leak it. `curl -v`
    prints an Authorization header base64'd, a URL-encoded value comes back in a
    query string, hex shows up in log dumps, and anything that round-trips
    through JSON arrives with its slashes escaped. Redacting only the raw form
    catches the careless case and misses every interesting one.

    This is a best effort and is documented as one. A command that encrypts the
    value, or splits it across two lines, defeats it — which is why redaction is
    the second line here and `command_allowed` is the first.
    """
    forms = {value}
    raw = value.encode("utf-8")
    try:
        forms.add(urllib.parse.quote(value, safe=""))
        forms.add(urllib.parse.quote_plus(value))
    except Exception:  # noqa: BLE001 — an unencodable value simply has fewer forms
        pass
    try:
        forms.update(_base64_fragments(raw))
        # Basic auth is `user:pass` base64'd, and the password half is what we
        # hold; the pair is what appears on the wire.
        forms.update(_base64_fragments(b":" + raw))
    except Exception:  # noqa: BLE001
        pass
    try:
        forms.add(raw.hex())
        forms.add(raw.hex().upper())
    except Exception:  # noqa: BLE001
        pass
    try:
        # json.dumps gives us the escaped form plus quotes; drop the quotes.
        forms.add(json.dumps(value)[1:-1])
    except Exception:  # noqa: BLE001
        pass
    return [form for form in forms if len(form) >= MIN_REDACTABLE]


def redactions_for(values: Mapping[str, str]) -> dict[str, bool]:
    """Which of these values redaction can actually cover.

    Returned rather than assumed, because "we scrubbed the output" and "we
    scrubbed the output except the two short ones" are different promises and
    only one of them is true.
    """
    return {name: len(str(value)) >= MIN_REDACTABLE for name, value in values.items()}


def redact(text: str, values: Mapping[str, str]) -> str:
    """Remove every injected value from text, in each form it could take.

    Longest first: if one secret contains another as a substring — which happens
    with a token and the same token carrying a prefix — replacing the short one
    first leaves a mangled fragment of the long one behind rather than removing
    it.
    """
    if not text:
        return text
    swaps: list[tuple[str, str]] = []
    for name, value in values.items():
        value = str(value)
        if len(value) < MIN_REDACTABLE:
            continue
        for form in _encodings(value):
            swaps.append((form, REDACTION.format(name=name)))
    for needle, marker in sorted(swaps, key=lambda pair: len(pair[0]), reverse=True):
        text = text.replace(needle, marker)
    return text


class Scrubber:
    """Redact a stream arriving in chunks, without letting a split hide a value.

    The naive version — redact each chunk as it arrives — fails on the case that
    matters: a secret straddling a read boundary appears in neither chunk, so
    both pass clean and the value lands on the terminal in two halves. A pipe
    hands you 4096 bytes at a time and cares nothing for where a token starts.

    So the tail of each chunk is held back rather than emitted: enough of it that
    any form of any value would still be intact on the next pass. `flush` at end
    of stream releases what is left, which is why it must be called even when the
    child produced nothing.
    """

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        longest = 0
        for value in self._values.values():
            for form in _encodings(str(value)):
                longest = max(longest, len(form))
        # One less than the longest form: any match that could still complete is
        # necessarily shorter than this, so holding it back is sufficient and
        # holding back more would only add latency.
        self._hold = max(0, longest - 1)
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        if not self._values:
            return chunk
        self._buffer += chunk
        # Redact the WHOLE buffer, then release all but the tail. Doing it the
        # other way round — cut first, redact the released part — was a real bug
        # and a subtle one: a form straddling the cut had its opening characters
        # emitted before anything looked at them, so it could never match. A
        # 46-character hex form with a 45-character hold-back went out with one
        # character shaved off the front and the rest following it.
        cleaned = redact(self._buffer, self._values)
        if len(cleaned) <= self._hold:
            self._buffer = cleaned
            return ""
        cut = len(cleaned) - self._hold
        ready, self._buffer = cleaned[:cut], cleaned[cut:]
        return ready

    def flush(self) -> str:
        rest, self._buffer = self._buffer, ""
        return redact(rest, self._values)


def stream(command: Sequence[str], values: Mapping[str, str], *,
           app: str = "", cwd: str = "", extra_env: Mapping[str, str] | None = None,
           grant: str = "", stdout: Any = None, stderr: Any = None) -> dict[str, Any]:
    """Run a command, passing its output through live, with values removed.

    This is what `passbook run` needs and `spawn` cannot give it: a build that
    prints for four minutes should print for four minutes, not sit silent and
    then arrive all at once. Interactivity is preserved by giving the child a
    pty when we have one, so a tool that colours its output or draws a progress
    bar behaves as it does normally.
    """
    argv = [str(part) for part in command if str(part) != ""]
    if not argv:
        return {"ok": False, "error": "no command"}
    token = grant or base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")
    env = _child_env(values, extra=extra_env, app=app, grant=token)
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    scrub_out, scrub_err = Scrubber(values), Scrubber(values)

    try:
        child = subprocess.Popen(  # noqa: S603 — argv is a list, never a shell string
            argv, cwd=cwd or None, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return {"ok": False, "error": f"command not found: {argv[0]}"}
    except PermissionError:
        return {"ok": False, "error": f"not executable: {argv[0]}"}
    except OSError as error:
        return {"ok": False, "error": f"could not run it: {error}"}

    def pump(source, sink, scrubber) -> None:
        try:
            for raw in iter(lambda: source.readline(), b""):
                text = scrubber.feed(raw.decode("utf-8", errors="replace"))
                if text:
                    sink.write(text)
                    sink.flush()
        finally:
            rest = scrubber.flush()
            if rest:
                sink.write(rest)
                sink.flush()

    pumps = [
        threading.Thread(target=pump, args=(child.stdout, out, scrub_out), daemon=True),
        threading.Thread(target=pump, args=(child.stderr, err, scrub_err), daemon=True),
    ]
    for worker in pumps:
        worker.start()
    code = child.wait()
    for worker in pumps:
        worker.join(timeout=5)
    return {"ok": True, "exit_code": code, "grant": token,
            "keys": sorted(values), "redacted": redactions_for(values)}


# ── guarded keys: which commands, which hosts ──────────────────────────────


def _guards(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    guards = policy.get("guards")
    return guards if isinstance(guards, Mapping) else {}


def guarded(policy: Mapping[str, Any]) -> list[str]:
    """Keys with a binding written for them, in name order."""
    return sorted(name for name, rule in _guards(policy).items() if isinstance(rule, Mapping))


def commands_for(key: str, policy: Mapping[str, Any]) -> list[str]:
    rule = _guards(policy).get(key)
    if not isinstance(rule, Mapping):
        return []
    return [str(pattern) for pattern in (rule.get("commands") or []) if str(pattern).strip()]


def destinations_for(key: str, policy: Mapping[str, Any]) -> list[str]:
    rule = _guards(policy).get(key)
    if not isinstance(rule, Mapping):
        return []
    return [str(host).lower() for host in (rule.get("destinations") or []) if str(host).strip()]


def _matches(pattern: str, text: str) -> bool:
    """Glob matching, anchored, case-sensitive for commands.

    `fnmatch` is tempting and wrong here: it treats `[...]` as a character class,
    so a pattern containing a bracket — common in real argv — silently means
    something else. Building the regex explicitly keeps `*` and `?` as the only
    metacharacters, which is what someone writing a command binding expects.
    """
    out = []
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    return re.fullmatch("".join(out), text) is not None


def command_allowed(key: str, command: Sequence[str], policy: Mapping[str, Any]) -> dict[str, Any]:
    """May this key be injected into this command?

    An unguarded key may go anywhere: that is what unguarded means, and saying
    so here keeps the decision in one place rather than spread across callers.
    """
    patterns = commands_for(key, policy)
    if not patterns:
        return {"allowed": True, "why": "not guarded"}
    line = " ".join(str(part) for part in command)
    for pattern in patterns:
        if _matches(pattern, line):
            return {"allowed": True, "why": f"matches {pattern!r}"}
    return {"allowed": False,
            "why": f"{key} is guarded and this command is not one of its "
                   f"{len(patterns)} allowed pattern(s)"}


def host_allowed(key: str, url: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """May this key be sent to this URL's host?

    Unlike commands, an unguarded key is refused here. A proxy sends the value
    *out*, to a host the caller named, and redaction cannot help with that — so
    a key with nobody having said where it may go does not go anywhere. This is
    the one place the default is closed, and it is closed because an open one
    would be an exfiltration primitive with a friendly name.
    """
    hosts = destinations_for(key, policy)
    if not hosts:
        return {"allowed": False,
                "why": f"{key} has no allowed destinations; "
                       f"bind one with:  passbook guard {key} --to <host>"}
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return {"allowed": False, "why": "that URL cannot be parsed"}
    host = (parsed.hostname or "").lower()
    if not host:
        return {"allowed": False, "why": "that URL names no host"}
    for allowed in hosts:
        # A leading dot means "this domain and anything under it"; anything else
        # is the exact host. Subdomain wildcards are the common real need and
        # `*.example.com` would collide with the command globs above.
        if allowed.startswith("."):
            if host == allowed[1:] or host.endswith(allowed):
                return {"allowed": True, "why": f"within {allowed}"}
        elif host == allowed:
            return {"allowed": True, "why": f"is {allowed}"}
    return {"allowed": False,
            "why": f"{key} may not be sent to {host}; allowed: {', '.join(hosts)}"}


# ── spawning ───────────────────────────────────────────────────────────────


def _child_env(values: Mapping[str, str], *, extra: Mapping[str, str] | None,
               app: str, grant: str, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment the child gets: a real one, plus exactly its keys.

    The broker's own environment is the base because the child needs a working
    PATH, HOME and locale to be a usable process at all. Anything PassBook uses
    to find or open a store is stripped: a child holding a grant must not also
    be able to re-derive the store for itself, and inheriting `HIVE_ENV_FILES`
    would let it do exactly that.
    """
    env = dict(os.environ if base is None else base)
    for name in ("HIVE_ENV_FILES", "PASSBOOK_STORE", "PASSBOOK_ROOT", GRANT_ENV):
        env.pop(name, None)
    for name, value in (extra or {}).items():
        # Caller-supplied environment is ordinary configuration — a port, a
        # log level. It is applied before the credentials so it can never
        # overwrite one, which would otherwise be a way to have the child print
        # a value of the caller's choosing under a trusted name.
        env[str(name)] = str(value)
    env.update({str(name): str(value) for name, value in values.items()})
    env[GRANT_ENV] = grant
    if app:
        env["PASSBOOK_APP"] = app
    return env


def spawn(command: Sequence[str], values: Mapping[str, str], *,
          app: str = "", cwd: str = "", extra_env: Mapping[str, str] | None = None,
          timeout: float = DEFAULT_TIMEOUT, detach: bool = False,
          grant: str = "", base_env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Run a command holding these values, and return output that does not.

    The caller gets an exit code and streams. It does not get an environment, a
    value, or a way to ask for one: the child's `PASSBOOK_GRANT` is what lets
    the child serve itself from its own environment, and it is minted here
    rather than accepted from outside.
    """
    argv = [str(part) for part in command if str(part) != ""]
    if not argv:
        return {"ok": False, "error": "no command"}
    token = grant or base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")
    env = _child_env(values, extra=extra_env, app=app, grant=token, base=base_env)
    where = cwd or None
    if where and not Path(where).is_dir():
        return {"ok": False, "error": f"no such directory: {where}"}

    started = time.time()
    try:
        if detach:
            # Long-running things — a dev server, a daemon — outlive the socket
            # request that asked for them. The caller gets a pid and nothing
            # else; its output is the child's own business from here.
            child = subprocess.Popen(  # noqa: S603 — argv is a list, never a shell string
                argv, cwd=where, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            return {"ok": True, "detached": True, "pid": child.pid,
                    "grant": token, "keys": sorted(values), "seconds": 0.0}
        done = subprocess.run(  # noqa: S603 — argv is a list, never a shell string
            argv, cwd=where, env=env, capture_output=True, text=True,
            timeout=timeout, errors="replace")
    except FileNotFoundError:
        return {"ok": False, "error": f"command not found: {argv[0]}"}
    except PermissionError:
        return {"ok": False, "error": f"not executable: {argv[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {timeout:.0f}s", "timeout": True}
    except OSError as error:
        return {"ok": False, "error": f"could not run it: {error}"}

    out = redact(done.stdout or "", values)
    err = redact(done.stderr or "", values)
    clipped = len(out) > MAX_OUTPUT or len(err) > MAX_OUTPUT
    return {
        "ok": True,
        "exit_code": done.returncode,
        "stdout": out[:MAX_OUTPUT],
        "stderr": err[:MAX_OUTPUT],
        "truncated": clipped,
        "keys": sorted(values),
        "redacted": redactions_for(values),
        "seconds": round(time.time() - started, 3),
    }


# ── proxying ───────────────────────────────────────────────────────────────

# `{{KEY}}` in a header or body is replaced by that key's value. Doubled braces
# because single ones collide with every templating language a caller might
# already have run over the same string.
_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _fill(text: str, values: Mapping[str, str]) -> tuple[str, list[str]]:
    """Substitute placeholders, reporting which keys were actually used."""
    used: list[str] = []

    def swap(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in values:
            used.append(name)
            return str(values[name])
        return match.group(0)

    return _PLACEHOLDER.sub(swap, text), used


def placeholders(*texts: str) -> list[str]:
    """Every key name a caller referenced, so it can be checked before use."""
    found: list[str] = []
    for text in texts:
        found.extend(_PLACEHOLDER.findall(text or ""))
    return sorted(set(found))


def proxy(spec: Mapping[str, Any], values: Mapping[str, str], *,
          timeout: float = 30.0) -> dict[str, Any]:
    """Make one HTTP request with credentials filled in, and return the reply.

    The strongest form of use-without-reveal: the value is never in an
    environment, never in an argv, and never in a file. It exists in this
    process for the length of one request.

    The response is redacted too. An API that echoes your key back — and several
    do, in an error message about it — would otherwise hand it straight to the
    caller through the reply body.
    """
    url = str(spec.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "no url"}
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme != "https":
        # A credential on a cleartext connection is a credential given away, and
        # a proxy that allowed it would be handing out the value with extra
        # steps. `http` to localhost is the one case with a real argument for
        # it, and it is not enough of one to open the hole.
        return {"ok": False, "error": "only https destinations are allowed"}

    method = str(spec.get("method") or "GET").upper()
    headers_in = spec.get("headers") if isinstance(spec.get("headers"), Mapping) else {}
    body_in = spec.get("body")
    body_text = "" if body_in is None else (
        body_in if isinstance(body_in, str) else json.dumps(body_in))

    used: list[str] = []
    headers: dict[str, str] = {}
    for name, raw in headers_in.items():
        filled, hit = _fill(str(raw), values)
        headers[str(name)] = filled
        used.extend(hit)
    body_filled, hit = _fill(body_text, values)
    used.extend(hit)
    url_filled, hit = _fill(url, values)
    used.extend(hit)

    request = urllib.request.Request(  # noqa: S310 — scheme is checked above
        url_filled, method=method, headers=headers,
        data=body_filled.encode("utf-8") if body_filled else None)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:  # noqa: S310
            status = answer.status
            payload = answer.read(MAX_OUTPUT + 1)
            got = dict(answer.headers)
    except urllib.error.HTTPError as error:
        status = error.code
        payload = error.read(MAX_OUTPUT + 1)
        got = dict(error.headers or {})
    except urllib.error.URLError as error:
        return {"ok": False, "error": f"could not reach it: {error.reason}"}
    except (OSError, ValueError) as error:
        return {"ok": False, "error": f"request failed: {error}"}

    text = payload.decode("utf-8", errors="replace")
    return {
        "ok": True,
        "status": status,
        "headers": {name: redact(str(value), values) for name, value in got.items()},
        "body": redact(text, values)[:MAX_OUTPUT],
        "truncated": len(payload) > MAX_OUTPUT,
        "used": sorted(set(used)),
        "redacted": redactions_for(values),
    }
