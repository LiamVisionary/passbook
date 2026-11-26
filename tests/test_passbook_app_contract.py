# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The contract the PassBook app runs on.

The native app holds no logic: every question and every change goes through the
CLI, so the CLI *is* its API. That has one sharp edge — the Rust side treats a
non-zero exit as a failure and shows the user an error. A command that does its
job and then dies printing the result therefore looks like a broken feature.

That is not hypothetical. `broker start` started the broker and then crashed on
a stale `policy['mode']` from the version-1 shape, exiting 1. The broker was
running; the app would have said it failed. These tests pin the exit code and
the shape for every call the app makes.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from _platform import broker_marker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
# setuptools looks here too; see package-dir in pyproject.toml.
PACKAGE = REPO / "src"

# The broker speaks over a Unix socket, which Windows does not have. These
# check CLI exit codes the app depends on, and there is no broker there to
# check them against.
needs_a_broker = broker_marker()


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"DEMO_KEY": "a-value", "OTHER_KEY": "another"})
    return tmp_path / "hive"


def _cli(*args, home: Path, stdin: str = ""):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", *args],
        capture_output=True, text=True, input=stdin, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(home), "PYTHONPATH": str(PACKAGE)},
    )


# ── every call the app makes must exit zero on success ─────────────────────


@pytest.mark.parametrize("args", [
    ("state",),
    ("policy",),
    ("policy", "--app", "agent", "--key", "DEMO_KEY", "--mode", "ask"),
    ("policy", "--app", "agent", "--key", "DEMO_KEY", "--mode", "always"),
    ("unlock", "--for", "15m", "--reason", "from PassBook"),
    ("lock",),
    ("link", "--json"),
    ("broker",),
])
def test_the_app_calls_exit_zero(machine, args):
    done = _cli(*args, home=machine)
    assert done.returncode == 0, f"{' '.join(args)} exited {done.returncode}: {done.stderr[-400:]}"


@needs_a_broker
def test_starting_and_stopping_the_broker_both_exit_zero(machine):
    """The bug this file exists for: it started, then died printing the result."""
    started = _cli("broker", "start", home=machine)
    stopped = _cli("broker", "stop", home=machine)

    assert started.returncode == 0, started.stderr[-400:]
    assert "Traceback" not in started.stderr
    assert stopped.returncode == 0, stopped.stderr[-400:]


def test_adding_a_key_over_stdin_exits_zero(machine):
    """The app passes secrets on stdin, never as an argument — `ps` can read those."""
    done = _cli("add", "--stdin", home=machine, stdin="FROM_APP=value\n")

    assert done.returncode == 0, done.stderr[-400:]
    assert "FROM_APP" in _cli("list", home=machine).stdout


# ── the shape the window renders from ──────────────────────────────────────


def test_state_carries_every_section_the_window_needs(machine):
    done = _cli("state", home=machine)
    state = json.loads(done.stdout)

    assert set(state) >= {"store", "sealing", "access", "broker", "links", "record"}
    assert state["store"]["keys"] == ["DEMO_KEY", "OTHER_KEY"]
    assert state["store"]["writes_to"]
    assert state["access"]["modes"] == ["always", "ask", "window", "never"]
    assert state["access"]["presets"]
    assert isinstance(state["record"]["rows"], list)


def test_every_section_reports_its_own_availability(machine):
    """A surface should render what is there and say what is not, rather than
    showing an empty panel that reads as a bug."""
    state = json.loads(_cli("state", home=machine).stdout)

    for section in ("access", "broker", "links", "record"):
        assert "available" in state[section], f"{section} does not say whether it is installed"
    assert "supported" in state["sealing"]


def test_state_never_carries_a_value(machine):
    passbook.set_values({"SECRET_ONE": "a-value-nobody-should-see"})

    blob = _cli("state", home=machine).stdout

    assert "SECRET_ONE" in blob, "key names are the point"
    assert "a-value-nobody-should-see" not in blob


def test_state_still_answers_on_a_machine_with_nothing_optional_installed(machine, monkeypatch):
    """The app must open on a bare machine and show it honestly."""
    import builtins

    real_import = builtins.__import__
    # `passbook_vault` joined this list when `state["sealing"]` moved onto it.
    # It reported from `passbook_seal`, which predates `hive-sealed:v2:` and so
    # called every v2-encrypted value plaintext — a machine with 261 sealed keys
    # was told it had none. A bare machine has neither module, so refusing only
    # the old one stopped simulating a bare machine.
    optional = {"passbook_stamp", "passbook_seal", "passbook_vault", "passbook_link",
                "passbook_broker", "passbook_access"}

    def refuse(name, *args, **kwargs):
        if name in optional:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    import passbook_cli

    state = passbook_cli.machine_state()

    assert state["store"]["keys"] == ["DEMO_KEY", "OTHER_KEY"]
    assert state["access"]["available"] is False
    assert state["broker"]["available"] is False
    assert state["record"]["available"] is False
    assert state["sealing"]["supported"] is False


# ── the vault calls the sign-in screen makes ───────────────────────────────

VAULT_PASSWORD = "a properly long vault password"


def _profile(home: Path):
    return _cli("profile", "create", "Owner", "--password-stdin",
                home=home, stdin=VAULT_PASSWORD + "\n")


def test_vault_state_exits_zero_and_is_json_on_a_bare_machine(machine):
    """The window asks this before anything exists, and must not be told an error."""
    done = _cli("vault", "--json", home=machine)
    assert done.returncode == 0, done.stderr[-400:]
    state = json.loads(done.stdout)
    assert state["profiles"] == [] and state["unlocked"] is False
    assert state["plaintext"], "a plaintext store should report what is readable"


def test_creating_a_profile_over_stdin_exits_zero(machine):
    done = _profile(machine)
    assert done.returncode == 0, done.stderr[-400:]
    assert "Traceback" not in done.stderr
    state = json.loads(_cli("vault", "--json", home=machine).stdout)
    assert [p["label"] for p in state["profiles"]] == ["Owner"]


def test_a_short_password_is_refused_without_a_traceback(machine):
    done = _cli("profile", "create", "Weak", "--password-stdin", home=machine, stdin="short\n")
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
    assert "8 characters" in done.stderr


def test_seal_and_unseal_over_stdin_both_exit_zero(machine):
    _profile(machine)
    sealed = _cli("seal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    assert sealed.returncode == 0, sealed.stderr[-400:]
    assert "a-value" not in (machine / ".env").read_text(encoding="utf-8")

    opened = _cli("unseal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    assert opened.returncode == 0, opened.stderr[-400:]
    assert "DEMO_KEY=a-value" in (machine / ".env").read_text(encoding="utf-8")


def test_a_wrong_password_fails_cleanly(machine):
    """The app shows stderr verbatim, so it must be a sentence, not a stack trace."""
    _profile(machine)
    done = _cli("seal", "--password-stdin", home=machine, stdin="not the password\n")
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
    assert done.stderr.strip() == "Wrong password"


@needs_a_broker
def test_signin_and_signout_exit_zero(machine):
    _profile(machine)
    _cli("seal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    started = _cli("broker", "start", home=machine)
    assert started.returncode == 0, started.stderr[-400:]
    try:
        signed = _cli("signin", "--password-stdin", "--for", "15m",
                      home=machine, stdin=VAULT_PASSWORD + "\n")
        assert signed.returncode == 0, signed.stderr[-400:]

        state = json.loads(_cli("vault", "--json", home=machine).stdout)
        assert state["unlocked"] and state["fully_sealed"]

        out = _cli("signout", home=machine)
        assert out.returncode == 0, out.stderr[-400:]
        assert json.loads(_cli("vault", "--json", home=machine).stdout)["unlocked"] is False
    finally:
        _cli("broker", "stop", home=machine)


@needs_a_broker
def test_signin_starts_the_broker_rather_than_sending_you_away(machine):
    """`passbook signin` on a machine with no broker used to just refuse.

    It printed "No broker is running, so there is nothing to sign in to. Run:
    passbook broker start" — one command whose entire job was to let you run
    the command you had already typed. Signing in *is* asking the broker to
    hold your key, so starting one is part of the job, not a prerequisite the
    person has to satisfy first. The app's own sign-in card had been claiming
    this already: "The broker is not running; signing in starts it."
    """
    _profile(machine)
    _cli("seal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    _cli("broker", "stop", home=machine)
    try:
        signed = _cli("signin", "--password-stdin", "--for", "15m",
                      home=machine, stdin=VAULT_PASSWORD + "\n")
        assert signed.returncode == 0, \
            f"signin refused with no broker running: {signed.stderr[-400:]}"
        assert json.loads(_cli("vault", "--json", home=machine).stdout)["unlocked"], \
            "signin reported success without opening the vault"
    finally:
        _cli("broker", "stop", home=machine)


def test_no_vault_command_ever_takes_a_password_as_an_argument(machine):
    """A password in argv is readable by every process on the machine."""
    helptext = _cli("--help", home=machine).stdout
    for verb in ("seal", "unseal", "signin", "profile"):
        detail = _cli(verb, "--help", home=machine).stdout
        assert "--password " not in detail and "--password=" not in detail, verb
        assert "PASSWORD" not in detail.replace("--password-stdin", ""), verb
    assert "signin" in helptext and "unseal" in helptext


# ── presence must not lie about a sealed store ─────────────────────────────


def _sealed(home: Path):
    pw = "a properly long vault password\n"
    _cli("profile", "create", "Owner", "--password-stdin", home=home, stdin=pw)
    _cli("seal", "--password-stdin", home=home, stdin=pw)


def test_check_says_locked_not_missing_for_a_sealed_key(machine):
    """`check` had two answers where there are three, so a sealed store made it
    report a present, readable-through-the-broker key as `missing` — and then
    advise `passbook-add`, which would have overwritten a working credential
    with whatever the reader pasted."""
    _sealed(machine)
    done = _cli("check", "DEMO_KEY", home=machine)

    assert "DEMO_KEY: locked" in done.stdout
    assert "missing" not in done.stdout
    assert "passbook-add DEMO_KEY" not in done.stderr, "it advised overwriting a real key"
    assert "signin" in done.stderr


def test_check_still_says_missing_for_a_key_that_is_not_there(machine):
    _sealed(machine)
    done = _cli("check", "NOT_A_KEY", home=machine)
    assert "NOT_A_KEY: missing" in done.stdout
    assert "passbook-add NOT_A_KEY" in done.stderr
    assert done.returncode == 1


def test_check_separates_the_two_when_both_happen(machine):
    _sealed(machine)
    done = _cli("check", "DEMO_KEY", "NOT_A_KEY", home=machine)
    assert "DEMO_KEY: locked" in done.stdout
    assert "NOT_A_KEY: missing" in done.stdout
    # The destructive remedy must name only the key that is really absent.
    assert "passbook-add NOT_A_KEY" in done.stderr
    assert "passbook-add DEMO_KEY" not in done.stderr


def test_list_and_check_agree_about_what_the_store_holds(machine):
    """`list` read names and `check` read values, so they disagreed the moment
    the store was sealed — which is what sent someone hunting a lost key."""
    _sealed(machine)
    listed = [line.strip() for line in _cli("list", home=machine).stdout.splitlines() if line.strip()]
    assert "DEMO_KEY" in listed
    assert "DEMO_KEY: missing" not in _cli("check", "DEMO_KEY", home=machine).stdout


# ── the window's own routing ────────────────────────────────────────────────


UI = REPO / "app" / "ui" / "index.html"


def _page_keys() -> list[str]:
    """The keys in the `PAGES` list — one per entry in the source list."""
    block = re.search(r"const PAGES = \[(.*?)\];", UI.read_text(encoding="utf-8"), re.S)
    assert block, "PAGES list not found in the window source"
    return re.findall(r'\["([a-z-]+)",', block.group(1))


def _routes() -> dict[str, str]:
    """The `page -> function` map the window paints from."""
    block = re.search(r"const body = \{(.*?)\}\[page\]\(\);", UI.read_text(encoding="utf-8"), re.S)
    assert block, "page router not found in the window source"
    return dict(re.findall(r"([a-z-]+):\s*([A-Za-z0-9_]+)", block.group(1)))


def test_every_nav_entry_has_a_page_to_paint():
    """A nav key with no route paints `undefined is not a function` and a blank
    window — and nothing else fails, so it survives a build and a launch.

    Renaming a page means changing the key in three places: the nav list, the
    router, and the counts. Two out of three looks completely fine until the
    tab is clicked.
    """
    routes = _routes()
    missing = [key for key in _page_keys() if key not in routes]
    assert not missing, f"nav entries with no page: {missing}"


def test_every_route_points_at_a_function_that_exists():
    source = UI.read_text(encoding="utf-8")
    absent = [name for name in _routes().values()
              if f"function {name}(" not in source]
    assert not absent, f"routes pointing at nothing: {absent}"


def test_every_goto_button_lands_on_a_real_page():
    routes = _routes()
    targets = set(re.findall(r'data-goto="([a-z-]+)"', UI.read_text(encoding="utf-8")))
    assert targets, "no data-goto buttons found — has the attribute been renamed?"
    assert not targets - set(routes), f"buttons going nowhere: {sorted(targets - set(routes))}"


def test_nothing_toggled_by_hidden_is_forced_visible_by_an_id_rule():
    """`el.hidden = true` is a no-op against `#el { display: ... }`.

    An id selector outranks the `[hidden]` rule every browser ships, so the
    element stays laid out. For the sign-in gate — fixed, inset 0, opaque, on
    top of everything — that meant a signed-in window painted its store and
    then covered it with an empty full-window sheet: a blank app, no error, no
    console, nothing to click. It only showed up once the vault was open,
    which is the state the window is in nearly all the time.

    Any element the script hides this way needs `[hidden]` given a rule of its
    own alongside whatever `display` its id rule sets.
    """
    source = UI.read_text(encoding="utf-8")
    toggled = set(re.findall(r"\b([A-Za-z_$][\w$]*)\.hidden\s*=", source))
    assert toggled, "no .hidden toggles found — has the gate stopped hiding itself?"

    ids = dict(re.findall(r"const\s+([A-Za-z_$][\w$]*)\s*="
                          r"\s*document\.getElementById\(\"([^\"]+)\"\)", source))
    unguarded = []
    for name in sorted(toggled):
        element = ids.get(name)
        if element is None:
            continue
        forced = re.search(rf"#{re.escape(element)}\s*\{{[^}}]*\bdisplay\s*:", source)
        if not forced:
            continue
        guard = re.search(rf"#{re.escape(element)}\[hidden\]\s*\{{[^}}]*"
                          rf"\bdisplay\s*:\s*none", source)
        if not guard:
            unguarded.append(element)
    assert not unguarded, (
        "these are hidden in script but given a display by an id rule, which "
        f"wins — they never actually hide: {unguarded}")


def _object_keys(source: str, name: str) -> set[str]:
    """Top-level keys of a JS object literal, whatever the line breaks.

    Reading them with a per-line regex silently saw only the first key on each
    line, which is how a table that named five operations passed for one that
    named nineteen.
    """
    start = source.find(f"const {name} = {{")
    if start < 0:
        return set()
    start = source.index("{", start)
    depth, keys, at = 0, set(), start
    while at < len(source):
        char = source[at]
        if char in "{[":
            depth += 1
        elif char in "}]":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1:
            found = re.match(r"([A-Za-z_$][\w$]*)\s*:", source[at:])
            if found and source[at - 1] in "{, \n\t":
                keys.add(found.group(1))
                at += found.end() - 1
        at += 1
    return keys


def test_the_window_has_a_word_for_every_operation_the_ledger_writes():
    """A missing entry does not fail — it prints the raw op at the reader.

    The window carried a verb table someone wrote from memory: `set`, `add`,
    `remove`, `revoke`, `grant` and `refuse`, none of which this ledger has
    ever written, while `reveal`, `denied`, `ask`, `export`, `import`, `seal`
    and `unseal` — all of which it does — were absent. So a reveal rendered as
    "hivemindos reveal 1 keys" and an export would have rendered as "you export
    281 keys", on the one page whose entire job is saying what happened.

    Both directions are checked. An entry for an op that cannot occur is dead
    weight that reads as coverage.
    """
    import passbook_stamp

    source = UI.read_text(encoding="utf-8")
    for name in ("OP_WORD", "OP_ICON"):
        covered = _object_keys(source, name)
        assert covered, f"{name} not found in the window source"
        missing = passbook_stamp.OPERATIONS - covered
        invented = covered - passbook_stamp.OPERATIONS
        assert not missing, f"{name} has no word for: {sorted(missing)}"
        assert not invented, f"{name} names operations that cannot happen: {sorted(invented)}"


def test_a_read_that_came_back_short_is_not_called_a_refusal():
    """`granted: false` means different things for different operations.

    On a `read` it means some of the names asked for were not in the store —
    ordinary, and 438 of the 2,208 rows on the author's machine. On a `signin`
    it means the password was wrong. The window called both "was refused" and
    put a warning tile beside them, which made a fifth of all activity look
    like an attack and hid the single row that was one.
    """
    source = UI.read_text(encoding="utf-8")
    block = re.search(r"const OP_WORD = \{(.*?)\n  \};", source, re.S)
    assert block, "OP_WORD not found"
    read = re.search(r"^\s*read:\s*\{([^}]*)\}", block.group(1), re.M)
    assert read, "OP_WORD has no entry for read"
    assert "refus" not in read.group(1).lower(), \
        f"a short read is being called a refusal: {read.group(1).strip()}"
    # And the one op that really is a refusal still says so.
    denied = re.search(r"^\s*denied:\s*\{([^}]*)\}", block.group(1), re.M)
    assert denied and "refus" in denied.group(1).lower(), \
        "the refusal op no longer says it was refused"


def _tag_around(source: str, at: int) -> str:
    """The markup tag an attribute occurrence sits in."""
    open_at = max(source.rfind("<button", 0, at), source.rfind("<input", 0, at),
                  source.rfind("<select", 0, at), source.rfind("<a ", 0, at))
    if open_at < 0:
        return ""
    shut = source.find(">", at)
    return source[open_at:shut if shut > 0 else at]


def test_no_handler_reads_an_attribute_its_buttons_do_not_carry():
    """A handler reading `dataset.key` off buttons that carry `data-for`.

    That is not a crash. `undefined` goes to the CLI as the key name, the
    command fails somewhere further down, and the window shows whatever error
    comes back — for a control that looked correct on screen and was wired to
    something. It happened here the moment a shared helper started drawing the
    access switch and named the key attribute differently from the handler that
    had always read it.
    """
    source = UI.read_text(encoding="utf-8")
    # Each handler's body runs to the start of the next one. Matching it with a
    # regex that stopped at the first semicolon read `dataset` uses from the
    # whole file instead, and reported every button against every handler.
    found = list(re.finditer(
        r'querySelectorAll\("\[data-([\w-]+)\]"\)\.forEach\(\((\w+)\)', source))
    checked = 0
    broken = []
    for index, binding in enumerate(found):
        selector, name = binding.group(1), binding.group(2)
        stop = found[index + 1].start() if index + 1 < len(found) else len(source)
        body = source[binding.end():stop]
        wants = set(re.findall(rf"\b{name}\.dataset\.(\w+)", body))
        camel = selector.replace("-", " ").title().replace(" ", "")
        camel = camel[0].lower() + camel[1:]
        for field in wants - {camel}:
            attribute = "data-" + re.sub(r"([A-Z])", r"-\1", field).lower()
            for spot in re.finditer(rf'{re.escape("data-" + selector)}=', source):
                tag = _tag_around(source, spot.start())
                if not tag or f"{attribute}=" in tag:
                    continue
                broken.append(f"[{selector}] handler reads .{field} but this tag has no "
                              f"{attribute}: {' '.join(tag.split())[:110]}")
            checked += 1
    # A helper that names its attribute `data-${attr}` cannot be matched by the
    # scan above — which is exactly how this got through the first time. What
    # can be required of such a tag is that it names its subject the one way
    # every handler in this window looks for it.
    for spot in re.finditer(r"data-\$\{", source):
        tag = _tag_around(source, spot.start())
        if tag and "data-key=" not in tag:
            broken.append("a control whose attribute name is computed must carry data-key, "
                          f"or no handler can find its subject: {' '.join(tag.split())[:110]}")
        checked += 1

    assert checked, "no handler/attribute pairs were found — has the wiring changed shape?"
    assert not broken, "handlers reading attributes their markup does not set:\n" + "\n".join(broken)


def _gate_handler(source: str, attribute: str) -> str:
    """The body of one `gate.querySelectorAll("[data-x]")` handler."""
    found = list(re.finditer(r'gate\.querySelectorAll\("\[data-([\w-]+)\]"\)', source))
    for index, binding in enumerate(found):
        if binding.group(1) != attribute:
            continue
        stop = found[index + 1].start() if index + 1 < len(found) else len(source)
        return source[binding.end():stop]
    return ""


def test_the_lock_screen_cannot_be_dismissed_without_a_factor():
    """Pressing Lock and then clicking your own name used to walk straight in.

    The reasoning written into the code was that an already-open workspace
    needs no password to look at, because the vault is unlocked for everything
    else on the machine anyway. That confuses two different questions. The
    vault being open is what lets agents read at four in the morning, which is
    deliberate. It is not evidence about who is sitting at the keyboard, and
    that is the only thing the lock screen asks.

    So the workspace picker may set up a sign-in and nothing else. Lifting the
    lock belongs to the paths that have just checked a password or a passkey.
    """
    source = UI.read_text(encoding="utf-8")
    picker = _gate_handler(source, "gpick")
    assert picker, "the workspace picker handler was not found"
    assert "unlockWindow" not in picker, \
        "picking a workspace lifts the window lock without checking anything"
    assert not re.search(r"appLocked\s*=\s*false", picker), \
        "picking a workspace clears the lock flag directly"

    # And the flag is only ever cleared in one place, so there is one thing to
    # audit rather than one per caller.
    clears = re.findall(r"appLocked\s*=\s*false", source)
    assert len(clears) == 1, \
        f"the lock flag is cleared in {len(clears)} places; it should only be cleared in unlockWindow"

    lifts = {m.group(1) for m in re.finditer(r"(\w+)[^\n]*\bunlockWindow\(\)", source)}
    assert "unlockWindow" in source and "rememberLock" in source, \
        "the lock is not remembered anywhere, so quitting the window would lift it"


def test_every_control_on_the_lock_screen_does_something():
    """"Unlock with passkey" was drawn on the gate and never wired.

    It had no handler and there was no command for one to call, so it was a
    button that looked exactly like the working one beside it and did nothing
    at all. On a lock screen that is the worst way to be broken: the person
    pressing it concludes their passkey is refused.
    """
    source = UI.read_text(encoding="utf-8")
    # Only the gate's own markup. `data-goto`, `data-grid` and `data-group` are
    # main-page controls that happen to start with the same letter.
    drawn = set()
    for name in ("gateTiles", "gateSignIn", "gateEnrol", "gateCreate", "gateAgentPanel"):
        body = re.search(rf"function {name}\(\) \{{(.*?)\n  \}}\n", source, re.S) \
            or re.search(rf"function {name}\([^)]*\) \{{(.*?)\n  \}}\n", source, re.S)
        assert body, f"{name} not found — has the gate been renamed?"
        drawn |= set(re.findall(r'data-(g[a-z]+)="', body.group(1)))
    # Read as data by the submit handler rather than pressed.
    drawn -= {"gform"}
    assert drawn, "no gate controls found at all"
    wired = set(re.findall(r'gate\.querySelectorAll\("\[data-(g[a-z]+)\]"\)', source))
    wired |= set(re.findall(r'gate\.querySelector\("\[data-(g[a-z]+)\]"\)', source))
    dead = drawn - wired
    assert not dead, f"lock-screen controls with no handler: {sorted(dead)}"


def test_every_command_the_window_calls_is_allowed_by_the_acl():
    """A command missing from the capability fails at the moment it is used.

    The window is served over http://localhost so a passkey has a domain to
    bind to. That makes it a remote origin to Tauri, and a remote origin gets
    no command it was not explicitly granted. The window still loads and still
    looks right — it just answers "Command state not allowed by ACL" the first
    time somebody touches the feature, which is how this shipped once already.

    Generated by scripts/sync-permissions.py, checked here so the two cannot
    drift when a command is added.
    """
    generator = REPO / "scripts/sync-permissions.py"
    assert generator.exists(), "the permission generator is missing"
    done = subprocess.run([sys.executable, str(generator), "--check"],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout.strip() or done.stderr.strip()

    # And the grant really does name every command, not merely agree with a
    # generator that could itself be looking at the wrong thing.
    source = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    block = re.search(r"tauri::generate_handler!\[(.*?)\]", source, re.S)
    assert block, "no generate_handler! block"
    commands = [name for name in dict.fromkeys(
        re.findall(r"[A-Za-z_][A-Za-z0-9_]*", block.group(1)))
        if f"fn {name}(" in source]
    assert commands, "no commands found in the handler list"
    granted = set(json.loads(
        (REPO / "app/src-tauri/capabilities/default.json").read_text(encoding="utf-8"))["permissions"])
    missing = [name for name in commands
               if f"allow-{name.replace('_', '-')}" not in granted]
    assert not missing, f"commands the window may not call: {missing}"


def test_every_script_the_window_loads_is_embedded_and_served():
    """A script tag the embedded server does not answer stops the whole window.

    The window is not read from disk: `mod ui` in main.rs embeds each file with
    `include_bytes!` and answers a fixed list of paths, 404 for anything else.
    1.10.28 added `<script src="/adddevice.js">` and neither embedded nor routed
    it. The running app answered 404, `window.createPassbookAddDevice` was
    undefined, and the first statement that called it threw before `boot()` was
    ever reached. Nothing here failed, because nothing here looked.
    """
    page = UI.read_text(encoding="utf-8")
    rust = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    scripts = re.findall(r'<script src="(/[^"]+)"', page)
    assert scripts, "no script tags found: has the page changed shape?"
    for path in scripts:
        name = path.lstrip("/")
        assert (REPO / "app/ui" / name).exists(), f"{path} is loaded but app/ui/{name} does not exist"
        assert f'include_bytes!("../../ui/{name}")' in rust, f"{path} is loaded but not embedded in mod ui"
        assert re.search(r'"%s"\s*=>\s*\("200 OK"' % re.escape(path), rust), f"{path} is embedded but no route serves it"


def test_the_source_list_stays_short():
    """Eight destinations is a filing cabinet, not an app.

    Six of the eight were about how PassBook works rather than what is in it —
    a page for the background service, one for the ledger, one for machine
    grants, one that listed all 281 keys a second time so it could carry a
    three-way switch. Nothing was missing and nothing could be found. Anything
    that is not one of the few things a person opens this app to do belongs on
    the settings shelf, which is one press away and does not cost a slot.

    Five since 2026-10-12: Balances, at Liam's ask for "an extra tab". It is one of those few things (what
    is left to spend, and topping it up), not how PassBook works, and it stays off until turned on.
    """
    source = UI.read_text(encoding="utf-8")
    block = re.search(r"const PAGES = \[(.*?)\n  \];", source, re.S)
    assert block, "PAGES not found"
    entries = re.findall(r'\["(\w+)"', block.group(1))
    assert len(entries) <= 5, f"the source list has grown back to {len(entries)}: {entries}"


def test_every_settings_pane_is_reachable_and_leads_back():
    """Tucked away has to still mean available.

    A pane moved off the source list is reachable only through its settings
    row, so the row has to name a real page and the page has to draw the way
    back — otherwise moving something out of sight is the same as deleting it.
    """
    source = UI.read_text(encoding="utf-8")
    shelf = re.search(r"const SETTINGS = \[(.*?)\n  \];", source, re.S)
    assert shelf, "the settings shelf was not found"
    panes = re.findall(r'\["(\w+)"', shelf.group(1))
    assert panes, "the settings shelf is empty"

    routes = _routes()
    assert not [p for p in panes if p not in routes], \
        f"settings rows pointing at nothing: {[p for p in panes if p not in routes]}"

    stranded = []
    for pane in panes:
        body = re.search(rf"function {routes[pane]}\(\) \{{(.*?)\n  \}}\n", source, re.S)
        assert body, f"{routes[pane]} not found"
        if "settingsBack(" not in body.group(1):
            stranded.append(pane)
    assert not stranded, f"settings panes with no way back: {stranded}"


def test_the_page_of_callers_is_not_headed_agents():
    """They are LaunchAgents, command lines and builds — the field is `app`.

    Heading the list "agents" was a claim about what those names were, and on a
    real machine it was wrong for every one of them. The word still belongs in
    the MCP block on the same page, where an agent really is what connects.
    """
    source = UI.read_text(encoding="utf-8")
    body = re.search(r"function appsPage\(\) \{(.*?)\n  \}\n", source, re.S)
    assert body, "appsPage not found — was it renamed without updating this test?"
    # The page is named where it is reached from — its settings row and the
    # heading its back link draws — as well as by any heading it draws itself.
    said = [text for pair in re.findall(
        r"<h2>([^<]*)</h2>|<p class=\"lede\">([^<]*)</p>|settingsBack\(\"([^\"]+)\"\)",
        body.group(1)) for text in pair if text]
    shelf = re.search(r"const SETTINGS = \[(.*?)\n  \];", source, re.S)
    assert shelf, "the settings shelf was not found"
    said += [label for page, label in
             re.findall(r'\["(\w+)", "([^"]+)"', shelf.group(1)) if page == "apps"]
    assert said, "the page has no name to check"
    assert not [t for t in said if "agent" in t.lower()], \
        f"the page of callers is still headed agents: {said}"


# ── what the five-second refresh is allowed to cost ─────────────────────────


def test_state_does_not_verify_the_chain_unless_asked(machine):
    """Re-hashing the whole ledger is the most expensive thing the CLI does.

    The window calls `state` every five seconds, and this walked every row of a
    six-megabyte record each time to answer a question only the Record page
    asks — 0.14s of SHA-256 twelve times a minute, growing with the ledger.
    """
    default = json.loads(_cli("state", home=machine).stdout)
    assert default["record"]["intact"] is None, "state must not verify by default"

    asked = json.loads(_cli("state", "--verify", home=machine).stdout)
    assert asked["record"]["intact"] is True
    assert asked["record"]["detail"] != default["record"]["detail"]


def test_an_unchecked_chain_is_never_labelled_intact():
    """`intact: null` means nobody looked, which is not the same as fine.

    The page read `intact === false` for broken and treated everything else as
    good, so the moment verification moved off the refresh path every store
    would have been labelled Intact without a single row being hashed.
    """
    body = re.search(r"function recordPage\(\) \{(.*?)\n  \}\n", UI.read_text(encoding="utf-8"), re.S)
    assert body, "recordPage not found"
    assert "Not checked" in body.group(1), "an unverified chain must say so"


def test_the_record_the_window_gets_is_the_record_it_draws(machine):
    """One bulk read stamps every key it touched, and there were a hundred rows.

    On a real store that was 501KB of the 632KB payload — parsed on the
    window's main thread every five seconds to draw forty rows of a page that
    was usually not open. The count survives even where the names are cut, so
    the row can still say how many there were.
    """
    import passbook_stamp

    names = [f"BULK_{n:03}" for n in range(60)]
    passbook.set_values(dict.fromkeys(names, "v"))
    for _ in range(50):
        passbook_stamp.stamp(op="read", keys=names, app="bulk-reader", root=machine)

    record = json.loads(_cli("state", home=machine).stdout)["record"]

    assert len(record["rows"]) <= 40, "more rows are sent than any page shows"
    for row in record["rows"]:
        assert len(row.get("keys", [])) <= 12, "a row carries an unbounded key list"
        assert "keyCount" in row, "a truncated row must still say how many there were"


def test_usage_carries_only_what_a_key_row_shows(machine):
    """`usage_by_key` also collects every app that ever asked for each key.

    Nothing renders that, and it grows with the ledger: 81KB of a payload that
    is re-parsed twelve times a minute.
    """
    import passbook_stamp

    passbook_stamp.stamp(op="read", keys=["DEMO_KEY"], app="a-reader", root=machine)
    usage = json.loads(_cli("state", home=machine).stdout)["usage"]

    assert usage, "usage must still be summarised for the key rows"
    for entry in usage.values():
        assert set(entry) == {"count", "last", "last_app"}, f"extra fields: {sorted(entry)}"


# ── the veil ────────────────────────────────────────────────────────────────
#
# A revealed credential is drawn by the app and the window is given a token, so
# that there is no string in the JavaScript heap to scrape and no text in the
# accessibility tree to read. None of that is enforced by a type: it holds only
# as long as no command hands a value back to the webview and no handler puts
# one in the DOM. Both are one careless line away, and neither would fail
# anything — the window would work perfectly and the guarantee would be gone.
#
# So it is pinned here, on the source, the way the ACL test above is.

RUST = REPO / "app/src-tauri/src/main.rs"


def _commands() -> dict[str, str]:
    """Every `#[tauri::command]` in the app, name -> return type."""
    source = RUST.read_text(encoding="utf-8")
    found = {}
    for match in re.finditer(
        r"#\[tauri::command(?:\([^)]*\))?\]\s*\n(?:pub\s+)?(?:async\s+)?fn\s+(\w+)"
        r"\s*\([^)]*\)\s*(?:->\s*([^{]+?))?\s*\{",
        source, re.S,
    ):
        found[match.group(1)] = " ".join((match.group(2) or "()").split())
    assert found, "no Tauri commands found — the parser has drifted from the source"
    return found


def test_no_command_hands_a_credential_to_the_window():
    """The invariant the whole veil rests on, checked by signature.

    `reveal_key` used to return `Result<String, String>` and the window put that
    string in an `<input>`. Anything that returns a bare String again is either
    a value on its way to the webview or a signature that needs saying so here.
    """
    # Only the success type matters: every command in here fails with a String,
    # and an error message is not a credential.
    def succeeds_with(returns: str) -> str:
        inner = re.fullmatch(r"Result<(.*),\s*String>", returns)
        return (inner.group(1) if inner else returns).strip()

    allowed = {
        # A yes/no about this platform, not about the store.
        "capture_protection": "Protection",
        # One of three words, "system", "light" or "dark": how the window looks. Read from the app's own
        # config folder and matched against those three before it is returned; never from the store.
        "appearance": "String",
        "set_appearance": "String",
    }
    for name, returns in _commands().items():
        ok = succeeds_with(returns)
        if allowed.get(name) == ok:
            continue
        assert ok != "String", (
            f"{name} returns {returns} — a command that succeeds with a String "
            f"is a value on its way to the webview. If it is not a credential, "
            f"add it to `allowed` with its type and a reason."
        )


def test_reveal_returns_a_token_and_not_a_value():
    """Specifically: the one command whose job is showing a credential."""
    returns = _commands()["reveal_key"]
    assert returns == "Result<Veiled, String>", (
        f"reveal_key returns {returns}; the window must be given a token, not a value"
    )
    source = RUST.read_text(encoding="utf-8")
    fields = re.search(r"struct Veiled \{(.*?)\n\}", source, re.S)
    assert fields, "the Veiled struct moved"
    names = set(re.findall(r"^\s*(?:pub\s+)?(\w+):", fields.group(1), re.M))
    assert names == {"token", "length", "hold_ms"}, (
        f"Veiled carries {sorted(names)} — a field that could hold a value is a "
        f"value on its way to the webview"
    )


def test_the_window_never_writes_a_value_to_the_clipboard():
    """`navigator.clipboard.writeText` takes a string, so a value copied there
    is a value materialised in the heap the veil exists to keep empty. Copying
    a credential happens in Rust now; the remaining uses are a recovery code and
    a fingerprint, which are shown on screen as text anyway."""
    page = UI.read_text(encoding="utf-8")
    for match in re.finditer(r"clipboard\.writeText\(([^)]*)\)", page):
        argument = match.group(1)
        assert "copytext" in argument, (
            f"clipboard.writeText({argument}) — a credential must go through "
            f"the copy_key command instead"
        )


def test_a_revealed_value_hides_itself_before_the_app_forgets_it():
    """The two clocks race on every reveal and the window's must win, or the
    picture 404s under a row still claiming to show something."""
    window = re.search(r"const HIDE_AFTER = (\d+);", UI.read_text(encoding="utf-8"))
    app = re.search(
        r"pub const HOLD: Duration = Duration::from_secs\((\d+)\);",
        (REPO / "app/src-tauri/src/veil.rs").read_text(encoding="utf-8"),
    )
    assert window and app, "one of the two holds moved"
    assert int(window.group(1)) / 1000 < int(app.group(1)), (
        f"the window hides after {int(window.group(1)) / 1000}s but the app holds "
        f"for {app.group(1)}s — the window must be the one that gives up first"
    )


# ── the app's reveal on a machine that seals reads ──────────────────────────
#
# A sealed machine has said values go only into processes the broker started.
# The window is not one, so under a seal the app stops reading the value at all:
# it asks the broker to spawn a child — itself, in `--draw` mode — which is given
# the value the way every brokered child is, draws it, and writes a PNG the
# parent reads back. The parent never holds the plaintext.
#
# Two things have to hold for that to work, and both are contracts of the CLI
# rather than of the app, which is why they are pinned here.


@pytest.mark.skipif(broker_marker() is None, reason="the broker needs a Unix socket")
def test_reveal_is_refused_once_reads_are_sealed(machine):
    """The gap this closes: `reveal --confirm` printed values straight past a
    seal that says this machine does not print them. It is the one command an
    agent reaches for, and `--confirm` skipped the terminal check that was the
    only thing in its way."""
    assert _cli("reveal", "DEMO_KEY", "--confirm", "DEMO_KEY",
                home=machine).stdout.strip() == "a-value", "open reads still print"

    assert _cli("policy", "--reads", "sealed", home=machine).returncode == 0
    done = _cli("reveal", "DEMO_KEY", "--confirm", "DEMO_KEY", home=machine)

    assert done.returncode != 0, "a sealed machine printed a value from `reveal`"
    assert "a-value" not in done.stdout, "the value came back anyway"
    # The refusal has to name the way through, or it is a dead end for the
    # person whose credential it is.
    assert "passbook run" in (done.stdout + done.stderr)
    assert "app" in (done.stdout + done.stderr).lower(), (
        "the refusal should say the owner can still see it in the window"
    )


@pytest.mark.skipif(broker_marker() is None, reason="the broker needs a Unix socket")
def test_a_brokered_child_still_gets_the_value_under_a_seal(machine, tmp_path):
    """What the app's drawing depends on: `run` delivers to the child under a
    seal, and delivers the real value rather than the redaction marker.

    The child here writes to a file for the same reason the app's does — `run`
    pumps a child's stdout through a redactor that decodes it as UTF-8 with
    replacement, so a PNG sent that way arrives with every non-UTF-8 byte
    destroyed. Anything binary has to come back some other way.
    """
    assert _cli("policy", "--reads", "sealed", home=machine).returncode == 0
    assert _cli("broker", "start", home=machine).returncode == 0
    try:
        out = tmp_path / "drawn.bin"
        child = (
            "import os,pathlib;"
            f"pathlib.Path({str(out)!r}).write_bytes("
            "b'\\x89PNG' + os.environ.get('DEMO_KEY','').encode())"
        )
        done = _cli("run", "--only", "DEMO_KEY", "--app", "passbook-app", "--",
                    sys.executable, "-c", child, home=machine)

        assert done.returncode == 0, done.stderr
        assert out.exists(), "the brokered child produced nothing"
        written = out.read_bytes()
        assert written == b"\x89PNGa-value", (
            f"the child got {written!r} — a redaction marker instead of the value "
            f"means the app would draw the marker"
        )
        # And the value did not come back out through the stream.
        assert "a-value" not in done.stdout
    finally:
        _cli("broker", "stop", home=machine)


# ── `--reads` is the whole store's switch, and says so ──────────────────────
#
# `policy --app hivemindos --key PLAID_CLIENT_ID --reads open` exited 0, printed
# "Reads are open", and left no trace of the app it named. Three separate
# problems in one command:
#
#   1. It read as scoped and was not. The scope flags were dropped on the floor
#      and the store-wide switch flipped anyway — so a command that looked like
#      it touched one key on one app unsealed every key on the machine.
#   2. Nothing was recorded for the app, so `policy` afterwards showed no row
#      for it and the person went looking for a policy that had never existed.
#   3. It implied a per-app exemption to sealed reads exists. It does not, and
#      that is deliberate: the broker removed exactly that exemption because an
#      app NAME is a claim (passbook_broker.py, above the sealed check).
#      Anything can call itself `hivemindos` and read what the exemption opened.
#
# So the combination is refused rather than made to work. The refusal is the
# honest answer — there is no scoped `--reads` to implement.


def _reads_mode(home: Path) -> str:
    import passbook_access as access

    return str(access.read_policy(home).get("reads") or "open")


@pytest.mark.parametrize("scope", [
    ("--app", "hivemindos"),
    ("--key", "DEMO_KEY"),
    ("--app", "hivemindos", "--key", "DEMO_KEY"),
])
def test_reads_refuses_to_be_narrowed_by_a_scope(machine, scope):
    """The reported command. It must fail loudly, and — the part that actually
    bites — it must not flip the store-wide switch on its way out."""
    assert _cli("policy", "--reads", "sealed", home=machine).returncode == 0
    assert _reads_mode(machine) == "sealed"

    done = _cli("policy", *scope, "--reads", "open", home=machine)

    assert done.returncode != 0, f"policy {' '.join(scope)} --reads open exited 0"
    assert _reads_mode(machine) == "sealed", (
        "a command that refused still unsealed the store — this is the bug, not "
        "the exit code"
    )


def test_the_refusal_explains_that_reads_is_store_wide(machine):
    """A refusal that does not say why reads a policy that is arbitrary, and the
    next thing somebody tries is the same command with `sudo`."""
    done = _cli("policy", "--app", "hivemindos", "--key", "DEMO_KEY",
                "--reads", "open", home=machine)
    said = done.stdout + done.stderr

    assert "--app" in said and "--key" in said, "the refusal must name what it rejected"
    assert "claim" in said.lower(), (
        "the refusal should say why there is no per-app exemption: a name is a claim"
    )
    assert "nothing was changed" in said.lower(), (
        "it must say the store was left alone, or the reader assumes a partial write"
    )
    # And it must name the two things the person was probably reaching for.
    assert "--mode" in said, "the refusal should point at the flag that IS scoped"
    assert "passbook run" in said, "the refusal should name the way to use a sealed key"


def test_a_refused_scope_writes_no_policy_row(machine):
    """The second half of the original confusion: `policy` afterwards showed no
    row for the app, because nothing had been written for it. A refusal must
    leave that state honest rather than half-recording the app it rejected."""
    _cli("policy", "--app", "hivemindos", "--key", "DEMO_KEY", "--reads", "open",
         home=machine)

    import passbook_access as access

    assert "hivemindos" not in access.read_policy(machine).get("apps", {})
    assert "hivemindos" not in _cli("policy", home=machine).stdout


def test_reads_and_mode_together_are_refused_rather_than_half_applied(machine):
    """`--mode` was discarded the same way whenever `--reads` was present: the
    reads branch returned before the mode branch could run. Two switches, one
    silently ignored."""
    done = _cli("policy", "--mode", "ask", "--reads", "sealed", home=machine)

    assert done.returncode != 0
    assert _reads_mode(machine) == "open", "the ignored --mode still let --reads through"


def test_reads_alone_still_sets_the_store_wide_switch(machine):
    """The behaviour the refusal must not have cost. Both directions, because
    `open` is the one an upgrade path depends on."""
    assert _cli("policy", "--reads", "sealed", home=machine).returncode == 0
    assert _reads_mode(machine) == "sealed"
    assert _cli("policy", "--reads", "open", home=machine).returncode == 0
    assert _reads_mode(machine) == "open"


def test_a_scoped_mode_rule_still_writes_and_shows(machine):
    """The other half of the same guard: the scope flags still mean what they
    always meant when they are used with the flag that is actually scoped."""
    assert _cli("policy", "--app", "hivemindos", "--key", "DEMO_KEY", "--mode",
                "never", home=machine).returncode == 0

    import passbook_access as access

    rule = access.read_policy(machine)["apps"]["hivemindos"]["keys"]["DEMO_KEY"]
    assert rule["mode"] == "never"
    assert "hivemindos" in _cli("policy", home=machine).stdout


def test_learn_may_still_seal_what_it_derived(machine):
    """`--learn` consumes `--mode` and then falls through to the reads branch,
    which is the one combination of the two that is meant to work. The guard
    must not catch it."""
    done = _cli("policy", "--learn", "--mode", "always", "--reads", "sealed",
                home=machine)

    assert done.returncode == 0, done.stderr[-400:]
    assert _reads_mode(machine) == "sealed"


def test_no_command_is_dispatched_on_the_main_thread():
    """A bare `#[tauri::command]` runs on the main thread.

    Every command in this app shells out to the PassBook CLI, so a bare one
    freezes the window for a Python start plus whatever it asked for. That is
    not a slow command, it is a frozen application: the spinner drawn for the
    wait cannot be painted, because the thread that would paint it is the thread
    that is waiting. `(async)` on a sync function runs it on the blocking pool
    instead — the macro calls that `sync_threadpool`.
    """
    source = RUST.read_text(encoding="utf-8")
    bare = re.findall(r"#\[tauri::command\]\s*\n(?:pub\s+)?fn\s+(\w+)", source)
    assert not bare, (
        f"these commands would block the window while they run: {sorted(bare)}. "
        f"Use #[tauri::command(async)]."
    )
    # And the parser above must still be finding them, or this passes vacuously
    # on a file it can no longer read.
    assert len(_commands()) > 40, "the command parser has drifted from the source"


def test_the_window_can_see_and_change_whether_a_restart_opens_the_vault():
    """This setting was CLI-only, and the window did not know it existed.

    So after a restart the app could not say why everything was shut — apps
    getting no credentials, `add` refused — and offered nothing to change it.
    The answer lived in `passbook vault --stay-open`, which you have to already
    know about to go looking for.

    Three pieces, and it is useless without all three: the state has to reach
    the window, the window has to have a control, and the window has to be
    allowed to call it.
    """
    import json
    import re

    cli = (REPO / "src/passbook_cli.py").read_text(encoding="utf-8")
    assert '"stay_open": _stay_open_state()' in cli, "vault --json must carry it"

    rust = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    assert "fn set_stay_open(" in rust
    block = re.search(r"tauri::generate_handler!\[(.*?)\]", rust, re.S)
    assert block and "set_stay_open" in block.group(1), "not registered; the window cannot call it"

    granted = set(json.loads(
        (REPO / "app/src-tauri/capabilities/default.json").read_text(encoding="utf-8"))["permissions"])
    assert "allow-set-stay-open" in granted

    ui = UI.read_text(encoding="utf-8")
    assert "function stayOpenBlock()" in ui
    assert "${stayOpenBlock()}" in ui, "defined but never rendered"
    assert '[data-stayopen]' in ui, "rendered but nothing handles the click"


def test_turning_it_on_carries_the_warning_rather_than_a_bare_switch():
    """Turning this on puts the opening key where any program running as you can
    fetch it. A switch labelled "open at restart" with that fact left in the CLI
    would be the app quietly making the machine weaker on the owner's behalf.

    The CLI's own sentence, in the window, in both directions — the state that
    offers to turn it on, and the state that describes it being on.
    """
    ui = UI.read_text(encoding="utf-8")
    start = ui.index("function stayOpenBlock()")
    block = ui[start:ui.index("\n  }\n", start)]

    for phrase in ("keystore", "running as you can fetch it", "no password", "agent"):
        assert phrase in block, f"the block does not say {phrase!r}"
    # And again at the moment of pressing it, not only as page text: the press opens a question on
    # the page (it was the webview's own confirm()), and the question carries the cost.
    #
    # Bounded to the handler itself. A fixed-size window after the selector
    # passed even with the warning deleted, because the slice ran on into the
    # next handler and found the word there — a guard that cannot fail is worse
    # than none, since it reads as coverage.
    start = ui.index('main.querySelectorAll("[data-stayopen]")')
    handler = ui[start:ui.index("\n    });", start)]
    assert 'askFirst("stayopen-on")' in handler, "turning it on must ask"
    asked = block[block.index('confirmStrip("stayopen-on"'):]
    asked = asked[:asked.index('"Open at restart")')]
    assert "keystore" in asked, "the question must carry the cost, not just ask"
    assert "no password" in asked
    # Only a yes to that question turns it on.
    yes = ui[ui.index('main.querySelectorAll("[data-askyes]")'):]
    yes = yes[:yes.index("\n    });")]
    assert 'id === "stayopen-on") setStayOpen(true)' in yes


def test_the_key_list_keeps_refreshing_while_the_search_box_has_the_caret():
    """The poll skipped every tick while any text field had focus, the search box
    included, so a key added while someone was searching was searched for against
    a list from before it existed: "no results" for a key that was there.
    Verified in a browser against the real page with a stubbed backend: the old
    page made 0 `state` calls in 11 s of searching, this one refreshes and keeps
    the caret."""
    ui = UI.read_text(encoding="utf-8")
    poll = ui[ui.index("let polling = false;"):]
    poll = poll[:poll.index("}, 5000);")]
    assert 'classList?.contains("search")' in poll
    assert "if (typing(focused)) return;" not in poll, "a focused search box must not stop the refresh"
    assert "paintKeepingSearch(focused)" in poll


def test_no_block_on_the_balances_page_is_pulled_over_another():
    """1.10.8 gave the filters row a negative bottom margin and the list slid up under it.

    Every block on that page pushes the next one away with margin-bottom, as `.group` does. A negative
    margin there is how two of them end up drawn on top of each other, and nothing else would notice.
    """
    page = UI.read_text(encoding="utf-8")
    start = page.index("/* ── balances ──")
    styles = page[start:page.index("/* ── end of balances ── */", start)]
    assert ".balfilters" in styles and ".stats4" in styles and ".brow" in styles, "the balances styles moved; point this test at them"
    pulled = re.findall(r"^\s*([^{}\n]+)\{[^}]*margin[a-z-]*:[^;}]*-\d", styles, re.M)
    assert not pulled, f"negative margins on the Balances page: {pulled}"


def test_a_key_added_in_the_window_is_sent_to_the_other_machines():
    """A piped `add` stays on this machine unless asked, and the window's add is piped.

    Liam added a key in the app on each of two paired Macs and neither showed the other's (2026-10-13):
    nothing pushed it, and each machine's collector serves from the grant it started with, which was
    older than the key. Every add the window makes says `--sync`.
    """
    source = RUST.read_text(encoding="utf-8")
    adds = re.findall(r'vec!\["add",[^\]]*\]', source)
    assert len(adds) >= 2, "the window's add commands moved; point this test at them"
    for call in adds:
        assert '"--stdin"' in call and '"--sync"' in call, f"{call} would keep the key on this machine"


def test_a_key_name_can_be_selected_and_copied_and_no_tooltip_is_the_systems():
    """Three things asked for together (Liam, 2026-10-13), each of which a later edit could quietly undo."""
    page = UI.read_text(encoding="utf-8")
    row = page[page.index("function keyRow("):page.index("function markCopied(")]
    # The name is its own selectable element, with a copy button that carries the NAME, not a value.
    assert 'class="mono keyname"' in row
    assert "iconbtn namecopy" in row and 'data-copytext="${esc(k)}" data-copymark="name:${esc(k)}"' in row, \
        "the copy button beside a key's name"
    assert "Copy key name" in row
    # Opening a row from its name gives way to a selection of that name, and the background refresh
    # gives way to a selection anywhere. (The chevron gives way to nothing: see the test below.)
    opener = page[page.index('main.querySelectorAll("[data-open]")'):page.index('main.querySelectorAll("[data-edit]")')]
    assert opener.count("selectingName(k)") == 2, "the click on a name, and the moment after it"
    poll = page[page.index("let polling = false;"):]
    assert "if (selectionIn(main)) return;" in poll[:poll.index("}, 5000);")]
    # Every title is taken over as it appears; nothing is left for the operating system to show.
    assert 'attributeFilter: ["title"]' in page and "function adoptTitles(" in page
    assert page.count("<title>") == 1, "only the document's own; an SVG <title> is a system tooltip too, use data-tip"



def test_the_balances_list_names_its_columns_in_a_header_that_stays_in_view():
    """Liam, 2026-10-19: "we need a sticky table header.. i dont know what each column is". The header is a row
    of the same grid, so it lines up; the card must not clip with overflow: hidden, or the header sticks to the
    card instead of the page; and every row's button is one width, or the columns drift row to row."""
    source = UI.read_text(encoding="utf-8")
    start = source.index("/* ── balances ──")
    styles = source[start:source.index("/* ── end of balances ── */", start)]
    assert ".group.ballist { overflow: clip; }" in styles
    assert "position: sticky" in styles.split(".brow.bhead {")[1].split("}")[0]
    assert ".brow > .act, .bhead .bph { width: 78px;" in styles
    assert "balanceHeader(span) + shownLive.map" in source
    for word in ("Service", "How full", "Left", "Spent"):
        assert word in source.split("function balanceHeader(span)")[1].split("function balanceRow")[0], word


# ── the Keys page: finding a key, opening it, changing it, adding one ───────
#
# Liam, 2026-11-24: "i search a key and there is no way to edit it. i even press the right arrow on it
# and it does nothing when in search wtf. adding a key also has a delay sometimes." Each of those was
# reproduced in the real page against a real store before anything was changed, and each test below
# is one of the things that was wrong.


def _window_source(*names: str) -> str:
    """The source of these top-level functions and constants of the window, to run outside it."""
    page = UI.read_text(encoding="utf-8")
    parts = []
    for name in names:
        found = (re.search(rf"^  (?:async )?function {name}\(.*?^  \}}$", page, re.S | re.M)
                 or re.search(rf"^  const {name} = .*?;$", page, re.M))
        assert found, f"{name} is no longer a top-level function or constant of the window"
        parts.append(found.group(0))
    return "\n".join(parts)


def _run_in_node(script: str):
    import shutil
    import tempfile

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH")
    # From a file: a script this long on a command line is at the mercy of how Windows quotes it.
    with tempfile.TemporaryDirectory() as folder:
        target = Path(folder) / "window.cjs"
        target.write_text(script, encoding="utf-8")
        done = subprocess.run([node, str(target)], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads(done.stdout)


def test_the_chevron_opens_a_row_whatever_is_selected():
    """With a key's name still highlighted from a double-click, every chevron on the page did nothing.

    The handler that opens a row began `if (selectionIn(main)) return;`, for the sake of the name: a
    drag across a name ends in a click, and opening the row would drop the selection. But the chevron
    shares that handler, so any selection anywhere in the page (a name, text in the search box in
    WebKit) made the one control whose only job is opening the row refuse to. Reproduced in the page:
    double-click a name, press its chevron twice, the row stays shut.
    """
    page = UI.read_text(encoding="utf-8")
    opener = page[page.index('main.querySelectorAll("[data-open]")'):page.index('main.querySelectorAll("[data-edit]")')]
    assert "selectionIn(main)" not in opener, "a selection somewhere else must not stop a row opening"
    # The name's own wait-and-see is inside its branch; what is left for the chevron asks nothing.
    name_branch, chevron = opener.split("return;\n      }\n", 1)
    assert 'classList.contains("named")' in name_branch
    assert "toggleKeyRow(k);" in chevron and "selecting" not in chevron and "if (" not in chevron


def test_every_key_row_can_change_its_value_and_clicking_away_saves_nothing():
    """The only way to change a value was to reveal it and then click the picture of it.

    Nothing on the row said so, and a guarded key, which is never revealed, could not be changed in the
    window at all. The box that opened then saved on blur: clicking anywhere else, which is also how a
    person abandons a field, overwrote a working credential with whatever was in it.
    """
    page = UI.read_text(encoding="utf-8")
    row = page[page.index("function keyRow("):page.index("function keyDetail(")]
    assert 'data-edit="${esc(k)}"' in row and "Change value" in row and 'icon(saved ? "check" : "pencil")' in row
    # Offered on every row: not inside the branch that draws the eye, which a guarded key does not get.
    assert row.index('data-edit="${esc(k)}"') > row.index('data-copy="${esc(k)}"')
    assert 'data-editsave="${esc(k)}"' in row and 'data-editcancel="${esc(k)}"' in row
    wiring = page[page.index('main.querySelectorAll("[data-replace]")'):]
    wiring = wiring[:wiring.index("});") + 3]
    assert "onblur" not in wiring, "losing focus must neither save nor discard what was typed"
    assert 'e.key === "Enter"' in wiring and "saveValue(k)" in wiring
    assert 'e.key === "Escape"' in wiring and "cancelEdit(k)" in wiring
    # The clock that hides a revealed value does not close a box somebody is typing into.
    hide = page[page.index("function hideValue(k) {"):]
    assert "delete replacing" not in hide[:hide.index("\n  }\n")]


def test_the_list_of_keys_answers_the_keyboard():
    """With a search typed and its result on screen, the arrows and Enter did nothing at all."""
    page = UI.read_text(encoding="utf-8")
    keys = page[page.index("function keysKey(event, mod)"):]
    keys = keys[:keys.index("\n  }\n") + 5]
    for press in ('"ArrowDown"', '"ArrowUp"', '"Enter"', '"ArrowRight"', '"ArrowLeft"', '"Escape"'):
        assert press in keys, f"{press} does nothing on the list of keys"
    assert 'else if (page === "keys") keysKey(event, mod);' in page
    # The cursor is a name, not a class on a node: a paint replaces every node.
    assert '${k === keyCursor ? " cursor" : ""}' in page
    # Typing in the search box puts the cursor on the best match, so Enter opens it.
    assert 'keyCursor = query.trim() ? (shownKeys()[0] || "") : ""; byKeyboard = !!keyCursor;' in page
    # A value goes to the clipboard from the keyboard only for a cursor the keyboard put on the row,
    # which is when the strip naming the shortcut is on screen: not for a row somebody clicked on.
    copy = keys[keys.index('key.toLowerCase() === "c"') - 120:keys.index('key.toLowerCase() === "c"')]
    assert "row && byKeyboard" in copy
    assert "keyCursor && byKeyboard && !notice" in page[page.index("function listHint()"):page.index("function listHint()") + 300]
    # A key a field has already answered is not answered again by the page.
    assert "event.defaultPrevented" in page


def test_search_takes_words_and_groups_and_lists_the_best_match_first():
    """The search was one substring of the name: "stripe secret" found nothing, because names are
    written with underscores, and a key filed under a vendor its name does not carry could not be found
    by the vendor."""
    script = _window_source("searchScore", "shownKeys") + """
      let query = "", keyFilter = "all", keySort = "group";
      const KEY_FILTERS = [];
      const state = { store: { keys: ["AZURE_OPENAI_KEY", "OPENAI_API_KEY", "OPENAI_ORG_ID", "SK_LIVE_MAIN",
                                      "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "UNRELATED"] },
                      catalog: { group_of: { SK_LIVE_MAIN: "Stripe", OPENAI_API_KEY: "OpenAI" } } };
      const ask = (q) => { query = q; return shownKeys(); };
      console.log(JSON.stringify({ words: ask("stripe secret"), best: ask("openai"), group: ask("stripe"),
                                   spaced: ask("api key"), none: ask("zzz"), all: ask("  ").length }));
    """
    found = _run_in_node(script)
    assert found["words"] == ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]
    assert found["best"] == ["OPENAI_API_KEY", "OPENAI_ORG_ID", "AZURE_OPENAI_KEY"], "names that start with it come first"
    assert "SK_LIVE_MAIN" in found["group"], "found by the group it is filed under"
    assert found["spaced"] == ["OPENAI_API_KEY"], "a space stands for the underscore"
    assert found["none"] == [] and found["all"] == 7


def test_a_key_in_a_folded_or_far_group_is_brought_on_screen():
    """Find anything, then Enter on a key, landed on Keys with nothing opened and nothing in view.

    `showKeyRow` counted how far down the key was in the plain list of names. The page is listed by
    group, which is a different order, and a folded group builds no rows at all.
    """
    script = _window_source("searchScore", "shownKeys", "keyBuckets", "rowOrder", "bringKeyRow") + """
      let query = "", keyFilter = "all", keySort = "group", page = "settings", rowLimit = 60, keyCursor = "";
      const ROW_PAGE = 60, KEY_FILTERS = [], expanded = {}, collapsed = { Zed: true };
      const painted = [];
      const paint = () => painted.push(rowOrder(shownKeys()).slice(0, rowLimit));
      const scrollToKey = () => {};
      const names = (group, n) => Array.from({ length: n }, (_, i) => `${group.toUpperCase()}_${String(i).padStart(3, "0")}`);
      // The store lists Zed's keys first; the page lists the groups in the catalog's order, Zed last.
      const groups = { Alpha: names("Alpha", 70), Beta: names("Beta", 70), Zed: names("Zed", 5) };
      const state = { store: { keys: [...groups.Zed, ...groups.Alpha, ...groups.Beta] }, catalog: { available: true, groups } };
      bringKeyRow("ZED_003", true);
      console.log(JSON.stringify({ page, built: painted[0].includes("ZED_003"), folded: !!collapsed.Zed,
                                   open: !!expanded.ZED_003, cursor: keyCursor }));
    """
    found = _run_in_node(script)
    assert found == {"page": "keys", "built": True, "folded": False, "open": True, "cursor": "ZED_003"}


def test_a_name_is_checked_and_tidied_the_way_the_store_would():
    """`my key` came back from the store as "Nothing on stdin looked like KEY=value"."""
    page = UI.read_text(encoding="utf-8")
    pattern = re.search(r"const KEY_NAME = /(.+?)/;", page)
    assert pattern and pattern.group(1) == passbook._KEY.pattern, "the window and the store disagree on what a name is"
    script = _window_source("KEY_NAME", "storedName", "tidyName") + """
      const state = { store: { keys: ["OPENAI_API_KEY", "lower_case"] } };
      console.log(JSON.stringify({
        tidy: ["my stripe-key", "9lives", "  ", "ok_already"].map(tidyName),
        held: ["openai_api_key", " OPENAI_API_KEY ", "LOWER_CASE", "NEW_ONE"].map(storedName),
        valid: ["A_1", "_x", "1a", "a b", "a-b", ""].map((n) => KEY_NAME.test(n)),
      }));
    """
    found = _run_in_node(script)
    assert found["tidy"] == ["MY_STRIPE_KEY", "_9LIVES", "", "OK_ALREADY"]
    assert found["held"] == ["OPENAI_API_KEY", "OPENAI_API_KEY", "lower_case", ""]
    assert found["valid"] == [True, True, False, False, False, False]
    for name in found["tidy"]:
        assert not name or passbook._KEY.match(name), f"{name} is offered as a name the store would refuse"


def test_adding_a_name_that_is_already_here_is_never_reported_as_added(machine):
    """`passbook add` leaves an existing key alone unless told to replace it, and exits 0.

    The window sent every add without `--replace` and answered every exit 0 with a green "Added": type
    the name of a key you already have and a new value for it, press Add, and the store kept the old
    value while the window said it was done.
    """
    kept = _cli("add", "--stdin", "--sync", home=machine, stdin="DEMO_KEY=a-newer-value\n")
    assert kept.returncode == 0
    # The words the app reads to tell "left alone" from "written".
    assert kept.stdout.startswith("already set, unchanged: DEMO_KEY")
    assert passbook.load()["DEMO_KEY"] == "a-value"

    page = UI.read_text(encoding="utf-8")
    submit = page[page.index("async function submitAdd()"):page.index("// ── what became of a key after it was saved here")]
    assert "const held = storedName(typed);" in submit
    assert 'invoke("add_key", { name: held || typed, value, replace: !!held })' in submit
    assert 'held ? "Replaced" : "Added"' in submit
    hint = page[page.index("function addHint()"):page.index("function openAdd(")]
    assert "is already here" in hint and '"Replace value"' in hint

    source = RUST.read_text(encoding="utf-8")
    add = source[source.index("fn add_key("):source.index("/// A key's name as the store spells one")]
    assert 'line.starts_with("already set, unchanged:")' in add and "return Err(" in add


def test_the_add_form_keeps_what_was_typed_until_the_store_has_it():
    """Pressing Add emptied both fields at once, so a refused add also cost the paste.

    A paint replaces every node, and pressing Add repainted to gray the button. Fields marked
    `data-keep` are carried across every paint; whatever wants one empty empties it first.
    """
    page = UI.read_text(encoding="utf-8")
    panel = page[page.index("function addPanel()"):page.index("function addHint()")]
    assert '<input id="k" data-keep' in panel and '<input id="v" data-keep type="password"' in panel
    paint = page[page.index("  function paint() {"):]
    assert paint.index("const typed = heldTyping();") < paint.index("main.innerHTML =") < paint.index("restoreTyping(typed);")
    submit = page[page.index("async function submitAdd()"):page.index("// ── what became of a key after it was saved here")]
    # Emptied only once the store has answered, and not when it refused.
    refused = submit[submit.index("catch (e) {"):submit.index("f.busy = false; state = next;")]
    assert 'box.value = ""' not in refused and "f.error = said(e);" in refused
    assert 'box.value = ""' in submit[submit.index("f.busy = false; state = next;"):]
    # The form has its own busy: adding one key does not gray every control on the page.
    assert "busy = true" not in submit.replace("f.busy = true", "")
    # Enter adds, from either field.
    wiring = page[page.index("const valueField = document.getElementById(\"v\"), nameField"):]
    wiring = wiring[:wiring.index("const go = document.getElementById(\"addgo\");")]
    assert 'e.key === "Enter"' in wiring and "submitAdd()" in wiring


def test_the_search_box_keeps_its_caret_through_a_repaint():
    """Copy a value, then type a search: 1.4 seconds in, the caret left the box mid-word.

    The "Copied" tick reverts by repainting. `paintKeepingCaret` carried the focused field across, but
    returned as soon as it saw the rebuilt field had text in it, before putting the caret back, and the
    search box always has text in it (the page supplies it). "openai_api" arrived as "openai" in both
    engines. Every paint now puts the caret back in a field marked `data-keep`; `="focus"` for one whose
    text is the page's to supply.
    """
    page = UI.read_text(encoding="utf-8")
    field = page[page.index("function searchField(id)"):page.index("function searchCount(")]
    assert 'data-keep="focus"' in field
    restore = page[page.index("function restoreTyping(kept)"):]
    restore = restore[:restore.index("\n  }\n")]
    # The text is put back only where the page left the field empty, and never into the search box...
    assert 'el.dataset.keep !== "focus" && !el.value && was.value' in restore
    # ...and the caret is put back whether or not there was text to put back.
    assert restore.index("if (!was.focused || el.disabled) continue;") < restore.index("el.focus(")
    assert "setSelectionRange(" in restore
    paint = page[page.index("  function paint() {"):]
    assert "restoreTyping(typed);" in paint[:paint.index('main.querySelectorAll("[data-goto]")')]


def test_add_says_what_it_wrote_before_it_sends_it_anywhere(machine, monkeypatch):
    """Into a pipe, "added: NAME" sat in a buffer until the command ended.

    So the window could not tell "written" from "written and sent to every machine", and waited for the
    slowest machine on the tailnet to learn that a key was in the store on this one. `add` flushes what
    it wrote before it sends anything.
    """
    import io

    import passbook_cli

    pipe = io.BytesIO()
    seen = {}
    monkeypatch.setattr(passbook_cli, "_replicate_write",
                        lambda keys, values: seen.update(on_the_pipe=pipe.getvalue().decode(), keys=list(keys)))
    # Block-buffered, as stdout is when it is a pipe: nothing reaches `pipe` until a flush.
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(pipe, encoding="utf-8", write_through=False))
    monkeypatch.setattr(sys, "stdin", io.StringIO("FLUSHED_FIRST=a-secret-value\n"))

    assert passbook_cli.main(["add", "--stdin", "--sync"]) == 0
    assert seen["keys"] == ["FLUSHED_FIRST"]
    assert seen["on_the_pipe"].startswith("added: FLUSHED_FIRST"), "the sending began before the write was said"
    assert "a-secret-value" not in seen["on_the_pipe"]


def test_the_window_answers_an_add_when_the_key_is_written_not_when_it_is_sent():
    """Every add the window made waited for the push to every other machine before the key appeared.

    `add --sync` writes the key and then sends it to every other machine, so the window's Add button
    sat grayed until the slowest of them had answered. (Asking the same machines for their status took
    23 to 48 seconds on Liam's Mac on 2026-11-24; the sending itself was not timed against them.) The
    app answers on the first thing the CLI says (that the keys are written), leaves the process to
    finish, and reports the sending in `passbook://sent`.
    """
    source = RUST.read_text(encoding="utf-8")
    helper = source[source.index("fn add_then_send("):source.index("/// An `add` that has said what it wrote")]
    assert "add_written(command, input)?" in helper
    spawned = helper[helper.index("std::thread::spawn"):]
    assert "sending.finish()" in spawned and 'app.emit("passbook://sent"' in spawned
    assert helper.rstrip().endswith("Ok(wrote)\n}"), "the answer does not wait for the thread"
    written = source[source.index("fn add_written("):source.index("#[cfg(all(test, unix))]\nmod adding")]
    assert "stdout.read(&mut first)" in written, "answer on the first thing the CLI prints"
    # Having read that, the only process it waits for is one that had already ended (it said nothing).
    assert written.count("wait_with_output()") == 1
    assert written.index("if got == 0 {") < written.index("wait_with_output()") < written.index("return Ok((String::new(), None));")
    # Timed, against a stand-in CLI that takes two seconds to send: `cargo test adding::`.
    assert "fn an_add_answers_when_the_key_is_written_and_not_when_it_has_been_sent()" in source
    # All three ways the window adds a key go through it, each still asking for the keys to be sent.
    assert source.count("add_then_send(&app, &args,") == 3
    assert len(re.findall(r'vec!\["add", "--stdin", "--sync"\]', source)) == 3
    # The event carries names and what the CLI said. The CLI never says a value.
    payload = spawned[spawned.index("serde_json::json!"):spawned.index("}));")]
    assert set(re.findall(r'"(\w+)":', payload)) == {"keys", "ok", "out", "problem"}
    page = UI.read_text(encoding="utf-8")
    assert 'events.listen("passbook://sent", (e) => sendingDone(e?.payload));' in page


def test_nothing_add_prints_is_a_value(machine):
    """What `add` prints is shown in the window, as it goes. None of it may be what was added."""
    said = []
    for args, text in ((("add", "--stdin", "--sync"), "PRINTED_KEY=never-print-me-1\n"),
                       (("add", "--stdin", "--sync"), "PRINTED_KEY=never-print-me-2\n"),
                       (("add", "--stdin", "--sync", "--replace"), "PRINTED_KEY=never-print-me-3\n")):
        done = _cli(*args, home=machine, stdin=text)
        assert done.returncode == 0, done.stderr[-400:]
        said.append(done.stdout + done.stderr)
    assert "never-print-me" not in "".join(said)
    assert "PRINTED_KEY" in said[0] and "PRINTED_KEY" in said[2]


def test_a_refusal_on_the_security_page_is_shown():
    """`said` was defined inside the lock screen's wiring and called from outside it.

    A refused "Seal reads" or "Open at restart" ran `alert(said(e))`, which threw a ReferenceError
    inside the handler: nothing was shown, and the press read as dead.
    """
    page = UI.read_text(encoding="utf-8")
    assert page.count("const said = (error) =>") == 1
    assert page.index("const said = (error) =>") < page.index("async function call(name, args = {})")
    gate = page[page.index("function wireGate()"):page.index("function wireGate()") + 400]
    assert "const said" not in gate
    assert "alert(" not in page, "a native alert is not how this window reports anything"


def test_a_refused_press_gives_back_what_was_typed():
    """"A vault password must be at least 8 characters", and then the name and the password to type again.

    The commands behind most of the window's forms repaint twice, to gray the page and to un-gray it,
    and a repaint rebuilds every field empty. Right when the press worked; when it was refused, the
    fields are given back as they were, including one the page fills in by default ("Owner").
    """
    page = UI.read_text(encoding="utf-8")
    for name in ("call", "callVault", "callSignin"):
        body = page[page.index(f"async function {name}(name, args = {{}})"):]
        body = body[:body.index("\n  }\n")]
        assert body.index("const typed = typedNow();") < body.index("busy = true; paint();"), name
        assert "refused = true" in body[body.index("catch (e)"):body.index("finally")], name
        assert "if (refused) giveBack(typed);" in body[body.index("finally"):], name
    give = page[page.index("function giveBack(held)"):]
    assert "el.value !== value" in give[:give.index("\n  }\n")]


def test_a_repaint_waits_for_a_press_that_is_in_progress():
    """A paint between the mouse going down and coming up took the button away, and the click never happened.

    Reproduced in WebKit and in Chrome: copy one value, then press another row's chevron as the "Copied"
    tick reverts (which repaints), and the row stays shut. The five-second refresh repaints too, whenever
    anything has changed; how often one landed inside a press was not measured.
    """
    page = UI.read_text(encoding="utf-8")
    paint = page[page.index("  function paint() {"):]
    assert paint.index("if (pressHeld) { paintOwed = true; return; }") < paint.index("main.innerHTML =")
    held = page[page.index("const PRESSABLE ="):page.index("  function paint() {")]
    assert 'document.addEventListener("mousedown"' in held and "pressHeld = true;" in held
    # It ends with the mouse coming up, and with anything else that means the press is over.
    for over in ('"mouseup"', '"click"', '"change"', '"keydown"'):
        assert over in held
    assert "if (paintOwed) paint();" in held
    # A dropdown's menu is the system's, and its mouse-up is not always reported: never held for one.
    assert 'closest?.("select")' in held
    # Nor for a press on a scrollbar or on the page itself, which is how a list being scrolled would stop
    # building its rows: only for a press on something there is to press.
    assert "!event.target?.closest?.(PRESSABLE)" in held and 'const PRESSABLE = "button, a, ' in held
    # And never for good.
    assert "pressTimer = setTimeout(pressOver," in held


def test_the_window_reads_how_the_sending_went_in_words_the_cli_still_says():
    """`passbook://sent` carries what `add` printed, and the window picks four things out of it.

    They are sentences written for a terminal. Reworded there, the window would stop saying which machine
    a key did not reach, and nothing else would notice.
    """
    cli = (PACKAGE / "passbook_cli.py").read_text(encoding="utf-8")
    page = UI.read_text(encoding="utf-8")
    done = page[page.index("function sendingDone(report)"):]
    done = done[:done.index("\n  }\n")]
    said_and_read = [
        ("""print(f"sent to {len(outcome['sent'])} machine(s): """, r"/^sent to (\d+) machine/m"),
        ('print(f"  not sent to {host} ({why}); queued for', r"/not sent to (\S+) \(([^)]*)\)/g"),
        ('print(f"not sent to any other machine: {where}. "', "/not sent to any other machine/"),
        (r'print(f"\n{key} is also on {len(items)} service(s):")', r"/^(\S+) is also on (\d+) service/m"),
    ]
    for said, read in said_and_read:
        assert said in cli, f"the command line no longer says: {said}"
        assert read in done, f"the window no longer reads: {read}"
    # And a paste of a whole .env does not become a notice of every name in it.
    assert "all.length > 3" in done


def test_a_check_of_the_record_that_could_not_be_run_says_so():
    """Pressing Verify when the check itself failed answered "This record has not been verified yet".

    Which is what the page said before the press, so the press read as dead. Found by pressing every kind
    of control on every page against a backend that refuses everything, and listing the ones that put
    nothing on screen: this was the only one of 11 pages' worth that was not simply already selected.
    """
    body = re.search(r"function recordPage\(\) \{(.*?)\n  \}\n", UI.read_text(encoding="utf-8"), re.S).group(1)
    assert "const failed = !chain.busy && checked && intact === null && checked.detail;" in body
    assert "The check could not be run: ${checked.detail}" in body
    # And it is still not called verified.
    assert 'intact ? "Verified" : "Not checked"' in body



# ── the other pages (2026-11-25) ──────────────────────────────────────────────


def test_nothing_in_the_window_asks_through_the_webviews_own_dialogs():
    """Allowing reads again, opening at restart and disconnecting GitHub each asked through the
    webview's confirm(): a modal from outside the page that stops it until answered. Each now asks on
    the page, beside the button, and Forget on a sign-in (which deletes its tokens, and which the CLI
    itself will not do without --yes) asks too. Walked in WebKit and Chrome: no native dialog fired."""
    ui = UI.read_text(encoding="utf-8")
    script = ui[ui.index("<script>"):]
    code = "\n".join(line.split("//")[0] for line in script.splitlines())   # comments may name them
    assert not re.search(r"(?<![\w.])(confirm|alert|prompt)\(", code), "a native dialog is still called"
    for asked in ('askFirst("reads-open")', 'askFirst("stayopen-on")', 'askFirst("ghdisconnect")',
                  'askFirst("oaforget:" + b.dataset.oaforget)'):
        assert asked in ui, f"{asked} does not ask first"
    for strip in ('confirmStrip("reads-open"', 'confirmStrip("stayopen-on"', 'confirmStrip("ghdisconnect"',
                  'confirmStrip("oaforget:" + s.id'):
        assert strip in ui, f"{strip} is asked but never shown"
    # Enter on an open question is never the yes, and Escape closes it.
    ask = ui[ui.index("function askFirst("):]
    ask = ask[:ask.index("\n  }\n")]
    assert '[data-askno]")?.focus(' in ask
    assert 'event.key === "Escape" && asking' in ui


def test_a_sign_in_is_added_from_a_form_and_its_secret_never_rides_an_argument():
    """Adding a sign-in was two terminal commands printed on the page with a placeholder to fill in.
    It is a form now, and the client secret goes to the CLI on stdin like every other value."""
    ui = UI.read_text(encoding="utf-8")
    assert "passbook oauth add google work --client-id" not in ui, "the terminal recipe is still the way in"
    assert 'invoke("oauth_add", form)' in ui
    assert 'id="sf-secret" type="password"' in ui
    page = ui[ui.index("function signinsPage()"):]
    page = page[:page.index("\n  }\n")]
    assert "${signinFormPanel()}" in page

    rust = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    command = rust[rust.index("fn oauth_add("):]
    command = command[:command.index("\n}\n")]
    assert "--client-secret-stdin" in rust[rust.index("fn oauth_add_args("):rust.index("fn oauth_add(")]
    assert "Zeroizing::new(client_secret)" in command
    assert "stdin.write_all(" in command
    block = re.search(r"tauri::generate_handler!\[(.*?)\]", rust, re.S)
    assert block and "oauth_add" in block.group(1)
    granted = set(json.loads(
        (REPO / "app/src-tauri/capabilities/default.json").read_text(encoding="utf-8"))["permissions"])
    assert "allow-oauth-add" in granted


def test_the_cli_takes_a_sign_in_the_way_the_window_writes_it(tmp_path):
    """The window writes options as --name=value and the positionals after --, so a typed label that
    starts with a dash is a label. This is the CLI accepting exactly that, with the secret on stdin."""
    env = {**os.environ, "HIVE_HOME": str(tmp_path / "hive"), "HOME": str(tmp_path),
           "PYTHONPATH": str(REPO / "src"), "PASSBOOK_FLEET": "off", "PASSBOOK_NO_BRIEF": "1",
           "PASSBOOK_KEYSTORE": "off", "PASSBOOK_NO_NOTIFY": "1"}
    for gone in ("HIVE_ENV_FILES", "HIVE_WORKSPACE"):
        env.pop(gone, None)
    (tmp_path / "hive").mkdir()
    done = subprocess.run([sys.executable, "-m", "passbook_cli", "oauth", "add", "--client-id=-an-id",
                           "--client-secret-stdin", "--", "google", "-work"],
                          input="a-client-secret\n", capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert done.returncode == 0, done.stderr
    listed = subprocess.run([sys.executable, "-m", "passbook_cli", "oauth", "--json"],
                            capture_output=True, text=True, env=env, cwd=str(tmp_path))
    ids = [g["id"] for g in json.loads(listed.stdout)]
    assert ids == ["google:-work"]
    assert "a-client-secret" not in done.stdout + done.stderr + listed.stdout


def test_the_devices_check_says_which_device_it_is_waiting_on():
    """The check asks every other device and took up to 48 s with nothing on screen but "Checking the
    other devices…". The CLI reports each step, the app passes each one on, and the page shows each
    device as it answers and how long the rest have been waited on."""
    cli = (REPO / "src/passbook_cli.py").read_text(encoding="utf-8")
    status = cli[cli.index("def _sync_status("):cli.index("def cmd_sync(")]
    assert '"@progress "' in status and "file=sys.stderr" in status, "progress must stay off stdout"
    assert "ThreadPoolExecutor" in status, "devices are asked together, not one after another"

    rust = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    command = rust[rust.index("fn sync_status("):rust.index("fn status_watched(")]
    assert '"--progress"' in command and '"passbook://sync-progress"' in command
    assert "unrecognized arguments: --progress" in command, "an older CLI must still answer"

    ui = UI.read_text(encoding="utf-8")
    assert 'events.listen("passbook://sync-progress", (e) => syncStep(e?.payload))' in ui
    panel = ui[ui.index("function syncPanel()"):]
    panel = panel[:panel.index("\n  }\n")]
    assert "syncProgressNote()" in panel and "syncProgressRows()" in panel


def test_the_security_page_asks_for_a_password_only_where_one_exists():
    """With no vault yet, opening at restart, a recovery code and profiles each asked for a "vault
    password" that did not exist: three password boxes on a first-run screen whose one real action was
    fourth on the page. And with the vault shut, signing in was offered twice."""
    ui = UI.read_text(encoding="utf-8")
    page = ui[ui.index("function vaultPage()"):]
    page = page[:page.index("\n  }\n")]
    shown = page[page.index("const noVault"):]
    assert "${noVault ? `<p" in shown and "${stayOpenBlock()}${recoveryPanel()}${profiles}" in shown
    assert shown.index("${signIn}${encryption}") < shown.index("${readsBlock()}"), "what needs doing comes first"
    assert 'id="si-pw2"' not in ui, "signing in is offered once"
    # Turning encryption off is a press away, with what it costs, not a password box that is always out.
    panel = ui[ui.index("function encryptionPanel("):]
    panel = panel[:panel.index("\n  }\n")]
    assert "data-unsealopen" in panel and panel.index("unsealing ?") < panel.index('id="sl-pw"')
