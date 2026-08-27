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
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1]


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
        capture_output=True, text=True, input=stdin, cwd=str(PACKAGE),
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


UI = PACKAGE / "app" / "ui" / "index.html"


def _page_keys() -> list[str]:
    """The keys in the `PAGES` list — one per entry in the source list."""
    block = re.search(r"const PAGES = \[(.*?)\];", UI.read_text(), re.S)
    assert block, "PAGES list not found in the window source"
    return re.findall(r'\["([a-z-]+)",', block.group(1))


def _routes() -> dict[str, str]:
    """The `page -> function` map the window paints from."""
    block = re.search(r"const body = \{(.*?)\}\[page\]\(\);", UI.read_text(), re.S)
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
    source = UI.read_text()
    absent = [name for name in _routes().values()
              if f"function {name}(" not in source]
    assert not absent, f"routes pointing at nothing: {absent}"


def test_every_goto_button_lands_on_a_real_page():
    routes = _routes()
    targets = set(re.findall(r'data-goto="([a-z-]+)"', UI.read_text()))
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
    source = UI.read_text()
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

    source = UI.read_text()
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
    source = UI.read_text()
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
    source = UI.read_text()
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
    source = UI.read_text()
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
    source = UI.read_text()
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
    generator = PACKAGE / "scripts/sync-permissions.py"
    assert generator.exists(), "the permission generator is missing"
    done = subprocess.run([sys.executable, str(generator), "--check"],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout.strip() or done.stderr.strip()

    # And the grant really does name every command, not merely agree with a
    # generator that could itself be looking at the wrong thing.
    source = (PACKAGE / "app/src-tauri/src/main.rs").read_text()
    block = re.search(r"tauri::generate_handler!\[(.*?)\]", source, re.S)
    assert block, "no generate_handler! block"
    commands = [name for name in dict.fromkeys(
        re.findall(r"[A-Za-z_][A-Za-z0-9_]*", block.group(1)))
        if f"fn {name}(" in source]
    assert commands, "no commands found in the handler list"
    granted = set(json.loads(
        (PACKAGE / "app/src-tauri/capabilities/default.json").read_text())["permissions"])
    missing = [name for name in commands
               if f"allow-{name.replace('_', '-')}" not in granted]
    assert not missing, f"commands the window may not call: {missing}"


def test_the_source_list_stays_short():
    """Eight destinations is a filing cabinet, not an app.

    Six of the eight were about how PassBook works rather than what is in it —
    a page for the background service, one for the ledger, one for machine
    grants, one that listed all 281 keys a second time so it could carry a
    three-way switch. Nothing was missing and nothing could be found. Anything
    that is not one of the few things a person opens this app to do belongs on
    the settings shelf, which is one press away and does not cost a slot.
    """
    source = UI.read_text()
    block = re.search(r"const PAGES = \[(.*?)\n  \];", source, re.S)
    assert block, "PAGES not found"
    entries = re.findall(r'\["(\w+)"', block.group(1))
    assert len(entries) <= 4, f"the source list has grown back to {len(entries)}: {entries}"


def test_every_settings_pane_is_reachable_and_leads_back():
    """Tucked away has to still mean available.

    A pane moved off the source list is reachable only through its settings
    row, so the row has to name a real page and the page has to draw the way
    back — otherwise moving something out of sight is the same as deleting it.
    """
    source = UI.read_text()
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
    source = UI.read_text()
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
    body = re.search(r"function recordPage\(\) \{(.*?)\n  \}\n", UI.read_text(), re.S)
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
