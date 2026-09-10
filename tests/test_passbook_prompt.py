# SPDX-License-Identifier: Apache-2.0
"""The secret prompt echoes bullets, and never the secret.

Driven through a real pseudo-terminal rather than by patching, because the whole
point of the change is what a TERMINAL does: `getpass` echoes nothing, and a
paste into nothing reads as a paste that did not work. A test that stubs the
terminal away would pass on the version that shows no feedback at all.
"""
from __future__ import annotations

import os
import pty
import select
import subprocess
import sys
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")

# Read the prompt back through the pty, then the value on stdout, so a test can
# tell "what the terminal showed" from "what the caller received".
DRIVER = """
import sys
sys.path.insert(0, {src!r})
from passbook_prompt import hidden_input
value = hidden_input("Key: ")
sys.stdout.write("VALUE[" + value + "]")
sys.stdout.flush()
"""


def _read_until(fd: int, seen: bytearray, done, timeout: float) -> bool:
    """Pump `fd` into `seen` until `done(seen)` or the timeout runs out."""
    while not done(seen):
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return False
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return False
        if not chunk:
            return False
        seen.extend(chunk)
    return True


def _run_in_tty(keystrokes: bytes, *, timeout: float = 10.0) -> str:
    """Run the prompt under a pty, type `keystrokes`, return everything shown."""
    primary, secondary = pty.openpty()
    process = subprocess.Popen(
        [sys.executable, "-c", DRIVER.format(src=SRC)],
        stdin=secondary, stdout=secondary, stderr=secondary,
        close_fds=True,
    )
    os.close(secondary)
    seen = bytearray()
    try:
        # WAIT for the prompt before typing. Writing first is a race the real
        # thing does not have: until the child clears ECHO the pty's own line
        # discipline echoes the keystrokes and hands over a canonical line, so
        # an early write tests the terminal rather than this code.
        assert _read_until(primary, seen, lambda buf: b"Key: " in buf, timeout), (
            f"the prompt never appeared; saw: {bytes(seen)!r}")
        os.write(primary, keystrokes)
        while True:
            ready, _, _ = select.select([primary], [], [], timeout)
            if not ready:
                break
            try:
                chunk = os.read(primary, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen.extend(chunk)
            if b"VALUE[" in seen and b"]" in seen.split(b"VALUE[", 1)[1]:
                break
    finally:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:                 # pragma: no cover
            process.kill()
        os.close(primary)
    return seen.decode("utf-8", "replace")


def _value(shown: str) -> str:
    assert "VALUE[" in shown, f"the prompt never returned; saw: {shown!r}"
    return shown.split("VALUE[", 1)[1].split("]", 1)[0]


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only; Windows uses the msvcrt path")
def test_typing_shows_one_bullet_per_character_and_never_the_secret():
    shown = _run_in_tty(b"hunter2\r")
    assert _value(shown) == "hunter2"
    # The secret must not appear anywhere the terminal drew.
    drawn = shown.split("VALUE[", 1)[0]
    assert "hunter2" not in drawn
    assert drawn.count("•") == len("hunter2")
    assert "Key: " in drawn


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_a_paste_arrives_whole_and_is_fully_bulleted():
    # The case that prompted this: a long value pasted in one go. It must not be
    # truncated, and every character must be acknowledged.
    pasted = "dW50cnVzdGVkIGNvbW1lbnQ6IHRlc3Qta2V5LW5vdC1yZWFs"
    shown = _run_in_tty(pasted.encode() + b"\r")
    assert _value(shown) == pasted
    drawn = shown.split("VALUE[", 1)[0]
    assert pasted not in drawn
    assert drawn.count("•") == len(pasted)


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_backspace_removes_a_character_and_a_bullet():
    shown = _run_in_tty(b"abcx\x7f\r")
    assert _value(shown) == "abc"
    drawn = shown.split("VALUE[", 1)[0]
    # Four drawn, one erased: the erase is "\b \b", so three bullets survive.
    assert drawn.count("•") == 4
    assert drawn.count("\b \b") == 1


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_ctrl_u_clears_what_was_typed():
    shown = _run_in_tty(b"wrong\x15right\r")
    assert _value(shown) == "right"


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_an_arrow_key_is_swallowed_rather_than_typed():
    # ESC [ C is Right. Its printable tail must not become part of the value —
    # a key with a stray "[C" in it fails much later, at use.
    shown = _run_in_tty(b"ab\x1b[Ccd\r")
    assert _value(shown) == "abcd"


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX-only")
def test_a_multibyte_character_is_one_bullet_not_one_per_byte():
    shown = _run_in_tty("é€".encode() + b"\r")
    assert _value(shown) == "é€"
    drawn = shown.split("VALUE[", 1)[0]
    assert drawn.count("•") == 2


def test_without_a_terminal_it_falls_through_to_getpass(monkeypatch):
    # Pipes, CI and every test that drives a prompt keep the old path exactly,
    # which is why none of the existing suites needed to change behaviour.
    import getpass as real_getpass

    sys.path.insert(0, SRC)
    import passbook_prompt

    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(real_getpass, "getpass", lambda prompt="": f"fell-through:{prompt}")
    assert passbook_prompt.hidden_input("Key: ") == "fell-through:Key: "


def test_the_bullet_degrades_when_the_terminal_cannot_encode_it():
    sys.path.insert(0, SRC)
    import passbook_prompt

    class Ascii:
        encoding = "ascii"

    class Utf8:
        encoding = "utf-8"

    assert passbook_prompt._bullet_for(Ascii()) == "*"
    assert passbook_prompt._bullet_for(Utf8()) == "•"
