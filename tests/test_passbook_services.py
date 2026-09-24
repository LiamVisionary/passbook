# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Which services hold a key, and what happens when that key is replaced.

Replacing a credential is half a rotation. The copies already sitting on a
Worker, a VPS or a CI secret store keep serving the old value until somebody
pushes the new one to each of them, and the list of where those copies are was
never written down anywhere. These tests pin the three properties that make
writing it down worth anything: the record travels between machines, the value
never reaches a command line, and a service that fails is remembered rather than
lost with the run that failed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

import passbook_services as services  # noqa: E402


# ── the record itself ──────────────────────────────────────────────────────

def test_it_replicates_because_it_is_an_ordinary_key():
    """The whole design rests on this: the registry is a store key, so it rides
    the replication the store already has. If it were ever excluded from sync,
    machines would silently disagree about where a key has been copied to."""
    import passbook_sync

    assert not passbook_sync.is_local_only(services.REGISTRY_KEY)


def test_a_binding_survives_a_round_trip_and_sorts_stably():
    registry = services.attach("API_KEY", "worker", "wrangler secret put API_KEY",
                               registry=services._blank())
    registry = services.attach("API_KEY", "ci", "gh secret set API_KEY", registry=registry)
    text = services.dump(registry)
    assert services.dump(services.parse(text)) == text, "an unchanged registry must not look changed to sync"
    assert [item["service"] for item in services.parse(text)["bindings"]["API_KEY"]] == ["ci", "worker"]


def test_unreadable_text_is_an_empty_registry_not_an_error():
    """A corrupted record must never stop somebody adding a credential."""
    for bad in (None, "", "{", "[]", '{"bindings": 3}', '{"bindings": {"K": "nope"}}'):
        assert services.parse(bad) == {"version": services.VERSION, "bindings": {}}


def test_attaching_the_same_service_twice_corrects_it_rather_than_duplicating():
    registry = services.attach("API_KEY", "worker", "old command", registry=services._blank())
    registry = services.attach("API_KEY", "worker", "new command", registry=registry)
    items = registry["bindings"]["API_KEY"]
    assert len(items) == 1 and items[0]["command"] == "new command"


def test_detaching_the_last_service_leaves_no_empty_key_behind():
    registry = services.attach("API_KEY", "worker", "cmd", registry=services._blank())
    registry, removed = services.detach("API_KEY", "worker", registry=registry)
    assert removed and "API_KEY" not in registry["bindings"]
    _, removed_again = services.detach("API_KEY", "worker", registry=registry)
    assert not removed_again


@pytest.mark.parametrize("bad", ["", "   ", "no spaces/slashes" + "/x", "a" * 80])
def test_a_service_name_is_a_label(bad):
    with pytest.raises(services.ServiceError):
        services.attach("API_KEY", bad, "cmd", registry=services._blank())


def test_a_command_may_not_interpolate_the_value():
    """The value would land on a command line, where `ps` shows it to every
    process on the box. The environment is how it travels."""
    for bad in ("echo {{value}}", "set-secret {{ secret }}", "curl -d ${PASSBOOK_VALUE}"):
        with pytest.raises(services.ServiceError) as caught:
            services.attach("API_KEY", "worker", bad, registry=services._blank())
        assert "ps" in str(caught.value)


# ── putting the value there ────────────────────────────────────────────────

def _binding(**extra):
    base = {"service": "worker", "command": "true", "stdin": False, "cwd": ""}
    base.update(extra)
    return base


def test_the_value_goes_in_the_environment_and_never_on_the_argv():
    seen = {}

    def runner(command, **kwargs):
        seen["command"] = command
        seen["env"] = kwargs["env"]
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(command, 0, "", "")

    ok, _ = services.run_binding("API_KEY", "s3cret-value", _binding(command="deploy"), runner=runner)
    assert ok
    assert "s3cret-value" not in seen["command"], "a secret on the command line is visible to ps"
    assert seen["env"]["API_KEY"] == "s3cret-value"
    assert seen["env"]["PASSBOOK_SERVICE"] == "worker"
    assert seen["input"] == "", "stdin is opt-in"


def test_stdin_is_how_wrangler_style_commands_are_fed():
    seen = {}

    def runner(command, **kwargs):
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(command, 0, "", "")

    services.run_binding("API_KEY", "s3cret-value", _binding(stdin=True), runner=runner)
    assert seen["input"] == "s3cret-value"


def test_a_failing_command_reports_its_last_line_with_the_value_removed():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, "", "setting up\nrejected s3cret-value outright")

    ok, detail = services.run_binding("API_KEY", "s3cret-value", _binding(), runner=runner)
    assert not ok
    assert "s3cret-value" not in detail, "a failure must not echo the secret back into our own record"
    assert "rejected" in detail


def test_a_hanging_command_is_a_failure_not_a_hang():
    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 5)

    ok, detail = services.run_binding("API_KEY", "v" * 10, _binding(), runner=runner, timeout=5)
    assert not ok and "timed out" in detail


def test_one_failure_never_stops_the_rest():
    """The point is to get as many services onto the new value as possible and
    leave a list of the ones that did not, not to stop at the first problem."""
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1 if command == "b" else 0, "", "no")

    results = services.update("API_KEY", "value-here",
                              [_binding(service="a", command="a"),
                               _binding(service="b", command="b"),
                               _binding(service="c", command="c")], runner=runner)
    assert calls == ["a", "b", "c"], "sequential, and none skipped"
    assert [entry["ok"] for entry in results] == [True, False, True]


def test_a_failure_outlives_the_run_that_caused_it():
    registry = services.attach("API_KEY", "worker", "cmd", registry=services._blank())
    registry = services.record("API_KEY", "worker", ok=False, error="403 from the provider",
                               registry=registry)
    outstanding = services.failures(registry)
    assert [key for key, _ in outstanding] == ["API_KEY"]
    assert outstanding[0][1]["lastError"] == "403 from the provider"
    registry = services.record("API_KEY", "worker", ok=True, registry=registry)
    assert services.failures(registry) == [], "a later success clears it"


# ── choosing which ones ────────────────────────────────────────────────────

def test_all_or_a_selection_by_number_or_by_name():
    items = [_binding(service="a"), _binding(service="b"), _binding(service="c")]
    assert services.select(items, "all") == items
    assert services.select(items, "") == items
    assert [item["service"] for item in services.select(items, "1,3")] == ["a", "c"]
    assert [item["service"] for item in services.select(items, "b")] == ["b"]
    assert [item["service"] for item in services.select(items, "2 2 1")] == ["b", "a"], "no duplicates"


def test_a_typo_in_the_selection_refuses_rather_than_pushing_to_fewer():
    """Silently skipping an unrecognised pick would leave the rotation half done
    and look exactly like it had finished."""
    items = [_binding(service="a"), _binding(service="b")]
    for bad in ("3", "0", "nope", "1,nope"):
        with pytest.raises(services.ServiceError):
            services.select(items, bad)


# ── the command line ───────────────────────────────────────────────────────

def _run(args, home, **extra):
    environment = {
        **dict(__import__("os").environ),
        "HIVE_HOME": str(home),
        "PASSBOOK_KEYSTORE": "file",
        **extra,
    }
    return subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args],
                          capture_output=True, text=True, env=environment)


def test_attach_list_and_detach_round_trip(tmp_path):
    home = tmp_path / "hive"
    home.mkdir()
    assert _run(["add", "API_KEY=abc123xyz"], home).returncode == 0

    attached = _run(["services", "attach", "API_KEY", "worker",
                     "--command", "echo pushing", "--stdin"], home)
    assert attached.returncode == 0, attached.stderr
    assert "worker" in attached.stdout

    listed = _run(["services", "list", "API_KEY", "--json"], home)
    assert listed.returncode == 0, listed.stderr
    payload = json.loads(listed.stdout)
    assert payload["API_KEY"][0]["service"] == "worker"
    assert payload["API_KEY"][0]["stdin"] is True

    gone = _run(["services", "detach", "API_KEY", "worker"], home)
    assert gone.returncode == 0
    assert "No service is recorded" in _run(["services"], home).stdout


def test_update_pushes_the_current_value_and_dry_run_pushes_nothing(tmp_path):
    home = tmp_path / "hive"
    home.mkdir()
    landed = home / "landed.txt"
    _run(["add", "API_KEY=abc123xyz"], home)
    _run(["services", "attach", "API_KEY", "worker",
          "--command", f"printenv API_KEY > {landed}"], home)

    dry = _run(["services", "update", "API_KEY", "--dry-run"], home)
    assert dry.returncode == 0 and not landed.exists(), "a dry run must not touch anything"

    done = _run(["services", "update", "API_KEY"], home)
    assert done.returncode == 0, done.stderr + done.stdout
    assert landed.read_text().strip() == "abc123xyz"


def test_a_failed_push_is_recorded_and_retry_finds_only_that_one(tmp_path):
    home = tmp_path / "hive"
    home.mkdir()
    _run(["add", "API_KEY=abc123xyz"], home)
    _run(["services", "attach", "API_KEY", "good", "--command", "true"], home)
    # Commands run under the platform's shell: cmd.exe on Windows, where `;` is
    # not a separator and `echo nope >&2; exit 3` echoes and exits 0.
    failing = "echo nope 1>&2 & exit 3" if os.name == "nt" else "echo nope >&2; exit 3"
    _run(["services", "attach", "API_KEY", "bad", "--command", failing], home)

    pushed = _run(["services", "update", "API_KEY"], home)
    assert pushed.returncode == 1, "a failure must not report success"
    assert "did not take: bad" in pushed.stderr

    listed = json.loads(_run(["services", "list", "API_KEY", "--json"], home).stdout)
    states = {item["service"]: item["lastStatus"] for item in listed["API_KEY"]}
    assert states == {"good": "ok", "bad": "failed"}

    retried = _run(["services", "retry"], home)
    assert "retrying API_KEY on 1 service(s)" in retried.stdout, "only the one that failed"


def test_replacing_a_key_offers_its_services_and_a_pipe_is_never_pushed_to(tmp_path):
    """A script piping a new value in is not asked and nothing is pushed: writing
    to a dozen live services is not something to do to somebody who did not ask."""
    home = tmp_path / "hive"
    home.mkdir()
    landed = home / "landed.txt"
    _run(["add", "API_KEY=abc123xyz"], home)
    _run(["services", "attach", "API_KEY", "worker",
          "--command", f"printenv API_KEY > {landed}"], home)

    quiet = _run(["add", "--replace", "API_KEY=second-value"], home)
    assert quiet.returncode == 0
    assert "is also on 1 service(s)" in quiet.stdout
    assert not landed.exists(), "nothing may be pushed without somebody saying so"
    assert "passbook services update API_KEY" in quiet.stderr

    asked = _run(["add", "--replace", "--update-services", "all", "API_KEY=third-value"], home)
    assert asked.returncode == 0, asked.stderr
    assert landed.read_text().strip() == "third-value"


def test_update_services_none_stays_silent(tmp_path):
    home = tmp_path / "hive"
    home.mkdir()
    _run(["add", "API_KEY=abc123xyz"], home)
    _run(["services", "attach", "API_KEY", "worker", "--command", "true"], home)
    quiet = _run(["add", "--replace", "--update-services", "none", "API_KEY=next-value"], home)
    assert "service(s)" not in quiet.stdout
