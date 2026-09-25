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


@pytest.mark.parametrize("bad", ["", "   ", "/abs/path", "../escape", "a/../b", "semi;colon",
                                 "$(whoami)", "back`tick`", "a" * 97])
def test_a_service_name_is_a_label(bad):
    """A label, not a path or a shell fragment. Slashes and colons are allowed
    since 1.9.0 so a recorded service can say what it is (`github:owner/repo`);
    what a path or a shell would act on still is not."""
    with pytest.raises(services.ServiceError):
        services.attach("API_KEY", bad, "cmd", registry=services._blank())


@pytest.mark.parametrize("good", ["worker:api", "github:owner/repo@production",
                                  "cf-secrets-store:0123abcd/NAME", "hivemindos website"])
def test_a_label_can_say_what_the_service_is(good):
    registry = services.attach("API_KEY", good, "cmd", registry=services._blank())
    assert registry["bindings"]["API_KEY"][0]["service"] == good


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


# ── 1.9.0: the record fills itself, and a rotation uses it ─────────────────
#
# Everything below runs the real CLI against a throwaway store, with fake
# `wrangler` and `gh` on PATH that write what they receive on stdin to a file.
# Values are fake and are checked by reading those files, never by printing.

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _platform import needs_a_posix_shell  # noqa: E402

OLD, NEW = "fake-old-value-111", "fake-new-value-222"

FAKE_TOOL = """#!/bin/sh
out="$FAKE_SINKS/$(basename "$0")-$(echo "$*" | tr ' /' '__')"
cat > "$out"
echo "ok from $(basename "$0")"
"""


@pytest.fixture
def box(tmp_path):
    """A throwaway store, a project directory, and fake sinks on PATH."""
    home = tmp_path / "hive"
    home.mkdir()
    tools = tmp_path / "bin"
    tools.mkdir()
    landed = tmp_path / "landed"
    landed.mkdir()
    for name in ("wrangler", "gh"):
        path = tools / name
        path.write_text(FAKE_TOOL)
        path.chmod(0o755)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "wrangler.toml").write_text('name = "site-api"\n')
    env = {"PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}",
           "FAKE_SINKS": str(landed)}

    class Box:
        pass

    b = Box()
    b.home, b.landed, b.project, b.env = home, landed, project, env

    def run(args, stdin=None, cwd=None):
        environment = {**os.environ, "HIVE_HOME": str(home), "PASSBOOK_KEYSTORE": "file", **env}
        for inherited in ("PASSBOOK_SERVICE", "PASSBOOK_GRANT", "API_KEY"):
            environment.pop(inherited, None)
        return subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args],
                              capture_output=True, text=True, env=environment,
                              input=stdin, cwd=str(cwd or project))

    b.run = run
    b.landed_value = lambda name: (landed / name).read_text() if (landed / name).exists() else None
    assert run(["add", f"API_KEY={OLD}"]).returncode == 0
    return b


def _no_value_in(*results):
    for result in results:
        for text in (result.stdout, result.stderr):
            assert OLD not in text and NEW not in text, text


@needs_a_posix_shell
def test_a_run_that_puts_a_key_on_a_worker_records_it(box):
    done = box.run(["run", "--only", "API_KEY", "--", "sh", "-c",
                    'printf %s "$API_KEY" | wrangler secret put API_KEY'])
    assert done.returncode == 0, done.stderr
    assert "recorded API_KEY on worker:site-api" in done.stderr
    listed = json.loads(box.run(["services", "list", "API_KEY", "--json"]).stdout)["API_KEY"]
    assert [(item["service"], item["lastStatus"], item["source"]) for item in listed] == \
        [("worker:site-api", "ok", "run")]
    assert listed[0]["command"] == "wrangler secret put API_KEY --name site-api"
    assert listed[0]["stdin"] is True and listed[0]["cwd"] == str(box.project)
    _no_value_in(done)


@needs_a_posix_shell
def test_a_run_that_fails_records_nothing(box):
    """A push that did not land must not be listed as a service that holds it."""
    failed = box.run(["run", "--only", "API_KEY", "--", "sh", "-c",
                      'printf %s "$API_KEY" | wrangler secret put API_KEY; exit 3'])
    assert failed.returncode == 3
    assert "No service is recorded" in box.run(["services"]).stdout


@needs_a_posix_shell
def test_a_run_without_only_says_how_to_have_it_recorded(box):
    done = box.run(["run", "--", "wrangler", "secret", "put", "API_KEY"], stdin="x")
    assert "Name the key with --only KEY" in done.stderr
    assert "No service is recorded" in box.run(["services"]).stdout


def test_used_in_on_a_run_records_a_place_or_a_push(box):
    placed = box.run(["run", "--only", "API_KEY", "--used-in", "NYC Mac launchd plist",
                      "--note", "restart the agent", "--", sys.executable, "-c", "pass"])
    assert placed.returncode == 0, placed.stderr
    assert "NYC Mac launchd plist — restart the agent" in box.run(["services"]).stdout

    pushed = box.run(["run", "--only", "API_KEY", "--used-in", "vps-box",
                      "--push-command", "ssh vps 'cat > /etc/app.key'", "--push-stdin",
                      "--", sys.executable, "-c", "pass"])
    assert pushed.returncode == 0, pushed.stderr
    listed = json.loads(box.run(["services", "list", "API_KEY", "--json"]).stdout)["API_KEY"]
    assert listed[0]["service"] == "vps-box" and listed[0]["stdin"] is True

    refused = box.run(["run", "--used-in", "somewhere", "--", sys.executable, "-c", "pass"])
    assert refused.returncode != 0 and "--only" in refused.stderr


def test_used_in_add_list_remove(box):
    added = box.run(["used-in", "API_KEY", "add", "GitHub Actions in acme/infra", "--note", "by hand"])
    assert added.returncode == 0, added.stderr
    also = box.run(["used-in", "add", "API_KEY", "NYC Mac launchd plist"])
    assert also.returncode == 0, "the verb first reads the same"
    listed = json.loads(box.run(["used-in", "list", "--json"]).stdout)
    assert [p["where"] for p in listed["API_KEY"]["places"]] == \
        ["GitHub Actions in acme/infra", "NYC Mac launchd plist"]
    history = box.run(["history", "API_KEY"])
    assert "by hand    GitHub Actions in acme/infra" in history.stdout
    gone = box.run(["used-in", "API_KEY", "remove", "nyc mac launchd plist"])
    assert gone.returncode == 0, "places match without regard to case"
    missing = box.run(["used-in", "API_KEY", "remove", "nowhere"])
    assert missing.returncode == 1


@needs_a_posix_shell
def test_push_to_performs_it_and_records_it(box):
    dry = box.run(["push", "API_KEY", "--to", "wrangler:edge", "--dry-run"])
    assert "wrangler secret put API_KEY --name edge" in dry.stdout
    assert not any(box.landed.iterdir()), "a dry run touches nothing"

    done = box.run(["push", "API_KEY", "--to", "wrangler:edge", "--to", "gh:acme/app"])
    assert done.returncode == 0, done.stderr
    assert box.landed_value("wrangler-secret_put_API_KEY_--name_edge") == OLD
    assert box.landed_value("gh-secret_set_API_KEY_--repo_acme_app") == OLD
    listed = {item["service"]: item for item in
              json.loads(box.run(["services", "list", "API_KEY", "--json"]).stdout)["API_KEY"]}
    assert set(listed) == {"worker:edge", "github:acme/app"}
    assert all(item["lastStatus"] == "ok" and item["source"] == "passbook push"
               for item in listed.values())
    assert "pushed to worker:edge" in box.run(["history", "API_KEY"]).stdout
    _no_value_in(dry, done)


def test_push_pushes_the_stores_value_not_a_stale_environment(box):
    """An agent started by `passbook run` holds the value from its launch. A
    push from inside it sent that old copy over the new one everywhere."""
    landed = box.home / "landed.txt"
    box.run(["services", "attach", "API_KEY", "worker", "--command", f"cat > {landed}", "--stdin"])
    environment = {**os.environ, "HIVE_HOME": str(box.home), "PASSBOOK_KEYSTORE": "file",
                   "API_KEY": "fake-stale-launch-value"}
    environment.pop("PASSBOOK_GRANT", None)
    done = subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), "services", "update",
                           "API_KEY"], capture_output=True, text=True, env=environment)
    assert done.returncode == 0, done.stderr
    assert landed.read_text() == OLD


def test_the_record_is_read_from_the_store_not_the_environment(box):
    """`passbook run` without --only hands the record to the child as a
    variable. Reading that launch-time copy and writing it back erased every
    service recorded since."""
    box.run(["services", "attach", "API_KEY", "first", "--command", "true"])
    stale = box.run(["services", "list", "--json"]).stdout
    box.run(["services", "attach", "API_KEY", "second", "--command", "true"])
    environment = {**os.environ, "HIVE_HOME": str(box.home), "PASSBOOK_KEYSTORE": "file",
                   services.REGISTRY_KEY: services.dump({"bindings": json.loads(stale)})}
    subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), "services", "attach",
                    "API_KEY", "third", "--command", "true"], env=environment, check=True,
                   capture_output=True)
    names = [item["service"] for item in
             json.loads(box.run(["services", "list", "API_KEY", "--json"]).stdout)["API_KEY"]]
    assert names == ["first", "second", "third"]


def test_the_record_is_dated_so_sync_replicates_changes(box):
    """Sync never overwrites a copy whose age it does not know, so an undated
    record reached other machines once and no change to it ever followed."""
    box.run(["services", "attach", "API_KEY", "worker", "--command", "true"])
    box.run(["used-in", "API_KEY", "add", "somewhere"])
    ages = json.loads((box.home / ".env.meta.json").read_text())["updatedAt"]
    assert services.REGISTRY_KEY in ages and services.USED_IN_KEY in ages


def test_a_sealed_record_is_refused_not_overwritten(box):
    """Read as empty, a record this process cannot open was replaced by the one
    entry being added. It has to stop instead."""
    store = box.home / ".env"
    store.write_text(store.read_text() + f"{services.REGISTRY_KEY}=hive-sealed:v2:opaque\n")
    listed = box.run(["services"])
    assert listed.returncode == 1 and "passbook unseal --only" in listed.stderr
    attached = box.run(["services", "attach", "API_KEY", "worker", "--command", "true"])
    assert attached.returncode == 1
    assert f"{services.REGISTRY_KEY}=hive-sealed:v2:opaque" in store.read_text()


def test_sealing_the_store_leaves_the_record_readable(tmp_path, monkeypatch):
    import passbook
    import passbook_vault as vault

    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    passbook.ensure(app="test")
    passbook.set_values({"API_KEY": OLD})
    services.write(services.attach("API_KEY", "worker:api", "true", registry=services._blank()))
    services.write_places(services.add_place("API_KEY", "somewhere", record=services.parse_places(None)))
    profile = vault.create_profile("Owner", password="a long enough password", root=home)["id"]
    dek = vault.unlock_with_password(profile, "a long enough password", root=home)
    result = vault.seal_store(dek, profile_id=profile, root=home)
    assert "API_KEY" in result["sealed"]
    assert services.REGISTRY_KEY not in result["sealed"] and services.USED_IN_KEY not in result["sealed"]
    assert services.bindings("API_KEY")[0]["service"] == "worker:api"
    assert services.places("API_KEY")[0]["where"] == "somewhere"
    assert vault.status(root=home)["fully_sealed"], "the record is not a readable secret"


@needs_a_posix_shell
def test_rotate_pushes_everywhere_keeps_the_old_one_and_lists_the_rest(box):
    box.run(["push", "API_KEY", "--to", "wrangler:edge"])
    failing = "echo 'remote said no' >&2; exit 4"
    box.run(["services", "attach", "API_KEY", "broken-box", "--command", failing])
    box.run(["used-in", "API_KEY", "add", "NYC Mac launchd plist"])

    rotated = box.run(["rotate", "API_KEY", "--stdin"], stdin=NEW + "\n")
    assert rotated.returncode == 1, "a service that did not take it is a failure"
    assert box.landed_value("wrangler-secret_put_API_KEY_--name_edge") == NEW
    assert "broken-box" in rotated.stdout and "FAILED — remote said no" in rotated.stdout
    assert "worker:edge" in rotated.stdout
    assert "Update these by hand" in rotated.stdout and "NYC Mac launchd plist" in rotated.stdout
    assert "passbook rotate API_KEY --confirm" in rotated.stdout
    assert "passbook services retry API_KEY" in rotated.stderr
    kept = json.loads((box.home / "rotations.json").read_text())
    assert kept["API_KEY"]["previous"] == OLD
    assert (box.home / "rotations.json").stat().st_mode & 0o077 == 0

    again = box.run(["rotate", "API_KEY", "--stdin"], stdin="fake-third-333\n")
    assert again.returncode == 1 and "still open" in again.stderr, \
        "a second rotation would overwrite the value being kept"

    confirmed = box.run(["rotate", "API_KEY", "--confirm"])
    assert confirmed.returncode == 0
    assert "API_KEY" not in json.loads((box.home / "rotations.json").read_text())
    _no_value_in(rotated, again, confirmed)


@needs_a_posix_shell
def test_rollback_restores_the_store_and_every_service_that_got_the_new_one(box):
    box.run(["push", "API_KEY", "--to", "wrangler:edge"])
    late = box.home / "late.txt"
    box.run(["services", "attach", "API_KEY", "late-box", "--command", "exit 4"])
    box.run(["rotate", "API_KEY", "--stdin"], stdin=NEW + "\n")
    # Fixed and retried after the rotation: it now holds the NEW value too.
    box.run(["services", "attach", "API_KEY", "late-box", "--command", f"cat > {late}", "--stdin"])
    assert box.run(["services", "retry"]).returncode == 0
    assert late.read_text() == NEW

    rolled = box.run(["rotate", "API_KEY", "--rollback"])
    assert rolled.returncode == 0, rolled.stderr + rolled.stdout
    assert box.landed_value("wrangler-secret_put_API_KEY_--name_edge") == OLD
    assert late.read_text() == OLD, "the retried service is rolled back as well"
    assert f"API_KEY={OLD}" in (box.home / ".env").read_text()
    assert "API_KEY" not in json.loads((box.home / "rotations.json").read_text())
    _no_value_in(rolled)


def test_rotate_refuses_what_it_cannot_do(box):
    assert box.run(["rotate", "NOPE", "--stdin"], stdin="x\n").returncode == 1
    same = box.run(["rotate", "API_KEY", "--stdin"], stdin=OLD + "\n")
    assert same.returncode == 1 and "already has" in same.stderr
    assert box.run(["rotate", "API_KEY", "--rollback"]).returncode == 1
    no_push = box.run(["rotate", "API_KEY", "--stdin", "--no-push"], stdin=NEW + "\n")
    assert no_push.returncode == 0 and "No service is recorded" in no_push.stdout


def test_a_corrected_command_keeps_a_failure_for_retry(box):
    box.run(["services", "attach", "API_KEY", "box", "--command", "exit 4"])
    box.run(["services", "update", "API_KEY"])
    box.run(["services", "attach", "API_KEY", "box", "--command", "true"])
    retried = box.run(["services", "retry"])
    assert "retrying API_KEY on 1 service(s)" in retried.stdout, \
        "correcting the command does not put the new value there; retry has to"


def test_add_with_update_services_all_fails_when_a_push_does(box):
    box.run(["services", "attach", "API_KEY", "box", "--command", "exit 4"])
    replaced = box.run(["add", "--replace", "--update-services", "all", f"API_KEY={NEW}"])
    assert replaced.returncode == 1, "a script read exit 0 as rotated everywhere"
    assert "replaced: API_KEY" in replaced.stdout
