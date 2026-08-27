# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Conformance tests for the PassBook standard, Python reference implementation.

Every test names a property from SPEC.md. Run against any implementation that
claims conformance by pointing the import at it.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _platform import assert_private  # noqa: E402

import passbook  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1]


@pytest.fixture
def hive(tmp_path, monkeypatch):
    """An isolated machine: HIVE_HOME points at a fresh root."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    return home


# ── 1. location ────────────────────────────────────────────────────────────


def test_the_root_is_hive_home_then_the_default(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "explicit"))
    assert passbook.root() == tmp_path / "explicit"

    monkeypatch.delenv("HIVE_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert passbook.root() == tmp_path / "home" / ".hivemindos"


def test_the_env_path_is_named_before_it_exists(hive):
    assert passbook.env_path() == hive / ".env"
    assert not passbook.env_path().is_file()


# ── 2. format ──────────────────────────────────────────────────────────────


def test_the_format_matches_what_a_shell_would_source():
    parsed = passbook.parse_env_text(
        "\n".join([
            "# a comment",
            "",
            "PLAIN=value",
            "export EXPORTED=exported-value",
            'QUOTED="quoted value"',
            "SINGLE='single value'",
            "EMPTY=",
            "not a pair",
            "WINS=first",
            "WINS=second",
        ])
    )
    assert parsed == {
        "PLAIN": "value",
        "EXPORTED": "exported-value",
        "QUOTED": "quoted value",
        "SINGLE": "single value",
        "WINS": "second",
    }


# ── 3. precedence ──────────────────────────────────────────────────────────


def test_the_hive_env_is_a_default_and_never_an_override(hive, monkeypatch):
    passbook.ensure(app="test")
    passbook.set_values({"SHARED_ONLY": "from-hive", "ALSO_IN_PROCESS": "from-hive"})
    monkeypatch.setenv("ALSO_IN_PROCESS", "from-process")

    values = passbook.load()

    assert values["SHARED_ONLY"] == "from-hive"
    assert values["ALSO_IN_PROCESS"] == "from-process"


def test_a_project_file_beats_the_hive_env_and_loses_to_the_process(hive, tmp_path, monkeypatch):
    passbook.ensure(app="test")
    passbook.set_values({"A": "hive", "B": "hive", "C": "hive"})
    project = tmp_path / "project.env"
    project.write_text("B=project\nC=project\n", encoding="utf-8")
    monkeypatch.setenv("C", "process")

    values = passbook.load(project_files=[project])

    assert (values["A"], values["B"], values["C"]) == ("hive", "project", "process")


def test_apply_fills_only_what_is_missing_and_reports_names(hive, monkeypatch):
    passbook.ensure(app="test")
    passbook.set_values({"FILL_ME": "from-hive", "ALREADY_SET": "from-hive"})
    monkeypatch.setenv("ALREADY_SET", "from-process")

    filled = passbook.apply()

    assert "FILL_ME" in filled
    assert "ALREADY_SET" not in filled
    assert os.environ["FILL_ME"] == "from-hive"
    assert os.environ["ALREADY_SET"] == "from-process"


# ── 4. convergence: provisioning IS linking ────────────────────────────────


def test_the_first_app_creates_the_canonical_store(hive):
    result = passbook.ensure(app="first-app", name="First App")

    assert result["provisioned"] is True
    assert result["adopted"] is False
    assert Path(result["path"]) == hive / ".env"
    assert result["apps"] == ["first-app"]


def test_every_later_app_adopts_it_rather_than_forking(hive):
    passbook.ensure(app="first-app")
    passbook.set_values({"OPENAI_API_KEY": "shared-value"})

    second = passbook.ensure(app="second-app", name="Second App")

    assert second["provisioned"] is False
    assert second["adopted"] is True
    # The whole point: one path, one store, both apps on it.
    assert Path(second["path"]) == hive / ".env"
    assert "OPENAI_API_KEY" in second["keys"]
    assert sorted(second["apps"]) == ["first-app", "second-app"]
    assert list((hive).glob("**/.env")) == [hive / ".env"], "no app may create a second store"


def test_ensure_is_idempotent(hive):
    first = passbook.ensure(app="app")
    again = passbook.ensure(app="app")

    assert first["provisioned"] is True
    assert again["provisioned"] is False
    assert again["apps"] == ["app"]


def test_a_seed_never_overwrites_what_is_already_shared(hive):
    passbook.ensure(app="first")
    passbook.set_values({"OPENAI_API_KEY": "the-users-real-key"})

    passbook.ensure(app="second", seed={"OPENAI_API_KEY": "an-app-default"})

    # Read the STORE, not the merged view: load() gives the process environment
    # precedence by design, so asserting through it would pass or fail on
    # whatever an unrelated test happened to leave in os.environ.
    stored = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    assert stored["OPENAI_API_KEY"] == "the-users-real-key"


# ── 5. writing is additive ─────────────────────────────────────────────────


def test_an_existing_key_is_kept_unless_overwrite_is_asked_for(hive):
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "original"})

    kept = passbook.set_values({"KEY": "replacement"})
    assert kept["kept"] == ["KEY"]
    assert passbook.load()["KEY"] == "original"

    replaced = passbook.set_values({"KEY": "replacement"}, overwrite=True)
    assert replaced["updated"] == ["KEY"]
    assert passbook.load()["KEY"] == "replacement"


def test_comments_and_unrelated_keys_survive_a_write(hive):
    passbook.ensure(app="app")
    path = passbook.env_path()
    path.write_text("# keep me\nUNRELATED=untouched\n", encoding="utf-8")

    passbook.set_values({"NEW_KEY": "new-value"})

    text = path.read_text(encoding="utf-8")
    assert "# keep me" in text
    assert "UNRELATED=untouched" in text
    assert passbook.load()["NEW_KEY"] == "new-value"


def test_a_value_that_needs_quoting_round_trips(hive):
    passbook.ensure(app="app")
    passbook.set_values({"SPACED": "two words", "HASHED": "a#b", "QUOTED": 'say "hi"'})

    values = passbook.load()
    assert values["SPACED"] == "two words"
    assert values["HASHED"] == "a#b"
    assert values["QUOTED"] == 'say "hi"'


def test_an_invalid_key_is_refused(hive):
    passbook.ensure(app="app")
    with pytest.raises(ValueError, match="not a valid environment key"):
        passbook.set_values({"not-a-key": "value"})


# ── 6. permissions and atomicity ───────────────────────────────────────────


def test_the_store_is_private(hive):
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})

    assert_private(passbook.env_path(), 0o600)
    assert_private(hive, 0o700)


def test_a_loose_mode_is_tightened_never_loosened(hive):
    passbook.ensure(app="app")
    passbook.env_path().chmod(0o644)

    passbook.ensure(app="app")

    assert_private(passbook.env_path(), 0o600)


def test_a_write_leaves_no_temporary_files_behind(hive):
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})

    assert [item.name for item in hive.iterdir() if item.name.startswith(".hive-env-")] == []


# ── 7. disclosure ──────────────────────────────────────────────────────────


def test_no_status_surface_returns_a_value(hive):
    passbook.ensure(app="app")
    passbook.set_values({"SECRET_KEY": "super-secret-value"})

    rendered = json.dumps(passbook.status()) + passbook.describe() + json.dumps(passbook.key_names())

    assert "SECRET_KEY" in rendered, "names are public"
    assert "super-secret-value" not in rendered, "values are not"


# ── 8. containers ──────────────────────────────────────────────────────────


@pytest.mark.skipif(sys.platform != "darwin",
                    reason="the App Sandbox container is a macOS thing")
def test_a_sandbox_container_is_reported_rather_than_written_into(tmp_path, monkeypatch):
    monkeypatch.delenv("HIVE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "Library" / "Containers" / "app.id" / "Data"))

    result = passbook.ensure(app="sandboxed")

    assert result["ok"] is False
    assert result["provisioned"] is False
    assert "sandbox container" in result["reason"]
    assert "HIVE_HOME" in result["remedy"]
    with pytest.raises(passbook.ContainerisedHomeError):
        passbook.set_values({"KEY": "value"})


def test_an_explicit_hive_home_is_the_way_out_of_a_container(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "Library" / "Containers" / "app.id" / "Data"))
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "real"))

    result = passbook.ensure(app="sandboxed")

    assert result["ok"] is True
    assert Path(result["path"]) == tmp_path / "real" / ".env"


# ── 9. the two implementations must agree ──────────────────────────────────


NODE_TWIN = Path(__file__).resolve().parents[1] / "passbook.mjs"
# ESM imports a URL, not a path. On Windows a bare path is refused outright,
# and interpolating one through `repr` leaves single backslashes that
# JavaScript reads as escapes, so `D:\a\passbook` silently becomes
# `D:apassbook`. A file URL is what every platform accepts.
NODE_TWIN_URL = NODE_TWIN.as_uri()


@pytest.mark.skipif(not NODE_TWIN.is_file(), reason="the Node twin is not present")
def test_the_node_twin_resolves_the_same_store_and_reads_what_python_wrote(hive):
    """An Electron main process and a Python backend in the same app must see
    exactly one store. If these two ever disagree, every app that mixes runtimes
    silently forks its credentials."""
    passbook.ensure(app="python-side", name="Python Side")
    passbook.set_values({"SHARED_KEY": "written-by-python", "QUOTED_KEY": "two words"})

    script = f"""
        import {{ ensure, load, status, keyNames }} from {json.dumps(NODE_TWIN_URL)};
        const joined = ensure({{ app: 'node-side', name: 'Node Side' }});
        const values = load();
        process.stdout.write(JSON.stringify({{
            path: status().path,
            provisioned: joined.provisioned,
            apps: status().apps.sort(),
            keys: keyNames(),
            shared: values.SHARED_KEY,
            quoted: values.QUOTED_KEY,
        }}));
    """
    completed = subprocess.run(
        [_node(), "--input-type=module", "-e", script],
        capture_output=True, text=True, check=True,
        env={**os.environ, "HIVE_HOME": str(hive)},
    )
    seen = json.loads(completed.stdout)

    assert seen["path"] == str(passbook.env_path()), "both runtimes must resolve one path"
    assert seen["provisioned"] is False, "the Node side must adopt, not re-provision"
    assert seen["shared"] == "written-by-python"
    assert seen["quoted"] == "two words", "the quoting rules must match"
    assert seen["apps"] == ["node-side", "python-side"]
    assert "SHARED_KEY" in seen["keys"]


@pytest.mark.skipif(not NODE_TWIN.is_file(), reason="the Node twin is not present")
def test_python_reads_what_the_node_twin_wrote(hive):
    script = f"""
        import {{ ensure, setValues }} from {json.dumps(NODE_TWIN_URL)};
        ensure({{ app: 'node-first', name: 'Node First' }});
        setValues({{ NODE_WRITTEN: 'written-by-node', NODE_SPACED: 'two words' }});
        process.stdout.write('ok');
    """
    subprocess.run(
        [_node(), "--input-type=module", "-e", script],
        capture_output=True, text=True, check=True,
        env={**os.environ, "HIVE_HOME": str(hive)},
    )

    adopted = passbook.ensure(app="python-second")

    assert adopted["provisioned"] is False, "Node created it; Python must adopt it"
    assert passbook.load()["NODE_WRITTEN"] == "written-by-node"
    assert passbook.load()["NODE_SPACED"] == "two words"
    assert sorted(adopted["apps"]) == ["node-first", "python-second"]


def _node() -> str:
    import shutil

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH")
    return node


# ── 10. workspace scoping ──────────────────────────────────────────────────


def _manifest(hive, entries, active=""):
    (hive).mkdir(parents=True, exist_ok=True)
    (hive / "workspaces.json").write_text(
        json.dumps({"version": 1, "activeWorkspaceId": active, "workspaces": entries}),
        encoding="utf-8",
    )


def test_main_is_the_hive_root_not_a_second_store(hive):
    """HivemindOS already calls the root store "main". Treating it as a separate
    workspace would put a second .env beside the one everything reads."""
    passbook.ensure(app="app")
    assert passbook.workspace_env_path("main") == passbook.env_path()


def test_a_workspace_sees_its_own_keys_on_top_of_the_machines(hive, monkeypatch):
    passbook.ensure(app="app")
    passbook.set_values({"MACHINE_KEY": "machine", "SHADOWED": "machine"})
    scoped = passbook.workspace_env_path("acme")
    scoped.parent.mkdir(parents=True, exist_ok=True)
    scoped.write_text("SHADOWED=workspace\nWORKSPACE_KEY=workspace\n", encoding="utf-8")
    monkeypatch.setenv("HIVE_WORKSPACE", "acme")

    values = passbook.load()

    assert values["MACHINE_KEY"] == "machine", "an unset key is inherited"
    assert values["SHADOWED"] == "workspace", "the more specific store wins"
    assert values["WORKSPACE_KEY"] == "workspace"


def test_a_non_inheriting_workspace_cannot_read_the_machine_store(hive, monkeypatch):
    """The scoping that matters: an agent pinned to a client's workspace must
    not be able to read the machine's own credentials."""
    passbook.ensure(app="app")
    passbook.set_values({"PERSONAL_KEY": "do-not-leak"})
    scoped = passbook.workspace_env_path("client")
    scoped.parent.mkdir(parents=True, exist_ok=True)
    scoped.write_text("CLIENT_KEY=client-value\n", encoding="utf-8")
    _manifest(hive, [{"id": "client", "envPath": str(scoped), "inherit": False}])
    monkeypatch.setenv("HIVE_WORKSPACE", "client")

    values = passbook.load()

    assert values["CLIENT_KEY"] == "client-value"
    assert "PERSONAL_KEY" not in values
    assert "PERSONAL_KEY" not in passbook.key_names()


def test_one_workspace_never_sees_a_siblings_keys(hive, monkeypatch):
    passbook.ensure(app="app")
    for name, key in (("alpha", "ALPHA_KEY"), ("beta", "BETA_KEY")):
        path = passbook.workspace_env_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{key}=value\n", encoding="utf-8")

    monkeypatch.setenv("HIVE_WORKSPACE", "alpha")
    assert "ALPHA_KEY" in passbook.key_names()
    assert "BETA_KEY" not in passbook.key_names()


def test_the_manifest_decides_where_a_workspace_store_lives(hive, monkeypatch):
    elsewhere = hive / "somewhere-else" / "custom.env"
    elsewhere.parent.mkdir(parents=True, exist_ok=True)
    elsewhere.write_text("CUSTOM=value\n", encoding="utf-8")
    _manifest(hive, [{"id": "moved", "envPath": str(elsewhere)}], active="moved")

    assert passbook.workspace() == "moved"
    assert passbook.workspace_env_path("moved") == elsewhere
    assert passbook.load()["CUSTOM"] == "value"


def test_hive_workspace_overrides_the_manifests_active_choice(hive, monkeypatch):
    _manifest(hive, [{"id": "one"}, {"id": "two"}], active="one")
    assert passbook.workspace() == "one"

    monkeypatch.setenv("HIVE_WORKSPACE", "two")
    assert passbook.workspace() == "two"


def test_an_invalid_workspace_id_is_refused(hive, monkeypatch):
    monkeypatch.setenv("HIVE_WORKSPACE", "../escape")
    with pytest.raises(ValueError, match="not a valid workspace id"):
        passbook.workspace()


def test_switching_the_active_workspace_writes_hivemindos_manifest(hive, monkeypatch):
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    _manifest(hive, [{"id": "one", "name": "One"}, {"id": "two"}], active="one")

    was = passbook.set_active_workspace("two")

    assert was == "one"
    assert passbook.workspace() == "two"
    # The same file HivemindOS reads, not a second registry beside it.
    payload = json.loads((hive / "workspaces.json").read_text(encoding="utf-8"))
    assert payload["activeWorkspaceId"] == "two"
    # Everything else in the manifest survives the write.
    assert [entry["id"] for entry in payload["workspaces"]] == ["one", "two"]
    assert payload["workspaces"][0]["name"] == "One"


def test_switching_to_an_unknown_workspace_is_refused(hive, monkeypatch):
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    _manifest(hive, [{"id": "one"}], active="one")

    with pytest.raises(ValueError, match="no workspace called"):
        passbook.set_active_workspace("nope")
    with pytest.raises(ValueError, match="not a valid workspace id"):
        passbook.set_active_workspace("../escape")
    assert passbook.workspace() == "one"


def test_a_pinned_process_keeps_its_workspace_when_the_manifest_moves(hive, monkeypatch):
    """HIVE_WORKSPACE is a deliberate pin, usually an agent working for one
    client. A person switching the desktop app must not re-point it."""
    _manifest(hive, [{"id": "one"}, {"id": "two"}], active="one")
    monkeypatch.setenv("HIVE_WORKSPACE", "one")
    assert passbook.workspace_pinned() is True

    passbook.set_active_workspace("two")

    assert passbook.workspace() == "one"
    payload = json.loads((hive / "workspaces.json").read_text(encoding="utf-8"))
    assert payload["activeWorkspaceId"] == "two"


def test_a_workspace_label_falls_back_to_its_id(hive, monkeypatch):
    _manifest(hive, [{"id": "one", "name": "Main shared brain"}, {"id": "two"}], active="one")
    assert passbook.workspace_label("one") == "Main shared brain"
    assert passbook.workspace_label("two") == "two"
    assert passbook.workspace_label("never-heard-of-it") == "never-heard-of-it"


# ── 11. access stamps (optional companion) ─────────────────────────────────

import passbook_seal  # noqa: E402
import passbook_stamp  # noqa: E402


def test_a_scoped_request_returns_only_what_was_asked_for(hive):
    passbook.ensure(app="app")
    passbook.set_values({"WANTED": "yes", "NOT_WANTED": "no"})
    passbook.set_recorder(None)

    got = passbook.request(["WANTED"], app="app")

    assert got == {"WANTED": "yes"}, "asking for one key must not hand over the store"


def test_a_request_leaves_a_receipt_naming_keys_but_never_values(hive):
    passbook.ensure(app="app")
    passbook.set_values({"OPENAI_API_KEY": "sk-super-secret"})
    passbook.set_recorder(passbook_stamp.recorder("app", workspace="main", actor_did="did:key:zA"))
    try:
        passbook.request(["OPENAI_API_KEY"], app="app", reason="a render")
    finally:
        passbook.set_recorder(None)

    ledger = (hive / passbook_stamp.PROOF_FILENAME).read_text(encoding="utf-8")
    assert "OPENAI_API_KEY" in ledger, "the key NAME is the point of the receipt"
    assert "sk-super-secret" not in ledger, "a value must never reach the ledger"
    row = passbook_stamp.read_stamps(root=hive)[-1]
    assert row["op"] == "read" and row["actorDid"] == "did:key:zA" and row["reason"] == "a render"


def test_the_ledger_is_hash_chained_and_verifies(hive):
    for _ in range(3):
        passbook_stamp.stamp(op="read", keys=["A_KEY"], app="app", root=hive)

    result = passbook_stamp.verify_chain(root=hive)

    assert result["ok"] is True and result["rows"] == 3


def test_removing_an_access_from_the_ledger_is_detected(hive):
    """The property the ledger exists for: an access cannot be un-recorded."""
    for name in ("FIRST", "SECOND", "THIRD"):
        passbook_stamp.stamp(op="read", keys=[name], app="app", root=hive)
    ledger = hive / passbook_stamp.PROOF_FILENAME
    rows = ledger.read_text(encoding="utf-8").strip().split("\n")
    ledger.write_text(rows[0] + "\n" + rows[2] + "\n", encoding="utf-8")

    result = passbook_stamp.verify_chain(root=hive)

    assert result["ok"] is False
    assert any("removed" in item["reason"] for item in result["breaks"])


def test_editing_a_recorded_access_is_detected(hive):
    passbook_stamp.stamp(op="read", keys=["REAL_KEY"], app="app", root=hive)
    ledger = hive / passbook_stamp.PROOF_FILENAME
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("REAL_KEY", "OTHER_KEY"), encoding="utf-8")

    result = passbook_stamp.verify_chain(root=hive)

    assert result["ok"] is False
    assert any("its own hash" in item["reason"] for item in result["breaks"])


def test_the_chain_format_is_the_one_gitlawb_already_verifies():
    """Byte-compatible with proof-chain.ts, so GitLawb's verifier reads these
    rows and a credential access sits in the same evidence model as every other
    proof. Drift here would fork the ledger format."""
    row = {"b": 1, "a": [1, "two", None], "z": None, "nested": {"y": 2, "x": "é"}}
    assert passbook_stamp.canonical_json(row) == '{"a":[1,"two",null],"b":1,"nested":{"x":"é","y":2}}'
    assert passbook_stamp.proof_sha256("x").startswith("sha256:")


def test_stamping_never_breaks_a_credential_read(hive, monkeypatch):
    """A ledger that can take the app down is worse than no ledger."""
    def explode(**_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(passbook_stamp, "stamp", explode)
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})
    passbook.set_recorder(passbook_stamp.recorder("app"))
    try:
        assert passbook.request(["KEY"], app="app") == {"KEY": "value"}
    finally:
        passbook.set_recorder(None)


# ── 12. encryption at rest ─────────────────────────────────────────────────


@pytest.fixture
def sealing_key(monkeypatch):
    monkeypatch.setenv("HIVE_ENV_KEY", "dGVzdC1rZXktMzItYnl0ZXMtbG9uZy1mb3Itc2VhbGluZyE=")


def test_sealing_leaves_names_readable_and_values_unreadable(hive, sealing_key):
    passbook.ensure(app="app")
    passbook.set_values({"OPENAI_API_KEY": "sk-super-secret"})

    passbook_seal.seal_store()

    on_disk = passbook.env_path().read_text(encoding="utf-8")
    assert "OPENAI_API_KEY" in on_disk, "names stay readable so status surfaces still work"
    assert "sk-super-secret" not in on_disk, "the value is not on disk any more"
    assert passbook_seal.status()["fully_sealed"] is True


def test_a_sealed_store_reads_back_unchanged_through_every_caller(hive, sealing_key):
    passbook.ensure(app="app")
    passbook.set_values({"HIVE_TEST_SEALED_A": "sk-super-secret", "HIVE_TEST_SEALED_B": "pex"})
    passbook_seal.seal_store()
    passbook.set_recorder(None)

    # Sealing must be invisible: no call site changes to adopt it.
    assert passbook.load()["HIVE_TEST_SEALED_A"] == "sk-super-secret"
    assert passbook.request(["HIVE_TEST_SEALED_B"], app="app") == {"HIVE_TEST_SEALED_B": "pex"}
    assert passbook.key_names() == ["HIVE_TEST_SEALED_A", "HIVE_TEST_SEALED_B"]


def test_a_store_copied_off_the_machine_is_inert(hive, sealing_key, monkeypatch):
    """The whole point of Tier 1: a leaked file, a backup, or a synced home
    directory yields names and nothing else."""
    passbook.ensure(app="app")
    passbook.set_values({"HIVE_TEST_STOLEN": "sk-super-secret"})
    passbook_seal.seal_store()

    monkeypatch.delenv("HIVE_ENV_KEY")           # the thief has the file, not the key
    monkeypatch.setattr(passbook_seal, "_key", lambda **_: (_ for _ in ()).throw(RuntimeError("no key")))

    assert passbook.load().get("HIVE_TEST_STOLEN") is None
    # Names, and nothing else — exactly what this test's own name promises.
    # They were never secret: the key name sits in the clear next to its
    # ciphertext in the file the thief is holding, so hiding them here would
    # protect nothing while making a locked machine claim it has no keys.
    assert passbook.key_names() == ["HIVE_TEST_STOLEN"]
    assert "sk-super-secret" not in (passbook.env_path()).read_text(encoding="utf-8")


def test_a_mixed_store_works_so_sealing_can_be_gradual(hive, sealing_key):
    passbook.ensure(app="app")
    passbook.set_values({"SEALED_ONE": "first"})
    passbook_seal.seal_store()
    passbook.set_values({"ADDED_LATER": "plaintext-for-now"})

    values = passbook.load()
    assert values["SEALED_ONE"] == "first"
    assert values["ADDED_LATER"] == "plaintext-for-now"
    assert passbook_seal.status()["plaintext"] == ["ADDED_LATER"]


def test_sealing_preserves_comments_and_permissions(hive, sealing_key):
    passbook.ensure(app="app")
    passbook.env_path().write_text("# a note\nKEY=value\n", encoding="utf-8")

    passbook_seal.seal_store()

    assert "# a note" in passbook.env_path().read_text(encoding="utf-8")
    assert_private(passbook.env_path(), 0o600)


# ── 13. removal ────────────────────────────────────────────────────────────


def test_removal_takes_only_the_named_keys(hive):
    passbook.ensure(app="app")
    passbook.set_values({"KEEP_ME": "a", "DROP_ME": "b", "ALSO_KEEP": "c"})

    result = passbook.remove_values(["DROP_ME"])

    assert result["removed"] == ["DROP_ME"]
    assert passbook.key_names() == ["ALSO_KEEP", "KEEP_ME"]


def test_removing_a_key_that_was_never_there_is_not_an_error(hive):
    passbook.ensure(app="app")
    passbook.set_values({"PRESENT": "a"})

    result = passbook.remove_values(["ABSENT", "PRESENT"])

    assert result["removed"] == ["PRESENT"]
    assert result["absent"] == ["ABSENT"]


def test_removal_preserves_comments_and_permissions(hive):
    passbook.ensure(app="app")
    passbook.env_path().write_text("# a note\nGONE=x\nSTAYS=y\n", encoding="utf-8")

    passbook.remove_values(["GONE"])

    text = passbook.env_path().read_text(encoding="utf-8")
    assert "# a note" in text
    assert "GONE" not in text
    assert "STAYS=y" in text
    assert_private(passbook.env_path(), 0o600)


def test_removal_refuses_inside_a_sandbox_container(hive, monkeypatch):
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})
    monkeypatch.delenv("HIVE_HOME")
    monkeypatch.setenv("APP_SANDBOX_CONTAINER_ID", "com.example.app")
    monkeypatch.setenv("HOME", str(hive.parent / "Library" / "Containers" / "com.example.app" / "Data"))

    with pytest.raises(passbook.ContainerisedHomeError):
        passbook.remove_values(["KEY"])


def test_the_node_twin_removes_the_same_way(hive):
    """Parity: a key removed by either runtime is gone for both."""
    passbook.ensure(app="app")
    passbook.set_values({"SHARED": "a", "DOOMED": "b"})

    script = f"""
        import {{ removeValues, keyNames }} from {json.dumps(NODE_TWIN_URL)};
        removeValues(['DOOMED']);
        process.stdout.write(JSON.stringify(keyNames()));
    """
    completed = subprocess.run(
        [_node(), "--input-type=module", "-e", script],
        capture_output=True, text=True, env={**os.environ, "HIVE_HOME": str(hive)}, check=True,
    )
    assert json.loads(completed.stdout) == ["SHARED"]
    assert passbook.key_names() == ["SHARED"]


# ── 14. the command line ───────────────────────────────────────────────────

CLI = Path(__file__).resolve().parents[1] / "bin" / "passbook"


def _cli(*args, hive_home, stdin: str = "", env: dict | None = None):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True, text=True, input=stdin,
        env={**os.environ, "HIVE_HOME": str(hive_home), **(env or {})},
    )


def test_check_reports_presence_and_never_the_value(hive):
    passbook.ensure(app="app")
    passbook.set_values({"SET_KEY": "super-secret-value"})

    done = _cli("check", "SET_KEY", "UNSET_KEY", hive_home=hive)

    assert done.returncode == 1, "a missing key must fail the command"
    assert "SET_KEY: set" in done.stdout
    assert "UNSET_KEY: missing" in done.stdout
    assert "super-secret-value" not in done.stdout + done.stderr


def test_check_length_discloses_a_length_and_nothing_else(hive):
    passbook.ensure(app="app")
    passbook.set_values({"SET_KEY": "abcdef"})

    done = _cli("check", "SET_KEY", "--length", hive_home=hive)

    assert "(6 chars)" in done.stdout
    assert "abcdef" not in done.stdout


def _stored(hive) -> dict[str, str]:
    """Read the store file itself, not `load()` — the process env must not leak in."""
    return passbook.parse_env_text((Path(hive) / ".env").read_text(encoding="utf-8"))


def test_add_is_additive_until_asked_to_replace(hive):
    _cli("add", "PB_ADD_KEY=first", hive_home=hive)

    second = _cli("add", "PB_ADD_KEY=second", hive_home=hive)
    assert _stored(hive)["PB_ADD_KEY"] == "first", "another app may be using it"
    assert "--replace" in second.stderr, "silently keeping it would read as success"

    _cli("add", "PB_ADD_KEY=second", "--replace", hive_home=hive)
    assert _stored(hive)["PB_ADD_KEY"] == "second"


def test_add_reads_key_value_lines_from_stdin(hive):
    done = _cli("add", "--stdin", hive_home=hive, stdin="PB_ONE=a\n# comment\nPB_TWO=b\n")

    assert done.returncode == 0
    assert sorted(_stored(hive)) == ["PB_ONE", "PB_TWO"]


def test_add_refuses_a_bare_key_when_it_cannot_prompt(hive):
    """A value must never be guessed, and a pipe cannot be prompted."""
    done = _cli("add", "LONELY_KEY", hive_home=hive)

    assert done.returncode == 1
    assert "No value given for LONELY_KEY" in done.stderr
    assert passbook.key_names(dict(os.environ, HIVE_HOME=str(hive))) == []


def test_run_hands_the_store_to_a_child_but_the_process_env_wins(hive):
    passbook.ensure(app="app")
    passbook.set_values({"FROM_STORE": "store-value", "OVERRIDDEN": "store-value"})

    done = _cli(
        "run", "--", "sh", "-c", "printf '%s|%s' \"$FROM_STORE\" \"$OVERRIDDEN\"",
        hive_home=hive, env={"OVERRIDDEN": "process-value"},
    )

    assert done.stdout == "store-value|process-value"


def test_run_without_a_command_says_so_rather_than_running_the_separator(hive):
    done = _cli("run", "--", hive_home=hive)

    assert done.returncode == 1
    assert "Nothing to run" in done.stderr


def test_the_hyphenated_alias_picks_the_subcommand(hive, tmp_path):
    passbook.ensure(app="app")
    passbook.set_values({"ALIASED": "value"})
    alias = tmp_path / "passbook-check"
    alias.symlink_to(CLI)

    done = subprocess.run(
        [sys.executable, str(alias), "ALIASED"],
        capture_output=True, text=True, env={**os.environ, "HIVE_HOME": str(hive)},
    )

    assert done.returncode == 0
    assert "ALIASED: set" in done.stdout


def test_list_and_status_disclose_names_and_paths_only(hive):
    passbook.ensure(app="app")
    passbook.set_values({"NAMED_KEY": "a-secret-nobody-should-see"})

    listing = _cli("list", hive_home=hive)
    state = _cli("status", hive_home=hive)

    assert listing.stdout.strip() == "NAMED_KEY"
    assert "NAMED_KEY" not in state.stdout
    for stream in (listing.stdout, listing.stderr, state.stdout, state.stderr):
        assert "a-secret-nobody-should-see" not in stream


# ── 15. workspace scoping ──────────────────────────────────────────────────


def _manifest(hive, entries, active=""):
    (hive).mkdir(parents=True, exist_ok=True)
    (hive / "workspaces.json").write_text(
        json.dumps({"activeWorkspaceId": active, "workspaces": entries}), encoding="utf-8")


def test_a_workspace_write_lands_in_that_workspace_not_machine_wide(hive, monkeypatch):
    """The property `"inherit": false` exists for. A write that ignored scope
    would put a client's key where every other workspace can read it."""
    _manifest(hive, [{"id": "main"}, {"id": "client"}], active="client")
    passbook.ensure(app="app")
    passbook.set_values({"MACHINE_KEY": "machine"}, workspace_id="main")

    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    passbook.set_values({"CLIENT_KEY": "client-only"})

    machine = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    scoped = passbook.parse_env_text(
        passbook.workspace_env_path("client").read_text(encoding="utf-8"))
    assert "CLIENT_KEY" not in machine, "a workspace key must not leak machine-wide"
    assert scoped["CLIENT_KEY"] == "client-only"


def test_a_workspace_still_reads_the_machine_store_by_default(hive, monkeypatch):
    _manifest(hive, [{"id": "main"}, {"id": "client"}], active="client")
    passbook.ensure(app="app")
    passbook.set_values({"MACHINE_KEY": "machine"}, workspace_id="main")

    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    passbook.set_values({"CLIENT_KEY": "client-only"})

    assert passbook.key_names() == ["CLIENT_KEY", "MACHINE_KEY"]


def test_a_non_inheriting_workspace_sees_only_its_own(hive, monkeypatch):
    _manifest(hive, [{"id": "main"}, {"id": "client", "inherit": False}], active="client")
    passbook.ensure(app="app")
    passbook.set_values({"MACHINE_KEY": "machine"}, workspace_id="main")

    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    passbook.set_values({"CLIENT_KEY": "client-only"})

    assert passbook.key_names() == ["CLIENT_KEY"]
    assert "MACHINE_KEY" not in passbook.load()


def test_sibling_workspaces_never_see_each_other(hive, monkeypatch):
    _manifest(hive, [{"id": "main"}, {"id": "one"}, {"id": "two"}], active="main")
    passbook.ensure(app="app")
    monkeypatch.setenv("HIVE_WORKSPACE", "one")
    passbook.set_values({"ONE_KEY": "a"})
    monkeypatch.setenv("HIVE_WORKSPACE", "two")
    passbook.set_values({"TWO_KEY": "b"})

    assert passbook.key_names() == ["TWO_KEY"]
    monkeypatch.setenv("HIVE_WORKSPACE", "one")
    assert passbook.key_names() == ["ONE_KEY"]


def test_removal_also_respects_the_active_workspace(hive, monkeypatch):
    _manifest(hive, [{"id": "main"}, {"id": "client"}], active="main")
    passbook.ensure(app="app")
    passbook.set_values({"SHARED_NAME": "machine"}, workspace_id="main")
    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    passbook.set_values({"SHARED_NAME": "client"})

    passbook.remove_values(["SHARED_NAME"])

    machine = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    assert machine["SHARED_NAME"] == "machine", "removing in a workspace must not touch the machine"


def test_a_machine_without_workspaces_writes_where_it_always_did(hive):
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})
    assert passbook.target_path() == passbook.env_path()


def test_main_is_the_machine_store_not_a_second_file(hive, monkeypatch):
    _manifest(hive, [{"id": "main"}], active="main")
    monkeypatch.setenv("HIVE_WORKSPACE", "main")
    assert passbook.target_path() == passbook.env_path()


def test_a_workspace_store_is_created_unreadable_to_anyone_else(hive, monkeypatch):
    _manifest(hive, [{"id": "client"}], active="client")
    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    passbook.set_values({"CLIENT_KEY": "value"})

    scoped = passbook.workspace_env_path("client")
    assert_private(scoped, 0o600)
    assert_private(scoped.parent, 0o700)


def test_both_runtimes_resolve_the_same_workspace_stores(hive, monkeypatch):
    """A Node app and a Python app on one machine must not disagree.

    They would not fail loudly if they did: each would simply find a different
    set of keys, and the same provider would work in one process and 401 in the
    other.
    """
    _manifest(hive, [{"id": "main"}, {"id": "client", "inherit": False}], active="client")
    passbook.ensure(app="app")
    passbook.set_values({"MACHINE_KEY": "m"}, workspace_id="main")
    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    passbook.set_values({"CLIENT_KEY": "c"})

    script = f"""
        import {{ keyNames, targetPath, status }} from {json.dumps(NODE_TWIN_URL)};
        process.stdout.write(JSON.stringify({{
            keys: keyNames(), writes: targetPath(), state: status(),
        }}));
    """
    completed = subprocess.run(
        [_node(), "--input-type=module", "-e", script], capture_output=True, text=True,
        env={**os.environ, "HIVE_HOME": str(hive), "HIVE_WORKSPACE": "client"}, check=True,
    )
    seen = json.loads(completed.stdout)

    assert seen["keys"] == passbook.key_names() == ["CLIENT_KEY"]
    assert seen["writes"] == str(passbook.target_path())
    assert seen["state"]["inherits_machine_store"] is False
    assert seen["state"]["workspaces"] == passbook.workspaces()


def test_the_node_twin_writes_into_the_workspace_too(hive, monkeypatch):
    _manifest(hive, [{"id": "main"}, {"id": "client"}], active="client")
    passbook.ensure(app="app")

    script = f"""
        import {{ setValues }} from {json.dumps(NODE_TWIN_URL)};
        setValues({{ FROM_NODE: 'value' }});
    """
    subprocess.run(
        [_node(), "--input-type=module", "-e", script], capture_output=True, text=True,
        env={**os.environ, "HIVE_HOME": str(hive), "HIVE_WORKSPACE": "client"}, check=True,
    )

    machine = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    scoped = passbook.parse_env_text(
        passbook.workspace_env_path("client").read_text(encoding="utf-8"))
    assert "FROM_NODE" not in machine
    assert scoped["FROM_NODE"] == "value"


# ── 16. nothing else is required ───────────────────────────────────────────
#
# The standard's promise is that a project vendors one file and it works. Every
# optional part added since — stamping, sealing, linking, the broker, the access
# modes — has to leave that promise intact, or PassBook becomes a runtime other
# software depends on rather than a file it copies. These tests exist so that
# stays true by rule rather than by luck.


def test_a_store_written_by_one_app_is_readable_by_another_with_nothing_installed(hive):
    """The whole point: one machine, one store, no coordination."""
    passbook.ensure(app="hivemindos-desktop", name="HivemindOS")
    passbook.set_values({"SHARED_KEY": "value"})

    # A second app, resolving the same path, with no broker and no daemon.
    assert passbook.request(["SHARED_KEY"], app="some-other-app") == {"SHARED_KEY": "value"}


def test_a_policy_has_no_force_without_a_broker(hive):
    """A policy is enforced by the broker, so it cannot lock out a machine that
    has none. Otherwise writing one would strand every app on that box."""
    access = pytest.importorskip("passbook_access")
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})
    access.write_policy({"default": {"mode": "never"},
                         "apps": {"app": {"keys": {"KEY": {"mode": "never"}}}}})

    assert passbook.request(["KEY"], app="app") == {"KEY": "value"}


def test_resolving_a_credential_costs_nothing_when_no_broker_is_running(hive):
    """No socket to time out on, so the common case must not pay for the rare one."""
    import time

    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})

    started = time.perf_counter()
    for _ in range(20):
        passbook.request(["KEY"], app="app")
    each = (time.perf_counter() - started) / 20

    assert each < 0.05, f"a brokerless read took {each * 1000:.0f}ms — something is waiting on a socket"


def test_the_optional_modules_are_genuinely_optional(hive, monkeypatch):
    """Import the store with every companion made unavailable."""
    import builtins

    real_import = builtins.__import__
    optional = {"passbook_stamp", "passbook_seal", "passbook_link", "passbook_broker", "passbook_access"}

    def refuse(name, *args, **kwargs):
        if name in optional:
            raise ImportError(f"{name} is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    passbook.ensure(app="app")
    passbook.set_values({"KEY": "value"})

    assert passbook.request(["KEY"], app="app") == {"KEY": "value"}
    assert passbook.key_names() == ["KEY"]
    assert passbook.status()["exists"] is True


# ── 17. the one deliberate disclosure ──────────────────────────────────────


def test_reveal_returns_the_value_it_is_asked_for(hive):
    passbook.ensure(app="app")
    passbook.set_values({"SHOWN": "the-actual-value"})

    assert passbook.reveal("SHOWN") == "the-actual-value"


def test_reveal_is_recorded_under_its_own_operation(hive):
    """A person looking at their own key must be legible as that, not confused
    with an app consuming it."""
    stamp = pytest.importorskip("passbook_stamp")
    passbook.ensure(app="app")
    passbook.set_values({"SHOWN": "value"})

    passbook.reveal("SHOWN", app="test")

    rows = [row for row in stamp.read_stamps(limit=20) if row.get("op") == "reveal"]
    assert rows, "reveal left no trace"
    assert rows[-1]["keys"] == ["SHOWN"]
    assert "value" not in stamp.proof_path().read_text(encoding="utf-8")


def test_reveal_of_a_missing_key_is_empty_and_still_recorded(hive):
    stamp = pytest.importorskip("passbook_stamp")
    passbook.ensure(app="app")

    assert passbook.reveal("NOT_THERE") == ""

    rows = [row for row in stamp.read_stamps(limit=20) if row.get("op") == "reveal"]
    assert rows and rows[-1]["granted"] is False


def test_no_status_surface_gained_a_value(hive):
    """The exception must stay an exception: adding values to status would lose
    the property that makes the rest of the surface safe."""
    passbook.ensure(app="app")
    passbook.set_values({"SHOWN": "a-value-nobody-should-see"})

    import json as _json

    for surface in (passbook.status(), passbook.key_names(), passbook.describe()):
        assert "a-value-nobody-should-see" not in _json.dumps(surface)


# ── 18. usage, derived rather than tracked ─────────────────────────────────


def test_usage_is_derived_from_the_record(hive):
    """Derived, not tracked separately, so it cannot drift from what it summarises."""
    stamp = pytest.importorskip("passbook_stamp")
    passbook.ensure(app="app")
    passbook.set_values({"USED": "value", "UNUSED": "value"})
    stamp.stamp(op="read", keys=["USED"], app="first")
    stamp.stamp(op="read", keys=["USED"], app="second")

    usage = stamp.usage_by_key()

    assert usage["USED"]["count"] == 2
    assert usage["USED"]["last_app"] == "second", "the newest row wins"
    assert sorted(usage["USED"]["apps"]) == ["first", "second"]
    assert "UNUSED" not in usage, "a key never read has no entry, not a zero"


def test_history_carries_the_proof_for_each_row(hive):
    """A history a person cannot check is just a list."""
    stamp = pytest.importorskip("passbook_stamp")
    passbook.ensure(app="app")
    passbook.set_values({"WATCHED": "value"})
    stamp.stamp(op="read", keys=["WATCHED"], app="an-app", reason="a job")

    rows = stamp.history_for_key("WATCHED")

    assert rows and rows[-1]["app"] == "an-app"
    assert rows[-1]["proof"].startswith("sha256:")
    assert rows[-1]["reason"] == "a job"


def test_history_never_carries_a_value(hive):
    stamp = pytest.importorskip("passbook_stamp")
    passbook.ensure(app="app")
    passbook.set_values({"WATCHED": "a-value-nobody-should-see"})
    stamp.stamp(op="read", keys=["WATCHED"], app="an-app")

    import json as _json

    assert "a-value-nobody-should-see" not in _json.dumps(stamp.history_for_key("WATCHED"))


def test_history_of_an_untouched_key_is_empty_not_an_error(hive):
    stamp = pytest.importorskip("passbook_stamp")
    passbook.ensure(app="app")
    assert stamp.history_for_key("NEVER_TOUCHED") == []


# ── who is asking ──────────────────────────────────────────────────────────


def _resolved(argv, env=None, monkeypatch=None):
    """The name a command would record itself under, without running it."""
    import passbook_cli

    args = passbook_cli.build_parser().parse_args(argv)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    if not (env or {}).get("PASSBOOK_APP"):
        monkeypatch.delenv("PASSBOOK_APP", raising=False)
    return passbook_cli.caller("a-default", args)


def test_a_command_run_by_hand_is_recorded_as_passbook(monkeypatch):
    """No claim made, so the honest answer is that you ran it."""
    assert _resolved(["get", "ALPHA"], monkeypatch=monkeypatch) == "a-default"


def test_an_app_name_can_be_said_on_the_command_line(monkeypatch):
    assert _resolved(["get", "ALPHA", "--app", "some-agent"],
                     monkeypatch=monkeypatch) == "some-agent"


def test_the_environment_names_the_caller_when_nothing_else_does(monkeypatch):
    """An agent harness sets it once rather than threading a flag everywhere.

    `passbook run` is how an agent actually gets an environment, and it had no
    way at all to say who it was for — so every agent on a machine was one
    indistinguishable row in the record and no policy could name any of them.
    """
    assert _resolved(["get", "ALPHA"], env={"PASSBOOK_APP": "from-the-env"},
                     monkeypatch=monkeypatch) == "from-the-env"


def test_saying_it_on_the_command_line_beats_the_environment(monkeypatch):
    """The flag is this call; the variable is the process tree around it."""
    assert _resolved(["get", "ALPHA", "--app", "said-here"],
                     env={"PASSBOOK_APP": "ambient"}, monkeypatch=monkeypatch) == "said-here"


def test_a_blank_claim_is_no_claim(monkeypatch):
    assert _resolved(["get", "ALPHA", "--app", "   "], env={"PASSBOOK_APP": "  "},
                     monkeypatch=monkeypatch) == "a-default"


@pytest.mark.parametrize("argv", [
    ["get", "ALPHA"], ["check", "ALPHA"], ["reveal", "ALPHA"],
    ["run", "--", "true"], ["add", "ALPHA=v"], ["remove", "ALPHA"],
])
def test_every_command_that_names_a_caller_can_be_told_one(argv, monkeypatch):
    """Only `get` could. The rest hardcoded a name no policy could ever match,
    so an audience rule about an agent could not reach the command that agent
    actually uses."""
    assert _resolved(argv, monkeypatch=monkeypatch) == "a-default"
    assert _resolved([*argv, "--app", "a-named-agent"] if argv[0] != "run"
                     else ["run", "--app", "a-named-agent", "--", "true"],
                     monkeypatch=monkeypatch) == "a-named-agent"


def test_run_hands_the_name_to_what_it_runs(tmp_path, monkeypatch):
    """Whatever it runs may ask PassBook itself, and those reads are the same
    caller's — not `passbook-run`'s."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    passbook.ensure(app="test")

    done = subprocess.run(
        [sys.executable, "-m", "passbook_cli", "run", "--app", "an-agent",
         "--", sys.executable, "-c", "import os; print(os.environ.get('PASSBOOK_APP'))"],
        capture_output=True, text=True, cwd=str(PACKAGE),
        env={**os.environ, "HIVE_HOME": str(home), "PYTHONPATH": str(PACKAGE)},
    )

    assert done.stdout.strip() == "an-agent", done.stderr


def test_a_vendor_group_is_spelled_the_way_the_vendor_spells_it():
    """A group heading is the largest text on a page of several hundred keys.

    `str.title()` is right for most vendors and conspicuously wrong for the
    ones everybody has: Openai, Github, Aws. Anything not in the table still
    falls through to `title()`, which is what the long tail wants.
    """
    import passbook_catalog

    for name, group in [
        ("OPENAI_API_KEY", "OpenAI"), ("GITHUB_TOKEN", "GitHub"),
        ("AWS_SECRET_ACCESS_KEY", "AWS"), ("POSTHOG_API_KEY", "PostHog"),
        ("XAI_API_KEY", "xAI"), ("SENDGRID_API_KEY", "SendGrid"),
        # The fallback still has to work, or the table becomes the whole world.
        ("STRIPE_SECRET_KEY", "Stripe"), ("TWILIO_AUTH_TOKEN", "Twilio"),
    ]:
        assert passbook_catalog.infer_group(name) == group, name

    # And the table must not invent a family for a name that has none.
    assert passbook_catalog.infer_group("API_KEY") == passbook_catalog.UNGROUPED
