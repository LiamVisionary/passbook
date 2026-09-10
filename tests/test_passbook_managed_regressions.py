# SPDX-License-Identifier: Apache-2.0
"""Regressions found through the managed setup and credential-use paths."""
from argparse import Namespace
import json
from pathlib import Path
import sys

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parent)]
from test_passbook_integrations import Installation
import passbook
import passbook_access as access
import passbook_broker as broker
import passbook_connect as connection
import passbook_integrations as managed
import passbook_keystore as keystore
import passbook_managed_store as storage
import passbook_stamp
import passbook_vault as vault


def connect_args(**overrides):
    return Namespace(**{"app": "hivemindos", "identity_env": "SYNTHETIC_HOST_IDENTITY", "json": True,
                        "workspace": "unselected-workspace", "name": "HivemindOS", "non_interactive": False,
                        "no_background": False, **overrides})


def locked_binding(background=False):
    return {"ok": True, "state": "locked", "binding": {
        "app": "hivemindos", "name": "HivemindOS", "workspace": "selected-workspace", "background": background}}


@pytest.mark.parametrize("interactive_flag,is_tty", [(True, True), (False, False)])
def test_headless_reconnect_reports_locked_and_never_claims_keys_are_ready(monkeypatch, capsys, interactive_flag, is_tty):
    monkeypatch.setenv("SYNTHETIC_HOST_IDENTITY", "synthetic-test-host-identity-only-542")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: is_tty)
    seen = []
    monkeypatch.setattr(connection, "exchange", lambda envelope: seen.append(envelope) or locked_binding())
    monkeypatch.setattr(connection, "hidden_input", lambda *_: pytest.fail("headless password prompt"))
    assert connection.connect(connect_args(non_interactive=interactive_flag)) == 1
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["code"] == "locked" and result["state"] == "locked" and not result["ok"]
    assert "ready to use" not in output.out + output.err
    assert [item["action"] for item in seen] == ["state"]


@pytest.mark.parametrize("background", [False, True])
def test_interactive_reconnect_unlocks_existing_binding_once_and_preserves_background_choice(monkeypatch, capsys, background):
    monkeypatch.setenv("SYNTHETIC_HOST_IDENTITY", "synthetic-test-host-identity-only-542")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(keystore, "available", lambda: True)
    prompts, seen = [], []
    monkeypatch.setattr(connection, "hidden_input", lambda prompt: prompts.append(prompt) or "synthetic-unlock-password")
    def exchange(envelope):
        seen.append(envelope)
        if envelope["action"] == "state":
            return locked_binding(background)
        assert envelope["action"] == "connect"
        return {**locked_binding(background), "state": "ready"}
    monkeypatch.setattr(connection, "exchange", exchange)
    assert connection.connect(connect_args()) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "ready"
    assert len(prompts) == 1 and [item["action"] for item in seen] == ["state", "connect"]
    body = seen[-1]["body"]
    assert body["workspace"] == "selected-workspace" and body["createWorkspace"] is False
    assert body["password"] == "synthetic-unlock-password" and body["background"] is background


@pytest.fixture
def root(tmp_path, monkeypatch):
    home = tmp_path / "hive"
    for name in ("HIVE_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("HIVE_WORKSPACE", "HIVE_WORKSPACE_ID", "HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    broker._forget_dek()
    yield home
    broker._forget_dek()


@pytest.fixture
def device_keys(monkeypatch):
    held = {}
    monkeypatch.setattr(keystore, "available", lambda: True)
    def store(name, value):
        held[name] = value
        return {"ok": True, "backend": "synthetic-memory"}
    monkeypatch.setattr(keystore, "store", store)
    monkeypatch.setattr(keystore, "fetch", held.get)
    monkeypatch.setattr(keystore, "forget", lambda name: held.pop(name, None))
    return held


@pytest.mark.parametrize("damage", ["removed-factor", "missing-device-key"])
def test_owner_reconnect_repairs_its_missing_background_factor_without_borrowing_another(root, device_keys, damage):
    app, other = Installation(root), Installation(root)
    assert app.connect(background=True)["ok"] and other.connect(background=True)["ok"]
    with storage.Store(root).transaction() as tx:
        first, second = tx.get("binding", app.id), tx.get("binding", other.id)
    target = managed.workspace_path(root, "hivemindos").parent
    other_key = f"passbook-vault-{second['profile']}-{second['deviceFactor']}"
    original_other_key = device_keys[other_key]
    if damage == "removed-factor":
        vault.remove_factor(first["profile"], first["deviceFactor"], root=target)
    else:
        device_keys.pop(f"passbook-vault-{first['profile']}-{first['deviceFactor']}")
    broker._forget_dek()
    assert app.call("state")["state"] == "locked", "another binding's device factor must not unlock this one"
    assert app.connect(background=True)["state"] == "ready"
    with storage.Store(root).transaction() as tx:
        repaired = tx.get("binding", app.id)
        unchanged = tx.get("binding", other.id)
    assert repaired["deviceFactor"] != first["deviceFactor"]
    assert unchanged == second and device_keys[other_key] == original_other_key
    broker._forget_dek()
    assert app.call("state")["state"] == "ready", "reconnect must survive losing the broker's in-memory key"


def test_a_sealed_skip_name_is_still_sensitive_even_when_another_workspace_has_public_config(root):
    app = Installation(root)
    assert app.connect()["ok"]
    passbook.set_values({"NEXT_PUBLIC_SYNTHETIC": "synthetic-public-config"},
                        path=root / ".env", environ=managed.env_for(root, "main"))
    assert app.call("service-write", {"values": {"NEXT_PUBLIC_SYNTHETIC": "synthetic-protected-value"}})["ok"]
    result = app.call("credential-names")
    assert "NEXT_PUBLIC_SYNTHETIC" in result["credentialNames"]
    assert "NEXT_PUBLIC_SYNTHETIC" not in result["configurationNames"]
    assert "synthetic-protected-value" not in json.dumps(result)


def test_service_remove_preserves_other_workspace_value_and_routes_names_only_receipt(root):
    app = Installation(root)
    assert app.connect()["ok"]
    passbook.set_values({"REMOVE_SYNTHETIC": "synthetic-main-value"},
                        path=root / ".env", environ=managed.env_for(root, "main"))
    assert app.call("service-write", {"values": {"REMOVE_SYNTHETIC": "synthetic-bound-value"}})["ok"]
    result = app.call("service-remove", {"keys": ["REMOVE_SYNTHETIC"]})
    assert result["ok"] and result["removed"] == ["REMOVE_SYNTHETIC"]
    assert "REMOVE_SYNTHETIC" in passbook.parse_env_text((root / ".env").read_text())
    assert "REMOVE_SYNTHETIC" not in passbook.parse_env_text(managed.workspace_path(root, "hivemindos").read_text())
    rows = [json.loads(line) for line in passbook_stamp.proof_path(root).read_text().splitlines()]
    removed = [row for row in rows if row["op"] == "remove" and row["keys"] == ["REMOVE_SYNTHETIC"]]
    assert len(removed) == 1 and removed[0]["workspace"] == "hivemindos"
    assert "synthetic-bound-value" not in json.dumps(rows)


@pytest.fixture
def inherited_managed_main(root):
    app = Installation(root)
    assert app.connect(workspace="main")["ok"]
    assert app.call("service-write", {"values": {
        "MANAGED_ONLY": "synthetic-managed-main", "LOCAL_OVERRIDE": "synthetic-managed-original"}})["ok"]
    manifest = passbook.workspace_manifest()
    manifest["workspaces"].append({"id": "legacy", "inherit": True})
    (root / "workspaces.json").write_text(json.dumps(manifest))
    passbook.set_values({"LOCAL_ONLY": "synthetic-local-only", "LOCAL_OVERRIDE": "synthetic-local-override"},
                        workspace_id="legacy")
    policy = access.read_policy(root)
    policy["reads"] = "open"
    access.write_policy(policy, root)
    return app


@pytest.mark.parametrize("disconnected", [False, True])
def test_legacy_reads_refuse_inherited_managed_owner_but_keep_local_values(root, inherited_managed_main, disconnected):
    app = inherited_managed_main
    if disconnected:
        assert app.call("revoke", {"disconnect": True})["ok"]
    result = broker._handle({"op": "request", "workspace": "legacy", "app": "legacy-reader",
                            "keys": ["MANAGED_ONLY", "LOCAL_ONLY", "LOCAL_OVERRIDE"]}, root)
    assert result["granted"] == {"LOCAL_ONLY": "synthetic-local-only", "LOCAL_OVERRIDE": "synthetic-local-override"}
    assert result["denied"] == ["MANAGED_ONLY"] and result["missing"] == []
    assert "verified connection" in result["why"]["MANAGED_ONLY"]
    direct = broker._handle({"op": "request", "workspace": "main", "keys": ["MANAGED_ONLY"]}, root)
    assert direct["code"] == "managed-connection-required" and not direct["granted"]
    alias = broker._handle({"op": "request", "workspace": "unregistered-alias", "keys": ["MANAGED_ONLY"]}, root)
    assert alias["denied"] == ["MANAGED_ONLY"] and not alias["granted"]


def test_legacy_spawn_never_receives_an_inherited_managed_value(root, inherited_managed_main):
    result = broker._handle({"op": "spawn", "workspace": "legacy", "app": "legacy-runner",
        "keys": ["MANAGED_ONLY", "LOCAL_ONLY", "LOCAL_OVERRIDE"],
        "command": [sys.executable, "-c", "import os; print('protected' if not os.environ.get('MANAGED_ONLY') "
                    "and os.environ.get('LOCAL_ONLY') == 'synthetic-local-only' "
                    "and os.environ.get('LOCAL_OVERRIDE') == 'synthetic-local-override' else 'wrong')"]}, root)
    assert result["ok"] and result["stdout"].strip() == "protected"
    assert result["denied"] == ["MANAGED_ONLY"] and result["missing"] == []


def test_legacy_proxy_refuses_inherited_managed_owner_before_network(root, inherited_managed_main, monkeypatch):
    import passbook_grant
    policy = access.read_policy(root)
    policy["guards"] = {"MANAGED_ONLY": {"destinations": ["service.example"]}}
    access.write_policy(policy, root)
    monkeypatch.setattr(passbook_grant, "proxy", lambda *args, **kwargs: pytest.fail("managed value reached the legacy transport"))
    result = broker._handle({"op": "proxy", "workspace": "legacy", "app": "legacy-proxy",
                            "url": "https://service.example/account",
                            "headers": {"Authorization": "Bearer {{MANAGED_ONLY}}"}}, root)
    assert not result["ok"] and result["denied"] == ["MANAGED_ONLY"]
    assert "verified connection" in result["why"]["MANAGED_ONLY"]


def test_plaintext_resolver_skips_managed_sources_even_without_caller_filter(root, inherited_managed_main):
    assert broker._resolve_values(["MANAGED_ONLY", "LOCAL_ONLY", "LOCAL_OVERRIDE"], workspace="legacy", root=root) == {
        "LOCAL_ONLY": "synthetic-local-only", "LOCAL_OVERRIDE": "synthetic-local-override"}


def test_alias_of_the_same_managed_file_cannot_reopen_plaintext_access(root, inherited_managed_main, device_keys):
    assert inherited_managed_main.connect(workspace="main", background=True)["ok"]
    manifest = passbook.workspace_manifest()
    manifest["workspaces"].append({"id": "alias", "inherit": False, "envPath": str(root / ".env")})
    (root / "workspaces.json").write_text(json.dumps(manifest))
    # Opening the same vault under another display ID must not change ownership.
    assert broker._handle({"op": "signin", "workspace": "alias", "device": True}, root)["ok"]
    result = broker._handle({"op": "request", "workspace": "alias", "keys": ["MANAGED_ONLY"]}, root)
    assert result["code"] == "managed-connection-required" and not result["granted"]
    assert broker._resolve_values(["MANAGED_ONLY"], workspace="alias", root=root) == {}
