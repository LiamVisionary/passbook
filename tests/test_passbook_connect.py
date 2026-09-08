# SPDX-License-Identifier: Apache-2.0
"""Owner setup entry point: no manual broker/signin and no secret argv."""
from argparse import Namespace
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_cli
import passbook_connect as connection
import passbook_managed_cli as transport
import passbook_managed_service as service


def args(**overrides):
    return Namespace(app="hivemindos", identity_env="TEST_HOST_IDENTITY", json=True,
                     workspace="HivemindOS", name="HivemindOS", non_interactive=True,
                     no_background=False, yes=True, **overrides)


def test_headless_missing_identity_never_initializes_or_prints_secret(monkeypatch, capsys):
    monkeypatch.delenv("TEST_HOST_IDENTITY", raising=False)
    monkeypatch.setattr(connection, "exchange", lambda *_: (_ for _ in ()).throw(AssertionError("must not initialize")))
    assert connection.connect(args()) == 1
    reply = json.loads(capsys.readouterr().out)
    assert reply["code"] == "needs-owner"


def test_installer_noninteractive_waits_for_owner_without_creating_profile(monkeypatch, capsys):
    monkeypatch.setenv("TEST_HOST_IDENTITY", "dummy-host-identity-for-test-only-7427")
    seen = []
    def exchange(message):
        seen.append(message)
        return {"ok": False, "code": "not-connected"}
    monkeypatch.setattr(connection, "exchange", exchange)
    assert connection.connect(args()) == 1
    assert len(seen) == 1 and seen[0]["action"] == "state" and seen[0]["signature"]
    output = capsys.readouterr().out
    assert json.loads(output)["code"] == "needs-owner"
    assert "dummy-host-identity" not in output


def test_existing_binding_resumes_service_without_prompt_or_reconnect(monkeypatch, capsys):
    monkeypatch.setenv("TEST_HOST_IDENTITY", "dummy-host-identity-for-test-only-7427")
    seen = []
    monkeypatch.setattr(connection, "exchange", lambda message: seen.append(message) or {
        "ok": True, "state": "ready", "binding": {"app": "hivemindos", "background": True}})
    monkeypatch.setattr(service, "install_managed_service", lambda: {"ok": True, "installed": True})
    monkeypatch.setattr(connection.getpass, "getpass", lambda *_: (_ for _ in ()).throw(AssertionError("prompt")))
    assert connection.connect(args()) == 0
    assert [message["action"] for message in seen] == ["state"]
    assert json.loads(capsys.readouterr().out)["backgroundService"]["installed"]


def test_explicit_pause_is_not_resumed_by_reinstall(monkeypatch, capsys):
    monkeypatch.setenv("TEST_HOST_IDENTITY", "dummy-host-identity-for-test-only-7427")
    monkeypatch.setattr(connection, "exchange", lambda message: {
        "ok": True, "state": "paused", "binding": {"app": "hivemindos", "background": True}})
    monkeypatch.setattr(service, "install_managed_service", lambda: (_ for _ in ()).throw(AssertionError("must not resume")))
    assert connection.connect(args()) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "paused"


def test_fresh_interactive_setup_uses_original_store_and_hidden_password(monkeypatch, capsys):
    monkeypatch.setenv("TEST_HOST_IDENTITY", "dummy-host-identity-for-test-only-7427")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(connection.getpass, "getpass", lambda *_: "dummy-vault-password")
    import passbook_keystore
    monkeypatch.setattr(passbook_keystore, "available", lambda: True)
    seen = []
    def exchange(message):
        seen.append(message)
        if message["action"] == "state":
            return {"ok": False, "code": "not-connected"}
        if message["action"] == "begin":
            return {"ok": True, "workspaces": [{"id": "main", "name": "main", "hasProfile": False}]}
        return {"ok": True, "state": "ready", "binding": {"workspace": "main", "name": "HivemindOS"}}
    monkeypatch.setattr(connection, "exchange", exchange)
    options = args(); options.non_interactive = False
    assert connection.connect(options) == 0
    assert seen[-1]["body"]["workspace"] == "main"
    assert seen[-1]["body"]["background"] and seen[-1]["body"]["consent"]
    out = capsys.readouterr()
    assert "dummy-vault-password" not in out.out + out.err


def test_disconnect_only_revokes_the_named_installation(monkeypatch, capsys):
    monkeypatch.setenv("TEST_HOST_IDENTITY", "dummy-host-identity-for-test-only-7427")
    seen = []
    def exchange(message):
        seen.append(message)
        return {"ok": True, "binding": {"app": "hivemindos"}} if message["action"] == "state" else {"ok": True, "revoked": True}
    monkeypatch.setattr(connection, "exchange", exchange)
    assert connection.disconnect(args()) == 0
    assert seen[-1]["action"] == "revoke" and json.loads(seen[-1]["bodyJson"]) == {"disconnect": True}
    assert json.loads(capsys.readouterr().out)["revoked"]


def test_connect_transport_installs_startup_after_confirmed_enrollment(monkeypatch):
    monkeypatch.setattr(transport.broker, "running", lambda **_: True)
    calls = []
    def ask(message, **_):
        calls.append(message["op"])
        return {"managed_integrations": 1} if message["op"] == "ping" else {"ok": True, "binding": {"background": True}}
    monkeypatch.setattr(transport.broker, "_ask", ask)
    monkeypatch.setattr(service, "install_managed_service", lambda **kwargs: calls.append("service") or {"ok": True})
    result = transport.exchange({"op": "managed", "action": "connect"})
    assert result["backgroundService"]["ok"]
    assert calls == ["ping", "managed", "service"]


def test_cli_parser_supports_installer_and_service_arguments():
    parser = passbook_cli.build_parser()
    parsed = parser.parse_args(["connect", "--app", "hivemindos", "--identity-env", "AUTH", "--workspace", "HivemindOS", "--non-interactive", "--json"])
    assert parsed.non_interactive and parsed.identity_env == "AUTH"
    assert parser.parse_args(["broker", "run", "--root", "/tmp/synthetic-store"]).root == "/tmp/synthetic-store"


def test_unconfigured_state_with_null_binding_does_not_inspect_a_service(monkeypatch):
    monkeypatch.setattr(transport.broker, "running", lambda **_: True)
    monkeypatch.setattr(transport.broker, "_ask", lambda message, **_: {"managed_integrations": 1}
                        if message["op"] == "ping" else {"ok": True, "binding": None, "state": "unconfigured"})
    result = transport.exchange({"op": "managed", "action": "state"})
    assert result == {"ok": True, "binding": None, "state": "unconfigured"}
