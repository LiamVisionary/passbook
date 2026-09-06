"""The first command on a second machine must finish the setup it needs."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from _platform import broker_marker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook
import passbook_broker as broker
import passbook_cli as cli
import passbook_fleet as fleet
import passbook_sync as sync
import passbook_vault as vault

PASSWORD = "a synthetic onboarding password"
REPO = Path(__file__).resolve().parents[1]
pytestmark = broker_marker()


@pytest.fixture
def machine(tmp_path, monkeypatch):
    for name in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.setattr(fleet, "reachable", lambda: [])
    yield tmp_path
    broker.stop(root=tmp_path)


def run_cli(machine, *args, stdin=""):
    return subprocess.run(
        [sys.executable, str(REPO / "bin/passbook"), *args],
        input=stdin, capture_output=True, text=True, timeout=20,
        env={**os.environ, "HIVE_HOME": str(machine)},
    )


def orphan(machine):
    # Real ciphertext, sealed under a profile this second machine never had.
    source = machine / "source"
    profile = vault.create_profile("Source", password=PASSWORD, root=source)
    dek = vault.unlock_with_password(profile["id"], PASSWORD, root=source)
    blob = vault.seal_value("EXISTING_KEY", "synthetic-original", dek,
                            profile_id=profile["id"])
    passbook.set_values({"EXISTING_KEY": blob})
    return (machine / ".env").read_bytes()


def test_first_signin_sets_up_and_opens_a_local_vault(machine):
    passbook.set_values({"EXISTING_KEY": "synthetic-original"})
    result = run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result.stderr
    assert vault.profiles()
    assert broker.vault_status()["unlocked"]
    assert vault.is_sealed(passbook.parse_env_text((machine / ".env").read_text())["EXISTING_KEY"])
    assert "synthetic-original" not in result.stdout + result.stderr


def test_missing_profile_is_diagnosed_before_asking_for_password(machine, monkeypatch, capsys):
    original = orphan(machine)
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("useless password prompt"))
    assert cli.main(["signin"]) == 1
    said = capsys.readouterr()
    assert "connected Mac" in said.err
    assert "passbook signin" in said.err
    assert (machine / ".env").read_bytes() == original
    assert not vault.profiles()
    assert not broker.running()


def test_signin_recovers_orphaned_ciphertext_and_opens_it(machine, monkeypatch, capsys):
    orphan(machine)
    monkeypatch.setattr(fleet, "reachable", lambda: [{"host": "source", "port": "8798", "address": ""}])
    monkeypatch.setattr(sync, "fetch", lambda *a, **k: {
        "ok": True, "values": {"EXISTING_KEY": "synthetic-original", "UNRELATED_KEY": "not-requested"},
    })
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: PASSWORD)
    assert cli.main(["signin"]) == 0
    assert broker.vault_status()["opens"] == 1
    assert "UNRELATED_KEY" not in passbook.key_names()
    profile = vault.active_profile_id()
    dek = vault.unlock_with_password(profile, PASSWORD)
    raw = passbook.parse_env_text((machine / ".env").read_text())
    assert vault.unseal_value("EXISTING_KEY", raw["EXISTING_KEY"], dek, profile_id=profile) == "synthetic-original"
    said = capsys.readouterr()
    assert "synthetic-original" not in said.out + said.err


def test_interactive_add_signs_in_and_keeps_the_entered_value(machine, monkeypatch):
    profile = vault.create_profile("Owner", password=PASSWORD)
    dek = vault.unlock_with_password(profile["id"], PASSWORD)
    passbook.set_values({"EXISTING_KEY": vault.seal_value("EXISTING_KEY", "synthetic-original", dek,
                                                       profile_id=profile["id"])})
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts = []
    def password(*args, **kwargs):
        prompts.append(args)
        return PASSWORD
    monkeypatch.setattr(cli, "_ask_password", password)
    assert cli.main(["add", "NEW_KEY=synthetic-new"]) == 0
    raw = passbook.parse_env_text((machine / ".env").read_text())
    assert vault.unseal_value("NEW_KEY", raw["NEW_KEY"], dek, profile_id=profile["id"]) == "synthetic-new"
    assert len(prompts) == 1


def test_existing_open_session_does_not_ask_again(machine, monkeypatch):
    vault.create_profile("Owner", password=PASSWORD)
    broker.start()
    assert broker.signin(password=PASSWORD)["ok"]
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("already signed in"))
    assert cli.main(["signin"]) == 0


def test_invalid_profile_never_prompts_or_starts_service(machine, monkeypatch, capsys):
    vault.create_profile("Owner", password=PASSWORD)
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("unknown profile"))
    assert cli.main(["signin", "--profile", "does-not-exist"]) == 1
    assert "No such profile" in capsys.readouterr().err
    assert not broker.running()


def test_piped_add_never_consumes_input_as_a_vault_password(machine):
    original = orphan(machine)
    result = run_cli(machine, "add", "--stdin", stdin="NEW_KEY=synthetic-new\n")
    assert result.returncode == 1
    assert "passbook signin" in result.stderr
    assert "Vault password:" not in result.stderr
    assert "synthetic-new" not in result.stdout + result.stderr
    assert (machine / ".env").read_bytes() == original


def test_workspace_bootstrap_uses_its_own_store(machine):
    (machine / "workspaces.json").write_text(json.dumps({"activeWorkspaceId": "client", "workspaces": []}))
    passbook.set_values({"CLIENT_KEY": "synthetic-client"})
    result = run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result.stderr
    assert vault.profiles(root=machine / "workspaces/client")
    assert not vault.profiles(root=machine)
    assert vault.status(root=machine / "workspaces/client")["fully_sealed"]


def test_invalid_duration_does_not_initialize_a_vault(machine, monkeypatch):
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("invalid session length"))
    assert cli.main(["signin", "--for", "bad-duration"]) == 1
    assert not vault.profiles()
    assert not broker.running()


def test_add_keeps_existing_encrypted_value_without_replace(machine, monkeypatch):
    profile = vault.create_profile("Owner", password=PASSWORD)
    dek = vault.unlock_with_password(profile["id"], PASSWORD)
    original = vault.seal_value("EXISTING_KEY", "synthetic-original", dek, profile_id=profile["id"])
    passbook.set_values({"EXISTING_KEY": original})
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("nothing to replace"))
    assert cli.main(["add", "EXISTING_KEY=synthetic-replacement"]) == 0
    assert passbook.parse_env_text((machine / ".env").read_text())["EXISTING_KEY"] == original


def test_add_to_initialized_workspace_stays_encrypted(machine, monkeypatch):
    (machine / "workspaces.json").write_text(json.dumps({"activeWorkspaceId": "client", "workspaces": []}))
    passbook.set_values({"CLIENT_KEY": "synthetic-client"})
    assert run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n").returncode == 0
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: PASSWORD)
    assert cli.main(["add", "NEW_KEY=synthetic-new"]) == 0
    raw = passbook.parse_env_text(passbook.target_path().read_text())
    assert vault.is_sealed(raw["NEW_KEY"])


def test_main_workspace_can_have_an_explicit_store_path(machine):
    target = machine / "custom/.env"
    (machine / "workspaces.json").write_text(json.dumps({"activeWorkspaceId": "main", "workspaces": [
        {"id": "main", "envPath": str(target)},
    ]}))
    passbook.set_values({"CLIENT_KEY": "synthetic-client"})
    result = run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result.stderr
    assert vault.profiles(root=target.parent)


@pytest.mark.parametrize("profiles", [None, [None], "invalid"])
def test_malformed_profile_list_has_no_traceback_or_prompt(machine, monkeypatch, capsys, profiles):
    original = json.dumps({"version": 2, "profiles": profiles, "active": ""})
    (machine / "vault.json").write_text(original)
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("malformed vault"))
    assert cli.main(["signin"]) == 1
    assert "Traceback" not in capsys.readouterr().err
    assert (machine / "vault.json").read_text() == original
    assert not broker.running()


def test_signin_to_empty_store_encrypts_the_first_add(machine, monkeypatch):
    result = run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result.stderr
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    assert cli.main(["add", "FIRST_KEY=synthetic-first"]) == 0
    assert vault.is_sealed(passbook.parse_env_text((machine / ".env").read_text())["FIRST_KEY"])


def test_first_secret_is_encrypted_when_setup_only_had_public_settings(machine, monkeypatch):
    passbook.set_values({"NEXT_PUBLIC_SITE_URL": "https://example.test"})
    result = run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result.stderr
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    assert cli.main(["add", "FIRST_KEY=synthetic-first"]) == 0
    raw = passbook.parse_env_text((machine / ".env").read_text())
    assert vault.is_sealed(raw["FIRST_KEY"])
    assert raw["NEXT_PUBLIC_SITE_URL"] == "https://example.test"


def test_full_unseal_still_leaves_later_writes_readable(machine):
    passbook.set_values({"EXISTING_KEY": "synthetic-original"})
    assert run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n").returncode == 0
    assert run_cli(machine, "unseal", "--password-stdin", stdin=PASSWORD + "\n").returncode == 0
    result = run_cli(machine, "add", "NEW_KEY=synthetic-new")
    assert result.returncode == 0, result.stderr
    assert passbook.parse_env_text((machine / ".env").read_text())["NEW_KEY"] == "synthetic-new"


def test_pinned_shell_add_uses_its_open_workspace_key(machine, monkeypatch):
    passbook.set_values({"MAIN_KEY": "synthetic-main"})
    assert run_cli(machine, "signin", "--password-stdin", stdin=PASSWORD + "\n").returncode == 0
    passbook.set_values({"CLIENT_KEY": "synthetic-client"}, workspace_id="client")
    result = run_cli(machine, "signin", "--workspace", "client", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result.stderr
    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts = []
    def password(*a, **k):
        prompts.append(True)
        return PASSWORD
    monkeypatch.setattr(cli, "_ask_password", password)
    assert cli.main(["add", "NEW_KEY=synthetic-new"]) == 0
    root = machine / "workspaces/client"
    profile = vault.active_profile_id(root=root)
    dek = vault.unlock_with_password(profile, PASSWORD, root=root)
    raw = passbook.parse_env_text((root / ".env").read_text())
    assert vault.unseal_value("NEW_KEY", raw["NEW_KEY"], dek, profile_id=profile) == "synthetic-new"
    assert not prompts


@pytest.mark.skipif(os.name == "nt", reason="PTY verification uses the POSIX terminal API")
def test_terminal_add_recovers_over_http_and_saves_without_reentry(machine):
    import pty
    import select
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    orphan(machine)
    requests = []
    class Peer(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = json.dumps({"ok": True, "values": {"EXISTING_KEY": "synthetic-original"}}).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    peer = {"host": "fixture-peer", "address": "127.0.0.1", "port": str(server.server_port)}
    # Inject only discovery; use the real CLI, HTTP fetch, encryption and broker.
    entry = ("import sys, passbook_fleet, passbook_cli; "
             f"passbook_fleet.reachable=lambda: [{peer!r}]; "
             "sys.exit(passbook_cli.main(['add', 'RELAY_API_KEY']))")
    master, slave = pty.openpty()
    child = subprocess.Popen([sys.executable, "-c", entry], stdin=slave, stdout=slave, stderr=slave,
                             env={**os.environ, "PYTHONPATH": str(REPO / "src")})
    os.close(slave)
    transcript = bytearray()
    prompts = [(b"RELAY_API_KEY: ", b"synthetic-relay\n"),
               (b"New vault password: ", PASSWORD.encode() + b"\n"),
               (b"Again: ", PASSWORD.encode() + b"\n")]
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
                if prompts and prompts[0][0] in transcript:
                    _, answer = prompts.pop(0)
                    os.write(master, answer)
            elif child.poll() is not None:
                break
        assert child.wait(timeout=2) == 0, transcript.decode(errors="replace")
        assert not prompts
        assert requests == ["/env?scope=shared&runtime=passbook"]
        assert b"synthetic-relay" not in transcript and PASSWORD.encode() not in transcript
        assert b"broker start" not in transcript
        assert broker.vault_status()["opens"] == 2
        assert set(passbook.key_names()) == {"EXISTING_KEY", "RELAY_API_KEY"}
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)
        server.shutdown()
        server.server_close()
