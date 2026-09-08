# SPDX-License-Identifier: Apache-2.0
"""The local host adapter derives authority; input cannot nominate a signer."""
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_connect as connect
import passbook_managed_cli as cli
import passbook_managed_store as storage

SECRET = "synthetic-protected-host-identity-for-tests"


def run(monkeypatch, capsys, payload):
    monkeypatch.setenv("SYNTHETIC_IDENTITY", SECRET)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
    code = cli.integration(SimpleNamespace(identity_env="SYNTHETIC_IDENTITY"))
    captured = capsys.readouterr()
    assert SECRET not in captured.out and not captured.err
    return code, json.loads(captured.out)


@pytest.mark.parametrize("action", ["connect", "recovery-pair"])
def test_caller_cannot_supply_another_installation_identity(monkeypatch, capsys, action):
    sent = []
    monkeypatch.setattr(cli, "exchange", lambda message: sent.append(message) or {"ok": True})
    assert run(monkeypatch, capsys, {"action": action, "installationId": "attacker", "signature": "attacker",
                                  "body": {"publicKey": "attacker", "workspace": "main"}})[0] == 0
    _, public, ident = connect.identity("SYNTHETIC_IDENTITY")
    assert sent == [{"op": "managed", "action": action, "installationId": ident,
                     "body": {"publicKey": public, "workspace": "main"}}]


def test_refresh_proof_is_public_and_does_not_need_to_start_a_broker(monkeypatch, capsys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    monkeypatch.setattr(cli, "exchange", lambda _: pytest.fail("proof generation must not start a broker"))
    body = {"leaseId": "synthetic-lease", "pairingToken": "synthetic-public-token", "keys": ["API_KEY"]}
    _, result = run(monkeypatch, capsys, {"action": "peer-refresh-proof", "body": body})
    proof = result["proof"]
    _, public, ident = connect.identity("SYNTHETIC_IDENTITY")
    assert proof["installationId"] == ident and storage.verified_body(proof) == body
    Ed25519PublicKey.from_public_bytes(storage.unb64(public)).verify(storage.unb64(proof["signature"]),
        storage.signed_bytes(proof["action"], ident, proof["issuedAt"], proof["nonce"], proof["bodyJson"]))
    code, refused = run(monkeypatch, capsys, {"action": "peer-refresh-proof", "body": {**body, "password": "synthetic-private-password"}})
    assert code == 1 and "synthetic-private-password" not in json.dumps(refused)


def test_unconnected_state_falls_back_only_to_names_without_reusing_unsigned_body(monkeypatch, capsys):
    sent = []
    def exchange(message):
        sent.append(message)
        return {"ok": False, "code": "not-connected"} if len(sent) == 1 else {"ok": True, "state": "unconfigured"}
    monkeypatch.setattr(cli, "exchange", exchange)
    code, result = run(monkeypatch, capsys, {"action": "state", "body": {}})
    assert code == 0 and result["state"] == "unconfigured"
    assert "signature" in sent[0] and sent[1] == {"op": "managed", "action": "state"}


def test_real_cli_waits_for_managed_work_beyond_the_connection_probe_timeout(tmp_path, monkeypatch):
    """Recovery and provider requests can legitimately take more than two seconds."""
    import passbook_broker as broker

    root = tmp_path / "delayed-broker"
    root.mkdir()
    for name in ("HOME", "USERPROFILE", "HIVE_HOME"):
        monkeypatch.setenv(name, str(root))
    for name in ("HIVE_WORKSPACE", "HIVE_WORKSPACE_ID", "HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setenv("PASSBOOK_KEYSTORE", "none")
    source = Path(cli.__file__).parent
    script = """
import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import passbook_broker as broker
original = broker._handle
def delayed(payload, *args, **kwargs):
    if payload.get('op') == 'managed':
        time.sleep(broker.CONNECT_TIMEOUT + 0.3)
    return original(payload, *args, **kwargs)
broker._handle = delayed
broker.serve(root=Path(sys.argv[2]))
"""
    process = subprocess.Popen([sys.executable, "-c", script, str(source), str(root)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=dict(os.environ))
    try:
        deadline = time.monotonic() + 10
        while not broker.running(root=root) and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.05)
        assert broker.running(root=root), "the isolated delayed broker did not start"
        done = subprocess.run([sys.executable, str(source / "passbook_cli.py"), "integration", "--json"],
                              input=json.dumps({"op": "managed", "action": "state"}),
                              text=True, capture_output=True, timeout=10, env=dict(os.environ))
        assert not done.stderr
        reply = json.loads(done.stdout)
        assert done.returncode == 0 and reply["ok"] and reply["state"] == "unconfigured", reply
    finally:
        broker.stop(root=root)
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=10)
