# SPDX-License-Identifier: Apache-2.0
"""Managed connections, through authenticated requests and isolated real stores."""
from __future__ import annotations

import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook
import passbook_access as access
import passbook_broker as broker
import passbook_integrations as managed
import passbook_managed_http as managed_http
import passbook_managed_store as storage
import passbook_vault as vault

PASSWORD = "synthetic-owner-password"
SECRET = "synthetic-managed-credential-735"


class Installation:
    def __init__(self, root, transport=None):
        self.root = root
        self.key = Ed25519PrivateKey.generate()
        self.public = storage.b64(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.id = storage.installation_id(self.public)
        self.transport = transport or (lambda envelope: managed.handle(envelope, root, broker))

    def connect(self, **overrides):
        body = {"publicKey": self.public, "app": "hivemindos", "name": "HivemindOS",
                "workspace": "hivemindos", "createWorkspace": True, "consent": True,
                "password": PASSWORD, "background": False, **overrides}
        return self.transport({"action": "connect", "installationId": self.id, "body": body})

    def envelope(self, action, body=None, *, body_json=None, issued=None, nonce=None):
        body_json = storage.canonical(body or {}) if body_json is None else body_json
        issued = storage.now_ms() if issued is None else issued
        nonce = uuid.uuid4().hex if nonce is None else nonce
        message = storage.signed_bytes(action, self.id, issued, nonce, body_json)
        return {"action": action, "installationId": self.id, "issuedAt": issued, "nonce": nonce,
                "bodyJson": body_json, "signature": storage.b64(self.key.sign(message))}

    def call(self, action, body=None):
        return self.transport(self.envelope(action, body))

    def approve(self, request, scope="once", *, host=False, decision="allow"):
        request_id = request["request"]["id"]
        challenge = self.call("challenge", {"requestId": request_id, "scope": scope, "decision": decision})
        assert challenge["ok"], challenge
        body = {**challenge["challenge"], **({"ownerVerified": True} if host else {"password": PASSWORD})}
        return self.call("decision", body)


def operation(**overrides):
    return {"agentId": "agent-a", "agentName": "Helpful agent", "keys": ["API_KEY"],
            "operation": "Read account", "destination": "https://service.example/account",
            "taskId": "task-a", "account": "work", "idempotencyKey": uuid.uuid4().hex,
            "parameters": {"method": "GET"}, **overrides}


@pytest.fixture
def root(tmp_path, monkeypatch):
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for name in ("HIVE_WORKSPACE", "HIVE_WORKSPACE_ID", "HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    broker._forget_dek()
    yield home
    broker._forget_dek()


@pytest.fixture
def connected(root):
    app = Installation(root)
    answer = app.connect()
    assert answer["ok"] and answer["state"] == "ready", answer
    result = broker._seal_values({"values": {"API_KEY": SECRET, "SECOND_KEY": "synthetic-second-key"},
                                   "workspace": "hivemindos"}, root, None)
    assert result["ok"], result
    return app


@pytest.fixture
def calls(monkeypatch):
    calls = []
    def proxy(parameters, values):
        calls.append((parameters, values))
        return {"ok": True, "status": 200, "body": "synthetic provider result", "used": sorted(values)}
    monkeypatch.setattr(managed_http, "proxy", proxy)
    return calls


def test_fresh_connection_creates_an_isolated_encrypted_workspace(root):
    app = Installation(root)
    state = app.connect()
    assert state["ok"] and state["state"] == "ready"
    assert state["binding"]["workspace"] == "hivemindos"
    assert not passbook.workspace_inherits("hivemindos", managed.env_for(root))
    assert vault.active_profile_id(root=managed.workspace_path(root, "hivemindos").parent)
    assert not (root / ".env").exists()
    assert state["grants"] == []
    assert PASSWORD not in json.dumps(state)


def test_existing_workspace_requires_its_password_and_preserves_main(root):
    passbook.set_values({"MAIN_ONLY": "synthetic-main"}, environ=managed.env_for(root))
    original_main = (root / ".env").read_bytes()
    app = Installation(root)
    assert app.connect()["ok"]
    profile = vault.active_profile_id(root=managed.workspace_path(root, "hivemindos").parent)
    second = Installation(root)
    assert second.connect(password="incorrect-password")["code"] == "authentication-failed"
    assert second.connect()["ok"]
    assert vault.active_profile_id(root=managed.workspace_path(root, "hivemindos").parent) == profile
    assert (root / ".env").read_bytes() == original_main
    assert passbook.workspace({"HIVE_HOME": str(root)}) in {"", "main"}


def test_foreign_ciphertext_requires_recovery_without_any_replacement(root):
    target = managed.workspace_path(root, "hivemindos")
    target.parent.mkdir(parents=True)
    original = "API_KEY=hive-sealed:v2:orphaned-synthetic-value\n"
    target.write_text(original)
    answer = Installation(root).connect()
    assert answer["code"] == "workspace-recovery-required"
    assert target.read_text() == original
    assert not vault.active_profile_id(root=target.parent)


@pytest.mark.parametrize("change", ["signature", "bodyJson", "action", "installationId", "issuedAt", "nonce"])
def test_tampered_envelope_cannot_act_as_the_connected_installation(connected, change):
    envelope = connected.envelope("request", operation())
    replacements = {"signature": storage.b64(b"\0" * 64), "bodyJson": storage.canonical(operation(agentId="forged")),
                    "action": "service-values", "installationId": "0" * 64,
                    "issuedAt": envelope["issuedAt"] + 1, "nonce": uuid.uuid4().hex}
    envelope[change] = replacements[change]
    answer = connected.transport(envelope)
    assert not answer["ok"] and answer["code"] in {"invalid-proof", "not-connected"}
    assert connected.call("state")["requests"] == []


def test_exact_signed_json_is_executed_and_unsigned_body_is_ignored(connected):
    raw = json.dumps(operation(reason="Unicode π and number formatting", parameters={"method": "GET", "body": {"n": 1.0}}), indent=2)
    envelope = connected.envelope("request", body_json=raw)
    envelope["body"] = operation(agentId="forged-agent")
    answer = connected.transport(envelope)
    assert answer["ok"] and answer["request"]["agentId"] == "agent-a"
    assert answer["request"]["reason"] == "Unicode π and number formatting"
    assert connected.transport(envelope)["code"] == "replayed-proof"


@pytest.mark.parametrize("raw", ["[]", "null", '{"x":NaN}', '{"x":Infinity}', '{'])
def test_signed_malformed_json_is_rejected(connected, raw):
    assert not connected.transport(connected.envelope("request", body_json=raw))["ok"]


def test_expired_assertions_cannot_be_replayed(connected):
    envelope = connected.envelope("state", issued=storage.now_ms() - storage.MAX_CLOCK_SKEW_MS - 1)
    assert connected.transport(envelope)["code"] == "invalid-proof"


def test_agent_names_do_not_transfer_permissions_between_agent_ids(connected):
    body = operation()
    first = connected.call("request", body)
    assert connected.approve(first, "remember", host=True)["ok"]
    assert connected.call("request", operation())["state"] == "ready"
    other = connected.call("request", operation(agentId="agent-b", agentName=body["agentName"]))
    assert other["state"] == "awaiting-approval"
    assert other["request"]["agentId"] == "agent-b"


@pytest.mark.parametrize("change", [
    {"parameters": {"method": "DELETE"}}, {"destination": "https://service.example/other"},
    {"keys": ["SECOND_KEY"]}, {"account": "personal"}, {"operation": "Change account"},
])
def test_remembered_permission_keeps_operation_destination_account_and_keys(connected, change):
    assert connected.approve(connected.call("request", operation()), "remember")["ok"]
    assert connected.call("request", operation(**change))["state"] == "awaiting-approval"


def test_task_permission_expires_at_the_task_boundary(connected):
    assert connected.approve(connected.call("request", operation()), "task")["ok"]
    assert connected.call("request", operation())["state"] == "ready"
    assert connected.call("request", operation(taskId="other-task"))["state"] == "awaiting-approval"


def test_all_keys_permission_is_explicit_and_still_bound_to_agent_and_destination(connected):
    assert connected.approve(connected.call("request", operation()), "all-keys")["ok"]
    assert connected.call("request", operation(keys=["SECOND_KEY"]))["state"] == "ready"
    assert connected.call("request", operation(keys=["SECOND_KEY"], agentId="other"))["state"] == "awaiting-approval"


def test_decision_requires_owner_auth_and_one_unchanged_challenge(connected):
    request = connected.call("request", operation())
    challenge = connected.call("challenge", {"requestId": request["request"]["id"], "scope": "once", "decision": "allow"})["challenge"]
    assert connected.call("decision", challenge)["code"] == "authentication-required"
    assert connected.call("decision", {**challenge, "password": "wrong-password"})["code"] == "authentication-failed"
    assert connected.call("decision", {**challenge, "scope": "all-keys", "password": PASSWORD})["code"] == "invalid-challenge"
    assert connected.call("decision", {**challenge, "ownerVerified": True})["ok"]
    assert connected.call("decision", {**challenge, "ownerVerified": True})["code"] == "invalid-challenge"


def test_another_installation_cannot_resolve_its_peers_approval(connected):
    request = connected.call("request", operation())
    other = Installation(connected.root)
    assert other.connect()["ok"]
    answer = other.call("challenge", {"requestId": request["request"]["id"], "scope": "once", "decision": "allow"})
    assert answer["code"] == "request-not-found"


def test_once_permission_executes_once_and_exact_retries_return_saved_result(connected, calls):
    body = operation()
    request = connected.call("request", body)
    assert connected.approve(request)["ok"]
    first = connected.call("use", body)
    second = connected.call("use", body)
    assert first == second and first["result"]["status"] == 200
    assert len(calls) == 1
    assert calls[0][1] == {"API_KEY": SECRET}
    assert SECRET not in json.dumps(first)
    assert connected.call("use", operation())["state"] == "awaiting-approval"
    assert SECRET.encode() not in (connected.root / storage.FILENAME).read_bytes()


def test_concurrent_retry_requests_and_use_share_one_record_and_execution(connected, calls):
    body = operation()
    with ThreadPoolExecutor(max_workers=8) as pool:
        requests = list(pool.map(lambda _: connected.call("request", body), range(16)))
    assert {row["request"]["id"] for row in requests} == {requests[0]["request"]["id"]}
    assert connected.approve(requests[0], "remember")["ok"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: connected.call("use", body), range(16)))
    assert len(calls) == 1
    assert all(row["requestId"] == requests[0]["request"]["id"] for row in results)


def test_idempotency_key_cannot_change_operation_or_cross_agent_identity(connected):
    body = operation()
    first = connected.call("request", body)
    assert connected.call("request", {**body, "parameters": {"method": "DELETE"}})["code"] == "idempotency-conflict"
    other = connected.call("request", {**body, "agentId": "other"})
    assert other["request"]["id"] != first["request"]["id"]


def test_pause_and_revocation_stop_future_uses_and_reconnect_does_not_restore_grants(connected, calls):
    body = operation()
    assert connected.approve(connected.call("request", body), "remember")["ok"]
    assert connected.call("pause", {"paused": True})["state"] == "paused"
    assert connected.call("use", body)["code"] == "paused"
    assert connected.call("pause", {"paused": False})["state"] == "ready"
    assert connected.call("revoke", {"disconnect": True})["ok"]
    assert connected.call("use", body)["code"] == "not-connected"
    assert connected.connect()["ok"]
    assert connected.call("state")["grants"] == []
    assert connected.call("use", operation())["state"] == "awaiting-approval"
    assert calls == []


def test_missing_key_is_supplied_encrypted_only_to_its_requested_workspace(connected):
    request = connected.call("request", operation(keys=["MISSING_KEY"]))
    assert request["state"] == "absent"
    value = "synthetic-new-missing-key"
    supplied = connected.call("supply-key", {"requestId": request["request"]["id"],
        "key": "MISSING_KEY", "value": value, "password": PASSWORD})
    assert supplied["ok"] and supplied["request"]["missingKeys"] == []
    target = managed.workspace_path(connected.root, "hivemindos")
    assert value not in target.read_text()
    assert passbook.parse_env_text(target.read_text())["MISSING_KEY"].startswith("hive-sealed:v2:")
    assert value not in json.dumps(supplied)
    assert value.encode() not in (connected.root / storage.FILENAME).read_bytes()
    assert not (connected.root / ".env").exists()
    repeat = connected.call("supply-key", {"requestId": request["request"]["id"],
        "key": "MISSING_KEY", "value": "replacement", "password": PASSWORD})
    assert repeat["code"] == "already-present"


def test_agent_cannot_receive_service_values_even_with_a_valid_host_signature(connected):
    denied = connected.call("service-values", {"agentId": "agent-a", "keys": ["API_KEY"]})
    assert denied["code"] == "agent-read-forbidden"
    assert SECRET not in json.dumps(denied)
    service = connected.call("service-values", {"keys": ["API_KEY"]})
    assert service["values"] == {"API_KEY": SECRET}


def test_rejoined_deduplicated_request_never_executes_twice(connected, calls):
    body = operation()
    other_retry = {**body, "idempotencyKey": "another-retry-key"}
    first = connected.call("request", body)
    second = connected.call("request", other_retry)
    assert second["request"]["id"] == first["request"]["id"]
    assert connected.approve(first, "remember")["ok"]
    connected.call("use", body)
    connected.call("use", other_retry)
    assert len(calls) == 1


def test_project_restrictions_use_the_authenticated_project(connected):
    policy = broker.read_policy(connected.root)
    access.set_projects("API_KEY", "include", ["allowed-project"], policy)
    broker.write_policy(policy, connected.root)
    answer = connected.call("request", operation(project="allowed-project"))
    assert answer["ok"] and answer["state"] == "awaiting-approval", answer
    assert connected.call("request", operation(project="other-project"))["code"] == "policy-denied"


def test_background_unlock_survives_broker_key_loss_but_explicit_pause_does_not(root, monkeypatch):
    import passbook_keystore as keystore
    protected = {}
    monkeypatch.setattr(keystore, "available", lambda: True)
    monkeypatch.setattr(keystore, "store", lambda name, value: protected.update({name: value}) or {"ok": True})
    monkeypatch.setattr(keystore, "fetch", lambda name: protected.get(name, ""))
    monkeypatch.setattr(keystore, "forget", lambda name: protected.pop(name, None) is not None)
    app = Installation(root)
    assert app.connect(background=True)["state"] == "ready"
    assert protected
    broker._forget_dek("hivemindos")
    assert app.call("state")["state"] == "ready"
    managed.pause_workspace("hivemindos", root)
    broker._forget_dek("hivemindos")
    assert app.call("state")["state"] == "paused"
    assert broker._held_dek("hivemindos")[0] is None


def test_background_connect_fails_before_profile_creation_without_protected_storage(root, monkeypatch):
    import passbook_keystore
    monkeypatch.setattr(passbook_keystore, "available", lambda: False)
    answer = Installation(root).connect(background=True)
    assert answer["code"] == "background-unavailable"
    assert not vault.active_profile_id(root=managed.workspace_path(root, "hivemindos").parent)


def test_expired_approval_challenge_and_grant_do_not_open_a_request(connected):
    request = connected.call("request", operation())
    challenge = connected.call("challenge", {"requestId": request["request"]["id"], "scope": "once", "decision": "allow"})["challenge"]
    with storage.Store(connected.root).transaction() as tx:
        saved = tx.get("challenge", challenge["challenge"])
        tx.put("challenge", challenge["challenge"], {**saved, "expiresMs": storage.now_ms() - 1})
    assert connected.call("decision", {**challenge, "ownerVerified": True})["code"] == "invalid-challenge"
    assert connected.approve(request, "task")["ok"]
    with storage.Store(connected.root).transaction() as tx:
        for grant in tx.all("grant"):
            tx.put("grant", grant["id"], {**grant, "expiresMs": storage.now_ms() - 1})
    assert connected.call("request", operation())["state"] == "awaiting-approval"


def test_revoke_one_permission_keeps_other_agent_permissions(connected):
    assert connected.approve(connected.call("request", operation()), "remember")["ok"]
    assert connected.approve(connected.call("request", operation(agentId="agent-b")), "remember")["ok"]
    grants = connected.call("state")["grants"]
    first = next(row for row in grants if row["agentId"] == "agent-a")
    assert connected.call("revoke", {"grantId": first["id"]})["ok"]
    assert connected.call("request", operation())["state"] == "awaiting-approval"
    assert connected.call("request", operation(agentId="agent-b"))["state"] == "ready"


@pytest.fixture
def tls_provider(tmp_path, monkeypatch, request):
    """A trusted synthetic HTTPS provider: no internet, real TLS and headers."""
    import http.server
    import ipaddress
    import ssl
    import threading
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = getattr(request, "param", "localhost")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    names = [x509.DNSName(hostname)]
    if hostname == "localhost":
        names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, hashes.SHA256()))
    certificate, private = tmp_path / "test-ca.pem", tmp_path / "test-server-key.pem"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    calls = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            calls.append({"path": self.path, "authorization": auth})
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "/unapproved")
            self.send_header("X-Echo", auth)
            if self.path == "/header-name":
                self.send_header("X-" + auth.removeprefix("Bearer "), "echo")
            self.send_header("Set-Cookie", auth)
            self.end_headers()
            self.wfile.write(("provider echoed " + auth).encode())
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(private))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield {"url": f"https://localhost:{server.server_address[1]}", "calls": calls}
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_real_https_proxy_scrubs_body_headers_and_refuses_redirects(tls_provider):
    url = tls_provider["url"]
    answer = managed_http.proxy({"url": url + "/account", "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": SECRET})
    assert answer["ok"] and answer["status"] == 200, answer
    assert SECRET not in json.dumps(answer)
    assert "set-cookie" not in {key.lower() for key in answer["headers"]}
    assert tls_provider["calls"] == [{"path": "/account", "authorization": "Bearer " + SECRET}]
    refused = managed_http.proxy({"url": url + "/redirect", "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": SECRET})
    assert not refused["ok"] and refused["status"] == 302
    assert [row["path"] for row in tls_provider["calls"]] == ["/account", "/redirect"]


def test_real_https_refuses_untrusted_certificate_before_sending_credentials(tls_provider, monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE")
    answer = managed_http.proxy({"url": tls_provider["url"] + "/account",
        "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": SECRET})
    assert not answer["ok"] and "could not be reached" in answer["error"], answer
    assert tls_provider["calls"] == []
    assert SECRET not in json.dumps(answer)


@pytest.mark.parametrize("tls_provider", ["different.example"], indirect=True)
def test_real_https_refuses_trusted_certificate_for_wrong_hostname(tls_provider):
    answer = managed_http.proxy({"url": tls_provider["url"] + "/account",
        "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": SECRET})
    assert not answer["ok"] and "could not be reached" in answer["error"], answer
    assert tls_provider["calls"] == []
    assert SECRET not in json.dumps(answer)


def test_real_https_refuses_invalid_host_trust_configuration(tls_provider, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing-ca.pem"))
    answer = managed_http.proxy({"url": tls_provider["url"] + "/account",
        "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": SECRET})
    assert not answer["ok"] and "could not be reached" in answer["error"], answer
    assert tls_provider["calls"] == []
    assert SECRET not in json.dumps(answer)


def test_real_broker_connection_approval_restart_use_and_disconnect(root, tls_provider):
    """The production socket, real encrypted files, persisted grants and TLS."""
    started = broker.start(root=root)
    assert started["ok"], started
    app = Installation(root, transport=lambda envelope: broker._ask({"op": "managed", **envelope}, root=root, timeout=30))
    try:
        assert app.connect()["ok"]
        body = operation(destination=tls_provider["url"] + "/account")
        request = app.call("request", body)
        assert request["state"] == "absent"
        supplied = app.call("supply-key", {"requestId": request["request"]["id"], "key": "API_KEY",
                                           "value": SECRET, "password": PASSWORD})
        assert supplied["ok"]
        assert app.approve(supplied, "remember", host=True)["ok"]
        state_before = app.call("state")
        assert len(state_before["grants"]) == 1
        assert broker.stop(root=root)["ok"]
        assert broker.start(root=root)["ok"]
        assert app.call("state")["state"] == "locked"
        assert app.connect()["ok"]
        assert app.call("state")["grants"] == state_before["grants"]
        used = app.call("use", body)
        assert used["result"].get("status") == 200, used
        assert SECRET not in json.dumps(used)
        assert len(tls_provider["calls"]) == 1
        assert app.call("use", body) == used
        assert len(tls_provider["calls"]) == 1
        legacy = broker._ask({"op": "request", "app": "hivemindos", "workspace": "hivemindos", "keys": ["API_KEY"]}, root=root)
        assert legacy.get("granted", {}) == {} and not legacy.get("missing")
        assert app.call("service-values", {"keys": ["API_KEY"], "agentId": "forged-agent"})["code"] == "agent-read-forbidden"
        assert app.call("revoke", {"disconnect": True})["ok"]
        assert app.call("use", operation(destination=tls_provider["url"] + "/account"))["code"] == "not-connected"
        assert len(tls_provider["calls"]) == 1
        assert SECRET.encode() not in (root / storage.FILENAME).read_bytes()
        assert SECRET not in managed.workspace_path(root, "hivemindos").read_text()
    finally:
        broker.stop(root=root)


def test_a_locked_existing_key_is_reported_locked_and_owner_password_opens_approved_use(connected, calls):
    broker._forget_dek("hivemindos")
    body = operation()
    request = connected.call("request", body)
    assert request["state"] == "locked"
    assert request["request"]["missingKeys"] == []
    assert connected.approve(request, "once")["ok"]
    used = connected.call("use", body)
    assert used["state"] == "ready" and used["result"]["status"] == 200, used
    assert len(calls) == 1


@pytest.mark.parametrize("restriction", ["never", "audience", "workspace", "destination"])
def test_managed_grant_cannot_override_an_explicit_credential_restriction(connected, restriction, calls):
    body = operation()
    assert connected.approve(connected.call("request", body), "remember")["ok"]
    policy = broker.read_policy(connected.root)
    if restriction == "never":
        policy.setdefault("apps", {})["agent-a"] = {"keys": {"API_KEY": {"mode": "never"}}}
    elif restriction == "audience":
        access.set_audience("API_KEY", "include", ["another-agent"], policy)
    elif restriction == "workspace":
        access.set_scope("API_KEY", "workspace", policy, workspace="another-workspace")
    else:
        access.set_guard("API_KEY", policy, destinations=["different.example"])
    broker.write_policy(policy, connected.root)
    answer = connected.call("use", body)
    assert answer["code"] == "policy-denied", answer
    assert calls == []


@pytest.mark.parametrize("change", [
    {"destination": "http://service.example/account"},
    {"destination": "https://user:pass@service.example/account"},
    {"destination": "https://service.example/account#fragment"},
    {"parameters": {"url": "https://different.example/account"}},
    {"parameters": {"method": "CONNECT"}},
    {"parameters": {"headers": {"Host": "different.example"}}},
    {"parameters": {"headers": {"Authorization": "Bearer {{SECOND_KEY}}"}}},
    {"parameters": {"body": "{{API_KEY}}"}},
])
def test_connection_operation_cannot_change_destination_or_smuggle_unnamed_credentials(connected, change):
    answer = connected.call("request", operation(**change))
    assert not answer["ok"]
    assert connected.call("state")["requests"] == []


def test_unsigned_state_does_not_expose_an_installations_requests_or_grants(connected):
    assert connected.call("request", operation())["state"] == "awaiting-approval"
    answer = connected.transport({"action": "state", "installationId": connected.id})
    assert answer["state"] == "unconfigured" and answer["binding"] is None
    assert answer["requests"] == [] and answer["grants"] == []


def test_real_https_never_returns_a_credential_in_response_header_names(tls_provider):
    answer = managed_http.proxy({"url": tls_provider["url"] + "/header-name",
        "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": SECRET})
    assert answer["ok"]
    assert SECRET not in json.dumps(answer)
    assert not any(SECRET in key for key in answer["headers"])


@pytest.mark.parametrize("value", ["abc", "12345"])
def test_real_https_redacts_short_credential_echoes_in_body_and_headers(tls_provider, value):
    answer = managed_http.proxy({"url": tls_provider["url"] + "/account",
        "headers": {"Authorization": "Bearer {{API_KEY}}"}}, {"API_KEY": value})
    assert answer["ok"]
    assert value not in answer["body"]
    assert all(value not in header for header in answer["headers"].values())
