# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_managed_client as client
import passbook_mcp as mcp


@pytest.fixture
def host(monkeypatch):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, self.headers.get("Authorization"), body))
            if body.get("operation") == "redirect":
                self.send_response(302); self.send_header("Location", "/stolen"); self.end_headers(); return
            self.send_response(200); self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "state": "awaiting-approval", "request": {"id": "request-1", "status": "pending"}}).encode())
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization"), None))
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true,"requests":[]}')
        def log_message(self, *_): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setenv("PASSBOOK_AGENT_URL", f"http://127.0.0.1:{server.server_port}/api/passbook")
    monkeypatch.setenv("PASSBOOK_AGENT_TOKEN", "dummy-scoped-agent-token")
    monkeypatch.delenv("PASSBOOK_AGENT_HEADER", raising=False)
    yield seen
    server.shutdown(); server.server_close(); thread.join(2)


def test_mcp_real_host_request_preserves_retry_identity_and_never_sends_owner_authority(host):
    body = {"keys": ["API_KEY"], "operation": "Read", "destination": "https://provider.example/account",
            "account": "work", "taskId": "task-1", "reason": "Finish task", "idempotencyKey": "same-operation", "waitSeconds": 0}
    call = {"id": 1, "method": "tools/call", "params": {"name": "credential_use", "arguments": body}}
    first = mcp.handle(call, {})["result"]["structuredContent"]
    second = mcp.handle(call, {})["result"]["structuredContent"]
    assert first["request"]["id"] == second["request"]["id"] == "request-1"
    assert len(host) == 2 and host[0][2] == host[1][2]
    assert host[0][1] == "Bearer dummy-scoped-agent-token"
    assert "agentId" not in host[0][2] and "ownerVerified" not in host[0][2] and "waitSeconds" not in host[0][2]


def test_redirect_does_not_forward_agent_capability(host):
    result = client.use({"operation": "redirect", "idempotencyKey": "redirect-test", "waitSeconds": 0})
    assert not result["ok"]
    assert [request[0] for request in host] == ["/api/passbook/use"]


def test_managed_mcp_removes_and_refuses_plaintext_tools_even_when_called_directly(host):
    tools = mcp.handle({"id": 1, "method": "tools/list"}, {})["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert {"credential_use", "credential_status"} <= names
    for name in ("get_credential", "get_oauth_token", "run_with_credentials", "proxy_request"):
        assert name not in names
        reply = mcp.handle({"id": 2, "method": "tools/call", "params": {"name": name, "arguments": {}}}, {})
        assert reply["result"]["structuredContent"]["code"] == "managed-connection-required"
    assert not host


def test_offline_managed_store_cannot_fall_back_to_plaintext_tools(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSBOOK_AGENT_URL", raising=False)
    monkeypatch.delenv("PASSBOOK_AGENT_TOKEN", raising=False)
    (tmp_path / "passbook-managed.json").write_text('{"managed":true}')
    reply = mcp.handle({"id": 1, "method": "tools/call", "params": {"name": "get_credential", "arguments": {"name": "API_KEY"}}}, {"root": tmp_path})
    assert reply["result"]["structuredContent"]["code"] == "managed-connection-required"


@pytest.mark.parametrize("url", ["http://remote.example/api/passbook", "https://user:password@example.org", "https://example.org#fragment", "https://example.org?query=1"])
def test_adapter_refuses_unsafe_host_addresses(url, monkeypatch):
    monkeypatch.setenv("PASSBOOK_AGENT_URL", url)
    monkeypatch.setenv("PASSBOOK_AGENT_TOKEN", "dummy-agent")
    assert client.status()["error"] == "This agent's key connection address is not secure."
