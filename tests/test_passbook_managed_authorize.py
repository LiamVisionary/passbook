"""Authorization links carry identifiers, never enrollment or pickup authority."""
import json
import importlib.util
from pathlib import Path
import pytest

from test_passbook_integrations import Installation, PASSWORD, root  # noqa: F401
import passbook_managed_authorize as authorize
import passbook_managed_store as storage


def begin(app):
    return app.call("authorize-begin", {"publicKey": app.public, "app": "hivemindos"})


def owner(app, action, request_id, **body):
    return app.transport({"action": action, "body": {"requestId": request_id, **body}})


def approve(app, request_id, **body):
    return owner(app, "authorize-decide", request_id, decision="allow", workspace="main",
                 background=False, consent=True, createWorkspace=True, password=PASSWORD, **body)


def test_owner_password_connects_exact_request_and_signed_host_picks_up(root):
    app = Installation(root)
    first = begin(app)
    request_id = first["request"]["id"]
    assert first["ok"] and first["request"]["status"] == "pending"
    assert begin(app)["request"]["id"] == request_id
    assert app.call("state")["code"] == "not-connected"
    inspected = owner(app, "authorize-inspect", request_id)
    assert inspected["ok"] and inspected["request"]["name"] == "HivemindOS"
    assert approve(app, request_id)["request"]["status"] == "approved"
    assert app.call("authorize-status", {"requestId": request_id})["request"]["status"] == "approved"
    state = app.call("state")
    assert state["state"] == "ready" and state["binding"]["workspace"] == "main"
    assert state["grants"] == []
    assert approve(app, request_id)["code"] == "already-resolved"
    assert PASSWORD not in json.dumps(state)
    assert PASSWORD.encode() not in (root / storage.FILENAME).read_bytes()


def test_password_failure_does_not_bind_and_retry_is_bounded(root, monkeypatch):
    app = Installation(root)
    assert app.connect(workspace="main")["ok"]
    request_id = begin(app)["request"]["id"]
    clock = authorize.now_ms()
    monkeypatch.setattr(authorize, "now_ms", lambda: clock)
    for _ in range(authorize.MAX_ATTEMPTS):
        answer = owner(app, "authorize-decide", request_id, decision="allow", workspace="main",
                       background=False, consent=True, password="wrong-password")
        assert answer["code"] == "authentication-failed"
        clock += 1001
    assert approve(app, request_id)["code"] == "authorization-busy"
    assert app.call("authorize-status", {"requestId": request_id})["request"]["status"] == "pending"


def test_unsigned_tampered_other_installation_and_replay_refused(root):
    app, other = Installation(root), Installation(root)
    envelope = app.envelope("authorize-begin", {"publicKey": app.public, "app": "hivemindos"})
    first = app.transport(envelope)
    request_id = first["request"]["id"]
    assert app.transport(envelope)["code"] == "replayed-proof"
    assert other.call("authorize-status", {"requestId": request_id})["code"] == "invalid-proof"
    assert not owner(app, "authorize-status", request_id)["ok"]
    tampered = app.envelope("authorize-begin", {"publicKey": app.public, "app": "hivemindos"})
    tampered["installationId"] = other.id
    assert app.transport(tampered)["code"] == "invalid-proof"
    assert not owner(app, "authorize-decide", request_id, decision="allow", ownerVerified=True)["ok"]


@pytest.mark.parametrize("action,status", [("authorize-decide", "denied"), ("authorize-cancel", "cancelled")])
def test_denial_and_host_cancel_never_connect(root, action, status):
    app = Installation(root)
    request_id = begin(app)["request"]["id"]
    answer = (owner(app, action, request_id, decision="deny") if action == "authorize-decide"
              else app.call(action, {"requestId": request_id}))
    assert answer["request"]["status"] == status
    assert approve(app, request_id)["code"] == "already-resolved"
    assert app.call("state")["code"] == "not-connected"


def test_expiry_and_global_pending_limit(root, monkeypatch):
    monkeypatch.setattr(authorize, "MAX_REQUESTS", 2)
    app = Installation(root)
    request_id = begin(app)["request"]["id"]
    assert begin(Installation(root))["ok"]
    assert begin(Installation(root))["code"] == "authorization-busy"
    monkeypatch.setattr(authorize, "now_ms", lambda: storage.now_ms() + authorize.LIFETIME_MS + 1)
    assert app.call("authorize-status", {"requestId": request_id})["request"]["status"] == "expired"
    assert approve(app, request_id)["code"] == "request-expired"
    assert begin(Installation(root))["ok"]


def test_packaged_desktop_staging_includes_authorization_module(tmp_path, monkeypatch):
    repository = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("authorize_test_staging", repository / "scripts/stage-runtime.py")
    staging = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(staging)
    monkeypatch.setattr(staging, "ROOT", tmp_path)
    monkeypatch.setattr(staging, "CLI_DIR", tmp_path / "cli")
    copied = staging.stage_cli()
    assert "passbook_managed_authorize.py" in copied
    assert (tmp_path / "cli/passbook_managed_authorize.py").read_bytes() == (repository / "src/passbook_managed_authorize.py").read_bytes()


def test_begin_reuses_pending_request_after_an_older_denial(root, monkeypatch):
    ids = iter(["f" * 32, "0" * 32])
    monkeypatch.setattr(authorize, "identifier", lambda: next(ids))
    clock = authorize.now_ms()
    monkeypatch.setattr(authorize, "now_ms", lambda: clock)
    app = Installation(root)
    old = begin(app)["request"]["id"]
    assert owner(app, "authorize-decide", old, decision="deny")["ok"]
    clock += 10_001
    current = begin(app)["request"]["id"]
    assert begin(app)["request"]["id"] == current
