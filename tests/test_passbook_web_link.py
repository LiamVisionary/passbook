# SPDX-License-Identifier: Apache-2.0
"""Linking a browser (HivemindOS on the web) to a workspace, through a relay that cannot read.

The browser here is a second real PassBook device in its own directory, so every envelope is
opened by the real `accept`, and the relay is an in-memory stand-in for the HivemindOS gateway.
"""
from __future__ import annotations

import json

import pytest

from test_passbook_integrations import PASSWORD, SECRET, connected, root  # noqa: F401
import passbook_broker as broker
import passbook_integrations as managed
import passbook_link as link
import passbook_web_link as web_link

RELAY = web_link.DEFAULT_RELAYS[0]
REQUEST_ID = "AbCdEfGhIjKlMnOpQrStUv"


class Relay:
    """The gateway's /api/passbook routes, reduced to what PassBook calls."""

    def __init__(self, token: str):
        self.token, self.answers, self.devices, self.unlinked = token, [], {}, set()
        self.signed: list[str] = []

    def __call__(self, method, url, body=None, *, opener=None, sign=False):
        assert url.startswith(RELAY), url
        path = url[len(RELAY):]
        if sign:
            self.signed.append(f"{method} {path}")
        if method == "GET" and path == f"/api/passbook/link-requests/{REQUEST_ID}":
            return 200, {"ok": True, "pairingToken": self.token, "site": "hivemindos.app", "label": "Chrome on Mac"}
        if method == "POST" and path == f"/api/passbook/link-requests/{REQUEST_ID}/answer":
            self.answers.append(body)
            return 200, {"ok": True}
        if method == "POST" and path.startswith("/api/passbook/devices/"):
            did = path.split("/")[4]
            if did in self.unlinked:
                return 410, {"ok": False, "unlinked": True}
            self.devices[did] = body["envelope"]
            return 200, {"ok": True}
        return 404, {"ok": False}


@pytest.fixture
def browser(tmp_path):
    home = tmp_path / "browser"
    home.mkdir()
    return {"root": home, "pairing": link.pairing_token(root=home)}


@pytest.fixture
def relay(browser, monkeypatch):
    fake = Relay(browser["pairing"]["token"])
    monkeypatch.setattr(web_link, "_http", fake)
    return fake


def owner(root, action, **body):
    return managed.handle({"op": "managed", "action": action, "body": body}, root, broker)


def opened(envelope, browser, issuer_fingerprint):
    seen = {}
    link.accept(envelope, confirm_fingerprint=issuer_fingerprint, root=browser["root"],
                write_values=lambda values: seen.update(values) or {"added": sorted(values), "updated": [], "kept": [], "path": "memory"})
    return seen


def test_owner_approves_with_password_and_matching_code_then_the_browser_opens_the_workspace(root, connected, browser, relay):
    code = browser["pairing"]["fingerprint"]
    seen = owner(root, "web-link-inspect", requestId=REQUEST_ID, relay=RELAY)
    assert seen["ok"] and seen["request"]["code"] == code and seen["request"]["label"] == "Chrome on Mac"
    assert "hivemindos" in {row["id"] for row in seen["workspaces"]}

    assert owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="allow",
                 workspace="hivemindos", code=code, password="wrong-password")["code"] == "authentication-failed"
    assert owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="allow",
                 workspace="hivemindos", code="AAAA-BBBB-CCCC-DDDD", password=PASSWORD)["code"] == "code-mismatch"
    assert relay.answers == [], "nothing is sent before both the password and the code check out"

    answer = owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="allow",
                   workspace="hivemindos", code=code.lower().replace("-", " "), password=PASSWORD)
    assert answer["ok"], answer
    assert answer["linked"]["workspace"] == "hivemindos" and answer["linked"]["keys"] == 2
    [sent] = relay.answers
    assert opened(sent["envelope"], browser, answer["issuerFingerprint"]) == {"API_KEY": SECRET, "SECOND_KEY": "synthetic-second-key"}
    assert SECRET not in json.dumps(sent), "the relay carries only the sealed envelope"
    assert PASSWORD not in json.dumps(owner(root, "web-link-list")), "nothing kept or listed carries the password"


def test_sync_keeps_a_linked_browser_current_skips_a_locked_workspace_and_stops_when_unlinked(root, connected, browser, relay):
    code = browser["pairing"]["fingerprint"]
    first = owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="allow",
                  workspace="hivemindos", code=code, password=PASSWORD)
    did = first["linked"]["did"]

    assert broker._seal_values({"values": {"ADDED_LATER": "synthetic-added"}, "workspace": "hivemindos"}, root, None)["ok"]
    synced = owner(root, "web-link-sync")
    assert synced["synced"] == ["Chrome on Mac"]
    assert opened(relay.devices[did], browser, first["issuerFingerprint"])["ADDED_LATER"] == "synthetic-added"
    assert any(row.startswith("POST /api/passbook/devices/") for row in relay.signed), "a refresh is signed"
    assert any(row.endswith("/answer") for row in relay.signed), "and so was the answer that linked it"

    broker._forget_dek()
    locked = owner(root, "web-link-sync")
    assert locked["synced"] == [] and locked["skipped"] == ["Chrome on Mac"], "a locked workspace is never forced open"

    assert broker._signin({"workspace": "hivemindos", "password": PASSWORD, "duration": "forever", "app": "test"}, root, None)["ok"]
    relay.unlinked.add(did)
    gone = owner(root, "web-link-sync")
    assert gone["unlinked"] == ["Chrome on Mac"]
    [row] = owner(root, "web-link-list")["linked"]
    assert row["revokedAt"], "unlinking from HivemindOS stops sealing here too"
    relay.devices.clear()
    assert owner(root, "web-link-sync")["synced"] == [] and relay.devices == {}


def test_decline_sends_a_refusal_and_foreign_relays_are_never_contacted(root, connected, browser, relay):
    assert owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="deny")["ok"]
    assert relay.answers == [{"declined": True}]
    for bad in ("https://evil.example", RELAY + "/steal", "http://hivemindos-paid-agent-gateway.hivemindos.workers.dev"):
        assert owner(root, "web-link-inspect", requestId=REQUEST_ID, relay=bad)["code"] == "relay-refused"
    assert owner(root, "web-link-inspect", requestId="short", relay=RELAY)["code"] == "request-not-found"


def test_link_addresses_parse_strictly():
    assert web_link.parse_link(f"passbook://link?request={REQUEST_ID}&relay={RELAY}") == (REQUEST_ID, RELAY)
    for bad in (f"passbook://link?request={REQUEST_ID}", f"passbook://link?request={REQUEST_ID}&relay={RELAY}&password=x",
                f"https://link?request={REQUEST_ID}&relay={RELAY}", f"passbook://link?request=bad&relay={RELAY}"):
        with pytest.raises(Exception):
            web_link.parse_link(bad)


def test_revoke_reports_what_it_cannot_recall(root, connected, browser, relay):
    first = owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="allow",
                  workspace="hivemindos", code=browser["pairing"]["fingerprint"], password=PASSWORD)
    answer = owner(root, "web-link-revoke", did=first["linked"]["did"])
    assert answer["ok"] and "rotate" in answer["detail"]
    assert owner(root, "web-link-sync")["synced"] == []


def test_a_workspace_without_a_password_is_refused_by_name_not_as_a_wrong_password(root, connected, browser, relay, monkeypatch):
    """Linking is confirmed with the workspace's password. A workspace that has none was
    offered anyway and could only fail as "The password was not accepted"."""
    code = browser["pairing"]["fingerprint"]
    seen = owner(root, "web-link-inspect", requestId=REQUEST_ID, relay=RELAY)
    assert all("hasProfile" in row for row in seen["workspaces"]), "the picker needs to know which can be linked"

    real_rows = managed._workspace_rows
    monkeypatch.setattr(managed, "_workspace_rows",
                        lambda r: [{**row, "hasProfile": False} if row["id"] == "hivemindos" else row for row in real_rows(r)])
    answer = owner(root, "web-link-decide", requestId=REQUEST_ID, relay=RELAY, decision="allow",
                   workspace="hivemindos", code=code, password=PASSWORD)
    assert answer["code"] == "workspace-unprotected"
    assert relay.answers == [], "nothing is sent for a workspace that cannot be linked"


def test_what_passbook_sends_a_browser_is_signed_by_the_machine_sending_it(monkeypatch, tmp_path):
    """The answer and every refresh carry X-PassBook-Proof, so the relay knows which PassBook a browser
    belongs to and takes fresh envelopes for it from that machine alone. Reads are not signed: they
    carry nothing only this machine could say."""
    import hashlib
    import io
    import passbook_join
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.setenv("PASSBOOK_WEB_RELAYS", RELAY)
    seen = []

    class Answer(io.BytesIO):
        status = 200

    def opener(request, timeout=None):
        seen.append(request)
        return Answer(b'{"ok": true}')

    body = {"envelope": "passbook-env:v1:abc"}
    path = "/api/passbook/devices/did:key:zExample/envelope"
    assert web_link._http("POST", RELAY + path, body, opener=opener, sign=True) == (200, {"ok": True})
    assert web_link._http("GET", RELAY + "/api/passbook/link-requests/x", opener=opener) == (200, {"ok": True})
    signed, plain = seen
    assert plain.get_header("X-passbook-proof") is None
    did, seconds, signature = signed.get_header("X-passbook-proof").split(" ")
    assert did == link.identity()["did"]
    text = signed.data.decode()
    message = f"passbook-relay:v1\nPOST\n{path}\n{seconds}\n{hashlib.sha256(text.encode()).hexdigest()}"
    Ed25519PublicKey.from_public_bytes(link.public_from_did(did)).verify(passbook_join._unb64(signature), message.encode())
    assert json.loads(text) == body, "the bytes signed are the bytes sent"
