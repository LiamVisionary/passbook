# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Adding a computer with `passbook join`, and keeping it current.

Two machines and a relay that is honest about transport and nothing else. The relay here is a fake
that holds the same contract as the real one (hivemindos-passbook-relay, tested in its own repo):
every call is signed by the machine making it, and it never sees a credential or the invite's
secret. Each test names the property in passbook_join's docstring that it holds.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import secrets
import sys
import urllib.error
import urllib.parse
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_link  # noqa: E402

pytestmark = pytest.mark.skipif(not passbook_link.available(), reason="joining needs the `cryptography` package")

import passbook_access as access  # noqa: E402
import passbook_join as join  # noqa: E402

RELAY = "https://relay.test"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key_of(did: str) -> bytes:
    value = 0
    for character in did[len("did:key:z"):]:
        value = value * 58 + B58.index(character)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    assert raw[:2] == b"\xed\x01"
    return raw[2:]


class FakeRelay:
    """The relay contract, held in memory. Records every request so tests can check what it saw."""

    def __init__(self):
        self.invites: dict[str, dict] = {}
        self.boxes: dict[tuple[str, str], dict] = {}
        self.seen: list[str] = []

    def _signer(self, request) -> str | None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        did, seconds, signature = request.get_header("X-passbook-proof").split(" ")
        parsed = urllib.parse.urlsplit(request.full_url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        body = (request.data or b"").decode()
        message = f"passbook-relay:v1\n{request.get_method()}\n{path}\n{seconds}\n{hashlib.sha256(body.encode()).hexdigest()}"
        try:
            Ed25519PublicKey.from_public_bytes(_key_of(did)).verify(_unb64(signature), message.encode())
        except Exception:
            return None
        return did

    def __call__(self, request, timeout=None):
        self.seen.append(request.full_url + " " + (request.data or b"").decode())
        status, answer = self.handle(request)
        if status != 200:
            raise urllib.error.HTTPError(request.full_url, status, "x", {}, io.BytesIO(json.dumps(answer).encode()))
        return contextlib.closing(_Response(status, answer))

    def handle(self, request):
        signer = self._signer(request)
        if not signer:
            return 401, {"ok": False}
        parsed = urllib.parse.urlsplit(request.full_url)
        path, method = parsed.path, request.get_method()
        body = json.loads(request.data or b"{}")
        parts = path.split("/")[3:]
        if parts == ["machine-invites"] and method == "POST":
            invite_id = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")
            self.invites[invite_id] = {"issuer": signer, "status": "open"}
            return 200, {"ok": True, "inviteId": invite_id, "expiresAt": passbook_link._stamp(passbook_link._now() + timedelta(minutes=15))}
        if parts[0] == "machine-invites":
            row = self.invites.get(parts[1])
            action = parts[2] if len(parts) > 2 else ""
            if row is None:
                return 404, {"ok": False}
            if action == "join":
                if row["status"] != "open":
                    return 404, {"ok": False}
                assert passbook_link.read_pairing_token(body["pairingToken"])["did"] == signer
                row.update(status="joined", device=signer, token=body["pairingToken"], proof=body["proof"], label=body.get("label"))
                return 200, {"ok": True}
            if action == "" and signer == row["issuer"]:
                return 200, {"ok": True, "status": row["status"], "pairingToken": row.get("token"),
                             "proof": row.get("proof"), "label": row.get("label")}
            if action == "answer" and signer == row["issuer"]:
                if body.get("declined"):
                    row["status"] = "declined"
                    return 200, {"ok": True}
                row.update(status="answered", envelope=body["envelope"])
                self.boxes[(row["device"], signer)] = {"envelope": body["envelope"], "revoked": False}
                return 200, {"ok": True}
            if action == "result" and signer == row.get("device"):
                return 200, {"ok": True, "status": row["status"], "envelope": row.get("envelope")}
            return 404, {"ok": False}
        if parts[0] == "machines":
            did = parts[1]
            issuer = urllib.parse.parse_qs(parsed.query).get("issuer", [signer])[0] if signer == did else signer
            box = self.boxes.get((did, issuer))
            if method == "POST" and signer == issuer:
                if not box or box["revoked"]:
                    return 410, {"ok": False, "unlinked": True}
                box["envelope"] = body["envelope"]
                return 200, {"ok": True}
            if method == "GET" and signer == did and box:
                return 200, ({"ok": True, "unlinked": True, "envelope": None} if box["revoked"]
                             else {"ok": True, "envelope": box["envelope"]})
            if method == "DELETE" and box:
                box.update(revoked=True, envelope=None)
                return 200, {"ok": True}
        return 404, {"ok": False}


class _Response:
    def __init__(self, status, answer):
        self.status, self._body = status, json.dumps(answer).encode()

    def read(self, *_):
        return self._body

    def close(self):
        pass


@pytest.fixture
def world(tmp_path, monkeypatch):
    """An owner with a few keys, a new machine, and the relay between them."""
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    monkeypatch.setenv("PASSBOOK_WEB_RELAYS", RELAY)
    monkeypatch.setenv("PASSBOOK_MACHINE_RELAY", RELAY)
    homes = {name: tmp_path / name for name in ("owner", "bot")}
    for home in homes.values():
        home.mkdir()

    @contextlib.contextmanager
    def at(name):
        monkeypatch.setenv("HIVE_HOME", str(homes[name]))
        yield homes[name]

    with at("owner"):
        passbook.set_values({"OPENAI_API_KEY": "sk-owner-1", "ANTHROPIC_API_KEY": "sk-ant-1",
                             "STRIPE_SECRET_KEY": "sk_live_x", "LOCAL_ONLY": "stays"}, overwrite=True)
        policy = access.read_policy()
        access.set_scope("LOCAL_ONLY", "machine", policy)
        access.write_policy(policy)
    relay = FakeRelay()
    return {"at": at, "relay": relay, "homes": homes}


def _invite(world, selection, **kwargs):
    with world["at"]("owner"):
        return join.create_invite(selection, opener=world["relay"], **kwargs)


def _join(world, invite, **kwargs):
    """Join as the bot, with the owner's PassBook answering while the bot waits."""
    def owner_answers(_seconds):
        with world["at"]("owner"):
            join.complete_invites(opener=world["relay"])
        world["at"]("bot").__enter__()

    with world["at"]("bot"):
        return join.join(invite, opener=world["relay"], sleep=owner_answers, poll_seconds=0, wait_seconds=5, **kwargs)


def _stored(world, name):
    with world["at"](name):
        return passbook.parse_env_text((passbook.target_path()).read_text()) if passbook.target_path().exists() else {}


def test_a_machine_joins_with_one_line_and_gets_exactly_what_was_chosen(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]})
    assert made["command"].startswith("passbook join pbj1.")
    result = _join(world, made["invite"], label="build-bot")
    assert result["keys"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    assert _stored(world, "bot") == {"ANTHROPIC_API_KEY": "sk-ant-1", "OPENAI_API_KEY": "sk-owner-1"}
    with world["at"]("owner"):
        lent = passbook_link.grants()["lent"]
    assert [(row["label"], row["live"]) for row in lent] == [("build-bot", True)]


def test_the_relay_never_sees_a_value_or_the_invite_secret(world):
    made = _invite(world, {"all": True})
    _join(world, made["invite"])
    secret = made["invite"].split(".")[2]
    traffic = "\n".join(world["relay"].seen)
    assert secret not in traffic
    for value in ("sk-owner-1", "sk-ant-1", "sk_live_x"):
        assert value not in traffic


def test_a_machine_without_the_invite_secret_is_turned_away(world):
    made = _invite(world, {"all": True})
    parsed = join.parse_invite(made["invite"])
    forged = made["invite"].replace(made["invite"].split(".")[2], base64.urlsafe_b64encode(b"x" * 16).decode().rstrip("="))
    with world["at"]("bot"):
        with pytest.raises(join.JoinError, match="turned this join away"):
            join.join(forged, opener=world["relay"], poll_seconds=0, wait_seconds=5,
                      sleep=lambda _s: _owner_completes(world))
    assert _stored(world, "bot") == {}
    assert parsed["id"] not in [row["id"] for row in _owner_invites(world)], "a forged join closes the invite"


def _owner_completes(world):
    with world["at"]("owner"):
        join.complete_invites(opener=world["relay"])
    world["at"]("bot").__enter__()


def _owner_invites(world):
    with world["at"]("owner"):
        return join.invites()


def test_only_keys_whose_reach_is_lendable_leave(world):
    made = _invite(world, {"all": True})
    assert "LOCAL_ONLY" in made["staying"] and "LOCAL_ONLY" not in made["keys"]
    _join(world, made["invite"])
    assert "LOCAL_ONLY" not in _stored(world, "bot")
    with pytest.raises(join.JoinError, match="stays on this machine"):
        _invite(world, {"keys": ["LOCAL_ONLY"]})
    with pytest.raises(join.JoinError, match="Not in this machine's store"):
        _invite(world, {"keys": ["NO_SUCH_KEY"]})


def test_groups_and_projects_resolve_to_the_keys_they_hold(world):
    with world["at"]("owner"):
        policy = access.read_policy()
        access.set_projects("STRIPE_SECRET_KEY", "include", ["shop"], policy)
        access.write_policy(policy)
        resolved = join.resolve_selection({"projects": ["shop"]})
    assert resolved["keys"] == ["STRIPE_SECRET_KEY"]


def test_a_live_link_follows_changes_and_drops_what_left_the_selection(world):
    with world["at"]("owner"):
        policy = access.read_policy()
        for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            policy.setdefault("keys", {}).setdefault(name, {})["projects"] = ["ai"]
        access.write_policy(policy)
    made = _invite(world, {"projects": ["ai"]})
    _join(world, made["invite"])
    with world["at"]("owner"):
        passbook.set_values({"OPENAI_API_KEY": "sk-owner-2"}, overwrite=True)
        policy = access.read_policy()
        policy["keys"]["ANTHROPIC_API_KEY"]["projects"] = ["elsewhere"]
        access.write_policy(policy)
        assert len(join.refresh(opener=world["relay"])["sent"]) == 1
    with world["at"]("bot"):
        pulled = join.pull(opener=world["relay"])
    assert pulled["links"][0]["status"] == "updated"
    assert _stored(world, "bot") == {"OPENAI_API_KEY": "sk-owner-2"}, "a changed value arrives; a key out of the selection leaves"
    with world["at"]("owner"):
        assert join.refresh(opener=world["relay"])["sent"] == [], "nothing changed, nothing sent"


def test_a_key_changed_on_the_joined_machine_is_its_own(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]})
    _join(world, made["invite"])
    with world["at"]("bot"):
        passbook.set_values({"OPENAI_API_KEY": "sk-bot-own"}, overwrite=True)
    with world["at"]("owner"):
        passbook.set_values({"OPENAI_API_KEY": "sk-owner-3"}, overwrite=True)
        join.refresh(opener=world["relay"])
    with world["at"]("bot"):
        join.pull(opener=world["relay"])
    assert _stored(world, "bot")["OPENAI_API_KEY"] == "sk-bot-own"
    with world["at"]("owner"):
        join.unlink(next(row["did"] for row in passbook_link.grants()["lent"]), opener=world["relay"])
    with world["at"]("bot"):
        assert join.pull(opener=world["relay"])["links"][0]["status"] == "unlinked"
    assert _stored(world, "bot")["OPENAI_API_KEY"] == "sk-bot-own", "unlinking never removes what the machine set itself"


def test_unlinking_takes_the_keys_back_from_a_machine_that_is_still_pulling(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]})
    _join(world, made["invite"])
    with world["at"]("owner"):
        did = passbook_link.grants()["lent"][0]["did"]
        result = join.unlink(did, opener=world["relay"])
    assert result["rotate"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"], "unlinking still names what to rotate"
    with world["at"]("bot"):
        pulled = join.pull(opener=world["relay"])
    assert pulled["links"][0]["removed"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    assert _stored(world, "bot") == {}
    with world["at"]("owner"):
        assert join.refresh(opener=world["relay"])["sent"] == []


def test_an_expired_grant_takes_its_keys_with_it(world, monkeypatch):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]}, live=False, days=1)
    _join(world, made["invite"])
    later = passbook_link._now() + timedelta(days=2)
    monkeypatch.setattr(passbook_link, "_now", lambda: later)
    with world["at"]("bot"):
        pulled = join.pull(opener=world["relay"])
    assert [(row["status"], row["removed"]) for row in pulled["links"]] == [("expired", ["OPENAI_API_KEY"])]
    assert _stored(world, "bot") == {}


def test_limits_travel_signed_and_are_applied_where_the_keys_land(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]}, caveats={"hosts": ["API.openai.com"], "apps": ["codex"]})
    _join(world, made["invite"])
    with world["at"]("bot"):
        policy = access.read_policy()
    assert access.read_guards(policy)["OPENAI_API_KEY"]["destinations"] == ["api.openai.com"]
    assert access.audience_for("OPENAI_API_KEY", policy)["agents"] == ["codex"]


def test_a_relay_that_strips_the_limits_breaks_the_signature(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]}, caveats={"hosts": ["api.openai.com"]})
    relay = world["relay"]
    original = relay.handle

    def stripping(request):
        status, answer = original(request)
        if answer.get("envelope"):
            outer = json.loads(_unb64(answer["envelope"][len(passbook_link.ENVELOPE_PREFIX):]))
            outer["grant"]["att"][0]["nb"].pop("hosts", None)
            answer = {**answer, "envelope": passbook_link.ENVELOPE_PREFIX + base64.urlsafe_b64encode(
                json.dumps(outer, separators=(",", ":")).encode()).decode().rstrip("=")}
        return status, answer

    relay.handle = stripping
    with pytest.raises(passbook_link.LinkError):
        _join(world, made["invite"])
    assert _stored(world, "bot") == {}


def test_an_older_envelope_cannot_roll_a_machine_back(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]})
    _join(world, made["invite"])
    with world["at"]("bot"):
        bot_did = passbook_link.identity()["did"]
    box = next(iter(world["relay"].boxes.values()))
    first = box["envelope"]
    with world["at"]("owner"):
        passbook.set_values({"OPENAI_API_KEY": "sk-owner-9"}, overwrite=True)
        join.refresh(opener=world["relay"])
    with world["at"]("bot"):
        join.pull(opener=world["relay"])
    assert _stored(world, "bot")["OPENAI_API_KEY"] == "sk-owner-9"
    box["envelope"] = first
    with world["at"]("bot"):
        join.pull(opener=world["relay"])
    assert _stored(world, "bot")["OPENAI_API_KEY"] == "sk-owner-9"
    assert bot_did


def test_an_invite_is_refused_on_the_machine_that_made_it_and_when_it_is_garbled(world):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]})
    with world["at"]("owner"):
        with pytest.raises(join.JoinError, match="made on this machine"):
            join.join(made["invite"], opener=world["relay"])
    with pytest.raises(join.JoinError, match="not a PassBook invite"):
        join.parse_invite("pbj1.short")
    assert join.parse_invite("passbook join " + made["invite"])["relay"] == RELAY


def test_an_invite_naming_a_relay_this_machine_does_not_trust_is_refused(world, monkeypatch):
    made = _invite(world, {"keys": ["OPENAI_API_KEY"]})
    monkeypatch.delenv("PASSBOOK_WEB_RELAYS")
    monkeypatch.delenv("PASSBOOK_MACHINE_RELAY")
    with pytest.raises(join.JoinError, match="not a relay this machine will use"):
        join.parse_invite(made["invite"])


def test_the_picker_offers_names_only(world):
    with world["at"]("owner"):
        offered = join.choices()
    text = json.dumps(offered)
    assert "sk-owner-1" not in text
    assert {row["name"]: row["leaves"] for row in offered["keys"]}["LOCAL_ONLY"] is False
