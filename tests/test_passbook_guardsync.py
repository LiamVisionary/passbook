"""Guarded keys between paired machines (passbook_guardsync): sealed to the machine, carrying their guard.

Liam, 2026-11-28, "Yes, build it", after guarded keys were found travelling as plaintext and then kept home. These
pin the format and the rules, then drive two real brokers over two stores: pairing needs the vault's password; a key
arrives sealed at rest and guarded; a second pass changes nothing; a replay, a wrong audience, a tampered envelope and
a paired machine written into the store file by hand are all refused.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_guardsync as gs  # noqa: E402

try:
    import cryptography  # noqa: F401
except ImportError:  # pragma: no cover
    pytest.skip("guard sync needs cryptography", allow_module_level=True)


def _machine(name: str):
    device = gs.load_device(gs.new_device())
    return device, gs.read_pairing_code(gs.pairing_code(device, name))


def _paired(code, last: float = 0.0):
    return gs.read_peers(gs.write_peers(gs.with_peer([], code, 1.0)))[0] | {"lastIssued": last}


ITEM = {"value": "the-secret", "updatedAt": 2000.0, "guard": {"commands": ["wrangler *"]}, "guardAt": 1500.0}


def test_a_pairing_code_carries_public_keys_and_a_fingerprint_a_swap_cannot_fake():
    device, code = _machine("m2")
    assert code["fingerprint"] == device["fingerprint"] and code["name"] == "m2"
    assert gs.same_fingerprint(device["fingerprint"].lower().replace("-", " "), code["fingerprint"])
    _other, other = _machine("other")
    assert not gs.same_fingerprint(other["fingerprint"], code["fingerprint"])
    with pytest.raises(gs.GuardSyncError):
        gs.read_pairing_code("passbook-guardsync:v1:not-a-code")


def test_an_envelope_opens_only_on_its_machine_from_a_paired_one_and_once():
    a, a_code = _machine("a")
    b, b_code = _machine("b")
    text = gs.seal_bundle(a, _paired(b_code), {"K": ITEM}, {"OLD": 900.0}, issued=1000.0)
    assert "the-secret" not in text
    peer, body = gs.open_bundle(text, b, [_paired(a_code)], now=1001.0)
    assert body["items"]["K"]["value"] == "the-secret" and body["cleared"] == {"OLD": 900.0}
    assert peer["fingerprint"] == a["fingerprint"] and peer["issued"] == 1000.0
    with pytest.raises(gs.GuardSyncError, match="not paired"):
        gs.open_bundle(text, b, [], now=1001.0)
    with pytest.raises(gs.AlreadyTaken):
        gs.open_bundle(text, b, [_paired(a_code, last=1000.0)], now=1001.0)
    with pytest.raises(gs.GuardSyncError, match="older"):
        gs.open_bundle(text, b, [_paired(a_code, last=1500.0)], now=1001.0)
    with pytest.raises(gs.GuardSyncError, match="future"):
        gs.open_bundle(text, b, [_paired(a_code)], now=1000.0 - gs.SKEW_SECONDS - 1)
    c, _c_code = _machine("c")
    with pytest.raises(gs.GuardSyncError, match="another machine"):
        gs.open_bundle(text, c, [_paired(a_code)], now=1001.0)
    raw = json.loads(gs.link._unb64(text[len(gs.ENVELOPE_PREFIX):]))
    raw["header"]["iat"] = 5000.0
    forged = gs.ENVELOPE_PREFIX + gs.link._b64(json.dumps(raw).encode())
    with pytest.raises(gs.GuardSyncError, match="signature"):
        gs.open_bundle(forged, b, [_paired(a_code)], now=6000.0)


def _plan(body, **local):
    base = {"local": {}, "stamps": {}, "guards": {}, "guard_changes": {}, "now": 10_000.0}
    return gs.plan_apply(body, **{**base, **local})


def test_a_new_guarded_key_arrives_with_its_guard_and_its_senders_stamp():
    plan = _plan({"items": {"K": ITEM}})
    assert plan["guard"] == {"K": ({"commands": ["wrangler *"]}, 1500.0)}
    assert plan["values"] == {"K": ("the-secret", 2000.0)}


def test_the_rules_plain_sync_keeps():
    # Identical: nothing written, no stamp moved; the guard already the same: no guard change either.
    same = _plan({"items": {"K": ITEM}}, local={"K": "the-secret"}, stamps={"K": 1000.0},
                 guards={"K": {"commands": ["wrangler *"]}}, guard_changes={"K": 1500.0})
    assert same["values"] == {} and same["guard"] == {}
    # This machine's copy is newer.
    newer_here = _plan({"items": {"K": ITEM}}, local={"K": "mine"}, stamps={"K": 3000.0},
                       guards={"K": {"commands": ["wrangler *"]}}, guard_changes={"K": 1500.0})
    assert newer_here["values"] == {} and "newer" in newer_here["kept"]["K"]
    # Removed here: a stamp with no value is not brought back.
    removed = _plan({"items": {"K": ITEM}}, stamps={"K": 500.0})
    assert removed["values"] == {} and removed["kept"]["K"] == "removed here"
    # From the future: refused.
    future = _plan({"items": {"K": {**ITEM, "updatedAt": 99_999.0}}})
    assert future["values"] == {} and "future" in future["kept"]["K"]
    # Its guard cleared here after the sender set it: the guard stays cleared and no unguarded value is written.
    cleared_here = _plan({"items": {"K": ITEM}}, guard_changes={"K": 1800.0})
    assert cleared_here["guard"] == {} and cleared_here["values"] == {} and cleared_here["kept"]["K"] == "unguarded here since"
    # A guard cleared on the sender, later than this machine's last change: cleared here too.
    tomb = _plan({"items": {}, "cleared": {"K": 1600.0}}, guards={"K": {"commands": ["x"]}}, guard_changes={"K": 1500.0})
    assert tomb["clear"] == {"K": 1600.0}
    # A guard-sync key of its own is never taken from a peer.
    own = _plan({"items": {gs.DEVICE_KEY: ITEM}})
    assert own["values"] == {} and own["guard"] == {}


def test_what_is_sent_is_each_guarded_key_that_may_leave_and_each_dated_clearing():
    items, cleared = gs.bundle_items(
        guards={"K": {"commands": ["wrangler *"]}, "HOME_ONLY": {"destinations": ["api.example.com"]}, "EMPTY": {}},
        guard_changes={"K": 1500.0, "HOME_ONLY": 1.0, "WAS": 1700.0},
        values={"K": "v", "HOME_ONLY": "h", "EMPTY": "e"}, stamps={"K": 2000.0},
        travels={"K": True, "HOME_ONLY": False, "EMPTY": True, "WAS": True})
    assert items == {"K": {"value": "v", "updatedAt": 2000.0, "guard": {"commands": ["wrangler *"]}, "guardAt": 1500.0}}
    assert cleared == {"WAS": 1700.0}


# ── two real machines ──────────────────────────────────────────────────────

from _platform import broker_marker  # noqa: E402

PASSWORD = "a properly long vault password"


@pytest.fixture
def two(tmp_path, monkeypatch):
    import passbook
    import passbook_broker
    import passbook_vault as vault

    for leaked in ("HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID", "HIVE_WORKSPACE", "HIVE_WORKSPACE_ID"):
        monkeypatch.delenv(leaked, raising=False)
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setenv("PASSBOOK_FLEET", "off")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    homes = {}
    for name in ("a", "b"):
        home = tmp_path / name
        monkeypatch.setenv("HIVE_HOME", str(home))
        passbook.ensure(app="test")
        passbook.set_values({"PLAIN": f"plain-{name}"})
        profile = vault.create_profile("Owner", password=PASSWORD, root=home)["id"]
        dek = vault.unlock_with_password(profile, PASSWORD, root=home)
        vault.seal_store(dek, profile_id=profile, root=home)
        started = passbook_broker.start()
        if not started.get("ok"):
            pytest.skip(f"the broker would not start here: {started.get('detail')}")
        assert passbook_broker.signin(password=PASSWORD, root=home).get("ok")
        homes[name] = home

    def at(name):
        monkeypatch.setenv("HIVE_HOME", str(homes[name]))
        return homes[name]

    def ask(machine, **payload):
        home = at(machine)
        return passbook_broker._ask({"op": "guardsync", **payload}, root=home, timeout=30) or {}

    try:
        yield at, ask
    finally:
        for name in homes:
            at(name)
            passbook_broker.stop()


@broker_marker()
def test_two_machines_pair_and_a_guarded_key_arrives_sealed_and_guarded(two):
    import passbook
    import passbook_access as access
    import passbook_sync
    import passbook_vault as vault

    at, ask = two
    code_a = ask("a", step="code", name="a")
    code_b = ask("b", step="code", name="b")
    assert code_a["ok"] and code_b["ok"]

    # Pairing needs this vault's password: an approval alone is not enough.
    wrong = ask("a", step="pair", code=code_b["code"], fingerprint=code_b["fingerprint"], password="not it")
    assert not wrong.get("ok")
    swapped = ask("a", step="pair", code=code_b["code"], fingerprint=code_a["fingerprint"], password=PASSWORD)
    assert not swapped.get("ok") and "fingerprint" in swapped["error"]
    paired = ask("a", step="pair", code=code_b["code"], fingerprint=code_b["fingerprint"], password=PASSWORD)
    assert paired.get("ok"), paired
    assert ask("b", step="pair", code=code_a["code"], fingerprint=code_a["fingerprint"], password=PASSWORD)["ok"]

    # A guards a key; it never goes out as plaintext, and its envelope for B carries it sealed.
    home_a = at("a")
    import passbook_broker
    assert passbook_broker.seal_values({"DEPLOY_TOKEN": "deploy-secret"}).get("ok")
    policy = access.read_policy()
    access.set_guard("DEPLOY_TOKEN", policy, commands=["wrangler *"], now=time.time() - 10)
    access.write_policy(policy)
    sealed = ask("a", step="seal")
    assert sealed["ok"] and sealed["sealedFor"] == 1 and sealed["keys"] == ["DEPLOY_TOKEN"]
    outbox = json.loads((home_a / gs.OUTBOX_FILENAME).read_text())["for"]
    envelope = outbox[code_b["fingerprint"]]
    assert "deploy-secret" not in json.dumps(outbox)

    took = ask("b", step="receive", envelopes=[envelope])
    assert took["ok"] and took["written"] == ["DEPLOY_TOKEN"] and took["guarded"] == ["DEPLOY_TOKEN"]
    home_b = at("b")
    raw_b = passbook.parse_env_text((home_b / ".env").read_text())
    assert vault.is_sealed(raw_b["DEPLOY_TOKEN"]), "sealed at rest on the machine it reached"
    assert access.read_guards(access.read_policy())["DEPLOY_TOKEN"] == {"commands": ["wrangler *"]}
    stamps = passbook_sync.read_meta(home_b / ".env")

    # A second pass with nothing changed: the same envelope stands, and taking it again changes nothing, refuses
    # nothing and moves no stamp.
    again = ask("a", step="seal")
    assert again["ok"] and again["fresh"] == 0
    assert json.loads((home_a / gs.OUTBOX_FILENAME).read_text())["for"][code_b["fingerprint"]] == envelope
    quiet = ask("b", step="receive", envelopes=[envelope])
    assert quiet["ok"] and quiet["written"] == [] and quiet["guarded"] == [] and quiet["refused"] == []
    assert passbook_sync.read_meta(home_b / ".env") == stamps
    # A rotation on A goes out as a new envelope; the old one, offered after it, is a replay and refused.
    at("a")
    assert passbook_broker.seal_values({"DEPLOY_TOKEN": "rotated-secret"}).get("ok")
    passbook_sync.touch_meta(home_a / ".env", ["DEPLOY_TOKEN"])
    assert ask("a", step="seal")["fresh"] == 1
    rotated = json.loads((home_a / gs.OUTBOX_FILENAME).read_text())["for"][code_b["fingerprint"]]
    assert ask("b", step="receive", envelopes=[rotated])["written"] == ["DEPLOY_TOKEN"]
    assert ask("b", step="receive", envelopes=[envelope])["refused"] == ["older than the last one taken from that machine"]

    # No door hands out this machine's guard-sync keys: not a request, not `run`. And no caller can write them: a paired
    # machine sealed in through `seal_values` would be a pairing without the password.
    at("a")
    opened = passbook_broker.request_through_broker(["PLAIN", gs.DEVICE_KEY, gs.PEERS_KEY], app="test") or {}
    assert opened.get("PLAIN") == "plain-a", f"the same door opens an ordinary key here: {sorted(opened)}"
    assert gs.DEVICE_KEY not in opened and gs.PEERS_KEY not in opened
    attacker, attacker_code = _machine("attacker")
    passbook_broker.seal_values({gs.PEERS_KEY: gs.write_peers(gs.with_peer([], attacker_code, 1.0))})
    listed = ask("a", step="peers")
    assert [peer["fingerprint"] for peer in listed["peers"]] == [code_b["fingerprint"]], "the sealed list is the broker's own"
    # A paired machine written into the store file by hand is not trusted: only what the broker sealed is.
    with open(home_a / ".env", "a", encoding="utf-8") as stream:
        stream.write(f"\n{gs.PEERS_KEY}={gs.write_peers(gs.with_peer([], attacker_code, 1.0))}\n")
    listed = ask("a", step="peers")
    assert attacker_code["fingerprint"] not in [peer["fingerprint"] for peer in listed["peers"]]


@broker_marker()
def test_a_guard_sync_key_and_the_outbox_never_travel_as_plain_keys():
    import passbook_sync

    assert passbook_sync.is_local_only(gs.DEVICE_KEY) and passbook_sync.is_local_only(gs.PEERS_KEY)


def test_the_sync_pass_takes_only_what_is_sealed_for_this_machine_and_seals_on_apply(monkeypatch):
    import passbook_broker
    import passbook_cli as cli

    asked = []

    def fake(payload, **_kw):
        asked.append(payload)
        if payload["step"] == "peers":
            return {"ok": True, "fingerprint": "MINE", "peers": [{"fingerprint": "THEIRS"}]}
        if payload["step"] == "receive":
            return {"ok": True, "written": ["K"], "guarded": ["K"]}
        return {"ok": True, "sealedFor": 1}

    monkeypatch.setattr(passbook_broker, "_ask", fake)
    payloads = [("m2", {"guardedFor": {"MINE": "passbook-guarded:v1:for-me", "OTHER": "passbook-guarded:v1:not-mine"}}),
                ("vps", {"values": {}})]
    report = cli._guardsync_pass(payloads, apply=True)
    received = next(item for item in asked if item["step"] == "receive")
    assert received["envelopes"] == ["passbook-guarded:v1:for-me"] and received["dry_run"] is False
    assert report == {"paired": 1, "written": ["K"], "guarded": ["K"], "sealedFor": 1}
    asked.clear()
    assert cli._guardsync_pass(payloads, apply=False)["paired"] == 1
    assert [item["step"] for item in asked] == ["peers", "receive"] and asked[1]["dry_run"] is True, "a dry run seals nothing"
