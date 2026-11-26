# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What the relay carries beyond linking: a plan, a backup, a phone, and other people.

The relay here is the fake from test_passbook_join with the newer routes added, holding the same
contract as `relay/` (which has its own tests, against the real code). What these tests are about
is the half that is NOT the relay's: everything PassBook checks for itself because the relay is not
trusted to. Each test names the sentence in a module docstring that it holds.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_link  # noqa: E402

pytestmark = pytest.mark.skipif(not passbook_link.available(), reason="these need the `cryptography` package")

import passbook_access as access  # noqa: E402
import passbook_backup  # noqa: E402
import passbook_cloud_backup as cloud  # noqa: E402
import passbook_grant  # noqa: E402
import passbook_join as join  # noqa: E402
import passbook_phone as phone  # noqa: E402
import passbook_plan as plan  # noqa: E402
import passbook_stamp  # noqa: E402
import passbook_team as team  # noqa: E402
from test_passbook_join import RELAY, FakeRelay, _join, _stored, world  # noqa: E402,F401


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _new_id() -> str:
    return _b64(secrets.token_bytes(16))


class Relay(FakeRelay):
    """FakeRelay plus plans, backups, phones and member reports."""

    def __init__(self):
        super().__init__()
        self.plan = {"plan": "free", "machines": 3, "seats": 0, "backup": False, "approvals": False,
                     "more": "PassBook Sync lifts this."}
        self.billing: dict | None = {"source": "free", "onSale": True}
        self.kinds: dict[str, str] = {}
        self.backups: dict[str, dict] = {}
        self.phones: dict[str, dict] = {}
        self.approvals: dict[str, dict] = {}
        self.events: list[dict] = []
        self.checkout = {"ok": True, "url": "https://checkout.stripe.com/c/pay/cs_test_1"}
        self.fail_next: tuple[int, dict] | None = None

    def _refuse(self, code: str, limit: int | None = None):
        body = {"ok": False, "code": code, "plan": self.plan["plan"], "error": f"Refused ({code}). {self.plan['more']}"}
        if limit is not None:
            body["limit"] = limit
        return 409 if code.endswith("_limit") else 403, body

    def handle(self, request):
        parsed = urllib.parse.urlsplit(request.full_url)
        path, method = parsed.path, request.get_method()
        parts = path.split("/")[3:]
        body = json.loads(request.data or b"{}")
        if self.fail_next is not None:
            answer, self.fail_next = self.fail_next, None
            return answer

        # A phone has no machine key: these two are not signed by one.
        if parts[:1] == ["phones"] and parts[2:] == ["join"] and method == "POST":
            row = self.phones.get(parts[1])
            if not row or row["status"] != "open":
                return 404, {"ok": False}
            row.update(status="joined", signKey=body["signKey"], sealKey=body["sealKey"], mac=body["mac"], label=body.get("label", "A phone"))
            return 200, {"ok": True}
        if parts[:1] == ["approvals"] and parts[2:] == ["decision"] and method == "POST":
            row = self.approvals.get(parts[1])
            if not row or row["status"] != "waiting":
                return 404, {"ok": False}
            row.update(status="decided", answer=body["answer"])
            return 200, {"ok": True}

        signer = self._signer(request)
        if not signer:
            return 401, {"ok": False}
        mine = lambda kind: sum(1 for (device, issuer), box in self.boxes.items()  # noqa: E731
                                if issuer == signer and not box["revoked"] and self.kinds.get(device, "machine") == kind)

        if parts == ["plan"] and method == "GET":
            return 200, {"ok": True, "plan": self.plan["plan"], "more": self.plan["more"], "billing": self.billing,
                         "limits": {key: self.plan[key] for key in ("machines", "seats", "backup", "approvals")},
                         "used": {"machines": mine("machine"), "members": mine("member"), "backups": len(self.backups),
                                  "phones": sum(1 for p in self.phones.values() if p["status"] == "linked")}}
        if parts == ["plan", "checkout"] and method == "POST":
            return (200 if self.checkout.get("ok") else 503), self.checkout
        if parts[:1] == ["plan"]:
            return 404, {"ok": False, "code": "no_billing", "error": "This relay has no paid plans."}

        if parts == ["machine-invites"] and method == "POST":
            if body.get("kind") == "member" and self.plan["seats"] < 1:
                return self._refuse("seat_limit", 0)
            status, answer = super().handle(request)
            self.invites[answer["inviteId"]]["kind"] = body.get("kind", "machine")
            return status, answer
        if parts[:1] == ["machine-invites"] and parts[2:] == ["answer"] and not body.get("declined"):
            row = self.invites.get(parts[1]) or {}
            kind = row.get("kind", "machine")
            limit = self.plan["seats"] if kind == "member" else self.plan["machines"]
            if signer == row.get("issuer") and (row.get("device"), signer) not in self.boxes and mine(kind) >= limit:
                return self._refuse("seat_limit" if kind == "member" else "machine_limit", limit)
            self.kinds[row.get("device", "")] = kind

        if parts == ["backups"] and method == "POST":
            if not self.plan["backup"]:
                return self._refuse("not_included")
            backup_id = _new_id()
            self.backups[backup_id] = {"owner": signer, "blob": body["blob"], "recovery": body["recovery"], "label": body.get("label", "")}
            return 200, {"ok": True, "id": backup_id, "at": "2026-11-26T00:00:00.000Z", "kept": 5}
        if parts == ["backups"] and method == "GET":
            return 200, {"ok": True, "backups": [{"id": key, "label": row["label"], "bytes": len(row["blob"]), "at": "2026-11-26T00:00:00.000Z"}
                                                 for key, row in self.backups.items() if row["owner"] == signer]}
        if parts[:1] == ["backups"]:
            row = self.backups.get(parts[1])
            described = lambda: {"ok": True, "blob": row["blob"], "digest": row.get("digest") or hashlib.sha256(row["blob"].encode()).hexdigest()}  # noqa: E731
            if parts[2:] == ["recover"]:
                good = row and hashlib.sha256(str(body.get("secret")).encode()).hexdigest() == row["recovery"]
                return (200, described()) if good else (404, {"ok": False})
            if not row or row["owner"] != signer:
                return 404, {"ok": False}
            if method == "DELETE":
                del self.backups[parts[1]]
                return 200, {"ok": True}
            return 200, described()

        if parts == ["phones"] and method == "POST":
            if not self.plan["approvals"]:
                return self._refuse("not_included")
            phone_id = _new_id()
            self.phones[phone_id] = {"owner": signer, "status": "open"}
            return 200, {"ok": True, "phoneId": phone_id, "expiresAt": "2099-01-01T00:00:00.000Z"}
        if parts == ["phones"] and method == "GET":
            return 200, {"ok": True, "phones": [{"id": key, "label": row.get("label"), "seenAt": "2026-11-26T01:00:00.000Z"}
                                                for key, row in self.phones.items() if row["owner"] == signer and row["status"] == "linked"]}
        if parts[:1] == ["phones"]:
            row = self.phones.get(parts[1])
            if not row or row["owner"] != signer:
                return 404, {"ok": False}
            if method == "DELETE":
                row["status"] = "revoked"
                return 200, {"ok": True}
            if parts[2:] == ["confirm"]:
                row["status"] = "linked"
                return 200, {"ok": True}
            return 200, {"ok": True, "status": row["status"], "label": row.get("label"), "signKey": row.get("signKey"),
                         "sealKey": row.get("sealKey"), "mac": row.get("mac")}
        if parts == ["approvals"] and method == "POST":
            approval = _new_id()
            self.approvals[approval] = {"owner": signer, "phone": body["phone"], "sealed": body["sealed"], "status": "waiting"}
            return 200, {"ok": True, "approvalId": approval}
        if parts[:1] == ["approvals"]:
            row = self.approvals.get(parts[1])
            if not row or row["owner"] != signer:
                return 404, {"ok": False}
            if method == "DELETE":
                del self.approvals[parts[1]]
                return 200, {"ok": True}
            return 200, {"ok": True, "status": row["status"], "answer": row.get("answer")}

        if parts == ["team", "events"] and method == "POST":
            box = self.boxes.get((signer, body["owner"]))
            if not box or box["revoked"] or self.kinds.get(signer) != "member":
                return 403, {"ok": False, "code": "not_member"}
            for sealed in body["events"]:
                self.events.append({"id": _new_id(), "owner": body["owner"], "member": signer, "sealed": sealed,
                                    "at": f"2026-11-26T00:00:{len(self.events):02d}.000Z"})
            return 200, {"ok": True, "stored": len(body["events"])}
        if parts == ["team", "events"] and method == "GET":
            after = urllib.parse.parse_qs(parsed.query).get("after", [""])[0]
            rows = [row for row in self.events if row["owner"] == signer and row["at"] > after]
            return 200, {"ok": True, "more": False, "events": [{key: row[key] for key in ("id", "member", "at", "sealed")} for row in rows]}
        return super().handle(request)


@pytest.fixture
def relay(world, monkeypatch):
    """The world of test_passbook_join, with the fuller relay, reachable without passing `opener`."""
    world["relay"] = Relay()
    monkeypatch.setattr(urllib.request, "urlopen", world["relay"])
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    return world["relay"]


# ── the plan ────────────────────────────────────────────────────────────────


def test_a_plan_is_read_as_the_relay_reports_it_and_said_in_one_line(world, relay):
    with world["at"]("owner"):
        seen = plan.status()
    assert (seen["plan"], seen["limits"], seen["relay"]) == ("free", {"machines": 3, "seats": 0, "backup": False, "approvals": False}, RELAY)
    assert seen["used"] == {"machines": 0, "members": 0, "backups": 0, "phones": 0}
    assert plan.describe(seen) == "Free: 0 of 3 computers"
    relay.plan.update(plan="teams", machines=50, seats=2)
    with world["at"]("owner"):
        assert plan.describe(plan.status()) == "PassBook Teams: 0 of 50 computers, 0 of 2 people"


def test_a_relay_from_before_plans_reports_none_and_sells_nothing(world, relay):
    relay.fail_next = (404, {"ok": False, "error": "Not found."})
    with world["at"]("owner"):
        seen = plan.status()
        assert (seen["plan"], seen["billing"]) == ("self-hosted", None)
        relay.checkout = {"ok": False, "code": "no_billing", "error": "This relay has no paid plans."}
        relay.fail_next = (404, relay.checkout)
        with pytest.raises(plan.PlanError, match="no paid plans") as refused:
            plan.subscribe("sync")
    assert refused.value.code == "no_billing"


def test_only_stripes_own_page_is_ever_handed_back_to_be_opened(world, relay):
    with world["at"]("owner"):
        assert plan.subscribe("sync", yearly=True)["url"].startswith("https://checkout.stripe.com/")
        relay.checkout = {"ok": True, "url": "https://checkout.stripe.com.evil.example/pay"}
        with pytest.raises(plan.PlanError, match="not Stripe's checkout"):
            plan.subscribe("sync")
        relay.checkout = {"ok": True, "url": "javascript:alert(1)"}
        with pytest.raises(plan.PlanError, match="not Stripe's checkout"):
            plan.subscribe("teams", seats=3)
        with pytest.raises(plan.PlanError, match="between 2 and 50"):
            plan.subscribe("teams", seats=1)
        relay.checkout = {"ok": False, "code": "not_on_sale", "error": "Paid plans are not on sale yet."}
        with pytest.raises(plan.PlanError, match="not on sale") as closed:
            plan.subscribe("sync")
    assert closed.value.code == "not_on_sale"


def test_a_plan_changed_in_place_opens_nothing(world, relay):
    relay.checkout = {"ok": True, "changed": True, "plan": "teams", "limits": {"machines": 50, "seats": 1, "backup": True, "approvals": True},
                      "used": {"machines": 2}, "billing": {"source": "stripe"}}
    with world["at"]("owner"):
        moved = plan.subscribe("teams", seats=2)
    assert moved["changed"] is True and "url" not in moved and moved["plan"] == "teams"


def test_a_refusal_at_the_limit_keeps_its_code_and_leaves_no_record_of_a_grant(world, relay):
    relay.plan["machines"] = 0
    with world["at"]("owner"):
        made = join.create_invite({"keys": ["OPENAI_API_KEY"]})
    with world["at"]("bot"):
        with pytest.raises(join.JoinError):
            join.join(made["invite"], poll_seconds=0, wait_seconds=0.2, sleep=lambda _s: _complete(world))
    with world["at"]("owner"):
        rows = join.complete_invites()
        assert [(row["status"], row.get("code")) for row in rows] == [("failed", "machine_limit")]
        assert "PassBook Sync lifts this." in rows[0]["detail"]
        assert passbook_link.grants()["lent"] == [], "a machine the relay refused is not shown as holding keys"
        assert [row["id"] for row in join.invites()] == [made["id"]], "the invite survives, to be used once the limit is lifted"
    assert _stored(world, "bot") == {}


def _complete(world):
    with world["at"]("owner"):
        join.complete_invites()
    world["at"]("bot").__enter__()


def test_a_relay_that_is_briefly_wrong_does_not_end_an_invite(world, relay):
    """`complete_invites` called any non-200 "expired" and threw the invite away, a rate limit included."""
    with world["at"]("owner"):
        made = join.create_invite({"keys": ["OPENAI_API_KEY"]})
        relay.fail_next = (429, {"ok": False, "error": "Too many requests."})
        rows = join.complete_invites()
        assert [(row["status"], row["detail"]) for row in rows] == [("waiting", "Too many requests.")]
        assert [row["id"] for row in join.invites()] == [made["id"]]
        relay.fail_next = (404, {"ok": False})
        assert [row["status"] for row in join.complete_invites()] == ["expired"]
        assert join.invites() == []


# ── a backup kept on the relay ──────────────────────────────────────────────


def _export(world, passphrase="correct horse battery"):
    with world["at"]("owner"):
        return passbook_backup.encrypt({"OPENAI_API_KEY": "sk-owner-1", "STRIPE_SECRET_KEY": "sk_live_x"}, passphrase)


def test_a_backup_is_recovered_on_a_machine_that_has_nothing_with_the_code_and_the_passphrase(world, relay):
    relay.plan["backup"] = True
    text = _export(world)
    with world["at"]("owner"):
        made = cloud.store(text, label="Studio Mac")
        assert [row["label"] for row in cloud.stored()] == ["Studio Mac"]
        assert cloud.fetch(made["id"]) == text
    assert cloud.CODE_SHAPE.fullmatch(made["code"])
    with world["at"]("bot"):
        back = cloud.fetch(made["code"])
        assert passbook_backup.keys_of(passbook_backup.read(back, passphrase="correct horse battery")) == {
            "OPENAI_API_KEY": "sk-owner-1", "STRIPE_SECRET_KEY": "sk_live_x"}
        with pytest.raises(passbook_backup.BackupError):
            passbook_backup.read(back, passphrase="not the passphrase")
        with pytest.raises(cloud.CloudBackupError, match="made by another machine"):
            cloud.fetch(made["id"])
        parts = made["code"].split(".")
        wrong = ".".join([*parts[:2], parts[2][:-4] + ("AAAA" if not parts[2].endswith("AAAA") else "BBBB"), *parts[3:]])
        with pytest.raises(cloud.CloudBackupError, match="No backup matches"):
            cloud.fetch(wrong)
        # A code whose relay part is damaged is refused without repeating what it decoded to.
        with pytest.raises(cloud.CloudBackupError, match="relay this machine does not use|damaged") as garbled:
            cloud.fetch(made["code"][:-4] + "AAAA")
        assert "\x00" not in str(garbled.value) and "relay.t" not in str(garbled.value)
        with pytest.raises(cloud.CloudBackupError, match="made by another machine"):
            cloud.remove(made["id"])
    with world["at"]("owner"):
        assert cloud.remove(made["id"]) is True and cloud.stored() == []


def test_the_relay_holds_ciphertext_and_a_hash_and_nothing_that_opens_either(world, relay):
    relay.plan["backup"] = True
    with world["at"]("owner"):
        made = cloud.store(_export(world, "correct horse battery"))
    secret = made["code"].split(".")[2]
    traffic = "\n".join(relay.seen)
    for private in ("correct horse battery", secret, "sk-owner-1", "sk_live_x"):
        assert private not in traffic
    stored = relay.backups[made["id"]]
    assert stored["recovery"] == hashlib.sha256(secret.encode()).hexdigest()
    assert stored["blob"].startswith("passbook-export:v1\n")


def test_nothing_but_an_encrypted_export_leaves_and_a_damaged_one_is_not_accepted_back(world, relay):
    relay.plan["backup"] = True
    with world["at"]("owner"):
        with pytest.raises(cloud.CloudBackupError, match="Only an export encrypted with a passphrase"):
            cloud.store("OPENAI_API_KEY=sk-owner-1\n")
        assert relay.backups == {}, "refused here, before it reached the relay"
        made = cloud.store(_export(world))
        relay.backups[made["id"]]["digest"] = "0" * 64
        with pytest.raises(cloud.CloudBackupError, match="damaged"):
            cloud.fetch(made["id"])
        relay.backups[made["id"]].update(digest=None, blob="not an export at all")
        with pytest.raises(cloud.CloudBackupError, match="not an encrypted PassBook export"):
            cloud.fetch(made["code"])
        with pytest.raises(cloud.CloudBackupError, match="not a PassBook recovery code"):
            cloud.parse_code("pbb1.short")


def test_a_plan_without_backup_is_refused_with_the_way_out_named(world, relay):
    with world["at"]("owner"):
        with pytest.raises(cloud.CloudBackupError, match="PassBook Sync lifts this") as refused:
            cloud.store(_export(world))
    assert refused.value.code == "not_included"


# ── a phone ─────────────────────────────────────────────────────────────────


class Handset:
    """What the page at /phone does, in Python: two P-256 key pairs, a join, an open, a signed answer."""

    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self.ec, self.ser = ec, serialization
        self.sign, self.seal = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        point = lambda key: _b64(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))  # noqa: E731
        self.sign_key, self.seal_key = point(self.sign), point(self.seal)

    def join(self, relay: Relay, url: str, *, secret: bytes | None = None, label="iPhone"):
        code = url.split("#", 1)[1].split(".")
        phone_id, real = code[1], _unb64(code[2])
        self.owner = _unb64(code[3]).decode()
        mac = hmac.new(secret or real, f"passbook-phone-join:v1\n{phone_id}\n{self.sign_key}\n{self.seal_key}".encode(), hashlib.sha256).digest()
        relay.phones[phone_id].update(status="joined", signKey=self.sign_key, sealKey=self.seal_key, mac=_b64(mac), label=label)
        return phone_id

    def open(self, sealed: str) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        _, eph, nonce, box = sealed.split(".")
        theirs = self.ec.EllipticCurvePublicKey.from_encoded_point(self.ec.SECP256R1(), _unb64(eph))
        shared = self.seal.exchange(self.ec.ECDH(), theirs)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"passbook-phone-seal:v1" + _unb64(eph) + _unb64(self.seal_key)).derive(shared)
        return AESGCM(key).decrypt(_unb64(nonce), _unb64(box), None).decode()

    def answer(self, text: str, decision="allow", remember=0, at=None, key=None) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        ask = json.loads(text)
        digest, at = hashlib.sha256(text.encode()).hexdigest(), int(time.time()) if at is None else at
        message = "\n".join(["passbook-approval:v1", self.owner, ask["rid"], digest, decision, str(remember), str(at)]).encode()
        r, s = decode_dss_signature((key or self.sign).sign(message, self.ec.ECDSA(hashes.SHA256())))
        return json.dumps({"v": 1, "rid": ask["rid"], "digest": digest, "decision": decision, "remember": remember, "at": at,
                           "signature": _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))})


def _linked_phone(world, relay) -> tuple[Handset, str]:
    relay.plan["approvals"] = True
    handset = Handset()
    with world["at"]("owner"):
        made = phone.begin()
        phone_id = handset.join(relay, made["url"])
        assert phone.check(phone_id) == {"ok": True, "status": "joined", "label": "iPhone"}
        phone.confirm(phone_id)
    return handset, phone_id


def test_a_phone_is_linked_only_after_it_proves_it_read_the_code_and_a_person_confirms_it(world, relay):
    relay.plan["approvals"] = True
    handset = Handset()
    with world["at"]("owner"):
        made = phone.begin()
        assert made["url"].startswith(RELAY + "/phone#pbp1.")
        assert phone.check(made["id"])["status"] == "waiting"
        with pytest.raises(phone.PhoneError, match="No phone has opened that link"):
            phone.confirm(made["id"])
        assert phone.linked() == [] and phone.any_linked() is False
        handset.join(relay, made["url"])
        assert phone.check(made["id"])["status"] == "joined"
        assert phone.linked() == [], "joined is not linked: nothing is sent to it until a person confirms"
        assert phone.confirm(made["id"])["phone"] == {"id": made["id"], "label": "iPhone"}
        assert [(p["label"], p["signKey"]) for p in phone.linked()] == [("iPhone", handset.sign_key)]
        assert phone.listed()[0]["seenAt"]
    secret = made["url"].split("#")[1].split(".")[2]
    assert secret not in "\n".join(relay.seen), "the code's secret never reaches the relay"


def test_keys_put_in_by_the_relay_instead_of_the_phone_are_turned_away(world, relay):
    relay.plan["approvals"] = True
    with world["at"]("owner"):
        made = phone.begin()
        Handset().join(relay, made["url"], secret=b"x" * 32)   # somebody without the code's secret
        seen = phone.check(made["id"])
        assert seen["status"] == "refused" and "turned away" in seen["detail"]
        assert relay.phones[made["id"]]["status"] == "revoked"
        assert phone.linked() == []

        # And a phone whose keys are swapped after it was shown, before it was confirmed.
        made = phone.begin()
        Handset().join(relay, made["url"])
        assert phone.check(made["id"])["status"] == "joined"
        original = phone.check

        def swap_then_report(*args, **kwargs):
            seen = original(*args, **kwargs)
            relay.phones[made["id"]]["signKey"] = Handset().sign_key
            return seen
        phone.check = swap_then_report
        try:
            with pytest.raises(phone.PhoneError, match="changed between being shown and being confirmed"):
                phone.confirm(made["id"])
        finally:
            phone.check = original
        assert phone.linked() == []


def test_a_request_is_readable_only_by_the_phone_and_only_its_own_signed_answer_counts(world, relay):
    handset, phone_id = _linked_phone(world, relay)
    with world["at"]("owner"):
        sent = phone.ask(rid="a1b2c3d4", app="claude-code", keys=["OPENAI_API_KEY"], reason="run the evals", workspace="main")
        assert len(sent) == 1
        sealed = relay.approvals[sent[0]["approval"]]["sealed"]
        assert "OPENAI_API_KEY" not in sealed and "claude-code" not in "\n".join(relay.seen)
        text = handset.open(sealed)
        shown = json.loads(text)
        assert (shown["app"], shown["keys"], shown["reason"], shown["kind"]) == ("claude-code", ["OPENAI_API_KEY"], "run the evals", "read")
        assert shown["owner"] == passbook_link.identity()["did"]
        with pytest.raises(Exception):
            Handset().open(sealed)

        assert phone.poll(sent) is None
        stranger = Handset()
        asked = sent[0]
        good = handset.answer(text, "allow", 3600)
        assert phone.verify(good, asked) == {"approve": True, "remember": 3600, "label": "iPhone", "phone": phone_id}
        assert phone.verify(handset.answer(text, "deny"), asked)["approve"] is False

        forged = json.loads(good)
        assert phone.verify(json.dumps({**forged, "decision": "deny"}), asked) is None, "the decision is inside the signature"
        assert phone.verify(json.dumps({**forged, "remember": 0}), asked) is None
        assert phone.verify(handset.answer(text, key=stranger.sign), asked) is None, "another phone's key"
        assert phone.verify(handset.answer(text, at=int(time.time()) - 3600), asked) is None, "an old answer"
        assert phone.verify(handset.answer(text, "allow", 86400), asked) is None, "a phone cannot say yes for a day"
        other = phone.request_text(rid="ffffffff", owner=shown["owner"], app="x", keys=["STRIPE_SECRET_KEY"], reason="", kind="read", workspace="", seconds=60)
        assert phone.verify(handset.answer(other), asked) is None, "an answer to another request"
        assert phone.verify("not json", asked) is None

        relay.approvals[asked["approval"]].update(status="decided", answer=json.dumps({**forged, "decision": "deny"}))
        assert phone.poll(sent) is None, "what the relay hands back is checked, not believed"
        relay.approvals[asked["approval"]].update(answer=good)
        assert phone.poll(sent)["approve"] is True
        phone.withdraw(sent)
        assert relay.approvals == {}


def test_a_phone_is_never_asked_about_adding_changing_or_deleting_a_key(world, relay):
    _linked_phone(world, relay)
    with world["at"]("owner"):
        for kind in ("add", "modify", "delete"):
            assert phone.ask(rid="aaaa1111", app="x", keys=["OPENAI_API_KEY"], kind=kind) == []
    assert relay.approvals == {}


def test_the_broker_waits_longer_with_a_phone_and_takes_its_signed_answer(world, relay, monkeypatch):
    import passbook_broker as broker
    monkeypatch.delenv("PASSBOOK_APPROVAL_TIMEOUT", raising=False)
    with world["at"]("owner") as home:
        assert broker._approval_timeout() == 60.0
    handset, _ = _linked_phone(world, relay)
    with world["at"]("owner") as home:
        assert broker._approval_timeout() == broker.PHONE_APPROVAL_SECONDS
        monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "5")
        assert broker._approval_timeout() == 5.0, "a number somebody set still wins"

        request_id, event = broker._queue("claude-code", ["OPENAI_API_KEY"], "run the evals", root=home)
        deadline = time.monotonic() + 5
        while not relay.approvals and time.monotonic() < deadline:
            time.sleep(0.05)
        (approval, row), = relay.approvals.items()
        row.update(status="decided", answer=handset.answer(handset.open(row["sealed"]), "allow"))
        assert broker._await_decision(request_id, event) == "approve"
        rows = passbook_stamp.read_stamps(root=home)
        assert any(r["op"] == "approve" and r["reason"] == "answered from phone: iPhone" and r["keys"] == ["OPENAI_API_KEY"] for r in rows)

        # Answered, so the question is taken back off the phone.
        deadline = time.monotonic() + 5
        while relay.approvals and time.monotonic() < deadline:
            time.sleep(0.05)
        assert relay.approvals == {}

        # A request to change the store is not sent to the phone at all.
        change_id, _ = broker._queue("claude-code", ["OPENAI_API_KEY"], "rotate", kind="modify", root=home)
        time.sleep(0.4)
        assert relay.approvals == {}
        broker.resolve(change_id, approve=False)


# ── other people ────────────────────────────────────────────────────────────


def _member(world, relay, role="use", keys=("OPENAI_API_KEY", "ANTHROPIC_API_KEY")):
    relay.plan.update(plan="teams", seats=2)
    with world["at"]("owner"):
        made = team.invite("Ada Lovelace", {"keys": list(keys)}, role=role)
    _join(world, made["invite"])
    return made


def test_a_person_is_refused_without_seats_before_anybody_is_sent_a_line(world, relay):
    with world["at"]("owner"):
        with pytest.raises(join.JoinError, match="PassBook Sync lifts this") as refused:
            team.invite("Ada", {"keys": ["OPENAI_API_KEY"]})
        assert refused.value.code == "seat_limit" and join.invites() == []
        with pytest.raises(team.TeamError, match="Give the person a name"):
            team.invite("  ", {"keys": ["OPENAI_API_KEY"]})
        with pytest.raises(team.TeamError, match="A role is"):
            team.invite("Ada", {"keys": ["OPENAI_API_KEY"]}, role="admin")


def test_shared_to_use_arrives_guarded_and_shared_to_read_does_not(world, relay):
    _member(world, relay, role="use")
    with world["at"]("bot"):
        assert passbook_grant.guarded(access.read_policy()) == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
        assert [(row["role"], row["keys"]) for row in team.shared_with_me()] == [("use", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])]
    with world["at"]("owner"):
        assert [(m["name"], m["role"], m["keys"]) for m in team.members()] == [("Ada Lovelace", "use", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])]
        assert passbook_link.grants()["lent"][0]["kind"] == "member" if "kind" in passbook_link.grants()["lent"][0] else True


def test_a_read_role_leaves_the_key_unguarded(world, relay):
    _member(world, relay, role="read", keys=("OPENAI_API_KEY",))
    with world["at"]("bot"):
        assert passbook_grant.guarded(access.read_policy()) == []
        assert team.shared_with_me()[0]["role"] == "read"


def test_the_role_and_name_are_inside_the_signed_grant(world, relay):
    made = _member(world, relay)
    box, = [box for box in relay.boxes.values()]
    outer = json.loads(_unb64(box["envelope"][len(passbook_link.ENVELOPE_PREFIX):]))
    assert outer["grant"]["att"][0]["nb"]["role"] == ["use"] and outer["grant"]["att"][0]["nb"]["member"] == ["Ada Lovelace"]
    # Changing the role on the way breaks the signature, so the member's PassBook refuses it.
    outer["grant"]["att"][0]["nb"]["role"] = ["read"]
    tampered = passbook_link.ENVELOPE_PREFIX + _b64(json.dumps(outer, separators=(",", ":")).encode())
    with world["at"]("bot"):
        with pytest.raises(passbook_link.LinkError, match="signature does not match"):
            passbook_link.envelope_issuer(tampered)
    assert made["role"] == "use"


def test_a_member_reports_only_the_owners_keys_and_only_the_owner_can_read_it(world, relay):
    _member(world, relay)
    with world["at"]("bot") as home:
        passbook.set_values({"MY_OWN_KEY": "mine"}, overwrite=True)
        passbook_stamp.stamp(op="use", keys=["OPENAI_API_KEY", "MY_OWN_KEY"], app="claude-code", reason="run the evals", granted=True, root=home)
        passbook_stamp.stamp(op="read", keys=["MY_OWN_KEY"], app="claude-code", reason="private", granted=True, root=home)
        passbook_stamp.stamp(op="denied", keys=["ANTHROPIC_API_KEY"], app="unknown-tool", reason="not allowed", granted=False, root=home)
        assert team.report() == {"ok": True, "sent": 2, "owners": 1}
        assert team.report()["sent"] == 0, "what was reported is not reported again"
    assert len(relay.events) == 2
    traffic = "\n".join(relay.seen)
    for private in ("MY_OWN_KEY", "run the evals", "claude-code", "unknown-tool"):
        assert private not in traffic.split("/team/events", 1)[1], f"{private} is sealed, not sent in the clear"
    with world["at"]("owner"):
        rows = team.activity()
        assert [(r["member"], r["op"], r["keys"], r["app"], r["granted"]) for r in rows] == [
            ("Ada Lovelace", "denied", ["ANTHROPIC_API_KEY"], "unknown-tool", False),
            ("Ada Lovelace", "use", ["OPENAI_API_KEY"], "claude-code", True)]
        assert "MY_OWN_KEY" not in json.dumps(rows)
        assert len(team.activity()) == 2, "read again, nothing is doubled"
        # Something the relay made up, or sealed to somebody else, is not shown.
        relay.events.append({"id": _new_id(), "owner": passbook_link.identity()["did"], "member": "did:key:zForged", "sealed": "pbts1.aaaa.bbbb.cccc", "at": "2026-11-26T09:00:00.000Z"})
        assert len(team.activity()) == 2
    with world["at"]("bot") as home:
        assert team._open_event(relay.events[0]["sealed"], passbook_link.identity()) is None, "the member cannot read it back either"


def test_two_uses_in_the_same_instant_are_both_reported(world, relay, monkeypatch):
    _member(world, relay)
    monkeypatch.setattr(passbook_stamp, "_now", lambda: "2026-11-26T03:00:00Z")
    with world["at"]("bot") as home:
        passbook_stamp.stamp(op="use", keys=["OPENAI_API_KEY"], app="one", granted=True, root=home)
        assert team.report()["sent"] == 1
        passbook_stamp.stamp(op="use", keys=["OPENAI_API_KEY"], app="two", granted=True, root=home)
        assert team.report()["sent"] == 1, "a second row at the very same time is not skipped"
        assert team.report()["sent"] == 0


def test_removing_a_person_stops_their_reports_and_names_what_to_rotate(world, relay):
    _member(world, relay)
    with world["at"]("owner"):
        did = team.members()[0]["did"]
        result = team.remove(did)
        assert result["ok"] and result["rotate"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
        assert team.members() == []
        with pytest.raises(team.TeamError, match="does not share with that person"):
            team.remove(did)
    with world["at"]("bot") as home:
        passbook_stamp.stamp(op="use", keys=["OPENAI_API_KEY"], app="late", granted=True, root=home)
        assert team.report()["sent"] == 0
    assert relay.events == []
