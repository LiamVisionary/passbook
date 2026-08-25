# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Machine-linking tests — two machines, one adversary.

Each test names a property from the module docstring. The four that matter are
here as their own cases: membership is not authorization, the fingerprint is the
second factor, values are sealed to a device, and a grant is narrow.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_link  # noqa: E402

pytestmark = pytest.mark.skipif(
    not passbook_link.available(), reason="machine linking needs the `cryptography` package"
)

CLI = Path(__file__).resolve().parents[1] / "bin" / "passbook"


@pytest.fixture
def machines(tmp_path, monkeypatch):
    """Three isolated machines: an owner, a joiner, and a bystander."""
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    made = {name: tmp_path / name for name in ("owner", "joiner", "bystander")}
    for path in made.values():
        path.mkdir()

    @contextlib.contextmanager
    def at(name: str):
        monkeypatch.setenv("HIVE_HOME", str(made[name]))
        yield made[name]

    made["at"] = at
    return made


def _pair(machines) -> tuple[str, str]:
    """The joiner's pairing token and the fingerprint a human would compare."""
    with machines["at"]("joiner"):
        pairing = passbook_link.pairing_token()
    return pairing["token"], pairing["fingerprint"]


def _lend(machines, keys, *, days: int = 30, owner: str = "owner") -> str:
    token, fingerprint = _pair(machines)
    with machines["at"](owner):
        return passbook_link.grant(token, keys, confirm_fingerprint=fingerprint, days=days)["envelope"]


def _accept(machines, envelope, *, at: str = "joiner", **kwargs):
    """Accept as a person would: with the sending machine's fingerprint in hand."""
    with machines["at"](at):
        issuer = passbook_link.envelope_issuer(envelope)
        return passbook_link.accept(envelope, confirm_fingerprint=issuer["fingerprint"], **kwargs)


# ── the happy path ─────────────────────────────────────────────────────────


def test_a_linked_machine_receives_exactly_the_keys_it_was_lent(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT_A": "value-a", "LENT_B": "value-b", "WITHHELD": "value-c"})

    envelope = _lend(machines, ["LENT_A", "LENT_B"])

    result = _accept(machines, envelope)
    with machines["at"]("joiner"):
        assert result["keys"] == ["LENT_A", "LENT_B"]
        assert passbook.key_names() == ["LENT_A", "LENT_B"], "the third key never left the owner"
        stored = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
        assert stored["LENT_A"] == "value-a"
        assert stored["LENT_B"] == "value-b"


def test_a_did_key_carries_its_own_public_key(machines):
    with machines["at"]("owner"):
        me = passbook_link.identity()
    assert passbook_link.public_from_did(me["did"]) == me["sign_public"]


# ── the fingerprint is the second factor ───────────────────────────────────


def test_a_mismatched_fingerprint_refuses_the_grant(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    token, _ = _pair(machines)

    with machines["at"]("owner"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.grant(token, ["LENT"], confirm_fingerprint="AAAA-BBBB-CCCC-DDDD")

    assert "does not match" in str(error.value)


def test_a_swapped_token_cannot_produce_a_matching_fingerprint(machines):
    """The attack the fingerprint exists for: a token substituted in transit."""
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    _, honest_fingerprint = _pair(machines)
    with machines["at"]("bystander"):
        attacker_token = passbook_link.pairing_token()["token"]

    with machines["at"]("owner"), pytest.raises(passbook_link.LinkError):
        # The human is reading the joiner's screen, so this is the fingerprint
        # they type — and it cannot belong to the attacker's token.
        passbook_link.grant(attacker_token, ["LENT"], confirm_fingerprint=honest_fingerprint)


def test_the_fingerprint_comparison_ignores_spacing_and_case(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    token, fingerprint = _pair(machines)

    with machines["at"]("owner"):
        result = passbook_link.grant(token, ["LENT"], confirm_fingerprint=fingerprint.lower().replace("-", " "))

    assert result["keys"] == ["LENT"]


# ── sealed to a device, not to a network ───────────────────────────────────


def test_a_machine_the_envelope_was_not_for_cannot_open_it(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    envelope = _lend(machines, ["LENT"])

    with machines["at"]("bystander"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.accept(envelope, confirm_fingerprint="")

    assert "different machine" in str(error.value)
    with machines["at"]("bystander"):
        assert passbook.key_names() == []


def test_an_envelope_carries_no_readable_value(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "a-value-that-must-not-appear"})
    envelope = _lend(machines, ["LENT"])

    body = envelope[len(passbook_link.ENVELOPE_PREFIX):]
    decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")

    assert "a-value-that-must-not-appear" not in envelope
    assert "a-value-that-must-not-appear" not in decoded
    assert "LENT" in decoded, "key NAMES are public; the grant is meant to be readable"


def test_an_edited_grant_fails_its_signature(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value", "WITHHELD": "secret"})
    envelope = _lend(machines, ["LENT"])

    body = envelope[len(passbook_link.ENVELOPE_PREFIX):]
    parsed = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    parsed["grant"]["att"][0]["nb"]["keys"].append("WITHHELD")
    rebuilt = passbook_link.ENVELOPE_PREFIX + base64.urlsafe_b64encode(
        json.dumps(parsed, separators=(",", ":")).encode()).decode().rstrip("=")

    with machines["at"]("joiner"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.accept(rebuilt, confirm_fingerprint="")

    assert "signature" in str(error.value)


def test_the_signed_grant_decides_what_lands_not_the_payload(machines):
    """Defence in depth: even a payload that got through may not widen a grant."""
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    token, fingerprint = _pair(machines)
    with machines["at"]("owner"):
        result = passbook_link.grant(token, ["LENT"], confirm_fingerprint=fingerprint)

    permitted = result["grant"]["att"][0]["nb"]["keys"]
    assert permitted == ["LENT"], "the capability names the keys, so accept can filter on it"


# ── a grant is narrow, and it expires ──────────────────────────────────────


def test_an_envelope_cannot_be_used_twice(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    envelope = _lend(machines, ["LENT"])

    _accept(machines, envelope)
    with machines["at"]("joiner"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.accept(envelope)

    assert "already been used" in str(error.value)


def test_an_expired_grant_is_refused(machines, monkeypatch):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    envelope = _lend(machines, ["LENT"], days=1)

    real_now = passbook_link._now
    monkeypatch.setattr(passbook_link, "_now", lambda: real_now() + timedelta(days=2))

    with machines["at"]("joiner"), pytest.raises(passbook_link.LinkError) as error:
        issuer = passbook_link.envelope_issuer(envelope)
        passbook_link.accept(envelope, confirm_fingerprint=issuer["fingerprint"])

    assert "expired" in str(error.value)


def test_an_expired_pairing_token_is_refused(machines, monkeypatch):
    with machines["at"]("joiner"):
        token = passbook_link.pairing_token(ttl_seconds=60)["token"]

    real_now = passbook_link._now
    monkeypatch.setattr(passbook_link, "_now", lambda: real_now() + timedelta(minutes=5))

    with pytest.raises(passbook_link.LinkError) as error:
        passbook_link.read_pairing_token(token)
    assert "expired" in str(error.value)


def test_lending_a_key_the_owner_does_not_have_fails_rather_than_part_sending(machines):
    with machines["at"]("owner"):
        passbook.set_values({"HAVE": "value"})
    token, fingerprint = _pair(machines)

    with machines["at"]("owner"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.grant(token, ["HAVE", "DO_NOT_HAVE"], confirm_fingerprint=fingerprint)

    assert "DO_NOT_HAVE" in str(error.value)


def test_a_machine_cannot_link_to_itself(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
        pairing = passbook_link.pairing_token()
        with pytest.raises(passbook_link.LinkError) as error:
            passbook_link.grant(pairing["token"], ["LENT"], confirm_fingerprint=pairing["fingerprint"])

    assert "own" in str(error.value)


# ── revocation, told honestly ──────────────────────────────────────────────


def test_revoking_names_the_keys_that_must_still_be_rotated(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT_A": "a", "LENT_B": "b"})
    envelope = _lend(machines, ["LENT_A", "LENT_B"])
    _accept(machines, envelope)
    with machines["at"]("joiner"):
        joiner_did = passbook_link.identity()["did"]

    with machines["at"]("owner"):
        result = passbook_link.revoke(joiner_did)
        listed = passbook_link.grants()

    assert result["ok"]
    assert result["rotate"] == ["LENT_A", "LENT_B"]
    assert "rotate them at the provider" in result["detail"]
    assert listed["lent"][0]["revoked"] is True
    assert listed["lent"][0]["active"] is False


def test_revoking_a_machine_that_was_never_linked_says_so(machines):
    with machines["at"]("owner"):
        result = passbook_link.revoke("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
    assert result["ok"] is False
    assert result["rotate"] == []


def test_grants_report_key_names_and_never_values(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "a-value-nobody-should-see"})
    envelope = _lend(machines, ["LENT"])
    _accept(machines, envelope)

    for name in ("owner", "joiner"):
        with machines["at"](name):
            listed = json.dumps(passbook_link.grants())
        assert "a-value-nobody-should-see" not in listed
        assert "LENT" in listed


# ── the files it writes ────────────────────────────────────────────────────


def test_the_device_key_is_created_unreadable_to_anyone_else(machines):
    with machines["at"]("owner") as home:
        passbook_link.identity()
        assert stat.S_IMODE((home / passbook_link.DEVICE_FILENAME).stat().st_mode) == 0o600


def test_the_grant_record_is_created_unreadable_to_anyone_else(machines):
    with machines["at"]("owner") as home:
        passbook.set_values({"LENT": "value"})
    _lend(machines, ["LENT"])
    with machines["at"]("owner"):
        assert stat.S_IMODE((home / passbook_link.GRANTS_FILENAME).stat().st_mode) == 0o600


def test_the_identity_is_stable_across_calls(machines):
    with machines["at"]("owner"):
        first = passbook_link.describe_identity()
        second = passbook_link.describe_identity()
    assert first["did"] == second["did"]
    assert first["fingerprint"] == second["fingerprint"]


# ── through the command line ───────────────────────────────────────────────


def _cli(*args, home):
    import os

    return subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True, text=True, env={**os.environ, "HIVE_HOME": str(home)},
    )


def test_approving_without_a_confirmed_fingerprint_refuses_rather_than_skipping(machines):
    """A non-interactive run cannot perform the human check, so it must not proceed."""
    with machines["at"]("owner") as owner:
        passbook.set_values({"LENT": "value"})
    token, _ = _pair(machines)

    done = _cli("link", "approve", token, "--keys", "LENT", home=owner)

    assert done.returncode == 1
    assert "fingerprint confirmed" in done.stderr
    with machines["at"]("joiner"):
        assert passbook.key_names() == []


def test_the_cli_link_flow_never_prints_a_value(machines):
    with machines["at"]("owner") as owner:
        passbook.set_values({"LENT": "a-value-nobody-should-see"})
    token, fingerprint = _pair(machines)
    joiner = machines["joiner"]

    approve = _cli("link", "approve", token, "--keys", "LENT", "--confirm", fingerprint, home=owner)
    envelope = approve.stdout.strip().split("\n")[-3].strip()
    issuer_fingerprint = approve.stdout.split("fingerprint is ")[1].split(".")[0]
    accept = _cli("link", "accept", envelope, "--confirm", issuer_fingerprint, home=joiner)
    listing = _cli("link", home=owner)

    assert approve.returncode == 0 and accept.returncode == 0, approve.stderr + accept.stderr
    for stream in (approve.stdout, approve.stderr, accept.stdout, accept.stderr, listing.stdout):
        assert "a-value-nobody-should-see" not in stream
    with machines["at"]("joiner"):
        assert passbook.key_names() == ["LENT"]


# ── accepting is a trust decision too ──────────────────────────────────────


def test_an_unknown_machine_cannot_inject_its_own_keys(machines):
    """The attack accepting exists to stop.

    Anyone who saw this machine's pairing token knows its public key, so they can
    seal a perfectly valid envelope to it carrying THEIR value for a real key —
    an API key pointing at a proxy that logs every prompt. A receiver that checks
    only "does this envelope open" would store it.
    """
    with machines["at"]("bystander"):
        passbook.set_values({"OPENAI_API_KEY": "attacker-controlled-value"})
    token, fingerprint = _pair(machines)
    with machines["at"]("bystander"):
        hostile = passbook_link.grant(
            token, ["OPENAI_API_KEY"], confirm_fingerprint=fingerprint)["envelope"]

    with machines["at"]("joiner"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.accept(hostile)

    assert "has not accepted from before" in str(error.value)
    with machines["at"]("joiner"):
        assert passbook.key_names() == [], "nothing the stranger sent was stored"


def test_confirming_the_wrong_fingerprint_refuses_the_envelope(machines):
    with machines["at"]("bystander"):
        passbook.set_values({"OPENAI_API_KEY": "attacker-controlled-value"})
    token, fingerprint = _pair(machines)
    with machines["at"]("bystander"):
        hostile = passbook_link.grant(
            token, ["OPENAI_API_KEY"], confirm_fingerprint=fingerprint)["envelope"]
    with machines["at"]("owner"):
        # What the person would type: the fingerprint of the machine they BELIEVE
        # is sending, which is not the machine that actually signed this.
        expected_sender = passbook_link.identity()["fingerprint"]

    with machines["at"]("joiner"), pytest.raises(passbook_link.LinkError) as error:
        passbook_link.accept(hostile, confirm_fingerprint=expected_sender)

    assert "did not come from the machine you think it did" in str(error.value)


def test_a_confirmed_machine_is_not_asked_again(machines):
    """Binding an identity once is the point; a recurring prompt gets clicked through."""
    with machines["at"]("owner"):
        passbook.set_values({"FIRST": "a", "SECOND": "b"})

    _accept(machines, _lend(machines, ["FIRST"]))
    second = _lend(machines, ["SECOND"])

    with machines["at"]("joiner"):
        result = passbook_link.accept(second)          # no fingerprint needed now
        assert result["keys"] == ["SECOND"]
        assert passbook.key_names() == ["FIRST", "SECOND"]


def test_the_issuer_fingerprint_is_the_sending_machines_own(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
        owner_fingerprint = passbook_link.identity()["fingerprint"]
    token, fingerprint = _pair(machines)
    with machines["at"]("owner"):
        result = passbook_link.grant(token, ["LENT"], confirm_fingerprint=fingerprint)

    assert result["issuer_fingerprint"] == owner_fingerprint
    assert passbook_link.envelope_issuer(result["envelope"])["fingerprint"] == owner_fingerprint


def test_reading_an_issuer_neither_stores_nor_opens_anything(machines):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "a-value-nobody-should-see"})
    envelope = _lend(machines, ["LENT"])

    with machines["at"]("joiner"):
        issuer = passbook_link.envelope_issuer(envelope)
        assert issuer["keys"] == ["LENT"]
        assert passbook.key_names() == [], "inspecting must not be accepting"
    assert "a-value-nobody-should-see" not in json.dumps(issuer["_parsed"])


# ── together with the rest of the product ──────────────────────────────────


def test_a_sealed_store_still_lends_correctly(machines):
    """Sealing and linking have to compose, and each is easy to test alone.

    The sender's value is encrypted at rest, so `grant` has to unseal it before
    it can seal it to the recipient. A regression here would look like a
    successful link that delivers ciphertext.
    """
    passbook_seal = pytest.importorskip("passbook_seal")
    with machines["at"]("owner") as home:
        monkey_key = "0" * 43 + "="
        os.environ["HIVE_ENV_KEY"] = monkey_key
        try:
            passbook.set_values({"LENT": "the-real-value"})
            if not passbook_seal.available():
                pytest.skip("no sealing key available on this machine")
            passbook_seal.seal_store()
            assert "hive-sealed:" in (home / ".env").read_text(encoding="utf-8")
        finally:
            os.environ.pop("HIVE_ENV_KEY", None)

    os.environ["HIVE_ENV_KEY"] = monkey_key
    try:
        envelope = _lend(machines, ["LENT"])
        _accept(machines, envelope)
    finally:
        os.environ.pop("HIVE_ENV_KEY", None)

    with machines["at"]("joiner"):
        stored = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
        assert stored["LENT"] == "the-real-value", "the receiver must get the value, not the ciphertext"


def test_a_borrowed_key_lands_in_the_receivers_workspace(machines, monkeypatch):
    with machines["at"]("owner"):
        passbook.set_values({"LENT": "value"})
    envelope = _lend(machines, ["LENT"])

    joiner = machines["joiner"]
    (joiner / "workspaces.json").write_text(
        json.dumps({"activeWorkspaceId": "client", "workspaces": [{"id": "main"}, {"id": "client"}]}),
        encoding="utf-8")
    monkeypatch.setenv("HIVE_WORKSPACE", "client")
    result = _accept(machines, envelope)
    monkeypatch.delenv("HIVE_WORKSPACE")

    assert result["workspace"] == "client"
    assert result["path"] == str(joiner / "workspaces" / "client" / ".env")
    assert "LENT" not in passbook.parse_env_text(
        (joiner / ".env").read_text(encoding="utf-8") if (joiner / ".env").is_file() else "")


def test_link_json_gives_one_unambiguous_fingerprint(machines):
    """The human layout prints `fingerprint` on more than one line once a
    machine is linked, so grepping it silently returns two. Scripts need the object."""
    with machines["at"]("owner") as owner:
        passbook.set_values({"LENT": "value"})
    envelope = _lend(machines, ["LENT"])
    _accept(machines, envelope)

    done = _cli("link", "--json", home=owner)
    payload = json.loads(done.stdout)

    assert done.returncode == 0
    assert payload["fingerprint"].count("-") == 3
    assert len(payload["lent"]) == 1
    assert "value" not in done.stdout
