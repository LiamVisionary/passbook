# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What the vault must guarantee, stated as tests.

The headline property is the one in the first test: a sealed store, read by
someone without a factor, yields nothing — not ciphertext, not an error, not a
partial. Everything else here defends that property's edges.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import passbook  # noqa: E402
import passbook_vault as vault  # noqa: E402

PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _cheap_scrypt(monkeypatch):
    """Tests exercise logic, not the cost parameter; 64 MiB each would crawl."""
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-not-a-real-key\nOTHER=plain\n", encoding="utf-8")
    return tmp_path


def _profile(root: Path, label: str = "Liam") -> str:
    return vault.create_profile(label, password=PASSWORD, root=root)["id"]


# ── the headline property ──────────────────────────────────────────────────


def test_a_sealed_store_reads_as_nothing_without_a_factor(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)

    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert all(v.startswith(vault.PREFIX) for v in on_disk.values()), "something stayed readable"
    assert "sk-not-a-real-key" not in (root / ".env").read_text(encoding="utf-8")

    # A reader with no data key gets an honest absence, never ciphertext.
    blind = vault.unseal_mapping(on_disk, None, profile_id=pid)
    assert blind == {}

    # And the names are still listable, so a first-run screen still works.
    assert sorted(on_disk) == ["OPENAI_API_KEY", "OTHER"]


def test_the_right_password_opens_it_again(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)

    reopened = vault.unlock_with_password(pid, PASSWORD, root=root)
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert vault.unseal_mapping(on_disk, reopened, profile_id=pid) == {
        "OPENAI_API_KEY": "sk-not-a-real-key", "OTHER": "plain"}


def test_a_wrong_password_is_refused_not_guessed_at(root):
    pid = _profile(root)
    with pytest.raises(vault.InvalidFactor):
        vault.unlock_with_password(pid, "not the password", root=root)


# ── binding: ciphertext cannot be moved around ─────────────────────────────


def test_a_value_cannot_be_pasted_onto_another_key(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    sealed = vault.seal_value("ADMIN_TOKEN", "super-secret", dek, profile_id=pid)
    with pytest.raises(vault.InvalidFactor):
        vault.unseal_value("READONLY_TOKEN", sealed, dek, profile_id=pid)


def test_a_value_cannot_be_moved_between_profiles(root):
    first = _profile(root, "First")
    second = vault.create_profile("Second", password=PASSWORD, root=root, make_active=False)["id"]
    dek = vault.unlock_with_password(first, PASSWORD, root=root)
    sealed = vault.seal_value("K", "v", dek, profile_id=first)
    with pytest.raises(vault.InvalidFactor):
        vault.unseal_value("K", sealed, dek, profile_id=second)


def test_a_tampered_ciphertext_is_refused(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    sealed = vault.seal_value("K", "v", dek, profile_id=pid)
    raw = bytearray(base64.urlsafe_b64decode(sealed[len(vault.PREFIX):] + "=="))
    raw[-1] ^= 0x01
    flipped = vault.PREFIX + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    with pytest.raises(vault.InvalidFactor):
        vault.unseal_value("K", flipped, dek, profile_id=pid)


# ── the vault file itself gives nothing away ───────────────────────────────


def test_the_vault_file_holds_no_bare_key(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    text = (root / vault.VAULT_FILENAME).read_text(encoding="utf-8")
    assert base64.urlsafe_b64encode(dek).decode().rstrip("=") not in text
    assert PASSWORD not in text
    stored = json.loads(text)
    for profile in stored["profiles"]:
        for factor in profile["factors"]:
            assert set(factor) >= {"wrapped", "params", "kind"}
            assert "key" not in factor and "secret" not in factor


def test_the_vault_file_is_private(root):
    _profile(root)
    assert oct((root / vault.VAULT_FILENAME).stat().st_mode & 0o777) == "0o600"


# ── rotating a factor is cheap and actually revokes ────────────────────────


def test_changing_the_password_rewraps_without_touching_values(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    before = (root / ".env").read_text(encoding="utf-8")

    vault.change_password(pid, dek=dek, new_password="a whole new password", root=root)
    assert (root / ".env").read_text(encoding="utf-8") == before, "values were re-encrypted"

    with pytest.raises(vault.InvalidFactor):
        vault.unlock_with_password(pid, PASSWORD, root=root)
    assert vault.unlock_with_password(pid, "a whole new password", root=root) == dek


def test_a_second_password_also_opens_it(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.add_password_factor(pid, "a shared operator password", dek=dek, label="operator", root=root)
    assert vault.unlock_with_password(pid, "a shared operator password", root=root) == dek
    assert vault.unlock_with_password(pid, PASSWORD, root=root) == dek


# ── you cannot lock yourself out by accident ───────────────────────────────


def test_removing_the_last_way_in_is_refused(root):
    pid = _profile(root)
    only = vault.profiles(root=root)[0]["factors"][0]["id"]
    with pytest.raises(vault.VaultError, match="only way in"):
        vault.remove_factor(pid, only, root=root)


def test_a_profile_must_keep_a_password(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.add_passkey_factor(pid, dek=dek, credential_id="cred-1",
                             prf_secret=b"\x05" * 32, root=root)
    password_factor = next(f for f in vault.profiles(root=root)[0]["factors"]
                           if f["kind"] == "password")
    with pytest.raises(vault.VaultError, match="password factor"):
        vault.remove_factor(pid, password_factor["id"], root=root)


def test_creating_a_profile_demands_a_real_password(root):
    with pytest.raises(vault.VaultError, match="at least 8"):
        vault.create_profile("Weak", password="short", root=root)


# ── passkeys ───────────────────────────────────────────────────────────────


def test_an_enrolled_passkey_opens_the_vault(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    prf = os.urandom(32)
    vault.add_passkey_factor(pid, dek=dek, credential_id="cred-abc", prf_secret=prf,
                             rp_id="hivemind.local", root=root)
    assert vault.unlock_with_passkey(pid, credential_id="cred-abc", prf_secret=prf, root=root) == dek


def test_a_different_passkey_secret_is_refused(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.add_passkey_factor(pid, dek=dek, credential_id="cred-abc",
                             prf_secret=os.urandom(32), root=root)
    with pytest.raises(vault.InvalidFactor):
        vault.unlock_with_passkey(pid, credential_id="cred-abc",
                                  prf_secret=os.urandom(32), root=root)


def test_an_unenrolled_credential_is_refused(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.add_passkey_factor(pid, dek=dek, credential_id="cred-abc",
                             prf_secret=b"\x07" * 32, root=root)
    with pytest.raises(vault.InvalidFactor, match="not enrolled"):
        vault.unlock_with_passkey(pid, credential_id="cred-other",
                                  prf_secret=b"\x07" * 32, root=root)


def test_the_passkey_secret_is_never_stored(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    prf = os.urandom(32)
    vault.add_passkey_factor(pid, dek=dek, credential_id="cred-abc", prf_secret=prf, root=root)
    text = (root / vault.VAULT_FILENAME).read_text(encoding="utf-8")
    assert base64.urlsafe_b64encode(prf).decode().rstrip("=") not in text
    assert prf.hex() not in text


# ── the way back out ───────────────────────────────────────────────────────


def test_sealing_is_reversible(root):
    pid = _profile(root)
    original = (root / ".env").read_text(encoding="utf-8")
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    assert "sk-not-a-real-key" not in (root / ".env").read_text(encoding="utf-8")

    result = vault.unseal_store(dek, profile_id=pid, root=root)
    assert result["ok"] and sorted(result["opened"]) == ["OPENAI_API_KEY", "OTHER"]
    back = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert back == passbook.parse_env_text(original)


def test_sealing_twice_is_a_no_op(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    again = vault.seal_store(dek, profile_id=pid, root=root)
    assert again["ok"] and again["sealed"] == []


def test_a_mixed_store_reads_correctly(root):
    """A hand-added key keeps working until the next seal pass."""
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    passbook.set_values({"ADDED_BY_HAND": "still-plain"}, overwrite=True)

    current = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    opened = vault.unseal_mapping(current, dek, profile_id=pid)
    assert opened["ADDED_BY_HAND"] == "still-plain"
    assert opened["OPENAI_API_KEY"] == "sk-not-a-real-key"


def test_status_counts_what_is_still_readable(root):
    pid = _profile(root)
    before = vault.status(root=root)
    assert before["plaintext"] == ["OPENAI_API_KEY", "OTHER"] and not before["fully_sealed"]

    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    after = vault.status(root=root)
    assert after["fully_sealed"] and after["plaintext"] == []
    assert after["sealed"] == ["OPENAI_API_KEY", "OTHER"]
    assert "sign" in after["detail"].lower()


# ── profiles ───────────────────────────────────────────────────────────────


def test_profiles_are_listed_without_key_material(root):
    _profile(root, "Liam")
    vault.create_profile("Work", password=PASSWORD, root=root, make_active=False)
    listed = vault.profiles(root=root)
    assert [p["label"] for p in listed] == ["Liam", "Work"]
    assert sum(1 for p in listed if p["active"]) == 1
    assert "wrapped" not in json.dumps(listed)


def test_removing_a_profile_leaves_its_values_shut(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    vault.remove_profile(pid, root=root)
    assert vault.profiles(root=root) == []
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert vault.unseal_mapping(on_disk, None, profile_id=pid) == {}


# ── a locked store still says what it holds ────────────────────────────────
#
# These pin a bug that shipped: `key_names()` unsealed before listing, so a
# sealed store reported zero keys. `passbook list` went blank, `status` said
# "0 keys", and the app's Keys page would have looked like an empty machine —
# sending someone off to re-paste credentials that were sitting right there.


def test_a_locked_store_still_lists_its_key_names(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    before = passbook.key_names()
    vault.seal_store(dek, profile_id=pid, root=root)

    assert passbook.key_names() == before == ["OPENAI_API_KEY", "OTHER"]


def test_a_locked_store_reports_its_key_count(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)

    state = passbook.status()
    assert state["keys"] == ["OPENAI_API_KEY", "OTHER"]
    assert state["exists"]


def test_listing_names_never_opens_a_value(root):
    """Names come from the file, so listing must work with no key anywhere."""
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    passbook.set_unsealer(None)
    try:
        assert passbook.key_names() == ["OPENAI_API_KEY", "OTHER"]
        assert passbook.load().get("OPENAI_API_KEY") is None
    finally:
        passbook.set_unsealer(None)


# ── some things must stay readable ─────────────────────────────────────────


def test_skipped_keys_stay_readable(root):
    passbook.set_values({"NEXT_PUBLIC_POSTHOG_KEY": "phc_public",
                         "HIVEMINDOS_TIP_BOT_AUTOSTART": "1"}, overwrite=True)
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)

    result = vault.seal_store(dek, profile_id=pid, root=root,
                              skip=["NEXT_PUBLIC_*", "HIVEMINDOS_TIP_BOT_AUTOSTART"])
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))

    assert on_disk["NEXT_PUBLIC_POSTHOG_KEY"] == "phc_public"
    assert on_disk["HIVEMINDOS_TIP_BOT_AUTOSTART"] == "1"
    assert vault.is_sealed(on_disk["OPENAI_API_KEY"])
    assert sorted(result["skipped"]) == ["HIVEMINDOS_TIP_BOT_AUTOSTART", "NEXT_PUBLIC_POSTHOG_KEY"]


def test_the_skip_list_is_remembered_for_later_seals(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root, skip=["OTHER"])
    passbook.set_values({"ADDED_LATER": "plain", "OTHER": "still-plain"}, overwrite=True)

    vault.seal_store(dek, profile_id=pid, root=root)
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert on_disk["OTHER"] == "still-plain", "a remembered exemption was swallowed"
    assert vault.is_sealed(on_disk["ADDED_LATER"])


def test_a_skipped_key_still_reads_back_when_locked(root):
    """The point of skipping: boot code that cannot sign in still sees it."""
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root, skip=["OTHER"])
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert vault.unseal_mapping(on_disk, None, profile_id=pid) == {"OTHER": "plain"}


def test_the_round_trip_preserves_a_value_exactly(root):
    """A migration must not edit credentials, not even whitespace.

    A real store held a quoted OAuth client id with a trailing space. The
    rollback trimmed it, because `set_values` trims what people paste. Sealing
    is a move, not a paste.
    """
    odd = "Iv1.abc123def456  "
    passbook.set_values({"GITHUB_OAUTH_CLIENT_ID": odd}, overwrite=True, exact=True)
    before = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert before["GITHUB_OAUTH_CLIENT_ID"] == odd

    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    vault.unseal_store(dek, profile_id=pid, root=root)

    after = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert after == before, "the round trip changed a value"


def test_reads_while_sealed_are_exact_too(root):
    odd = "trailing-space-matters  "
    passbook.set_values({"ODD_ONE": odd}, overwrite=True, exact=True)
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert vault.unseal_mapping(on_disk, dek, profile_id=pid)["ODD_ONE"] == odd


def test_one_key_can_be_released_and_stays_released(root):
    """A boot flag that got sealed silently turns a feature off, and the symptom
    appears somewhere else entirely. Releasing it must also be remembered, or
    the next seal pass turns it off again."""
    passbook.set_values({"TIP_BOT_AUTOSTART": "1"}, overwrite=True)
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    assert vault.is_sealed(passbook.parse_env_text((root / ".env").read_text())["TIP_BOT_AUTOSTART"])

    result = vault.unseal_store(dek, profile_id=pid, root=root, only=["TIP_BOT_AUTOSTART"])
    on_disk = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert result["opened"] == ["TIP_BOT_AUTOSTART"]
    assert on_disk["TIP_BOT_AUTOSTART"] == "1"
    assert vault.is_sealed(on_disk["OPENAI_API_KEY"]), "releasing one key unsealed the rest"

    # And a later seal must leave it alone.
    passbook.set_values({"ADDED_LATER": "plain"}, overwrite=True)
    vault.seal_store(dek, profile_id=pid, root=root)
    after = passbook.parse_env_text((root / ".env").read_text(encoding="utf-8"))
    assert after["TIP_BOT_AUTOSTART"] == "1", "the release was forgotten"
    assert vault.is_sealed(after["ADDED_LATER"])


def test_releasing_a_key_that_is_not_there_says_so(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    result = vault.unseal_store(dek, profile_id=pid, root=root, only=["NOT_A_KEY"])
    assert not result["ok"] and result["absent"] == ["NOT_A_KEY"]
    assert result["opened"] == []


def test_writing_to_a_sealed_store_updates_rather_than_duplicating(root):
    """`set_values` asked "is this key here?" of a read that DROPS values it
    cannot open, so a writer without the key saw every sealed name as absent and
    appended a second line. PassBook then read the new value (last line wins)
    while anything regexing the file read the stale sealed one (first match) —
    two readers, two answers, one file."""
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    passbook.set_unsealer(None)          # a process that cannot open the store
    try:
        passbook.set_values({"OPENAI_API_KEY": "rewritten"}, overwrite=True)
    finally:
        passbook.set_unsealer(None)

    text = (root / ".env").read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l.startswith("OPENAI_API_KEY=")]
    assert len(lines) == 1, f"the key was duplicated: {lines}"
    assert lines[0] == "OPENAI_API_KEY=rewritten"


def test_no_key_ever_appears_twice_after_a_seal_and_a_write(root):
    pid = _profile(root)
    dek = vault.unlock_with_password(pid, PASSWORD, root=root)
    vault.seal_store(dek, profile_id=pid, root=root)
    vault.unseal_store(dek, profile_id=pid, root=root, only=["OTHER"])
    vault.seal_store(dek, profile_id=pid, root=root)

    names = [l.split("=", 1)[0] for l in (root / ".env").read_text().splitlines()
             if l and not l.startswith("#") and "=" in l]
    assert len(names) == len(set(names)), f"duplicate keys: {sorted(set(n for n in names if names.count(n) > 1))}"


def test_a_shadowed_duplicate_is_found_and_removed(root):
    """Readers disagree about a duplicated key: PassBook takes the last line,
    a tool regexing the file takes the first."""
    path = root / ".env"
    path.write_text("A_KEY=old\nOTHER=x\nA_KEY=new\n", encoding="utf-8")

    found = passbook.duplicate_keys(path)
    assert found == {"A_KEY": [1, 3]}

    result = passbook.drop_duplicate_lines(path)
    assert result["removed"] == {"A_KEY": [1]}
    text = path.read_text(encoding="utf-8")
    assert text.splitlines() == ["OTHER=x", "A_KEY=new"]
    assert passbook.duplicate_keys(path) == {}


def test_tidying_refuses_if_it_would_change_a_value(root, monkeypatch):
    """A repair that quietly altered a credential would be worse than the mess."""
    path = root / ".env"
    path.write_text("A_KEY=one\nA_KEY=two\n", encoding="utf-8")
    monkeypatch.setattr(passbook, "parse_env_text",
                        lambda text: {"A_KEY": "one" if "\n" in text.strip() else "two"})
    with pytest.raises(ValueError, match="would change a value"):
        passbook.drop_duplicate_lines(path)


def test_a_clean_file_needs_no_repair(root):
    assert passbook.duplicate_keys(root / ".env") == {}
    assert passbook.drop_duplicate_lines(root / ".env")["removed"] == {}
