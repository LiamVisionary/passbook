# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Which provider account each key belongs to (passbook_accounts.py).

Why it exists: during a rotation (2026-11-24) signing in to the wrong account cost time twice. DeepInfra's key
is in an account that signs in with GitHub, and a Google sign-in with the same address made an empty new one;
DashScope's key is in an account that signs in with Google under another address. So the claims tested here:
where a provider's API says who owns a key PassBook asks it and keeps the answer; where it does not, a person
(or an agent) can type it; a lookup never wipes what was typed; the email is kept beside the store, owner-only,
never in the store, the default `list`, or a reading's cache; and every surface that shows a key shows it.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_accounts as accounts  # noqa: E402
import passbook_balances as balances  # noqa: E402
import passbook_mcp as mcp  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src"

# The shape DeepInfra's /v1/me answered on 2026-11-24, with made-up values, plus a field that must never be kept.
DEEPINFRA_ME = {"uid": "u-123", "email": "Owner@Example.com", "provider": "github", "display_name": "owner",
                "team_display_name": "Owner's team", "api_key": "must-not-be-kept"}


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID", "PASSBOOK_APP"):
        monkeypatch.delenv(leaked, raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"DEEP_INFRA_API_KEY": "di-one", "DASHSCOPE_API_KEY": "ds-one", "OTHER_KEY": "x"})
    return tmp_path / "hive"


def _cli(*args, home: Path, stdin: str = ""):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", *args],
        capture_output=True, text=True, input=stdin, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(home), "PYTHONPATH": str(PACKAGE), "PASSBOOK_APP": ""},
    )


def _asked(answers):
    calls = []

    def fetch(kind, key):
        calls.append((kind, key))
        return answers(kind, key)

    return fetch, calls


# ── the record ──────────────────────────────────────────────────────────────


def test_an_entry_is_kept_beside_the_store_owner_only_and_not_in_it(machine):
    accounts.set_fields("DASHSCOPE_API_KEY", {"email": "Vibe@Example.com", "via": "google",
                                              "note": "Singapore region"})

    entry = accounts.get("DASHSCOPE_API_KEY")
    assert entry["email"] == "vibe@example.com" and entry["via"] == "google"
    assert accounts.describe(entry) == "vibe@example.com, signs in with Google · Singapore region"
    assert accounts.sources(entry) == "entered by hand"
    if os.name != "nt":
        assert stat.S_IMODE(accounts.path().stat().st_mode) == 0o600
    # Not a store key, so sync never carries it; and the address is nowhere in the store's files.
    assert not any(name.startswith("PASSBOOK_ACCOUNT") for name in passbook.key_names())
    for store in passbook._scoped_paths():
        assert "vibe@example.com" not in Path(store).read_text(encoding="utf-8").lower()


def test_a_field_left_out_is_kept_and_an_empty_one_is_cleared(machine):
    accounts.set_fields("OTHER_KEY", {"email": "a@example.com", "via": "github", "note": "first"})
    accounts.set_fields("OTHER_KEY", {"note": "second", "email": None})
    assert accounts.get("OTHER_KEY")["email"] == "a@example.com"
    assert accounts.get("OTHER_KEY")["note"] == "second"

    accounts.set_fields("OTHER_KEY", {"via": ""})
    assert "via" not in accounts.get("OTHER_KEY")
    accounts.set_fields("OTHER_KEY", {"email": "", "note": ""})
    assert accounts.get("OTHER_KEY") is None  # nothing left: the entry is gone


@pytest.mark.parametrize("field,value", [("email", "not an email"), ("email", "a@b"), ("via", "carrier pigeon"),
                                         ("note", "two\nlines")])
def test_what_cannot_be_right_is_refused(machine, field, value):
    with pytest.raises(accounts.AccountError):
        accounts.set_fields("OTHER_KEY", {field: value})
    assert accounts.get("OTHER_KEY") is None


def test_sign_in_methods_take_the_words_people_use(machine):
    accounts.set_fields("OTHER_KEY", {"via": "GH"})
    assert accounts.get("OTHER_KEY")["via"] == "github"
    accounts.set_fields("OTHER_KEY", {"via": "Email and password"})
    assert accounts.get("OTHER_KEY")["via"] == "password"


# ── asking the provider ─────────────────────────────────────────────────────


def test_deepinfra_says_who_owns_its_key_and_only_the_named_fields_are_kept(machine):
    fetch, calls = _asked(lambda kind, key: (200, DEEPINFRA_ME))
    [result] = accounts.lookup({"DEEP_INFRA_API_KEY": "di-one"}, ["DEEP_INFRA_API_KEY"], fetch=fetch)

    assert calls == [("deepinfra", "di-one")]
    assert result["status"] == "found"
    entry = accounts.get("DEEP_INFRA_API_KEY")
    assert (entry["email"], entry["via"], entry["account"]) == ("owner@example.com", "github", "Owner's team")
    assert accounts.sources(entry) == "found by DeepInfra's API"
    kept = accounts.path().read_text(encoding="utf-8")
    assert "must-not-be-kept" not in kept and "di-one" not in kept and "u-123" not in kept


def test_a_lookup_never_wipes_what_was_typed_and_corrects_what_differs(machine):
    accounts.set_fields("DEEP_INFRA_API_KEY", {"email": "typo@example.com", "via": "google", "note": "Ami"})
    fetch, _ = _asked(lambda kind, key: (200, {"email": "owner@example.com"}))
    [result] = accounts.lookup({"DEEP_INFRA_API_KEY": "di-one"}, ["DEEP_INFRA_API_KEY"], fetch=fetch)

    entry = accounts.get("DEEP_INFRA_API_KEY")
    assert entry["email"] == "owner@example.com" and result["changed"] == ["email"]
    assert entry["via"] == "google" and entry["note"] == "Ami"  # the provider did not say; typed stays
    assert entry["from"] == {"email": "DeepInfra's API", "via": "by hand", "note": "by hand"}


def test_the_same_key_is_asked_once_and_a_replaced_key_again(machine):
    fetch, calls = _asked(lambda kind, key: (200, DEEPINFRA_ME))
    accounts.lookup({"DEEP_INFRA_API_KEY": "di-one"}, ["DEEP_INFRA_API_KEY"], fetch=fetch)
    [again] = accounts.lookup({"DEEP_INFRA_API_KEY": "di-one"}, ["DEEP_INFRA_API_KEY"], fetch=fetch)
    assert again["status"] == "kept" and len(calls) == 1

    accounts.lookup({"DEEP_INFRA_API_KEY": "di-two"}, ["DEEP_INFRA_API_KEY"], fetch=fetch)
    assert len(calls) == 2  # rotated: its account may be another one
    accounts.lookup({"DEEP_INFRA_API_KEY": "di-two"}, ["DEEP_INFRA_API_KEY"], fetch=fetch, fresh=True)
    assert len(calls) == 3


@pytest.mark.parametrize("answer,status", [((401, None), "rejected"), ((403, None), "not-allowed"),
                                           ((200, {"uid": "only-an-id"}), "unsaid"), ((500, None), "error")])
def test_an_answer_that_names_nobody_changes_nothing(machine, answer, status):
    accounts.set_fields("DEEP_INFRA_API_KEY", {"email": "kept@example.com"})
    fetch, _ = _asked(lambda kind, key: answer)
    [result] = accounts.lookup({"DEEP_INFRA_API_KEY": "di-one"}, ["DEEP_INFRA_API_KEY"], fetch=fetch)
    assert result["status"] == status
    assert accounts.get("DEEP_INFRA_API_KEY")["email"] == "kept@example.com"


def test_a_provider_that_will_not_say_and_a_sealed_key_are_not_asked(machine):
    fetch, calls = _asked(lambda kind, key: (200, DEEPINFRA_ME))
    results = accounts.lookup({"DASHSCOPE_API_KEY": "ds-one", "DEEP_INFRA_API_KEY": "hive-sealed:v2:abc"},
                              ["DASHSCOPE_API_KEY", "DEEP_INFRA_API_KEY"], fetch=fetch)
    assert [item["status"] for item in results] == ["no-api", "locked"]
    assert calls == []


def test_which_keys_a_provider_can_be_asked_about():
    assert balances.owner_provider("DEEP_INFRA_API_KEY")["id"] == "deepinfra"
    assert balances.owner_provider("DEEPINFRA_TOKEN")["id"] == "deepinfra"
    assert balances.owner_provider("DASHSCOPE_API_KEY") is None
    assert balances.owner_provider("GROQ_API_KEY") is None
    # A balance-only key may be made in another account; it never speaks for a key's owner.
    assert balances.owner_provider("ANTHROPIC_BALANCE_KEY") is None
    assert balances.owner_provider("STRIPE_BALANCE_KEY") is None
    assert balances.owner_provider("CLAUDE_API_KEY_SECOND")["id"] == "anthropic"


# Each kind's reader against the shape its provider documents (made-up values). A kind with no reader would
# be asked and never understood.
DOCUMENTED = {
    "deepinfra": (DEEPINFRA_ME, {"email": "Owner@Example.com", "via": "github", "account": "Owner's team"}),
    "vultr": ({"account": {"name": "Liam", "email": "v@example.com", "acls": []}}, {"email": "v@example.com", "account": "Liam"}),
    "runpod": ({"id": "r1", "email": "r@example.com"}, {"email": "r@example.com"}),
    "huggingface": ({"name": "hfuser", "fullname": "HF", "email": "h@example.com", "auth": {"type": "access_token"}},
                    {"email": "h@example.com", "account": "hfuser"}),
    "stripe": ({"id": "acct_1", "email": "s@example.com", "settings": {"dashboard": {"display_name": "Shop"}}},
               {"email": "s@example.com", "account": "Shop"}),
    "cloudflare": ({"result": {"id": "c1", "email": "c@example.com"}, "success": True}, {"email": "c@example.com"}),
    "vast": ({"id": 1, "email": "va@example.com"}, {"email": "va@example.com"}),
    "apify": ({"data": {"username": "ap", "email": "a@example.com", "proxy": {"password": "secret"}}},
              {"email": "a@example.com", "account": "ap"}),
    "resemble": ({"success": True, "item": {"email": "re@example.com"}}, {"email": "re@example.com"}),
    "github": ({"login": "octo", "email": None}, {"account": "octo"}),
    "anthropic": ({"id": "org-1", "name": "newvisionary", "type": "organization"}, {"account": "newvisionary"}),
    "fal": ({"username": "faluser", "credits": {}}, {"account": "faluser"}),
}


def test_every_provider_asked_has_a_reader_and_a_catalog_entry():
    assert set(DOCUMENTED) == set(balances.OWNERS)
    for kind, (payload, expected) in DOCUMENTED.items():
        found = balances.parse_owner(kind, payload)
        assert found, kind
        assert {field: value for field, value in found.items() if value} == expected, kind
        assert "secret" not in json.dumps(found)
        assert any(entry.get("owner") == kind for entry in balances.PROVIDERS), kind
        url = balances.OWNERS[kind][0]
        assert url.startswith("https://") and "?" not in url  # nothing personal or secret ever in an address


def test_rows_say_whose_account_they_are_without_putting_it_in_the_cache(machine, monkeypatch):
    import passbook_cli

    accounts.set_fields("DEEP_INFRA_API_KEY", {"email": "o@example.com", "via": "github"})
    rows = [{"providerId": "deepinfra", "name": "DeepInfra", "status": "manual", "accountKeys": ["DEEP_INFRA_API_KEY"]},
            {"providerId": "groq", "name": "Groq", "status": "manual", "accountKeys": ["GROQ_API_KEY"]}]
    monkeypatch.setattr(balances, "fetch_owner", lambda kind, key: (_ for _ in ()).throw(AssertionError("asked")))
    passbook_cli._owners_for_rows(rows, {})
    assert rows[0]["owner"]["line"] == "o@example.com, signs in with GitHub"
    assert rows[1]["owner"] is None
    # The line a person reads names the account; nothing an alert is made from does (name, issue).
    assert "o@example.com" not in rows[0]["name"]


# ── every surface ───────────────────────────────────────────────────────────


def test_set_check_list_and_rotate_status_from_the_command_line(machine):
    done = _cli("account", "set", "DASHSCOPE_API_KEY", "--email=vibe@example.com", "--via=google",
                "--account=Alibaba Cloud international", "--note=Singapore region", home=machine)
    assert done.returncode == 0, done.stderr
    line = "vibe@example.com, signs in with Google · Alibaba Cloud international · Singapore region"
    assert line in done.stdout

    checked = _cli("check", "DASHSCOPE_API_KEY", home=machine)
    assert checked.stdout.splitlines()[:2] == ["DASHSCOPE_API_KEY: set", f"    account: {line}"]

    # The default list is safe to paste anywhere: names only, as it always was.
    plain = _cli("list", home=machine).stdout
    assert "vibe@example.com" not in plain and "DASHSCOPE_API_KEY" in plain.splitlines()
    assert json.loads(_cli("list", "--json", home=machine).stdout) == passbook.key_names()
    assert line in _cli("list", "--accounts", home=machine).stdout

    status = json.loads(_cli("rotate", "DASHSCOPE_API_KEY", "--status", home=machine).stdout)
    assert status["account"]["email"] == "vibe@example.com" and status["account"]["line"] == line
    assert status["canLookUpAccount"] is False

    shown = json.loads(_cli("account", "DASHSCOPE_API_KEY", "--json", home=machine).stdout)
    assert shown["accounts"]["DASHSCOPE_API_KEY"]["via"] == "google"
    assert _cli("account", "clear", "DASHSCOPE_API_KEY", home=machine).returncode == 0
    assert accounts.get("DASHSCOPE_API_KEY") is None


def test_lookup_of_a_provider_that_will_not_say_asks_nothing_and_says_how_to_enter_it(machine):
    done = _cli("account", "lookup", "DASHSCOPE_API_KEY", home=machine)
    assert done.returncode == 0, done.stderr
    assert "passbook account set DASHSCOPE_API_KEY" in done.stdout
    answer = json.loads(_cli("account", "lookup", "DASHSCOPE_API_KEY", "--json", home=machine).stdout)
    assert answer["results"][0]["status"] == "no-api"


def test_a_bad_entry_fails_and_says_what_would_work(machine):
    done = _cli("account", "set", "OTHER_KEY", "--via=pigeon", home=machine)
    assert done.returncode == 1 and "google" in done.stderr


def test_the_window_gets_every_account_with_its_state(machine):
    accounts.set_fields("DASHSCOPE_API_KEY", {"email": "vibe@example.com", "via": "google"})
    state = json.loads(_cli("state", home=machine).stdout)
    catalog = state["catalog"]["accounts"]
    assert catalog["entries"]["DASHSCOPE_API_KEY"]["viaLabel"] == "Google"
    assert "DEEP_INFRA_API_KEY" in catalog["askable"] and "DASHSCOPE_API_KEY" not in catalog["askable"]
    assert catalog["via"]["github"] == "GitHub"


def test_the_window_calls_match_the_commands_it_may_run():
    rust = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    ui = (REPO / "app/ui/index.html").read_text(encoding="utf-8")
    handlers = re.search(r"tauri::generate_handler!\[(.*?)\]", rust, re.S).group(1)
    assert "account_set" in handlers and "account_lookup" in handlers
    assert "fn account_set(key: String, email: String, via: String, account: String, note: String)" in rust
    assert "fn account_lookup(key: String)" in rust
    assert re.search(r'"account_set", \{ key: [^}]*email: [^}]*via: [^}]*account: [^}]*note: ', ui)
    assert re.search(r'"account_lookup", \{ key: ', ui)
    # A typed value goes as --field=value, so one that starts with a dash is never read as a flag.
    assert 'format!("{flag}={}", value.trim())' in rust


def test_an_agent_records_and_reads_an_account_over_mcp(machine):
    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code"}}}, state)

    def call(tool, arguments):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                            "params": {"name": tool, "arguments": arguments}}, state)
        return reply["result"].get("structuredContent", reply["result"])

    noted = call("record_account", {"name": "DASHSCOPE_API_KEY", "email": "vibe@example.com", "via": "google"})
    assert noted["ok"] and noted["account"]["said"] == "recorded by claude-code"
    assert accounts.get("DASHSCOPE_API_KEY")["from"]["email"] == "mcp:claude-code"
    assert call("record_account", {"name": "DASHSCOPE_API_KEY", "via": "pigeon"})["ok"] is False
    listed = call("list_accounts", {})
    assert listed["accounts"]["DASHSCOPE_API_KEY"]["email"] == "vibe@example.com"
    names = {tool["name"] for tool in mcp.TOOLS}
    assert {"record_account", "list_accounts"} <= names
