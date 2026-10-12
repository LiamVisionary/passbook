# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""`passbook balances`: what each service account has left, read with the keys this store holds.

The readers and the provider list came from HivemindOS's service accounts, which now reads through this
module (Liam, 2026-10-12). These hold what they promised there: a reading is only what the provider
reported, a denial is only its HTTP category (the body can echo the key), a key never follows a redirect,
an inference key is never taken for a billing key, and the record says every read was to read balances.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import passbook_balances as balances  # noqa: E402

KEY = "sk-test-0123456789abcdef"


def test_the_catalog_is_whole_and_every_reader_has_an_address():
    ids = [entry["id"] for entry in balances.PROVIDERS]
    assert len(ids) == len(set(ids)) == 57
    readers = {entry["adapter"] for entry in balances.PROVIDERS if entry.get("adapter")}
    assert readers == set(balances.REQUESTS) and len(readers) == 13
    for url, _ in balances.REQUESTS.values():
        assert url.startswith("https://")
    for entry in balances.PROVIDERS:
        assert entry.get("keys") or entry.get("reading_keys") or not entry.get("adapter"), entry["id"]


@pytest.mark.parametrize("adapter, payload, expected", [
    ("openrouter", {"data": {"total_credits": 150, "total_usage": 15.66}}, {"balance": pytest.approx(134.34), "unit": "USD", "usageUsd": 15.66}),
    ("fal", {"credits": {"current_balance": 12.5, "currency": "USD"}, "username": "liam"}, {"balance": 12.5, "unit": "USD", "accountLabel": "liam"}),
    ("meshy", {"balance": 900}, {"balance": 900, "unit": "credits"}),
    ("vast", {"balance": 0}, {"balance": 0, "unit": "USD"}),
    ("apify", {"data": {"totalUsageCreditsUsdAfterVolumeDiscount": 3.2}}, {"usageUsd": 3.2}),
    ("deepseek", {"balance_infos": [{"currency": "CNY", "total_balance": "7.00"}, {"currency": "USD", "total_balance": "4.20", "granted_balance": "1.00"}]}, {"balance": 4.2, "unit": "USD"}),
    ("venice", {"balances": {"usd": 9.5, "diem": 2}}, {"balance": 9.5, "unit": "USD"}),
    ("bankr", {"effectiveBalanceUsd": 8, "dailyBudget": {"limitUsd": 5}}, {"balance": 8, "unit": "USD"}),
    ("elevenlabs", {"character_count": 92294, "character_limit": 300000, "next_character_count_reset_unix": 1793000000, "tier": "creator"}, {"allowance": {"used": 92294, "limit": 300000, "unit": "characters", "resetsAt": "2026-10-26T07:33:20Z"}}),
    ("agentmail", {"inbox_count": 3, "domain_count": 1, "organization_id": "org_1"}, {"accountLabel": "org_1"}),
    ("vultr", {"account": {"balance": -12.5, "pending_charges": 3.1, "name": "Liam"}}, {"accountLabel": "Liam"}),
    ("resend", {"emails": {"monthly": {"used": 291, "limit": 50000}, "daily": {"used": 4, "limit": None}}}, {"allowance": {"used": 291, "limit": 50000, "unit": "emails", "resetsAt": None}}),
    ("quiver", {"available_credits": "120", "observed_at": 1791800000, "organization_id": "org_q"}, {"balance": 120, "unit": "credits", "accountLabel": "org_q"}),
])
def test_each_reader_reads_its_providers_answer(adapter, payload, expected):
    reading = balances.parse_reading(adapter, payload)
    for key, value in expected.items():
        assert reading[key] == value, (adapter, key)


@pytest.mark.parametrize("adapter", sorted(balances.REQUESTS))
def test_an_answer_it_does_not_understand_is_never_a_balance(adapter):
    with pytest.raises(balances.Unreadable):
        balances.parse_reading(adapter, {"surprise": True})


def test_vultr_reports_amounts_as_given_and_never_calls_them_spendable():
    reading = balances.parse_reading("vultr", {"account": {"balance": -12.5, "pending_charges": 3.1}})
    assert "balance" not in reading, "a postpaid account's number is not money you have"
    assert {"label": "Pending charges", "value": "3.1 USD"} in reading["details"]


def test_the_finer_points_hivemindos_held_its_reader_to():
    """Carried over from HivemindOS's own suite when its Service Accounts started reading through PassBook."""
    deepseek = balances.parse_reading("deepseek", {"balance_infos": [
        {"currency": "CNY", "total_balance": "110.00", "granted_balance": "10.00", "topped_up_balance": "100.00"},
        {"currency": "USD", "total_balance": "20.123456789", "granted_balance": "0", "topped_up_balance": "20.123456789"}]})
    assert deepseek["unit"] == "USD" and deepseek["balance"] == 20.123456789
    assert any(row["value"] == "110.00 CNY" for row in deepseek["details"]), "other currencies keep their own strings"
    venice = balances.parse_reading("venice", {"balances": {"usd": 25, "diem": 90.5, "bundledCredits": 10, "earnedCredits": 5},
                                               "diemEpochAllocation": 100})
    assert venice["balance"] == 25 and any(row["value"] == "90.5 DIEM" for row in venice["details"]), "DIEM never inflates dollars"
    assert balances.parse_reading("bankr", {"balanceUsd": 12.34, "effectiveBalanceUsd": 11.2, "undeductedCostUsd": 1.14})["balance"] == 11.2
    eleven = balances.parse_reading("elevenlabs", {"tier": "starter", "character_count": 11000, "character_limit": 10000,
                                                   "current_overage": {"amount": "2.55", "currency": "usd"}, "currency": "usd",
                                                   "next_invoice": {"amount_due_cents": 1000}, "secret": "hidden"})
    assert "balance" not in eleven and eleven["allowance"]["used"] == 11000, "over-plan use is kept; an allowance is not cash"
    assert {"label": "Next invoice", "value": "10 USD"} in eleven["details"] and "hidden" not in json.dumps(eleven)
    resend = balances.parse_reading("resend", {"emails": {"daily": {"used": 10, "limit": None},
                                                          "monthly": {"used": 100, "limit": 50000, "resets_at": "2026-11-01T00:00:00.000Z"}}})
    assert any(row["value"] == "10 / No cap emails" for row in resend["details"]), "no cap is never a zero cap"
    now = int(time.time())
    quiver = balances.parse_reading("quiver", {"available_credits": "1234.567", "organization_id": "org", "observed_at": now - 120})
    assert quiver["balance"] == 1234.567 and quiver["observedAt"].startswith(time.strftime("%Y-%m-%dT", time.gmtime(now - 120)))
    for odd in (("deepseek", {"balance_infos": [{"currency": "USD", "total_balance": ""}]}),
                ("bankr", {"balanceUsd": 12.34}),
                ("elevenlabs", {"character_count": None, "character_limit": 100}),
                ("resend", {"emails": {"daily": {"used": None, "limit": None}, "monthly": {"used": 0, "limit": 100}}}),
                ("quiver", {"available_credits": 1e20, "organization_id": "org", "observed_at": now}),
                ("quiver", {"available_credits": 10, "organization_id": "org", "observed_at": now + 3600})):
        with pytest.raises(balances.Unreadable):
            balances.parse_reading(*odd)


def _entry(provider_id):
    return balances.provider(provider_id)


def test_the_states_a_provider_can_be_in():
    never = lambda *a: pytest.fail("no key, no request")  # noqa: E731
    assert balances.read_provider(_entry("meshy"), {}, set(), fetch=never)["status"] == "missing"
    held = balances.read_provider(_entry("meshy"), {"MESHY_API_KEY": "hive-sealed:x"}, {"MESHY_API_KEY"}, fetch=never)
    assert held["status"] == "locked", "held but not openable here is not missing"
    manual = balances.read_provider(_entry("openai-api"), {"OPENAI_API_KEY": KEY}, {"OPENAI_API_KEY"}, fetch=never)
    assert manual["status"] == "manual" and manual["topUpUrl"].startswith("https://platform.openai.com")
    # An inference key is never taken for a billing key.
    quiver = balances.read_provider(_entry("quiver"), {"QUIVER_API_KEY": KEY}, {"QUIVER_API_KEY"}, fetch=never)
    assert quiver["status"] == "missing" and "QUIVER_BILLING_ADMIN_KEY" in quiver["message"]


def test_a_denial_is_its_category_and_its_body_is_never_read():
    for status, category in ((401, "authentication-rejected"), (403, "access-denied")):
        reading = balances.read_provider(_entry("bankr"), {"BANKR_LLM_KEY": KEY}, {"BANKR_LLM_KEY"},
                                         fetch=lambda adapter, key, s=status: (s, None))
        assert reading["status"] == "error"
        assert reading["providerError"] == {"httpStatus": status, "category": category}
        assert reading["balance"] is None


def test_a_failure_or_an_odd_answer_assumes_no_balance():
    def offline(adapter, key):
        raise OSError("no network")
    for fetch in (offline, lambda a, k: (500, None), lambda a, k: (200, {"odd": 1})):
        reading = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, {"OPENROUTER_MANAGEMENT_KEY"}, fetch=fetch)
        assert reading["status"] == "error" and reading["balance"] is None


def test_a_ready_reading_says_what_it_is_and_where_to_top_up():
    reading = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, {"OPENROUTER_MANAGEMENT_KEY"},
                                     fetch=lambda a, k: (200, {"data": {"total_credits": 10, "total_usage": 4}}))
    assert reading["status"] == "ready" and reading["balance"] == 6
    assert reading["topUpUrl"] == "https://openrouter.ai/settings/credits"
    assert reading["keyName"] == "OPENROUTER_MANAGEMENT_KEY"
    assert KEY not in json.dumps(reading)


def test_a_reading_names_its_key_by_a_fingerprint_that_changes_when_the_key_does():
    salt, other = b"s" * 32, b"t" * 32
    answer = lambda a, k: (200, {"data": {"total_credits": 10, "total_usage": 4}})  # noqa: E731
    one = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, {"OPENROUTER_MANAGEMENT_KEY"},
                                 fetch=answer, salt=salt)
    same = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, {"OPENROUTER_MANAGEMENT_KEY"},
                                  fetch=answer, salt=salt)
    rotated = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY + "x"},
                                     {"OPENROUTER_MANAGEMENT_KEY"}, fetch=answer, salt=salt)
    assert one["connection"] and one["connection"] == same["connection"] != rotated["connection"]
    assert balances.fingerprint(other, "openrouter", KEY) != one["connection"], "a fingerprint means nothing off this machine"
    assert KEY not in one["connection"]


def test_a_recent_reading_is_reused_only_for_the_same_key():
    salt = b"s" * 32
    never = lambda *a: pytest.fail("the same key is answered from the recent reading")  # noqa: E731
    kept = {"openrouter": {"providerId": "openrouter", "status": "ready", "balance": 6,
                           "connection": balances.fingerprint(salt, "openrouter", KEY)}}
    held = {"OPENROUTER_MANAGEMENT_KEY"}
    assert balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, held, fetch=never,
                                  salt=salt, fresh_from=kept) is kept["openrouter"]
    asked = []
    rotated = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": "new-" + KEY}, held,
                                     fetch=lambda a, k: asked.append(a) or (200, {"data": {"total_credits": 1, "total_usage": 0}}),
                                     salt=salt, fresh_from=kept)
    assert asked == ["openrouter"] and rotated["balance"] == 1, "a rotated key is asked afresh"


def test_the_fingerprint_secret_stays_on_this_machine(tmp_path):
    salt = balances.salt_for(tmp_path)
    assert len(salt) == 32 and balances.salt_for(tmp_path) == salt
    if os.name != "nt":  # Windows has no POSIX modes; the file sits in the store's own folder
        assert (tmp_path / balances.SALT_FILE).stat().st_mode & 0o077 == 0


class _Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/stolen")
            self.end_headers()
        else:
            # A denial whose body echoes the key, as some do.
            body = json.dumps({"error": f"bad key {self.headers.get('Authorization')}"}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_provider(monkeypatch):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield lambda path: monkeypatch.setitem(balances.REQUESTS, "meshy", (base + path, "Bearer"))
    server.shutdown()


def test_a_key_never_follows_a_redirect(local_provider):
    local_provider("/redirect")
    status, payload = balances.fetch_reading("meshy", KEY)
    assert status == 302 and payload is None


def test_a_denials_echo_of_the_key_never_comes_back(local_provider):
    local_provider("/deny")
    status, payload = balances.fetch_reading("meshy", KEY)
    assert status == 403 and payload is None
    reading = balances.read_provider(_entry("meshy"), {"MESHY_API_KEY": KEY}, {"MESHY_API_KEY"})
    assert KEY not in json.dumps(reading)


# ── the command ─────────────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path, monkeypatch):
    home = tmp_path / "hive"
    home.mkdir()
    env = {**os.environ, "HIVE_HOME": str(home), "PASSBOOK_KEYSTORE": "file"}
    for inherited in ("PASSBOOK_SERVICE", "PASSBOOK_GRANT", "PASSBOOK_APP", "PASSBOOK_REASON"):
        env.pop(inherited, None)

    def cli(*args):
        return subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args], capture_output=True,
                              text=True, env=env, cwd=str(tmp_path), stdin=subprocess.DEVNULL)

    assert cli("add", f"OPENROUTER_MANAGEMENT_KEY={KEY}", f"OPENAI_API_KEY={KEY}").returncode == 0
    monkeypatch.setenv("HIVE_HOME", str(home))
    monkeypatch.setenv("PASSBOOK_KEYSTORE", "file")
    for name in ("PASSBOOK_GRANT", "PASSBOOK_APP", "PASSBOOK_REASON", "OPENROUTER_MANAGEMENT_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    return cli, home


def test_the_page_is_off_until_turned_on(store):
    cli, _ = store
    assert json.loads(cli("balances", "status", "--json").stdout)["enabled"] is False
    assert json.loads(cli("balances", "enable", "--json").stdout)["enabled"] is True
    assert json.loads(cli("balances", "status", "--json").stdout)["enabled"] is True
    assert json.loads(cli("balances", "disable", "--json").stdout)["enabled"] is False


_READINGS = balances.readings


def _balances(monkeypatch, capsys, **flags):
    import passbook
    import passbook_cli

    # The command installs the broker's unsealer for the life of its process; here that is the test run's,
    # and a later test would read the store through it.
    monkeypatch.setattr(passbook, "_UNSEALER", passbook._UNSEALER)
    calls = []

    def fetch(adapter, key, timeout=12.0):
        calls.append(adapter)
        return 200, {"data": {"total_credits": 20, "total_usage": 5}}

    monkeypatch.setattr(balances, "fetch_reading", fetch)
    # read_provider took the default when it was defined; a list call passes it through readings().
    monkeypatch.setattr(balances, "readings", lambda *a, **kw: _READINGS(*a, **{**kw, "fetch": fetch}))
    # No test asks a real provider for anything: the daily figures are their own test, with a stand-in.
    monkeypatch.setattr(balances, "refresh_daily", lambda *a, **k: None)
    args = argparse.Namespace(**{"action": "list", "provider": [], "all": False, "fresh": False, "json": True,
                                 "app": "test-app", **flags})
    assert passbook_cli.cmd_balances(args) == 0
    return json.loads(capsys.readouterr().out), calls


def test_listing_reads_the_providers_you_hold_keys_for_and_remembers_only_numbers(store, monkeypatch, capsys):
    _, home = store
    shown, calls = _balances(monkeypatch, capsys)
    by_id = {row["providerId"]: row for row in shown["providers"]}
    assert set(by_id) == {"openrouter", "openai-api"}, "only providers a held key belongs to"
    assert by_id["openrouter"]["balance"] == 15 and by_id["openai-api"]["status"] == "manual"
    assert calls == ["openrouter"]
    assert KEY not in json.dumps(shown)
    assert by_id["openrouter"]["keyName"] == "OPENROUTER_MANAGEMENT_KEY" and by_id["openrouter"]["connection"]
    cache = (home / balances.CACHE_FILE).read_text()
    assert KEY not in cache
    # Within two minutes the same key is answered from memory, without asking the provider again.
    again, calls_again = _balances(monkeypatch, capsys)
    assert again["cached"] is True and calls_again == []
    # --fresh asks again.
    fresh, calls_fresh = _balances(monkeypatch, capsys, fresh=True)
    assert fresh["cached"] is False and calls_fresh == ["openrouter"]


def test_every_read_is_recorded_as_reading_balances(store, monkeypatch, capsys):
    cli, _ = store
    _balances(monkeypatch, capsys)
    history = json.loads(cli("history", "OPENROUTER_MANAGEMENT_KEY", "--json").stdout)
    reads = [row for row in history if row["op"] == "read"]
    assert reads and reads[-1]["app"] == "test-app" and reads[-1]["reason"] == "read service balances"


def test_open_goes_only_to_a_catalog_billing_page(store, monkeypatch, capsys):
    import passbook_cli
    import webbrowser

    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))
    args = argparse.Namespace(action="open", provider=["openrouter"], all=False, fresh=False, json=True, app="")
    assert passbook_cli.cmd_balances(args) == 0
    assert opened == ["https://openrouter.ai/settings/credits"]
    args.provider = ["https://evil.example"]
    assert passbook_cli.cmd_balances(args) != 0 and opened == ["https://openrouter.ai/settings/credits"]


# ── what the readings mean, kept and worked out by the command ──────────────


def test_a_listing_keeps_the_reading_and_says_what_it_means(store, monkeypatch, capsys):
    import passbook_insights as insights

    _, home = store
    monkeypatch.setattr(balances, "refresh_daily", lambda *a, **k: None)
    shown, _ = _balances(monkeypatch, capsys)
    row = {r["providerId"]: r for r in shown["providers"]}["openrouter"]
    assert row["insights"]["meter"]["left"] == 15 and row["insights"]["meter"]["kind"] == "balance"
    assert shown["summary"]["usd"]["balance"] == 15 and shown["summary"]["live"] == 1
    assert shown["alerts"]["on"] is False and shown["alerts"]["sent"] == 0
    kept = insights.load(home)["openrouter"]
    assert len(kept) == 1 and kept[0]["b"] == 15 and KEY not in (home / insights.HISTORY_FILE).read_text()
    _balances(monkeypatch, capsys)
    assert len(insights.load(home)["openrouter"]) == 1, "a reading answered from memory is not a second reading"
    assert "insights" not in (home / balances.CACHE_FILE).read_text(), "insights are worked out each time, never replayed"


def test_openrouters_daily_figures_are_summed_per_day_and_asked_a_few_times_a_day(tmp_path):
    import passbook_insights as insights

    payload = {"data": [{"date": "2026-10-10", "usage": 1.5, "model": "a"}, {"date": "2026-10-10 00:00:00", "usage": 2.0, "model": "b"},
                        {"date": "2026-10-11", "usage": 0.25}, {"date": "nonsense", "usage": 9}, {"date": "2026-10-11", "usage": -1}]}
    assert balances.parse_daily("openrouter", payload) == {"2026-10-10": 3.5, "2026-10-11": 0.25}
    with pytest.raises(balances.Unreadable):
        balances.parse_daily("openrouter", {"surprise": True})
    asked = []
    row = {"providerId": "openrouter", "status": "ready", "connection": "c1", "keyName": "OPENROUTER_MANAGEMENT_KEY"}
    fetch = lambda adapter, key: (asked.append((adapter, key)) or (200, payload))  # noqa: E731
    clock = [1_800_000_000.0]
    go = lambda **k: balances.refresh_daily(tmp_path, [row, {"providerId": "fal", "status": "ready", "connection": "c", "keyName": "FAL_KEY"}],  # noqa: E731
                                            {"OPENROUTER_MANAGEMENT_KEY": KEY, "FAL_KEY": KEY}, fetch=fetch, now=lambda: clock[0], **k)
    go()
    assert asked == [("openrouter", KEY)], "only a provider with daily figures is asked, with its own key"
    assert insights.daily(tmp_path)["openrouter"]["days"] == {"2026-10-10": 3.5, "2026-10-11": 0.25}
    assert KEY not in (tmp_path / insights.DAILY_FILE).read_text()
    go()
    assert len(asked) == 1, "not again within six hours"
    go(force=True)
    clock[0] += balances.DAILY_SECONDS + 1
    go()
    assert len(asked) == 3
    balances.refresh_daily(tmp_path, [row], {"OPENROUTER_MANAGEMENT_KEY": KEY}, fetch=lambda a, k: (403, None), now=lambda: clock[0], force=True)
    assert insights.daily(tmp_path)["openrouter"]["days"], "a refusal leaves what was kept"


def test_a_full_mark_is_set_and_cleared_from_the_command_line(store):
    cli, home = store
    assert json.loads(cli("balances", "full", "openrouter", "200", "--json").stdout) == {"full": {"openrouter": 200.0}}
    assert json.loads(cli("balances", "full", "openrouter", "clear", "--json").stdout) == {"full": {}}
    for bad in (("openrouter", "lots"), ("nobody", "5"), ("openrouter", "-3"), ("openrouter",)):
        assert cli("balances", "full", *bad).returncode != 0


def test_alerts_stay_off_until_a_test_message_has_arrived(store):
    cli, home = store
    assert json.loads(cli("balances", "alerts", "status", "--json").stdout) == {
        "on": False, "key": "PASSBOOK_TELEGRAM_BOT_TOKEN", "chat": "", "keyHeld": False}
    said = cli("balances", "alerts", "on", "--chat=-100123")
    assert said.returncode != 0 and "no key named PASSBOOK_TELEGRAM_BOT_TOKEN" in said.stderr
    assert json.loads(cli("balances", "alerts", "status", "--json").stdout)["on"] is False
    assert cli("balances", "alerts", "set", "--chat", "not a chat").returncode != 0
    assert json.loads(cli("balances", "alerts", "set", "--key", "OPENAI_API_KEY", "--json").stdout)["keyHeld"] is True


def test_turning_balances_off_forgets_the_history_the_logos_and_stops_alerts(store, monkeypatch, capsys):
    import passbook_alerts as alerts
    import passbook_insights as insights
    import passbook_logos as logos

    cli, home = store
    monkeypatch.setattr(balances, "refresh_daily", lambda *a, **k: None)
    _balances(monkeypatch, capsys)
    insights.set_mark(home, "openrouter", 50)
    (home / logos.ICONS_FILE).write_text("{}")
    alerts.configure(home, chat="42")
    alerts.configure(home, on=True)
    assert (home / insights.HISTORY_FILE).exists()
    assert cli("balances", "disable").returncode == 0
    for name in (insights.HISTORY_FILE, insights.MARKS_FILE, logos.ICONS_FILE, balances.CACHE_FILE):
        assert not (home / name).exists(), name
    assert alerts.settings(home) == {"on": False, "key": alerts.DEFAULT_KEY, "chat": "42"}, "where they went is kept for next time"
