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
import urllib.request
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import passbook_balances as balances  # noqa: E402

KEY = "sk-test-0123456789abcdef"
NOW_S = int(time.time())
NOW_ISO = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime())


def test_the_catalog_is_whole_and_every_reader_has_an_address():
    ids = [entry["id"] for entry in balances.PROVIDERS]
    assert len(ids) == len(set(ids)) == 65
    readers = {entry["adapter"] for entry in balances.PROVIDERS if entry.get("adapter")}
    readers |= {item["adapter"] for entry in balances.PROVIDERS for item in entry.get("accounts", ()) if item.get("adapter")}
    assert readers == set(balances.REQUESTS) and len(readers) == 27
    for url, *_ in balances.REQUESTS.values():
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
    manual = balances.read_provider(_entry("groq"), {"GROQ_API_KEY": KEY}, {"GROQ_API_KEY"}, fetch=never)
    assert manual["status"] == "manual" and manual["issue"]["kind"] == "no-api"
    # OpenAI reports spend only to an Admin key: an inference key is never tried, and the fix is named.
    openai = balances.read_provider(_entry("openai-api"), {"OPENAI_API_KEY": KEY}, {"OPENAI_API_KEY"}, fetch=never)
    assert openai["status"] == "missing" and openai["topUpUrl"].startswith("https://platform.openai.com")
    assert openai["issue"]["kind"] == "needs-balance-key" and openai["issue"]["key"] == "OPENAI_BALANCE_KEY"
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
    again = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, held, fetch=never,
                                   salt=salt, fresh_from=kept)
    assert again is kept["openrouter"] and again["balance"] == 6
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
    monkeypatch.setattr(balances, "readings", lambda *a, **kw: _READINGS(*a, **{**kw, "fetch": fetch, "identify": lambda kind, key: (401, None)}))
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
    assert by_id["openrouter"]["balance"] == 15 and by_id["openai-api"]["status"] == "missing"
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


# ── 2026-10-18: every balance a held key can read, and a key of its own for the ones it cannot ─────────
#
# Liam: "passbook is missing LOTS of balances ... add a way in the balances view to add those higher permission
# keys specifically for that, so the rest of the keys keep their current permissions". The shapes below are
# what each provider answered to his own keys that day (numbers changed), read through a probe that printed
# only shapes.


@pytest.mark.parametrize("adapter, payload, expected", [
    ("venice", {"data": {"balances": {"USD": 5.95, "DIEM": 0, "BUNDLED_CREDITS": 0}, "accessPermitted": True}}, {"balance": 5.95, "unit": "USD"}),
    ("runpod", {"data": {"myself": {"clientBalance": 25.07, "currentSpendPerHr": 0.005, "spendLimit": 80}}}, {"balance": 25.07, "unit": "USD"}),
    ("kie", {"code": 200, "msg": "success", "data": 1050.0}, {"balance": 1050.0, "unit": "credits"}),
    ("tripo", {"code": 0, "data": {"balance": 12, "frozen": 2}}, {"balance": 12, "unit": "credits"}),
    ("bfl", {"credits": 5388.8}, {"balance": 5388.8, "unit": "credits"}),
    ("runware", {"data": [{"balance": 18.32, "organizationName": "Liam", "apiKeys": [{"apiKey": "rw-secret"}]}]}, {"balance": 18.32, "unit": "USD", "accountLabel": "Liam"}),
    ("muapi", {"balance": 18.3, "currency": "USD", "email": "x@y.z"}, {"balance": 18.3, "unit": "USD"}),
    ("fish", {"credit": "100.688820", "cumulative_top_up": "105.00"}, {"balance": 100.68882, "unit": "USD"}),
    ("browser-use", {"totalCreditsBalanceUsd": 50.04, "monthlyCreditsBalanceUsd": 0.0, "additionalCreditsBalanceUsd": 50.04}, {"balance": 50.04, "unit": "USD"}),
    ("openrouter-key", {"data": {"limit": 100, "limit_remaining": 97.9, "usage_monthly": 2.1, "usage": 99.1,
                                 "effective_budget": {"resets_at": "2026-11-01T00:00:00.000Z"}}},
     {"usageUsd": 2.1, "allowance": {"used": 2.1, "limit": 100, "unit": "USD", "resetsAt": "2026-11-01T00:00:00Z"}}),
    ("openai-costs", {"data": [{"start_time": NOW_S, "results": [{"amount": {"value": 1.25, "currency": "usd"}}]}, {"start_time": NOW_S, "results": []},
                               {"start_time": NOW_S, "results": [{"amount": {"value": 0.5, "currency": "usd"}}]}], "has_more": False}, {"usageUsd": 1.75}),
    ("anthropic-costs", {"data": [{"starting_at": NOW_ISO, "results": [{"amount": "123.45", "currency": "USD"}]},
                                  {"starting_at": NOW_ISO, "results": [{"amount": "100", "currency": "USD"}]}],
                         "has_more": False}, {"usageUsd": 2.2345, "usagePeriod": "This month so far"}),
])
def test_the_new_readers_read_what_each_provider_answered(adapter, payload, expected):
    reading = balances.parse_reading(adapter, payload)
    for key, value in expected.items():
        assert (reading[key] == pytest.approx(value)) if isinstance(value, float) else reading[key] == value, (adapter, key)


def test_money_held_or_invested_is_shown_as_reported_and_never_as_a_balance_to_spend():
    stripe = balances.parse_reading("stripe", {"available": [{"amount": 0, "currency": "usd"}],
                                               "pending": [{"amount": 2520, "currency": "usd"}], "livemode": True})
    alpaca = balances.parse_reading("alpaca", {"cash": "17.55", "equity": "20.47", "buying_power": "17.55", "currency": "USD",
                                               "account_number": "291555379", "status": "ACTIVE"})
    for reading in (stripe, alpaca):
        assert "balance" not in reading, "a sale or a market move must never read as a top-up or as spend"
    assert {"label": "Pending", "value": "25.2 USD"} in stripe["details"]
    assert alpaca["details"][0] == {"label": "Account value", "value": "20.47 USD"}
    assert "291555379" not in json.dumps(alpaca), "the brokerage account number is not kept"
    wallet = balances.parse_reading("bankr-wallet", {"success": True, "evmAddress": "0xabc", "balances": {
        "base": {"total": "176.27"}, "mainnet": {"total": "2.41"}, "solana": {"total": "0"}}})
    assert "balance" not in wallet and wallet["details"][0] == {"label": "Wallet value", "value": "178.68 USD"}
    assert "0xabc" not in json.dumps(wallet) and not any("solana" in d["label"] for d in wallet["details"]), "empty chains are not listed"
    runware = balances.parse_reading("runware", {"data": [{"balance": 1, "apiKeys": [{"apiKey": "rw-secret"}]}]})
    assert "rw-secret" not in json.dumps(runware), "Runware lists the account's keys in the same answer; none is kept"


def test_cost_readers_refuse_what_they_cannot_add_up():
    for odd in (("openai-costs", {"data": [{"results": [{"amount": {"value": 1, "currency": "eur"}}]}]}),
                ("anthropic-costs", {"data": [{"results": [{"amount": "1", "currency": "USD"}]}], "has_more": True}),
                ("kie", {"code": 401, "data": 5}), ("tripo", {"code": 2000, "data": {"balance": 1}}),
                ("stripe", {"available": [], "pending": []}), ("alpaca", {"cash": "x", "equity": "1", "currency": "USD"})):
        with pytest.raises(balances.Unreadable):
            balances.parse_reading(*odd)


def test_a_balance_only_key_is_tried_before_every_other_key():
    seen = []
    fetch = lambda adapter, key: seen.append(key) or (200, {"credits": {"current_balance": 3, "currency": "USD"}})  # noqa: E731
    values = {"FAL_KEY": "inference", "FAL_BALANCE_KEY": "admin"}
    row = balances.read_provider(_entry("fal"), values, set(values), fetch=fetch)
    assert seen == ["admin"] and row["keyName"] == "FAL_BALANCE_KEY" and row["balanceKey"]["held"]


def test_each_problem_says_what_is_wrong_and_the_one_thing_that_fixes_it():
    held = {"FAL_KEY", "VULTR_API_KEY", "OPENAI_API_KEY"}
    values = {name: KEY for name in held}
    refused = {"fal": 403, "vultr": 401}
    rows = balances.readings(values, held, fetch=lambda adapter, key: (refused[adapter], None))
    found = {item["providerId"]: item for item in balances.issues(rows)}
    assert [item["kind"] for item in balances.issues(rows)] == ["key-rejected", "needs-balance-key", "needs-balance-key"], "worst first"
    assert found["vultr"]["action"] == "add-key" and found["vultr"]["key"] == "VULTR_BALANCE_KEY"
    assert "allowed list" in found["vultr"]["fix"], "a Vultr 401 is often the key's address list, so it says so"
    assert found["fal"]["title"] == "FAL_KEY can't see billing" and found["fal"]["key"] == "FAL_BALANCE_KEY"
    assert found["fal"]["createUrl"].startswith("https://fal.ai/")
    assert found["openai-api"]["title"] == "Needs an OpenAI admin key", "an inference key is never tried for OpenAI's costs"
    assert KEY not in json.dumps(rows)


def test_a_second_account_is_its_own_row_and_the_same_account_is_shown_once():
    answers = {"main": 10, "backup": 4}
    fetch = lambda adapter, key: (200, {"credits": {"current_balance": answers[key], "currency": "USD"}})  # noqa: E731
    values = {"FAL_BALANCE_KEY": "main", "FAL_KEY_BACKUP": "backup"}
    rows = balances.readings(values, set(values), fetch=fetch)
    assert [(r["providerId"], r["provider"], r["balance"]) for r in rows] == [("fal", "fal", 10), ("fal/FAL_KEY_BACKUP", "fal", 4)]
    assert rows[1]["name"] == "fal · backup key" and rows[1]["balanceKey"] is None
    assert balances.provider("fal/FAL_KEY_BACKUP")["id"] == "fal/FAL_KEY_BACKUP", "full marks and top-ups find it"
    answers["backup"] = 10
    assert len(balances.readings(values, set(values), fetch=fetch)) == 1, "two keys on one account are one row"
    assert set(balances.wanted_keys(set(values))) == {"FAL_BALANCE_KEY", "FAL_KEY_BACKUP"}


def test_a_key_that_signs_in_as_a_pair_needs_both_halves():
    never = lambda *a: pytest.fail("half a pair is never sent")  # noqa: E731
    half = balances.read_provider(_entry("alpaca"), {"ALPACA_API_SECRET_KEY": "secret"}, {"ALPACA_API_SECRET_KEY"}, fetch=never)
    assert half["status"] == "missing" and half["issue"]["title"] == "Needs ALPACA_API_KEY_ID"
    sent = []
    values = {"ALPACA_API_SECRET_KEY": "secret", "ALPACA_API_KEY_ID": "id"}
    balances.read_provider(_entry("alpaca"), values, set(values),
                           fetch=lambda a, k: sent.append(k) or (200, {"cash": "1", "equity": "1", "currency": "USD"}))
    assert sent == ["id\nsecret"] and balances._headers("alpaca", sent[0], "")["APCA-API-KEY-ID"] == "id"
    assert set(balances.wanted_keys(set(values))) == set(values)


def test_balance_only_keys_are_opened_for_the_balance_readers_alone():
    # The callers that run the readers: this CLI, PassBook's window and HivemindOS (readings.ts says --app hivemindos).
    assert balances.BALANCE_KEY_READERS == ("passbook-balances", "passbook-app", "hivemindos")
    for entry in balances.PROVIDERS:
        slot = balances.balance_key(entry)
        if slot:
            assert slot["key"] not in entry.get("keys", ()), f"{entry['id']}: a balance-only key is never a key other apps use"
            assert slot["createUrl"].startswith("https://"), entry["id"]


def test_open_keys_goes_to_the_page_for_making_a_key(store, monkeypatch, capsys):
    import passbook_cli
    import webbrowser

    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))
    args = argparse.Namespace(action="open", provider=["fal"], all=False, fresh=False, json=True, app="", keys=True)
    assert passbook_cli.cmd_balances(args) == 0 and opened == ["https://fal.ai/dashboard/keys"]
    args.provider = ["fal/FAL_KEY_BACKUP"]
    args.keys = False
    assert passbook_cli.cmd_balances(args) == 0 and opened[-1] == "https://fal.ai/dashboard/usage-billing/billing"


def test_a_guarded_key_makes_balances_run_again_under_a_grant(store, monkeypatch):
    """Stripe's keys are guarded: a plain read leaves them out entirely, so their row said "locked" until
    the reading ran itself again inside a process the broker started, as `run` does (2026-10-18)."""
    import passbook_broker
    import passbook_cli
    import passbook_grant

    monkeypatch.setattr(passbook_grant, "guarded", lambda policy: ["STRIPE_MANAGEMENT_API_KEY"])
    monkeypatch.setattr(passbook_broker, "running", lambda: True)
    monkeypatch.setattr(passbook_cli, "_use_broker_for_sealed_values", lambda *a, **k: set())
    asked = []
    monkeypatch.setattr(passbook_cli, "_rerun_under_grant",
                        lambda app, reason, keys=None, guarded=False: asked.append((app, list(keys), guarded)) or 0)
    assert passbook_cli._balance_values("hivemindos", ["STRIPE_MANAGEMENT_API_KEY"]) == 0
    assert asked == [("hivemindos", ["STRIPE_MANAGEMENT_API_KEY"], True)]
    asked.clear()
    monkeypatch.setattr(passbook_grant, "guarded", lambda policy: [])
    passbook_cli._balance_values("hivemindos", ["STRIPE_MANAGEMENT_API_KEY"])
    assert asked == [("hivemindos", ["STRIPE_MANAGEMENT_API_KEY"], False)], "an unguarded missing key keeps the old path"


# ── 2026-10-18, later: several keys for one provider are several accounts, each named ──────────────────
#
# Liam: "i have multiple antrhopic api keys, which one is this for? ... users might have multiple of the same
# platform's keys". He holds six Anthropic keys in four organizations; Anthropic names the organization to
# any of them at /v1/organizations/me.

ORGS = {"k-main": ("org_main", "NewVisionary"), "k-main-2": ("org_main", "NewVisionary"),
        "k-ami": ("org_ami", "Ami's Individual Org"), "k-ami-2": ("org_ami", "Ami's Individual Org")}


def _who(kind, key):
    if key not in ORGS:
        return 401, None
    return 200, {"id": ORGS[key][0], "name": ORGS[key][1]}


def _anthropic_values():
    return {"ANTHROPIC_API_KEY": "k-main", "CLAUDE_CODE_X_API_KEY": "k-main-2",
            "ANTHROPIC_API_KEY_AMI": "k-ami", "CLAUDE_API_KEY_VIBE": "k-ami-2"}


def test_each_account_is_its_own_row_named_by_its_organization_with_its_own_balance_key():
    values = _anthropic_values()
    rows = balances.readings(values, set(values), fetch=lambda a, k: (403, None), identify=_who, known={}, salt=b"s" * 32)
    by_id = {row["providerId"]: row for row in rows}
    assert set(by_id) == {"anthropic", "anthropic/ANTHROPIC_API_KEY_AMI"}, "the first key's account keeps the bare id"
    main, ami = by_id["anthropic"], by_id["anthropic/ANTHROPIC_API_KEY_AMI"]
    assert main["name"] == "Anthropic API · NewVisionary" and ami["name"] == "Anthropic API · Ami's Individual Org"
    assert main["accountKeys"] == ["ANTHROPIC_API_KEY", "CLAUDE_CODE_X_API_KEY"]
    assert ami["accountKeys"] == ["ANTHROPIC_API_KEY_AMI", "CLAUDE_API_KEY_VIBE"]
    assert main["balanceKey"]["key"] == "ANTHROPIC_BALANCE_KEY" and ami["balanceKey"]["key"] == "ANTHROPIC_API_KEY_AMI_BALANCE_KEY"
    issue = {item["providerId"]: item for item in balances.issues(rows)}["anthropic/ANTHROPIC_API_KEY_AMI"]
    assert issue["title"] == "Ami's Individual Org is an individual organization" and issue["keys"] == ami["accountKeys"]
    # An Organization-scope key refused (403) is Anthropic declining the account (individual accounts have no
    # Admin API), not a key to paste; a workspace key's 401 asks for an Organization-scope key.
    assert issue["kind"] == "not-offered" and issue["action"] == "open" and "Convert to team" in issue["fix"]
    rows = balances.readings(values, set(values), fetch=lambda a, k: (401, None), identify=_who, known={})
    main_issue = next(row for row in rows if row["providerId"] == "anthropic")["issue"]
    assert main_issue["kind"] == "needs-balance-key" and main_issue["key"] == "ANTHROPIC_BALANCE_KEY"
    assert main_issue["title"] == "Needs an Anthropic key with Organization scope for NewVisionary"
    assert balances.provider("anthropic/ANTHROPIC_API_KEY_AMI")["billing_key"]["key"] == "ANTHROPIC_API_KEY_AMI_BALANCE_KEY"


def test_a_key_whose_account_cannot_be_told_is_never_merged_and_ids_hold_offline():
    values = _anthropic_values()
    known: dict = {}
    salt = b"s" * 32
    balances.readings(values, set(values), fetch=lambda a, k: (403, None), identify=_who, known=known, salt=salt)
    offline = lambda kind, key: (_ for _ in ()).throw(OSError("offline"))  # noqa: E731
    again = balances.readings(values, set(values), fetch=lambda a, k: (403, None), identify=offline, known=known, salt=salt)
    assert {row["providerId"] for row in again} == {"anthropic", "anthropic/ANTHROPIC_API_KEY_AMI"}, "kept identities hold the rows"
    alone = balances.readings(values, set(values), fetch=lambda a, k: (403, None), identify=offline, known={}, salt=salt)
    assert len(alone) == 4 and alone[0]["providerId"] == "anthropic", "never known: one row per key, the first keeps its id"


def test_a_balance_only_key_from_another_account_is_named_and_never_read_as_this_one():
    values = {**_anthropic_values(), "ANTHROPIC_API_KEY_AMI_BALANCE_KEY": "k-main"}
    sent = []
    rows = balances.readings(values, set(values), fetch=lambda a, k: sent.append(k) or (403, None), identify=_who, known={})
    ami = next(row for row in rows if row["providerId"] == "anthropic/ANTHROPIC_API_KEY_AMI")
    assert ami["issue"]["kind"] == "wrong-account" and "NewVisionary" in ami["issue"]["fix"]
    assert sent.count("k-main") == 1, "the stray key read only for its own account's row, if at all"


def test_each_key_of_an_account_is_tried_until_one_can_read_its_cost():
    values = _anthropic_values()
    answer = {"k-main-2": (200, {"data": [{"starting_at": NOW_ISO, "results": [{"amount": "250", "currency": "USD"}]}], "has_more": False})}
    rows = balances.readings(values, set(values), fetch=lambda a, k: answer.get(k, (401, None)), identify=_who, known={})
    main = next(row for row in rows if row["providerId"] == "anthropic")
    assert main["status"] == "ready" and main["keyName"] == "CLAUDE_CODE_X_API_KEY" and main["usageUsd"] == 2.5


def test_every_key_named_like_a_providers_is_found_and_balance_keys_are_not_mistaken_for_them():
    held = {"ANTHROPIC_API_KEY", "CLAUDE_API_KEY_LIAM_NABUT", "CLAUDE_CODE_LIAMVISIONARY_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_API_KEY_LIAM_NABUT_BALANCE_KEY", "ANTHROPIC_BALANCE_KEY", "CLAUDE_CLOUD_CLOUDFLARE_API_TOKEN"}
    assert balances.held_names(balances.provider("anthropic"), held) == [
        "ANTHROPIC_API_KEY", "CLAUDE_API_KEY_LIAM_NABUT", "CLAUDE_CODE_LIAMVISIONARY_API_KEY"]
    wanted = set(balances.wanted_keys(held))
    assert {"CLAUDE_API_KEY_LIAM_NABUT", "CLAUDE_API_KEY_LIAM_NABUT_BALANCE_KEY", "ANTHROPIC_BALANCE_KEY"} <= wanted
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in wanted


def test_keys_that_read_the_same_figures_are_one_account_and_different_ones_are_two():
    same = {"STRIPE_MANAGEMENT_API_KEY": "a", "PORTFOLIO_STRIPE_SECRET_KEY": "b"}
    answer = {"available": [{"amount": 0, "currency": "usd"}], "pending": [], "livemode": True}
    rows = balances.readings(same, set(same), only=["stripe"], fetch=lambda a, k: (200, answer))
    assert len(rows) == 1 and rows[0]["accountKeys"] == ["STRIPE_MANAGEMENT_API_KEY", "PORTFOLIO_STRIPE_SECRET_KEY"]
    other = {**answer, "pending": [{"amount": 500, "currency": "usd"}]}
    rows = balances.readings(same, set(same), only=["stripe"], fetch=lambda a, k: (200, answer if k == "a" else other))
    assert [row["providerId"] for row in rows] == ["stripe", "stripe/PORTFOLIO_STRIPE_SECRET_KEY"]
    assert rows[1]["name"] == "Stripe · PORTFOLIO_STRIPE_SECRET_KEY"


def test_an_organization_keys_refusal_says_more_than_a_workspace_keys():
    values = _anthropic_values()
    refusals = {"k-main": (401, None), "k-main-2": (403, None)}
    rows = balances.readings(values, set(values), fetch=lambda a, k: refusals.get(k, (401, None)), identify=_who, known={})
    main = next(row for row in rows if row["providerId"] == "anthropic")
    assert main["keyName"] == "CLAUDE_CODE_X_API_KEY" and main["issue"]["kind"] == "not-offered"


# ── 2026-10-18, later still: a balance you enter, where the provider reports only spend ─────────────────
#
# Liam: "it also isnt showing the meter and how many credits i have even though newvisionary ... has 247.57
# organization credits". Anthropic reports cost, never the credit left; he enters the figure once.

def _cost(days):
    return {"data": [{"starting_at": f"{day}T00:00:00Z", "results": [{"amount": str(cents), "currency": "USD"}]}
                     for day, cents in days.items()], "has_more": False}


def test_an_entered_balance_loses_only_what_is_spent_after_it_was_entered():
    today = time.strftime("%Y-%m-%d", time.gmtime())
    values = {"ANTHROPIC_API_KEY": "k-main"}
    # $5 had already gone today when he entered $247.57; $2 more since.
    record = balances.entered_record(247.57, {today: 5.0})
    assert record["baseline"] == 5.0 and record["day"] == today
    seen = []
    fetch = lambda a, k, start=None: seen.append(start) or (200, _cost({today: 700}))  # noqa: E731
    row = balances.readings(values, set(values), fetch=fetch, identify=_who, known={}, entered={"anthropic": record})[0]
    assert seen == [today], "the report is asked for from the day it was entered"
    assert row["balance"] == pytest.approx(245.57) and row["balanceKind"] == "entered" and row["unit"] == "USD"
    assert row["entered"]["spentSince"] == pytest.approx(2.0) and "estimate" in row["message"].lower()
    assert row.get("issue") is None
    used_up = balances.readings(values, set(values), fetch=lambda a, k, start=None: (200, _cost({today: 30000})),
                                identify=_who, known={}, entered={"anthropic": record})[0]
    assert used_up["issue"]["kind"] == "entered-stale", "more spent than it held: a top-up was missed, so ask again"


def test_a_spend_only_account_without_an_entry_asks_for_one_and_others_do_not():
    today = time.strftime("%Y-%m-%d", time.gmtime())
    values = {"ANTHROPIC_API_KEY": "k-main"}
    row = balances.readings(values, set(values), fetch=lambda a, k: (200, _cost({today: 100})), identify=_who, known={})[0]
    # Anthropic can also be read from its Console, so that is what is asked for first; typing it stays possible.
    assert row["canEnterBalance"] and row["issue"]["kind"] == "console-signin" and row["balance"] is None
    assert row["consoleSignIn"]["provider"] == "anthropic" and "undocumented" in row["issue"]["fix"]
    kie = balances.readings({"KIE_API_KEY": "k"}, {"KIE_API_KEY"}, fetch=lambda a, k: (200, {"code": 200, "data": 5}))[0]
    assert not kie.get("canEnterBalance"), "a provider that reports its balance never asks for one"


def test_a_cost_report_longer_than_a_page_is_followed(monkeypatch):
    pages = iter([(200, {"data": [{"starting_at": "2026-09-01T00:00:00Z", "results": []}], "has_more": True, "next_page": "p2"}),
                  (200, {"data": [{"starting_at": "2026-09-02T00:00:00Z", "results": []}], "has_more": False})])
    asked = []
    monkeypatch.setattr(balances, "_get", lambda url, *a, **k: asked.append(url) or next(pages))
    status, payload = balances.fetch_reading("anthropic-costs", KEY, start="2026-09-01")
    assert status == 200 and len(payload["data"]) == 2 and asked[1].endswith("&page=p2")
    assert "starting_at=2026-09-01T00:00:00Z" in asked[0]


def test_providers_are_asked_at_once_and_rows_keep_the_catalogs_order():
    import threading

    names = {"KIE_API_KEY": "a", "BFL_API_KEY": "b", "FISH_AUDIO_API_KEY": "c", "MUAPI_API_KEY": "d"}
    threads = set()
    answers = {"kie": {"code": 200, "data": 1}, "bfl": {"credits": 2}, "fish": {"credit": "3"}, "muapi": {"balance": 4, "currency": "USD"}}

    def fetch(adapter, key):
        threads.add(threading.get_ident())
        time.sleep(0.05)
        return 200, answers[adapter]

    rows = balances.readings(names, set(names), fetch=fetch)
    catalog = [entry["id"] for entry in balances.PROVIDERS]
    assert [row["providerId"] for row in rows] == sorted((row["providerId"] for row in rows), key=catalog.index)
    assert len(threads) > 1


def test_known_keeps_the_entered_balance_and_clear_takes_it_off(store, monkeypatch, capsys):
    import passbook
    import passbook_cli

    _, home = store
    today = time.strftime("%Y-%m-%d", time.gmtime())
    assert store[0]("add", f"ANTHROPIC_API_KEY={KEY}").returncode == 0
    monkeypatch.setattr(passbook, "_UNSEALER", passbook._UNSEALER)
    monkeypatch.setattr(balances, "readings", lambda *a, **kw: _READINGS(*a, **{**kw, "fetch": lambda ad, k, start=None: (200, _cost({today: 300})),
                                                                             "identify": lambda kind, key: (401, None)}))
    args = argparse.Namespace(action="known", provider=["anthropic", "100"], all=False, fresh=False, json=True, app="test-app")
    assert passbook_cli.cmd_balances(args) == 0
    kept = balances.entered(home)["anthropic"]
    assert kept["amount"] == 100 and kept["baseline"] == 3.0
    capsys.readouterr()
    args.provider = ["anthropic", "clear"]
    assert passbook_cli.cmd_balances(args) == 0 and balances.entered(home) == {}
    args.provider = ["kie", "5"]
    assert passbook_cli.cmd_balances(args) != 0, "only a provider that reports spend and not credit takes one"


def test_a_remembered_reading_keeps_what_it_asks_for():
    """1.10.18 wiped a cached row's issue, so "Enter credits" vanished for two minutes after every fresh read."""
    salt = b"s" * 32
    kept = {"openrouter": {"providerId": "openrouter", "status": "ready", "balance": 6, "issue": {"kind": "enter-balance"},
                           "connection": balances.fingerprint(salt, "openrouter", KEY)}}
    again = balances.read_provider(_entry("openrouter"), {"OPENROUTER_MANAGEMENT_KEY": KEY}, {"OPENROUTER_MANAGEMENT_KEY"},
                                   fetch=lambda *a: pytest.fail("answered from memory"), salt=salt, fresh_from=kept)
    assert again["issue"] == {"kind": "enter-balance"}



# ── 2026-10-19: Anthropic's credits from its own Console, signed in once ───────────────────────────────
#
# Liam: "let me sign in to the Anthropic Console in PassBook so it reads the live credit balance the Console
# shows, and say clearly that it uses Anthropic's undocumented web API".

def _console(orgs, credits):
    def fetch(url, cookie, **kw):
        assert cookie.startswith("sessionKey="), "the saved cookies are sent as they are"
        if url.endswith("/api/organizations"):
            return orgs
        org = url.split("/api/organizations/")[1].split("/")[0]
        return credits.get(org, (404, None))
    return fetch


def test_the_console_credit_figure_is_read_for_every_organization_the_sign_in_sees():
    today = time.strftime("%Y-%m-%d", time.gmtime())
    values = {**_anthropic_values(), "ANTHROPIC_CONSOLE_SESSION_LIAM": "sessionKey=abc; cf=1"}
    console = _console((200, [{"uuid": "org_main", "name": "NewVisionary"}, {"uuid": "org_ami", "name": "Ami"}]),
                       {"org_main": (200, {"amount": 24757}), "org_ami": (200, {"amount": 20000})})
    rows = balances.readings(values, set(values), fetch=lambda a, k, start=None: (200, _cost({today: 100})), identify=_who,
                             known={}, console=console, entered={"anthropic": balances.entered_record(500, {})})
    main, ami = rows[0], rows[1]
    assert main["balance"] == 247.57 and main["balanceKind"] == "console", "the Console's own figure beats an entered one"
    assert ami["balance"] == 200.0 and ami["status"] == "ready" and ami["issue"] is None
    assert main["usageUsd"] == 1.0, "spend still comes from the cost report"
    assert "undocumented" in main["message"] and "anything the Console can" in main["message"]
    assert "ANTHROPIC_CONSOLE_SESSION_LIAM" in balances.wanted_keys(set(values))


def test_an_ended_or_refused_console_sign_in_is_named_and_never_a_figure():
    values = {"ANTHROPIC_API_KEY": "k-main", "ANTHROPIC_CONSOLE_SESSION_LIAM": "sessionKey=old"}
    gone = balances.readings(values, set(values), fetch=lambda a, k: (401, None), identify=_who, known={},
                             console=_console((401, None), {}))[0]
    assert gone["issue"]["kind"] == "console-expired" and gone["issue"]["action"] == "console-signin"
    blocked = balances.readings(values, set(values), fetch=lambda a, k: (401, None), identify=_who, known={},
                                console=_console((balances.BLOCKED, None), {}))[0]
    assert blocked["issue"]["kind"] == "console-blocked" and blocked.get("balance") is None


def test_a_console_page_that_is_not_json_is_blocked_not_a_balance(monkeypatch):
    class Page:
        status = 200
        def read(self, n): return b"<html>Just a moment...</html>"
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, req, timeout=0: Page())
    assert balances.fetch_console("https://platform.claude.com/api/organizations", "sessionKey=x") == (balances.BLOCKED, None)
    assert balances.parse_console_credits({"amount": "lots"}) is None and balances.parse_console_credits({"amount": 456}) == 4.56


def test_a_console_sign_in_never_leaves_this_machine():
    import passbook_sync

    assert not passbook_sync.may_leave_machine("ANTHROPIC_CONSOLE_SESSION_LIAM")["allowed"]


def test_a_new_sign_in_is_named_after_its_login():
    def fetch(url, cookie, **kw):
        return (200, [{"uuid": "o1", "name": "NewVisionary"}]) if url.endswith("/organizations") else (200, {"email_address": "liam@example.com"})
    found = balances.console_login_name("anthropic", "sessionKey=x", fetch=fetch)
    assert found["key"] == "ANTHROPIC_CONSOLE_SESSION_LIAM_EXAMPLE_COM" and found["orgs"][0]["id"] == "o1"
    assert balances.console_login_name("anthropic", "sessionKey=x", fetch=lambda u, c, **k: (401, None))["ok"] is False
