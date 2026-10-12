"""Meters, spend and runway are sums a person will run a business on, so the sums are pinned.

Every case names the claim it protects: an unknown is never a zero, a comparison is only made
against a span that was watched, a top-up is not negative spend, and only dollars are added up.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_insights as insights  # noqa: E402

DAY = insights.DAY
NOW = 20_000 * DAY + DAY / 2  # noon UTC on some day
TODAY = insights._day(NOW)


def _row(**fields):
    return {"providerId": "openrouter", "name": "OpenRouter", "status": "ready", "connection": "c1", "unit": "USD",
            "balance": None, "usageUsd": None, "allowance": None, **fields}


def _sample(days_ago, **fields):
    return {"t": int(NOW - days_ago * DAY), "p": "openrouter", "c": "c1", "b": None, "u": "USD", "s": None,
            "au": None, "al": None, "an": None, **fields}


def test_a_first_reading_is_full_and_claims_no_spend():
    got = insights.for_row(_row(balance=134.0), [_sample(0, b=134.0)], now=NOW)
    assert got["meter"] == {"kind": "balance", "left": 134.0, "full": 134.0, "unit": "USD", "basis": "highest", "fraction": 1.0}
    assert got["spend"] is None and got["runwayDays"] is None and got["low"] is False, "nothing is known yet, so nothing is said"


def test_a_falling_balance_is_spend_spread_over_the_days_it_took():
    samples = [_sample(10.5, b=200.0), _sample(0.5, b=100.0), _sample(0, b=95.0)]
    got = insights.for_row(_row(balance=95.0), samples, now=NOW)
    assert got["meter"]["fraction"] == pytest.approx(0.475) and got["meter"]["basis"] == "highest"
    spend = got["spend"]
    assert spend["unit"] == "USD"
    assert spend["today"] == pytest.approx(5.0), "the fall since midnight"
    assert spend["yesterday"] == pytest.approx(10.0) and spend["week"] == pytest.approx(70.0)
    assert spend["weekChange"] is None, "the week before was not fully watched, so there is no comparison"
    assert got["runwayDays"] == pytest.approx(9.5), "95 left at 10 a day"
    assert got["low"] is False


def test_low_is_a_fifth_left_or_under_a_week_at_this_rate():
    nearly_empty = insights.for_row(_row(balance=10.0), [_sample(40, b=100.0), _sample(0, b=10.0)], now=NOW)
    assert nearly_empty["low"] and nearly_empty["lowWhy"] == "10% left"
    burning = insights.for_row(_row(balance=60.0), [_sample(8.5, b=162.0), _sample(0.5, b=66.0), _sample(0, b=60.0)], now=NOW)
    assert burning["meter"]["fraction"] > insights.LOW_FRACTION
    assert burning["low"] and burning["lowWhy"] == "about 5 days left at this rate"


def test_a_top_up_is_the_new_full_mark_and_never_negative_spend():
    samples = [_sample(5, b=20.0), _sample(4, b=10.0), _sample(3, b=110.0), _sample(0, b=80.0)]
    got = insights.for_row(_row(balance=80.0), samples, now=NOW)
    assert got["lastTopUp"]["amount"] == pytest.approx(100.0)
    assert got["meter"]["basis"] == "top-up" and got["meter"]["full"] == 110.0, "full is the balance just after the top-up"
    assert got["spend"]["month"] + got["spend"]["today"] == pytest.approx(40.0), "10 before and 30 after; the top-up adds nothing"


def test_a_mark_you_set_is_what_full_means_until_the_balance_passes_it():
    samples = [_sample(1, b=134.0)]
    assert insights.for_row(_row(balance=134.0), samples, mark=200.0, now=NOW)["meter"] == {
        "kind": "balance", "left": 134.0, "full": 200.0, "unit": "USD", "basis": "set", "fraction": 0.67}
    assert insights.for_row(_row(balance=250.0), samples, mark=200.0, now=NOW)["meter"]["full"] == 250.0


def test_a_usage_counter_is_exact_across_a_top_up_and_says_what_was_bought():
    # OpenRouter: balance = credits - usage. Usage rose 30 while the balance rose 70: 100 was bought.
    samples = [_sample(3, b=20.0, s=800.0), _sample(1, b=90.0, s=830.0), _sample(0, b=88.0, s=832.0)]
    got = insights.for_row(_row(balance=88.0, usageUsd=832.0), samples, now=NOW)
    assert got["lastTopUp"]["amount"] == pytest.approx(100.0)
    assert got["spend"]["today"] + got["spend"]["month"] == pytest.approx(32.0), "spend hidden by the top-up is still counted"


def test_a_counter_that_went_down_was_reset_and_reads_as_spend_since():
    # Apify reports usage for the billing month; a new month starts it again.
    samples = [_sample(3, s=21.0), _sample(1, s=2.0), _sample(0, s=2.5)]
    got = insights.for_row(_row(usageUsd=2.5), samples, now=NOW)
    assert got["meter"] is None, "usage alone is not something that runs out"
    assert got["spend"]["today"] + got["spend"]["month"] == pytest.approx(2.5)


def test_a_quota_is_measured_against_its_limit_and_one_that_refills_first_is_not_low():
    reset = insights._date(TODAY + 2) + "T00:00:00Z"
    row = _row(unit=None, allowance={"used": 90_000, "limit": 300_000, "unit": "characters", "resetsAt": reset})
    samples = [_sample(8.5, au=20_000, al=300_000, an="characters"), _sample(0.5, au=85_000, al=300_000, an="characters"),
               _sample(0, au=90_000, al=300_000, an="characters")]
    got = insights.for_row(row, samples, now=NOW)
    assert got["meter"]["kind"] == "quota" and got["meter"]["fraction"] == 0.7 and got["meter"]["used"] == 90_000
    assert got["spend"]["unit"] == "characters"
    assert got["low"] is False
    over = insights.for_row(_row(unit=None, allowance={"used": 11_000, "limit": 10_000, "unit": "characters", "resetsAt": None}), [], now=NOW)
    assert over["meter"]["left"] == 0 and over["low"] and over["lowWhy"] == "0% left"


def test_a_providers_own_daily_figures_replace_the_pieced_together_ones_and_allow_a_comparison():
    provided = {"c": "c1", "days": {insights._date(TODAY - back): 4.0 if back <= 7 else 2.0 for back in range(1, 61)}}
    provided["days"][insights._date(TODAY)] = 99.0  # an unfinished day is not taken from the provider
    got = insights.for_row(_row(balance=40.0, usageUsd=500.0), [_sample(0, b=40.0, s=500.0)], provided, now=NOW)
    spend = got["spend"]
    assert spend["week"] == pytest.approx(28.0) and spend["prevWeek"] == pytest.approx(14.0) and spend["weekChange"] == 100.0
    assert spend["month"] == pytest.approx(7 * 4 + 23 * 2) and spend["monthChange"] == pytest.approx(23.3)
    assert spend["today"] == 0.0 and got["days"][-1]["v"] == 0.0
    assert got["runwayDays"] == pytest.approx(10.0)
    assert got["since"] == insights._date(TODAY - 60)
    other_key = insights.for_row(_row(balance=40.0, connection="c2"), [], provided, now=NOW)
    assert other_key["spend"] is None, "another key's days are another account's"


def test_a_rotated_key_starts_its_history_again():
    samples = [_sample(5, b=500.0), {**_sample(1, b=50.0), "c": "c2"}, {**_sample(0, b=45.0), "c": "c2"}]
    got = insights.for_row(_row(balance=45.0, connection="c2"), samples, now=NOW)
    assert got["meter"]["full"] == 50.0 and got["spend"]["today"] + got["spend"]["month"] == pytest.approx(5.0)


def test_only_dollars_are_added_together():
    def live(pid, name, **fields):
        row = {**_row(**fields), "providerId": pid, "name": name}
        return row
    usd = live("openrouter", "OpenRouter", balance=95.0)
    usd["insights"] = insights.for_row(usd, [_sample(10.5, b=200.0), _sample(0.5, b=100.0), _sample(0, b=95.0)], now=NOW)
    credits = live("meshy", "Meshy", balance=10.0, unit="credits")
    credits["insights"] = insights.for_row(credits, [{**_sample(40, b=100.0), "u": "credits"}, {**_sample(0, b=10.0), "u": "credits"}], now=NOW)
    broken = {"providerId": "fal", "name": "fal", "status": "error"}
    said = insights.summary([usd, credits, broken], now=NOW)
    assert said["live"] == 2 and said["usd"]["balance"] == 95.0 and said["usd"]["accounts"] == 1
    assert said["usd"]["week"] == pytest.approx(70.0) and said["usd"]["today"] == pytest.approx(5.0)
    assert said["usd"]["weekChange"] is None
    assert [low["id"] for low in said["low"]] == ["meshy"]
    assert said["nextOut"]["id"] == "meshy" or said["nextOut"]["id"] == "openrouter"
    assert len(said["usd"]["days"]) == insights.WINDOW_DAYS and said["usd"]["days"][-1]["v"] == pytest.approx(5.0)


def test_the_history_holds_numbers_only_and_skips_a_reading_that_changed_nothing(tmp_path):
    clock = [NOW]
    row = {**_row(balance=95.0, usageUsd=10.0), "keyName": "OPENROUTER_MANAGEMENT_KEY", "message": "words", "accountLabel": "liam"}
    assert insights.append(tmp_path, [row, {"providerId": "fal", "status": "error"}], now=lambda: clock[0]) == 1
    clock[0] += 600
    assert insights.append(tmp_path, [row], now=lambda: clock[0]) == 0, "the same numbers ten minutes later"
    clock[0] += 600
    assert insights.append(tmp_path, [{**row, "balance": 94.0}], now=lambda: clock[0]) == 1
    clock[0] += insights.SAME_READING_SECONDS + 1
    assert insights.append(tmp_path, [{**row, "balance": 94.0}], now=lambda: clock[0]) == 1, "unchanged, but long enough ago to mark the time"
    text = (tmp_path / insights.HISTORY_FILE).read_text()
    assert "OPENROUTER" not in text and "liam" not in text and "words" not in text
    (tmp_path / insights.HISTORY_FILE).write_text(text + '{"t": 1, "p": "torn', encoding="utf-8")
    assert [sample["b"] for sample in insights.load(tmp_path)["openrouter"]] == [95.0, 94.0, 94.0], "a torn line loses one reading"


def test_marks_and_daily_figures_are_kept_and_forgotten(tmp_path):
    assert insights.set_mark(tmp_path, "openrouter", 200) == {"openrouter": 200.0}
    assert insights.set_mark(tmp_path, "openrouter", None) == {}
    insights.set_mark(tmp_path, "fal", 50)
    insights.remember_daily(tmp_path, "openrouter", "c1", {"2024-10-01": 1.5}, now=lambda: NOW)
    insights.remember_daily(tmp_path, "openrouter", "c1", {"2024-10-02": 2.5}, now=lambda: NOW)
    assert insights.daily(tmp_path)["openrouter"]["days"] == {"2024-10-01": 1.5, "2024-10-02": 2.5}, "kept past the provider's window"
    insights.remember_daily(tmp_path, "openrouter", "c2", {"2024-10-03": 9.0}, now=lambda: NOW)
    assert insights.daily(tmp_path)["openrouter"]["days"] == {"2024-10-03": 9.0}, "a new key starts again"
    insights.forget(tmp_path)
    assert insights.marks(tmp_path) == {} and insights.daily(tmp_path) == {} and insights.load(tmp_path) == {}
    json.dumps(insights.for_row(_row(balance=1.0), [], now=NOW))
