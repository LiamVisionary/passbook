"""What the balance readings mean over time: how full, how fast it is going, how long it will last.

`passbook_balances.py` asks a provider what an account has left right now. A number alone does not say
whether that is a lot: $40 is plenty on a service that costs $1 a week and an emergency on one that costs
$30 a day. So each live reading is also kept here, numbers only, and turned into the three things a person
running a business on these services looks for (Liam, 2026-10-13: "at a glance visibility so users can see
immediately what's low", "daily, weekly, monthly spend", "% change this month"):

    a meter     what is left against what "full" is: a plan's quota, or for bought credits the balance
                just after the last top-up this computer saw (or the mark you set, or the most it has seen)
    spend       per day, from how the readings moved (or the provider's own daily figures where it has
                them), summed over today, the last 7 days and the last 30, each against the span before
    runway      what is left divided by the recent daily rate

Everything is derived from readings this computer took, so it starts the day Balances was turned on and
says so (`since`, `covered`): a comparison is only made when the earlier span was fully watched, and an
unknown is never a zero. Days are UTC days, because the providers that report daily figures report those.

The files, all in the store's folder and all without a key in them:

    balances-history.jsonl   one line per reading: time, provider, the key's fingerprint, the numbers
    balances-daily.json      a provider's own daily spend, where it reports one (kept past its window)
    balances-marks.json      "full" marks you set by hand
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

HISTORY_FILE = "balances-history.jsonl"
DAILY_FILE = "balances-daily.json"
MARKS_FILE = "balances-marks.json"

DAY = 86400
WINDOW_DAYS = 30
# Below a fifth left, or under a week at the current rate, a service is "low".
LOW_FRACTION = 0.2
LOW_RUNWAY_DAYS = 7
# A reading identical to the one before it is only worth a new line now and then.
SAME_READING_SECONDS = 6 * 3600
KEEP_DAYS = 400
PRUNE_BYTES = 4_000_000
TRAIL_POINTS = 40


def _day(seconds: float) -> int:
    return int(seconds // DAY)


def _date(day: int) -> str:
    return datetime.fromtimestamp(day * DAY, timezone.utc).strftime("%Y-%m-%d")


def _day_of(date: str) -> int | None:
    try:
        return _day(datetime.strptime(date[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, TypeError):
        return None


def _num(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value == value else None


# ── the record ──────────────────────────────────────────────────────────────


def sample_of(row: Mapping[str, Any], now: float) -> dict | None:
    """One live reading as a line of numbers, or None when there is nothing to keep."""
    if row.get("status") != "ready" or not row.get("connection"):
        return None
    allowance = row.get("allowance") or {}
    sample = {"t": int(now), "p": row["providerId"], "c": row["connection"], "b": _num(row.get("balance")),
              "u": row.get("unit"), "s": _num(row.get("usageUsd")), "au": _num(allowance.get("used")),
              "al": _num(allowance.get("limit")), "an": allowance.get("unit")}
    return sample if any(sample[name] is not None for name in ("b", "s", "au")) else None


def _read_lines(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue  # a torn last line from a crash is one lost reading, not a lost history
        if isinstance(row, dict) and isinstance(row.get("t"), (int, float)) and row.get("p"):
            rows.append(row)
    return rows


def load(root: Path) -> dict[str, list[dict]]:
    """Every kept reading, by provider, oldest first."""
    grouped: dict[str, list[dict]] = {}
    for row in _read_lines(Path(root) / HISTORY_FILE):
        grouped.setdefault(str(row["p"]), []).append(row)
    for rows in grouped.values():
        rows.sort(key=lambda row: row["t"])
    return grouped


def append(root: Path, rows: Iterable[Mapping[str, Any]], *, now: Callable[[], float] = time.time) -> int:
    """Keep the readings that were just taken. Returns how many lines were written."""
    path = Path(root) / HISTORY_FILE
    moment = now()
    latest: dict[str, dict] = {}
    existing = _read_lines(path)
    for row in existing:
        latest[str(row["p"])] = row
    fresh = []
    for row in rows:
        sample = sample_of(row, moment)
        if not sample:
            continue
        last = latest.get(sample["p"])
        same = last and all(last.get(name) == sample[name] for name in ("c", "b", "u", "s", "au", "al"))
        if same and moment - last["t"] < SAME_READING_SECONDS:
            continue
        fresh.append(sample)
    if not fresh:
        return 0
    try:
        if path.exists() and path.stat().st_size > PRUNE_BYTES:
            kept = [row for row in existing if moment - row["t"] <= KEEP_DAYS * DAY]
            path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in kept), encoding="utf-8")
        with path.open("a", encoding="utf-8") as handle:
            for sample in fresh:
                handle.write(json.dumps(sample, separators=(",", ":")) + "\n")
    except OSError:
        return 0
    return len(fresh)


def _read_json(path: Path) -> dict:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def marks(root: Path) -> dict[str, float]:
    """The "full" marks set by hand: what a full account is, for a meter to measure against."""
    return {str(name): float(value) for name, value in _read_json(Path(root) / MARKS_FILE).items()
            if _num(value) is not None and value > 0}


def set_mark(root: Path, provider_id: str, amount: float | None) -> dict[str, float]:
    kept = marks(root)
    if amount is None or amount <= 0:
        kept.pop(provider_id, None)
    else:
        kept[provider_id] = float(amount)
    (Path(root) / MARKS_FILE).write_text(json.dumps(kept) + "\n", encoding="utf-8")
    return kept


def daily(root: Path) -> dict[str, dict]:
    """A provider's own daily spend where it reports one: {provider: {"c", "at", "days": {date: amount}}}."""
    return {name: value for name, value in _read_json(Path(root) / DAILY_FILE).items() if isinstance(value, dict)}


def remember_daily(root: Path, provider_id: str, connection: str, days: Mapping[str, float], *,
                   now: Callable[[], float] = time.time) -> None:
    """Merge a provider's latest daily figures over the ones kept, so its window (OpenRouter: 31 days)
    does not become ours. A different key starts again: its days are another account's."""
    kept = daily(root)
    before = kept.get(provider_id) or {}
    merged = dict(before.get("days") or {}) if before.get("c") == connection else {}
    merged.update({date: float(amount) for date, amount in days.items()})
    oldest = _date(_day(now()) - KEEP_DAYS)
    kept[provider_id] = {"c": connection, "at": int(now()), "days": {d: v for d, v in sorted(merged.items()) if d >= oldest}}
    (Path(root) / DAILY_FILE).write_text(json.dumps(kept, separators=(",", ":")) + "\n", encoding="utf-8")


def forget(root: Path) -> None:
    for name in (HISTORY_FILE, DAILY_FILE, MARKS_FILE):
        (Path(root) / name).unlink(missing_ok=True)


# ── what the record says ────────────────────────────────────────────────────


def _moves(samples: list[dict]) -> tuple[str | None, list[tuple[float, float, float]], list[tuple[float, float]]]:
    """How the readings moved: (unit spent in, [(from, to, amount spent)], [(when, amount topped up)]).

    Spend is read from the best thing the provider reports. A usage counter (OpenRouter's all-time usage)
    is exact and survives a top-up; a counter that went down was reset (a new billing month), so what it
    reads now is what was spent since. With only a balance, a fall is spend and a rise is a top-up; spend
    that happened across a top-up is hidden inside the rise, so it is undercounted and never invented.
    """
    if not samples:
        return None, [], []
    last = samples[-1]
    spends: list[tuple[float, float, float]] = []
    topups: list[tuple[float, float]] = []
    counter = "s" if last.get("s") is not None else None if last.get("b") is not None else "au" if last.get("au") is not None else None
    unit = "USD" if counter == "s" else last.get("an") if counter == "au" else last.get("u")
    for before, after in zip(samples, samples[1:]):
        if counter:
            a, b = before.get(counter), after.get(counter)
            if a is None or b is None:
                continue
            spent = b - a if b >= a else b
            if spent > 0:
                spends.append((before["t"], after["t"], spent))
        if after.get("b") is None or before.get("b") is None:
            continue
        rise = after["b"] - before["b"]
        if counter == "s" and before.get("s") is not None and after.get("s") is not None and after["s"] >= before["s"]:
            rise += after["s"] - before["s"]  # what was bought = how far the balance rose + what was used meanwhile
        tolerance = max(0.005, abs(before["b"]) * 0.001)
        if rise > tolerance:
            topups.append((after["t"], rise))
        elif not counter and -rise > 0:
            spends.append((before["t"], after["t"], -rise))
    return unit, spends, topups


def _per_day(spends: list[tuple[float, float, float]]) -> dict[int, float]:
    """Each move spread evenly over the time it took, so two readings a week apart are seven days of spend."""
    days: dict[int, float] = {}
    for start, end, amount in spends:
        if end <= start:
            days[_day(end)] = days.get(_day(end), 0.0) + amount
            continue
        cursor = start
        while cursor < end:
            edge = min(end, (_day(cursor) + 1) * DAY)
            days[_day(cursor)] = days.get(_day(cursor), 0.0) + amount * (edge - cursor) / (end - start)
            cursor = edge
    return days


def _change(now_amount: float, before_amount: float) -> float | None:
    return None if before_amount <= 0 else round((now_amount - before_amount) / before_amount * 100, 1)


def _spend(per_day: Mapping[int, float], watched: Callable[[int], bool], today: int) -> dict:
    total = lambda first, last: sum(per_day.get(day, 0.0) for day in range(first, last + 1))  # noqa: E731
    seen = lambda first, last: all(watched(day) for day in range(first, last + 1))  # noqa: E731
    week, before_week = total(today - 7, today - 1), total(today - 14, today - 8)
    month, before_month = total(today - 30, today - 1), total(today - 60, today - 31)
    return {
        "today": round(per_day.get(today, 0.0), 4), "yesterday": round(per_day.get(today - 1, 0.0), 4) if watched(today - 1) else None,
        "week": round(week, 4), "prevWeek": round(before_week, 4) if seen(today - 14, today - 8) else None,
        "month": round(month, 4), "prevMonth": round(before_month, 4) if seen(today - 60, today - 31) else None,
        "weekChange": _change(week, before_week) if seen(today - 14, today - 1) else None,
        "monthChange": _change(month, before_month) if seen(today - 60, today - 1) else None,
        "weekWatched": seen(today - 7, today - 1), "monthWatched": seen(today - 30, today - 1),
    }


def for_row(row: Mapping[str, Any], samples: list[dict], provided: Mapping[str, Any] | None = None,
            mark: float | None = None, *, now: float | None = None) -> dict:
    """The meter, the spend and the runway for one live reading."""
    moment = time.time() if now is None else now
    today = _day(moment)
    connection = row.get("connection")
    mine = [sample for sample in samples if sample.get("c") == connection]
    unit, spends, topups = _moves(mine)
    per_day = _per_day(spends)
    first_day = _day(mine[0]["t"]) if mine else None
    days_given: set[int] = set()
    if provided and provided.get("c") == connection:
        for date, amount in (provided.get("days") or {}).items():
            day = _day_of(date)
            # The provider's figure for a finished day replaces what was pieced together from readings.
            if day is not None and day < today and _num(amount) is not None:
                per_day[day] = float(amount)
                days_given.add(day)
        if days_given:
            unit = "USD"
    # A day counts as watched when the provider reported it, or readings were being taken before it began.
    watched = lambda day: day in days_given or (first_day is not None and first_day < day <= today)  # noqa: E731

    balance, allowance = _num(row.get("balance")), row.get("allowance") or {}
    meter = None
    if _num(allowance.get("limit")) and _num(allowance.get("used")) is not None:
        limit, used = float(allowance["limit"]), float(allowance["used"])
        meter = {"kind": "quota", "left": max(limit - used, 0.0), "full": limit, "used": used, "unit": allowance.get("unit"),
                 "fraction": round(max(limit - used, 0.0) / limit, 4), "basis": "plan", "resetsAt": allowance.get("resetsAt")}
    elif balance is not None:
        after_top_up = None
        if topups:
            when = topups[-1][0]
            after_top_up = next((sample["b"] for sample in mine if sample["t"] >= when and sample.get("b") is not None), None)
        highest = max([sample["b"] for sample in mine if sample.get("b") is not None] + [balance])
        full, basis = (mark, "set") if mark else (after_top_up, "top-up") if after_top_up else (highest, "highest")
        full = max(full or 0.0, balance)
        meter = {"kind": "balance", "left": balance, "full": full, "unit": row.get("unit"), "basis": basis,
                 "fraction": round(balance / full, 4) if full > 0 else 0.0}

    spend = {"unit": unit, **_spend(per_day, watched, today)} if unit and (spends or days_given) else None
    rate = None
    if spend:
        if spend["weekWatched"]:
            rate = spend["week"] / 7
        else:
            finished = [day for day in range(today - WINDOW_DAYS, today) if watched(day)]
            if finished:
                rate = sum(per_day.get(day, 0.0) for day in finished) / len(finished)
            elif mine and moment - mine[0]["t"] >= DAY / 4:
                rate = sum(amount for _, _, amount in spends) / ((moment - mine[0]["t"]) / DAY)
        spend["perDay"] = round(rate, 4) if rate is not None else None

    runway = None
    if meter and rate and rate > 0 and spend and spend["unit"] == meter["unit"]:
        runway = round(meter["left"] / rate, 1)
    low_why = ""
    # An account that has never been seen with anything in it is empty, not running low: a key for a
    # service you have not paid into yet is not a warning.
    if meter and meter["full"] <= 0:
        meter["empty"] = True
    elif meter and meter["fraction"] < LOW_FRACTION:
        low_why = f"{round(meter['fraction'] * 100)}% left"
    elif runway is not None and runway < LOW_RUNWAY_DAYS:
        resets = _reset_days(meter.get("resetsAt") if meter else None, moment)
        # A quota that refills before it runs out is not running out.
        if resets is None or runway < resets:
            low_why = "under a day left at this rate" if runway < 1 else f"about {round(runway)} days left at this rate"

    earliest = ([first_day] if first_day is not None else []) + ([min(days_given)] if days_given else [])
    trail = [[sample["t"], sample["b"]] for sample in mine if sample.get("b") is not None]
    if len(trail) > TRAIL_POINTS:
        step = len(trail) / TRAIL_POINTS
        trail = [trail[int(index * step)] for index in range(TRAIL_POINTS - 1)] + [trail[-1]]
    return {
        "meter": meter, "spend": spend, "runwayDays": runway, "low": bool(low_why), "lowWhy": low_why,
        "days": [{"d": _date(day), "v": round(per_day.get(day, 0.0), 4), "watched": watched(day)}
                 for day in range(today - WINDOW_DAYS + 1, today + 1)] if spend else [],
        "trail": trail,
        "since": _date(min(earliest)) if earliest else None,
        "lastTopUp": {"at": _date(_day(topups[-1][0])), "amount": round(topups[-1][1], 4)} if topups else None,
    }


def _reset_days(resets_at: Any, moment: float) -> float | None:
    if not isinstance(resets_at, str):
        return None
    try:
        when = datetime.fromisoformat(resets_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    return max((when - moment) / DAY, 0.0)


def summary(rows: Iterable[Mapping[str, Any]], *, now: float | None = None) -> dict:
    """The page's top line: dollars on hand, dollars going out, what is low and what runs out first.

    Only dollars are added together. Credits, characters and emails stay on their own rows: a total of
    unlike things is a number that means nothing.
    """
    today = _day(time.time() if now is None else now)
    live = [row for row in rows if row.get("status") == "ready"]
    cash = [row for row in live if row.get("unit") == "USD" and _num(row.get("balance")) is not None]
    spending = [row["insights"]["spend"] for row in live if (row.get("insights") or {}).get("spend")
                and row["insights"]["spend"]["unit"] == "USD"]
    add = lambda name, among=None: round(sum((spend.get(name) or 0.0) for spend in (spending if among is None else among)), 4)  # noqa: E731
    compared_week = [spend for spend in spending if spend.get("prevWeek") is not None and spend.get("weekWatched")]
    compared_month = [spend for spend in spending if spend.get("prevMonth") is not None and spend.get("monthWatched")]
    days: dict[str, float] = {}
    for row in live:
        insight = row.get("insights") or {}
        if (insight.get("spend") or {}).get("unit") != "USD":
            continue
        for point in insight.get("days") or []:
            days[point["d"]] = days.get(point["d"], 0.0) + point["v"]
    running_out = sorted(((row["insights"]["runwayDays"], row) for row in live
                          if (row.get("insights") or {}).get("runwayDays") is not None
                          and row["insights"]["meter"]["kind"] == "balance"), key=lambda pair: pair[0])
    return {
        "live": len(live),
        "usd": {
            "balance": round(sum(float(row["balance"]) for row in cash), 2), "accounts": len(cash),
            "today": add("today"), "yesterday": add("yesterday"), "week": add("week"), "month": add("month"),
            "perDay": add("perDay"), "tracked": len(spending),
            "weekChange": _change(add("week", compared_week), add("prevWeek", compared_week)) if compared_week else None,
            "monthChange": _change(add("month", compared_month), add("prevMonth", compared_month)) if compared_month else None,
            "days": [{"d": _date(day), "v": round(days.get(_date(day), 0.0), 4)}
                     for day in range(today - WINDOW_DAYS + 1, today + 1)] if spending else [],
        },
        "low": [{"id": row["providerId"], "name": row["name"], "why": row["insights"]["lowWhy"]}
                for row in live if (row.get("insights") or {}).get("low")],
        "nextOut": {"id": running_out[0][1]["providerId"], "name": running_out[0][1]["name"],
                    "days": running_out[0][0]} if running_out else None,
    }
