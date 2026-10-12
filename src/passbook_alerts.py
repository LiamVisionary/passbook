"""A message when a balance runs low, cannot be read, or recovers. Telegram, with your own bot.

The Balances page says what is low when somebody looks at it. This says it when nobody is looking
(Liam, 2026-10-13: "I also get telegram messages for balances, wire that into this too in a generic way so
users can supply their own telegram bot access token and get the same kinds of alerts I get"). The alerts
he gets come from HivemindOS's hosted supplier monitor; these are the same kinds, said the same way:

    warning   "fal is running low"            when a service is low (passbook_insights: under a fifth left,
              a "Top up fal" button            or under a week at the recent rate)
    error     "Vultr's balance could not      when a reading fails twice running: a rejected key, a refusal,
              be read"                         no answer. Once is not news; providers time out.
    recovery  "fal is no longer low"          when either clears, once, and only if the alert was sent

While something stays wrong the alert repeats every six hours, not on every reading.

The bot is yours. Its token is a key in this store like any other (PassBook never has one of its own, and
nothing goes through anybody's server but Telegram's): make a bot with @BotFather, save its token, say
which chat. The token is read through the store the way the provider keys are, recorded as "send balance
alerts", and travels only in the address of a request to api.telegram.org, which is where Telegram puts
it. It is never in a message, an error, or the state kept here.

`balances-alerts.json` holds the settings (on, which key, which chat) and which conditions are active and
when each was last sent. No token, no balances.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

ALERTS_FILE = "balances-alerts.json"
DEFAULT_KEY = "PASSBOOK_TELEGRAM_BOT_TOKEN"
REPEAT_SECONDS = 6 * 3600
REASON = "send balance alerts"
API = "https://api.telegram.org"
MARKS = {"info": "ℹ️", "warning": "⚠️", "error": "\U0001f6a8", "recovery": "✅"}

_CHAT = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def valid_chat(chat: str) -> bool:
    """A numeric chat or group id, or a public channel's @name: what Telegram accepts as `chat_id`."""
    return bool(_CHAT.match(str(chat or "").strip()))


# ── settings and state ──────────────────────────────────────────────────────


def _load(root: Path) -> dict:
    try:
        loaded = json.loads((Path(root) / ALERTS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _save(root: Path, record: Mapping[str, Any]) -> None:
    (Path(root) / ALERTS_FILE).write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")


def settings(root: Path) -> dict:
    kept = _load(root).get("telegram")
    kept = kept if isinstance(kept, dict) else {}
    key, chat = str(kept.get("key") or DEFAULT_KEY), str(kept.get("chat") or "")
    return {"on": bool(kept.get("on")) and valid_chat(chat), "key": key if _KEY.match(key) else DEFAULT_KEY,
            "chat": chat if valid_chat(chat) else ""}


def configure(root: Path, *, on: bool | None = None, key: str | None = None, chat: str | None = None) -> dict:
    """Change where alerts go or whether they do. Raises ValueError on a chat or key name it cannot use."""
    record = _load(root)
    now = settings(root)
    if key is not None:
        if not _KEY.match(key.strip()):
            raise ValueError("Name the key that holds the bot's token, like PASSBOOK_TELEGRAM_BOT_TOKEN.")
        now["key"] = key.strip()
    if chat is not None:
        if not valid_chat(chat):
            raise ValueError("A chat is a number (your own, or a group's) or a public channel's @name.")
        now["chat"] = chat.strip()
    if on is not None:
        if on and not now["chat"]:
            raise ValueError("Say which chat the alerts go to first.")
        now["on"] = bool(on)
        if not on:
            record.pop("state", None)  # turned back on later, what is wrong then is said afresh
    record["telegram"] = now
    _save(root, record)
    return settings(root)


def forget(root: Path) -> None:
    (Path(root) / ALERTS_FILE).unlink(missing_ok=True)


# ── what is worth a message ─────────────────────────────────────────────────


def _left(row: Mapping[str, Any]) -> str:
    meter = (row.get("insights") or {}).get("meter") or {}
    if row.get("balance") is not None:
        amount, unit = float(row["balance"]), row.get("unit") or ""
        return f"${amount:,.2f}" if unit == "USD" else f"{amount:,.2f} {unit}".strip()
    if meter.get("kind") == "quota":
        return f"{float(meter['left']):,.0f} {meter.get('unit') or ''}".strip()
    return "little"


def conditions(rows: Iterable[Mapping[str, Any]]) -> list[dict]:
    """Every condition worth watching for the rows just read, active or not (a clear one ends an alert)."""
    found = []
    for row in rows:
        if not row.get("credentialPresent") or row.get("status") not in ("ready", "error"):
            continue  # nothing was asked of this provider, so nothing is known either way
        name, live = row["name"], row.get("status") == "ready"
        insight = row.get("insights") or {}
        action = {"label": f"Top up {name}", "url": row["topUpUrl"]} if str(row.get("topUpUrl") or "").startswith("https://") else None
        if live:
            found.append({
                "id": f"{row['providerId']}:low", "active": bool(insight.get("low")), "severity": "warning",
                "title": f"{name} is running low",
                "body": f"{name} has {_left(row)} left ({insight.get('lowWhy') or 'low'}).",
                "recoveryTitle": f"{name} is no longer low", "recoveryBody": f"{name} has {_left(row)} left.",
                "action": action, "confirm": False,
            })
        found.append({
            "id": f"{row['providerId']}:read", "active": not live, "severity": "error",
            "title": f"{name}'s balance could not be read",
            "body": f"{row.get('message') or 'The provider did not answer.'} No balance is assumed until it can be read again.",
            "recoveryTitle": f"{name}'s balance can be read again", "recoveryBody": f"{name} is answering: {_left(row)} left." if live else "",
            "action": {"label": f"Open {name}", "url": row["topUpUrl"]} if action else None,
            # One failed reading is a timeout; two running is something to look at.
            "confirm": True,
        })
    return found


def due(state: Mapping[str, Any], found: Iterable[Mapping[str, Any]], now: float) -> tuple[list[tuple[str, dict]], dict]:
    """(what to send as [(condition id, message)], the state if nothing is sent).

    The state is only advanced for a message by `settle`, once it has really gone: a failed send is tried
    again on the next reading instead of being recorded as said.
    """
    sends: list[tuple[str, dict]] = []
    after = {name: dict(value) for name, value in state.items() if isinstance(value, dict)}
    for condition in found:
        cid, kept = condition["id"], after.get(condition["id"]) or {}
        if condition["active"]:
            if condition.get("confirm") and not kept.get("seen") and not kept.get("active"):
                after[cid] = {"seen": int(now)}
                continue
            last = kept.get("notifiedAt")
            if not kept.get("active") or last is None or now - float(last) >= REPEAT_SECONDS:
                sends.append((cid, {"severity": condition["severity"], "title": condition["title"],
                                    "body": condition["body"], "action": condition.get("action")}))
            after[cid] = {**kept, "seen": kept.get("seen") or int(now)}
        else:
            if kept.get("active") and kept.get("notifiedAt") is not None:
                sends.append((cid, {"severity": "recovery", "title": condition["recoveryTitle"],
                                    "body": condition["recoveryBody"], "action": None, "clears": True}))
            else:
                after.pop(cid, None)
    return sends, after


def settle(state: dict, cid: str, message: Mapping[str, Any], sent: bool, now: float) -> None:
    if not sent:
        return
    if message.get("clears"):
        state.pop(cid, None)
    else:
        state[cid] = {**(state.get(cid) or {}), "active": True, "notifiedAt": int(now)}


# ── telegram ────────────────────────────────────────────────────────────────


def _call(token: str, method: str, payload: Mapping[str, Any] | None = None, *, timeout: float = 15.0) -> tuple[bool, Any]:
    """(ok, result or a plain reason). The reason never holds the token: nothing built from the address
    or from an exception's own text is returned, only Telegram's description or a status."""
    request = urllib.request.Request(f"{API}/bot{token}/{method}", method="POST",
                                     data=json.dumps(payload or {}).encode("utf-8"),
                                     headers={"Content-Type": "application/json", "User-Agent": "passbook-alerts"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 — https, a fixed host
            answer = json.loads(response.read(1_000_000).decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            described = json.loads(error.read(100_000).decode("utf-8")).get("description")
        except Exception:  # noqa: BLE001
            described = None
        finally:
            error.close()
        if error.code in (401, 404):
            return False, "Telegram does not know this bot token. Check the key holds the whole token from @BotFather."
        return False, str(described or f"Telegram answered {error.code}.")[:300]
    except Exception:  # noqa: BLE001 — offline, a timeout, an odd answer
        return False, "Telegram could not be reached."
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        return False, str((answer or {}).get("description") or "Telegram refused the request.")[:300]
    return True, answer.get("result")


def text_of(message: Mapping[str, Any]) -> str:
    return f"{MARKS.get(str(message.get('severity')), '')} {message['title']}\n\n{message['body']}".strip()


def send(token: str, chat: str, message: Mapping[str, Any], *, call: Callable[..., tuple[bool, Any]] = _call) -> tuple[bool, str]:
    payload: dict[str, Any] = {"chat_id": chat, "text": text_of(message), "link_preview_options": {"is_disabled": True}}
    action = message.get("action")
    if action and str(action.get("url") or "").startswith("https://"):
        payload["reply_markup"] = {"inline_keyboard": [[{"text": action["label"], "url": action["url"]}]]}
    ok, result = call(token, "sendMessage", payload)
    return ok, "" if ok else str(result)


def chats(token: str, *, call: Callable[..., tuple[bool, Any]] = _call) -> tuple[list[dict], str]:
    """The chats that have written to the bot lately, so nobody has to hunt for a chat id.

    Telegram only tells a bot about chats that spoke to it: message the bot (or add it to the group and
    say something), then ask. Returns ([{id, name, kind}], "" or why it could not be asked).
    """
    ok, result = call(token, "getUpdates", {"limit": 100, "timeout": 0, "allowed_updates": ["message", "channel_post", "my_chat_member"]})
    if not ok:
        return [], str(result)
    seen: dict[str, dict] = {}
    for update in result if isinstance(result, list) else []:
        for part in ("message", "channel_post", "my_chat_member", "edited_message"):
            chat = ((update or {}).get(part) or {}).get("chat") if isinstance(update, dict) else None
            if not isinstance(chat, dict) or chat.get("id") is None:
                continue
            name = chat.get("title") or " ".join(x for x in (chat.get("first_name"), chat.get("last_name")) if x) or chat.get("username") or "A chat"
            seen[str(chat["id"])] = {"id": str(chat["id"]), "name": str(name)[:80], "kind": str(chat.get("type") or "")}
    return list(seen.values()), ""


TEST = {"severity": "info", "title": "PassBook balance alerts are on",
        "body": "You will get a message here when a service runs low, when a balance cannot be read, and when either recovers."}


def run(root: Path, rows: Iterable[Mapping[str, Any]], token: str, *, now: Callable[[], float] = time.time,
        deliver: Callable[[str, str, Mapping[str, Any]], tuple[bool, str]] = send) -> dict:
    """Send what the readings just taken call for. Returns {"on", "sent", "failed", "error"}."""
    config = settings(root)
    if not config["on"]:
        return {"on": False, "sent": 0, "failed": 0, "error": ""}
    if not token or token.startswith("hive-sealed:"):
        return {"on": True, "sent": 0, "failed": 0, "error": f"The bot token ({config['key']}) could not be read here."}
    record = _load(root)
    moment = now()
    sends, state = due(record.get("state") if isinstance(record.get("state"), dict) else {}, conditions(rows), moment)
    sent = failed = 0
    error = ""
    for cid, message in sends:
        ok, why = deliver(token, config["chat"], message)
        settle(state, cid, message, ok, moment)
        sent, failed, error = sent + int(ok), failed + int(not ok), error or why
    record["state"] = state
    _save(root, record)
    return {"on": True, "sent": sent, "failed": failed, "error": error}
