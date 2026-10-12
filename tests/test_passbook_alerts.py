"""Balance alerts: what is worth a message, said once, through the owner's own bot, without the token leaking."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_alerts as alerts  # noqa: E402

TOKEN = "123456:synthetic-bot-token-never-real"
NOW = 1_800_000_000.0


def _row(pid="fal", name="fal", status="ready", low=False, **fields):
    return {"providerId": pid, "name": name, "status": status, "credentialPresent": True, "balance": 4.0, "unit": "USD",
            "topUpUrl": "https://fal.ai/dashboard/billing", "message": "The provider rejected the key.",
            "insights": {"low": low, "lowWhy": "8% left" if low else "", "meter": {"kind": "balance"}}, **fields}


def _on(tmp_path):
    alerts.configure(tmp_path, key="MY_BOT_TOKEN", chat="-100123")
    return alerts.configure(tmp_path, on=True)


def _collector():
    sent = []
    return sent, lambda token, chat, message: (sent.append((token, chat, dict(message))) or (True, ""))


def test_off_until_a_chat_is_named_and_a_bad_chat_or_key_is_refused(tmp_path):
    assert alerts.settings(tmp_path) == {"on": False, "key": alerts.DEFAULT_KEY, "chat": ""}
    with pytest.raises(ValueError, match="which chat"):
        alerts.configure(tmp_path, on=True)
    for bad in ("", "abc", "12 34", "@x", "https://t.me/x"):
        with pytest.raises(ValueError):
            alerts.configure(tmp_path, chat=bad)
    with pytest.raises(ValueError):
        alerts.configure(tmp_path, key="not a key name")
    assert alerts.configure(tmp_path, chat="@my_channel")["chat"] == "@my_channel"
    assert _on(tmp_path) == {"on": True, "key": "MY_BOT_TOKEN", "chat": "-100123"}


def test_low_is_said_once_with_a_top_up_button_repeated_after_six_hours_and_its_recovery_once(tmp_path):
    _on(tmp_path)
    sent, deliver = _collector()
    clock = [NOW]
    run = lambda row: alerts.run(tmp_path, [row], TOKEN, now=lambda: clock[0], deliver=deliver)  # noqa: E731
    assert run(_row(low=False))["sent"] == 0, "fine is not news"
    assert run(_row(low=True))["sent"] == 1
    token, chat, message = sent[-1]
    assert (token, chat) == (TOKEN, "-100123")
    assert message["severity"] == "warning" and message["title"] == "fal is running low"
    assert message["body"] == "fal has $4.00 left (8% left)."
    assert message["action"] == {"label": "Top up fal", "url": "https://fal.ai/dashboard/billing"}
    clock[0] += 3600
    assert run(_row(low=True))["sent"] == 0, "still low an hour later is the same news"
    clock[0] += alerts.REPEAT_SECONDS
    assert run(_row(low=True))["sent"] == 1, "still low six hours on is worth saying again"
    assert run(_row(low=False, balance=54.0))["sent"] == 1
    assert sent[-1][2]["severity"] == "recovery" and sent[-1][2]["title"] == "fal is no longer low"
    assert sent[-1][2]["body"] == "fal has $54.00 left." and sent[-1][2]["action"] is None
    assert run(_row(low=False))["sent"] == 0, "recovered is said once"


def test_a_reading_that_fails_once_is_not_news_and_twice_is(tmp_path):
    _on(tmp_path)
    sent, deliver = _collector()
    run = lambda row: alerts.run(tmp_path, [row], TOKEN, now=lambda: NOW, deliver=deliver)  # noqa: E731
    failing = _row(status="error", insights=None)
    assert run(failing)["sent"] == 0, "one timeout"
    assert run(_row())["sent"] == 0, "and it came back: nothing was said, so nothing is taken back"
    assert run(failing)["sent"] == 0
    assert run(failing)["sent"] == 1
    assert sent[-1][2]["severity"] == "error" and sent[-1][2]["title"] == "fal's balance could not be read"
    assert "No balance is assumed" in sent[-1][2]["body"]
    assert run(_row())["sent"] == 1 and sent[-1][2]["title"] == "fal's balance can be read again"


def test_a_message_that_did_not_go_is_tried_again_and_never_recorded_as_said(tmp_path):
    _on(tmp_path)
    attempts = []
    failing = lambda token, chat, message: (attempts.append(1) or (False, "Telegram could not be reached."))  # noqa: E731
    told = alerts.run(tmp_path, [_row(low=True)], TOKEN, now=lambda: NOW, deliver=failing)
    assert told == {"on": True, "sent": 0, "failed": 1, "error": "Telegram could not be reached."}
    sent, deliver = _collector()
    assert alerts.run(tmp_path, [_row(low=True)], TOKEN, now=lambda: NOW + 60, deliver=deliver)["sent"] == 1


def test_nothing_is_asked_of_a_service_with_no_key_or_no_reader_and_nothing_is_sent_while_off(tmp_path):
    quiet = [_row(status="manual"), _row(status="missing"), {**_row(status="error"), "credentialPresent": False}]
    assert alerts.conditions(quiet) == []
    sent, deliver = _collector()
    assert alerts.run(tmp_path, [_row(low=True)], TOKEN, deliver=deliver) == {"on": False, "sent": 0, "failed": 0, "error": ""}
    _on(tmp_path)
    assert "could not be read here" in alerts.run(tmp_path, [_row(low=True)], "hive-sealed:v1:abc", deliver=deliver)["error"]
    assert sent == []


def test_the_message_is_said_the_way_the_hosted_alerts_are_and_the_token_goes_nowhere_but_the_address(tmp_path):
    calls = []
    def call(token, method, payload=None, timeout=15.0):
        calls.append((token, method, payload))
        return True, {"message_id": 1}
    ok, why = alerts.send(TOKEN, "-100123", {"severity": "warning", "title": "fal is running low", "body": "fal has $4.00 left (8% left).",
                                             "action": {"label": "Top up fal", "url": "https://fal.ai/billing"}}, call=call)
    assert ok and why == ""
    token, method, payload = calls[0]
    assert method == "sendMessage" and payload["chat_id"] == "-100123"
    assert payload["text"] == "⚠️ fal is running low\n\nfal has $4.00 left (8% left)."
    assert payload["reply_markup"] == {"inline_keyboard": [[{"text": "Top up fal", "url": "https://fal.ai/billing"}]]}
    assert payload["link_preview_options"] == {"is_disabled": True}
    assert TOKEN not in str(payload)
    alerts.send(TOKEN, "1", {"severity": "info", "title": "t", "body": "b", "action": {"label": "x", "url": "http://insecure"}}, call=call)
    assert "reply_markup" not in calls[-1][2], "a button only ever opens an https page"
    _on(tmp_path)
    alerts.run(tmp_path, [_row(low=True)], TOKEN, now=lambda: NOW, deliver=lambda t, c, m: (True, ""))
    assert TOKEN not in (tmp_path / alerts.ALERTS_FILE).read_text()


def test_a_refusal_never_repeats_the_token(monkeypatch):
    import io
    import urllib.error

    def refuse(request, timeout=0):
        assert request.full_url.startswith("https://api.telegram.org/bot")
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"ok":false,"description":"Unauthorized"}'))
    monkeypatch.setattr(alerts.urllib.request, "urlopen", refuse)
    ok, why = alerts._call(TOKEN, "sendMessage", {"chat_id": "1", "text": "x"})
    assert not ok and TOKEN not in why and "bot token" in why

    def offline(request, timeout=0):
        raise OSError(f"could not connect to {request.full_url}")
    monkeypatch.setattr(alerts.urllib.request, "urlopen", offline)
    ok, why = alerts._call(TOKEN, "sendMessage", {})
    assert not ok and why == "Telegram could not be reached." and TOKEN not in why


def test_finding_a_chat_lists_who_wrote_to_the_bot():
    updates = [{"message": {"chat": {"id": 42, "first_name": "Liam", "type": "private"}}},
               {"message": {"chat": {"id": 42, "first_name": "Liam", "type": "private"}}},
               {"channel_post": {"chat": {"id": -1001, "title": "Ops", "type": "channel"}}}, {"other": 1}]
    found, why = alerts.chats(TOKEN, call=lambda token, method, payload=None: (True, updates))
    assert why == "" and found == [{"id": "42", "name": "Liam", "kind": "private"}, {"id": "-1001", "name": "Ops", "kind": "channel"}]
    assert alerts.chats(TOKEN, call=lambda *a, **k: (False, "Telegram could not be reached.")) == ([], "Telegram could not be reached.")
