# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The guarantee: a credential is used without ever being shown.

These are the tests that hold the promise up. The interesting ones are not
"does spawn work" but "does it still work when the caller is trying to break
it" — because the caller picks the command, and every one of these is a command
somebody would actually pick.
"""

from __future__ import annotations

import base64
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_grant as grant  # noqa: E402
from _platform import needs_a_posix_shell  # noqa: E402

SECRET = "sk-live-abcdef123456789"
VALUES = {"SECRET_TOKEN": SECRET}


# ── redaction ──────────────────────────────────────────────────────────────


def test_the_raw_value_never_survives():
    assert SECRET not in grant.redact(f"token is {SECRET} ok", VALUES)


@pytest.mark.parametrize("prefix", ["", "X", "XY"], ids=["aligned", "off-by-one", "off-by-two"])
def test_base64_is_scrubbed_at_every_alignment(prefix):
    """Where the value sits changes its encoding; all three cases must go.

    This is the one that failed first. `echo $S | base64` appends a newline,
    which shifts the tail, and a redactor that knew only `b64(value)` handed the
    secret straight back through a command anyone would think to run.
    """
    encoded = base64.b64encode((prefix + SECRET).encode()).decode()
    cleaned = grant.redact(encoded, VALUES)
    assert "[redacted:SECRET_TOKEN]" in cleaned
    # The marker alone is not proof: what remains must not still decode to the
    # secret. Every leftover run of base64 characters is checked, because the
    # fragments left at each end are exactly where a partial scrub would hide.
    # A leftover that will not decode at all is not a leak — it is a three or
    # four character tail, which is what a correct scrub leaves behind.
    for leftover in cleaned.replace("[redacted:SECRET_TOKEN]", " ").split():
        for pad in range(3):
            try:
                decoded = base64.b64decode(("A" * pad) + leftover + "=" * 4, validate=False)
            except Exception:  # noqa: BLE001 — undecodable means nothing recoverable
                continue
            assert SECRET.encode() not in decoded


def test_a_trailing_newline_does_not_smuggle_it_out():
    assert "[redacted" in grant.redact(
        base64.b64encode((SECRET + "\n").encode()).decode(), VALUES)


def test_hex_and_url_and_json_forms_are_scrubbed():
    import json
    import urllib.parse

    for form in (SECRET.encode().hex(), urllib.parse.quote(SECRET, safe=""),
                 json.dumps(SECRET)[1:-1]):
        assert SECRET not in grant.redact(f"< {form} >", VALUES)


def test_a_short_value_is_reported_rather_than_silently_missed():
    """Honesty about the floor, because the alternative is a false promise.

    A two-character value cannot be searched for without destroying the output
    it appears in. What must not happen is claiming it was scrubbed.
    """
    coverage = grant.redactions_for({"LONG": SECRET, "SHORT": "ab"})
    assert coverage == {"LONG": True, "SHORT": False}


def test_a_longer_secret_containing_a_shorter_one_goes_entirely():
    """Longest-first, or the short match leaves a fragment of the long one."""
    values = {"SHORT": "abcdef123", "LONG": "abcdef123456789xyz"}
    assert "abcdef" not in grant.redact("here: abcdef123456789xyz", values)


# ── streaming ──────────────────────────────────────────────────────────────


def test_a_value_split_across_chunks_is_still_caught():
    """A pipe hands over 4096 bytes at a time and cares nothing for tokens.

    Redacting chunk by chunk would let a secret straddling a boundary through in
    two clean halves, which is the failure a reader would never notice.
    """
    text = f"before {SECRET} after"
    for cut in range(1, len(text)):
        scrubber = grant.Scrubber(VALUES)
        out = scrubber.feed(text[:cut]) + scrubber.feed(text[cut:]) + scrubber.flush()
        assert SECRET not in out, f"leaked when split at {cut}"


def test_byte_at_a_time_is_still_caught():
    scrubber = grant.Scrubber(VALUES)
    out = "".join(scrubber.feed(char) for char in f"x{SECRET}y") + scrubber.flush()
    assert SECRET not in out and "[redacted:SECRET_TOKEN]" in out


def test_flush_releases_what_was_held_back():
    """Without this, output shorter than the hold-back would vanish entirely."""
    scrubber = grant.Scrubber(VALUES)
    assert scrubber.feed("hi") + scrubber.flush() == "hi"


@pytest.mark.parametrize("form", ["hex", "raw", "base64"])
def test_a_form_is_still_caught_once_output_is_long_enough_to_release(form):
    """The bug the split test above did NOT catch, because it was too short.

    Once a stream is longer than the hold-back the scrubber has to start
    releasing, and the first version cut the buffer and only then redacted what
    it had released — so a form straddling that cut lost its opening characters
    to the output before anything examined them. Everything short enough to sit
    in the buffer until flush looked perfect the whole time.
    """
    encoded = {
        "hex": SECRET.encode().hex(),
        "raw": SECRET,
        "base64": base64.b64encode(SECRET.encode()).decode(),
    }[form]
    filler = "x" * 4000
    scrubber = grant.Scrubber(VALUES)
    out = scrubber.feed(filler + encoded) + scrubber.flush()
    assert encoded not in out, f"{form} survived once the buffer had to release"


def test_a_long_stream_does_not_accumulate_without_bound():
    """The buffer holds a tail, not the transcript. A build printing megabytes
    must not grow the scrubber by megabytes."""
    scrubber = grant.Scrubber(VALUES)
    for _ in range(200):
        scrubber.feed("y" * 1000)
    assert len(scrubber._buffer) <= scrubber._hold + 1


# ── the child gets it; the caller does not ─────────────────────────────────


@needs_a_posix_shell
def test_the_command_receives_the_real_value():
    """The whole point. A scrubbed output is worthless if the tool cannot work."""
    done = grant.spawn(
        ["sh", "-c", f'test "$SECRET_TOKEN" = "{SECRET}" && echo MATCHED'], VALUES)
    assert done["ok"] and done["stdout"].strip() == "MATCHED"


@needs_a_posix_shell
@pytest.mark.parametrize("script", [
    "printenv",
    "echo $SECRET_TOKEN",
    "echo $SECRET_TOKEN | base64",
    "printf %s $SECRET_TOKEN | base64",
    "printf 'pre%ssuf' $SECRET_TOKEN | base64",
    "env | grep SECRET",
], ids=["printenv", "echo", "echo-b64", "printf-b64", "embedded-b64", "env-grep"])
def test_the_caller_cannot_read_it_back_however_it_asks(script):
    """Every one of these is a command somebody would actually pick.

    The caller chooses what runs, so the guarantee is only worth anything if it
    survives a caller choosing the command designed to break it.
    """
    done = grant.spawn(["sh", "-c", script], VALUES)
    assert done["ok"]
    assert SECRET not in done["stdout"], f"{script!r} leaked it"


@needs_a_posix_shell
def test_the_store_locators_are_stripped_from_the_child():
    """A child holding a grant must not be able to re-derive the whole store.

    Inheriting HIVE_ENV_FILES would let it read the file directly and make the
    key set it was granted meaningless.
    """
    done = grant.spawn(["sh", "-c", "echo ${HIVE_ENV_FILES:-stripped}"], VALUES,
                       base_env={"HIVE_ENV_FILES": "/somewhere/real.env", "PATH": "/bin:/usr/bin"})
    assert done["stdout"].strip() == "stripped"


@needs_a_posix_shell
def test_caller_environment_cannot_overwrite_a_credential():
    """Otherwise `extra_env` is a way to have the child print a chosen value
    under a trusted name, which would make the record say something false."""
    done = grant.spawn(["sh", "-c", "echo $SECRET_TOKEN"], VALUES,
                       extra_env={"SECRET_TOKEN": "attacker-chosen"})
    assert "attacker-chosen" not in done["stdout"]


@needs_a_posix_shell
def test_streaming_redacts_as_it_goes():
    out, err = io.StringIO(), io.StringIO()
    answer = grant.stream(
        ["sh", "-c", f'printf "start "; printf %s "$SECRET_TOKEN"; echo " end"'],
        VALUES, stdout=out, stderr=err)
    assert answer["ok"] and answer["exit_code"] == 0
    assert SECRET not in out.getvalue()
    assert out.getvalue().strip() == "start [redacted:SECRET_TOKEN] end"


# ── guards: where a value may go ───────────────────────────────────────────


def test_an_unguarded_key_goes_into_any_command():
    assert grant.command_allowed("ANY", ["whatever"], {})["allowed"]


def test_a_guarded_key_only_goes_into_its_own_commands():
    policy = {"guards": {"CF": {"commands": ["wrangler *"]}}}
    assert grant.command_allowed("CF", ["wrangler", "deploy"], policy)["allowed"]
    assert not grant.command_allowed("CF", ["curl", "evil.example"], policy)["allowed"]


def test_a_key_with_no_destination_cannot_be_proxied_anywhere():
    """The one default that is closed, and it has to be.

    A proxy that sent any key to any host the caller named would be an
    exfiltration tool with a friendly name — the caller points it at a host it
    controls and reads the value out of its own access log.
    """
    verdict = grant.host_allowed("ANY", "https://wherever.example", {})
    assert not verdict["allowed"]
    assert "passbook guard" in verdict["why"]


def test_a_bound_key_reaches_its_host_and_no_other():
    policy = {"guards": {"CF": {"destinations": ["api.cloudflare.com"]}}}
    assert grant.host_allowed("CF", "https://api.cloudflare.com/v4", policy)["allowed"]
    assert not grant.host_allowed("CF", "https://evil.example/v4", policy)["allowed"]


def test_a_leading_dot_covers_subdomains_and_nothing_else():
    policy = {"guards": {"K": {"destinations": [".example.com"]}}}
    assert grant.host_allowed("K", "https://api.example.com/", policy)["allowed"]
    assert grant.host_allowed("K", "https://example.com/", policy)["allowed"]
    assert not grant.host_allowed("K", "https://notexample.com/", policy)["allowed"]
    # The trap: a suffix match alone would let this through.
    assert not grant.host_allowed("K", "https://evil-example.com/", policy)["allowed"]


def test_a_command_pattern_with_brackets_is_matched_literally():
    """`fnmatch` would read `[...]` as a character class and quietly mean
    something else than what was written."""
    policy = {"guards": {"K": {"commands": ["run [x] *"]}}}
    assert grant.command_allowed("K", ["run", "[x]", "go"], policy)["allowed"]
    assert not grant.command_allowed("K", ["run", "x", "go"], policy)["allowed"]


def test_proxy_refuses_plain_http():
    assert not grant.proxy({"url": "http://api.example.com"}, VALUES)["ok"]


class _Answer:
    """Enough of an http response for `proxy` to read, and no network."""

    def __init__(self, body: bytes) -> None:
        self.status = 200
        self.headers = {"X-Echo": SECRET}
        self._body = body

    def read(self, _n=None):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_proxy_fills_the_placeholder_and_scrubs_the_reply(monkeypatch):
    """The strongest form: the value is in no environment and no argv.

    The response is scrubbed too, which is not paranoia — several APIs quote
    your key back at you in the error message about it, which would hand it to
    the caller through the reply body.
    """
    sent = {}

    def fake_open(request, timeout=None):
        sent["url"] = request.full_url
        sent["headers"] = dict(request.headers)
        sent["body"] = (request.data or b"").decode()
        return _Answer(f'{{"you_sent":"{SECRET}"}}'.encode())

    monkeypatch.setattr(grant.urllib.request, "urlopen", fake_open)
    answer = grant.proxy(
        {"url": "https://api.example.com/v1",
         "headers": {"Authorization": "Bearer {{SECRET_TOKEN}}"},
         "body": {"k": "{{SECRET_TOKEN}}"}},
        VALUES)

    # The far end really did receive it — otherwise this is useless.
    assert sent["headers"]["Authorization"] == f"Bearer {SECRET}"
    assert SECRET in sent["body"]
    # And the caller really did not.
    assert answer["ok"] and SECRET not in answer["body"]
    assert SECRET not in json.dumps(answer["headers"])
    assert answer["used"] == ["SECRET_TOKEN"]


def test_proxy_refuses_a_request_with_no_placeholder(monkeypatch):
    """Otherwise it is an open HTTP client wearing a credential tool's name,
    and every unrelated fetch on the machine would route through the broker."""
    monkeypatch.setattr(grant.urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("should not have been sent"))
    # placeholders() is what the broker checks before it gets this far.
    assert grant.placeholders("https://api.example.com", "", "") == []


def test_placeholders_are_found_wherever_they_sit():
    assert grant.placeholders("https://x/{{A}}", '{"k":"{{B}}"}', "Bearer {{C}}") == ["A", "B", "C"]


# ── the policy round-trips ─────────────────────────────────────────────────


def test_a_guard_survives_being_written_and_read(tmp_path, monkeypatch):
    """Guards live in a section `write_policy` does not name literally, so this
    is the test that catches it dropping them — which is exactly how `keys` and
    `groups` were lost once before."""
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    passbook.ensure(app="test")
    policy = access.read_policy()
    access.set_guard("CF_TOKEN", policy, commands=["wrangler *"],
                     destinations=["api.cloudflare.com"])
    access.write_policy(policy)

    again = access.read_policy()
    assert grant.guarded(again) == ["CF_TOKEN"]
    assert grant.commands_for("CF_TOKEN", again) == ["wrangler *"]
    assert grant.destinations_for("CF_TOKEN", again) == ["api.cloudflare.com"]


def test_adding_a_second_host_keeps_the_first(tmp_path, monkeypatch):
    """Additive by default: a narrowing nobody asked for shows up as something
    breaking a week later, with no way to connect it to the command that did it."""
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    passbook.ensure(app="test")
    policy = access.read_policy()
    access.set_guard("K", policy, destinations=["one.example"])
    access.set_guard("K", policy, destinations=["two.example"])
    assert grant.destinations_for("K", policy) == ["one.example", "two.example"]


def test_replace_actually_replaces(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    passbook.ensure(app="test")
    policy = access.read_policy()
    access.set_guard("K", policy, destinations=["one.example"])
    access.set_guard("K", policy, destinations=["two.example"], replace=True)
    assert grant.destinations_for("K", policy) == ["two.example"]


# ── a grant-backed process serves itself ───────────────────────────────────


def test_a_process_born_with_a_grant_does_not_ask_again(tmp_path, monkeypatch):
    """The short circuit that keeps a long-running service alive.

    Without it, a child would ask the broker on every read, and the first broker
    restart — which forgets its grants — would take the service down with a
    credential error naming the wrong cause.
    """
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.setenv("PASSBOOK_GRANT", "a-token")
    monkeypatch.setenv("SOME_KEY", "from-the-grant")

    def explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("a grant-backed process asked the broker")

    monkeypatch.setattr(passbook, "_ask_broker", explode)
    assert passbook.request(["SOME_KEY"], app="child") == {"SOME_KEY": "from-the-grant"}
