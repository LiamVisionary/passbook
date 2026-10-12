"""A provider's logo comes from its own site, is checked to be an image, and its absence is not an error."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_logos as logos  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
ENTRY = {"id": "openrouter", "console_url": "https://console.openrouter.ai/settings"}


def test_an_image_is_known_by_its_first_bytes_never_by_what_it_is_called():
    assert logos.kind(PNG) == "image/png"
    assert logos.kind(b"\xff\xd8\xff\xe0rest") == "image/jpeg"
    assert logos.kind(b"\x00\x00\x01\x00rest") == "image/x-icon"
    assert logos.kind(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert logos.kind(b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"></svg>') == "image/svg+xml"
    assert logos.kind(b"<!doctype html><html><body>Just a moment...</body></html>") == "", "a challenge page is not a logo"
    assert logos.kind(b"") == ""


def test_the_touch_icon_wins_then_the_largest_and_the_favicon_is_the_last_resort():
    html = """<head>
      <link rel="icon" sizes="16x16" href="/small.png">
      <link href='/big.png' sizes='192x192' rel='icon'>
      <link rel="mask-icon" href="/silhouette.svg" color="#000">
      <link rel="apple-touch-icon" href="https://cdn.example.com/touch.png">
      <link rel="icon" href="data:image/png;base64,AAAA">
      <link rel="stylesheet" href="/site.css">
      <link rel="icon" href="http://insecure.example.com/x.png">
    </head>"""
    assert logos.candidates(html, "https://example.com/app/") == [
        "https://cdn.example.com/touch.png", "https://example.com/big.png", "https://example.com/small.png",
        "https://example.com/favicon.ico"]
    assert logos.candidates("", "https://example.com/") == ["https://example.com/favicon.ico"]


def test_it_looks_on_the_console_then_the_main_domain_and_sends_no_key():
    assert logos.sites(ENTRY) == ["https://console.openrouter.ai/", "https://openrouter.ai/"]
    assert logos.sites({"id": "x", "console_url": "https://fal.ai/dashboard"}) == ["https://fal.ai/"]
    assert logos.sites({"id": "x"}) == []
    asked = []

    def fetch(url, limit):
        asked.append(url)
        if url == "https://console.openrouter.ai/":
            raise OSError("refused")
        if url == "https://openrouter.ai/":
            return url, b'<link rel="icon" href="/logo.png">'
        if url == "https://openrouter.ai/logo.png":
            return url, PNG
        return url, b"<html>not an image</html>"

    found = logos.resolve(ENTRY, fetch=fetch)
    assert found == "data:image/png;base64," + base64.b64encode(PNG).decode()
    assert asked == ["https://console.openrouter.ai/", "https://console.openrouter.ai/favicon.ico",
                     "https://openrouter.ai/", "https://openrouter.ai/logo.png"]


def test_something_that_is_not_an_image_or_is_too_big_is_never_shown():
    page = b'<link rel="icon" href="/logo.png">'
    not_image = lambda url, limit: (url, page if url.endswith("/") else b"<html>blocked</html>")  # noqa: E731
    assert logos.resolve(ENTRY, fetch=not_image) == ""
    too_big = lambda url, limit: (url, page if url.endswith("/") else PNG + b"\x00" * logos.ICON_BYTES)  # noqa: E731
    assert logos.resolve(ENTRY, fetch=too_big) == ""


def test_a_site_is_asked_once_a_month_and_a_miss_once_a_day(tmp_path):
    clock, asks = [1_800_000_000.0], []
    other = {"id": "vultr", "console_url": "https://my.vultr.com"}

    def find(entry):
        asks.append(entry["id"])
        if entry["id"] == "vultr":
            raise RuntimeError("the site refused")
        return "data:image/png;base64,AAAA"

    run = lambda: logos.icons(tmp_path, [ENTRY, other], now=lambda: clock[0], find=find)  # noqa: E731
    assert run() == {"openrouter": "data:image/png;base64,AAAA"}, "a miss is simply not in the answer"
    assert sorted(asks) == ["openrouter", "vultr"]
    assert run() == {"openrouter": "data:image/png;base64,AAAA"} and len(asks) == 2, "both answers are kept"
    clock[0] += logos.MISS_SECONDS + 1
    run()
    assert asks[2:] == ["vultr"], "a miss is tried again after a day; a logo is kept for a month"
    clock[0] += logos.KEEP_SECONDS
    run()
    assert sorted(asks[3:]) == ["openrouter", "vultr"]
    logos.forget(tmp_path)
    assert not (tmp_path / logos.ICONS_FILE).exists()
