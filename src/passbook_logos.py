"""A provider's own logo, found on its own site, for the Balances page.

A list of twenty services is read by its marks faster than by its names, and a letter in a circle is not a
mark. Shipping logos would mean keeping fifty-seven trademarks current in this repository, and asking a
logo service would tell a third party which providers you hold keys for. So the logo comes from the one
place that already knows you are a customer and gets a request from this computer anyway: the provider's
own site, the address in the catalog (`console_url`).

How it is found: fetch that page, read its `<link rel="...icon...">` tags, prefer the touch icon (a
finished square tile) and then the largest icon, fall back to `/favicon.ico`, and try the site's main
domain when the console's own page gives nothing. No key is ever sent: these are plain page requests.

What comes back is checked to be an image by its first bytes (never by what the server calls it), kept
under a size, and handed to the window as a `data:` address, so the page never loads anything from the
network itself. An SVG is shown through `<img>`, where a browser runs no script in it.

Kept in `balances-icons.json` for thirty days; a miss is remembered for a day so a site without a usable
icon is not asked on every visit. When there is none, the page draws the letter it always drew.
"""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

ICONS_FILE = "balances-icons.json"
KEEP_SECONDS = 30 * 86400
MISS_SECONDS = 86400
PAGE_BYTES = 600_000
ICON_BYTES = 300_000
TIMEOUT = 6.0
WORKERS = 8
# Sites answer an unknown client with a challenge page; this says plainly what is asking.
AGENT = "Mozilla/5.0 (compatible; PassBook; +https://github.com/LiamVisionary/passbook)"

_LINK = re.compile(r"<link\b[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")


def kind(data: bytes) -> str:
    """The image type by its first bytes, or "" when it is not one this page will show."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "image/x-icon"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<svg", b"<?xml")) and b"<svg" in data[:4096].lower():
        return "image/svg+xml"
    return ""


def candidates(html: str, base: str) -> list[str]:
    """The icons a page declares, best first: a touch icon, then by size, then whatever is left."""
    found: list[tuple[int, str]] = []
    for tag in _LINK.findall(html):
        attrs = {name.lower(): (a or b or c) for name, a, b, c in _ATTR.findall(tag)}
        rel, href = (attrs.get("rel") or "").lower(), (attrs.get("href") or "").strip()
        if "icon" not in rel or not href or href.startswith("data:"):
            continue
        sizes = [int(n) for n in re.findall(r"(\d+)x\d+", (attrs.get("sizes") or "").lower())]
        size = max(sizes) if sizes else 0
        if "apple-touch-icon" in rel:
            score = 1000 + size
        elif "mask-icon" in rel:
            continue  # a one-colour silhouette meant to be tinted, not a logo
        elif href.lower().split("?")[0].endswith(".svg"):
            score = 500
        else:
            score = size or 16
        found.append((score, urllib.parse.urljoin(base, href)))
    ordered = [url for _, url in sorted(found, key=lambda pair: -pair[0])]
    ordered.append(urllib.parse.urljoin(base, "/favicon.ico"))
    return list(dict.fromkeys(url for url in ordered if url.startswith("https://")))


def _fetch(url: str, limit: int) -> tuple[str, bytes]:
    """(the address finally answered from, the first `limit` bytes). https only, wherever it redirects."""
    request = urllib.request.Request(url, headers={"User-Agent": AGENT, "Accept": "text/html,image/*;q=0.9,*/*;q=0.5"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 — https, checked below
        final = response.geturl()
        if not final.startswith("https://"):
            raise urllib.error.URLError("left https")
        return final, response.read(limit + 1)


def sites(entry: Mapping[str, Any]) -> list[str]:
    """Where to look for a provider's icon: its console's own page, then its main domain."""
    host = urllib.parse.urlsplit(str(entry.get("console_url") or "")).hostname or ""
    if not host:
        return []
    labels = host.split(".")
    apex = ".".join(labels[-2:])
    return list(dict.fromkeys([f"https://{host}/", f"https://{apex}/"]))


def resolve(entry: Mapping[str, Any], *, fetch: Callable[[str, int], tuple[str, bytes]] = _fetch) -> str:
    """A provider's logo as a `data:` address, or "" when its site offers none this page can use."""
    for site in sites(entry):
        try:
            final, page = fetch(site, PAGE_BYTES)
            html = page[:PAGE_BYTES].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 — unreachable, refused, not a page: try the next place
            final, html = site, ""
        for url in candidates(html, final):
            try:
                _, data = fetch(url, ICON_BYTES)
            except Exception:  # noqa: BLE001
                continue
            mime = kind(data)
            if mime and len(data) <= ICON_BYTES:
                return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
    return ""


def _kept(root: Path) -> dict:
    try:
        loaded = json.loads((Path(root) / ICONS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def icons(root: Path, entries: Iterable[Mapping[str, Any]], *, now: Callable[[], float] = time.time,
          find: Callable[[Mapping[str, Any]], str] = resolve) -> dict[str, str]:
    """{provider id: `data:` address} for the providers given, asking each site at most once a month."""
    kept, moment = _kept(root), now()
    chosen = list(entries)

    def fresh(entry: Mapping[str, Any]) -> bool:
        had = kept.get(entry["id"])
        if not isinstance(had, dict):
            return False
        return moment - float(had.get("at") or 0) < (KEEP_SECONDS if had.get("data") else MISS_SECONDS)

    wanted = [entry for entry in chosen if not fresh(entry)]
    if wanted:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for entry, data in zip(wanted, pool.map(lambda entry: _quietly(find, entry), wanted)):
                kept[entry["id"]] = {"at": int(moment), "data": data}
        try:
            (Path(root) / ICONS_FILE).write_text(json.dumps(kept, separators=(",", ":")) + "\n", encoding="utf-8")
        except OSError:
            pass
    return {entry["id"]: kept[entry["id"]]["data"] for entry in chosen
            if isinstance(kept.get(entry["id"]), dict) and kept[entry["id"]].get("data")}


def _quietly(find: Callable[[Mapping[str, Any]], str], entry: Mapping[str, Any]) -> str:
    try:
        return find(entry) or ""
    except Exception:  # noqa: BLE001 — a logo is decoration; its absence is a letter in a circle
        return ""


def forget(root: Path) -> None:
    (Path(root) / ICONS_FILE).unlink(missing_ok=True)
