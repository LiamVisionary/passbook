#!/usr/bin/env python3
"""Write `latest.json`, the file the app reads to learn there is a newer release.

    python3 scripts/update-manifest.py v1.10.6 ASSETS_DIR > latest.json

`ASSETS_DIR` holds what the release's build jobs attached: each platform's update
file and, beside it, the signature Tauri made for it (`.sig`). The manifest names
one update file per platform and carries that file's signature; the app installs
a file only if the signature verifies against the public key compiled into it
(app/src-tauri/tauri.conf.json), so this file is an index, not a trust anchor.

With `--verify`, every signature is checked against its file before anything
is written, the way the app will check it (`verified`). A manifest whose signatures do not verify looks
exactly like one that is fine, right up until every installed app refuses the
update, and by then the release is published.

It is published at `releases/latest/download/latest.json`, an address GitHub
serves only for a published release: a draft offers nothing to anybody.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/LiamVisionary/passbook"
# The update file each platform installs, by how its name ends. The names are the
# ones the release workflow attaches (the Mac archives are renamed there, since
# both chips build a `PassBook.app.tar.gz`).
PLATFORMS = (
    ("darwin-aarch64", "_aarch64.app.tar.gz"),
    ("darwin-x86_64", "_x64.app.tar.gz"),
    ("windows-x86_64", "-setup.exe"),
    ("linux-x86_64", ".AppImage"),
)


def notes(version: str, changelog: str) -> str:
    """What the release is, as the headings of its changelog section."""
    section = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.S | re.M)
    titles = re.findall(r"^### (.+)$", section.group(1), re.M) if section else []
    return "\n".join(title.strip() for title in titles)


def public_key() -> bytes:
    config = json.loads((ROOT / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    return base64.b64decode(config["plugins"]["updater"]["pubkey"])


def verified(update: pathlib.Path, signature: str, key: bytes | None = None) -> bool:
    """Whether `signature` is this file's, under the key the app carries.

    Tauri signs with minisign. Both halves are a text file in base64: the key is
    a comment line and then `Ed` + an 8-byte key id + the 32-byte Ed25519 key;
    the signature is a comment line, then `ED` + the key id + a 64-byte
    signature over the file's BLAKE2b-512 digest, then a trusted comment and a
    second signature over (the first signature + that comment). All of it is
    checked: the key id, the file, and the comment.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key_lines = (key if key is not None else public_key()).decode("utf-8").splitlines()
        holder = base64.b64decode(key_lines[1])
        lines = base64.b64decode(signature).decode("utf-8").splitlines()
        detached, comment, overall = base64.b64decode(lines[1]), lines[2], base64.b64decode(lines[3])
        if holder[:2] != b"Ed" or len(holder) != 42 or len(detached) != 74 or len(overall) != 64:
            return False
        if detached[2:10] != holder[2:10] or not comment.startswith("trusted comment: "):
            return False
        if detached[:2] == b"ED":
            digest = hashlib.blake2b(digest_size=64)
            with update.open("rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
            message = digest.digest()
        elif detached[:2] == b"Ed":
            message = update.read_bytes()
        else:
            return False
        signer = Ed25519PublicKey.from_public_bytes(holder[10:])
        signer.verify(detached[10:], message)
        signer.verify(overall, detached[10:] + comment[len("trusted comment: "):].encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, IndexError, UnicodeDecodeError, OSError):
        return False


def manifest(tag: str, assets: pathlib.Path, *, verify: bool = False, now: datetime | None = None) -> dict:
    version = tag.lstrip("v")
    platforms: dict[str, dict[str, str]] = {}
    for platform, ending in PLATFORMS:
        found = sorted(path for path in assets.iterdir() if path.name.endswith(ending + ".sig"))
        if not found:
            continue
        if len(found) > 1:
            raise SystemExit(f"{platform}: more than one signature ends with {ending}.sig: {[p.name for p in found]}")
        signature = found[0].read_text(encoding="utf-8").strip()
        name = found[0].name[: -len(".sig")]
        if not signature:
            raise SystemExit(f"{platform}: {found[0].name} is empty")
        if verify:
            update = assets / name
            if not update.is_file():
                raise SystemExit(f"{platform}: {name} is not beside its signature, so it cannot be checked")
            if not verified(update, signature):
                raise SystemExit(f"{platform}: the signature does not verify for {name}; no app would install it")
        platforms[platform] = {"signature": signature, "url": f"{REPOSITORY}/releases/download/{tag}/{name}"}
    if not platforms:
        raise SystemExit("no update signatures found: nothing to offer")
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    said = notes(version, (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    return {"version": version, "notes": said, "pub_date": stamp, "platforms": platforms}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tag")
    parser.add_argument("assets", type=pathlib.Path)
    parser.add_argument("--verify", action="store_true", help="check every signature with minisign first")
    args = parser.parse_args()
    built = manifest(args.tag, args.assets, verify=args.verify)
    print(json.dumps(built, indent=2))
    print("platforms: " + ", ".join(built["platforms"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
