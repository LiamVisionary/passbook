"""`latest.json` is what every installed app reads to learn there is a newer release.

Wrong here is silent: an app offered nothing, or offered a file it then refuses. So the
names it matches, the address it gives and what it does with a half-built release are pinned.
"""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("update_manifest", ROOT / "scripts/update-manifest.py")
update_manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_manifest)

NAMES = {
    "darwin-aarch64": "PassBook_9.9.9_aarch64.app.tar.gz",
    "darwin-x86_64": "PassBook_9.9.9_x64.app.tar.gz",
    "windows-x86_64": "PassBook_9.9.9_x64-setup.exe",
    "linux-x86_64": "PassBook_9.9.9_amd64.AppImage",
}


def _release(tmp_path, only=None):
    for platform, name in NAMES.items():
        if only and platform not in only:
            continue
        (tmp_path / name).write_bytes(b"the update")
        (tmp_path / (name + ".sig")).write_text(f"signature-of-{platform}\n", encoding="utf-8")
    # What else a release carries, none of it an update file.
    (tmp_path / "PassBook_9.9.9_aarch64.dmg").write_bytes(b"")
    (tmp_path / "PassBook_9.9.9_amd64.deb").write_bytes(b"")
    (tmp_path / "PassBook_9.9.9_amd64.deb.sig").write_text("a package is not an update file", encoding="utf-8")
    return tmp_path


def test_every_platform_gets_its_own_file_and_that_files_signature(tmp_path):
    built = update_manifest.manifest("v9.9.9", _release(tmp_path), now=datetime(2026, 10, 13, tzinfo=timezone.utc))
    assert built["version"] == "9.9.9" and built["pub_date"] == "2026-10-13T00:00:00Z"
    assert set(built["platforms"]) == set(NAMES)
    for platform, name in NAMES.items():
        entry = built["platforms"][platform]
        assert entry["signature"] == f"signature-of-{platform}"
        assert entry["url"] == f"https://github.com/LiamVisionary/passbook/releases/download/v9.9.9/{name}"
    json.dumps(built)


def test_a_platform_that_did_not_build_is_left_out_and_nothing_at_all_is_an_error(tmp_path):
    built = update_manifest.manifest("v9.9.9", _release(tmp_path, only={"darwin-aarch64"}))
    assert set(built["platforms"]) == {"darwin-aarch64"}
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SystemExit, match="nothing to offer"):
        update_manifest.manifest("v9.9.9", empty)


def test_an_empty_or_doubled_signature_stops_the_manifest(tmp_path):
    release = _release(tmp_path)
    (release / (NAMES["linux-x86_64"] + ".sig")).write_text("", encoding="utf-8")
    with pytest.raises(SystemExit, match="is empty"):
        update_manifest.manifest("v9.9.9", release)
    (release / (NAMES["linux-x86_64"] + ".sig")).write_text("x", encoding="utf-8")
    (release / "PassBook_9.9.8_amd64.AppImage.sig").write_text("an older one", encoding="utf-8")
    with pytest.raises(SystemExit, match="more than one"):
        update_manifest.manifest("v9.9.9", release)


def test_a_signature_that_does_not_verify_stops_the_manifest(tmp_path, monkeypatch):
    release = _release(tmp_path)
    asked = []
    monkeypatch.setattr(update_manifest, "verified", lambda update, signature: asked.append(update.name) or True)
    assert set(update_manifest.manifest("v9.9.9", release, verify=True)["platforms"]) == set(NAMES)
    assert sorted(asked) == sorted(NAMES.values()), "each update file is checked against its own signature"
    monkeypatch.setattr(update_manifest, "verified", lambda update, signature: "aarch64" not in update.name)
    with pytest.raises(SystemExit, match="does not verify"):
        update_manifest.manifest("v9.9.9", release, verify=True)
    (release / NAMES["windows-x86_64"]).unlink()
    monkeypatch.setattr(update_manifest, "verified", lambda update, signature: True)
    with pytest.raises(SystemExit, match="cannot be checked"):
        update_manifest.manifest("v9.9.9", release, verify=True)


def test_a_real_tauri_signature_verifies_and_nothing_else_does(tmp_path):
    """The fixture is a file signed by `tauri signer sign` with a key made for this test and thrown away."""
    pytest.importorskip("cryptography")
    fixture = ROOT / "tests/fixtures/update-signature"
    key = __import__("base64").b64decode((fixture / "key.pub").read_text(encoding="utf-8"))
    signature = (fixture / "update.bin.sig").read_text(encoding="utf-8").strip()
    assert update_manifest.verified(fixture / "update.bin", signature, key)

    changed = tmp_path / "update.bin"
    changed.write_bytes((fixture / "update.bin").read_bytes() + b"one more byte")
    assert not update_manifest.verified(changed, signature, key), "a changed file"
    assert not update_manifest.verified(fixture / "update.bin", signature), "the app's key did not sign this"
    assert not update_manifest.verified(fixture / "update.bin", "not a signature", key)
    assert not update_manifest.verified(fixture / "missing.bin", signature, key)


def test_notes_are_the_headings_of_that_versions_changelog_section():
    changelog = "# Changelog\n\n## [Unreleased]\n\n### Not yet\n\n## [9.9.9] — 2026-10-13\n\n### The app updates itself\n\n- how\n\n### Balances at a glance\n\n## [9.9.8] — 2026-10-12\n\n### Older\n"
    assert update_manifest.notes("9.9.9", changelog) == "The app updates itself\nBalances at a glance"
    assert update_manifest.notes("1.2.3", changelog) == ""


def test_the_app_is_built_to_read_the_manifest_this_writes():
    """The address the app asks, the key it checks with, and the switch the release turns on."""
    config = json.loads((ROOT / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    updater = config["plugins"]["updater"]
    assert updater["endpoints"] == ["https://github.com/LiamVisionary/passbook/releases/latest/download/latest.json"]
    assert update_manifest.public_key().startswith(b"untrusted comment: minisign public key")
    # Off in the committed config, so a checkout or a fork builds without the signing key;
    # the release workflow turns it on with this overlay when it has the key.
    assert "createUpdaterArtifacts" not in config["bundle"]
    overlay = json.loads((ROOT / "app/src-tauri/tauri.updater.conf.json").read_text(encoding="utf-8"))
    assert overlay == {"bundle": {"createUpdaterArtifacts": True}}
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "tauri.updater.conf.json" in workflow and "scripts/update-manifest.py" in workflow
    assert "PASSBOOK_UPDATER_PRIVATE_KEY" in workflow
