# SPDX-License-Identifier: Apache-2.0
"""Cooperating writers serialize conditional encrypted imports with local edits."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook


def test_waiting_conditional_import_preserves_a_local_edit(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    path = tmp_path / ".env"
    original, local, incoming = ("hive-sealed:v2:synthetic-" + label for label in ("original", "local", "peer"))
    passbook.set_values({"KEY": original}, path=path)
    waiting = threading.Event()

    def receive():
        waiting.set()
        with pytest.raises(ValueError, match="changed locally"):
            passbook.set_values({"KEY": incoming}, path=path, overwrite=True,
                                expected_versions={"KEY": hashlib.sha256(original.encode()).hexdigest()})

    with ThreadPoolExecutor(max_workers=1) as pool:
        with passbook.store_lock(path):
            task = pool.submit(receive)
            assert waiting.wait(2)
            passbook.set_values({"KEY": local}, path=path, overwrite=True)
            assert not task.done()
        task.result(timeout=3)
    assert passbook.parse_env_text(path.read_text())["KEY"] == local


def test_concurrent_writers_keep_unrelated_keys_and_lock_is_per_store(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    path = tmp_path / ".env"
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: passbook.set_values({f"KEY_{i}": "synthetic-value"}, path=path), range(30)))
    assert len(passbook.parse_env_text(path.read_text())) == 30
    with passbook.store_lock(path):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(passbook.set_values, {"OTHER": "synthetic-value"}, path=tmp_path / "other.env").result(timeout=3)


def test_conditional_update_replaces_every_duplicate_occurrence(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    path = tmp_path / ".env"
    value = "hive-sealed:v2:synthetic-old"
    path.write_text(f"KEY={value}\n# preserved\nKEY={value}\n")
    passbook.set_values({"KEY": "hive-sealed:v2:synthetic-new"}, path=path, overwrite=True,
                        expected_versions={"KEY": hashlib.sha256(value.encode()).hexdigest()})
    assert value not in path.read_text() and "# preserved" in path.read_text()
    assert passbook.parse_env_text(path.read_text())["KEY"] == "hive-sealed:v2:synthetic-new"


def test_concurrent_sync_stamps_preserve_other_keys(tmp_path):
    import passbook_sync as sync

    store = tmp_path / ".env"
    sync.touch_meta(store, ["EXISTING"], when=100)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: sync.touch_meta(store, [f"KEY_{i}"], when=200 + i), range(30)))
    assert sync.read_meta(store) == {"EXISTING": 100, **{f"KEY_{i}": 200 + i for i in range(30)}}
