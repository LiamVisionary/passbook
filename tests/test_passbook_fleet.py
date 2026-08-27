# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Tailnet discovery — and what it is allowed to cost.

`describe()` sits inside `passbook state`, which an open window runs every five
seconds. Unmeasured, that was nineteen blocking TCP connects per call: 2.9 of
the 3.5 seconds the whole state command took, twelve times a minute, to answer
a question whose answer changes when somebody reboots a laptop.

The other half of this file is the promise the module opens with: an address is
used to probe a port and then dropped. Nothing that leaves here — return value
or cache file — may contain one.
"""

from __future__ import annotations

import json
import re
import stat
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _platform import assert_private  # noqa: E402

import passbook_fleet as fleet  # noqa: E402

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

PEERS = {
    "Peer": {
        "a": {"Online": True, "HostName": "alpha", "OS": "macOS",
              "TailscaleIPs": ["100.64.0.1"]},
        "b": {"Online": True, "HostName": "beta", "OS": "linux",
              "TailscaleIPs": ["100.64.0.2"]},
        "c": {"Online": False, "HostName": "gone", "OS": "linux",
              "TailscaleIPs": ["100.64.0.3"]},
    },
    "Self": {"HostName": "here", "OS": "macOS"},
}


@pytest.fixture
def tailnet(tmp_path, monkeypatch):
    """A machine with two online peers, one of which runs a collector."""
    fleet._STATUS_CACHE = None
    monkeypatch.setattr(fleet, "_tailscale_cli", lambda: "/usr/bin/true")
    monkeypatch.setattr(fleet, "_read_status", lambda: PEERS)
    monkeypatch.setattr(fleet, "_reachable_collector",
                        lambda ip: "8798" if ip.endswith(".1") else "")
    yield tmp_path
    fleet._STATUS_CACHE = None


def test_discovery_reports_peers_without_ever_returning_an_address(tailnet):
    answer = fleet.describe(fresh=True, root=tailnet)

    assert [row["host"] for row in answer["peers"]] == ["alpha", "beta"]
    assert answer["replicating"] == 1
    assert not IPV4.search(json.dumps(answer)), "an address reached the caller"


def test_an_offline_peer_is_not_a_peer(tailnet):
    hosts = [row["host"] for row in fleet.describe(fresh=True, root=tailnet)["peers"]]
    assert "gone" not in hosts


def test_the_second_call_does_not_probe_the_tailnet_again(tailnet, monkeypatch):
    """The expensive half is the probing, and it is what the cache is for."""
    fleet.describe(fresh=True, root=tailnet)

    probes = []
    monkeypatch.setattr(fleet, "_reachable_collector",
                        lambda ip: probes.append(ip) or "")

    again = fleet.describe(root=tailnet)

    assert probes == [], "a cached answer probed anyway"
    assert again["cached"] is True
    assert again["replicating"] == 1, "the cached answer lost what it knew"


def test_asking_for_a_fresh_answer_ignores_the_cache(tailnet, monkeypatch):
    fleet.describe(fresh=True, root=tailnet)

    probes = []
    monkeypatch.setattr(fleet, "_reachable_collector",
                        lambda ip: probes.append(ip) or "8798")

    answer = fleet.describe(fresh=True, root=tailnet)

    assert probes, "fresh=True must go and look"
    assert answer["replicating"] == 2


def test_a_stale_answer_is_not_used(tailnet, monkeypatch):
    fleet.describe(fresh=True, root=tailnet)
    monkeypatch.setattr(fleet, "CACHE_SECONDS", -1.0)

    probes = []
    monkeypatch.setattr(fleet, "_reachable_collector",
                        lambda ip: probes.append(ip) or "")

    fleet.describe(root=tailnet)

    assert probes, "an expired answer was served"


def test_the_cache_holds_no_address_and_nobody_else_can_read_it(tailnet):
    fleet.describe(fresh=True, root=tailnet)
    path = fleet._cache_path(tailnet)

    held = path.read_text(encoding="utf-8")

    assert not IPV4.search(held), "an address was written to disk"
    assert_private(path, 0o600)


def test_a_damaged_cache_is_no_cache_rather_than_an_error(tailnet):
    fleet.describe(fresh=True, root=tailnet)
    fleet._cache_path(tailnet).write_text("{not json", encoding="utf-8")

    answer = fleet.describe(root=tailnet)

    assert [row["host"] for row in answer["peers"]] == ["alpha", "beta"]


def test_peers_are_probed_together_not_one_after_another(tailnet, monkeypatch):
    """Sequentially, one unreachable peer delayed every peer behind it.

    Six peers at the 0.35s timeout was over two seconds of waiting for nothing,
    and the waits are on unrelated machines with no reason to be taken in turn.
    """
    many = {"Peer": {str(n): {"Online": True, "HostName": f"peer{n}", "OS": "linux",
                              "TailscaleIPs": [f"100.64.1.{n}"]} for n in range(8)},
            "Self": {"HostName": "here", "OS": "linux"}}
    fleet._STATUS_CACHE = None
    monkeypatch.setattr(fleet, "_read_status", lambda: many)
    monkeypatch.setattr(fleet, "_reachable_collector",
                        lambda ip: time.sleep(0.2) or "")

    started = time.perf_counter()
    answer = fleet.describe(fresh=True, root=tailnet)
    took = time.perf_counter() - started

    assert len(answer["peers"]) == 8
    assert took < 0.2 * 8 / 2, f"probes were taken in turn: {took:.2f}s for 8 peers"


def test_the_tailscale_status_subprocess_runs_once_per_call(tailnet, monkeypatch):
    """`describe` asked three times — to check, to list, and for this machine."""
    runs = []
    fleet._STATUS_CACHE = None
    monkeypatch.setattr(fleet, "_read_status", lambda: runs.append(1) or PEERS)

    fleet.describe(fresh=True, root=tailnet)

    assert len(runs) == 1, f"tailscale status ran {len(runs)} times"
