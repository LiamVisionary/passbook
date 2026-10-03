# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""A company host keeps only the keys its owner shares to it.

HivemindOS can move a company to another computer, often a rented Linux box,
installed with `--company-host`. On 2026-10-03 a fresh one held the whole store
(~400 keys, wallet keys among them) four minutes after joining the tailnet.
HivemindOS fixed its side: that collector's `/health` says
`envSync.companyHost: true` (with `ready: false` for older peers), it refuses
`GET /env`, and it acknowledges `POST /env` without writing it.

That left PassBook. It found peers by a TCP connect alone and never read
`/health`, so `passbook add` and `passbook rotate` still sent every new VALUE to
the rented box. Discarded on arrival is not the same as never sent: the value
crossed the wire to a machine the owner did not share it with.

These tests talk to a real HTTP server on loopback standing in for a collector.
Nothing here reaches a real tailnet: the tailnet status is replaced and the
only collector port is the test server's own.
"""

from __future__ import annotations

import http.server
import json
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_fleet as fleet  # noqa: E402
import passbook_sync as sync  # noqa: E402

COMPANY_HEALTH = {"ok": True, "envSync": {"ready": False, "companyHost": True,
                                          "user": "tester", "error": "keeps only shared keys"}}
ORDINARY_HEALTH = {"ok": True, "envSync": {"ready": True, "user": "tester", "error": ""},
                   "capabilities": {"envHttpSync": True}}


class Collector:
    """A stand-in collector that records every request it is sent."""

    def __init__(self, health, env_payload=None):
        self.health = health
        self.env_payload = env_payload
        self.requests: list[tuple[str, str, bytes]] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _reply(self, status, body):
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                owner.requests.append(("GET", self.path, b""))
                path = self.path.split("?")[0]
                if path == "/health" and owner.health is not None:
                    return self._reply(200, owner.health)
                if path == "/env" and owner.env_payload is not None:
                    return self._reply(200, owner.env_payload)
                return self._reply(404, {"ok": False})

            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                owner.requests.append(("POST", self.path, body))
                return self._reply(200, {"ok": True, "updated": 0})

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = str(self.server.server_port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def posts(self):
        return [(path, body) for method, path, body in self.requests if method == "POST"]

    def gets(self, path):
        return [p for method, p, _ in self.requests if method == "GET" and p.split("?")[0] == path]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def collector(monkeypatch):
    """Make a one-peer tailnet whose only collector is a loopback test server."""
    made: list[Collector] = []

    def make(health, env_payload=None, host="rented"):
        server = Collector(health, env_payload)
        made.append(server)
        fleet._STATUS_CACHE = None
        monkeypatch.setattr(fleet, "_tailscale_cli", lambda: "/usr/bin/true")
        monkeypatch.setattr(fleet, "_read_status", lambda: {"Peer": {"p": {
            "Online": True, "HostName": host, "OS": "linux",
            "TailscaleIPs": ["127.0.0.1"]}}})
        monkeypatch.setattr(fleet, "COLLECTOR_PORTS", (server.port,))
        return server

    yield make
    for server in made:
        server.close()
    fleet._STATUS_CACHE = None
    fleet._COMPANY_HOSTS_SEEN = []


def _cli(tmp_path, monkeypatch, *args):
    import passbook_cli

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("HIVE_COMPANY_HOST", raising=False)
    return passbook_cli.main(list(args))


# ── reading the flag ───────────────────────────────────────────────────────


@pytest.mark.parametrize("health, expected", [
    (COMPANY_HEALTH, True),
    # How the collector nests it today, and the flag on its own at the top.
    ({"envSync": {"ready": True, "companyHost": True}}, True),
    ({"companyHost": True}, True),
    (ORDINARY_HEALTH, False),
    # Only a real `true` counts: a string or a missing field is an ordinary peer.
    ({"envSync": {"companyHost": "yes"}}, False),
    (None, False),
    ("not json", False),
])
def test_a_company_host_is_read_from_its_health(health, expected):
    assert fleet.is_company_host(health) is expected


# ── a value never travels to a company host ────────────────────────────────


def test_a_new_key_is_not_sent_to_a_company_host(tmp_path, monkeypatch, collector, capsys):
    """The leak this file exists for: `passbook add` sent the value to every
    collector a TCP connect found, including the rented box."""
    server = collector(COMPANY_HEALTH)

    assert _cli(tmp_path, monkeypatch, "add", "WALLET_PRIVATE_KEY=0xsecret") == 0

    assert server.posts() == [], "a value went to a computer that keeps only shared keys"
    assert server.gets("/health"), "the peer's /health was never read"
    # Nothing queued for it either: it is not asleep, it is not a target.
    assert sync.read_pending(tmp_path) == {}
    assert "0xsecret" not in capsys.readouterr().out


def test_an_ordinary_peer_still_gets_the_new_key(tmp_path, monkeypatch, collector):
    server = collector(ORDINARY_HEALTH)

    assert _cli(tmp_path, monkeypatch, "add", "SHARED_TOKEN=fresh") == 0

    posts = server.posts()
    assert [path for path, _ in posts] == ["/env"]
    assert json.loads(posts[0][1])["entries"] == {"SHARED_TOKEN": "fresh"}


def test_a_peer_whose_health_does_not_answer_is_treated_as_before(tmp_path, monkeypatch, collector):
    """An older collector, or one whose /health is not there: replication keeps
    working as it did. Only a peer that SAYS it is a company host is skipped."""
    server = collector(None)

    assert _cli(tmp_path, monkeypatch, "add", "SHARED_TOKEN=fresh") == 0

    assert [path for path, _ in server.posts()] == ["/env"]


def test_push_itself_refuses_a_company_host(collector):
    """The last step before a value leaves checks too, so a caller that found a
    peer some other way cannot send to one."""
    server = collector(COMPANY_HEALTH)

    ok, why = sync.push("rented", server.port, {"TOKEN": "value"}, address="127.0.0.1")

    assert ok is False
    assert why == sync.COMPANY_HOST_REFUSAL
    assert server.posts() == []


# ── nor is one asked for the store ─────────────────────────────────────────


def test_sync_neither_pulls_from_nor_seeds_a_company_host(tmp_path, monkeypatch, collector, capsys):
    """Even a company host that answered GET /env is not a pull source, and
    `--push-missing` sends it nothing. It is reported as what it is rather
    than as unreachable."""
    store_payload = {"ok": True, "values": {"FROM_HOST": "x"}, "updatedAt": {"FROM_HOST": time.time()},
                     "withheldSealed": [], "withheldByPolicy": []}
    server = collector(COMPANY_HEALTH, env_payload=store_payload)
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("MINE=1\n", encoding="utf-8")
    sync.touch_meta(tmp_path / ".env", ["MINE"])

    capsys.readouterr()
    assert _cli(tmp_path, monkeypatch, "sync", "--apply", "--push-missing", "--retry-pending") == 0
    said = capsys.readouterr().out

    assert server.gets("/env") == [], "asked a company host for the whole store"
    assert server.posts() == []
    assert "skipped rented: it keeps only the keys you share to it" in said
    assert "unreachable" not in said
    assert "FROM_HOST" not in (tmp_path / ".env").read_text(encoding="utf-8")


def test_sync_json_names_company_hosts_beside_the_peers_it_used(tmp_path, monkeypatch, capsys):
    """Two machines on the tailnet: an ordinary one and a company host. The
    JSON every collector's maintenance reads lists the company host on its own,
    never under `peers` or `unreachable`, and only the ordinary one is asked
    for the store or seeded."""
    fleet._STATUS_CACHE = None
    monkeypatch.setattr(fleet, "_tailscale_cli", lambda: "/usr/bin/true")
    monkeypatch.setattr(fleet, "_read_status", lambda: {"Peer": {
        "a": {"Online": True, "HostName": "laptop", "OS": "macos", "TailscaleIPs": ["100.64.0.1"]},
        "b": {"Online": True, "HostName": "rented", "OS": "linux", "TailscaleIPs": ["100.64.0.9"]}}})
    monkeypatch.setattr(fleet, "_reachable_collector", lambda ip: "8798")
    monkeypatch.setattr(fleet, "collector_health", lambda address, port, **_: (
        COMPANY_HEALTH if address == "100.64.0.9" else ORDINARY_HEALTH))
    fetched, pushed = [], []
    monkeypatch.setattr(sync, "fetch", lambda host, port, **_: fetched.append(host) or {
        "ok": True, "values": {}, "updatedAt": {}, "withheldSealed": [], "withheldByPolicy": []})
    monkeypatch.setattr(sync, "push", lambda host, port, values, **_: pushed.append(host) or (True, ""))
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("MINE=1\n", encoding="utf-8")
    sync.touch_meta(tmp_path / ".env", ["MINE"])
    sync.note_undelivered(["MINE"], ["rented"], root=tmp_path)

    try:
        capsys.readouterr()
        assert _cli(tmp_path, monkeypatch, "sync", "--json", "--apply", "--push-missing",
                    "--retry-pending", "--no-adopt") == 0
        answer = json.loads(capsys.readouterr().out)
    finally:
        fleet._STATUS_CACHE = None
        fleet._COMPANY_HOSTS_SEEN = []

    assert fetched == ["laptop"] and pushed == ["laptop"]
    assert answer["peers"] == ["laptop"]
    assert answer["companyHosts"] == ["rented"]
    assert answer["unreachable"] == []
    assert answer["wouldSeed"] == {"laptop": ["MINE"]}
    # The old debt to the company host is gone rather than retried.
    assert answer["stillOwed"] == {}


def test_an_old_debt_to_a_company_host_is_dropped_not_kept_for_ever(
        tmp_path, monkeypatch, collector, capsys):
    """A key queued for a machine before it became a company host. Retrying it
    would send the value; keeping it would list it as owed on every pass."""
    server = collector(COMPANY_HEALTH)
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("OWED=1\n", encoding="utf-8")
    sync.note_undelivered(["OWED"], ["rented", "laptop"], root=tmp_path)

    assert _cli(tmp_path, monkeypatch, "sync", "--retry-pending") == 0
    assert sync.read_pending(tmp_path)["OWED"]["owed"] == ["laptop", "rented"], \
        "a dry run changes nothing"

    assert _cli(tmp_path, monkeypatch, "sync", "--apply", "--retry-pending") == 0
    assert sync.read_pending(tmp_path)["OWED"]["owed"] == ["laptop"]
    assert server.posts() == []


# ── and a company host does not fan out itself ─────────────────────────────


@pytest.mark.parametrize("how", ["env", "file"])
def test_on_a_company_host_sync_and_add_stay_on_this_machine(tmp_path, monkeypatch, collector,
                                                            capsys, how):
    """HivemindOS stops a company host's own maintenance from syncing, but a
    person running `passbook sync --apply` there would still have pulled every
    peer's store onto the rented box. The marker is the one HivemindOS writes."""
    import passbook_cli

    server = collector(ORDINARY_HEALTH, env_payload={
        "ok": True, "values": {"THEIRS": "x"}, "updatedAt": {}, "withheldSealed": []})
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("HIVE_COMPANY_HOST", raising=False)
    if how == "env":
        monkeypatch.setenv("HIVE_COMPANY_HOST", "1")
    else:
        (tmp_path / "company-host.env").write_text("HIVE_COMPANY_HOST=1\n", encoding="utf-8")

    assert passbook_cli.main(["add", "LOCAL_ONLY_HERE=1"]) == 0
    capsys.readouterr()
    assert passbook_cli.main(["sync", "--json", "--apply", "--maintenance"]) == 0
    answer = json.loads(capsys.readouterr().out)

    assert server.requests == [], "a company host reached out to another computer"
    assert answer["companyHost"] is True
    assert answer["peers"] == [] and answer["pulled"] == []
    assert "THEIRS" not in (tmp_path / ".env").read_text(encoding="utf-8")


def test_the_marker_needs_a_true_value(tmp_path, monkeypatch):
    monkeypatch.delenv("HIVE_COMPANY_HOST", raising=False)
    (tmp_path / "company-host.env").write_text("HIVE_COMPANY_HOST=0\n", encoding="utf-8")
    assert fleet.company_host_mode(root=tmp_path) is False
    (tmp_path / "company-host.env").write_text("# set up by setup.sh\nHIVE_COMPANY_HOST='true'\n",
                                               encoding="utf-8")
    assert fleet.company_host_mode(root=tmp_path) is True


def test_naming_a_company_host_as_the_peer_to_sync_with_is_refused(
        tmp_path, monkeypatch, collector, capsys):
    server = collector(COMPANY_HEALTH)
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("MINE=1\n", encoding="utf-8")

    assert _cli(tmp_path, monkeypatch, "sync", "--from", "rented", "--apply") == 1
    assert "keeps only the keys you share to it" in capsys.readouterr().err
    assert server.gets("/env") == [] and server.posts() == []
