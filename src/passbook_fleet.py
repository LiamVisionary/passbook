# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Machines that hold this store because they are on the same tailnet.

PassBook has always known about one kind of machine: the ones it linked to
itself, by exchanging a `did:key` identity and comparing a fingerprint out of
band. Those are in `passbook_link`, they are signed, they are revocable, and
they name the keys they may borrow.

They are not the only machines holding your credentials.

HivemindOS replicates the shared store between tailnet peers through its
collector, and that path predates PassBook, does not ask it anything, and shows
up nowhere in it. A person reading the Machines page saw "no linked machines"
while six machines held the store — which is the same failure the vault screen
had: a page that is accurate about what it tracks and misleading about what it
implies.

This module exists to end that. It discovers those peers and reports them as
what they are: machines that receive this store WITHOUT a PassBook grant. It
deliberately does not make them look like links. A tailnet peer is trusted
because it is on the tailnet, and a linked machine is trusted because both ends
compared a fingerprint; showing them as one list would be the more comfortable
lie.

Read-only, on purpose. Nothing here sends, receives or changes a credential.

  * Tailnet IPs are never returned. They are used to probe a port and then
    dropped: an IP is the one part of this that must not end up in a log, a
    screenshot, or a note. Hostnames identify a machine to a person perfectly
    well.
  * Every failure is "no peers", never an exception. A credential manager that
    cannot open its own Machines page because Tailscale is not running is worse
    than one that says it cannot see the fleet.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

# The ports a HivemindOS collector may answer on. A peer that answers one of
# these is a peer that participates in env replication; a peer that does not is
# on the tailnet but not in the fleet.
COLLECTOR_PORTS = ("8798", "8799", "8787")
PROBE_TIMEOUT = 0.35
_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

# How long a discovery answer stays good, and where it is kept.
#
# Every probe is a TCP connect to another machine, and `describe()` sits inside
# `passbook state`, which the window calls every five seconds. Unmeasured, that
# was nineteen blocking connects per call and 2.9 of the 3.5 seconds the whole
# state command took — the window spent two of every five seconds asking the
# tailnet a question whose answer changes when someone reboots a laptop.
#
# So the answer is cached across processes: the CLI is a new process each time
# and has nowhere else to keep one. Only what `describe()` already returns is
# written, which is hostnames and ports — never an address.
CACHE_FILENAME = ".passbook-fleet.json"
CACHE_SECONDS = 45.0

# Probes run together rather than one after another. They are independent waits
# on unrelated machines, and done in sequence one unreachable peer delays every
# peer behind it by the full timeout.
PROBE_WORKERS = 12

_STATUS_CACHE: dict[str, Any] | None = None


def available() -> tuple[bool, str]:
    """Can this machine see a tailnet at all?"""
    if _tailscale_cli():
        return True, "tailscale"
    return False, "no tailscale CLI on this machine"


def _tailscale_cli() -> str:
    explicit = os.environ.get("PASSBOOK_TAILSCALE_CLI", "").strip()
    if explicit:
        return explicit
    found = shutil.which("tailscale")
    if found:
        return found
    # The macOS App Store build does not put itself on PATH.
    packaged = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    return packaged if os.path.exists(packaged) else ""


def _status() -> dict[str, Any]:
    """`tailscale status`, run at most once per process.

    `describe()` used to call this three times — once to check the tailnet was
    there, once for the peers and once for this machine — and each call is a
    subprocess. They cannot disagree within one command, so they share an answer.
    """
    global _STATUS_CACHE
    if _STATUS_CACHE is not None:
        return _STATUS_CACHE
    _STATUS_CACHE = _read_status()
    return _STATUS_CACHE


def _read_status() -> dict[str, Any]:
    cli = _tailscale_cli()
    if not cli:
        return {}
    try:
        done = subprocess.run([cli, "status", "--json"], capture_output=True,
                              text=True, timeout=6)
    except (OSError, subprocess.SubprocessError):
        return {}
    if done.returncode != 0 or not done.stdout.strip():
        return {}
    try:
        parsed = json.loads(done.stdout)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _reachable_collector(ip: str) -> str:
    """Which collector port this peer answers on, or "" for none.

    A TCP connect, not an HTTP request: this is asking "is the fleet running
    here", and a body would tell us nothing more while costing a round trip per
    peer on a page that redraws.
    """
    for port in COLLECTOR_PORTS:
        try:
            with socket.create_connection((ip, int(port)), timeout=PROBE_TIMEOUT):
                return port
        except OSError:
            continue
    return ""


def _clean_host(peer: dict[str, Any]) -> str:
    dns = str(peer.get("DNSName") or "").rstrip(".")
    if dns:
        return dns.split(".")[0] if dns.count(".") > 1 else dns
    return str(peer.get("HostName") or "").strip()


def peers(*, probe: bool = True) -> list[dict[str, Any]]:
    """Online tailnet machines, with whether each runs a fleet collector.

    Never returns an address. The IP is used to probe and then discarded.
    """
    data = _status()
    if not data:
        return []
    found: list[tuple[dict[str, Any], str]] = []
    for entry in (data.get("Peer") or {}).values():
        if not isinstance(entry, dict) or entry.get("Online") is False:
            continue
        host = _clean_host(entry)
        if not host:
            continue
        ip = next((str(v) for v in entry.get("TailscaleIPs") or []
                   if _IPV4.match(str(v))), "")
        found.append(({
            "host": host,
            "os": str(entry.get("OS") or "").lower(),
            # "replicates" is the honest word. It does not say the peer is
            # trusted or granted anything; it says this store reaches it.
            "replicates": False,
            "collector_port": "",
        }, ip if probe else ""))

    ports = _probe_all([ip for _, ip in found])
    for (row, ip), port in zip(found, ports):
        row["collector_port"] = port
        row["replicates"] = bool(port)
    return sorted((row for row, _ in found), key=lambda row: row["host"])


def _probe_all(addresses: list[str]) -> list[str]:
    """Probe every peer at once. Order is preserved; a blank address stays blank.

    Sequentially this cost one full timeout per unreachable peer, paid by every
    peer after it. The waits are independent, so they overlap: the whole sweep
    now takes about as long as the slowest single peer.
    """
    if not any(addresses):
        return ["" for _ in addresses]
    live = [ip for ip in addresses if ip]
    with ThreadPoolExecutor(max_workers=min(PROBE_WORKERS, len(live))) as pool:
        answers = dict(zip(live, pool.map(_reachable_collector, live)))
    return [answers.get(ip, "") if ip else "" for ip in addresses]


def reachable(*, timeout: float = PROBE_TIMEOUT) -> list[dict[str, str]]:
    """Peers running a collector, WITH the address needed to reach them.

    Separate from `peers()` because this is the only thing that may see an
    address, and it exists to be handed straight to a socket. Nothing here is
    stored, logged or returned to a window: `describe()` is what the app gets,
    and it has no address in it.
    """
    data = _status()
    out: list[dict[str, str]] = []
    for entry in (data.get("Peer") or {}).values():
        if not isinstance(entry, dict) or entry.get("Online") is False:
            continue
        host = _clean_host(entry)
        ip = next((str(v) for v in entry.get("TailscaleIPs") or []
                   if _IPV4.match(str(v))), "")
        if not host or not ip:
            continue
        port = _reachable_collector(ip)
        if port:
            out.append({"host": host, "address": ip, "port": port})
    return sorted(out, key=lambda row: row["host"])


def this_machine() -> dict[str, Any]:
    data = _status()
    me = data.get("Self") if isinstance(data.get("Self"), dict) else {}
    return {"host": _clean_host(me) if me else "", "os": str(me.get("OS") or "").lower()}


def _cache_path(root: Path | None = None) -> Path:
    if root is not None:
        return Path(root) / CACHE_FILENAME
    import passbook

    return passbook.root() / CACHE_FILENAME


def _cached(root: Path | None = None) -> dict[str, Any] | None:
    """A recent discovery, or None. Never raises: a bad cache is no cache."""
    try:
        path = _cache_path(root)
        held = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(held, dict):
            return None
        if time.time() - float(held.get("at") or 0) > CACHE_SECONDS:
            return None
        answer = held.get("fleet")
        return answer if isinstance(answer, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def _remember(answer: dict[str, Any], root: Path | None = None) -> None:
    """Keep a discovery for the next process. Failing to is not an error."""
    try:
        path = _cache_path(root)
        path.write_text(json.dumps({"at": time.time(), "fleet": answer}),
                        encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass


def describe(*, probe: bool = True, fresh: bool = False,
             root: Path | None = None) -> dict[str, Any]:
    """What the Machines page needs, in one call.

    Answered from a recent cache when there is one. Discovery is a sweep of TCP
    connects across the tailnet, and it sat on the path of a command the window
    runs every five seconds; a peer that went offline a moment ago is worth
    knowing about, but not twelve times a minute. `fresh=True` skips the cache
    for the case where somebody pressed refresh and means it.
    """
    if not fresh and probe:
        held = _cached(root)
        if held is not None:
            return {**held, "cached": True}

    ok, detail = available()
    if not ok:
        return {"available": False, "detail": detail, "peers": [], "replicating": 0}
    found = peers(probe=probe)
    replicating = [row for row in found if row["replicates"]]
    answer = {
        "available": True,
        "detail": "tailnet peers discovered from this machine",
        "self": this_machine(),
        "peers": found,
        "replicating": len(replicating),
    }
    if probe:
        _remember(answer, root)
    return answer
