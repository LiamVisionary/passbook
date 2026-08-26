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
from typing import Any

# The ports a HivemindOS collector may answer on. A peer that answers one of
# these is a peer that participates in env replication; a peer that does not is
# on the tailnet but not in the fleet.
COLLECTOR_PORTS = ("8798", "8799", "8787")
PROBE_TIMEOUT = 0.35
_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


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
    out: list[dict[str, Any]] = []
    for entry in (data.get("Peer") or {}).values():
        if not isinstance(entry, dict) or entry.get("Online") is False:
            continue
        host = _clean_host(entry)
        if not host:
            continue
        ip = next((str(v) for v in entry.get("TailscaleIPs") or []
                   if _IPV4.match(str(v))), "")
        port = _reachable_collector(ip) if (probe and ip) else ""
        out.append({
            "host": host,
            "os": str(entry.get("OS") or "").lower(),
            # "replicates" is the honest word. It does not say the peer is
            # trusted or granted anything; it says this store reaches it.
            "replicates": bool(port),
            "collector_port": port,
        })
    return sorted(out, key=lambda row: row["host"])


def this_machine() -> dict[str, Any]:
    data = _status()
    me = data.get("Self") if isinstance(data.get("Self"), dict) else {}
    return {"host": _clean_host(me) if me else "", "os": str(me.get("OS") or "").lower()}


def describe(*, probe: bool = True) -> dict[str, Any]:
    """What the Machines page needs, in one call."""
    ok, detail = available()
    if not ok:
        return {"available": False, "detail": detail, "peers": [], "replicating": 0}
    found = peers(probe=probe)
    replicating = [row for row in found if row["replicates"]]
    return {
        "available": True,
        "detail": "tailnet peers discovered from this machine",
        "self": this_machine(),
        "peers": found,
        "replicating": len(replicating),
    }
