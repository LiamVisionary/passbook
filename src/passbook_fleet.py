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


def fleet_disabled() -> bool:
    """`PASSBOOK_FLEET=off` hides the tailnet from this process and its children.

    The test suite sets it. A CLI test that ran `passbook add` once reached the
    developer's real peers, and their collectors stored the test's keys.
    """
    return os.environ.get("PASSBOOK_FLEET", "").strip().lower() in ("off", "0", "false", "no")


def _read_status() -> dict[str, Any]:
    if fleet_disabled():
        return {}
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


# ── company hosts ──────────────────────────────────────────────────────────
#
# HivemindOS can move a company to another computer, often a rented server,
# installed with `--company-host`. That computer keeps ONLY the keys its owner
# shares to it. On 2026-10-03 a fresh one held the whole store (~400 keys,
# wallet keys among them) four minutes after joining the tailnet. Its collector
# now says so in `/health` (`envSync.companyHost: true`, with `ready: false` for
# older peers), refuses `GET /env`, and acknowledges `POST /env` unwritten.
#
# Acknowledged unwritten is still received. The TCP probe above cannot tell a
# company host from any other collector, so before anything sends a value to a
# peer, or asks one for the store, the peer's `/health` is read and a company
# host is left out entirely: not a target, not a pull source, not "unreachable".
# A peer whose `/health` does not answer is treated as it always was.

HEALTH_TIMEOUT = 2.0
COMPANY_HOST_FILENAME = "company-host.env"
_TRUTHY = ("1", "true", "yes", "on")
_COMPANY_HOSTS_SEEN: list[str] = []


def collector_health(address: str, port: str, *,
                     timeout: float = HEALTH_TIMEOUT) -> dict[str, Any] | None:
    """A collector's `/health`, or None when it does not answer with JSON."""
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://{address}:{port}/health",
                                    timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 — no answer is "unknown", never a crash
        return None
    return data if isinstance(data, dict) else None


def is_company_host(health: Any) -> bool:
    """Does this `/health` say the machine keeps only keys shared to it?

    Read where the collector puts it (`envSync.companyHost`) and at the top
    level. Only a real `true` counts, as in HivemindOS's own reader.
    """
    if not isinstance(health, dict):
        return False
    if health.get("companyHost") is True:
        return True
    env_sync = health.get("envSync")
    return isinstance(env_sync, dict) and env_sync.get("companyHost") is True


def peer_is_company_host(address: str, port: str = "", *, every_port: bool = True,
                         timeout: float = HEALTH_TIMEOUT) -> bool:
    """Ask the peer. By default every collector port is checked, not only the
    one that answered a connect: a port can belong to another app on that
    machine (one of the fleet's Macs has a different app on 8787), and the
    company host's own collector could be on the next one. `every_port=False`
    asks only `port`, for a caller about to send to exactly that one."""
    ports = [port] if port else []
    if every_port or not ports:
        ports += [p for p in COLLECTOR_PORTS if p not in ports]
    return any(is_company_host(collector_health(address, p, timeout=timeout)) for p in ports)


def company_host_mode(root: Path | None = None) -> bool:
    """Is THIS machine a company host? Then it does not replicate at all.

    The marker is the one HivemindOS's setup writes (`HIVE_COMPANY_HOST=1` in
    `company-host.env` under the hive root) or the same variable in the
    environment. Mirrors `company_host_mode` in HivemindOS's `hive-env-add`.
    """
    if os.environ.get("HIVE_COMPANY_HOST", "").strip().lower() in _TRUTHY:
        return True
    try:
        if root is None:
            import passbook

            root = passbook.root()
        text = (Path(root) / COMPANY_HOST_FILENAME).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ImportError):
        return False
    value = ""
    for line in text.splitlines():
        match = re.match(r"^\s*HIVE_COMPANY_HOST\s*=\s*(.*)$", line)
        if match:
            value = match.group(1)
    return value.strip().strip("'\"").lower() in _TRUTHY


def reachable(*, timeout: float = PROBE_TIMEOUT) -> list[dict[str, str]]:
    """Peers running a collector, WITH the address needed to reach them.

    Separate from `peers()` because this is the only thing that may see an
    address, and it exists to be handed straight to a socket. Nothing here is
    stored, logged or returned to a window: `describe()` is what the app gets,
    and it has no address in it.

    Company hosts are not in it: see `reachable_split`. The ones a call left
    out are kept for `company_hosts_seen()`, so callers (and the tests that
    replace this function) keep using `reachable()` as the one way in.
    """
    global _COMPANY_HOSTS_SEEN
    _COMPANY_HOSTS_SEEN = []
    found, company = reachable_split(timeout=timeout)
    _COMPANY_HOSTS_SEEN = company
    return found


def company_hosts_seen() -> list[str]:
    """Company hosts the latest `reachable()` call in this process left out.

    Host names only, never an address."""
    return list(_COMPANY_HOSTS_SEEN)


def reachable_split(*, timeout: float = PROBE_TIMEOUT) -> tuple[list[dict[str, str]], list[str]]:
    """`(peers to replicate with, names of company hosts left out)`.

    Every value PassBook sends and every store it pulls goes to a peer from
    here, so this is where a company host is removed. Probed together: each
    peer now costs a connect and a `/health` read.
    """
    data = _status()
    found: list[tuple[str, str]] = []
    for entry in (data.get("Peer") or {}).values():
        if not isinstance(entry, dict) or entry.get("Online") is False:
            continue
        host = _clean_host(entry)
        ip = next((str(v) for v in entry.get("TailscaleIPs") or []
                   if _IPV4.match(str(v))), "")
        if host and ip:
            found.append((host, ip))
    if not found:
        return [], []

    def look(ip: str) -> tuple[str, bool]:
        port = _reachable_collector(ip)
        return port, bool(port) and peer_is_company_host(ip, port)

    with ThreadPoolExecutor(max_workers=min(PROBE_WORKERS, len(found))) as pool:
        answers = list(pool.map(look, [ip for _, ip in found]))
    out: list[dict[str, str]] = []
    company: list[str] = []
    for (host, ip), (port, is_company) in zip(found, answers):
        if not port:
            continue
        if is_company:
            company.append(host)
        else:
            out.append({"host": host, "address": ip, "port": port})
    return sorted(out, key=lambda row: row["host"]), sorted(set(company))


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
