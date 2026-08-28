# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Replicating this store to the machines that share your tailnet.

Ported from HivemindOS's `hive-env-add`, which grew this over months against a
real fleet and got the hard parts right. What it never had was an opinion about
whether a key was allowed to leave. That is what this adds.

THE RULE, and it comes from the scope words themselves rather than from
anything invented here:

    workspace   "this workspace only"                        -> never leaves
    machine     "every workspace on this machine"            -> never leaves
    tailnet     "every workspace here, and lendable to
                 linked machines"                            -> may replicate

So a key replicates if, and only if, its reach is `tailnet`. Before this, every
key replicated regardless — the reach dropdown in the app was a control that
looked like it constrained something and did not. Every key on this machine
happens to be at `tailnet` today, so switching this on changes nothing
immediately; it starts mattering the first time somebody narrows one, which is
exactly when they will believe it works.

The parts that were already right, kept deliberately intact:

  * NEWEST-WINS PER KEY, from an `updatedAt` map beside the store. Not file
    mtime, which moves when any key changes.
  * TOMBSTONES. A key removed locally keeps its timestamp, so a peer holding an
    older copy cannot resurrect it.
  * NEVER OVERWRITE BLIND. A local value with no recorded age is left alone
    rather than assumed old.
  * COMPARE SECRETS, NOT REPRESENTATIONS. A sealed local copy and a peer's
    plaintext are never byte-equal for the same secret; comparing unopened
    reports a difference every pass and newest-wins then replaces the encrypted
    copy with the readable one, key by key, forever. That is not hypothetical:
    it decrypted 192 of 262 keys on this machine.
  * PLAINTEXT ON THE WIRE, CIPHERTEXT ON THE DISK. A `hive-sealed:` blob is
    meaningless to any other machine, so serving one hands over a credential
    that fails later for a reason that names nothing. A value that cannot be
    opened is withheld — absent is a gap a peer can fill.
  * SEAL ON THE WAY IN, or write nothing. There is deliberately no plaintext
    fallback; the fallback is the hole.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
WIRE_TIMEOUT = 20.0

# A local value that exists but could not be opened. Not None and not a string,
# so it can never accidentally compare equal to a peer's value.
UNOPENED = object()

# Per-machine credentials that must never replicate, inbound or outbound. Each
# machine mints its own; one machine's push clobbering another's breaks that
# machine's auth. Mirrors hive-env-add's list, which learned this the hard way.
LOCAL_ONLY = frozenset({
    "HIVEMINDOS_DASHBOARD_AUTH_SECRET",
    "HIVEMINDOS_DASHBOARD_DEVICE_TOKEN",
    "HIVE_AGENT_ENV_FILE",
    "HIVE_ENV_BACKUP_DIR",
    "HIVE_ENV_COLLECTOR_PORT",
    "HIVE_ENV_COLLECTOR_PORTS",
    "HIVE_ENV_FILE",
})
LOCAL_ONLY_PREFIXES = ("HIVE_ENV_TAILNET_", "HIVE_LINK_")


def _looks_sealed(value: str) -> bool:
    """Any generation of PassBook ciphertext, without importing the vault.

    Deliberately a prefix test rather than a call into `passbook_vault`: this
    runs on every key of every payload from every peer, and the question is
    only "is this a blob", which the prefix answers.
    """
    return isinstance(value, str) and value.startswith("hive-sealed:")


def is_local_only(key: str) -> bool:
    return key in LOCAL_ONLY or key.startswith(LOCAL_ONLY_PREFIXES)


# ── the age map ────────────────────────────────────────────────────────────

def meta_path(store: Path) -> Path:
    return Path(store).with_name(Path(store).name + ".meta.json")


def read_meta(store: Path) -> dict[str, float]:
    try:
        data = json.loads(meta_path(store).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    updated = data.get("updatedAt") if isinstance(data, dict) else None
    if not isinstance(updated, dict):
        return {}
    return {str(k): float(v) for k, v in updated.items()
            if isinstance(v, (int, float))}


def write_meta(store: Path, updated: Mapping[str, float]) -> None:
    import passbook

    passbook._atomic_write(
        meta_path(store),
        json.dumps({"version": 1, "updatedAt": dict(sorted(updated.items()))},
                   indent=2) + "\n")


def touch_meta(store: Path, keys: Iterable[str], *, when: float | None = None) -> None:
    """Stamp keys as changed now. Also how a tombstone is written: a removed
    key keeps its stamp so a peer's older copy cannot bring it back."""
    names = [str(k) for k in keys if str(k)]
    if not names:
        return
    updated = read_meta(store)
    stamp = time.time() if when is None else float(when)
    for name in names:
        updated[name] = stamp
    write_meta(store, updated)


# ── the policy gate: the reason this module exists ─────────────────────────

def may_leave_machine(key: str, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """May this key be sent to another machine at all?

    Decided from the key's reach and nothing else. `workspace` and `machine`
    both mean "not off this box"; only `tailnet` says otherwise, and it says so
    in as many words: "lendable to linked machines".
    """
    if is_local_only(key):
        return {"allowed": False, "why": "per-machine credential; each machine mints its own"}
    try:
        import passbook_access
    except ImportError:
        # Without the policy module there is no reach to consult. Historic
        # behaviour was to send everything; keep it rather than silently
        # stopping a fleet's replication on an install that never had scopes.
        return {"allowed": True, "why": "no policy installed; historic behaviour"}
    if policy is None:
        policy = passbook_access.read_policy()
    rule = passbook_access.scope_for(key, policy)
    scope = rule.get("scope", passbook_access.DEFAULT_SCOPE)
    if scope == "tailnet":
        return {"allowed": True, "why": "reaches linked machines"}
    return {"allowed": False,
            "why": f"reach is `{scope}`, which does not leave this machine"}


def sendable(values: Mapping[str, str], *,
             policy: Mapping[str, Any] | None = None) -> tuple[dict[str, str], dict[str, str]]:
    """Split a store into what may leave and what may not, with reasons."""
    try:
        import passbook_access

        if policy is None:
            policy = passbook_access.read_policy()
    except ImportError:
        policy = None
    allowed: dict[str, str] = {}
    withheld: dict[str, str] = {}
    for key, value in values.items():
        verdict = may_leave_machine(key, policy)
        if verdict["allowed"]:
            allowed[key] = value
        else:
            withheld[key] = verdict["why"]
    return allowed, withheld


# ── what this machine serves to a peer ─────────────────────────────────────

def serve(values: Mapping[str, str], store: Path, *,
          policy: Mapping[str, Any] | None = None,
          opener=None) -> dict[str, Any]:
    """The payload a peer receives when it asks this machine for the store.

    Two filters, in order: policy first (may this key leave at all), then
    opening (can this machine still read it). A key failing either is absent
    rather than sent as something unusable.
    """
    allowed, withheld = sendable(values, policy=policy)
    opened, still_sealed = _open_for_wire(allowed, opener=opener)
    updated = read_meta(store)
    return {
        "ok": True,
        "version": 1,
        "values": opened,
        "updatedAt": {key: updated.get(key, 0) for key in opened},
        "withheldByPolicy": sorted(withheld),
        "withheldSealed": sorted(still_sealed),
    }


def _open_for_wire(values: Mapping[str, str], *, opener=None) -> tuple[dict[str, str], list[str]]:
    """Plaintext for what opens; the rest LEFT OUT, never sent as ciphertext."""
    import passbook_vault

    sealed = [k for k, v in values.items() if passbook_vault.is_sealed(v)
              or passbook_vault.is_sealed_v1(v)]
    if not sealed:
        return dict(values), []
    opened = (opener or _open_via_broker)(sealed)
    out = dict(values)
    still: list[str] = []
    for key in sealed:
        plain = opened.get(key)
        if plain:
            out[key] = plain
        else:
            del out[key]
            still.append(key)
    return out, still


def _open_via_broker(keys: list[str]) -> dict[str, str]:
    import passbook

    try:
        return passbook.request(keys, app="passbook-sync",
                                reason="serve the shared store to a tailnet peer")
    except Exception:  # noqa: BLE001 — a shut vault is "nothing opens", not a crash
        return {}


# ── fetching a peer's store ────────────────────────────────────────────────

def fetch(host: str, port: str, *, address: str = "",
          timeout: float = WIRE_TIMEOUT) -> dict[str, Any] | None:
    """One peer's payload, or None when it cannot be reached or does not agree.

    `address` is used to connect and never retained: an address is the one part
    of this that must not end up in a log or a screenshot.
    """
    where = address or host
    url = f"http://{where}:{port}/env?scope=shared&runtime=passbook"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 — an unreachable peer is not an error here
        return None
    if not isinstance(data, dict) or data.get("ok") is not True:
        return None
    return data


# ── the merge ──────────────────────────────────────────────────────────────

def plan_repair(peer_payload: Mapping[str, Any], local_values: Mapping[str, str], *,
                policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Keys where a peer holds ciphertext that this machine can replace.

    A peer serving `hive-sealed:` is holding a blob sealed under some other
    machine's data key — usually this one's, from before sync learned to open
    values on the way out. That key never leaves the machine that made it, so
    the peer cannot open the blob, now or ever. Every agent there asking for
    that credential gets a string that passes every "looks like a token" check
    and fails at the far end for a reason that names nothing.

    Push-missing cannot fix it: the peer HAS the key, so nothing is missing.
    The only repair is to overwrite, which is why this is its own verb rather
    than something a normal pass does quietly.
    """
    theirs = peer_payload.get("values") if isinstance(peer_payload.get("values"), dict) else {}
    broken = [key for key, value in theirs.items() if _looks_sealed(value)]
    allowed, withheld = sendable({k: local_values.get(k, "") for k in broken}, policy=policy)
    fixable = {key: local_values[key] for key in allowed
               if local_values.get(key) and not _looks_sealed(local_values[key])}
    return {
        "broken": sorted(broken),
        "repair": fixable,
        "cannotOpen": sorted(k for k in allowed if k not in fixable),
        "withheldByPolicy": sorted(withheld),
    }


def push(host: str, port: str, values: Mapping[str, str], *, address: str = "",
         timeout: float = WIRE_TIMEOUT) -> tuple[bool, str]:
    """Send values to a peer's collector. Plaintext on the wire, by contract.

    Refuses to send ciphertext even if a caller asks: a blob is exactly what
    this is repairing, and sending one would be the bug reintroducing itself.
    """
    blobs = [key for key, value in values.items() if _looks_sealed(value)]
    if blobs:
        return False, f"refusing to send {len(blobs)} sealed value(s); the wire carries plaintext"
    if not values:
        return True, ""
    payload = json.dumps({"scope": "shared", "runtime": "passbook",
                          "entries": dict(values)}).encode("utf-8")
    where = address or host
    request = urllib.request.Request(
        f"http://{where}:{port}/env", data=payload,
        headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            answer = json.loads(response.read().decode("utf-8") or "{}")
    except Exception as error:  # noqa: BLE001 — an unreachable peer is not a crash
        return False, str(error)
    if answer.get("ok") is True:
        return True, ""
    return False, str(answer.get("error") or "the collector refused it")


def plan_pull(local_values: Mapping[str, Any], local_meta: Mapping[str, float],
              payloads: Iterable[tuple[str, Mapping[str, Any]]]) -> dict[str, Any]:
    """What a pull WOULD change, given local state and what peers offered.

    Pure: no network, no disk, no clock. Every rule that decides whether a
    peer's value replaces a local one lives here so it can be tested directly
    and read in one place.
    """
    candidates: dict[str, tuple[str, float, str]] = {}
    sealed_from_peers: list[str] = []
    for host, payload in payloads:
        raw = payload.get("values")
        if not isinstance(raw, dict):
            continue
        ages = payload.get("updatedAt") if isinstance(payload.get("updatedAt"), dict) else {}
        for key, value in raw.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if not KEY_RE.match(key) or is_local_only(key):
                continue
            if _looks_sealed(value):
                # A peer's `hive-sealed:` blob is sealed under THAT machine's
                # data key, which never leaves it. Accepting one stores a value
                # nothing here can ever open, and — worse — it compares unequal
                # to the real secret forever, so newest-wins rewrites it every
                # pass. Peers running pre-fix code still serve these; refusing
                # them is what stops one machine's staleness spreading.
                sealed_from_peers.append(key)
                continue
            age_raw = ages.get(key)
            age = float(age_raw) if isinstance(age_raw, (int, float)) else 0.0
            best = candidates.get(key)
            if best is None or age > best[1]:
                candidates[key] = (value, age, host)

    apply: dict[str, tuple[str, float, str]] = {}
    skipped_unknown_age: list[str] = []
    skipped_shut: list[str] = []
    for key, (value, age, source) in sorted(candidates.items()):
        local_age = float(local_meta.get(key, 0.0))
        if key in local_values:
            local = local_values[key]
            if local is UNOPENED:
                # Refusing to compare is refusing to overwrite: without the
                # secret there is no telling "the peer agrees" from "the peer is
                # newer", and guessing wrong writes plaintext over a sealed value.
                skipped_shut.append(key)
                continue
            if local == value:
                continue
            if age <= local_age:
                continue
            if local_age == 0.0:
                skipped_unknown_age.append(key)
                continue
        elif local_age and age <= local_age:
            # Tombstoned: removed here after the peer's copy was written.
            continue
        apply[key] = (value, age, source)

    return {
        "apply": {key: value for key, (value, _, _) in apply.items()},
        "sources": {key: source for key, (_, _, source) in apply.items()},
        "skippedUnknownAge": skipped_unknown_age,
        "skippedSealedShut": skipped_shut,
        "refusedSealedFromPeer": sorted(set(sealed_from_peers)),
    }


def plan_push(local_values: Mapping[str, str], local_meta: Mapping[str, float],
              peer_payload: Mapping[str, Any], *,
              policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What this machine WOULD send a peer: keys it lacks, that may leave.

    Also pure. The policy filter is applied here rather than at the socket so
    that a dry run reports exactly what a real run would send.
    """
    theirs = peer_payload.get("values") if isinstance(peer_payload.get("values"), dict) else {}
    allowed, withheld = sendable(local_values, policy=policy)
    missing = {key: value for key, value in allowed.items() if key not in theirs}
    return {
        "send": missing,
        "withheldByPolicy": sorted(withheld),
        "reasons": withheld,
        "updatedAt": {key: local_meta.get(key, 0.0) for key in missing},
    }
