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
import math
import os
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

# ── keys with no timestamp ─────────────────────────────────────────────────


def plan_backfill(names: Iterable[str], meta: Mapping[str, float]) -> list[str]:
    """Keys carrying no `updatedAt`, which are frozen out of sync BOTH ways.

    A key lands in the store with no timestamp whenever something writes it
    outside the sanctioned path — a hand edit, an older writer, a tool that
    knows the file but not the meta. `plan_pull` then reads its age as 0.0 and
    refuses to overwrite it, while `serve` offers it as `updatedAt: 0` so no
    peer will adopt it either. The key is stuck on whichever machine wrote it
    and diverges silently the moment anyone edits it somewhere else.

    Stamping makes it eligible again. Pure, so the caller decides the clock.
    """
    return sorted(name for name in names
                  if str(name) and not float(meta.get(str(name), 0.0) or 0.0))


# ── keys that have not reached every peer ──────────────────────────────────
#
# A push can fail for reasons that have nothing to do with the key: a peer
# asleep, a collector restarting, a tailnet that has not converged. Without a
# record, that key is simply absent there until somebody happens to change it
# again — which on a fleet means "until somebody notices", and the last time
# nobody noticed for a day.
#
# So a failed delivery is written down per key per host, and retried. The file
# holds NAMES and timestamps, never values: it is bookkeeping about replication,
# not a second copy of the store.

PENDING_FILENAME = "sync-pending.json"


def pending_path(root: Path | None = None) -> Path:
    import passbook

    return (Path(root) if root is not None else passbook.root()) / PENDING_FILENAME


def read_pending(root: Path | None = None) -> dict[str, dict[str, Any]]:
    """What is still owed to which peers. Unreadable bookkeeping is empty."""
    try:
        data = json.loads(pending_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    entries = data.get("pending") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, raw in entries.items():
        if not isinstance(key, str) or not KEY_RE.match(key) or not isinstance(raw, dict):
            continue
        owed = raw.get("owed")
        stamped = raw.get("ts")
        out[key] = {
            "ts": float(stamped) if isinstance(stamped, (int, float)) else 0.0,
            "owed": sorted({str(h) for h in owed if str(h)}) if isinstance(owed, list) else [],
        }
    return {k: v for k, v in out.items() if v["owed"]}


def write_pending(entries: Mapping[str, Mapping[str, Any]], root: Path | None = None) -> Path:
    path = pending_path(root)
    payload = {"version": 1, "pending": {
        key: {"ts": float(entry.get("ts") or 0.0),
              "owed": sorted({str(h) for h in (entry.get("owed") or []) if str(h)})}
        for key, entry in sorted(entries.items())
        if entry.get("owed")}}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return path


def note_undelivered(keys: Iterable[str], hosts: Iterable[str], *,
                     when: float | None = None, root: Path | None = None) -> dict[str, dict[str, Any]]:
    """Record that these keys did not reach these hosts. Additive."""
    stamp = time.time() if when is None else float(when)
    entries = read_pending(root)
    owed_hosts = sorted({str(h) for h in hosts if str(h)})
    if not owed_hosts:
        return entries
    for key in keys:
        name = str(key)
        if not name or not KEY_RE.match(name):
            continue
        entry = entries.setdefault(name, {"ts": stamp, "owed": []})
        entry["ts"] = stamp
        entry["owed"] = sorted({*entry.get("owed", []), *owed_hosts})
    write_pending(entries, root)
    return entries


def note_delivered(keys: Iterable[str], host: str, *, root: Path | None = None) -> dict[str, dict[str, Any]]:
    """Clear a debt. A key owed to nobody stops being pending at all."""
    entries = read_pending(root)
    target = str(host)
    for key in keys:
        entry = entries.get(str(key))
        if not entry:
            continue
        entry["owed"] = [h for h in entry.get("owed", []) if h != target]
    entries = {k: v for k, v in entries.items() if v["owed"]}
    write_pending(entries, root)
    return entries


def plan_retry(pending: Mapping[str, Mapping[str, Any]],
               reachable: Iterable[str]) -> dict[str, list[str]]:
    """Which keys to resend to which reachable host. Pure.

    A host that is still unreachable keeps its debt rather than losing it: the
    point of the queue is that an absence survives the outage that caused it.
    """
    live = {str(h) for h in reachable if str(h)}
    plan: dict[str, list[str]] = {}
    for key, entry in pending.items():
        for host in entry.get("owed", []):
            if host in live:
                plan.setdefault(host, []).append(str(key))
    return {host: sorted(keys) for host, keys in sorted(plan.items())}


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

def plan_bootstrap(orphaned: Iterable[str],
                   payloads: Iterable[tuple[str, Mapping[str, Any]]], *,
                   policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Recover peer values for ciphertext whose local vault profile is absent.

    This only plans a recovery; it never opens, writes, or fetches anything.
    The caller must verify the missing-profile condition and require BOTH
    `missing` and `conflicts` to be empty before initializing a local vault.
    Resolved values remain private input to that initialization, never output.

    Only requested names may be recovered, within the same reach rules as
    ordinary replication. Matching peer values need no ages. Differing values
    require a known age on every copy and one strictly newest value, so a peer
    with missing metadata cannot silently lose to another peer's dated copy.
    """
    requested = {name for name in orphaned if isinstance(name, str)}
    allowed, _ = sendable({name: "" for name in requested if KEY_RE.fullmatch(name)},
                          policy=policy)
    candidates: dict[str, list[tuple[str, float]]] = {name: [] for name in allowed}
    for _, payload in payloads:
        if not isinstance(payload, Mapping) or payload.get("ok") is not True:
            continue
        values = payload.get("values")
        if not isinstance(values, Mapping):
            continue
        ages = payload.get("updatedAt")
        if not isinstance(ages, Mapping):
            ages = {}
        for name in allowed:
            value = values.get(name)
            if not isinstance(value, str) or not value.strip() or _looks_sealed(value):
                continue
            stamp = ages.get(name)
            try:
                age = float(stamp) if isinstance(stamp, (int, float)) \
                    and not isinstance(stamp, bool) else 0.0
            except OverflowError:
                age = 0.0
            if not math.isfinite(age) or age <= 0:
                age = 0.0
            candidates[name].append((value, age))

    recovered: dict[str, str] = {}
    conflicts: list[str] = []
    for name, copies in sorted(candidates.items()):
        if not copies:
            continue
        unique = {value for value, _ in copies}
        if len(unique) == 1:
            recovered[name] = copies[0][0]
            continue
        if all(age > 0 for _, age in copies):
            newest = max(age for _, age in copies)
            winners = {value for value, age in copies if age == newest}
            if len(winners) == 1:
                recovered[name] = winners.pop()
                continue
        conflicts.append(name)

    return {"values": recovered,
            "missing": sorted(requested - recovered.keys() - set(conflicts)),
            "conflicts": conflicts}


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


CONFLICT_POLICIES = ("newest", "local-wins", "remote-wins", "fail")


def plan_pull(local_values: Mapping[str, Any], local_meta: Mapping[str, float],
              payloads: Iterable[tuple[str, Mapping[str, Any]]],
              *, conflict: str = "newest") -> dict[str, Any]:
    """What a pull WOULD change, given local state and what peers offered.

    Pure: no network, no disk, no clock. Every rule that decides whether a
    peer's value replaces a local one lives here so it can be tested directly
    and read in one place.

    `conflict` decides what happens when both sides hold a value and they
    differ. `newest` is the default and the only one that needs timestamps:

      newest       the later `updatedAt` wins; an unknown local age holds
      local-wins   never overwrite a value this machine already has
      remote-wins  take the peer's copy whatever the ages say
      fail         change nothing and report every disagreement

    `local-wins` and `remote-wins` still refuse a peer's ciphertext and still
    refuse to guess at a value the vault will not open: those are not conflict
    resolution, they are cases where there is nothing to compare.
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

    wanted = str(conflict or "newest").strip().lower()
    if wanted not in CONFLICT_POLICIES:
        raise ValueError(f"conflict must be one of {', '.join(CONFLICT_POLICIES)}")

    apply: dict[str, tuple[str, float, str]] = {}
    skipped_unknown_age: list[str] = []
    skipped_shut: list[str] = []
    disagreed: list[str] = []
    held_by_policy: list[str] = []
    for key, (value, age, source) in sorted(candidates.items()):
        local_age = float(local_meta.get(key, 0.0))
        if key in local_values:
            local = local_values[key]
            if local is UNOPENED:
                # Refusing to compare is refusing to overwrite: without the
                # secret there is no telling "the peer agrees" from "the peer is
                # newer", and guessing wrong writes plaintext over a sealed value.
                # No conflict policy reaches this — there is nothing to compare.
                skipped_shut.append(key)
                continue
            if local == value:
                continue
            disagreed.append(key)
            if wanted == "local-wins":
                held_by_policy.append(key)
                continue
            if wanted == "fail":
                continue
            if wanted == "newest":
                if age <= local_age:
                    continue
                if local_age == 0.0:
                    skipped_unknown_age.append(key)
                    continue
            # remote-wins falls through: the peer's copy is taken as given.
        elif local_age and age <= local_age:
            # Tombstoned: removed here after the peer's copy was written.
            continue
        apply[key] = (value, age, source)

    if wanted == "fail" and disagreed:
        # Report, change nothing. Half-applying a run the caller asked to abort
        # is the worst of both answers.
        apply = {}

    return {
        "apply": {key: value for key, (value, _, _) in apply.items()},
        "sources": {key: source for key, (_, _, source) in apply.items()},
        "skippedUnknownAge": skipped_unknown_age,
        "skippedSealedShut": skipped_shut,
        "refusedSealedFromPeer": sorted(set(sealed_from_peers)),
        "conflict": wanted,
        "disagreed": sorted(set(disagreed)),
        "heldByConflictPolicy": sorted(set(held_by_policy)),
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

    # A key absent from a peer's payload is not necessarily a key the peer
    # LACKS. `serve` leaves out anything it could not open, so a peer whose
    # vault is shut offers a short list of exactly the values it can read — and
    # seeding it "what it is missing" would rewrite hundreds of keys it already
    # has. Measured: this machine's own collector served 18 of 305, and a blind
    # push-missing would have re-sent the other 286.
    #
    # So the peer has to SAY it withheld nothing. `withheldSealed` is part of
    # the serve contract; a payload without the field is an older or foreign
    # server that cannot tell us, and the answer there is to send nothing rather
    # than to guess. An absent key is a gap a later pass can fill; an overwrite
    # is not undoable.
    unopenable = peer_payload.get("withheldSealed")
    if not isinstance(unopenable, list):
        return {
            "send": {},
            "withheldByPolicy": sorted(withheld),
            "reasons": withheld,
            "updatedAt": {},
            "cannotTell": True,
        }

    shut = {str(name) for name in unopenable}
    missing = {key: value for key, value in allowed.items()
               if key not in theirs and key not in shut}
    return {
        "send": missing,
        "withheldByPolicy": sorted(withheld),
        "reasons": withheld,
        "updatedAt": {key: local_meta.get(key, 0.0) for key in missing},
        "heldBackAsUnopenableThere": sorted(shut & set(allowed)),
        "cannotTell": False,
    }
