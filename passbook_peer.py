# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Who is on the other end of the socket, when the system can vouch for it.

Optional companion to `passbook_broker.py`, macOS only for now.

## The gap this closes, and the one it cannot

The broker's headline limit has always been that anything running as you can
connect and claim to be any app, because nothing in a request proves otherwise.
On macOS that is fixable for one category of caller: ask the kernel for the
connecting process, hand that to the code-signing machinery, and check the
result against a requirement naming your Developer ID team. The claim in the
JSON stops mattering.

**It only works for signed bundles.** A script, a CLI tool and an agent are all
run by the same interpreter, so they all present that interpreter's signature.
This can prove *an* Apple-signed Python is calling; it can never tell one script
from another. That is not a gap to engineer around — it is what process identity
means on a shared runtime.

So the answer here is three-valued, never two:

  verified    the caller is a bundle whose signature satisfies the requirement
  unsigned    the caller is real, and carries no identity worth checking
  unknown     the platform, or this build, cannot tell

An `unknown` must never be treated as `verified`, and an `unsigned` must never be
treated as an attacker — most honest software on the machine is unsigned.

## Why the kernel, and not the path

It is tempting to read the peer's pid, look up its executable path, and run
`codesign --verify` on that file. Do not. The path can be replaced between the
lookup and the check, and a process can exec something else entirely; the answer
would describe a file rather than the process holding the socket.
`SecCodeCopyGuestWithAttributes` asks the kernel about *that* process, which is
the only question worth asking.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import sys
from typing import Any

__all__ = ["DEFAULT_REQUIREMENT", "available", "describe", "peer_identity", "requirement_for_team"]

# Apple's own anchor, plus the leaf OU that carries a Developer ID team.
DEFAULT_REQUIREMENT = 'anchor apple generic and certificate leaf[subject.OU] = "{team}"'

# <sys/un.h>: SOL_LOCAL is 0 and LOCAL_PEERPID is 2 on Darwin.
_SOL_LOCAL = 0
_LOCAL_PEERPID = 2

_KERN_SUCCESS = 0
_CS_DEFAULT_FLAGS = 0


def requirement_for_team(team: str) -> str:
    return DEFAULT_REQUIREMENT.format(team=team)


def available() -> bool:
    """Whether this platform can answer the question at all."""
    return sys.platform == "darwin" and _frameworks() is not None


_LOADED: dict[str, Any] | None = None


def _frameworks() -> dict[str, Any] | None:
    """Load Security and CoreFoundation once, or report that we cannot."""
    global _LOADED
    if _LOADED is not None:
        return _LOADED or None
    if sys.platform != "darwin":
        _LOADED = {}
        return None
    try:
        security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    except OSError:
        _LOADED = {}
        return None

    core.CFStringCreateWithCString.restype = ctypes.c_void_p
    core.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    core.CFNumberCreate.restype = ctypes.c_void_p
    core.CFNumberCreate.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    core.CFDictionaryCreate.restype = ctypes.c_void_p
    core.CFDictionaryCreate.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
    ]
    core.CFRelease.argtypes = [ctypes.c_void_p]

    security.SecCodeCopyGuestWithAttributes.restype = ctypes.c_int32
    security.SecCodeCopyGuestWithAttributes.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    security.SecRequirementCreateWithString.restype = ctypes.c_int32
    security.SecRequirementCreateWithString.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    security.SecCodeCheckValidity.restype = ctypes.c_int32
    security.SecCodeCheckValidity.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]

    _LOADED = {"security": security, "core": core}
    return _LOADED


def _cfstring(core, text: str) -> ctypes.c_void_p:
    return ctypes.c_void_p(core.CFStringCreateWithCString(None, text.encode("utf-8"), 0x08000100))


def peer_pid(sock: socket.socket) -> int | None:
    """The pid at the other end of a Unix socket, straight from the kernel."""
    try:
        return sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID)
    except (OSError, AttributeError):
        return None


def peer_identity(sock: socket.socket, *, team: str = "") -> dict[str, Any]:
    """Identify the caller. Returns a three-valued verdict, never a bare bool.

    `team` is the Developer ID team the caller must belong to. With no team
    given, the signature is checked for validity but not for whose it is —
    which is weaker than it looks, since anyone's Developer ID would pass.
    """
    pid = peer_pid(sock)
    if pid is None:
        return {"status": "unknown", "pid": None, "reason": "the socket did not report a peer"}

    loaded = _frameworks()
    if loaded is None:
        return {"status": "unknown", "pid": pid,
                "reason": "code identity is not checkable on this platform"}

    security, core = loaded["security"], loaded["core"]
    guest = ctypes.c_void_p()
    key = _cfstring(core, "pid")
    number = ctypes.c_void_p(core.CFNumberCreate(None, 3, ctypes.byref(ctypes.c_int32(pid))))
    keys = (ctypes.c_void_p * 1)(key)
    values = (ctypes.c_void_p * 1)(number)
    attributes = ctypes.c_void_p(core.CFDictionaryCreate(None, keys, values, 1, None, None))

    try:
        status = security.SecCodeCopyGuestWithAttributes(
            None, attributes, _CS_DEFAULT_FLAGS, ctypes.byref(guest))
        if status != _KERN_SUCCESS or not guest:
            # No code object at all. Almost always a process that is simply not
            # a signed bundle, which is the ordinary case rather than a threat.
            return {"status": "unsigned", "pid": pid,
                    "reason": f"no code identity for pid {pid} (OSStatus {status})"}

        requirement = ctypes.c_void_p()
        text = requirement_for_team(team) if team else "anchor apple generic"
        made = security.SecRequirementCreateWithString(
            _cfstring(core, text), _CS_DEFAULT_FLAGS, ctypes.byref(requirement))
        if made != _KERN_SUCCESS:
            return {"status": "unknown", "pid": pid,
                    "reason": f"could not build the requirement (OSStatus {made})"}

        valid = security.SecCodeCheckValidity(guest, _CS_DEFAULT_FLAGS, requirement)
        if valid == _KERN_SUCCESS:
            return {"status": "verified", "pid": pid, "team": team,
                    "reason": f"signature satisfies {text}"}
        return {"status": "unsigned", "pid": pid,
                "reason": f"signature does not satisfy the requirement (OSStatus {valid})"}
    finally:
        for handle in (attributes, number, key, guest):
            if handle:
                try:
                    core.CFRelease(handle)
                except Exception:  # noqa: BLE001 — releasing a null or foreign handle must not raise
                    pass


def describe(identity: dict[str, Any]) -> str:
    """One line for a record or a panel. Never overstates what was proven."""
    status = identity.get("status")
    if status == "verified":
        return f"verified bundle (pid {identity['pid']})"
    if status == "unsigned":
        return f"unsigned caller (pid {identity['pid']})"
    return f"caller not identifiable ({identity.get('reason', 'unknown')})"
