# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Caller identification: three-valued, and honest about which value it earned.

The whole point of code signing here was to stop "I am the Content Studio" being
a bare claim. It does — for bundles. These tests exist mostly to pin the part
that is easy to get wrong later: that `unknown` never quietly becomes
`verified`, and that `unsigned` is treated as ordinary rather than hostile.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_peer as peer

# Any well-formed Apple team id. These tests check the shape of a verdict and
# the text of a requirement, never whose signature it is, so a real team id
# here would only tie an open-source test suite to one organisation.
EXAMPLE_TEAM = "ABCDE12345"  # noqa: E402

darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="code identity is macOS-only")

# The verdict shape is checked over a Unix socket pair, which Windows does not
# have. Three tests errored at setup there rather than saying so.
needs_unix_sockets = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="a socket pair needs AF_UNIX")


@pytest.fixture
def pair():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        yield a, b
    finally:
        a.close()
        b.close()


@needs_unix_sockets
def test_the_verdict_is_always_one_of_three(pair):
    identity = peer.peer_identity(pair[0], team=EXAMPLE_TEAM)
    assert identity["status"] in {"verified", "unsigned", "unknown"}


@needs_unix_sockets
def test_every_verdict_carries_its_reason(pair):
    """A refusal with no cause is what makes people switch a policy off."""
    identity = peer.peer_identity(pair[0], team=EXAMPLE_TEAM)
    assert identity.get("reason")


@darwin_only
def test_the_kernel_reports_the_peer_pid(pair):
    """From the kernel, not from anything the caller said about itself."""
    assert peer.peer_pid(pair[0]) == __import__("os").getpid()


@darwin_only
def test_a_script_under_a_shared_interpreter_is_not_verified(pair):
    """The limit, asserted rather than described.

    This test process is Python. It can never be `verified`, no matter how it is
    launched, because the signature belongs to the interpreter and not to the
    script. Anything claiming otherwise has broken the meaning of the word.
    """
    identity = peer.peer_identity(pair[0], team=EXAMPLE_TEAM)
    assert identity["status"] != "verified"


@needs_unix_sockets
def test_an_unidentifiable_caller_is_unknown_not_verified(pair, monkeypatch):
    """Failing closed on the *label* matters more than failing closed on access:
    a caller we could not check must not be recorded as one we did."""
    monkeypatch.setattr(peer, "_frameworks", lambda: None)

    identity = peer.peer_identity(pair[0], team=EXAMPLE_TEAM)

    # The status is the claim, and it does not vary by platform.
    assert identity["status"] == "unknown"
    # The reason does. `LOCAL_PEERPID` is a macOS socket option, so elsewhere
    # the caller cannot be named at all and the verdict is reached one step
    # earlier. Both answers are honest. Pinning the macOS wording everywhere
    # failed this on Linux for a reason that had nothing to do with the claim.
    if peer.peer_pid(pair[0]) is None:
        assert identity["reason"] == "the socket did not report a peer"
    else:
        assert "not checkable" in identity["reason"]


def test_a_socket_with_no_peer_is_unknown():
    lonely = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        identity = peer.peer_identity(lonely, team=EXAMPLE_TEAM)
    finally:
        lonely.close()
    assert identity["status"] == "unknown"


def test_the_requirement_names_the_team():
    text = peer.requirement_for_team(EXAMPLE_TEAM)
    assert "anchor apple generic" in text
    assert f'subject.OU] = "{EXAMPLE_TEAM}"' in text


def test_describe_never_overstates_what_was_proven():
    assert "verified" in peer.describe({"status": "verified", "pid": 1})
    assert "unsigned" in peer.describe({"status": "unsigned", "pid": 1})
    unknown = peer.describe({"status": "unknown", "reason": "no peer"})
    assert "verified" not in unknown and "not identifiable" in unknown
