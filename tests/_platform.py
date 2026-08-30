# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What a claim about the filesystem means on a platform that has no POSIX modes."""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

import pytest

WINDOWS = os.name == "nt"


def assert_private(path: str | Path, expected: int = 0o600) -> None:
    """Assert `path` is readable only by its owner, where that can be asserted.

    Windows has no POSIX mode. `os.chmod` there sets one read-only flag and
    nothing else, so `st_mode` comes back 0o666 or 0o777 whatever the code
    asked for. Thirteen tests failed on Windows with `assert 438 == 384`,
    which is 0o666 against 0o600 and says nothing about what they check.

    The claim is real on POSIX and is carried by an inherited ACL on Windows,
    which this cannot read. So it is asserted where it means something and
    passed over where it does not, rather than the whole test being skipped
    and taking its other assertions with it.
    """
    if WINDOWS:
        return
    got = stat_module.S_IMODE(os.stat(path).st_mode)
    assert got == expected, f"{path} is {oct(got)}, expected {oct(expected)}"


# The broker's transport, and whether this platform has one.
#
# It used to be AF_UNIX or nothing, so every broker test skipped itself on
# Windows. That skip was load-bearing in the worst way: it meant the whole
# Windows job passed green while `passbook signin` could not run at all there,
# because reaching for `socket.AF_UNIX` raised AttributeError before any of it
# got going. There is a named pipe on Windows now, so these tests run
# everywhere — which is the only reason to trust that they work everywhere.
#
# Kept as a marker rather than deleted from sixty tests, so that if a platform
# ever genuinely cannot host one, there is a single place to say so.
def _broker_transport_missing() -> bool:
    if WINDOWS:
        try:
            import passbook_pipe  # noqa: F401
        except ImportError:  # pragma: no cover - would mean a broken install
            return True
        return False
    import socket
    return not hasattr(socket, "AF_UNIX")


def broker_marker():
    """A skipif marker for tests that need a running broker."""
    import pytest
    return pytest.mark.skipif(
        _broker_transport_missing(),
        reason="this platform has no broker transport")


def command_file(prefix, name: str) -> Path:
    """The file `passbook install` writes for one command, as this platform
    needs it named.

    Windows resolves a bare `passbook` through PATHEXT, and an extensionless
    file is not on it, so the shim there is `passbook.cmd`. Tests that spelled
    the POSIX name directly were asserting a filename rather than the thing
    they were about.
    """
    return Path(prefix) / (f"{name}.cmd" if WINDOWS else name)


# `install.sh`, the command shims, and any test that runs `sh -c` need a POSIX
# shell. Windows cannot execute them at all — it answers "%1 is not a valid
# Win32 application" — so the tests that need one say so here, once, rather
# than each rediscovering it on a red Windows job.
needs_a_posix_shell = pytest.mark.skipif(
    os.name == "nt", reason="this needs a POSIX shell")


# The stray-broker work is POSIX-shaped and says so in the code: it turns on a
# socket file that can vanish with its directory, a process table `ps` can read,
# and SIGSTOP/SIGTERM. The Windows pipe namespace is machine-wide rather than a
# directory, so the failure being guarded against cannot happen there — the
# listener reports it cannot tell and the check is skipped by design.
needs_a_process_table = pytest.mark.skipif(
    os.name == "nt",
    reason="a socket file, `ps` and SIGSTOP; the pipe transport has none of them")
