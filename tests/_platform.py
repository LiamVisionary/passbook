# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What a claim about the filesystem means on a platform that has no POSIX modes."""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

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
