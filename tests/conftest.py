# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Things no test should do to the machine it is running on.

An approval request notifies, and on macOS notifying now means making sure the
PassBook window exists to post it — so a test suite that exercises the `ask`
path would launch the real app, on a developer's real machine, once per test.
Both halves are switched off here for every test, and the tests that are about
notifying turn the one they are testing back on.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_notifications(monkeypatch):
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setenv("PASSBOOK_NO_LAUNCH", "1")
