#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Where one made-up key can be seen, under `run` and under `run --capture`.

    python scripts/measure-capture.py

Runs the same small program twice: once under plain `passbook run --only KEY`,
once under `passbook run --only KEY --capture`. The program reads its key from
the environment, sends it to the host the key is for and to another host, and
writes down what it held and what came back. Two local HTTPS servers stand in
for the hosts and record what reached them.

Every cell in the table is read off what was observed, not written in. If
capture stopped working, the right-hand column would say REAL VALUE.

It touches nothing real. The store is a temporary directory made here, the key
is invented, the hosts are on loopback under a certificate root that is thrown
away, and nothing is sent to a network. What it does not measure, it says.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

KEY = "MEASURED_API_KEY"
VALUE = "sk-made-up-for-measurement-0123456789abcdef"  # not a credential for anything
MARKER = f"[redacted:{KEY}]"


def main() -> int:
    if os.name == "nt":
        print("--capture is not available on Windows; nothing to measure.")
        return 0
    scratch = Path(tempfile.mkdtemp(prefix="passbook-measure-"))
    try:
        return measure(scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def measure(scratch: Path) -> int:
    # Before PassBook is imported, and before anything is written: this run's
    # store is the temporary one and no other.
    for name in list(os.environ):
        if name.upper() in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE",
                            "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
                            "HIVE_ENV_FILES", "HIVE_WORKSPACE", "PASSBOOK_GRANT", "PASSBOOK_APP",
                            "PASSBOOK_SERVICE", KEY):
            del os.environ[name]
    home = scratch / "hive"
    os.environ.update(HIVE_HOME=str(home), PASSBOOK_KEYSTORE="file", PASSBOOK_FLEET="off",
                      PASSBOOK_NO_BRIEF="1", HOME=str(scratch / "home"))
    (scratch / "home").mkdir()
    made = scratch / "made"
    made.mkdir()
    tempfile.tempdir = str(made)  # so anything capture leaves behind is found below

    import passbook
    import passbook_capture
    import passbook_cli
    from capture_harness import ALLOWED, CLIENT, OTHER, Pki, Provider, install_seam

    if scratch not in passbook.env_path().parents:
        print(f"refusing to run: the store resolved to {passbook.env_path()}")
        return 1
    passbook.ensure(app="measure")
    passbook.set_values({KEY: VALUE})

    pki = Pki(scratch / "pki")
    allowed, other = Provider(pki.server_context(ALLOWED)), Provider(pki.server_context(OTHER))
    client = scratch / "client.py"
    client.write_text(CLIENT, encoding="utf-8")
    bearer = {"Authorization": "Bearer $KEY"}
    requests = [
        {"url": f"https://{ALLOWED}/echo", "headers": bearer, "also_trust": str(pki.root)},
        # Trusting ONLY the test root: if PassBook had opened this connection,
        # the certificate would be one it made and the request would fail.
        {"url": f"https://{OTHER}/collect", "headers": bearer, "only_trust": str(pki.root)},
    ]

    def observe(report: Path) -> dict:
        seen = json.loads(report.read_text())
        return {
            "environ": json.dumps(seen["environ"]), "argv": json.dumps(seen["argv"]),
            "own": allowed.seen(), "other": other.seen(),
            "reply": json.dumps(seen["answers"][0]),
            "other_ok": seen["answers"][1].get("status") == 200,
            "proxy": seen["environ"].get("HTTPS_PROXY", ""),
            "trust": seen["environ"].get("SSL_CERT_FILE", ""),
        }

    # ── plain `run`: the real command, in its own process, exec and all ─────
    report = scratch / "plain.json"
    plan = {"key": KEY, "report": str(report), "requests": requests,
            "direct": {ALLOWED: allowed.address, OTHER: other.address}}
    done = subprocess.run(
        [sys.executable, str(SRC / "passbook_cli.py"), "run", "--only", KEY, "--",
         sys.executable, str(client), json.dumps(plan)], capture_output=True, text=True)
    if done.returncode != 0 or not report.exists():
        print("the plain run failed:", done.stderr)
        return 1
    plain = observe(report)
    allowed.requests.clear()
    other.requests.clear()

    # ── `run --capture`: in this process, because the test hosts are reached
    # by replacing two functions here; the program is still a real child ────
    install_seam(passbook_capture, pki,
                 {(ALLOWED, 443): allowed.address, (OTHER, 443): other.address}, setattr)
    sessions = []

    class Recorded(passbook_capture.Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            sessions.append(self)

    passbook_capture.Session = Recorded
    report = scratch / "captured.json"
    plan = {"key": KEY, "report": str(report), "requests": requests}
    code = passbook_cli.main([
        "run", "--only", KEY, "--capture", "--capture-host", f"{KEY}={ALLOWED}", "--",
        sys.executable, str(client), json.dumps(plan)])
    if code != 0 or not report.exists():
        print("the captured run failed with exit code", code)
        return 1
    captured = observe(report)
    seen = sessions[0].report()
    port = urllib.parse.urlsplit(captured["proxy"]).port
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        listening = "STILL LISTENING"
    except OSError:
        listening = "nothing listens"
    left = sorted(path.name for path in made.iterdir())
    allowed.close()
    other.close()

    def what(text: str) -> str:
        found = [label for label, needle in (
            ("REAL VALUE", VALUE), ("stand-in", passbook_capture.STANDIN_PREFIX),
            ("redacted", MARKER)) if needle in text]
        return " + ".join(found) or "absent"

    rows = [
        ("in the program's environment", what(plain["environ"]), what(captured["environ"])),
        ("in the program's arguments", what(plain["argv"]), what(captured["argv"])),
        (f"received by the key's own host ({ALLOWED})", what(plain["own"]), what(captured["own"])),
        (f"received by another host ({OTHER})", what(plain["other"]), what(captured["other"])),
        ("in the reply the program read (the host echoes the key)",
         what(plain["reply"]), what(captured["reply"])),
        ("the other host's connection, opened by PassBook", "no proxy in the path",
         "no" if captured["other_ok"] and seen["tunnelled"].get(OTHER) and OTHER not in seen["opened"]
         else "YES"),
        ("certificates made for hosts off the list", "none",
         ", ".join(h for h in sessions[0]._authority.minted if h != ALLOWED) or "none"),
        ("after the program exits: proxy", "none started", listening),
        ("after the program exits: temporary files", "none made", ", ".join(left) or "none left"),
    ]
    width = max(len(row[0]) for row in rows)
    middle = max(len(row[1]) for row in rows + [("", "passbook run", "")])
    print(f"One made-up key, {KEY}, allowed for {ALLOWED} only.\n")
    print(f"{'where':<{width}}  {'passbook run':<{middle}}  passbook run --capture")
    print(f"{'-' * width}  {'-' * middle}  {'-' * 22}")
    for label, before, after in rows:
        print(f"{label:<{width}}  {before:<{middle}}  {after}")
    print(
        "\nNot measured here: what another process sees by reading the program's environment\n"
        "from outside (it reads the same bytes the program reported in row 1); a program that\n"
        "ignores HTTPS_PROXY or pins certificates; and anything on a real network.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
