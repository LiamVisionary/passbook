# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""A real OAuth token endpoint, on loopback, for tests.

Mocking `urlopen` would test that the code calls a function. This serves actual
HTTP on a real socket and speaks the actual grant, so what is under test is the
thing that runs in production: form encoding, JSON parsing, error shapes, and
the rotation behaviour that a mock would have let us get wrong.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
import urllib.parse


class FakeProvider:
    """Serves `/token`. Counts calls, can rotate, can fail on demand."""

    def __init__(self, *, rotate: bool = False, expires_in: int = 3600,
                 fail_with: int = 0, lifetime_field: bool = True):
        self.rotate = rotate
        self.expires_in = expires_in
        self.fail_with = fail_with
        self.lifetime_field = lifetime_field
        self.calls: list[dict[str, str]] = []
        self.issued = 0
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        # A refresh token the test can rotate out from under the caller.
        self.current_refresh = "refresh-1"
        self.delay = 0.0

    # ── lifecycle ──────────────────────────────────────────────────────────

    def __enter__(self):
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in urllib.parse.parse_qs(
                    self.rfile.read(length).decode("utf-8")).items()}
                body, code = provider._answer(form)
                raw = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def token_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/token"

    # ── behaviour ──────────────────────────────────────────────────────────

    def _answer(self, form):
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.calls.append(form)
            if self.fail_with:
                return {"error": "invalid_grant",
                        "error_description": "the grant has been revoked"}, self.fail_with
            offered = form.get("refresh_token", "")
            if form.get("grant_type") == "refresh_token" and offered != self.current_refresh:
                # What a rotating provider does when a stale refresh token is
                # replayed. Getting this wrong disconnects a live grant.
                return {"error": "invalid_grant",
                        "error_description": "refresh token already used"}, 400
            self.issued += 1
            body = {"access_token": f"access-{self.issued}", "token_type": "Bearer"}
            if self.lifetime_field:
                body["expires_in"] = self.expires_in
            if self.rotate:
                self.current_refresh = f"refresh-{self.issued + 1}"
                body["refresh_token"] = self.current_refresh
            return body, 200
