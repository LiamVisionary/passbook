# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""`passbook run --capture`: a command uses a key it never holds.

`passbook run` puts real values in the child's environment, where every
dependency the child loads and every other process running as the same user can
read them. Capture gives the child a stand-in and has PassBook put the value on
the wire itself, to the one host that key is for.

The sentence being held up is: **the value reaches its own host and nothing
else.** Each test below is one way that sentence could be false: the child
holding it after all, another host receiving it, the host handing it back, a
stranger borrowing the proxy, a key with nowhere to go being let through, or
something being left behind when the command has gone.

The far end is a real TLS server (`capture_harness.py`), because a claim about
what crossed a wire is only as good as what was listening on it.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_capture as capture  # noqa: E402
import passbook_cli  # noqa: E402
from _platform import broker_marker  # noqa: E402
from capture_harness import ALLOWED, CLIENT, OTHER, Pki, Provider, install_seam  # noqa: E402

# Capture refuses to start on Windows (it hands TLS a key through /dev/fd so
# that none is written to disk), so there is nothing here to run there.
pytestmark = pytest.mark.skipif(os.name == "nt", reason="--capture is not available on Windows")

KEY = "FAKE_API_KEY"
VALUE = "sk-made-up-for-this-test-0123456789abcdef"  # not a credential for anything
REDACTED = f"[redacted:{KEY}]"
NOT_INHERITED = (
    "PASSBOOK_SERVICE", "PASSBOOK_GRANT", "PASSBOOK_APP", "HIVE_ENV_FILES", "HIVE_WORKSPACE",
    "APP_SANDBOX_CONTAINER_ID", KEY, "OTHER_KEY", "AWKWARD_KEY", "MISSING_KEY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY",
    "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY")


# ── a machine, two hosts, and a program that knows nothing ─────────────────


@pytest.fixture(autouse=True)
def _unsealer_as_it_was(monkeypatch):
    """Put the store's unsealer back after every test here.

    A `passbook run` installs the broker's unsealer for the life of its process.
    These tests run the command in this process, so that life is the whole test
    run: left in place, a later test that seals a store with its own key
    (`test_a_sealed_store_still_lends_correctly`) reads its values through a
    broker that is no longer there and lends ciphertext. CI caught exactly that
    on 2026-10-13; the balances tests met the same leak before.
    """
    monkeypatch.setattr(passbook, "_UNSEALER", passbook._UNSEALER)


@pytest.fixture
def pki(tmp_path):
    return Pki(tmp_path / "pki")


@pytest.fixture
def hosts(pki, monkeypatch):
    """`api.allowed.test`, which the key is for, and `other.example.test`, which it is not."""
    allowed, other = Provider(pki.server_context(ALLOWED)), Provider(pki.server_context(OTHER))
    install_seam(capture, pki, {(ALLOWED, 443): allowed.address, (OTHER, 443): other.address},
                 monkeypatch.setattr)
    try:
        yield argparse.Namespace(allowed=allowed, other=other)
    finally:
        allowed.close()
        other.close()


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A plaintext store in a temporary home, holding one made-up key."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    monkeypatch.setenv("PASSBOOK_KEYSTORE", "file")
    for name in NOT_INHERITED:
        monkeypatch.delenv(name, raising=False)
    # Every temporary file capture makes lands where the test can look for it.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    passbook.ensure(app="test")
    passbook.set_values({KEY: VALUE})
    return home


@pytest.fixture
def sessions(monkeypatch):
    """Every capture session the code under test makes, kept for inspection."""
    made = []

    class Recorded(capture.Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            made.append(self)

    monkeypatch.setattr(capture, "Session", Recorded)
    return made


@pytest.fixture
def program(tmp_path):
    """Run the unaware client under `passbook run`, in this process.

    In this process because the upstream seam is patched here; the client
    itself is a real child process, started exactly as the CLI starts it.
    """
    script = tmp_path / "client.py"
    script.write_text(CLIENT, encoding="utf-8")
    report = tmp_path / "report.json"

    def run(flags, requests=(), **plan):
        if report.exists():
            report.unlink()
        plan = {"key": KEY, "report": str(report), "requests": list(requests), **plan}
        code = passbook_cli.main(["run", *flags, "--", sys.executable, str(script), json.dumps(plan)])
        seen = json.loads(report.read_text()) if report.exists() else None
        return code, seen

    return run


CAPTURE = ["--only", KEY, "--capture", "--capture-host", f"{KEY}={ALLOWED}"]
BEARER = {"Authorization": "Bearer $KEY"}


def _listening(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        return True
    except OSError:
        return False


# ── (a) and (b): the child holds a stand-in, the host gets the key ─────────


def test_the_command_holds_a_stand_in_and_its_host_still_gets_the_key(store, hosts, program):
    """The two halves of the feature, in one run, because either alone is useless.

    A stand-in that never becomes the key is a broken credential. A key that
    reaches the host but is also in the child's environment is plain `run`.
    """
    code, seen = program(CAPTURE, [{"url": f"https://{ALLOWED}/v1/models", "headers": BEARER}])

    assert code == 0
    held = seen["environ"][KEY]
    assert held.startswith(capture.STANDIN_PREFIX) and len(held) == len(capture.STANDIN_PREFIX) + 32
    assert VALUE not in json.dumps(seen["environ"]), "the real value is in the child's environment"
    assert VALUE not in json.dumps(seen["argv"])

    assert seen["answers"][0]["status"] == 200
    arrived = hosts.allowed.requests[0]
    assert arrived["headers"]["authorization"] == f"Bearer {VALUE}"
    assert held not in hosts.allowed.seen(), "the host was sent the stand-in as well"


def test_the_key_is_swapped_wherever_the_program_put_it(store, hosts, program):
    """A key is not always a bearer header. It rides in query strings, JSON
    bodies and form posts, and a value has to be written correctly for each:
    one holding `&` or `"` that was pasted in raw would change what the request
    means. So the value here has both."""
    awkward = 'p&ss "word"/with+odd=chars'
    passbook.set_values({"AWKWARD_KEY": awkward})
    flags = ["--only", "AWKWARD_KEY", "--capture", "--capture-host", f"AWKWARD_KEY={ALLOWED}"]
    code, seen = program(flags, key="AWKWARD_KEY", requests=[
        {"url": f"https://{ALLOWED}/v1/query?api_key=$KEY&page=2"},
        {"url": f"https://{ALLOWED}/v1/json", "method": "POST", "body": '{"token": "$KEY", "n": 1}',
         "headers": {"Content-Type": "application/json"}},
        {"url": f"https://{ALLOWED}/v1/form", "method": "POST", "body": "client_secret=$KEY&grant=x",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    ])

    assert code == 0 and [answer["status"] for answer in seen["answers"]] == [200, 200, 200]
    query, as_json, form = hosts.allowed.requests
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(query["path"]).query) == {
        "api_key": [awkward], "page": ["2"]}
    assert json.loads(as_json["body"]) == {"token": awkward, "n": 1}
    assert urllib.parse.parse_qs(form["body"].decode()) == {"client_secret": [awkward], "grant": ["x"]}


# ── (c): another host gets the stand-in, through a connection nobody read ──


def test_another_host_gets_the_stand_in_through_a_connection_nobody_opened(
        store, hosts, program, pki, sessions):
    """A proxy that swapped wherever it saw a stand-in would be `passbook get`
    with a network hop: name a host, send the stand-in, read the key off the
    far end.

    "Never decrypted" is proved, not asserted: the child trusts ONLY the test
    root for this request, and the per-launch authority is not in that list.
    Had the proxy opened the connection, the certificate would be one it made,
    and the handshake would have failed. It succeeded, end to end, with the
    real server."""
    code, seen = program(CAPTURE, [
        {"url": f"https://{OTHER}/collect", "headers": BEARER, "only_trust": str(pki.root)}])

    assert code == 0
    assert seen["answers"][0].get("status") == 200, seen["answers"][0]
    arrived = hosts.other.requests[0]
    assert arrived["headers"]["authorization"] == f"Bearer {seen['environ'][KEY]}"
    assert VALUE not in hosts.other.seen()

    report = sessions[0].report()
    assert report["tunnelled"] == {OTHER: 1}
    assert report["opened"] == {} and report["swapped"] == {}
    assert sessions[0]._authority.minted == [], "a certificate was made for a host off the list"


def test_a_redirect_is_the_childs_to_follow_and_the_key_does_not_follow_it(
        store, hosts, program, pki):
    """An allowed host that answers 302 to somewhere else must not carry the
    key there. The proxy passes the 302 back and makes no second request. The
    child follows it itself, as HTTP clients do, and its new connection is
    judged on its own host: off the list, so a stand-in."""
    code, seen = program(CAPTURE, [
        {"url": f"https://{ALLOWED}/redirect", "headers": BEARER, "also_trust": str(pki.root)}])

    assert code == 0 and seen["answers"][0]["url"] == f"https://{OTHER}/landed"
    assert [row["path"] for row in hosts.allowed.requests] == ["/redirect"]
    assert [row["path"] for row in hosts.other.requests] == ["/landed"]
    assert VALUE not in hosts.other.seen()


# ── (d): a host that echoes the key does not hand it back ──────────────────


@pytest.mark.parametrize(
    "path", ["/echo", "/echo-gzip", "/echo-deflate", "/echo-split", "/echo-header"])
def test_a_key_the_host_echoes_does_not_come_back(store, hosts, program, path):
    """APIs repeat the key you sent, most often in the error about it. Without
    this the child reads its own credential out of a response body and the
    stand-in bought nothing.

    Five shapes, because each defeats a redactor that only handles the first:
    plain, compressed two ways (unreadable unless inflated), cut into
    seven-byte chunks (the key is in no single read), and in a response
    header."""
    code, seen = program(CAPTURE, [{"url": f"https://{ALLOWED}{path}", "headers": BEARER}])

    assert code == 0
    assert hosts.allowed.requests[0]["headers"]["authorization"] == f"Bearer {VALUE}"
    answer = seen["answers"][0]
    assert answer["status"] == 200
    assert VALUE not in json.dumps(answer), "the host handed the key back to the child"
    assert REDACTED in json.dumps(answer)
    if path != "/echo-header":
        assert json.loads(answer["body"])["authorization"] == f"Bearer {REDACTED}"


def test_a_response_that_cannot_be_read_is_not_passed_on(store, hosts, program):
    """Capture asks for an uncompressed response. A host that sends an encoding
    it cannot read anyway has sent something it cannot check, and an unchecked
    body is exactly where an echoed key gets through. It is refused, and the
    refusal says so, instead of being waved along."""
    code, seen = program(CAPTURE, [{"url": f"https://{ALLOWED}/echo-unreadable", "headers": BEARER}])

    answer = seen["answers"][0]
    assert answer["status"] == 502
    assert "could not be checked" in answer["body"]
    assert VALUE not in json.dumps(answer)


# ── (e): no host, no start ─────────────────────────────────────────────────


def test_a_key_with_no_host_does_not_start(store, hosts, program, sessions, capsys):
    """The failure this prevents is the quiet one: no host is known, so the
    child is given the real value "just this once", under a flag that says it
    never is. Nothing runs, and the message names the key and what fixes it."""
    code, seen = program(["--only", KEY, "--capture"],
                         [{"url": f"https://{ALLOWED}/v1/models", "headers": BEARER}])

    assert code == 1
    assert seen is None, "the command ran"
    assert sessions == [] and hosts.allowed.requests == []
    err = capsys.readouterr().err
    assert KEY in err and "no known host" in err
    assert f"--capture-host {KEY}=" in err and f"passbook guard {KEY} --to" in err


def test_capture_needs_a_named_set_of_keys(store, program, capsys):
    """`run` without `--only` hands over the whole store. Capturing "the whole
    store" would need a host for every key in it, and capturing some while the
    rest went through as real values would look protected and not be."""
    code, seen = program(["--capture"])
    assert code == 1 and seen is None
    assert "--capture needs --only" in capsys.readouterr().err


def test_a_host_flag_without_capture_is_a_mistake_not_a_no_op(store, program, capsys):
    """Someone who typed `--capture-host` and forgot `--capture` believes the
    key is protected. Running anyway hands the child the real value."""
    code, seen = program(["--only", KEY, "--capture-host", f"{KEY}={ALLOWED}"])
    assert code == 1 and seen is None
    assert "--capture-host needs --capture" in capsys.readouterr().err


def test_a_captured_key_with_no_value_does_not_run(store, hosts, program, capsys):
    """A name the store does not hold gets no stand-in, and a command started
    without it fails against its provider as a bad key. Plain `run` warns and
    carries on; under capture there is nothing to carry on with."""
    code, seen = program(["--only", f"{KEY},MISSING_KEY", "--capture",
                          "--capture-host", f"{KEY}={ALLOWED}",
                          "--capture-host", f"MISSING_KEY={ALLOWED}"])
    assert code == 1 and seen is None
    err = capsys.readouterr().err
    assert "no value to stand in for: MISSING_KEY" in err


def test_a_command_that_stores_the_key_somewhere_is_not_captured(store, program, capsys):
    """`--used-in` records that a service now holds the key. Under capture the
    command would have pushed the stand-in, exited 0, and been written down as
    a place the key lives."""
    code, seen = program([*CAPTURE, "--used-in", "deploy box"])
    assert code == 1 and seen is None
    assert "stand-in" in capsys.readouterr().err


@pytest.mark.parametrize("entry", [
    "*.example.com", "https://api.example.com", "api.example.com:8443", "api.example.com/v1",
    "10.0.0.1", ".com", "", "exa mple.com"])
def test_a_host_entry_is_a_name_or_a_dot_suffix_and_nothing_else(entry):
    """The list is the security of the whole feature, so an entry that might
    mean more than it appears to is refused rather than interpreted."""
    with pytest.raises(capture.CaptureError):
        capture.host_entry(entry)


def test_host_entries_match_exactly_or_by_dot_suffix():
    assert capture._covers("api.example.com", "api.example.com")
    assert not capture._covers("api.example.com", "evil-api.example.com")
    assert not capture._covers("api.example.com", "api.example.com.evil.test")
    assert capture._covers(".example.com", "example.com")
    assert capture._covers(".example.com", "a.b.example.com")
    assert not capture._covers(".example.com", "notexample.com")


def test_a_guard_says_where_a_key_goes_and_a_flag_cannot_widen_it():
    """`passbook guard KEY --to HOST` is the one place PassBook already records
    a host for a key, written by the owner. `--capture-host` is typed by the
    caller. If the flag could add a host, capture would be the way round the
    guard."""
    policy = {"guards": {"BOUND": {"destinations": [".example.com"]}}}

    assert capture.allowlist(["BOUND"], policy) == {"BOUND": [".example.com"]}
    assert capture.allowlist(["BOUND"], policy, {"BOUND": ["api.example.com"]}) == {
        "BOUND": ["api.example.com"]}, "a flag may narrow a binding"
    with pytest.raises(capture.CaptureError, match="cannot add evil.test"):
        capture.allowlist(["BOUND"], policy, {"BOUND": ["evil.test"]})
    with pytest.raises(capture.CaptureError, match="cannot add .badexample.com"):
        capture.allowlist(["BOUND"], policy, {"BOUND": [".badexample.com"]})
    with pytest.raises(capture.CaptureError, match="which --only does not"):
        capture.allowlist(["BOUND"], policy, {"ELSE": ["api.example.com"]})
    with pytest.raises(capture.CaptureError, match="LOOSE has no known host"):
        capture.allowlist(["BOUND", "LOOSE"], policy)


def test_a_session_cannot_be_built_around_a_key_with_no_host():
    """`allowlist` is the front door. This is the same check on the object that
    will actually hold the value, so no caller can skip it by not calling."""
    with pytest.raises(capture.CaptureError, match="no host"):
        capture.Session({KEY: VALUE}, {})
    with pytest.raises(capture.CaptureError, match="no host"):
        capture.Session({KEY: VALUE, "OTHER_KEY": "another-made-up-value"}, {KEY: [ALLOWED]})


# ── (f): a stranger on the port ────────────────────────────────────────────


@pytest.fixture
def session(hosts, monkeypatch, tmp_path):
    for name in NOT_INHERITED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with capture.Session({KEY: VALUE}, {KEY: [ALLOWED]}, base_env={}) as running:
        yield running


def _connect(running, host, *, credential="right", port=443):
    """CONNECT through the proxy as a client would. (status, tls socket or None)."""
    proxy = urllib.parse.urlsplit(running.environment()["HTTPS_PROXY"])
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if credential:
        password = proxy.password if credential == "right" else "guessed"
        token = base64.b64encode(f"{proxy.username}:{password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    reply = b""
    while b"\r\n\r\n" not in reply:
        more = sock.recv(1)
        if not more:
            break
        reply += more
    status = int(reply.split()[1])
    if status != 200:
        sock.close()
        return status, None
    context = ssl.create_default_context(cafile=running.environment()["SSL_CERT_FILE"])
    return status, context.wrap_socket(sock, server_hostname=host)


def _exchange(tls, request: bytes, method="POST"):
    tls.sendall(request)
    answer = http.client.HTTPResponse(tls, method=method)
    answer.begin()
    body = answer.read()
    return answer.status, dict(answer.getheaders()), body


def test_a_stranger_on_the_port_gets_no_swap(session, hosts):
    """The proxy listens on loopback, where any local process can connect. One
    that merely found the port must not be able to send a stand-in through it
    and have the key attached, so every connection has to present the credential
    minted for this launch. It is refused before the host is even looked at.

    What this does NOT cover is said in the SPEC: a process that can read the
    child's environment can read the credential too."""
    standin = session.standins[KEY]

    assert _connect(session, ALLOWED, credential=None)[0] == 407
    assert _connect(session, ALLOWED, credential="wrong")[0] == 407
    assert _connect(session, OTHER, credential=None)[0] == 407, "an open relay for strangers"
    assert hosts.allowed.requests == [] and hosts.other.requests == []
    assert session.report()["refused"] == {"no credential": 3}

    # The control: the same request with the credential IS swapped, so the
    # refusals above are the credential's doing and not a broken proxy.
    status, tls = _connect(session, ALLOWED)
    assert status == 200
    assert _exchange(tls, f"GET /v1 HTTP/1.1\r\nHost: {ALLOWED}\r\nAuthorization: Bearer {standin}"
                          f"\r\n\r\n".encode(), "GET")[0] == 200
    assert hosts.allowed.requests[0]["headers"]["authorization"] == f"Bearer {VALUE}"


def test_nothing_is_swapped_in_cleartext(session, hosts):
    """A credential on a cleartext request is a credential given away. The
    child is given no `HTTP_PROXY`, and a client that sends a plain request to
    this proxy anyway is refused: there is no code path that could swap one."""
    env = session.environment()
    assert "HTTP_PROXY" not in env and "http_proxy" not in env and "ALL_PROXY" not in env

    proxy = urllib.parse.urlsplit(env["HTTPS_PROXY"])
    token = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    sock.sendall(f"GET http://{ALLOWED}/v1 HTTP/1.1\r\nHost: {ALLOWED}\r\n"
                 f"Proxy-Authorization: Basic {token}\r\n"
                 f"Authorization: Bearer {session.standins[KEY]}\r\n\r\n".encode())
    assert sock.recv(4096).startswith(b"HTTP/1.1 405 ")
    assert hosts.allowed.requests == []


def test_a_listed_host_on_another_port_is_not_opened(session, hosts, pki, monkeypatch):
    """A key's list names hosts, and the service behind a name is the one on
    443. Something else answering on another port of the same name is not what
    the owner listed, so it is treated like any other destination: copied
    through unread, the stand-in left as it is."""
    install_seam(capture, pki, {(ALLOWED, 8443): hosts.other.address}, monkeypatch.setattr)
    proxy = urllib.parse.urlsplit(session.environment()["HTTPS_PROXY"])
    token = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    sock.sendall(f"CONNECT {ALLOWED}:8443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode())
    assert sock.recv(4096).startswith(b"HTTP/1.1 200 ")
    # The far end's own certificate (for the other name, under the test root):
    # this connection was not terminated on the way.
    tls = pki.client_context().wrap_socket(sock, server_hostname=OTHER)
    standin = session.standins[KEY]
    assert _exchange(tls, (f"GET /v1 HTTP/1.1\r\nHost: {ALLOWED}:8443\r\n"
                           f"Authorization: Bearer {standin}\r\n\r\n").encode(), "GET")[0] == 200
    assert hosts.other.requests[0]["headers"]["authorization"] == f"Bearer {standin}"
    assert session.report()["tunnelled"] == {ALLOWED: 1} and session.report()["opened"] == {}


# ── (g): nothing left behind ───────────────────────────────────────────────


def test_nothing_is_left_when_the_command_has_gone(store, hosts, program, sessions, tmp_path):
    """The proxy holds real values and the directory holds what the child was
    told to trust. Either one outliving the child is a listener nobody is
    watching, or a certificate authority lying around in /tmp.

    While it ran, the child looked at what it had been given: a 0600 file in a
    0700 directory, with no private key anywhere in it."""
    code, seen = program(CAPTURE, [{"url": f"https://{ALLOWED}/v1/models", "headers": BEARER}],
                         exit=7)

    assert code == 7, "the child's exit code is PassBook's"
    assert seen["trust_mode"] == "0o600" and seen["folder_mode"] == "0o700"
    assert seen["private_key_on_disk"] is False
    assert b"PRIVATE KEY" not in sessions[0]._authority.cert_pem

    ended = sessions[0]
    assert not _listening(ended.port), "the proxy is still listening"
    folder = Path(seen["environ"]["SSL_CERT_FILE"]).parent
    assert not folder.exists()
    assert list((tmp_path / "scratch").iterdir()) == [], "a temporary file was left behind"
    assert ended._authority._key is None and ended._values == {}
    assert not [thread for thread in threading.enumerate()
                if thread.name.startswith("passbook-capture")]


def test_a_child_that_is_killed_is_reported_the_way_a_shell_reports_it(store, hosts, tmp_path):
    """Plain `run` execs, so the child's fate is the caller's directly. Capture
    stays in between and has to pass it on: a child ended by a signal exits
    128 + the signal, which is what a script checking `$?` already expects."""
    code = passbook_cli.main(["run", *CAPTURE, "--", sys.executable, "-c",
                              "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"])
    assert code == 128 + 15


def test_a_failure_that_is_really_a_bypassed_proxy_is_named(store, hosts, program, capsys):
    """A program that ignores HTTPS_PROXY sends the stand-in straight to its
    provider and gets an authentication error with nothing in it that points
    at capture. This is the line that does, and it is printed only when the
    command failed, so a working command stays quiet."""
    code, _ = program(CAPTURE, exit=3)   # makes no request at all, then fails
    assert code == 3
    assert "may not use HTTPS_PROXY" in capsys.readouterr().err

    code, _ = program(CAPTURE, [{"url": f"https://{ALLOWED}/v1", "headers": BEARER}])
    assert code == 0 and "HTTPS_PROXY" not in capsys.readouterr().err


def test_a_value_too_short_to_redact_is_said_to_be(store, hosts, program, capsys):
    """Redaction cannot search for "1234" without wrecking every response, so
    it does not try. Saying so is the difference between "an echoed key is
    removed" and "an echoed key is removed, except this one"."""
    passbook.set_values({"OTHER_KEY": "1234"})
    code, seen = program(["--only", "OTHER_KEY", "--capture", "--capture-host",
                          f"OTHER_KEY={ALLOWED}"], key="OTHER_KEY")
    assert code == 0 and seen["environ"]["OTHER_KEY"].startswith(capture.STANDIN_PREFIX)
    assert "OTHER_KEY is too short to redact from responses" in capsys.readouterr().err


# ── (h): without the flag, nothing is different ────────────────────────────


def test_without_capture_the_child_gets_what_it_always_got(store, tmp_path):
    """Capture is opt-in per launch. A run that did not ask for it must not
    pay for it or be changed by it: same environment, same exec, and the new
    module (and the crypto library under it) never loaded at all.

    Run as a real `passbook run` in a fresh interpreter, with `os.execvpe`
    replaced by a recorder, so what is checked is the exact environment the
    command would have been exec'd with."""
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import json, os, sys\n"
        "before = dict(os.environ)\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import passbook_cli\n"
        "def record(program, argv, env):\n"
        "    print(json.dumps({'argv': argv, 'env': env, 'before': before, 'loaded': sorted(\n"
        "        name for name in sys.modules if name.split('.')[0] in\n"
        "        ('passbook_capture', 'cryptography'))}))\n"
        "    raise SystemExit(0)\n"
        "passbook_cli.os.execvpe = record\n"
        "sys.exit(passbook_cli.main(sys.argv[1:]))\n", encoding="utf-8")
    done = subprocess.run(
        [sys.executable, str(driver), "run", "--only", KEY, "--", "some-command", "--flag"],
        capture_output=True, text=True, env=dict(os.environ), cwd=str(tmp_path))
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])

    assert seen["argv"] == ["some-command", "--flag"]
    assert seen["env"][KEY] == VALUE
    assert seen["loaded"] == [], "a plain run loaded the capture module"
    # Its own environment (`run` has always dropped variables that are set but
    # empty), the key, and its name. Nothing else, and no proxy or trust file.
    expected = {**{name: value for name, value in seen["before"].items() if value},
                KEY: VALUE, "PASSBOOK_APP": "passbook-run"}
    assert seen["env"] == expected, "a plain run's environment is not what it was"


def test_the_single_file_store_never_loads_capture():
    """`passbook.py` is copied into projects as one file with no dependencies.
    It must not reach for this module, eagerly or at all."""
    assert "passbook_capture" not in (SRC / "passbook.py").read_text(encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(SRC)!r}); import passbook; "
         "print(sorted(n for n in sys.modules if n.split('.')[0] in "
         "('passbook_capture', 'cryptography', 'ssl')))"],
        capture_output=True, text=True)
    assert done.stdout.strip() == "[]", done.stdout + done.stderr


def test_a_run_that_did_not_ask_sends_the_broker_what_it_always_sent(monkeypatch):
    """The brokered path is byte-for-byte the old request unless capture was
    asked for. An older broker never sees a field it does not know."""
    sent = []

    class Wire:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def sendall(self, data):
            sent.append(json.loads(data))

        def recv(self, _size):
            return b'{"t":"end","ok":true,"exit_code":0}\n'

    monkeypatch.setattr(passbook_broker, "_dial", lambda root, timeout: Wire())
    passbook_broker.spawn_streaming(["true"], ["A"], app="x")
    passbook_broker.spawn_streaming(["true"], ["A"], app="x", capture={"hosts": {}})
    assert "capture" not in sent[0]
    assert sent[1]["capture"] == {"hosts": {}}
    assert {name for name in sent[1] if name != "capture"} == set(sent[0])


# ── (i): a swap changes the length, and the message stays whole ────────────


def test_a_swap_that_changes_the_length_keeps_the_request_whole(session, hosts):
    """The value is not the length of its stand-in. A request sent on with the
    old Content-Length is either cut short or runs into the next one, and a
    chunked one with a stand-in cut across two chunks is not found at all
    unless the body is put back together first.

    Two requests go down ONE connection. The second being read correctly is
    the proof that the first was framed correctly: a single byte too many or
    too few and it would have been parsed out of the wrong place."""
    standin = session.standins[KEY]
    assert len(standin) != len(VALUE)
    status, tls = _connect(session, ALLOWED)
    assert status == 200

    first = json.dumps({"api_key": standin, "pad": "x" * 50}).encode()
    assert _exchange(tls, (
        f"POST /sized HTTP/1.1\r\nHost: {ALLOWED}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(first)}\r\n\r\n").encode() + first)[0] == 200

    half = len(standin) // 2
    pieces = [b'{"api_key": "' + standin[:half].encode(), standin[half:].encode() + b'"}']
    chunked = b"".join(b"%x\r\n" % len(piece) + piece + b"\r\n" for piece in pieces) + b"0\r\n\r\n"
    assert _exchange(tls, (
        f"POST /chunked HTTP/1.1\r\nHost: {ALLOWED}\r\nContent-Type: application/json\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n").encode() + chunked)[0] == 200

    sized, split = hosts.allowed.requests
    assert sized["path"] == "/sized" and split["path"] == "/chunked"
    assert json.loads(sized["body"]) == {"api_key": VALUE, "pad": "x" * 50}
    assert int(sized["headers"]["content-length"]) == len(sized["body"]) != len(first)
    assert json.loads(split["body"]) == {"api_key": VALUE}
    # Sent on with a length, which is the framing nobody can misread.
    assert split["framing"] == "length"
    assert int(split["headers"]["content-length"]) == len(split["body"])
    assert "transfer-encoding" not in split["headers"]


def test_a_body_too_large_to_search_goes_on_unsearched_and_intact(session, hosts, monkeypatch):
    """A body is searched only up to `MAX_SWAP_BODY`; an upload is not held in
    memory to look for a token it will not contain. What matters is that the
    larger one still arrives whole, with its headers swapped, and that the
    stand-in inside it stays a stand-in rather than being half-handled."""
    monkeypatch.setattr(capture, "MAX_SWAP_BODY", 64)
    standin = session.standins[KEY]
    status, tls = _connect(session, ALLOWED)
    assert status == 200
    body = (f"upload {standin} " + "z" * 200).encode()

    assert _exchange(tls, (
        f"POST /big HTTP/1.1\r\nHost: {ALLOWED}\r\nAuthorization: Bearer {standin}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n").encode() + body)[0] == 200
    chunked = b"".join(b"%x\r\n" % len(body[at:at + 50]) + body[at:at + 50] + b"\r\n"
                       for at in range(0, len(body), 50)) + b"0\r\n\r\n"
    assert _exchange(tls, (
        f"POST /big-chunked HTTP/1.1\r\nHost: {ALLOWED}\r\nAuthorization: Bearer {standin}\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n").encode() + chunked)[0] == 200

    sized, streamed = hosts.allowed.requests
    for arrived in (sized, streamed):
        assert arrived["body"] == body, "the body was changed or cut"
        assert arrived["headers"]["authorization"] == f"Bearer {VALUE}"
    assert sized["framing"] == "length" and streamed["framing"] == "chunked"
    assert session.report()["unsearched"] == {ALLOWED: 2}


# ── the rest of what "only its own host" has to mean ───────────────────────


def test_the_host_header_cannot_send_the_key_to_another_tenant(session, hosts):
    """The value is written for the host the connection is to. A shared front
    end routes on the Host header, so a request that connects to the allowed
    name and then names another tenant in Host would carry the key to that
    tenant. Refused before anything is sent."""
    status, tls = _connect(session, ALLOWED)
    answer = _exchange(tls, (
        f"GET /v1 HTTP/1.1\r\nHost: attacker.example.test\r\n"
        f"Authorization: Bearer {session.standins[KEY]}\r\n\r\n").encode(), "GET")
    assert answer[0] == 421
    assert hosts.allowed.requests == []


def test_a_key_is_swapped_only_for_its_own_host_even_on_an_opened_connection(
        hosts, monkeypatch, tmp_path):
    """Two keys, two hosts, both opened. One key's stand-in sent to the other
    key's host must stay a stand-in: the list is per key, not "any captured key
    on any captured host"."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    other_value = "another-made-up-value-9876543210"
    with capture.Session({KEY: VALUE, "OTHER_KEY": other_value},
                         {KEY: [ALLOWED], "OTHER_KEY": [OTHER]}, base_env={}) as running:
        mine, theirs = running.standins[KEY], running.standins["OTHER_KEY"]
        status, tls = _connect(running, OTHER)
        assert status == 200
        assert _exchange(tls, (
            f"GET /v1 HTTP/1.1\r\nHost: {OTHER}\r\nAuthorization: Bearer {mine}\r\n"
            f"X-Own: {theirs}\r\n\r\n").encode(), "GET")[0] == 200

    arrived = hosts.other.requests[0]["headers"]
    assert arrived["authorization"] == f"Bearer {mine}", "a key went to a host not on its list"
    assert arrived["x-own"] == other_value
    assert VALUE not in hosts.other.seen()


def test_a_key_sent_as_basic_auth_is_found_inside_the_base64(session, hosts):
    """Stripe, Twilio and git over HTTPS send the key as the user or password
    of Basic auth. The stand-in is then inside base64, where a search of the
    header as written never sees it, and the command simply fails to log in."""
    status, tls = _connect(session, ALLOWED)
    pair = base64.b64encode(f"{session.standins[KEY]}:".encode()).decode()
    assert _exchange(tls, (f"GET /v1 HTTP/1.1\r\nHost: {ALLOWED}\r\n"
                           f"Authorization: Basic {pair}\r\n\r\n").encode(), "GET")[0] == 200
    sent = hosts.allowed.requests[0]["headers"]["authorization"]
    assert base64.b64decode(sent.split()[1]).decode() == f"{VALUE}:"


def test_an_upgrade_is_refused_rather_than_carried_half_understood(session, hosts):
    """Capture reads one HTTP/1.1 request at a time. After an upgrade the
    connection is another protocol, which it would be relaying without being
    able to check. It says so."""
    status, tls = _connect(session, ALLOWED)
    answer = _exchange(tls, (f"GET /socket HTTP/1.1\r\nHost: {ALLOWED}\r\nConnection: Upgrade\r\n"
                             f"Upgrade: websocket\r\n\r\n").encode(), "GET")
    assert answer[0] == 501 and b"WebSocket" in answer[2]
    assert hosts.allowed.requests == []


def test_only_http_1_1_is_offered_on_an_opened_connection(session):
    """A client that negotiated HTTP/2 would send frames this cannot read."""
    proxy = urllib.parse.urlsplit(session.environment()["HTTPS_PROXY"])
    token = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    sock.sendall(f"CONNECT {ALLOWED}:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode())
    assert sock.recv(4096).startswith(b"HTTP/1.1 200 ")
    context = ssl.create_default_context(cafile=session.environment()["SSL_CERT_FILE"])
    context.set_alpn_protocols(["h2", "http/1.1"])
    tls = context.wrap_socket(sock, server_hostname=ALLOWED)
    assert tls.selected_alpn_protocol() == "http/1.1"


def test_the_authority_cannot_vouch_for_a_host_off_the_list(session, pki):
    """Belt and braces under `keys_for`. The per-launch certificate is name-
    constrained to the listed hosts, so even a leaf it was somehow made to sign
    for another name is refused by the client that trusts it."""
    authority = session._authority
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)

    def serve(host):
        connection, _ = listener.accept()
        try:
            authority._context(host).wrap_socket(connection, server_side=True).close()
        except OSError:
            pass

    trusting = ssl.create_default_context(cafile=session.environment()["NODE_EXTRA_CA_CERTS"])
    for host, accepted in ((ALLOWED, True), (OTHER, False)):
        threading.Thread(target=serve, args=(host,), daemon=True).start()
        raw = socket.create_connection(listener.getsockname(), timeout=10)
        try:
            trusting.wrap_socket(raw, server_hostname=host).close()
            assert accepted, f"a certificate for {host} was accepted"
        except ssl.SSLCertVerificationError:
            assert not accepted
    listener.close()


def test_a_value_cut_across_two_reads_is_still_removed_and_plain_text_is_not_held():
    """A response arrives in pieces that care nothing for where a key starts,
    so a redactor working a piece at a time passes each half clean. And one
    that fixes it by always holding a tail back delays the end of every
    streamed event until the next one arrives."""
    scrubber = capture._ResponseScrubber({KEY: VALUE})
    assert scrubber.feed("data: hello\n\n") == "data: hello\n\n", "plain text was held back"
    out = scrubber.feed(f"your key {VALUE[:9]}") + scrubber.feed(f"{VALUE[9:]} is wrong")
    out += scrubber.flush()
    assert out == f"your key {REDACTED} is wrong"


# ── the brokered path: sealed reads, guarded keys ──────────────────────────


def _frames(payload, root):
    """Run one streamed spawn through the broker's own handler, in process."""
    ours, theirs = socket.socketpair()
    worker = threading.Thread(target=passbook_broker._spawn_streaming,
                              args=(payload, root, {"status": "test"}, theirs), daemon=True)
    worker.start()
    raw = b""
    ours.settimeout(60)
    while b'"t":"end"' not in raw:
        more = ours.recv(65536)
        if not more:
            break
        raw += more
    worker.join(timeout=10)
    ours.close()
    theirs.close()
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def test_the_broker_captures_a_guarded_key_for_the_host_its_owner_bound(
        store, hosts, tmp_path, sessions):
    """On a machine that seals reads, or for a guarded key, `run` does not hold
    the values: the broker does, so the broker runs the proxy. This is that
    path through the broker's own handler, with the host coming from `passbook
    guard --to` instead of a flag, which is the case a flag cannot reach.

    The grant matters as much as the swap. A child the broker starts carries a
    token, and a token that listed the captured keys could be handed back to
    the broker in exchange for their values."""
    policy = access.read_policy()
    access.set_guard(KEY, policy, destinations=[ALLOWED])
    access.write_policy(policy)
    script, report = tmp_path / "client.py", tmp_path / "report.json"
    script.write_text(CLIENT, encoding="utf-8")
    plan = {"key": KEY, "report": str(report), "requests": [
        {"url": f"https://{ALLOWED}/echo", "headers": BEARER}]}

    frames = _frames({"op": "spawn", "stream": True, "app": "agent", "keys": [KEY],
                      "command": [sys.executable, str(script), json.dumps(plan)],
                      "capture": {"hosts": {}}, "cwd": str(tmp_path),
                      "env": {name: value for name, value in os.environ.items() if value}}, store)

    end = frames[-1]
    assert end["ok"] and end["exit_code"] == 0, end
    assert frames[0]["t"] == "begin" and frames[0]["capture"] is True
    seen = json.loads(report.read_text())
    assert seen["environ"][KEY].startswith(capture.STANDIN_PREFIX)
    assert VALUE not in json.dumps(seen["environ"])
    assert hosts.allowed.requests[0]["headers"]["authorization"] == f"Bearer {VALUE}"
    assert VALUE not in json.dumps(seen["answers"])
    assert end["capture"]["swapped"] == {KEY: 1}

    assert not _listening(sessions[0].port), "the broker kept the proxy after the child"
    grant = passbook_broker._grant_for(seen["environ"]["PASSBOOK_GRANT"])
    assert grant is not None and grant["keys"] == [], "the grant can be traded for the value"


def test_the_broker_holds_a_callers_host_to_the_owners_binding(store, hosts, tmp_path):
    """The caller's `--capture-host` arrives at the broker as a request, and
    the broker decides. A host outside the binding is refused there, where the
    caller cannot edit the answer."""
    policy = access.read_policy()
    access.set_guard(KEY, policy, destinations=[ALLOWED])
    access.write_policy(policy)
    marker = tmp_path / "ran"

    frames = _frames({"op": "spawn", "stream": True, "app": "agent", "keys": [KEY],
                      "command": [sys.executable, "-c", f"open({str(marker)!r}, 'w')"],
                      "capture": {"hosts": {KEY: [OTHER]}}, "cwd": str(tmp_path)}, store)

    assert frames[-1]["ok"] is False and f"cannot add {OTHER}" in frames[-1]["error"]
    assert not marker.exists(), "the command ran"


def test_a_capture_request_is_never_answered_with_a_plain_spawn(store):
    """The one-shot spawn (the MCP tool's path) cannot capture: it returns when
    the child does. Ignoring the field would start the child with real values
    for a caller that asked for stand-ins, so it is refused."""
    answer = passbook_broker._spawn(
        {"op": "spawn", "app": "agent", "keys": [KEY], "command": ["true"],
         "capture": {"hosts": {KEY: [ALLOWED]}}}, store, None)
    assert answer["ok"] is False and "streamed" in answer["error"]


def test_a_broker_from_before_capture_is_not_trusted_to_capture(store, monkeypatch, capsys):
    """A broker started before this existed ignores a field it has never heard
    of and runs the command with real values. The flag promised it would not,
    so `run` asks the broker first and refuses when it does not say yes."""
    policy = access.read_policy()
    policy["reads"] = "sealed"
    access.write_policy(policy)
    monkeypatch.setattr(passbook_broker, "running", lambda **_: True)
    monkeypatch.setattr(passbook_broker, "_ask",
                        lambda payload, **_: {"ok": True, "version": "1.10.3"})
    monkeypatch.setattr(passbook_broker, "spawn_streaming",
                        lambda *a, **k: pytest.fail("the command was sent to the old broker"))

    code = passbook_cli.main(["run", *CAPTURE, "--", "true"])
    assert code == 1
    err = capsys.readouterr().err
    assert "predates --capture" in err and "passbook broker restart" in err
    assert passbook_broker._handle({"op": "ping"}).get("capture") == 1, "this broker says it can"


@broker_marker()
def test_on_a_sealed_machine_the_command_still_holds_only_a_stand_in(tmp_path, monkeypatch):
    """The whole path on a machine shaped like a real one: an encrypted store,
    sealed reads, a real broker in its own process. `run --capture` goes
    through `_sealed_run` to that broker, and the command reports what it was
    given.

    The upstream seam cannot reach into another process, so no request is made
    here; the swap itself is proved against the same code above. What this
    proves is the wiring: the real CLI, the real socket, and a real child that
    holds a stand-in where a plain run on the same machine holds the value."""
    import passbook_vault as vault

    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for name in NOT_INHERITED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    passbook.ensure(app="test")
    passbook.set_values({KEY: VALUE})
    password = "a properly long vault password"
    profile = vault.create_profile("Owner", password=password, root=home)["id"]
    vault.seal_store(vault.unlock_with_password(profile, password, root=home),
                     profile_id=profile, root=home)
    started = passbook_broker.start()
    if not started.get("ok"):
        pytest.skip(f"the broker would not start here: {started.get('detail')}")
    try:
        passbook_broker.signin(profile=profile, password=password, duration="always")
        policy = passbook_broker.read_policy()
        policy["reads"] = "sealed"
        passbook_broker.write_policy(policy)
        assert passbook_broker.offers_capture()

        out = tmp_path / "held.json"
        show = ("import json, os, sys; json.dump({'key': os.environ.get(sys.argv[1], ''), "
                "'proxy': os.environ.get('HTTPS_PROXY', '')}, open(sys.argv[2], 'w'))")
        plain = passbook_cli.main(["run", "--only", KEY, "--", sys.executable, "-c", show,
                                   KEY, str(out)])
        assert plain == 0 and json.loads(out.read_text()) == {"key": VALUE, "proxy": ""}

        code = passbook_cli.main(["run", *CAPTURE, "--", sys.executable, "-c", show, KEY, str(out)])
        held = json.loads(out.read_text())
        assert code == 0
        assert held["key"].startswith(capture.STANDIN_PREFIX) and VALUE not in json.dumps(held)
        port = urllib.parse.urlsplit(held["proxy"]).port
        assert port and not _listening(port), "the broker kept the proxy after the child"
    finally:
        passbook_broker.stop()
