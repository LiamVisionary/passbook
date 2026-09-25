# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""GitHub as a place keys go, against a stub of GitHub's API.

The stub is a real HTTP server on localhost that answers the handful of
endpoints PassBook uses, with a keypair of its own. It decrypts every secret it
is sent, so these tests check the property that matters: what reached "GitHub"
opens to the value in the store, under the name the person chose, and the token
and the value appear nowhere else — not in output, not in the record, not on a
command line.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook_github as github  # noqa: E402
from _platform import needs_a_posix_shell  # noqa: E402

TOKEN = "gho_fake_token_for_tests_0123456789"
VALUE = "fake-secret-value-111"
NEWER = "fake-secret-value-222"

# A known answer from libsodium (PyNaCl 1.6.2): crypto_box with the one-off key
# bytes(33..64) to the recipient bytes(1..32), nonce blake2b(epk || pk). Fake
# keys, fake message.
KAT_PRIVATE = bytes(range(1, 33))
KAT_EPHEMERAL = bytes(range(33, 65))
KAT_PUBLIC = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
KAT_MESSAGE = b"fake-secret-for-a-known-answer-test"
KAT_BOX = ("WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpnu1FhadLJj3B20ktELh9AiRJLn1bq0tKRQasY7AS"
           "qK2ZjQI/VCFY0jopsqn0A5Y7VHpm+g=")


# ── the sealed box ──────────────────────────────────────────────────────────

def test_the_sealed_box_matches_libsodium_byte_for_byte():
    box = github.seal(base64.b64decode(KAT_PUBLIC), KAT_MESSAGE, ephemeral=KAT_EPHEMERAL)
    assert base64.b64encode(box).decode() == KAT_BOX


def test_libsodiums_box_opens_here():
    assert github.open_sealed(KAT_PRIVATE, base64.b64decode(KAT_BOX)) == KAT_MESSAGE


def test_a_box_opens_only_with_its_key_and_only_untouched():
    from cryptography.exceptions import InvalidSignature

    box = bytearray(github.seal(base64.b64decode(KAT_PUBLIC), b"fake"))
    assert github.open_sealed(KAT_PRIVATE, bytes(box)) == b"fake"
    box[-1] ^= 1
    with pytest.raises(InvalidSignature):
        github.open_sealed(KAT_PRIVATE, bytes(box))
    with pytest.raises(InvalidSignature):
        github.open_sealed(bytes(range(2, 34)), github.seal(base64.b64decode(KAT_PUBLIC), b"fake"))


def test_every_box_is_fresh():
    public = base64.b64decode(KAT_PUBLIC)
    assert github.seal(public, b"same") != github.seal(public, b"same")


@pytest.mark.parametrize("length", [0, 1, 63, 64, 65, 200])
def test_block_boundaries_round_trip(length):
    message = bytes(range(256))[:length] * 1
    assert github.open_sealed(KAT_PRIVATE, github.seal(base64.b64decode(KAT_PUBLIC), message)) == message


def test_it_agrees_with_pynacl_when_that_is_installed():
    nacl = pytest.importorskip("nacl.public")
    key = nacl.PrivateKey.generate()
    box = github.seal(bytes(key.public_key), b"fake-cross-check")
    assert nacl.SealedBox(key).decrypt(box) == b"fake-cross-check"


# ── names and targets ──────────────────────────────────────────────────────

@pytest.mark.parametrize("name, stored", [("DEPLOY_KEY", "DEPLOY_KEY"), ("deploy_key", "DEPLOY_KEY"),
                                          ("_X1", "_X1")])
def test_a_good_name_is_stored_upper_case(name, stored):
    assert github.secret_name(name) == stored


@pytest.mark.parametrize("bad", ["", "GITHUB_TOKEN", "github_x", "1ABC", "HAS-DASH", "HAS SPACE",
                                 "DOT.NAME"])
def test_githubs_naming_rules(bad):
    with pytest.raises(github.GitHubError):
        github.secret_name(bad)


def test_a_target_is_a_repo_an_environment_or_an_org():
    assert github.target(repo="acme/app") == {"repo": "acme/app"}
    assert github.target(repo="acme/app", env="production") == {"repo": "acme/app", "env": "production"}
    assert github.target(org="acme", visibility="all") == {"org": "acme", "visibility": "all"}
    for bad in ({"repo": "acme"}, {"repo": "acme/app", "org": "acme"}, {},
                {"org": "acme", "env": "x"}, {"org": "acme", "visibility": "selected"}):
        with pytest.raises(github.GitHubError):
            github.target(**bad)


# ── a stub GitHub ───────────────────────────────────────────────────────────

class StubGitHub:
    """Enough of api.github.com and github.com/login for PassBook, on localhost."""

    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        self.private = X25519PrivateKey.generate()
        self.private_raw = self.private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        self.public_b64 = base64.b64encode(self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.secrets: dict[str, dict] = {}  # path -> {value, key_id, visibility}
        self.existing = {"/repos/acme/app/actions/secrets/TAKEN": "2026-09-01T10:00:00Z"}
        self.log: list[dict] = []
        self.device_polls = 0
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                size = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(size).decode() if size else ""

            def do_GET(self):
                stub.log.append({"method": "GET", "path": self.path,
                                 "auth": self.headers.get("Authorization", "")})
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._answer(401, {"message": "Bad credentials"})
                path = self.path.split("?")[0]
                if path == "/user":
                    return self._answer(200, {"login": "octo-fake"})
                if path == "/user/repos":
                    return self._answer(200, [
                        {"full_name": "acme/app", "private": True, "permissions": {"admin": True}},
                        {"full_name": "acme/site", "private": False, "permissions": {"admin": False}}])
                if path == "/user/orgs":
                    return self._answer(200, [{"login": "acme"}])
                if path == "/repos/acme/app/environments":
                    return self._answer(200, {"environments": [{"name": "production"}]})
                if path.endswith("/public-key"):
                    return self._answer(200, {"key_id": "kid-1", "key": stub.public_b64})
                if path in stub.existing or path in stub.secrets:
                    return self._answer(200, {"name": path.rsplit("/", 1)[1],
                                              "updated_at": stub.existing.get(path, "2026-09-25T00:00:00Z")})
                return self._answer(404, {"message": "Not Found"})

            def do_PUT(self):
                raw = self._body()
                stub.log.append({"method": "PUT", "path": self.path, "body": raw,
                                 "auth": self.headers.get("Authorization", "")})
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._answer(401, {"message": "Bad credentials"})
                data = json.loads(raw)
                value = github.open_sealed(stub.private_raw, base64.b64decode(data["encrypted_value"]))
                created = self.path not in stub.secrets and self.path not in stub.existing
                stub.secrets[self.path] = {"value": value.decode(), "key_id": data["key_id"],
                                           "visibility": data.get("visibility")}
                self.send_response(201 if created else 204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                raw = self._body()
                stub.log.append({"method": "POST", "path": self.path, "body": raw})
                if self.path == "/login/device/code":
                    return self._answer(200, {"device_code": "dev-fake", "user_code": "ABCD-1234",
                                              "verification_uri": "https://github.com/login/device",
                                              "interval": 0, "expires_in": 60})
                if self.path == "/login/oauth/access_token":
                    stub.device_polls += 1
                    if stub.device_polls < 2:
                        return self._answer(200, {"error": "authorization_pending"})
                    return self._answer(200, {"access_token": TOKEN, "token_type": "bearer"})
                return self._answer(404, {})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def value_at(self, path):
        return self.secrets.get(path, {}).get("value")


@pytest.fixture
def gh(tmp_path):
    stub = StubGitHub()
    home = tmp_path / "hive"
    home.mkdir()
    tools = tmp_path / "bin"
    tools.mkdir()
    # Recorded pushes run `passbook …` by name, as they do on a real machine.
    (tools / "passbook").write_text(
        f"#!/bin/sh\nexec {sys.executable} {SRC / 'passbook_cli.py'} \"$@\"\n")
    (tools / "passbook").chmod(0o755)
    outputs: list = []

    def run(args, stdin=None, extra=None):
        environment = {**os.environ, "HIVE_HOME": str(home), "PASSBOOK_KEYSTORE": "file",
                       "PASSBOOK_GITHUB_API": stub.url, "PASSBOOK_GITHUB_WEB": stub.url,
                       "PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}", **(extra or {})}
        for inherited in ("PASSBOOK_GRANT", "PASSBOOK_SERVICE", "PASSBOOK_GITHUB_TOKEN"):
            environment.pop(inherited, None)
        done = subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args],
                              capture_output=True, text=True, env=environment, input=stdin,
                              cwd=str(tmp_path), timeout=120)
        outputs.append(done)
        return done

    stub.run, stub.home, stub.tools, stub.outputs = run, home, tools, outputs
    assert run(["add", f"DEPLOY_TOKEN={VALUE}"]).returncode == 0
    yield stub
    stub.server.shutdown()
    for done in outputs:
        for text in (done.stdout, done.stderr):
            assert TOKEN not in text, "the GitHub token was printed"
            assert VALUE not in text and NEWER not in text, "a secret value was printed"
    for entry in stub.log:
        assert VALUE not in entry.get("body", "") and NEWER not in entry.get("body", ""), \
            "a value travelled unencrypted"
    record = (home / "credential-access-proofs.jsonl")
    if record.exists():
        assert TOKEN not in record.read_text() and VALUE not in record.read_text()


def _connect(gh):
    done = gh.run(["github", "connect", "--token-stdin", "--json"], stdin=TOKEN + "\n")
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


# ── connecting ─────────────────────────────────────────────────────────────

def test_connect_with_a_token_names_the_account_and_stores_it_as_a_key(gh):
    answer = _connect(gh)
    assert answer["account"] == "octo-fake" and answer["method"] == "token"
    status = json.loads(gh.run(["github", "status", "--json"]).stdout)
    assert status == {**status, "connected": True, "account": "octo-fake", "tokenStored": True}
    assert "PASSBOOK_GITHUB_TOKEN" in gh.run(["list"]).stdout
    grants = json.loads((gh.home / "passbook-oauth.json").read_text())["grants"]
    assert [g["id"] for g in grants] == ["github:connection"], "beside the other sign-ins"
    assert TOKEN not in (gh.home / "passbook-oauth.json").read_text()


def test_a_token_github_rejects_is_not_saved(gh):
    done = gh.run(["github", "connect", "--token-stdin"], stdin="gho_wrong\n")
    assert done.returncode == 1 and "did not accept" in done.stderr
    assert "PASSBOOK_GITHUB_TOKEN" not in gh.run(["list"]).stdout


def test_device_flow_waits_for_the_code_then_connects(gh):
    done = gh.run(["github", "connect", "--device", "--client-id", "Iv1.fakeclient", "--json"])
    assert done.returncode == 0, done.stderr
    first, last = [json.loads(line) for line in done.stdout.strip().splitlines()]
    assert first == {"userCode": "ABCD-1234", "verificationUri": "https://github.com/login/device"}
    assert last["account"] == "octo-fake" and last["method"] == "device"
    assert gh.device_polls == 2, "it kept polling through authorization_pending"
    assert not (gh.home / "github-device.json").exists(), "the pending code is cleared"


def test_device_flow_needs_somebodys_client_id(gh):
    done = gh.run(["github", "connect", "--device"])
    assert done.returncode == 1 and "client id" in done.stderr


@needs_a_posix_shell
def test_the_gh_login_is_used_only_after_a_yes(gh):
    (gh.tools / "gh").write_text(f'#!/bin/sh\n[ "$2" = token ] && echo {TOKEN}\nexit 0\n')
    (gh.tools / "gh").chmod(0o755)
    refused = gh.run(["github", "connect", "--from-gh"])
    assert refused.returncode == 1 and "--yes" in refused.stderr
    assert "PASSBOOK_GITHUB_TOKEN" not in gh.run(["list"]).stdout
    done = gh.run(["connect", "github", "--from-gh", "--yes", "--json"])
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["method"] == "gh"


def test_disconnect_forgets_the_token_and_the_record(gh):
    _connect(gh)
    assert gh.run(["github", "disconnect"]).returncode == 1, "needs a yes off a terminal"
    done = gh.run(["disconnect", "github", "--yes"])
    assert done.returncode == 0, done.stderr
    assert "PASSBOOK_GITHUB_TOKEN" not in gh.run(["list"]).stdout
    assert json.loads(gh.run(["github", "status", "--json"]).stdout)["connected"] is False


# ── listing ────────────────────────────────────────────────────────────────

def test_targets_environments_and_existing_names(gh):
    _connect(gh)
    targets = json.loads(gh.run(["github", "targets", "--json"]).stdout)
    assert [r["repo"] for r in targets["repos"]] == ["acme/app", "acme/site"]
    assert targets["repos"][1]["admin"] is False and targets["orgs"] == ["acme"]
    envs = json.loads(gh.run(["github", "environments", "acme/app", "--json"]).stdout)
    assert envs["environments"] == ["production"]
    checked = json.loads(gh.run(["github", "check", "TAKEN", "fresh", "GITHUB_X",
                                 "--repo", "acme/app", "--json"]).stdout)["secrets"]
    assert checked[0] == {"name": "TAKEN", "valid": True, "exists": True,
                          "updatedAt": "2026-09-01T10:00:00Z"}
    assert checked[1]["name"] == "FRESH" and checked[1]["exists"] is False
    assert checked[2]["valid"] is False


# ── pushing ────────────────────────────────────────────────────────────────

@needs_a_posix_shell
def test_push_seals_to_the_repos_key_and_records_the_renamed_secret(gh):
    _connect(gh)
    done = gh.run(["push", "DEPLOY_TOKEN", "--to", "gh:acme/app:CI_DEPLOY"])
    assert done.returncode == 0, done.stderr + done.stdout
    assert gh.value_at("/repos/acme/app/actions/secrets/CI_DEPLOY") == VALUE
    assert gh.secrets["/repos/acme/app/actions/secrets/CI_DEPLOY"]["key_id"] == "kid-1"
    listed = json.loads(gh.run(["services", "list", "DEPLOY_TOKEN", "--json"]).stdout)["DEPLOY_TOKEN"]
    assert listed[0]["service"] == "github:acme/app/CI_DEPLOY"
    assert listed[0]["kind"] == "gh-secret" and listed[0]["secretName"] == "CI_DEPLOY"
    assert listed[0]["command"] == ("passbook run --only PASSBOOK_GITHUB_TOKEN -- passbook sink "
                                    "gh-secret CI_DEPLOY --repo acme/app")
    assert listed[0]["lastStatus"] == "ok"


@needs_a_posix_shell
def test_an_existing_secret_is_replaced_only_when_asked(gh):
    _connect(gh)
    refused = gh.run(["push", "DEPLOY_TOKEN", "--to", "gh:acme/app:TAKEN"])
    assert refused.returncode == 1
    assert "TAKEN already exists" in refused.stderr and "2026-09-01T10:00:00Z" in refused.stderr
    assert "--overwrite" in refused.stderr
    assert not any(entry["method"] == "PUT" for entry in gh.log)
    done = gh.run(["push", "DEPLOY_TOKEN", "--to", "gh:acme/app:TAKEN", "--overwrite"])
    assert done.returncode == 0, done.stderr
    assert gh.value_at("/repos/acme/app/actions/secrets/TAKEN") == VALUE


@needs_a_posix_shell
def test_environment_and_org_secrets(gh):
    _connect(gh)
    env = gh.run(["push", "DEPLOY_TOKEN", "--to", "gh:acme/app", "--env", "production"])
    assert env.returncode == 0, env.stderr
    assert gh.value_at("/repos/acme/app/environments/production/secrets/DEPLOY_TOKEN") == VALUE
    org = gh.run(["push", "DEPLOY_TOKEN", "--to", "gh-org:acme:ORG_DEPLOY", "--visibility", "all"])
    assert org.returncode == 0, org.stderr
    assert gh.secrets["/orgs/acme/actions/secrets/ORG_DEPLOY"] == {
        "value": VALUE, "key_id": "kid-1", "visibility": "all"}
    services = {item["service"] for item in json.loads(
        gh.run(["services", "list", "DEPLOY_TOKEN", "--json"]).stdout)["DEPLOY_TOKEN"]}
    assert services == {"github:acme/app@production", "github-org:acme/ORG_DEPLOY"}


def test_a_bad_secret_name_is_refused_before_anything_is_sent(gh):
    _connect(gh)
    for bad in ("GITHUB_DEPLOY", "1DEPLOY"):
        done = gh.run(["push", "DEPLOY_TOKEN", "--to", f"gh:acme/app:{bad}"])
        assert done.returncode == 1, bad
    assert not any(entry["method"] == "PUT" for entry in gh.log)


@needs_a_posix_shell
def test_rotate_sends_the_new_value_under_the_same_renamed_secret(gh):
    _connect(gh)
    gh.run(["push", "DEPLOY_TOKEN", "--to", "gh:acme/app:CI_DEPLOY"])
    rotated = gh.run(["rotate", "DEPLOY_TOKEN", "--stdin"], stdin=NEWER + "\n")
    assert rotated.returncode == 0, rotated.stderr + rotated.stdout
    assert gh.value_at("/repos/acme/app/actions/secrets/CI_DEPLOY") == NEWER
    assert "github:acme/app/CI_DEPLOY" in rotated.stdout


@needs_a_posix_shell
def test_the_windows_plan_sends_several_keys_and_reports_each(gh):
    _connect(gh)
    gh.run(["add", "OTHER_TOKEN=fake-other-333"])
    plan = {"target": {"repo": "acme/app"},
            "items": [{"key": "DEPLOY_TOKEN", "name": "renamed_one"},
                      {"key": "OTHER_TOKEN", "name": "TAKEN"}],
            "overwrite": ["TAKEN"]}
    done = gh.run(["github", "push", "--plan-stdin"], stdin=json.dumps(plan))
    assert done.returncode == 0, done.stderr + done.stdout
    answer = json.loads(done.stdout)
    assert [(r["key"], r["name"], r["ok"]) for r in answer["results"]] == [
        ("DEPLOY_TOKEN", "RENAMED_ONE", True), ("OTHER_TOKEN", "TAKEN", True)]
    assert gh.value_at("/repos/acme/app/actions/secrets/RENAMED_ONE") == VALUE
    assert gh.value_at("/repos/acme/app/actions/secrets/TAKEN") == "fake-other-333"


@needs_a_posix_shell
def test_github_push_by_flags_renames_and_refuses_an_unasked_overwrite(gh):
    _connect(gh)
    done = gh.run(["github", "push", "DEPLOY_TOKEN", "--repo", "acme/app",
                   "--name", "DEPLOY_TOKEN=SHIP_IT", "--yes"])
    assert done.returncode == 0, done.stderr + done.stdout
    assert "DEPLOY_TOKEN" in done.stdout and "SHIP_IT" in done.stdout
    assert gh.value_at("/repos/acme/app/actions/secrets/SHIP_IT") == VALUE
    clash = gh.run(["github", "push", "DEPLOY_TOKEN", "--repo", "acme/app",
                    "--name", "DEPLOY_TOKEN=TAKEN", "--yes"])
    assert clash.returncode == 1 and "Pass --overwrite" in clash.stderr


def test_without_a_connection_gh_specs_still_use_the_gh_cli(gh):
    dry = gh.run(["push", "DEPLOY_TOKEN", "--to", "gh:acme/app", "--env", "production", "--dry-run"])
    assert "gh secret set DEPLOY_TOKEN --repo acme/app --env production" in dry.stdout


def test_the_token_only_ever_travels_in_the_authorization_header(gh):
    _connect(gh)
    gh.run(["github", "targets", "--json"])
    assert all(entry.get("auth") in ("", f"Bearer {TOKEN}") for entry in gh.log)
    assert not any(TOKEN in entry.get("body", "") for entry in gh.log)


def test_the_connection_is_not_mistaken_for_a_refreshable_sign_in(gh):
    """It lives in the sign-ins file. Every reader that lists or renews OAuth
    grants skips an entry without a key prefix, so a broker running older code
    never tries to renew it and the Sign-ins page does not offer 'Sign in again'
    for something that has no browser sign-in."""
    _connect(gh)
    record = json.loads((gh.home / "passbook-oauth.json").read_text())["grants"][0]
    assert record["id"] == "github:connection" and "key_prefix" not in record
    listed = gh.run(["oauth", "--json"])
    assert json.loads(listed.stdout) == []
