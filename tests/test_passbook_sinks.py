# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Reading where a command puts a key, and never guessing.

The record of which services hold a key was empty on the machine it was built
for, because the only way to fill it was typing `passbook services attach` by
hand after the fact. The keys were reaching Workers and GitHub through
`passbook run` all along. These tests pin the recogniser that turns those runs
into records: it finds the shapes that name a service, it refuses to guess which
key went where, and what it records pushes on stdin with every borrowed part
quoted.
"""

from __future__ import annotations

import io
import json
import shlex
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_sinks as sinks  # noqa: E402


def _one(command, keys, cwd):
    found, notes = sinks.detect(command, keys, cwd=str(cwd))
    assert len(found) == 1, (found, notes)
    return found[0]


# ── wrangler ────────────────────────────────────────────────────────────────

def test_a_worker_secret_piped_in_through_a_shell(tmp_path):
    sink = _one(["sh", "-c", 'printf %s "$API_KEY" | npx wrangler secret put API_KEY --name api'],
                ["API_KEY"], tmp_path)
    assert sink["key"] == "API_KEY"
    assert sink["service"] == "worker:api"
    assert sink["stdin"] is True
    assert sink["command"] == "npx wrangler secret put API_KEY --name api", \
        "started the way the person started it, value on stdin"


def test_the_worker_name_comes_from_the_config_when_not_given(tmp_path):
    (tmp_path / "wrangler.toml").write_text(
        'name = "site-api"\nmain = "src/index.ts"\n[env.staging]\nname = "not-this"\n')
    sink = _one(["wrangler", "secret", "put", "API_KEY"], ["API_KEY"], tmp_path)
    assert sink["service"] == "worker:site-api"
    assert "--name site-api" in sink["command"]
    assert sink["cwd"] == str(tmp_path)


def test_jsonc_config_and_an_environment(tmp_path):
    (tmp_path / "wrangler.jsonc").write_text('{\n  // comment\n  "name": "edge"\n}\n')
    sink = _one(["wrangler", "versions", "secret", "put", "API_KEY", "--env", "prod"],
                ["API_KEY"], tmp_path)
    assert sink["service"] == "worker:edge@prod"
    assert sink["command"].startswith("wrangler versions secret put API_KEY --name edge")
    assert "--env prod" in sink["command"]


def test_pages_secret(tmp_path):
    sink = _one(["wrangler", "pages", "secret", "put", "API_KEY", "--project-name", "docs"],
                ["API_KEY"], tmp_path)
    assert sink["service"] == "pages:docs"
    assert sink["kind"] == "wrangler-pages-secret"


def test_bulk_records_each_key_the_run_mentions(tmp_path):
    found, _ = sinks.detect(
        ["sh", "-c", 'printf \'{"A":"%s","B":"%s"}\' "$A" "$B" | wrangler secret bulk --name w'],
        ["A", "B"], cwd=str(tmp_path))
    assert sorted(sink["key"] for sink in found) == ["A", "B"]
    assert all(sink["command"].startswith("wrangler secret put") for sink in found)


def test_secrets_store_goes_through_passbooks_own_helper(tmp_path):
    sink = _one(["npx", "wrangler", "secrets-store", "secret", "create", "abc123",
                 "--name", "API_KEY", "--scopes", "workers", "--remote"], ["API_KEY"], tmp_path)
    assert sink["kind"] == "cf-secrets-store"
    assert sink["service"] == "cf-secrets-store:abc123/API_KEY"
    assert "passbook sink cf-secrets-store abc123 API_KEY" in sink["command"]
    assert "--only CLOUDFLARE_API_TOKEN" in sink["command"]


# ── GitHub, Vercel, Fly ─────────────────────────────────────────────────────

def test_gh_secret_with_body_on_argv_is_recorded_with_stdin(tmp_path):
    sink = _one(["sh", "-c", 'gh secret set DEPLOY --repo acme/app --body "$API_KEY"'],
                ["API_KEY"], tmp_path)
    assert sink["key"] == "API_KEY", "the key the command referenced, not the name it used"
    assert sink["service"] == "github:acme/app/DEPLOY"
    assert sink["command"] == "gh secret set DEPLOY --repo acme/app"
    assert "--body" not in sink["command"]
    assert "command line" in sink["warning"]


def test_gh_environment_and_org(tmp_path):
    env = _one(["gh", "secret", "set", "API_KEY", "-R", "acme/app", "-e", "production"],
               ["API_KEY"], tmp_path)
    assert env["service"] == "github:acme/app@production"
    assert "--env production" in env["command"]
    org = _one(["gh", "secret", "set", "API_KEY", "--org", "acme", "--visibility", "all"],
               ["API_KEY"], tmp_path)
    assert org["service"] == "github-org:acme"
    assert "--visibility all" in org["command"]


def test_gh_variable_is_flagged_as_not_secret(tmp_path):
    sink = _one(["gh", "variable", "set", "API_KEY", "--repo", "acme/app"], ["API_KEY"], tmp_path)
    assert sink["nonSecret"] is True
    assert "not secret" in sink["warning"]


def test_gh_repo_comes_from_the_git_remote(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin",
                    "git@github.com:acme/site.git"], check=True)
    sink = _one(["gh", "secret", "set", "API_KEY"], ["API_KEY"], tmp_path)
    assert sink["service"] == "github:acme/site"
    assert "--repo acme/site" in sink["command"]


def test_vercel_env_add_is_replayed_with_force(tmp_path):
    project = tmp_path / "web"
    project.mkdir()
    sink = _one(["vercel", "env", "add", "API_KEY", "production"], ["API_KEY"], project)
    assert sink["service"] == "vercel:web@production"
    assert sink["command"] == "vercel env add API_KEY production --force", \
        "a replay adds over an existing value, which needs --force"


def test_fly_secrets_set_never_replays_the_value_on_argv(tmp_path):
    (tmp_path / "fly.toml").write_text('app = "api-prod"\n')
    sink = _one(["sh", "-c", 'fly secrets set API_KEY="$API_KEY"'], ["API_KEY"], tmp_path)
    assert sink["service"] == "fly:api-prod"
    assert sink["stdin"] is False
    assert "fly secrets import --app api-prod" in sink["command"]
    assert '"$API_KEY"' in sink["command"] and "printf" in sink["command"]


# ── what it refuses to do ───────────────────────────────────────────────────

def test_it_does_not_guess_which_key_went_where(tmp_path):
    """Two keys handed over, a secret put under a third name, neither mentioned:
    recording either would make a rotation push the wrong key."""
    found, notes = sinks.detect(["wrangler", "secret", "put", "OTHER", "--name", "w"],
                                ["A", "B"], cwd=str(tmp_path))
    assert found == []
    assert notes and "--used-in" in notes[0]


def test_a_script_that_does_not_mention_the_key_is_not_a_push_of_it(tmp_path):
    found, _ = sinks.detect(["sh", "-c", "echo literal | wrangler secret put OTHER --name w"],
                            ["API_KEY"], cwd=str(tmp_path))
    assert found == []


def test_ordinary_commands_are_not_sinks(tmp_path):
    for command in (["wrangler", "deploy"], ["gh", "pr", "list"], ["node", "server.js"],
                    ["sh", "-c", "wrangler secret list"], ["vercel", "env", "ls"]):
        assert sinks.detect(command, ["API_KEY"], cwd=str(tmp_path)) == ([], []), command


def test_without_named_keys_it_still_says_where(tmp_path):
    found, notes = sinks.detect(["wrangler", "secret", "put", "API_KEY", "--name", "w"], [],
                                cwd=str(tmp_path))
    assert [sink["service"] for sink in found] == ["worker:w"]
    assert found[0]["key"] == "" and notes == []


def test_borrowed_parts_are_quoted_not_executed(tmp_path):
    sink = _one(["wrangler", "secret", "put", "API_KEY", "--name", "$(touch pwned)"],
                ["API_KEY"], tmp_path)
    assert shlex.split(sink["command"])[-1] == "$(touch pwned)"
    assert "'$(touch pwned)'" in sink["command"]


# ── specs for `passbook push --to` ─────────────────────────────────────────

@pytest.mark.parametrize("spec, service, fragment", [
    ("wrangler:api", "worker:api", "secret put API_KEY --name api"),
    ("wrangler:api:OPENAI", "worker:api/OPENAI", "secret put OPENAI --name api"),
    ("wrangler-pages:docs", "pages:docs", "pages secret put API_KEY --project-name docs"),
    ("gh:acme/app", "github:acme/app", "gh secret set API_KEY --repo acme/app"),
    ("gh-env:acme/app:prod", "github:acme/app@prod", "--env prod"),
    ("gh-org:acme", "github-org:acme", "--org acme"),
    ("gh-var:acme/app", "github-var:acme/app", "gh variable set API_KEY"),
    ("vercel:production", "vercel:", "vercel env add API_KEY production --force"),
    ("fly:api-prod", "fly:api-prod", "secrets import --app api-prod"),
    ("cf-secrets-store:abc123", "cf-secrets-store:abc123/API_KEY", "sink cf-secrets-store abc123 API_KEY"),
])
def test_every_spec_form(spec, service, fragment, tmp_path):
    sink = sinks.parse_spec(spec, "API_KEY", cwd=str(tmp_path))
    assert sink["service"].startswith(service)
    assert fragment in sink["command"]


@pytest.mark.parametrize("bad", ["", "wrangler", "wrangler:", "nope:thing", "gh:noslash",
                                 "wrangler:a:b:c", "wrangler:$(x)", "gh:acme/app:not-a-name"])
def test_a_bad_spec_says_what_the_good_ones_are(bad):
    with pytest.raises(sinks.SinkError):
        sinks.parse_spec(bad, "API_KEY")


# ── Cloudflare Secrets Store over its API ──────────────────────────────────

class _FakeCloudflare:
    """Answers like the API does, and remembers what it was sent."""

    def __init__(self, existing):
        self.existing = existing
        self.calls = []

    def __call__(self, request, timeout=None):
        body = json.loads(request.data.decode()) if request.data else None
        self.calls.append((request.get_method(), request.full_url, body))
        if request.get_method() == "GET":
            payload = {"success": True, "result": self.existing,
                       "result_info": {"page": 1, "total_pages": 1}}
        else:
            payload = {"success": True, "result": {}}
        response = io.BytesIO(json.dumps(payload).encode())
        response.__enter__ = lambda *a: response
        response.__exit__ = lambda *a: None
        return response


def test_an_existing_secret_is_patched_by_its_id():
    api = _FakeCloudflare([{"id": "s1", "name": "OTHER"}, {"id": "s2", "name": "API_KEY"}])
    ok, detail = sinks.cf_store_put("store1", "API_KEY", "fake-value", account="acct",
                                    token="tok", opener=api)
    assert ok and detail == "updated"
    method, url, body = api.calls[-1]
    assert method == "PATCH" and url.endswith("/stores/store1/secrets/s2")
    assert body == {"value": "fake-value"}


def test_a_missing_secret_is_created_with_its_scopes():
    api = _FakeCloudflare([])
    ok, detail = sinks.cf_store_put("store1", "API_KEY", "fake-value", account="acct",
                                    token="tok", opener=api)
    assert ok and detail == "created"
    method, url, body = api.calls[-1]
    assert method == "POST" and url.endswith("/accounts/acct/secrets_store/stores/store1/secrets")
    assert body[0]["name"] == "API_KEY" and body[0]["scopes"] == ["workers"]
