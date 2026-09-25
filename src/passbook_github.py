# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""GitHub as a place keys go: a connected account, and secrets set through its API.

`passbook push KEY --to gh:owner/repo` could already put a key in a GitHub
Actions secret, by running the `gh` CLI. This makes GitHub a connection
PassBook holds itself, so the window can list your repositories and
environments, say which secrets already exist, and set them.

## The connection is a sign-in like the others

Described in `passbook-oauth.json` beside every other sign-in (provider
`github`, id `github:connection`), with its token in the store under
`PASSBOOK_GITHUB_TOKEN`. That means sealed at rest, policy-checked and recorded
like any credential. There is no second vault.

Three ways to connect, none of them silent:

* **Device flow.** GitHub shows a code and you type it on github.com. It needs
  an OAuth app's client id with device flow switched on. None ships here, for
  the reason `passbook_oauth` gives: a client belongs to whoever registered it.
  Give yours with `--client-id` or `PASSBOOK_GITHUB_CLIENT_ID`.
* **Your `gh` login**, copied in only after you say yes. It is your token,
  issued to GitHub CLI; PassBook asks rather than borrowing it.
* **A token you paste**, hidden, e.g. a fine-grained token with
  "Secrets: read and write" on the repositories you choose.

## Secrets are encrypted here, to GitHub's key

GitHub takes a secret only as a libsodium sealed box to the repository's (or
environment's, or organisation's) public key. `seal` builds that box from
`cryptography`'s X25519 and Poly1305, plus XSalsa20, which `cryptography` does
not offer and is written out below. The tests check it against libsodium's own
output. `cryptography` is already PassBook's one dependency, and adding a
second would have meant changing every install path (the installers, the app's
bundled Python) for one feature.

A value is read, sealed and sent inside one call. It is never printed or
logged, and never goes on a command line.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Mapping

API = "https://api.github.com"
WEB = "https://github.com"
TOKEN_KEY = "PASSBOOK_GITHUB_TOKEN"
CLIENT_ID_KEY = "PASSBOOK_GITHUB_CLIENT_ID"
CONNECTION_ID = "github:connection"


def api_base() -> str:
    """`PASSBOOK_GITHUB_API` points this at GitHub Enterprise (or a test stub)."""
    import os

    return (os.environ.get("PASSBOOK_GITHUB_API") or API).rstrip("/")


def web_base() -> str:
    import os

    return (os.environ.get("PASSBOOK_GITHUB_WEB") or WEB).rstrip("/")

#: `repo` covers repository and environment secrets. `admin:org` only when you
#: ask for organisation secrets: a scope nobody asked for is a scope to leak.
REPO_SCOPE = "repo"
ORG_SCOPE = "admin:org"
VISIBILITIES = ("private", "all", "selected")

#: (method, url, headers, body text or None) -> (status, body text)
Transport = Callable[[str, str, Mapping[str, str], "str | None"], "tuple[int, str]"]


class GitHubError(RuntimeError):
    """Something GitHub said no to, in words for a person."""


# ── libsodium's sealed box, from cryptography's parts ─────────────────────

_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"
_MASK = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    value &= _MASK
    return ((value << count) | (value >> (32 - count))) & _MASK


def _double_rounds(x: list[int]) -> None:
    for _ in range(10):
        x[4] ^= _rotl(x[0] + x[12], 7); x[8] ^= _rotl(x[4] + x[0], 9)          # noqa: E702
        x[12] ^= _rotl(x[8] + x[4], 13); x[0] ^= _rotl(x[12] + x[8], 18)       # noqa: E702
        x[9] ^= _rotl(x[5] + x[1], 7); x[13] ^= _rotl(x[9] + x[5], 9)          # noqa: E702
        x[1] ^= _rotl(x[13] + x[9], 13); x[5] ^= _rotl(x[1] + x[13], 18)       # noqa: E702
        x[14] ^= _rotl(x[10] + x[6], 7); x[2] ^= _rotl(x[14] + x[10], 9)       # noqa: E702
        x[6] ^= _rotl(x[2] + x[14], 13); x[10] ^= _rotl(x[6] + x[2], 18)       # noqa: E702
        x[3] ^= _rotl(x[15] + x[11], 7); x[7] ^= _rotl(x[3] + x[15], 9)        # noqa: E702
        x[11] ^= _rotl(x[7] + x[3], 13); x[15] ^= _rotl(x[11] + x[7], 18)      # noqa: E702
        x[1] ^= _rotl(x[0] + x[3], 7); x[2] ^= _rotl(x[1] + x[0], 9)           # noqa: E702
        x[3] ^= _rotl(x[2] + x[1], 13); x[0] ^= _rotl(x[3] + x[2], 18)         # noqa: E702
        x[6] ^= _rotl(x[5] + x[4], 7); x[7] ^= _rotl(x[6] + x[5], 9)           # noqa: E702
        x[4] ^= _rotl(x[7] + x[6], 13); x[5] ^= _rotl(x[4] + x[7], 18)         # noqa: E702
        x[11] ^= _rotl(x[10] + x[9], 7); x[8] ^= _rotl(x[11] + x[10], 9)       # noqa: E702
        x[9] ^= _rotl(x[8] + x[11], 13); x[10] ^= _rotl(x[9] + x[8], 18)       # noqa: E702
        x[12] ^= _rotl(x[15] + x[14], 7); x[13] ^= _rotl(x[12] + x[15], 9)     # noqa: E702
        x[14] ^= _rotl(x[13] + x[12], 13); x[15] ^= _rotl(x[14] + x[13], 18)   # noqa: E702


def _state(key: bytes, middle: bytes) -> list[int]:
    k = struct.unpack("<8I", key)
    m = struct.unpack("<4I", middle)
    return [_SIGMA[0], k[0], k[1], k[2], k[3], _SIGMA[1], m[0], m[1],
            m[2], m[3], _SIGMA[2], k[4], k[5], k[6], k[7], _SIGMA[3]]


def _hsalsa20(key: bytes, nonce16: bytes) -> bytes:
    x = _state(key, nonce16)
    _double_rounds(x)
    return struct.pack("<8I", x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9])


def _xsalsa20_stream(key: bytes, nonce24: bytes, length: int) -> bytes:
    subkey = _hsalsa20(key, nonce24[:16])
    out = bytearray()
    counter = 0
    while len(out) < length:
        start = _state(subkey, nonce24[16:24] + struct.pack("<Q", counter))
        x = list(start)
        _double_rounds(x)
        out += struct.pack("<16I", *((a + b) & _MASK for a, b in zip(x, start)))
        counter += 1
    return bytes(out[:length])


def _secretbox(message: bytes, nonce24: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    stream = _xsalsa20_stream(key, nonce24, 32 + len(message))
    cipher = bytes(a ^ b for a, b in zip(message, stream[32:]))
    return Poly1305.generate_tag(stream[:32], cipher) + cipher


def _secretbox_open(box: bytes, nonce24: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    tag, cipher = box[:16], box[16:]
    stream = _xsalsa20_stream(key, nonce24, 32 + len(cipher))
    Poly1305.verify_tag(stream[:32], cipher, tag)  # raises InvalidSignature
    return bytes(a ^ b for a, b in zip(cipher, stream[32:]))


def _box_key(private, public_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared = private.exchange(X25519PublicKey.from_public_bytes(public_raw))
    return _hsalsa20(shared, b"\0" * 16)  # crypto_box_beforenm


def seal(public_key: bytes, message: bytes, *, ephemeral: bytes | None = None) -> bytes:
    """`crypto_box_seal`: an anonymous box only `public_key`'s owner can open.

    `ephemeral` pins the one-off key, for known-answer tests only.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    if len(public_key) != 32:
        raise GitHubError("GitHub's public key is not 32 bytes.")
    one_off = (X25519PrivateKey.from_private_bytes(ephemeral) if ephemeral is not None
               else X25519PrivateKey.generate())
    one_off_public = one_off.public_key().public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw)
    nonce = hashlib.blake2b(one_off_public + public_key, digest_size=24).digest()
    return one_off_public + _secretbox(message, nonce, _box_key(one_off, public_key))


def open_sealed(private_key: bytes, box: bytes) -> bytes:
    """`crypto_box_seal_open`. PassBook never needs it; the tests do."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    mine = X25519PrivateKey.from_private_bytes(private_key)
    my_public = mine.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
    theirs = box[:32]
    nonce = hashlib.blake2b(theirs + my_public, digest_size=24).digest()
    return _secretbox_open(box[32:], nonce, _box_key(mine, theirs))


def encrypt_for(public_key_b64: str, value: str) -> str:
    """What GitHub's `encrypted_value` field wants."""
    sealed = seal(base64.b64decode(public_key_b64), value.encode("utf-8"))
    return base64.b64encode(sealed).decode("ascii")


# ── names and targets ──────────────────────────────────────────────────────

def secret_name(name: str) -> str:
    """GitHub's rules for a secret name, checked before anything is sent.

    Letters, digits and underscores; not starting with a digit or `GITHUB_`.
    GitHub stores names in upper case, so the name is upper-cased here and the
    person sees the name that will actually exist.
    """
    text = str(name or "").strip().upper()
    if not text:
        raise GitHubError("A secret needs a name.")
    if not re.fullmatch(r"[A-Z0-9_]+", text):
        raise GitHubError(f"{name!r}: a secret name is letters, digits and underscores only.")
    if text[0].isdigit():
        raise GitHubError(f"{name!r}: a secret name cannot start with a digit.")
    if text.startswith("GITHUB_"):
        raise GitHubError(f"{name!r}: names starting with GITHUB_ are reserved by GitHub.")
    return text


_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PLAIN = re.compile(r"^[A-Za-z0-9_.-]+$")


def target(repo: str = "", env: str = "", org: str = "", visibility: str = "private") -> dict[str, str]:
    """A place secrets go: a repository, one of its environments, or an org."""
    repo, env, org = str(repo or "").strip(), str(env or "").strip(), str(org or "").strip()
    if bool(repo) == bool(org):
        raise GitHubError("Say a repository (owner/name) or an organisation, not both.")
    if repo and not _REPO.match(repo):
        raise GitHubError(f"{repo!r} is not owner/name.")
    if env and (not repo or not re.fullmatch(r"[^/\x00-\x1f]{1,255}", env)):
        raise GitHubError("An environment belongs to a repository.")
    if org:
        if not _PLAIN.match(org):
            raise GitHubError(f"{org!r} is not an organisation name.")
        if visibility not in VISIBILITIES:
            raise GitHubError(f"Visibility is one of {', '.join(VISIBILITIES)}.")
        if visibility == "selected":
            raise GitHubError("Choosing repositories for an org secret is not supported yet; "
                              "use private or all.")
        return {"org": org, "visibility": visibility}
    return {"repo": repo, "env": env} if env else {"repo": repo}


def describe(where: Mapping[str, str]) -> str:
    if where.get("org"):
        return f"org {where['org']} ({where.get('visibility', 'private')})"
    return where["repo"] + (f", environment {where['env']}" if where.get("env") else "")


def label(where: Mapping[str, str], name: str, key: str) -> str:
    """The service label a push is recorded under; same shape as `passbook_sinks`."""
    if where.get("org"):
        base = f"github-org:{where['org']}"
    else:
        base = f"github:{where['repo']}" + (f"@{where['env']}" if where.get("env") else "")
    return base + (f"/{name}" if name != key else "")


def _base(where: Mapping[str, str]) -> str:
    if where.get("org"):
        return f"/orgs/{urllib.parse.quote(where['org'])}/actions/secrets"
    owner, name = where["repo"].split("/", 1)
    repo = f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}"
    if where.get("env"):
        return f"{repo}/environments/{urllib.parse.quote(where['env'], safe='')}/secrets"
    return f"{repo}/actions/secrets"


# ── talking to GitHub ──────────────────────────────────────────────────────

def direct_transport(token: str) -> Transport:
    """Requests from this process, holding the token for their length."""
    def send(method: str, url: str, headers: Mapping[str, str], body: str | None):
        request = urllib.request.Request(url, method=method, data=body.encode() if body else None,
                                         headers={**headers, "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310
                return answer.status, answer.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as error:
            raise GitHubError(f"Could not reach GitHub: {getattr(error, 'reason', error)}") from None
    return send


def broker_transport(app: str, root=None) -> Transport:
    """Requests the broker makes, filling the token in itself.

    For a machine that seals reads: this process never holds the token. The
    token has to be bound to api.github.com (`passbook guard`), which
    `passbook github connect` offers to do.
    """
    import passbook
    import passbook_broker

    def send(method: str, url: str, headers: Mapping[str, str], body: str | None):
        answer = passbook_broker._ask({
            "op": "proxy", "app": app, "url": url, "method": method,
            "headers": {**headers, "Authorization": "Bearer {{" + TOKEN_KEY + "}}"},
            "body": body, "reason": "GitHub secrets", "project": passbook.project(),
            "workspace": passbook.workspace() or "main"}, root=root) or {}
        if not answer.get("ok"):
            why = answer.get("why") or {}
            raise GitHubError(str(why.get(TOKEN_KEY) or answer.get("error") or "the broker refused"))
        return int(answer.get("status") or 0), str(answer.get("body") or "")
    return send


class Client:
    def __init__(self, transport: Transport):
        self.transport = transport

    def call(self, method: str, path: str, body: Any = None, *, ok=(200, 201, 204)) -> tuple[int, Any]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "passbook"}
        text = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            text = json.dumps(body)
        status, raw = self.transport(method, api_base() + path, headers, text)
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {}
        if status not in ok:
            message = data.get("message") if isinstance(data, dict) else ""
            raise GitHubError(_explain(status, str(message or ""), path))
        return status, data

    def user(self) -> dict[str, Any]:
        return self.call("GET", "/user")[1]

    def repos(self, limit: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while len(out) < limit:
            _, batch = self.call("GET", f"/user/repos?per_page=100&page={page}&sort=pushed"
                                        "&affiliation=owner,collaborator,organization_member")
            if not isinstance(batch, list) or not batch:
                break
            for repo in batch:
                if isinstance(repo, dict):
                    permissions = repo.get("permissions") or {}
                    out.append({"repo": repo.get("full_name", ""), "private": bool(repo.get("private")),
                                "admin": bool(permissions.get("admin")),
                                "pushedAt": repo.get("pushed_at") or ""})
            if len(batch) < 100:
                break
            page += 1
        return out[:limit]

    def orgs(self) -> list[str]:
        _, data = self.call("GET", "/user/orgs?per_page=100")
        return [str(org.get("login")) for org in data if isinstance(org, dict)] if isinstance(data, list) else []

    def environments(self, repo: str) -> list[str]:
        owner, name = repo.split("/", 1)
        _, data = self.call("GET", f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}"
                                   "/environments?per_page=100")
        return [str(env.get("name")) for env in (data.get("environments") or [])
                if isinstance(env, dict)] if isinstance(data, dict) else []

    def existing(self, where: Mapping[str, str], name: str) -> dict[str, Any] | None:
        """The secret's metadata if it exists (never a value; GitHub has none to give)."""
        status, data = self.call("GET", f"{_base(where)}/{urllib.parse.quote(name)}", ok=(200, 404))
        if status == 404:
            return None
        return {"name": data.get("name", name), "updatedAt": data.get("updated_at", "")}

    def public_key(self, where: Mapping[str, str]) -> tuple[str, str]:
        _, data = self.call("GET", f"{_base(where)}/public-key")
        return str(data.get("key_id", "")), str(data.get("key", ""))

    def put(self, where: Mapping[str, str], name: str, value: str) -> str:
        """Seal `value` to the target's key and store it. "created" or "updated"."""
        name = secret_name(name)
        key_id, key = self.public_key(where)
        body: dict[str, Any] = {"encrypted_value": encrypt_for(key, value), "key_id": key_id}
        if where.get("org"):
            body["visibility"] = where.get("visibility", "private")
        status, _ = self.call("PUT", f"{_base(where)}/{urllib.parse.quote(name)}", body)
        return "created" if status == 201 else "updated"


def _explain(status: int, message: str, path: str) -> str:
    if status == 401:
        return "GitHub did not accept the connection's token. Connect again: passbook github connect"
    if status == 403:
        return ("GitHub refused: the token cannot manage secrets there "
                f"({message or 'forbidden'}). It needs admin on the repository"
                + (", and admin:org for an organisation." if "/orgs/" in path else "."))
    if status == 404:
        return ("GitHub found nothing there, or the token cannot see it. Check the name, "
                "and that the token has access.")
    if status == 422:
        return f"GitHub refused the request: {message or 'unprocessable'}"
    return f"GitHub answered {status}: {message or 'no detail'}"


# ── connecting ─────────────────────────────────────────────────────────────

def _form(url: str, form: Mapping[str, str], opener=None) -> dict[str, Any]:
    request = urllib.request.Request(url, data=urllib.parse.urlencode(dict(form)).encode(),
                                     headers={"Accept": "application/json", "User-Agent": "passbook"})
    try:
        with (opener or urllib.request.urlopen)(request, timeout=30) as answer:  # noqa: S310
            return json.loads(answer.read().decode() or "{}")
    except urllib.error.HTTPError as error:
        try:
            return json.loads(error.read().decode() or "{}")
        except ValueError:
            return {"error": f"http_{error.code}"}
    except (urllib.error.URLError, OSError) as error:
        raise GitHubError(f"Could not reach GitHub: {getattr(error, 'reason', error)}") from None


def device_start(client_id: str, scope: str, *, opener=None) -> dict[str, Any]:
    """Step one of the device flow. The `device_code` stays in this process."""
    answer = _form(web_base() + "/login/device/code", {"client_id": client_id, "scope": scope}, opener)
    if not answer.get("device_code"):
        raise GitHubError("GitHub would not start a sign-in"
                          + (f": {answer.get('error_description') or answer.get('error')}"
                             if answer.get("error") else "")
                          + ". Is device flow switched on for that OAuth app?")
    return answer


def device_wait(client_id: str, started: Mapping[str, Any], *, opener=None,
                sleep=time.sleep, clock=time.monotonic) -> str:
    """Poll until the person approves. Returns the token; raises on no."""
    interval = int(started.get("interval") or 5)
    deadline = clock() + int(started.get("expires_in") or 900)
    while clock() < deadline:
        sleep(interval)
        answer = _form(web_base() + "/login/oauth/access_token", {
            "client_id": client_id, "device_code": str(started["device_code"]),
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}, opener)
        if answer.get("access_token"):
            return str(answer["access_token"])
        error = str(answer.get("error") or "")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval = int(answer.get("interval") or interval + 5)
            continue
        if error == "access_denied":
            raise GitHubError("The sign-in was declined on GitHub; nothing was saved.")
        if error == "expired_token":
            break
        raise GitHubError(f"GitHub ended the sign-in: {answer.get('error_description') or error}")
    raise GitHubError("The code expired before it was entered; nothing was saved.")


def gh_login_available(runner=subprocess.run) -> bool:
    try:
        return runner(["gh", "auth", "status", "--hostname", "github.com"],
                      capture_output=True, text=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def gh_token(runner=subprocess.run) -> str:
    """The `gh` CLI's token, read from its stdout into memory. Never printed."""
    try:
        done = runner(["gh", "auth", "token", "--hostname", "github.com"],
                      capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as error:
        raise GitHubError(f"Could not ask gh for its login: {error}") from None
    token = (done.stdout or "").strip()
    if done.returncode != 0 or not token:
        raise GitHubError("gh is not signed in to github.com.")
    return token


def connection_from(client: Client, *, method: str) -> dict[str, Any]:
    """Who the token belongs to. Fails before anything is saved if it does not work."""
    who = client.user()
    login = str(who.get("login") or "")
    if not login:
        raise GitHubError("GitHub did not say whose token that is.")
    return {"account": login, "method": method}


# ── the record of the connection ───────────────────────────────────────────

def read_connection(*, root=None) -> dict[str, Any] | None:
    import passbook_oauth

    for grant in passbook_oauth.read_grants(root=root).get("grants", []):
        if isinstance(grant, dict) and grant.get("id") == CONNECTION_ID:
            return grant
    return None


def save_connection(details: Mapping[str, Any], *, root=None) -> dict[str, Any]:
    """Record the connection beside the other sign-ins. The token is not here."""
    import passbook_oauth

    vault = passbook_oauth.read_grants(root=root)
    vault["grants"] = [g for g in vault["grants"]
                       if not (isinstance(g, dict) and g.get("id") == CONNECTION_ID)]
    record = {
        "id": CONNECTION_ID, "provider": "github", "label": "GitHub",
        "account": str(details.get("account", "")), "method": str(details.get("method", "")),
        # No `key_prefix`, on purpose: every reader of this file that renews
        # or lists OAuth grants skips an entry without one, including a broker
        # already running older code. A connection is not a refreshable grant.
        "scope": str(details.get("scope", "")),
        "keys": {"access_token": TOKEN_KEY}, "token_url": "", "connection": True,
        "created_at": passbook_oauth._now_iso(), "connected_at": passbook_oauth._now_iso(),
    }
    vault["grants"].append(record)
    passbook_oauth._write(vault, root=root)
    return record


def forget_connection(*, root=None) -> bool:
    import passbook_oauth

    vault = passbook_oauth.read_grants(root=root)
    kept = [g for g in vault["grants"] if not (isinstance(g, dict) and g.get("id") == CONNECTION_ID)]
    if len(kept) == len(vault["grants"]):
        return False
    vault["grants"] = kept
    passbook_oauth._write(vault, root=root)
    return True


def status(*, root=None) -> dict[str, Any]:
    """Names only: whether GitHub is connected, as whom, and how."""
    import passbook

    record = read_connection(root=root)
    held = TOKEN_KEY in set(passbook.key_names())
    if not record:
        return {"connected": False, "tokenStored": held}
    return {"connected": held, "account": record.get("account", ""),
            "method": record.get("method", ""), "scope": record.get("scope", ""),
            "connectedAt": record.get("connected_at", ""), "tokenStored": held}


def names_in(values: Iterable[str]) -> list[str]:
    return sorted({str(value) for value in values if str(value)})
