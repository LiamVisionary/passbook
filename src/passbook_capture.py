# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook capture — a child that uses a credential it never holds.

Optional companion to `passbook_grant.py`, reached through
`passbook run --only KEY --capture`.

## The problem this exists for

`passbook run` puts real values in the child's environment. That is the right
default: it is what every program already knows how to read. It is also the
weakest place a credential can sit while it is in use. Another process running
as the same user can read a child's environment, and so can every dependency
the child loads, every crash reporter that dumps `os.environ`, and every debug
log that prints its configuration.

`proxy_request` already avoids this. The value is filled in at send time and
never enters an environment. But it only works for a caller that knows about
PassBook and writes `{{KEY}}` into its request. `wrangler`, `curl`, an SDK and
somebody's deploy script do not.

## The rule

**The child gets a stand-in. The real value is put on the wire by PassBook, on
the way to the one host that key is for, and nowhere else.**

For the length of one launch:

  * each captured key's variable holds a random stand-in of the same name
  * a forward proxy listens on 127.0.0.1, on a port the OS chose, and the child
    is pointed at it by `HTTPS_PROXY`, with a credential minted for this launch
  * a CONNECT to a host on some captured key's list is opened: the request is
    read, a stand-in whose key is allowed for THAT host is replaced by the
    value, and the request goes on over a connection PassBook verified
  * a CONNECT to any other host is copied through unread. No certificate is
    made for it, and a stand-in sent there arrives as a stand-in
  * what comes back from an opened host has every captured value removed, with
    the same forms `passbook_grant.redact` already knows

## Why the list is the whole of it

A proxy that swapped a stand-in wherever it saw one would be `passbook get`
with a network hop: the child names a host, sends the stand-in, and reads the
value off the far end. So a key with no host does not start (`allowlist`), and
a key is only ever swapped for a host on its own list (`Session.keys_for`).
Nothing here infers a host from a key's name. A wrong guess sends a credential
to somebody else's server, and that is not a mistake worth making on a guess.

## What this does not buy

Stated here because the failure mode is somebody relying on a boundary that was
never there.

**It is not a sandbox for hostile code.** The child can still use the key
against its own host for as long as it runs, and a host that will transform and
return what it is sent (a model asked to spell a string backwards) hands the
value back in a form no redactor can recognise. Capture stops the value sitting
in an environment and stops it travelling to another host. It does not confine
a program that is trying.

**Only what goes through the proxy is swapped.** A program that ignores
`HTTPS_PROXY`, pins certificates, or trusts the operating system's store
instead of the variables set here sends the stand-in, or refuses the
connection. Either way it fails to authenticate. It does not leak.

**Only values sent as they are.** A key used to sign something (AWS SigV4, a
JWT, a webhook signature) is never on the wire, so there is nothing to swap and
the signature is made with the stand-in.

**HTTP/1.1 only** on an opened connection. No HTTP/2, no WebSocket upgrade, and
a body larger than `MAX_SWAP_BODY` is passed on without being searched.

**On a machine whose store this process can read**, the child can read it too.
Capture keeps the value out of the environment; `passbook policy --reads
sealed` is what keeps it out of reach.

The two functions `_upstream_context` and `_upstream_address` are the seam the
tests use to stand a local server in for a real host. No flag, no environment
variable and no file changes them: a switch that redirected where real values
are sent would be the vulnerability this module exists to prevent.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import collections
import hmac
import json
import os
import re
import secrets
import selectors
import shutil
import socket
import ssl
import tempfile
import threading
import urllib.parse
import zlib
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

import passbook_grant

__all__ = [
    "CaptureError",
    "MAX_SWAP_BODY",
    "STANDIN_PREFIX",
    "Session",
    "allowlist",
    "host_entry",
    "parse_host_flags",
]

# What a captured variable holds in the child: `pbk-standin-` and 32 hex
# characters, 128 random bits, new for every key on every launch. Lower-case
# hex and hyphens on purpose: URL-encoding, JSON and a shell all leave it
# exactly as it is, so it can be found again wherever the child puts it.
STANDIN_PREFIX = "pbk-standin-"

# A request body up to this size is read whole and searched. A larger one is
# passed on as it arrives, unsearched, with the request line and headers still
# swapped. Credentials live in headers and small bodies; the large ones are
# uploads, and holding an upload in memory to look for a token it will not
# contain is how a proxy falls over on a shared machine.
MAX_SWAP_BODY = 8 * 1024 * 1024

# A request line and its headers. Larger is refused rather than buffered.
MAX_HEAD = 64 * 1024

# How long a certificate made here is good for. The key that signed it lives
# only in this process, so the date protects nothing once the launch ends; it
# is this long so a server left running under capture does not stop working
# one morning. A child that outlives it has to be started again.
VALID_DAYS = 365

PROXY_USER = "passbook"
CONNECT_TIMEOUT = 30.0
HANDSHAKE_TIMEOUT = 30.0
IDLE_TIMEOUT = 300.0

# Where a system keeps its public roots, tried in order after what Python's own
# TLS was built to use. `SSL_CERT_FILE` REPLACES a runtime's default bundle, so
# the file the child is given has to contain these as well as ours.
_ROOT_FILES = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
)
# The variables that replace a runtime's bundle: OpenSSL and Python, requests,
# curl. `NODE_EXTRA_CA_CERTS` adds to Node's instead and is handled apart.
_BUNDLE_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CHUNK_SIZE = re.compile(rb"^[0-9A-Fa-f]{1,16}$")
# Left as they are when a value is written into a request target. Everything
# else is percent-encoded, so a value holding `&`, `#` or a space cannot change
# what the URL means.
_TARGET_SAFE = "-._~:@"
# Hop-by-hop, or rewritten below because the body's length or coding changes.
_DROPPED_REQUEST = frozenset({
    b"proxy-authorization", b"proxy-connection", b"expect", b"accept-encoding",
    b"content-length", b"transfer-encoding", b"trailer",
})
_DROPPED_RESPONSE = frozenset({
    b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"trailer",
})


class CaptureError(ValueError):
    """Capture cannot start. The message says why, and `remedy` what fixes it."""

    def __init__(self, message: str, remedy: str = "") -> None:
        super().__init__(message)
        self.remedy = remedy


class _Bad(Exception):
    """A request this proxy will not carry, answered with a status and a reason."""

    def __init__(self, status: int, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.status, self.reason, self.detail = status, reason, detail


class _Closed(Exception):
    """The other end went away in the middle of a message."""


# ── which host a key may go to ─────────────────────────────────────────────


def host_entry(text: Any) -> str:
    """One allowed destination, normalised: `api.example.com` or `.example.com`.

    The same two forms `passbook guard --to` takes, and no others. A scheme, a
    port, a path or a `*` is refused rather than tidied up, because a list
    somebody thinks says one thing and that matches another is worse than an
    error. Addresses are refused too: a certificate is checked against a name.
    """
    entry = str(text or "").strip().lower()
    suffix = entry.startswith(".")
    name = entry[1:] if suffix else entry
    if not name or len(name) > 253 or not _HOSTNAME.match(name):
        raise CaptureError(
            f"{str(text)!r} is not a host name.",
            "Give the bare host, like api.example.com, or .example.com for a "
            "domain and everything under it.")
    labels = name.split(".")
    if labels[-1].isdigit():
        raise CaptureError(
            f"{str(text)!r} is an address, not a name.",
            "A certificate is checked against a name, so capture needs the host's name.")
    if suffix and len(labels) < 2:
        raise CaptureError(
            f"{str(text)!r} would cover every host under a top-level domain.",
            "Name the domain: .example.com")
    return entry


def parse_host_flags(flags: Iterable[str] | None) -> dict[str, list[str]]:
    """`--capture-host KEY=host`, repeated, as {KEY: [hosts]}."""
    found: dict[str, list[str]] = {}
    for raw in flags or []:
        key, sep, host = str(raw).partition("=")
        key = key.strip()
        if not sep or not _KEY.match(key) or not host.strip():
            raise CaptureError(
                f"--capture-host takes KEY=host; got {str(raw)!r}.",
                "Like:  --capture-host OPENAI_API_KEY=api.openai.com")
        entry = host_entry(host)
        if entry not in found.setdefault(key, []):
            found[key].append(entry)
    return found


def _covers(entry: str, host: str) -> bool:
    """Does this entry admit this host? The rule `host_allowed` uses."""
    if entry.startswith("."):
        return host == entry[1:] or host.endswith(entry)
    return host == entry


def _within(narrow: str, wide: str) -> bool:
    """Is every host `narrow` admits also admitted by `wide`?"""
    if narrow.startswith("."):
        return wide.startswith(".") and narrow.endswith(wide)
    return _covers(wide, narrow)


def allowlist(keys: Iterable[str], policy: Mapping[str, Any],
              flags: Mapping[str, Sequence[str]] | None = None) -> dict[str, list[str]]:
    """Where each captured key may be sent, or a refusal naming what is missing.

    Two sources and nothing else. A key its owner bound with `passbook guard
    KEY --to HOST` goes where the binding says: that is the one place PassBook
    already records a host for a key. Any other key needs `--capture-host`.

    A binding is the owner's and a flag is the caller's, so a flag may narrow a
    binding and may not widen it. Letting it would turn `--capture-host` into a
    way round `guard`.

    A key with neither is refused, by name. Falling back to the real value in
    the environment would be the old behaviour under a flag that promises the
    new one.
    """
    named = {str(key): list(hosts) for key, hosts in (flags or {}).items()}
    wanted = list(dict.fromkeys(str(key) for key in keys))
    stray = sorted(set(named) - set(wanted))
    if stray:
        raise CaptureError(
            f"--capture-host names {', '.join(stray)}, which --only does not.",
            "Add it to --only, or drop the flag.")
    hosts: dict[str, list[str]] = {}
    missing: list[str] = []
    for key in wanted:
        asked = [host_entry(entry) for entry in named.get(key) or []]
        written = passbook_grant.destinations_for(key, policy)
        if written:
            bound = []
            for entry in written:
                try:
                    bound.append(host_entry(entry))
                except CaptureError:
                    continue  # not a form capture can match; never widened to fit
            if not bound:
                raise CaptureError(
                    f"{key} is bound to {', '.join(written)}, which capture cannot match.",
                    f"Bind it to a host name:  passbook guard {key} --to api.example.com")
            outside = [entry for entry in asked
                       if not any(_within(entry, wide) for wide in bound)]
            if outside:
                raise CaptureError(
                    f"{key} is guarded and may only be sent to {', '.join(bound)}; "
                    f"--capture-host cannot add {', '.join(outside)}.",
                    f"Change the binding instead:  passbook guard {key} --to <host>")
            hosts[key] = asked or bound
        elif asked:
            hosts[key] = asked
        else:
            missing.append(key)
    if missing:
        first = missing[0]
        raise CaptureError(
            f"{', '.join(missing)} {'has' if len(missing) == 1 else 'have'} no known host, "
            f"so --capture has nowhere it may send the real value.",
            f"Name one:  --capture-host {first}=api.example.com\n"
            f"Or bind it for good:  passbook guard {first} --to api.example.com")
    return hosts


# ── upstream: the seam the tests use, and nothing else does ────────────────


def _upstream_context() -> ssl.SSLContext:
    """How the real host is verified: the system's roots, and its name."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    return context


def _upstream_address(host: str, port: int) -> tuple[str, int]:
    """Where a host is reached. The name itself; the resolver does the rest."""
    return host, port


# ── the per-launch authority ───────────────────────────────────────────────


def _load_chain(context: ssl.SSLContext, cert_pem: bytes, key_pem: bytes) -> None:
    """Give TLS a certificate and its key without either touching a disk.

    Python's `ssl` loads a key from a path and offers nothing else. So the path
    is a pipe: the bytes are written into one, and OpenSSL reads them back out
    of `/dev/fd/N`. Nothing is created in a filesystem, and the pipe is gone
    when this returns.
    """
    readers: list[int] = []
    try:
        paths = []
        for blob in (cert_pem, key_pem):
            reader, writer = os.pipe()
            readers.append(reader)
            try:
                os.write(writer, blob)  # far under a pipe's buffer; cannot block
            finally:
                os.close(writer)
            paths.append(f"/dev/fd/{reader}")
        context.load_cert_chain(paths[0], paths[1])
    finally:
        for reader in readers:
            os.close(reader)


class _Authority:
    """A certificate authority that exists for one launch, in memory.

    Its key is never serialised. Its certificate is public and is what the
    child is told to trust. It is name-constrained to the hosts on the list, so
    even the certificate itself says it cannot vouch for anything else: a
    runtime that checks constraints refuses a leaf for another name whoever
    signed it.
    """

    def __init__(self, entries: Iterable[str]) -> None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        except ImportError as error:
            raise CaptureError(
                "--capture needs the `cryptography` package, and this Python does not have it.",
                "The installed tool carries it:  uv tool install passbook") from error
        import datetime

        self._x509, self._hashes, self._serialization, self._ec = x509, hashes, serialization, ec
        self._server_auth, self._name_oid = ExtendedKeyUsageOID.SERVER_AUTH, NameOID
        now = datetime.datetime.now(datetime.timezone.utc)
        self._not_before = now - datetime.timedelta(hours=1)  # a child's clock may trail ours
        self._not_after = now + datetime.timedelta(days=VALID_DAYS)
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, f"PassBook capture, one launch ({secrets.token_hex(4)})")])
        permitted = sorted({entry.lstrip(".") for entry in entries})
        builder = (
            x509.CertificateBuilder()
            .subject_name(self._name).issuer_name(self._name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before).not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()),
                           critical=False))
        if permitted:
            builder = builder.add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(name) for name in permitted],
                excluded_subtrees=None), critical=True)
        self.cert_pem = builder.sign(self._key, hashes.SHA256()).public_bytes(
            serialization.Encoding.PEM)
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self.minted: list[str] = []
        try:
            self._context("probe.invalid")  # fail at start, not on the first request
        except OSError as error:
            raise CaptureError(
                "This system cannot hand TLS a key from memory (no usable /dev/fd), "
                "and --capture will not write one to disk.",
                f"({type(error).__name__})") from error

    def _context(self, host: str) -> ssl.SSLContext:
        x509 = self._x509
        if self._key is None:
            raise _Closed()
        key = self._ec.generate_private_key(self._ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(self._name_oid.COMMON_NAME, host[:64])]))
            .issuer_name(self._name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before).not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([self._server_auth]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._key.public_key()), critical=False)
            .sign(self._key, self._hashes.SHA256()))
        encoding = self._serialization.Encoding.PEM
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # HTTP/1.1 and nothing else is offered, so a client that could speak
        # HTTP/2 is told not to. What is read here is one request at a time.
        context.set_alpn_protocols(["http/1.1"])
        _load_chain(context, cert.public_bytes(encoding), key.private_bytes(
            encoding, self._serialization.PrivateFormat.PKCS8,
            self._serialization.NoEncryption()))
        return context

    def context_for(self, host: str) -> ssl.SSLContext:
        """The server side of TLS for one allowed host, made once per launch."""
        with self._lock:
            context = self._contexts.get(host)
            if context is None:
                context = self._contexts[host] = self._context(host)
                self.minted.append(host)
            return context

    def forget(self) -> None:
        """Drop the key. Dropped, not wiped: Python cannot zero its own memory."""
        with self._lock:
            self._key = None
            self._contexts.clear()


# ── reading HTTP off a socket ──────────────────────────────────────────────


class _Reader:
    """Bytes from one socket, with what was read past a boundary kept."""

    def __init__(self, sock: Any) -> None:
        self.sock = sock
        self.buffer = b""

    def _more(self) -> bool:
        data = self.sock.recv(65536)
        if not data:
            return False
        self.buffer += data
        return True

    def head(self, limit: int = MAX_HEAD) -> bytes | None:
        """A start line and headers, through the blank line. None at a clean end."""
        while True:
            self.buffer = self.buffer.lstrip(b"\r\n")
            at = self.buffer.find(b"\r\n\r\n")
            if at != -1:
                head, self.buffer = self.buffer[:at + 4], self.buffer[at + 4:]
                return head
            if len(self.buffer) > limit:
                raise _Bad(431, "Request Header Fields Too Large")
            if not self._more():
                if self.buffer:
                    raise _Closed()
                return None

    def line(self, limit: int) -> bytes:
        while True:
            at = self.buffer.find(b"\r\n")
            if at != -1:
                line, self.buffer = self.buffer[:at], self.buffer[at + 2:]
                return line
            if len(self.buffer) > limit:
                raise _Bad(400, "Bad Request", "a line is too long")
            if not self._more():
                raise _Closed()

    def some(self, most: int) -> bytes:
        if not self.buffer and not self._more():
            return b""
        piece, self.buffer = self.buffer[:most], self.buffer[most:]
        return piece

    def exact(self, count: int) -> bytes:
        pieces = []
        for piece in self.stream(count):
            pieces.append(piece)
        return b"".join(pieces)

    def stream(self, count: int) -> Iterator[bytes]:
        while count:
            piece = self.some(min(count, 65536))
            if not piece:
                raise _Closed()
            count -= len(piece)
            yield piece

    def rest(self) -> Iterator[bytes]:
        while True:
            piece = self.some(65536)
            if not piece:
                return
            yield piece

    def chunks(self) -> Iterator[bytes]:
        """The data of a chunked body. Trailers are read and dropped."""
        while True:
            size_text = self.line(1024).split(b";", 1)[0].strip()
            if not _CHUNK_SIZE.match(size_text):
                raise _Bad(400, "Bad Request", "a chunk size is not hexadecimal")
            size = int(size_text, 16)
            if size == 0:
                while self.line(MAX_HEAD):
                    pass
                return
            yield from self.stream(size)
            if self.exact(2) != b"\r\n":
                raise _Bad(400, "Bad Request", "a chunk does not end where it says")


def _parse_head(head: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    """A start line and its headers, strictly.

    Strict because this message is rewritten and sent on. A header folded over
    two lines, or one with no colon, is where two parsers disagree about what a
    request says, and the request going out must mean what the one coming in
    meant.
    """
    lines = head[:-4].split(b"\r\n")
    start = lines[0]
    if b"\n" in start or b"\r" in start or b"\0" in start:
        raise _Bad(400, "Bad Request", "the start line is malformed")
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if (not sep or not _TOKEN.match(name)
                or b"\n" in value or b"\r" in value or b"\0" in value):
            raise _Bad(400, "Bad Request", "a header line is malformed")
        headers.append((name, value.strip(b" \t")))
    return start, headers


def _get(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    return [value for held, value in headers if held.lower() == name]


def _tokens(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    return [token.strip().lower() for value in _get(headers, name)
            for token in value.split(b",") if token.strip()]


def _chunk(data: bytes) -> bytes:
    return b"%x\r\n" % len(data) + data + b"\r\n"


def _respond(sock: Any, status: int, reason: str, detail: str = "",
             headers: Sequence[tuple[str, str]] = ()) -> None:
    body = (detail + "\n").encode("utf-8") if detail else b""
    lines = [f"HTTP/1.1 {status} {reason}", *(f"{name}: {value}" for name, value in headers),
             "Content-Type: text/plain; charset=utf-8", f"Content-Length: {len(body)}",
             "Connection: close", "Via: 1.1 passbook-capture", "", ""]
    try:
        sock.sendall("\r\n".join(lines).encode("latin-1") + body)
    except OSError:
        pass


def _readable(socks: Sequence[Any], timeout: float) -> list[Any]:
    # A selector, not select(): this also runs inside the broker, which holds
    # far more descriptors than select() can be handed.
    with selectors.DefaultSelector() as selector:
        for sock in socks:
            selector.register(sock, selectors.EVENT_READ)
        return [key.fileobj for key, _ in selector.select(timeout)]


def _still_open(sock: Any) -> bool:
    """Is an idle TLS connection still there, or did the far end hang up?

    Readable does not mean closed: TLS 1.3 sends tickets and key updates on an
    idle connection. Reading one byte tells them apart. Wanting more means it
    was only bookkeeping; nothing, or data nobody asked for, means it is over.
    """
    sock.settimeout(0)
    try:
        sock.recv(1)
    except (ssl.SSLWantReadError, BlockingIOError):
        return True
    except OSError:
        return False
    finally:
        try:
            sock.settimeout(None)
        except OSError:
            pass
    return False


class _ResponseScrubber:
    """`passbook_grant.redact` over a stream, holding back only what it must.

    `passbook_grant.Scrubber` holds back a fixed tail, which is right for a
    build log and wrong for a response streamed an event at a time: the end of
    every event would wait for the next one. This holds back only a tail that
    is the beginning of something it would redact, so ordinary text passes
    straight through and a value split across two reads is still caught whole.
    """

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        self._needles = [
            form for value in self._values.values()
            if len(value) >= passbook_grant.MIN_REDACTABLE
            for form in passbook_grant._encodings(value)]
        self._longest = max((len(needle) for needle in self._needles), default=0)
        self._buffer = ""

    def feed(self, text: str) -> str:
        if not self._needles:
            return text
        self._buffer = passbook_grant.redact(self._buffer + text, self._values)
        held = 0
        for size in range(min(self._longest - 1, len(self._buffer)), 0, -1):
            tail = self._buffer[-size:]
            if any(needle.startswith(tail) for needle in self._needles):
                held = size
                break
        if not held:
            ready, self._buffer = self._buffer, ""
        else:
            ready, self._buffer = self._buffer[:-held], self._buffer[-held:]
        return ready

    def flush(self) -> str:
        rest, self._buffer = self._buffer, ""
        return passbook_grant.redact(rest, self._values)


def _system_roots() -> bytes:
    """The public roots this machine trusts, as one PEM file's worth."""
    paths = ssl.get_default_verify_paths()
    for path in (paths.cafile, paths.openssl_cafile, *_ROOT_FILES):
        data = _pem(path)
        if data:
            return data
    try:
        import certifi  # not a dependency; used when it happens to be there

        return _pem(certifi.where())
    except ImportError:
        return b""


def _pem(path: Any) -> bytes:
    try:
        data = Path(str(path)).read_bytes() if path else b""
    except OSError:
        return b""
    return data.rstrip() + b"\n" if b"-----BEGIN CERTIFICATE-----" in data else b""


# ── one launch ─────────────────────────────────────────────────────────────


class Session:
    """Everything capture holds for one child: stand-ins, proxy, authority.

    `start()` before the child, `environment()` into it, `stop()` after it.
    Nothing outlives `stop()`: the listener is closed, every open connection is
    cut, the authority's key is dropped and the directory holding the public
    certificate is removed.
    """

    def __init__(self, values: Mapping[str, str], hosts: Mapping[str, Sequence[str]], *,
                 base_env: Mapping[str, str] | None = None) -> None:
        self._values = {str(name): str(value) for name, value in values.items()}
        if not self._values:
            raise CaptureError("--capture has no key to stand in for.")
        empty = sorted(name for name, value in self._values.items() if not value)
        if empty:
            raise CaptureError(f"--capture has no value to stand in for: {', '.join(empty)}.")
        # Checked again here, not only in `allowlist`: this is the object that
        # will hold real values, and it must not be possible to build one that
        # has a key with nowhere to go.
        homeless = sorted(name for name in self._values if not hosts.get(name))
        if homeless:
            raise CaptureError(f"{', '.join(homeless)} has no host it may be sent to.")
        self.hosts = {name: [host_entry(entry) for entry in hosts[name]] for name in self._values}
        self.standins = {name: STANDIN_PREFIX + secrets.token_hex(16) for name in self._values}
        self._base = dict(os.environ if base_env is None else base_env)
        self._token = secrets.token_urlsafe(24)
        self._expected = base64.b64encode(f"{PROXY_USER}:{self._token}".encode("ascii"))
        self._lock = threading.Lock()
        self._seen: dict[str, collections.Counter] = {
            name: collections.Counter() for name in
            ("opened", "tunnelled", "swapped", "distrusted", "unreachable", "unsearched", "refused")}
        self._sockets: set[Any] = set()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        self._authority: _Authority | None = None
        self._context: ssl.SSLContext | None = None
        self._listener: socket.socket | None = None
        self._accepting: threading.Thread | None = None
        self._dir = ""
        self._files: dict[str, str] = {}
        self.port = 0
        self.notes: list[str] = []

    # ── lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> "Session":
        if os.name == "nt":
            raise CaptureError(
                "--capture is not available on Windows yet.",
                "It hands TLS a key through /dev/fd so that none is written to disk.")
        try:
            self._authority = _Authority(
                entry for entries in self.hosts.values() for entry in entries)
            self._dir = tempfile.mkdtemp(prefix="passbook-capture-")  # 0700, by mkdtemp
            self._write_bundles()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))  # the OS picks, so two launches never collide
            listener.listen(64)
            listener.settimeout(0.2)
            self._listener, self.port = listener, listener.getsockname()[1]
            self._accepting = threading.Thread(target=self._accept, daemon=True,
                                               name="passbook-capture")
            self._accepting.start()
        except BaseException:
            self.stop()
            raise
        return self

    def stop(self) -> None:
        """Take all of it down. Safe to call twice, and after a failed start."""
        self._stopping.set()
        if self._accepting is not None:
            self._accepting.join(timeout=5)
            self._accepting = None
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        with self._lock:
            open_now, self._sockets = list(self._sockets), set()
            threads, self._threads = list(self._threads), []
        for sock in open_now:
            _hang_up(sock)
        for thread in threads:
            thread.join(timeout=1)
        if self._authority is not None:
            self._authority.forget()
        self._values = {}
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = ""

    def __enter__(self) -> "Session":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()

    # ── what the child is given ────────────────────────────────────────────

    def _write(self, name: str, data: bytes) -> str:
        path = os.path.join(self._dir, name)
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(handle, data)
        finally:
            os.close(handle)
        return path

    def _write_bundles(self) -> None:
        """Public certificates only. The authority's key is never written.

        A variable that replaces a runtime's bundle gets the roots that runtime
        would have used, plus ours: the system's, or the file the caller had
        already pointed that variable at, so a company's own bundle keeps
        working and is not quietly widened to the public roots it left out.
        """
        assert self._authority is not None
        ours = self._authority.cert_pem
        system = _system_roots()
        if not system:
            self.notes.append("no system certificate bundle was found, so the command "
                              "will trust only the captured hosts")
        written: dict[bytes, str] = {}
        for variable in _BUNDLE_VARS:
            roots = _pem(self._base.get(variable)) or system
            if roots not in written:
                written[roots] = self._write(f"ca-bundle-{len(written)}.pem", roots + ours)
            self._files[variable] = written[roots]
        self._files["NODE_EXTRA_CA_CERTS"] = self._write(
            "passbook-capture-ca.pem", _pem(self._base.get("NODE_EXTRA_CA_CERTS")) + ours)

    def environment(self) -> dict[str, str]:
        """What to lay over the child's environment. Holds no real value."""
        if not self.port:
            raise CaptureError("capture has not started")
        proxy = f"http://{PROXY_USER}:{self._token}@127.0.0.1:{self.port}"
        env = dict(self.standins)
        # HTTPS only. `HTTP_PROXY` is deliberately not set: this proxy carries
        # CONNECT and nothing else, and a credential on a cleartext request is
        # a credential given away, so there is no path here that could swap one.
        env["HTTPS_PROXY"] = env["https_proxy"] = proxy
        env.update(self._files)
        # Node reads the proxy variables only when told to (22.21 and 24 on).
        env["NODE_USE_ENV_PROXY"] = "1"
        return env

    def unredactable(self) -> list[str]:
        """Captured keys too short to remove from a response. Names only."""
        return sorted(name for name, covered in
                      passbook_grant.redactions_for(self._values).items() if not covered)

    def report(self) -> dict[str, Any]:
        """What happened, for a diagnosis. Key names, host names and counts."""
        with self._lock:
            return {name: dict(counter) for name, counter in self._seen.items()}

    def _count(self, what: str, name: str, by: int = 1) -> None:
        with self._lock:
            self._seen[what][name] += by

    # ── the allowlist check ────────────────────────────────────────────────

    def keys_for(self, host: str) -> list[str]:
        """The captured keys that may be sent to this host. Empty means none.

        This is the decision the whole module rests on. An empty answer makes
        the connection a blind tunnel; a key absent from a non-empty one keeps
        its stand-in on a connection that is otherwise opened.
        """
        return [name for name, entries in self.hosts.items()
                if any(_covers(entry, host) for entry in entries)]

    # ── serving ────────────────────────────────────────────────────────────

    def _track(self, sock: Any) -> Any:
        with self._lock:
            self._sockets.add(sock)
        return sock

    def _accept(self) -> None:
        listener = self._listener
        while listener is not None and not self._stopping.is_set():
            try:
                client, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._serve, args=(client,), daemon=True,
                                      name="passbook-capture-connection")
            with self._lock:
                self._threads = [held for held in self._threads if held.is_alive()]
                self._threads.append(thread)
            thread.start()

    def _serve(self, client: socket.socket) -> None:
        mine: list[Any] = [self._track(client)]
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client.settimeout(HANDSHAKE_TIMEOUT)
            start, headers = _parse_head(_connect_head(client))
            # The credential first. A process that merely found the port learns
            # nothing from it, not even which hosts would have been opened.
            offered = b"".join(_get(headers, b"proxy-authorization"))
            scheme, _, blob = offered.partition(b" ")
            if scheme.lower() != b"basic" or not hmac.compare_digest(blob.strip(), self._expected):
                self._count("refused", "no credential")
                raise _Bad(407, "Proxy Authentication Required",
                           "this proxy belongs to one passbook run --capture launch")
            parts = start.split(b" ")
            if len(parts) != 3 or parts[0] != b"CONNECT":
                self._count("refused", "not CONNECT")
                raise _Bad(405, "Method Not Allowed",
                           "this proxy carries HTTPS (CONNECT) only; nothing is swapped in cleartext")
            host, port = _authority_of(parts[1])
            keys = self.keys_for(host) if port == 443 else []
            if keys:
                self._open(client, mine, host, keys)
            else:
                self._tunnel(client, mine, host, port)
        except _Bad as bad:
            headers_out = ([("Proxy-Authenticate", 'Basic realm="passbook capture"')]
                           if bad.status == 407 else [])
            _respond(client, bad.status, bad.reason, bad.detail, headers_out)
        except (OSError, ValueError, _Closed):
            # Every TLS failure, and a socket `stop()` closed under us: the
            # connection simply ends.
            pass
        finally:
            for sock in mine:
                _hang_up(sock)
            with self._lock:
                self._sockets.difference_update(mine)

    def _tunnel(self, client: socket.socket, mine: list[Any], host: str, port: int) -> None:
        """Not on any key's list: bytes in, bytes out, nothing read.

        No certificate is made and the authority is not consulted, so there is
        no way for this path to see a request, let alone change one.
        """
        try:
            upstream = socket.create_connection(_upstream_address(host, port),
                                                timeout=CONNECT_TIMEOUT)
        except OSError:
            self._count("unreachable", host)
            raise _Bad(502, "Bad Gateway", f"could not reach {host}:{port}")
        mine.append(self._track(upstream))
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self._count("tunnelled", host)
        client.settimeout(None)
        upstream.settimeout(None)

        def pump(source: socket.socket, sink: socket.socket) -> None:
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        outward = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        outward.start()
        pump(upstream, client)
        outward.join()

    def _open(self, client: socket.socket, mine: list[Any], host: str, keys: list[str]) -> None:
        """On a key's list: terminate TLS here, swap, and send on verified."""
        assert self._authority is not None
        try:
            raw = socket.create_connection(_upstream_address(host, 443), timeout=CONNECT_TIMEOUT)
            mine.append(self._track(raw))
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self._context is None:
                self._context = _upstream_context()
            # Verified against the system's roots and the host's own name
            # BEFORE the child is told the connection is up. A value is never
            # written to a peer that has not proved it is that host.
            upstream = self._context.wrap_socket(raw, server_hostname=host)
            mine.append(self._track(upstream))
        except OSError as error:
            self._count("unreachable", host)
            why = getattr(error, "verify_message", "") or type(error).__name__
            raise _Bad(502, "Bad Gateway",
                       f"capture could not reach {host} over verified TLS ({why})")
        context = self._authority.context_for(host)
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        try:
            inner = context.wrap_socket(client, server_side=True)
        except OSError:
            # The child would not take our certificate: it pins, or it trusts
            # the system store and not the variables. It fails; nothing leaks.
            self._count("distrusted", host)
            return
        mine.append(self._track(inner))
        self._count("opened", host)
        inner.settimeout(None)
        upstream.settimeout(None)
        reader, answers = _Reader(inner), _Reader(upstream)
        state = {"answering": False}
        try:
            while self._next_request(reader, inner, upstream):
                state["answering"] = False
                if not self._exchange(reader, inner, upstream, answers, host, keys, state):
                    break
        except _Bad as bad:
            if not state["answering"]:
                _respond(inner, bad.status, bad.reason, bad.detail)

    def _next_request(self, reader: _Reader, inner: Any, upstream: Any) -> bool:
        """Wait for the child's next request, or for either side to finish."""
        if reader.buffer or inner.pending():
            return True
        while not self._stopping.is_set():
            ready = _readable([inner, upstream], IDLE_TIMEOUT)
            if not ready:
                return False
            if upstream in ready and not _still_open(upstream):
                return False
            if inner in ready:
                return True
        return False

    def _swaps(self, keys: Sequence[str]) -> list[tuple[bytes, str, str]]:
        return [(self.standins[name].encode("ascii"), name, self._values[name])
                for name in keys if name in self._values]

    def _swap(self, data: bytes, swaps: Sequence[tuple[bytes, str, str]],
              written: Callable[[str, str], bytes]) -> bytes:
        """Replace the stand-ins of the keys allowed here. Others are left."""
        for standin, name, value in swaps:
            hits = data.count(standin)
            if hits:
                data = data.replace(standin, written(name, value))
                self._count("swapped", name, hits)
        return data

    def _exchange(self, reader: _Reader, inner: Any, upstream: Any, answers: _Reader,
                  host: str, keys: Sequence[str], state: dict[str, bool]) -> bool:
        """One request out and its response back. True to keep the connection."""
        head = reader.head()
        if head is None:
            return False
        start, headers = _parse_head(head)
        parts = start.split(b" ")
        if len(parts) != 3:
            raise _Bad(400, "Bad Request", "the request line is malformed")
        method, target, version = parts
        if version not in (b"HTTP/1.1", b"HTTP/1.0"):
            raise _Bad(505, "HTTP Version Not Supported", "capture carries HTTP/1.1 only")
        if not (target.startswith(b"/") or target == b"*"):
            raise _Bad(400, "Bad Request", "capture carries origin-form requests only")
        # The Host header must name the host this connection is to. The value
        # is about to be written for THAT host, and a server that routes on
        # Host (every shared front end does) would otherwise hand the request,
        # key included, to whichever other tenant the child named.
        named = _get(headers, b"host")
        if len(named) != 1 or named[0].lower().rstrip(b".") not in (
                host.encode("ascii"), host.encode("ascii") + b":443"):
            raise _Bad(421, "Misdirected Request",
                       f"this connection is to {host}, and the Host header must say so")
        if _get(headers, b"upgrade") or b"upgrade" in _tokens(headers, b"connection"):
            raise _Bad(501, "Not Implemented",
                       "capture does not carry protocol upgrades such as WebSocket")
        coding, lengths = _tokens(headers, b"transfer-encoding"), _get(headers, b"content-length")
        if coding and lengths:
            raise _Bad(400, "Bad Request", "both Transfer-Encoding and Content-Length")
        if coding and coding != [b"chunked"]:
            raise _Bad(501, "Not Implemented", "a request body coding other than chunked")
        if lengths and (len(set(lengths)) != 1 or not lengths[0].isdigit()):
            raise _Bad(400, "Bad Request", "Content-Length is malformed")
        expecting = _tokens(headers, b"expect")
        if expecting and expecting != [b"100-continue"]:
            raise _Bad(417, "Expectation Failed")

        swaps = self._swaps(keys)
        target = self._swap(target, swaps, _for_target)
        sending: list[tuple[bytes, bytes]] = []
        for name, value in headers:
            lower = name.lower()
            if lower in _DROPPED_REQUEST:
                continue
            if lower == b"authorization":
                value = self._swap_basic(value, swaps)
            sending.append((name, self._swap(value, swaps, _for_header)))
        # Asked for uncompressed, so that what comes back can be read and the
        # key removed from it. See the Content-Encoding handling below for a
        # server that compresses anyway.
        sending.append((b"Accept-Encoding", b"identity"))

        if expecting:
            inner.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        content_type = b",".join(_get(headers, b"content-type")).lower()
        written = (_for_form if content_type.startswith(b"application/x-www-form-urlencoded")
                   else _for_json if b"json" in content_type else _raw)
        body, following = b"", None  # `following`: body still to pass on, unsearched
        if coding:
            pieces = reader.chunks()
            held = bytearray()
            for piece in pieces:
                held += piece
                if len(held) > MAX_SWAP_BODY:
                    break
            else:
                pieces = None
            if pieces is None:
                # Whole, searched, and sent with a length: the swap changed how
                # long it is, and a length is the framing nobody can misread.
                body = self._swap(bytes(held), swaps, written)
                sending.append((b"Content-Length", b"%d" % len(body)))
            else:
                self._count("unsearched", host)
                sending.append((b"Transfer-Encoding", b"chunked"))
                body, following = _chunk(bytes(held)), pieces
        elif lengths:
            length = int(lengths[0])
            if length <= MAX_SWAP_BODY:
                body = self._swap(reader.exact(length), swaps, written)
                sending.append((b"Content-Length", b"%d" % len(body)))
            else:
                self._count("unsearched", host)
                sending.append((b"Content-Length", lengths[0]))
                following = reader.stream(length)

        upstream.sendall(b"\r\n".join(
            [b" ".join((method, target, b"HTTP/1.1")),
             *(name + b": " + value for name, value in sending), b"", b""]) + body)
        if following is not None:
            for piece in following:
                upstream.sendall(_chunk(piece) if coding else piece)
            if coding:
                upstream.sendall(b"0\r\n\r\n")

        # ── the response ───────────────────────────────────────────────────
        while True:
            answer = answers.head()
            if answer is None:
                raise _Bad(502, "Bad Gateway", f"{host} closed the connection without answering")
            answer_start, answer_headers = _parse_head(answer)
            answer_parts = answer_start.split(b" ", 2)
            if len(answer_parts) < 2 or not answer_parts[1].isdigit():
                raise _Bad(502, "Bad Gateway", f"{host} sent a malformed response")
            status = int(answer_parts[1])
            if status == 101:
                raise _Bad(502, "Bad Gateway", "an upgrade capture did not ask for")
            if status >= 200:
                break
            inner.sendall(self._clean(answer[:-4]) + b"\r\n\r\n")  # 100, 103: passed on

        bodiless = method == b"HEAD" or status in (204, 304)
        chunked = b"chunked" in _tokens(answer_headers, b"transfer-encoding")
        sized = _get(answer_headers, b"content-length")
        if not chunked and sized and not sized[0].isdigit():
            raise _Bad(502, "Bad Gateway", f"{host} sent a malformed Content-Length")
        to_close = not bodiless and not chunked and not sized
        inflate = None
        codings = [token for token in _tokens(answer_headers, b"content-encoding")
                   if token != b"identity"]
        if codings and not bodiless:
            if codings in ([b"gzip"], [b"x-gzip"], [b"deflate"]):
                inflate = zlib.decompressobj(47)  # gzip or zlib, whichever arrives
            else:
                # It was asked for plain text and compressed anyway, in a form
                # that cannot be read here. Unread means unchecked, and an
                # unchecked response is where an echoed key gets through.
                raise _Bad(502, "Bad Gateway",
                           f"{host} answered in an encoding capture cannot read "
                           f"({b','.join(codings).decode('latin-1')}), so the response could "
                           f"not be checked for the key and was not passed on")
        keep = (version == b"HTTP/1.1" and not to_close
                and b"close" not in _tokens(headers, b"connection")
                and b"close" not in _tokens(answer_headers, b"connection")
                and answer_parts[0] != b"HTTP/1.0")

        lines = [b" ".join([b"HTTP/1.1", *answer_parts[1:]])]
        for name, value in answer_headers:
            lower = name.lower()
            if lower in _DROPPED_RESPONSE:
                continue
            if not bodiless and lower == b"content-length":
                continue  # redaction changes the length; it is re-framed below
            if inflate is not None and lower == b"content-encoding":
                continue
            lines.append(name + b": " + value)
        framed = not bodiless and version == b"HTTP/1.1"
        if framed:
            lines.append(b"Transfer-Encoding: chunked")
        if not keep:
            lines.append(b"Connection: close")
        state["answering"] = True
        inner.sendall(self._clean(b"\r\n".join(lines)) + b"\r\n\r\n")

        if not bodiless:
            scrubber = _ResponseScrubber(self._values)
            decoder = codecs.getincrementaldecoder("utf-8")("surrogateescape")

            def checked(raw: bytes, final: bool = False) -> None:
                clean = scrubber.feed(decoder.decode(raw, final))
                if final:
                    clean += scrubber.flush()
                data = clean.encode("utf-8", "surrogateescape")
                if data:
                    inner.sendall(_chunk(data) if framed else data)

            def passing(raw: bytes, final: bool = False) -> None:
                if inflate is None:
                    return checked(raw, final)
                # A megabyte at a time, so a small compressed body that unpacks
                # to a very large one is never all in memory at once.
                while raw:
                    checked(inflate.decompress(raw, 1 << 20))
                    raw = inflate.unconsumed_tail
                if final:
                    checked(inflate.flush(), final=True)

            try:
                source = (answers.chunks() if chunked
                          else answers.stream(int(sized[0])) if sized else answers.rest())
                for piece in source:
                    passing(piece)
                passing(b"", final=True)
            except (zlib.error, _Bad) as error:
                # Half a response has gone. Ending the connection without the
                # final chunk is how HTTP says the rest never arrived.
                raise _Closed() from error
            if framed:
                inner.sendall(b"0\r\n\r\n")
        return keep

    def _swap_basic(self, value: bytes, swaps: Sequence[tuple[bytes, str, str]]) -> bytes:
        """`Authorization: Basic` hides a stand-in inside base64. Look there.

        Stripe, Twilio and git-over-HTTPS all send the key this way, and a
        search of the header as written would never find it.
        """
        scheme, _, blob = value.partition(b" ")
        if scheme.lower() != b"basic":
            return value
        try:
            pair = base64.b64decode(blob.strip(), validate=True)
        except (binascii.Error, ValueError):
            return value
        swapped = self._swap(pair, swaps, _raw)
        return value if swapped == pair else scheme + b" " + base64.b64encode(swapped)

    def _clean(self, data: bytes) -> bytes:
        text = data.decode("utf-8", "surrogateescape")
        return passbook_grant.redact(text, self._values).encode("utf-8", "surrogateescape")


# ── how a value is written where its stand-in was ──────────────────────────


def _raw(_name: str, value: str) -> bytes:
    return value.encode("utf-8")


def _for_target(_name: str, value: str) -> bytes:
    return urllib.parse.quote(value, safe=_TARGET_SAFE).encode("ascii")


def _for_form(_name: str, value: str) -> bytes:
    return urllib.parse.quote(value, safe="").encode("ascii")


def _for_json(_name: str, value: str) -> bytes:
    return json.dumps(value)[1:-1].encode("ascii")


def _for_header(name: str, value: str) -> bytes:
    if any(mark in value for mark in "\r\n\0"):
        # A line break in a header is a second header. Refused by name; the
        # value is not in the message.
        raise _Bad(400, "Bad Request",
                   f"the value of {name} contains a line break and cannot be sent in a header")
    return value.encode("utf-8")


# ── small socket helpers ───────────────────────────────────────────────────


def _connect_head(client: socket.socket) -> bytes:
    """Read the CONNECT request and not one byte more.

    What follows it is the child's TLS handshake, which has to be read by TLS.
    Peeking finds the blank line before anything is taken off the socket.
    """
    head = b""
    while True:
        seen = client.recv(4096, socket.MSG_PEEK)
        if not seen:
            raise _Closed()
        joined = head[-3:] + seen
        at = joined.find(b"\r\n\r\n")
        take = len(seen) if at == -1 else at + 4 - len(head[-3:])
        head += client.recv(take)
        if at != -1:
            return head
        if len(head) > MAX_HEAD:
            raise _Bad(431, "Request Header Fields Too Large")


def _authority_of(target: bytes) -> tuple[str, int]:
    try:
        text = target.decode("ascii")
        host, _, port_text = text.rpartition(":")
        port = int(port_text)
    except (UnicodeDecodeError, ValueError):
        raise _Bad(400, "Bad Request", "CONNECT takes host:port")
    host = host.strip("[]").lower().rstrip(".")
    if not host or not 0 < port < 65536:
        raise _Bad(400, "Bad Request", "CONNECT takes host:port")
    return host, port


def _hang_up(sock: Any) -> None:
    # shutdown first: a thread blocked in recv() on this socket is woken by a
    # shutdown and not, on Linux, by a close.
    for end in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
        try:
            end()
        except (OSError, ValueError):
            pass
