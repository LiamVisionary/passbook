# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Real HTTPS hosts on loopback, for `passbook run --capture`.

Capture is a claim about bytes on a wire, so the far end of the wire is real:
a TLS server with a certificate for a host name, recording exactly what reached
it. Stubbing the proxy's sockets would prove that the code calls `sendall`.

The certificates come from a root made here and thrown away with the test
directory. The proxy is told to trust that root for upstream by replacing two
functions in `passbook_capture` from inside the test process. Nothing a user
can set does the same, and that is deliberate: see the module's own note.

Used by `tests/test_passbook_capture.py` and by `scripts/measure-capture.py`,
which is why it is a module and not a set of fixtures.
"""

from __future__ import annotations

import datetime
import gzip
import http.server
import json
import ssl
import threading
import zlib
from pathlib import Path

ALLOWED = "api.allowed.test"
OTHER = "other.example.test"


class Pki:
    """A throwaway root, and server certificates under it."""

    def __init__(self, directory: Path) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self._x509, self._hashes, self._serialization, self._ec = x509, hashes, serialization, ec
        self._oid = NameOID
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        self._window = (now - datetime.timedelta(hours=1), now + datetime.timedelta(days=2))
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "throwaway test root")])
        root = (
            x509.CertificateBuilder().subject_name(self._name).issuer_name(self._name)
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(self._window[0]).not_valid_after(self._window[1])
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            # Python 3.13 verifies strictly by default: a root without key usage
            # and a leaf without an authority key identifier are both refused.
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()),
                           critical=False)
            .sign(self._key, hashes.SHA256()))
        self.root = self.directory / "test-root.pem"
        self.root.write_bytes(root.public_bytes(serialization.Encoding.PEM))

    def server_context(self, host: str) -> ssl.SSLContext:
        x509, serialization = self._x509, self._serialization
        key = self._ec.generate_private_key(self._ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(self._oid.COMMON_NAME, host)]))
            .issuer_name(self._name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._window[0]).not_valid_after(self._window[1])
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._key.public_key()), critical=False)
            .sign(self._key, self._hashes.SHA256()))
        chain, secret = self.directory / f"{host}.pem", self.directory / f"{host}.key"
        chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        secret.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(chain), str(secret))
        return context

    def client_context(self) -> ssl.SSLContext:
        """Trusts the throwaway root and nothing else."""
        context = ssl.create_default_context(cafile=str(self.root))
        context.set_alpn_protocols(["http/1.1"])
        return context


class Provider:
    """One API host. Records every request that reaches it, as it arrived."""

    def __init__(self, context: ssl.SSLContext) -> None:
        self.requests: list[dict] = []
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def _serve(self):
                headers = {name.lower(): value for name, value in self.headers.items()}
                if "chunked" in headers.get("transfer-encoding", "").lower():
                    body, framing = b"", "chunked"
                    while True:
                        size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                        if size == 0:
                            while self.rfile.readline().strip():
                                pass
                            break
                        body += self.rfile.read(size)
                        self.rfile.readline()
                else:
                    body = self.rfile.read(int(headers.get("content-length") or 0))
                    framing = "length" if "content-length" in headers else "none"
                provider.requests.append({
                    "method": self.command, "path": self.path, "headers": headers,
                    "body": body, "framing": framing})
                provider._answer(self, headers, body)

            do_GET = do_POST = do_PUT = do_HEAD = _serve

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.address = ("127.0.0.1", self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def seen(self) -> str:
        """Everything that arrived, as one string to search."""
        return "\n".join(
            f"{row['method']} {row['path']}\n"
            + "\n".join(f"{name}: {value}" for name, value in row["headers"].items())
            + "\n" + row["body"].decode("latin-1")
            for row in self.requests)

    def _answer(self, handler, headers, body) -> None:
        path = handler.path
        # What an API does when it tells you about the key you sent it.
        echo = json.dumps({"authorization": headers.get("authorization", ""), "path": path,
                           "body": body.decode("latin-1")}).encode("utf-8")
        send = {"Content-Type": "application/json"}
        status, payload, pieces = 200, echo, None
        if path.startswith("/redirect"):
            status, payload = 302, b""
            send["Location"] = f"https://{OTHER}/landed"
        elif path.startswith("/echo-gzip"):
            payload = gzip.compress(echo)
            send["Content-Encoding"] = "gzip"
        elif path.startswith("/echo-deflate"):
            payload = zlib.compress(echo)
            send["Content-Encoding"] = "deflate"
        elif path.startswith("/echo-unreadable"):
            send["Content-Encoding"] = "br"  # not really brotli; the proxy cannot tell
        elif path.startswith("/echo-header"):
            payload = b"{}"
            send["X-Seen"] = headers.get("authorization", "")
        elif path.startswith("/echo-split"):
            # Seven bytes at a time, so the key is cut across many chunks.
            pieces = [echo[at:at + 7] for at in range(0, len(echo), 7)]
        elif not path.startswith("/echo"):
            payload = b'{"ok": true}'
        handler.send_response(status)
        for name, value in send.items():
            handler.send_header(name, value)
        if pieces is None:
            handler.send_header("Content-Length", str(len(payload)))
            handler.end_headers()
            if handler.command != "HEAD":
                handler.wfile.write(payload)
            return
        handler.send_header("Transfer-Encoding", "chunked")
        handler.end_headers()
        for piece in pieces:
            handler.wfile.write(b"%x\r\n" % len(piece) + piece + b"\r\n")
            handler.wfile.flush()
        handler.wfile.write(b"0\r\n\r\n")


def install_seam(capture_module, pki: Pki, routes: dict, patch) -> None:
    """Point the proxy's upstream at the local hosts, for this test process.

    `patch(object, name, value)` is `monkeypatch.setattr`, or anything shaped
    like it.
    """
    def address(host: str, port: int):
        try:
            return routes[(host, port)]
        except KeyError:
            raise OSError(f"no such host in this test: {host}:{port}")

    patch(capture_module, "_upstream_address", address)
    patch(capture_module, "_upstream_context", pki.client_context)


# A program that has never heard of PassBook. It reads its key from the
# environment and its proxy and trust from the variables every HTTP client
# reads, makes the requests it is told to, and writes down what it saw.
#
# `$KEY` in a URL, header or body is replaced by whatever the variable holds,
# which is the whole point: the program cannot tell a stand-in from a value.
CLIENT = r'''
import json, os, socket, ssl, stat, sys, urllib.error, urllib.request

plan = json.loads(sys.argv[1])
held = os.environ.get(plan.get("key", ""), "")
direct = {(host, 443): tuple(where) for host, where in (plan.get("direct") or {}).items()}
if direct:
    # No proxy on this run: reach the test hosts by the address given.
    dial = socket.create_connection
    socket.create_connection = lambda address, *a, **k: dial(direct.get(tuple(address), address), *a, **k)

def fill(text):
    return text.replace("$KEY", held)

answers = []
for step in plan.get("requests", []):
    if step.get("only_trust"):
        context = ssl.create_default_context(cafile=step["only_trust"])
    else:
        context = ssl.create_default_context()  # SSL_CERT_FILE, as any program would
        if step.get("also_trust"):
            context.load_verify_locations(step["also_trust"])
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    body = step.get("body")
    request = urllib.request.Request(
        fill(step["url"]), method=step.get("method"),
        data=None if body is None else fill(body).encode("utf-8"),
        headers={name: fill(value) for name, value in (step.get("headers") or {}).items()})
    try:
        with opener.open(request, timeout=20) as answer:
            answers.append({"status": answer.status, "url": answer.geturl(),
                            "headers": dict(answer.headers),
                            "body": answer.read().decode("utf-8", "replace")})
    except urllib.error.HTTPError as error:
        answers.append({"status": error.code, "body": error.read().decode("utf-8", "replace")})
    except Exception as error:
        answers.append({"error": type(error).__name__ + ": " + str(error)})

trust = os.environ.get("SSL_CERT_FILE", "")
folder = os.path.dirname(trust) if trust else ""
report = {
    "environ": dict(os.environ), "argv": sys.argv[1:], "answers": answers,
    "trust_mode": oct(stat.S_IMODE(os.stat(trust).st_mode)) if trust else "",
    "folder_mode": oct(stat.S_IMODE(os.stat(folder).st_mode)) if folder else "",
    "folder_files": sorted(os.listdir(folder)) if folder else [],
    "private_key_on_disk": any(
        b"PRIVATE KEY" in open(os.path.join(folder, name), "rb").read()
        for name in (os.listdir(folder) if folder else [])),
}
with open(plan["report"], "w") as out:
    json.dump(report, out)
sys.exit(int(plan.get("exit", 0)))
'''
