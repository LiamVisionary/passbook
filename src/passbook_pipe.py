# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""A Windows named pipe that behaves enough like a socket for the broker.

The broker's whole design rests on a door only this user can open: a Unix
socket, created unreachable and narrowed to mode 0600, whose other end the
kernel will name for us. Windows has no `AF_UNIX` in CPython, so on Windows
there was no door at all — `passbook signin` raised `AttributeError` reaching
for `socket.AF_UNIX`, and with no broker there is no way to hold a data key,
which means a sealed store could not be opened on Windows by any route.

A named pipe is the same shape of thing:

  * it is created with an explicit DACL naming this user and nobody else,
    which is what 0600 buys on the other platforms;
  * `GetNamedPipeClientProcessId` names the process on the other end, the way
    `LOCAL_PEERPID` does, so caller identification keeps working rather than
    quietly degrading to "unknown" on one platform;
  * it carries bytes, so the line-delimited JSON the broker already speaks
    needs no second encoding.

What this deliberately does not do is overlapped I/O. Reads poll with
`PeekNamedPipe` and a deadline instead, which costs a millisecond of latency
per request and saves a category of bug that is very hard to be sure about.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import threading
import time
from pathlib import Path

# `ctypes.wintypes` refuses to import anywhere else, so this module cannot
# pretend to be cross-platform even for the sake of a tidier import. Callers
# ask `os.name` first; the broker does exactly that and reaches for the Unix
# socket otherwise.
if os.name != "nt":  # pragma: no cover - the guard is the platform check
    raise ImportError("passbook_pipe is the Windows transport; elsewhere there is AF_UNIX")

from ctypes import wintypes  # noqa: E402 - deliberately after the platform guard

__all__ = ["pipe_name", "PipeServer", "PipeConnection", "connect", "is_listening"]

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ERROR_FILE_NOT_FOUND = 2
ERROR_BROKEN_PIPE = 109
ERROR_PIPE_BUSY = 231
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_PIPE_CONNECTED = 535

SDDL_REVISION_1 = 1
TOKEN_QUERY = 0x0008
# The TOKEN_INFORMATION_CLASS value, kept out of the way of the structure of
# the same name below -- defining the class second silently replaced this, and
# GetTokenInformation was then handed a ctypes class where it wanted a 1.
TOKEN_USER_CLASS = 1

# The buffers the kernel keeps per instance. A request is a short JSON line;
# this is generous and still trivial.
_BUFFER_BYTES = 64 * 1024

# How often a blocked read looks again. Small enough to be invisible next to a
# credential lookup, large enough not to spin a core.
_POLL_SECONDS = 0.002


def _declare() -> None:
    """Give every call a prototype before using it.

    ctypes assumes a C `int` return unless told otherwise. A HANDLE is 64 bits
    on a 64-bit build, so without this every handle comes back sign-extended
    from its low half — usually still truthy, so the failure is not a crash at
    the call but nonsense much later, in whichever call is handed the ruined
    value first.
    """
    k, a = _kernel32, _advapi32
    k.CreateNamedPipeW.restype = wintypes.HANDLE
    k.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.ConnectNamedPipe.restype = wintypes.BOOL
    k.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    k.DisconnectNamedPipe.restype = wintypes.BOOL
    k.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k.FlushFileBuffers.restype = wintypes.BOOL
    k.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.PeekNamedPipe.restype = wintypes.BOOL
    k.PeekNamedPipe.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD)]
    k.ReadFile.restype = wintypes.BOOL
    k.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    k.WriteFile.restype = wintypes.BOOL
    k.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    k.WaitNamedPipeW.restype = wintypes.BOOL
    k.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    k.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.GetCurrentProcess.argtypes = []
    k.LocalFree.restype = wintypes.HANDLE
    k.LocalFree.argtypes = [wintypes.HANDLE]

    a.OpenProcessToken.restype = wintypes.BOOL
    a.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.restype = wintypes.BOOL
    a.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    a.ConvertSidToStringSidW.restype = wintypes.BOOL
    a.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG)]


_declare()


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


def _last_error() -> int:
    return ctypes.get_last_error()


def _fail(what: str) -> OSError:
    code = _last_error()
    return OSError(f"{what} failed (Windows error {code})")


def current_user_sid() -> str:
    """This process's user, as an SDDL string.

    Named explicitly rather than relying on a default DACL: the default for a
    named pipe grants read access to Everyone, which for the process holding a
    decrypted data key is not a detail to leave to a default.
    """
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        raise _fail("OpenProcessToken")
    try:
        size = wintypes.DWORD()
        _advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not _advapi32.GetTokenInformation(
            token, TOKEN_USER_CLASS, buffer, size, ctypes.byref(size)
        ):
            raise _fail("GetTokenInformation")
        user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(text)):
            raise _fail("ConvertSidToStringSid")
        try:
            return str(text.value)
        finally:
            _kernel32.LocalFree(text)
    finally:
        _kernel32.CloseHandle(token)


def _security_attributes() -> tuple[SECURITY_ATTRIBUTES, ctypes.c_void_p]:
    """A DACL that admits this user and refuses everyone else.

    `D:P` makes it protected, so nothing is inherited in from elsewhere, and
    the single ACE grants all access to us. Returned with the descriptor so the
    caller can free it once the pipe holds its own copy.
    """
    sddl = f"D:P(A;;GA;;;{current_user_sid()})"
    descriptor = ctypes.c_void_p()
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        raise _fail("ConvertStringSecurityDescriptorToSecurityDescriptor")
    attributes = SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    attributes.lpSecurityDescriptor = descriptor
    attributes.bInheritHandle = False
    return attributes, descriptor


def pipe_name(root: Path | str) -> str:
    """The pipe for one store, on one account.

    Sockets are files, so the POSIX side gets separation for free by living
    inside the store. Pipe names are one flat machine-wide namespace, so the
    store's path and the user's SID are folded into the name instead — two
    accounts on one machine, or one account with two stores, must not land on
    the same pipe.
    """
    try:
        sid = current_user_sid()
    except OSError:  # pragma: no cover - the name still has to be derivable
        sid = ""
    # `casefold` because Windows paths are case-insensitive: the same store
    # reached by a differently-cased path is the same store.
    seed = f"{Path(root).resolve()}".casefold() + "\0" + sid
    return "\\\\.\\pipe\\passbook-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


class PipeConnection:
    """One accepted or dialled pipe, with the bits of the socket API used here."""

    def __init__(self, handle: int, *, server_side: bool) -> None:
        self._handle = handle
        self._server_side = server_side
        self._timeout: float | None = None
        self._closed = False

    # ── the socket-shaped surface ──────────────────────────────────────────

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout

    def recv(self, size: int) -> bytes:
        deadline = None if self._timeout is None else time.monotonic() + self._timeout
        while True:
            waiting = self._peek()
            if waiting is None:
                return b""  # the other end went away, which is EOF
            if waiting:
                return self._read(min(size, waiting))
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for the broker")
            time.sleep(_POLL_SECONDS)

    def sendall(self, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = wintypes.DWORD()
            if not _kernel32.WriteFile(
                wintypes.HANDLE(self._handle), ctypes.c_char_p(bytes(view)),
                len(view), ctypes.byref(written), None
            ):
                code = _last_error()
                if code in (ERROR_BROKEN_PIPE, ERROR_NO_DATA):
                    raise BrokenPipeError("the other end closed the pipe")
                raise _fail("WriteFile")
            if not written.value:
                raise BrokenPipeError("the pipe accepted nothing")
            view = view[written.value:]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        handle = wintypes.HANDLE(self._handle)
        if self._server_side:
            # Let the client read what we just wrote before the pipe goes.
            _kernel32.FlushFileBuffers(handle)
            _kernel32.DisconnectNamedPipe(handle)
        _kernel32.CloseHandle(handle)

    # ── identification ─────────────────────────────────────────────────────

    def peer_pid(self) -> int | None:
        """The process on the other end, from the kernel rather than a claim."""
        if not self._server_side:
            return None
        pid = wintypes.DWORD()
        if not _kernel32.GetNamedPipeClientProcessId(
            wintypes.HANDLE(self._handle), ctypes.byref(pid)
        ):
            return None
        return int(pid.value)

    # ── internals ──────────────────────────────────────────────────────────

    def _peek(self) -> int | None:
        waiting = wintypes.DWORD()
        if not _kernel32.PeekNamedPipe(
            wintypes.HANDLE(self._handle), None, 0, None, ctypes.byref(waiting), None
        ):
            # Broken, not-connected, or something rarer: in every case there is
            # nothing more to read, and the caller's next move is the same.
            return None
        return int(waiting.value)

    def _read(self, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        read = wintypes.DWORD()
        if not _kernel32.ReadFile(
            wintypes.HANDLE(self._handle), buffer, size, ctypes.byref(read), None
        ):
            if _last_error() == ERROR_BROKEN_PIPE:
                return b""
            raise _fail("ReadFile")
        return buffer.raw[: read.value]

    def __enter__(self) -> "PipeConnection":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class PipeServer:
    """Listens on one name, one connection at a time, like `accept()`."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._lock = threading.Lock()
        self._closed = False
        self._pending = self._instance()

    @property
    def name(self) -> str:
        return self._name

    def _instance(self) -> int:
        attributes, descriptor = _security_attributes()
        try:
            handle = _kernel32.CreateNamedPipeW(
                self._name,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                _BUFFER_BYTES, _BUFFER_BYTES,
                0,
                ctypes.byref(attributes),
            )
        finally:
            _kernel32.LocalFree(descriptor)
        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise _fail("CreateNamedPipe")
        return handle

    def accept(self) -> PipeConnection:
        """Block until somebody connects, then hand back their end.

        A fresh instance is created before this one is handed over, so the name
        is never momentarily unlistened — a client arriving in that gap would
        get "file not found" and conclude there is no broker.
        """
        if self._closed:
            raise OSError("the pipe server is closed")
        handle = self._pending
        connected = _kernel32.ConnectNamedPipe(wintypes.HANDLE(handle), None)
        if not connected and _last_error() not in (ERROR_PIPE_CONNECTED, 0):
            raise _fail("ConnectNamedPipe")
        with self._lock:
            if self._closed:
                _kernel32.CloseHandle(wintypes.HANDLE(handle))
                raise OSError("the pipe server is closed")
            self._pending = self._instance()
        return PipeConnection(handle, server_side=True)

    def close(self) -> None:
        """Stop listening, and unblock whoever is sitting in `accept`.

        `ConnectNamedPipe` cannot be cancelled from another thread, so the only
        portable way out is to be that client for a moment.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            pending = self._pending
        try:
            waker = _kernel32.CreateFileW(
                self._name, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
            if waker not in (INVALID_HANDLE_VALUE, None):
                _kernel32.CloseHandle(wintypes.HANDLE(waker))
        except OSError:  # pragma: no cover - best effort
            pass
        _kernel32.CloseHandle(wintypes.HANDLE(pending))


def is_listening(name: str) -> bool:
    """Whether anything holds this name right now."""
    # 0 means "do not wait": the question is whether it exists, not whether an
    # instance is free this instant.
    if _kernel32.WaitNamedPipeW(name, 0):
        return True
    return _last_error() not in (ERROR_FILE_NOT_FOUND,)


def connect(name: str, timeout: float | None) -> PipeConnection:
    """Dial the broker, waiting out a busy moment but not a missing one.

    `None` means no deadline, matching what `settimeout(None)` means on a
    socket: block for as long as it takes. A streaming spawn asks for that,
    because the caller's command decides how long it runs and a timeout here
    would kill a legitimate build at an arbitrary minute.

    Without this, `max(None, 0.0)` raised a TypeError before the connection was
    ever attempted — POSIX took `None` happily and Windows died on every
    streamed run.
    """
    deadline = None if timeout is None else time.monotonic() + max(timeout, 0.0)
    while True:
        handle = _kernel32.CreateFileW(
            name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if handle not in (INVALID_HANDLE_VALUE, None):
            connection = PipeConnection(handle, server_side=False)
            connection.settimeout(timeout)
            return connection
        code = _last_error()
        if code == ERROR_FILE_NOT_FOUND:
            raise FileNotFoundError("no broker is listening")
        if code != ERROR_PIPE_BUSY:
            raise _fail("CreateFile")
        # Every instance is in use. That is a queue, not an absence.
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("every broker instance was busy")
        _kernel32.WaitNamedPipeW(name, 50)
