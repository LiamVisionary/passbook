"""Reading a secret from a terminal, with the typing visible as bullets.

`getpass.getpass` echoes NOTHING. On a password that is typed, that is merely
austere; on a value that is PASTED — which is what a credential store asks for
almost every time — it is a dead screen, and the honest reading of it is "did
that work?". People answer that by pasting again, or by giving up and pasting
into somewhere visible first, which is the one place a secret must never go.

So: one bullet per character. The characters themselves are still never echoed,
nothing is written to stdout (the bullets go to the terminal, so a redirected
stdout stays clean), and the value is still never in argv or the shell history.

Everything else about the contract is unchanged, deliberately:

  * No terminal — a pipe, CI, a test — falls straight through to
    `getpass.getpass`. That keeps every non-interactive caller byte-identical,
    including the ones that patch `getpass.getpass` to drive a prompt.
  * A terminal that will not go into cbreak mode falls through the same way. A
    prettier prompt is not worth failing to read a password.
  * Ctrl-C still interrupts and Ctrl-D still ends the input, because ISIG is
    left alone rather than the whole terminal being put into raw mode.
"""

from __future__ import annotations

import codecs
import getpass as _getpass
import os
import sys

BULLET = "•"
FALLBACK_BULLET = "*"

# Control bytes worth answering. Everything else unprintable is dropped rather
# than counted: a stray escape sequence must not silently become part of a key.
_ENTER = (b"\r", b"\n")
_BACKSPACE = (b"\x7f", b"\x08")
_INTERRUPT = b"\x03"
_EOF = b"\x04"
_KILL_LINE = b"\x15"   # Ctrl-U
_KILL_WORD = b"\x17"   # Ctrl-W
_ESCAPE = b"\x1b"


def _bullet_for(stream) -> str:
    """`•` unless this terminal cannot encode it, in which case `*`."""
    encoding = getattr(stream, "encoding", None) or sys.getdefaultencoding()
    try:
        BULLET.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return FALLBACK_BULLET
    return BULLET


def _silent(prompt: str) -> str:
    """The stdlib prompt, which echoes nothing, saying so.

    Used only where bullets cannot be drawn: not a terminal, or one that will
    not leave line mode. A prompt that shows nothing and does not say why reads
    as a hung command, or as keys going nowhere.
    """
    if prompt.endswith(": "):
        prompt = f"{prompt[:-2]} (input hidden): "
    elif prompt:
        prompt = f"{prompt.rstrip()} (input hidden) "
    return _getpass.getpass(prompt)


def hidden_input(prompt: str = "", *, stream=None) -> str:
    """Read a line without echoing it, showing one bullet per character.

    Raises KeyboardInterrupt on Ctrl-C and EOFError on Ctrl-D at an empty
    prompt — the same two exceptions `getpass.getpass` raises, because every
    call site here already handles exactly those.
    """
    if not sys.stdin.isatty():
        return _silent(prompt)
    if os.name == "nt":
        return _windows_hidden_input(prompt)
    return _posix_hidden_input(prompt, stream)


def _posix_hidden_input(prompt: str, stream) -> str:
    try:
        import termios
    except ImportError:                                   # pragma: no cover
        return _silent(prompt)

    # The prompt and the bullets belong to the TERMINAL, not to stdout: a caller
    # redirecting stdout to a file wants the value's side effects, not a row of
    # bullets in the file. getpass makes the same choice for the same reason.
    tty = stream
    opened = False
    if tty is None:
        try:
            tty = open("/dev/tty", "w", encoding=sys.stderr.encoding or "utf-8", errors="replace")
            opened = True
        except OSError:
            tty = sys.stderr

    fd = sys.stdin.fileno()
    try:
        saved = termios.tcgetattr(fd)
    except termios.error:
        if opened:
            tty.close()
        return _silent(prompt)

    bullet = _bullet_for(tty)
    # Explicit flags rather than tty.setcbreak: what setcbreak clears has moved
    # between Python versions, and the two flags that matter here are the two
    # this touches. ISIG is deliberately left ON so Ctrl-C still signals.
    mode = termios.tcgetattr(fd)
    mode[3] &= ~(termios.ECHO | termios.ICANON)           # lflag
    mode[6][termios.VMIN] = 1                             # cc
    mode[6][termios.VTIME] = 0

    decoder = codecs.getincrementaldecoder(sys.stdin.encoding or "utf-8")(errors="replace")
    typed: list[str] = []

    def echo(text: str) -> None:
        try:
            tty.write(text)
            tty.flush()
        except (OSError, ValueError):                     # pragma: no cover
            pass

    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, mode)
        echo(prompt)
        while True:
            # A whole buffer at a time, not a byte: a paste arrives as one read,
            # and reading it byte-by-byte makes a long value visibly crawl.
            chunk = os.read(fd, 4096)
            if not chunk:
                if typed:
                    break
                raise EOFError
            index = 0
            done = False
            while index < len(chunk):
                byte = chunk[index:index + 1]
                index += 1
                if byte in _ENTER:
                    done = True
                    break
                if byte == _INTERRUPT:                    # pragma: no cover
                    raise KeyboardInterrupt
                if byte == _EOF:
                    if not typed:
                        raise EOFError
                    done = True
                    break
                if byte in _BACKSPACE:
                    if typed:
                        typed.pop()
                        echo("\b \b")
                    continue
                if byte == _KILL_LINE:
                    echo("\b \b" * len(typed))
                    typed.clear()
                    continue
                if byte == _KILL_WORD:
                    removed = 0
                    while typed and typed[-1].isspace():
                        typed.pop()
                        removed += 1
                    while typed and not typed[-1].isspace():
                        typed.pop()
                        removed += 1
                    echo("\b \b" * removed)
                    continue
                if byte == _ESCAPE:
                    # An arrow key is ESC [ A. Swallow the sequence instead of
                    # letting its printable tail ("[A") become part of the key.
                    index = _skip_escape(chunk, index)
                    continue
                if byte < b" ":
                    continue                              # any other control byte
                text = decoder.decode(byte)
                if not text:
                    continue                              # mid multi-byte character
                typed.append(text)
                echo(bullet * len(text))
            if done:
                break
        echo("\n")
        return "".join(typed)
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        except termios.error:                             # pragma: no cover
            pass
        if opened:
            tty.close()


def _skip_escape(chunk: bytes, index: int) -> int:
    """Advance past one escape sequence that began just before `index`."""
    if index < len(chunk) and chunk[index:index + 1] in (b"[", b"O"):
        index += 1
        while index < len(chunk):
            byte = chunk[index]
            index += 1
            # CSI ends on a byte in @-~; that final byte is part of the sequence.
            if 0x40 <= byte <= 0x7E:
                break
    return index


def _windows_hidden_input(prompt: str) -> str:            # pragma: no cover
    try:
        import msvcrt
    except ImportError:
        return _silent(prompt)

    bullet = _bullet_for(sys.stderr)
    typed: list[str] = []
    for char in prompt:
        msvcrt.putwch(char)
    while True:
        char = msvcrt.getwch()
        if char in ("\r", "\n"):
            break
        if char == "\x03":
            raise KeyboardInterrupt
        if char == "\x04" and not typed:
            raise EOFError
        if char == "\b":
            if typed:
                typed.pop()
                for piece in "\b \b":
                    msvcrt.putwch(piece)
            continue
        if char in ("\x00", "\xe0"):
            msvcrt.getwch()                               # a function/arrow key
            continue
        if char < " ":
            continue
        typed.append(char)
        msvcrt.putwch(bullet)
    msvcrt.putwch("\r")
    msvcrt.putwch("\n")
    return "".join(typed)
