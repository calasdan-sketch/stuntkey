"""Questions asked right after a key was handled: answered without echo, and
never treating a pasted key as an answer.

A person who has just copied a key, and is then asked "Is that the key?",
may paste it AT that question. An ordinary prompt shows what is typed or
pasted, so the key ended up on screen (and in a screenshot). Here the answer
is read the way a password is: nothing is shown. Only Enter, y and n mean
anything; text that is long or looks like a key is refused with a plain
sentence that does not repeat it, and is dropped, not kept or logged.
"""

from __future__ import annotations

import getpass
import re
import sys
import warnings

MAX_TRIES = 3
LONGEST_ANSWER = 8          # "yes" is the longest real answer; more is not one
_PASTE_MARKS = re.compile(r"\x1b\[20[01]~")
_ESCAPES = re.compile(r"\x1b\[[0-9;?]*[A-Za-z~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _drain_input() -> None:
    """Throw away what is still waiting in the terminal's input: the rest of
    a multi-line paste must not become the answer to the NEXT question."""
    try:
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        return
    except Exception:
        pass
    try:
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getwch()
    except Exception:
        pass


def read_quiet(prompt: str) -> str:
    """One line, without echo when there is a terminal; from a pipe or file
    otherwise (nothing is shown for those). EOFError at the end of input."""
    stdin = sys.stdin
    try:
        is_tty = bool(stdin and stdin.isatty())
    except (OSError, ValueError):
        is_tty = False
    if is_tty:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")     # "may be echoed": never the text
            try:
                return getpass.getpass(prompt)
            finally:
                _drain_input()
    sys.stderr.write(prompt)
    sys.stderr.flush()
    line = stdin.readline() if stdin else ""
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


PASTE_MIN = 16        # a burst this long is a paste, not typing
SETTLE = 0.35         # seconds of quiet that end a paste


def read_hidden(prompt: str) -> str:
    """The hidden paste prompt. On a terminal each character shows as *, so
    the person can see something arrived, and a paste is taken as soon as it
    ends - no Enter needed (typing by hand still ends with Enter). Elsewhere
    (a pipe, a test) it reads like getpass. The rest of a multi-line paste is
    thrown away afterwards."""
    try:
        is_tty = bool(sys.stdin and sys.stdin.isatty())
    except (OSError, ValueError):
        is_tty = False
    try:
        if is_tty:
            try:
                return _read_masked(prompt)
            except ImportError:
                pass
        return getpass.getpass(prompt)
    finally:
        _drain_input()


def _read_masked(prompt: str, out=None) -> str:
    """Stars for each character; returns on Enter, or when a paste of at
    least PASTE_MIN characters stops arriving for SETTLE seconds."""
    import time
    out = out or sys.stderr
    out.write(prompt)
    out.flush()
    if sys.platform == "win32":
        import msvcrt

        def read_char():
            return msvcrt.getwch()

        def waiting(timeout):
            end = time.monotonic() + timeout
            while not msvcrt.kbhit():
                if time.monotonic() >= end:
                    return False
                time.sleep(0.01)
            return True
        return _masked_loop(read_char, waiting, out)
    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        return _masked_loop(lambda: sys.stdin.read(1),
                            lambda t: bool(select.select([fd], [], [], t)[0]), out)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _masked_loop(read_char, waiting, out) -> str:
    buf: list[str] = []
    burst = 0
    try:
        while True:
            ch = read_char()
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in ("\x04", "\x1a") and not buf:
                raise EOFError
            if ch in ("\x00", "\xe0"):          # Windows arrow/function key prefix
                read_char()
                continue
            if ch in ("\x08", "\x7f"):
                if buf:
                    buf.pop()
                    out.write("\b \b")
                    out.flush()
                burst = 0
                continue
            if ch < " ":
                continue
            buf.append(ch)
            out.write("*")
            burst += 1
            if not waiting(0.03):
                # the input went quiet: a long burst was a paste, so take it
                if burst >= PASTE_MIN and not waiting(SETTLE):
                    break
                burst = 0
            out.flush()
    finally:
        out.write("\n")
        out.flush()
    return "".join(buf)


def strip_paste_marks(text: str) -> str:
    """Terminal 'bracketed paste' markers (ESC[200~ ... ESC[201~) that a
    terminal may wrap around pasted text."""
    return _PASTE_MARKS.sub("", text)


def classify(raw: str, secret_pattern: str | None = None) -> str:
    """'enter', 'yes', 'no', 'key' (long or key-shaped) or 'other'."""
    text = _CONTROL.sub("", _ESCAPES.sub("", raw or "")).strip()
    low = text.lower()
    if not low:
        return "enter"
    if low in ("y", "yes"):
        return "yes"
    if low in ("n", "no"):
        return "no"
    if len(text) > LONGEST_ANSWER or "\n" in (raw or "").strip():
        return "key"
    if secret_pattern:
        try:
            if re.search(secret_pattern, text):
                return "key"
        except re.error:
            pass
    return "other"


def ask(prompt: str, out, *, enter_means: bool, reader=None,
        secret_pattern: str | None = None, if_key: str | None = None,
        tries: int = MAX_TRIES) -> bool | None:
    """True / False for the answer, None when cancelled (Ctrl-C, end of
    input, or `tries` answers that were not an answer). `enter_means` is what
    a bare Enter answers. Nothing typed is ever written to `out`."""
    reader = reader or read_quiet
    for _ in range(tries):
        try:
            raw = reader(prompt)
        except (EOFError, KeyboardInterrupt):
            return None
        kind = classify(raw, secret_pattern)
        raw = None                              # not kept
        if kind == "enter":
            return enter_means
        if kind == "yes":
            return True
        if kind == "no":
            return False
        if kind == "key":
            out.write("  " + (if_key or "That looked like a key. Do not paste it "
                                        "here. Nothing was saved or sent.") + "\n")
        else:
            out.write("  Please press Enter, or type y or n.\n")
    return None
