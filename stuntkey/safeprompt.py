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
import os
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


def typing_can_be_hidden(stdin=None) -> bool:
    """False when there is a terminal but the system will not let a program
    turn its echo off. `getpass` then prints a warning and carries on, which
    shows the pasted key on screen (and in a screenshot or a recording): for
    a key that is the one thing not to do. When stdin is a pipe or file
    nothing is shown, so that is fine. Where this cannot be told (Windows),
    it says yes, as before; that was read, not run."""
    stdin = sys.stdin if stdin is None else stdin
    try:
        if not (stdin and stdin.isatty()):
            return True
        import termios
    except (OSError, ValueError, ImportError):
        return True
    try:
        termios.tcgetattr(stdin.fileno())
    except termios.error:
        return False
    except (OSError, ValueError):
        return True
    return True


def read_hidden(prompt: str) -> str:
    """The hidden paste prompt: like getpass, and the rest of a multi-line
    paste is thrown away afterwards. Refuses (as EOFError, which the callers
    treat as "cancelled") when the terminal cannot hide what is typed."""
    if not typing_can_be_hidden():
        sys.stderr.write(
            "\n  This terminal does not let stuntkey hide what you paste, so it would "
            "be\n  shown on screen. Nothing was read. Use a normal terminal window "
            "(or `get --clipboard`,\n  where a clipboard tool is installed).\n")
        sys.stderr.flush()
        raise EOFError
    if _piped_with_no_terminal():
        # nothing to hide and nowhere to type: read the line from the pipe. (getpass
        # would print "Password input may be echoed", which reads like a danger
        # and is not one here.)
        return read_quiet(prompt)
    try:
        return getpass.getpass(prompt)
    finally:
        _drain_input()


def _piped_with_no_terminal() -> bool:
    """stdin is a pipe or file and this program has no controlling terminal
    to ask on either. On Windows, and whenever a terminal exists, getpass
    keeps its own behaviour (it asks on the terminal)."""
    if os.name != "posix":
        return False
    try:
        if sys.stdin and sys.stdin.isatty():
            return False
        os.close(os.open("/dev/tty", os.O_RDWR))
        return False
    except (OSError, ValueError):
        return True


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
