"""Copy-and-go: take a key from the clipboard the moment it is copied.

The person clicks the vendor's own "Copy" button; this notices a new,
key-shaped value on the clipboard, takes it and EMPTIES the clipboard, so
the key is not left there for the next paste or another program. Nothing
is typed or pasted, and the value is never shown.

It only looks while `stuntkey connect --clipboard` is waiting for a key,
and only takes a value that:
  - matches the field's pattern, when the recipe gives one; otherwise
  - looks like a key: one line, no spaces, 16 to 4096 visible characters,
    and different from what was on the clipboard when it started waiting
    and from the values already taken for this connect.

Backends: Windows (user32, no extra tools), macOS (pbpaste / pbcopy),
Linux (wl-paste / wl-copy, xclip or xsel). With none available, connect
falls back to the hidden paste prompt. Windows clipboard history (Win+V)
and clipboard managers can keep their own copy; this cannot clear those.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time

from . import safeexec

POLL_SECONDS = 0.3
WAIT_SECONDS = 180
# How many windows of WAIT_SECONDS copy-and-go waits before it gives up and
# asks for a hidden paste instead (3 x 3 minutes). Each lapse says so plainly.
AUTO_ROUNDS = 3
MAX_LEN = 4096
KEY_SHAPE = re.compile(r"^[!-~]{16,4096}\Z")  # printable ASCII, no spaces, 16+ long
NOT_A_KEY = (
    re.compile(r"^[\w.-]+:\d{1,5}(/\S*)?\Z"),              # localhost:3000
    re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+\Z"),           # an e-mail address
    re.compile(r"^(~|\.{0,2}/|[A-Za-z]:[\\/])\S*\Z"),        # a file path
    re.compile(r"^[a-z]+(-[a-z]+){1,}\Z"),                     # plain-hyphenated words
)


class Unavailable(Exception):
    """No way to read the clipboard on this system."""


# ---- backends ----------------------------------------------------------------

def _windows():
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    user32.EmptyClipboard.restype = wintypes.BOOL
    cf_unicode = 13

    def opened(fn):
        for _ in range(10):                     # another program may hold it a moment
            if user32.OpenClipboard(None):
                try:
                    return fn()
                finally:
                    user32.CloseClipboard()
            time.sleep(0.05)
        raise OSError("the clipboard could not be opened")

    def get() -> str:
        """The text, "" when the clipboard holds no text. Raises OSError when
        it could not be opened: unreadable is not the same as empty."""
        def read():
            handle = user32.GetClipboardData(cf_unicode)
            if not handle:
                return ""
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return ""
            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(handle)
        return opened(read) or ""

    def clear() -> bool:
        try:
            return bool(opened(user32.EmptyClipboard))
        except OSError:
            return False

    def sequence() -> int:
        """Changes whenever anything is copied (even the same text again):
        a cheap check before opening the clipboard at all."""
        return int(user32.GetClipboardSequenceNumber())

    get.sequence = sequence
    return get, clear


def _command(read: list[str], clear: list[str], run=safeexec.run):
    def get() -> str:
        """The text; raises OSError when the tool failed (unreadable is not
        the same as empty). An empty clipboard is "" with some tools'
        non-zero exit, which is treated as empty only for no-selection."""
        try:
            done = run(read, capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise OSError("the clipboard tool did not answer") from e
        if done.returncode == 0:
            return done.stdout.decode("utf-8", "replace")
        if not (done.stdout or b"").strip() and done.returncode in (1, 2):
            return ""                           # xclip / wl-paste: nothing on the clipboard
        raise OSError("the clipboard tool failed")

    def wipe() -> bool:
        # no pipes to hold: xclip and wl-copy stay alive to serve the
        # selection, and a captured pipe would make us wait for them
        try:
            done = run(clear, input=b"", stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return done.returncode == 0
    return get, wipe


def backend(find=safeexec.find):
    """(get, clear) functions for this system, or raise Unavailable. The tools
    are looked up in system folders only (safeexec.py)."""
    if sys.platform == "win32":
        try:
            return _windows()
        except (OSError, AttributeError) as e:
            raise Unavailable(f"Windows clipboard not reachable ({e})") from None
    if sys.platform == "darwin" and find("pbpaste") and find("pbcopy"):
        return _command([find("pbpaste")], [find("pbcopy")])
    if find("wl-paste") and find("wl-copy"):
        return _command([find("wl-paste"), "--no-newline"], [find("wl-copy"), "--clear"])
    if find("xclip"):
        x = find("xclip")
        return _command([x, "-selection", "clipboard", "-o"], [x, "-selection", "clipboard", "-i"])
    if find("xsel"):
        x = find("xsel")
        return _command([x, "--clipboard", "--output"], [x, "--clipboard", "--clear"])
    for name in ("wl-paste", "xclip", "xsel"):
        # Strict on purpose, for the clipboard tools too: the key passes through
        # this program's output, so a user-owned copy earlier on PATH could read
        # or replace it. The refusal is said out loud instead of failing quietly.
        why = safeexec.explain(name)
        if why:
            raise Unavailable(why)
    raise Unavailable("no clipboard tool found (install wl-clipboard, xclip or xsel in "
                      "/usr/bin)")


# ---- clipboard history -----------------------------------------------------

HISTORY_KEY = r"Software\Microsoft\Clipboard"
HISTORY_WARNING = (
    "Windows clipboard history is ON (Win+V). It keeps its own copy of what "
    "you copy - including this key - and this tool cannot remove it: only the "
    "program that copies can ask Windows to leave something out of the "
    "history, and here that program is the vendor's web page. Clearing the "
    "clipboard does not clear the history.")


def _read_registry_flags() -> dict:
    """{"history": bool, "cloud": bool} from the current user's settings."""
    import winreg
    flags = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, HISTORY_KEY) as key:
        for name, label in (("EnableClipboardHistory", "history"),
                            ("CloudClipboardAutomaticUpload", "cloud")):
            try:
                flags[label] = bool(winreg.QueryValueEx(key, name)[0])
            except OSError:
                flags[label] = False
    return flags


def history_warning(platform: str | None = None, read_flags=None) -> str | None:
    """A sentence when this system is known to keep a clipboard history that
    copy-and-go cannot keep the key out of - today only Windows' history
    (Win+V), which the registry says is on. None otherwise. On macOS and
    Linux a clipboard manager (Maccy, CopyQ, Klipper ...) may do the same and
    cannot be detected from here: see the README."""
    if (platform or sys.platform) != "win32":
        return None
    try:
        flags = (read_flags or _read_registry_flags)()
    except (OSError, ImportError):
        return None         # setting not present: history is off by default
    if flags.get("history"):
        return HISTORY_WARNING + (" Cloud sync of the clipboard is on too." if flags.get("cloud") else "")
    return None


# ---- waiting for a key ---------------------------------------------------------

def looks_like(value: str, pattern: str | None) -> bool:
    value = value.strip()
    if not value or len(value) > MAX_LEN:
        return False
    # one line, no spaces or control characters, whatever the pattern says:
    # a gate that names only the start must not accept "sk-ant-x\nrm -rf"
    if re.search(r"[\s\x00-\x1f\x7f]", value):
        return False
    if re.match(r"https?://", value, re.IGNORECASE):
        return False                        # a copied link is never the key
    if pattern:
        # from the START of the value, not the whole of it: a gate such as
        # "^sk-ant-" names only the documented beginning, and a valid key
        # that is longer than any example must still pass
        return re.match(pattern, value) is not None
    if KEY_SHAPE.match(value) is None:
        return False
    if any(rx.match(value) for rx in NOT_A_KEY):
        return False
    # a real key mixes character kinds; one plain word or number is not one
    kinds = sum(bool(re.search(c, value)) for c in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return kinds >= 2 or len(value) >= 24


def describe(value: str) -> str:
    """What a taken value looks like, without any of its characters."""
    kinds = [name for name, c in (("lower-case letters", r"[a-z]"), ("capitals", r"[A-Z]"),
                                  ("digits", r"[0-9]"), ("symbols", r"[^A-Za-z0-9]"))
             if re.search(c, value)]
    return f"{len(value)} characters ({', '.join(kinds)})"


def wait_for_key(pattern: str | None, taken: set[str], get, clear,
                 wait: float = WAIT_SECONDS, poll: float = POLL_SECONDS,
                 now=time.monotonic, sleep=time.sleep) -> str | None:
    """The next key-shaped value copied, or None after `wait` seconds.

    What is on the clipboard when waiting starts is taken only when the
    recipe's pattern recognises it (the person copied the key a moment
    early); a generic-looking value from before is stale: it is emptied
    away (so copying the same key again counts as new). The clipboard is
    emptied as soon as a value is taken."""
    raw_get = get

    def get():
        try:
            return raw_get()
        except Exception:
            return ""                           # unreadable now: look again next time
    start = (get() or "").strip()
    if pattern and start not in taken and looks_like(start, pattern):
        clear()
        return start
    if start and looks_like(start, None):
        # A key-shaped value that is NOT recognised as this service's key:
        # it must not stay on the clipboard, and emptying the clipboard also
        # means a second, identical Copy shows up as a change.
        clear()
        start = ""
    seen = start
    deadline = now() + wait
    while now() < deadline:
        sleep(poll)
        current = (get() or "").strip()
        if current == seen:
            continue
        seen = current
        if current not in taken and looks_like(current, pattern):
            clear()
            return current
    return None


def clear_verified(get, clear, wait: float = 3.0, poll: float = 0.1,
                   now=time.monotonic, sleep=time.sleep) -> bool:
    """Empty the clipboard and make sure it is: clear, read it back, and try
    again for up to `wait` seconds. False when it still holds something, when
    clear() said it failed (returned False), or when the clipboard cannot be
    read back (unreadable is NOT proof of empty)."""
    deadline = now() + wait
    while True:
        cleared = True
        try:
            cleared = clear() is not False
        except Exception:
            cleared = False
        try:
            if cleared and not (get() or "").strip():
                return True
        except Exception:
            pass
        if now() >= deadline:
            return False
        sleep(poll)
