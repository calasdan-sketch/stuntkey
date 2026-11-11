"""Ask the person before something risky happens.

Preferred: a real pop-up window from the operating system. It works even
when the AI app has no terminal (Claude Desktop, Cursor), and a program
cannot answer it by typing into a console. If no pop-up is possible we ask
on the console device itself and require a random 4-digit code that is only
shown on screen. If neither is possible the answer is NO.

Honest limit: a program running as you that can drive your screen
(UI automation) could still click a pop-up. SECURITY.md says so.
"""
from __future__ import annotations

import hmac
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time

from . import safeexec

TIMEOUT = 120
MAX_SHOWN = 900      # broker refuses requests whose description is longer
SHOW_LIMIT = 1800    # the longest text a window shows once look-alike characters are spelled out


def _tool(*paths):
    """First of these ABSOLUTE paths that is a real file. Never searches PATH
    or the current folder, so a program an AI dropped there cannot answer the
    pop-up for you."""
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def _system_root() -> str:
    """The Windows folder, asked of the OS rather than an environment variable
    an AI-tool config could point somewhere else."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
            return os.path.dirname(buf.value)       # ...\Windows\System32 -> ...\Windows
    except Exception:
        pass
    return os.environ.get("SystemRoot") or r"C:\Windows"


# Characters that can make one thing look like another in a pop-up: invisible and
# direction-changing characters (zero-width space, right-to-left override), and letters
# of other alphabets that are drawn like Latin ones (Cyrillic, Greek, Armenian, Cherokee,
# full-width and "mathematical" letters). Each one is shown as <U+XXXX> so the person
# can SEE it; a real name written in such letters stays readable beside its code.
_LOOKALIKE_RANGES = ((0x0370, 0x03FF), (0x0400, 0x052F), (0x0530, 0x058F), (0x13A0, 0x13FF),
                     (0x1F00, 0x1FFF), (0x1D400, 0x1D7FF), (0xFF00, 0xFFEF), (0x2460, 0x24FF),
                     (0x1D00, 0x1DBF), (0xA640, 0xA69F))


def _odd(ch: str) -> bool:
    o = ord(ch)
    if o < 128:
        return False
    import unicodedata
    if unicodedata.category(ch)[0] in "CZM" or unicodedata.category(ch) in ("Zs",):
        return True                      # control, format, separator, private, unassigned, marks
    return any(a <= o <= b for a, b in _LOOKALIKE_RANGES)


def _safe(text: str, limit: int = MAX_SHOWN) -> str:
    """The request as the pop-up shows it: line breaks and tabs as spaces, runs of
    spaces cut to three (so blank padding cannot push the real words out of view),
    and every invisible or look-alike character spelled out as <U+XXXX>. A text
    longer than `limit` is cut here, but `dialog` and `console` never show a cut
    text: they refuse it (see _too_long)."""
    out, odd = [], False
    for c in str(text):
        if c in "\r\n\t\x0b\x0c":
            c = " "
        if c == " " or (c.isascii() and c.isprintable()):
            out.append(c)
        elif c.isascii() or _odd(c):
            out.append("<U+%04X>" % ord(c))
            odd = True
        else:
            out.append(c)
    s = re.sub(r" {4,}", "   ", "".join(out)).strip()
    if odd:
        s += "  [characters shown as <U+...> are invisible or look like other letters]"
    return s if len(s) <= limit else s[:limit] + "...[+%d more characters]" % (len(s) - limit)


def _too_long(summary: str) -> bool:
    """A request longer than MAX_SHOWN cannot be read whole in a window, and a
    window that cuts it off could hide the part that matters: it is refused."""
    # (the spelled-out look-alike characters make the shown text longer than the raw one,
    # so it is the SHOWN length that is held to SHOW_LIMIT)
    if len(str(summary)) <= MAX_SHOWN and len(_safe(summary, 10 ** 6)) <= SHOW_LIMIT:
        return False
    _say("a permission request was too long to show whole (%d characters, at most %d), "
         "so the answer is no. Nothing was done. Ask for a shorter request." % (len(str(summary)), MAX_SHOWN))
    return True

def _window_env(msg: str) -> dict:
    """The environment the pop-up helper runs with: a fixed, minimal one (the
    same as dialog.py's), never the caller's, so a PATH, LD_PRELOAD or
    PYTHON* variable an AI-tool config set cannot reach the helper."""
    if os.name == "nt":
        root = _system_root()
        return {"SystemRoot": root, "windir": root,
                "PATH": os.path.join(root, "System32"), "SEA_MSG": msg}
    return dict(safeexec.env(), SEA_MSG=msg)


# The Windows pop-up. The message box is OWNED by an invisible always-on-top form, so it
# opens in front of every other window (a program cannot hide it behind its own window and
# wait for a stray click), "No" is the default button, and the title is fixed text.
WIN_SCRIPT = (
    "Add-Type -AssemblyName System.Windows.Forms; "
    "$o=New-Object System.Windows.Forms.Form; $o.TopMost=$true; $o.ShowInTaskbar=$false; "
    "$o.Opacity=0; $o.FormBorderStyle='None'; $o.Size=New-Object System.Drawing.Size(1,1); "
    "$null=$o.Handle; "
    "$r=[System.Windows.Forms.MessageBox]::Show($o,$env:SEA_MSG,"
    "'stuntkey - permission needed','YesNo','Warning','Button2'); "
    "$o.Dispose(); "
    "if($r -eq 'Yes'){exit 0}else{exit 1}")

MAX_WINDOWS_PER_MINUTE = 6       # more pop-ups than this in a minute are refused unseen
_shown: list = []                 # when each pop-up was shown (monotonic seconds)
_shown_lock = threading.Lock()


def _say(text: str) -> None:
    """A plain line for the person on standard error (never standard output:
    an MCP server talks on that). Never raises."""
    try:
        print("stuntkey: " + text, file=sys.stderr, flush=True)
    except Exception:
        pass


def _too_many_windows(now: float | None = None) -> bool:
    """Approval-fatigue guard: an agent that keeps asking cannot wear the
    person down with modal pop-ups. Counts pop-ups shown in the last minute."""
    now = time.monotonic() if now is None else now
    with _shown_lock:
        _shown[:] = [t for t in _shown if now - t < 60]
        if len(_shown) >= MAX_WINDOWS_PER_MINUTE:
            return True
        _shown.append(now)
        return False


def dialog(summary: str) -> bool | None:
    """True/False from a pop-up, or None if no pop-up could be shown.

    STUNTKEY_NO_WINDOW=1 means the person turned pop-up windows off: the answer
    is NO, with a plain message (never a fall-back to guessing). More than
    MAX_WINDOWS_PER_MINUTE pop-ups in one minute are also answered NO without
    showing one (approval fatigue)."""
    if os.environ.get("STUNTKEY_NO_WINDOW") == "1":
        _say("a permission window was asked for, but windows are turned off "
             "(STUNTKEY_NO_WINDOW=1), so the answer is no. Nothing was done.")
        return False
    if _too_long(summary):
        return False
    if _too_many_windows():
        _say("too many permission windows in the last minute, so this one was "
             "refused without being shown. Nothing was done. Wait a minute, "
             "then ask again.")
        return False
    msg = _safe(summary, SHOW_LIMIT) + "\n\nAllow this?"
    env = _window_env(msg)
    try:
        if os.name == "nt":
            ps = _tool(os.path.join(_system_root(), "System32", "WindowsPowerShell",
                                    "v1.0", "powershell.exe"))
            if not ps:
                return None
            cmd = [ps, "-NoProfile", "-NonInteractive", "-Command", WIN_SCRIPT]
            return subprocess.run(cmd, env=env, timeout=TIMEOUT,
                                  capture_output=True).returncode == 0
        if sys.platform == "darwin":
            osa = _tool("/usr/bin/osascript")
            if not osa:
                return None
            r = subprocess.run(
                [osa, "-e",
                 'display dialog (system attribute "SEA_MSG") with title '
                 '"stuntkey - permission needed" buttons {"No","Yes"} '
                 'default button "No" with icon caution'],
                env=env, timeout=TIMEOUT, capture_output=True, text=True)
            return r.returncode == 0 and "button returned:Yes" in r.stdout
        for names, argv in ((("zenity",), ["--question", "--no-markup",
                                           "--title=stuntkey", "--text=" + msg]),
                            (("kdialog",), ["--yesno", "<qt>" + _no_markup(msg) + "</qt>", "--title", "stuntkey"])):
            exe = _tool(*[d + "/" + n for n in names for d in ("/usr/bin", "/bin")])
            if exe:
                return subprocess.run([exe] + argv, env=env, timeout=TIMEOUT,
                                      capture_output=True).returncode == 0
    except subprocess.TimeoutExpired:
        return False                 # no answer in time means no
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def _no_markup(msg: str) -> str:
    """kdialog has no plain-text switch and treats <b>...</b> as markup, so a
    request could dress itself up. Turn the three special characters into
    their harmless spelling."""
    return msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _flush(inp) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        else:
            import termios
            termios.tcflush(inp.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


def console(summary: str) -> bool:
    """Ask on the console device, with a code shown only on screen."""
    dev_in, dev_out = (("CONIN$", "CONOUT$") if os.name == "nt"
                       else ("/dev/tty", "/dev/tty"))
    if _too_long(summary):
        return False
    code = "%04d" % random.SystemRandom().randrange(10000)
    try:
        with open(dev_out, "w", encoding="utf-8") as out, \
                open(dev_in, encoding="utf-8") as inp:
            _flush(inp)
            out.write(f"\nstuntkey needs your permission:\n  {_safe(summary, SHOW_LIMIT)}\n"
                      f"To allow, type {code} and press Enter (anything else = no): ")
            out.flush()
            return hmac.compare_digest(inp.readline().strip().encode("utf-8", "replace"), code.encode("ascii"))
    except OSError:
        return False


def ask_person(summary: str) -> bool:
    shown = dialog(summary)
    if shown is not None:
        return shown
    return console(summary)
