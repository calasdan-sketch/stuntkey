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

import os
import random
import subprocess
import sys

from . import safeexec

TIMEOUT = 120
MAX_SHOWN = 900      # broker refuses requests whose description is longer


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


def _safe(text: str, limit: int = MAX_SHOWN) -> str:
    s = "".join(c if c.isprintable() else " " for c in str(text))
    return s if len(s) <= limit else s[:limit] + "...[+%d more characters]" % (len(s) - limit)


def _window_env(msg: str) -> dict:
    """The environment the pop-up helper runs with: a fixed, minimal one (the
    same as dialog.py's), never the caller's, so a PATH, LD_PRELOAD or
    PYTHON* variable an AI-tool config set cannot reach the helper."""
    if os.name == "nt":
        root = _system_root()
        return {"SystemRoot": root, "windir": root,
                "PATH": os.path.join(root, "System32"), "SEA_MSG": msg}
    return dict(safeexec.env(), SEA_MSG=msg)


def dialog(summary: str) -> bool | None:
    """True/False from a pop-up, or None if no pop-up could be shown."""
    msg = _safe(summary) + "\n\nAllow this?"
    env = _window_env(msg)
    try:
        if os.name == "nt":
            ps = _tool(os.path.join(_system_root(), "System32", "WindowsPowerShell",
                                    "v1.0", "powershell.exe"))
            if not ps:
                return None
            cmd = [ps, "-NoProfile", "-NonInteractive", "-Command",
                   "Add-Type -AssemblyName System.Windows.Forms; "
                   "$r=[System.Windows.Forms.MessageBox]::Show($env:SEA_MSG,"
                   "'stuntkey - permission needed','YesNo','Warning','Button2'); "
                   "if($r -eq 'Yes'){exit 0}else{exit 1}"]
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
    code = "%04d" % random.SystemRandom().randrange(10000)
    try:
        with open(dev_out, "w", encoding="utf-8") as out, \
                open(dev_in, encoding="utf-8") as inp:
            _flush(inp)
            out.write(f"\nstuntkey needs your permission:\n  {_safe(summary)}\n"
                      f"To allow, type {code} and press Enter (anything else = no): ")
            out.flush()
            return inp.readline().strip() == code
    except OSError:
        return False


def ask_person(summary: str) -> bool:
    shown = dialog(summary)
    if shown is not None:
        return shown
    return console(summary)
