"""Calas Automations look for StuntKey's terminal output.

Small, stdlib-only, and safe to import anywhere. Colour and fancy glyphs are
used only when the terminal can show them; otherwise the same words come out
as plain ASCII. Nothing here ever raises on a weird console.

Stable names (other modules import these defensively):
  COLORS, BLUE, GOLD, WHITE, banner(), step(), ok(), warn(), fail(), plain_box()

Every helper RETURNS the text. Pass file=sys.stdout (or any stream) to also
write it as a line.
"""
from __future__ import annotations

import os
import sys

BLUE = "#155F87"
GOLD = "#F0C171"
WHITE = "#FFFFFF"
COLORS = {"blue": BLUE, "gold": GOLD, "white": WHITE}

NAME = "STUNTKEY"
TAGLINE = "BY CALAS AUTOMATIONS"

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_vt_checked = None   # None = not tried yet, else True/False


def _rgb(hexcolor: str):
    h = hexcolor.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _enable_windows_vt() -> bool:
    """Turn on ANSI colour in a Windows console. False on the legacy console."""
    global _vt_checked
    if _vt_checked is not None:
        return _vt_checked
    ok_ = False
    try:
        if os.name == "nt":
            import ctypes
            k32 = ctypes.windll.kernel32
            handle = k32.GetStdHandle(-11)            # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                if mode.value & 0x0004:               # already on
                    ok_ = True
                else:
                    ok_ = bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
        else:
            ok_ = True
    except Exception:
        ok_ = False
    _vt_checked = ok_
    return ok_


def _stream(file):
    return file if file is not None else sys.stdout


def color_enabled(file=None) -> bool:
    """True only when ANSI colour is safe: a real terminal, NO_COLOR unset,
    TERM not 'dumb', and (on Windows) virtual-terminal mode switched on."""
    try:
        env = os.environ
        if env.get("NO_COLOR"):
            return False
        if env.get("TERM", "") == "dumb":
            return False
        force = env.get("FORCE_COLOR") or env.get("CLICOLOR_FORCE")
        s = _stream(file)
        isatty = bool(getattr(s, "isatty", lambda: False)())
        if not isatty and not (force and force != "0"):
            return False
        return _enable_windows_vt()
    except Exception:
        return False


def _unicode_ok(file=None) -> bool:
    """True when the stream can print non-ASCII (never on a cp1252/legacy console)."""
    try:
        s = _stream(file)
        enc = (getattr(s, "encoding", None) or "ascii")
        "✓─".encode(enc)
        if os.name == "nt" and not color_enabled(file):
            return False                              # legacy console: stay ASCII
        return True
    except Exception:
        return False


def _paint(text: str, hexcolor: str, file=None, bold: bool = False) -> str:
    if not color_enabled(file):
        return text
    env = os.environ
    if env.get("COLORTERM", "").lower() in ("truecolor", "24bit") or env.get("WT_SESSION"):
        r, g, b = _rgb(hexcolor)
        code = "\x1b[38;2;%d;%d;%dm" % (r, g, b)
    elif "256" in env.get("TERM", ""):
        code = "\x1b[38;5;%dm" % (24 if hexcolor == BLUE else 222)
    else:
        code = "\x1b[%dm" % (34 if hexcolor == BLUE else 33)
    return (_BOLD if bold else "") + code + text + _RESET


def _out(text: str, file) -> str:
    if file is not None:
        try:
            file.write(text + "\n")
        except Exception:
            pass
    return text


def banner(file=None) -> str:
    """Compact three-line banner: name, gold rule, tagline."""
    rule = ("─" if _unicode_ok(file) else "-") * len(TAGLINE)
    lines = [
        "  " + _paint(NAME, BLUE, file, bold=True),
        "  " + _paint(rule, GOLD, file),
        "  " + _paint(TAGLINE, BLUE, file),
    ]
    return _out("\n".join(lines), file)


def _tag(label: str, hexcolor: str, glyph: str, file) -> str:
    mark = glyph if _unicode_ok(file) else label
    return _paint(mark, hexcolor, file, bold=True)


def ok(text: str, file=None) -> str:
    """A friendly success line."""
    return _out("%s %s" % (_tag("[ok]", BLUE, "✓", file), text), file)


def warn(text: str, file=None) -> str:
    """A friendly heads-up line."""
    return _out("%s %s" % (_tag("[!]", GOLD, "!", file), text), file)


def fail(text: str, file=None) -> str:
    """A friendly problem line. Say what happened and what to do next."""
    return _out("%s %s" % (_tag("[x]", GOLD, "✗", file), text), file)


def step(n: int, total: int, text: str, file=None) -> str:
    """'Step 2 of 4: text'."""
    label = _paint("Step %d of %d" % (n, total), BLUE, file, bold=True)
    return _out("%s: %s" % (label, text), file)


def plain_box(title: str, lines, file=None, width: int = 70) -> str:
    """A simple box. Always ASCII borders so it survives any console."""
    import textwrap
    inner = max(20, min(width, 100)) - 4
    body = []
    for ln in lines:
        wrapped = textwrap.wrap(str(ln), inner) or [""]
        body.extend(wrapped)
    t = str(title)[:inner]
    top = "+- " + t + " " + "-" * max(0, inner - len(t) - 1) + "+"
    out = [_paint(top, BLUE, file)]
    for b in body:
        out.append(_paint("|", BLUE, file) + " " + b.ljust(inner) + " " + _paint("|", BLUE, file))
    out.append(_paint("+" + "-" * (inner + 2) + "+", BLUE, file))
    return _out("\n".join(out), file)
