"""Public APIs directory: discover free APIs by task.

Source: the public-apis/public-apis GitHub README (api.publicapis.org is
unreliable, so we parse the canonical list directly). Cached locally for
7 days; searchable offline after the first fetch.

Each entry: {name, url, description, auth, https, cors, category}.
Auth values in the wild: "No", "apiKey", "OAuth", etc.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
import urllib.request

from . import fsutil
from . import __version__

SOURCE_URL = ("https://raw.githubusercontent.com/public-apis/"
              "public-apis/master/README.md")
CACHE_TTL = 7 * 24 * 3600
# How far ahead of the clock a copy's date may be and still count as written
# just now. A clock that moves in 15 ms steps next to a file system that
# stamps finer (Windows: the list just downloaded was dated a few
# milliseconds AHEAD of "now", and the next call downloaded it again), a
# network drive whose server runs a minute fast, a stick formatted FAT: all
# of them date a fresh file a little in the future. Days ahead is a clock
# that was wrong (see _is_fresh).
CLOCK_SKEW = 3600

_CATEGORY_RE = re.compile(r"^###\s+(.+?)\s*$")
_ROW_RE = re.compile(
    r"^\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*(.*?)\s*\|\s*"
    r"`?([^`|]*)`?\s*\|\s*([^|]*)\|\s*([^|]*)\|")


# --- terminal-escape sanitization -------------------------------------
# Community directory strings are printed straight into the user's
# terminal by `stuntkey find` and embedded in MCP stdout, so they must never
# carry control sequences: `\x1b]0;…\x07` (OSC window-title hijack),
# `\x1b[2J` (screen clear), `\x1b[6n` (device-status-report exfil), etc.
# Every print path for directory data goes through sanitize_display.

_CSI_RE = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")          # ESC [ … final byte
_OSC_RE = re.compile(
    r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)")  # … BEL/ESC\/ST


def sanitize_display(text):
    """Strip ANSI escape sequences (CSI, OSC) and C0/C1 control characters
    (including a lone ESC and single-byte CSI/OSC) from community-sourced
    text. Newline and tab are preserved so legitimate multi-line
    descriptions still format.
    """
    if not isinstance(text, str):
        return text
    text = _OSC_RE.sub("", text)
    text = _CSI_RE.sub("", text)
    # C0 (\x00-\x1f except \n \t) + DEL + C1 (\x80-\x9f). \x1b (lone ESC)
    # falls in \x0e-\x1f and is removed here too.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)
    return text


def cache_path() -> str:
    d = os.path.expanduser("~/.stuntkey")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "public-apis.md")


def _is_fresh(path: str) -> bool:
    """Is the cached file young enough to use? One dated far in the future
    (the clock was wrong when it was written, a VM snapshot came back) is
    not: its age is negative, which is "younger than a week" for as long as
    the future lasts, and the old list would be served all that time. A few
    seconds ahead is only two clocks that differ (CLOCK_SKEW)."""
    age = time.time() - os.path.getmtime(path)
    return -CLOCK_SKEW <= age < CACHE_TTL


def _save(path: str, text: str) -> None:
    """Write the cache in one step: into a temp file next to it, then renamed
    over it. A reader, or a crash half-way, never meets half a list that
    carries a fresh date."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".public-apis.",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        fsutil.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def fetch(refresh: bool = False) -> str:
    """Return the README text, using the cache unless stale/refresh. A cache
    dated in the future counts as stale (see _is_fresh)."""
    path = cache_path()
    if not refresh and os.path.isfile(path) and _is_fresh(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    req = urllib.request.Request(SOURCE_URL,
                                 headers={"User-Agent": f"stuntkey/{__version__}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    _save(path, text)
    return text


def parse(text: str) -> list[dict]:
    entries: list[dict] = []
    category = ""
    for line in text.splitlines():
        m = _CATEGORY_RE.match(line)
        if m:
            category = m.group(1).strip()
            continue
        m = _ROW_RE.match(line)
        if m and category:
            entries.append({
                "name": m.group(1).strip(),
                "url": m.group(2).strip(),
                "description": m.group(3).strip(),
                "auth": m.group(4).strip() or "No",
                "https": m.group(5).strip(),
                "cors": m.group(6).strip(),
                "category": category,
            })
    return entries


def search(entries: list[dict], query: str,
           auth: str | None = None, category: str | None = None,
           limit: int = 10) -> list[dict]:
    """Keyword search. All query words must appear in name/description/
    category; name hits rank first."""
    words = [w.lower() for w in query.split() if w]
    scored: list[tuple[int, dict]] = []
    for e in entries:
        if auth and e["auth"].lower() != auth.lower():
            continue
        if category and category.lower() not in e["category"].lower():
            continue
        hay = f"{e['name']} {e['description']} {e['category']}".lower()
        if not all(w in hay for w in words):
            continue
        name_hay = f"{e['name']} {e['category']}".lower()
        score = sum(2 for w in words if w in name_hay) + sum(
            1 for w in words if w in hay)
        scored.append((score, e))
    scored.sort(key=lambda t: -t[0])
    return [e for _, e in scored[:limit]]


def find_by_name(entries: list[dict], name: str) -> dict | None:
    low = name.lower()
    for e in entries:
        if e["name"].lower() == low:
            return e
    for e in entries:
        if low in e["name"].lower():
            return e
    return None
