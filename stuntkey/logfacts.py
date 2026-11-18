"""Plain facts about the activity log (size, entries, last write) for
`stuntkey overview` and `stuntkey status`. A leaf module on purpose: it imports
nothing from stuntkey, so it adds no import cycle."""
from __future__ import annotations

import json
import os

# The words the PreToolUse / PostToolUse hook writes in the activity log's
# "result" field. They live here (a leaf module) so `doctor` can count them
# without importing the hook, which would tie it into the hook import cycle.
SHAPE_UNVERIFIED = "HOOK-POST-SHAPE-UNVERIFIED"   # a Read / Grep result in a shape we could not mask
POST_FAILED_RESULT = "HOOK-POST-FAILED"           # the output check itself failed
UNMASKABLE = "HOOK-POST-UNMASKABLE"               # a result with no text to mask (pdf, image ...)
PROBE_SKIPPED = "HOOK-PROBE-SKIPPED"              # a big content search let through unchecked
TAIL_BYTES = 1 << 20                              # only the last megabyte of the log is read


BIG_LOG_ENTRIES = 50_000


def default_audit_path() -> str:
    """Where the activity log normally is (no stuntkey import: a leaf)."""
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "audit.log")


def count_results(path, word: str) -> int:
    """How many of the last TAIL_BYTES of the activity log at `path` are lines
    whose "result" is `word`. Parsed line by line (a cut-off first line is
    dropped); 0 when there is no log. Never raises."""
    if not path:
        return 0
    needle = word.encode()
    n = 0
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > TAIL_BYTES:
                f.seek(size - TAIL_BYTES)
                f.readline()
            for line in f:
                if needle not in line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("result") == word:
                    n += 1
    except OSError:
        return 0
    return n


def shape_unverified_count(path=None) -> int:
    return count_results(path or default_audit_path(), SHAPE_UNVERIFIED)


def post_failures(path=None) -> int:
    return count_results(path or default_audit_path(), POST_FAILED_RESULT)


def log_facts(alog) -> dict:
    """{"entries", "bytes", "last_write"(epoch or None)} for the activity log,
    cheaply. Uses AuditLog.stats() when this build has it; otherwise counts
    lines without parsing them. Never raises."""
    facts = {"entries": None, "bytes": None, "last_write": None}
    stats = getattr(alog, "stats", None)
    if callable(stats):
        try:
            got = stats()
            if isinstance(got, dict):
                facts["entries"] = got.get("entries", got.get("n"))
                facts["bytes"] = got.get("bytes", got.get("size"))
                facts["last_write"] = got.get("last_write", got.get("mtime"))
        except Exception:               # noqa: BLE001 - facts are a courtesy
            pass
    path = getattr(alog, "path", None)
    if path and (facts["bytes"] is None or facts["last_write"] is None):
        try:
            st = os.stat(path)
            facts["bytes"] = st.st_size if facts["bytes"] is None else facts["bytes"]
            facts["last_write"] = st.st_mtime if facts["last_write"] is None else facts["last_write"]
        except OSError:
            pass
    if path and facts["entries"] is None:
        try:
            count = 0
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    count += chunk.count(b"\n")
            facts["entries"] = count
        except OSError:
            pass
    return facts


def _size_words(n) -> str:
    if n is None:
        return "unknown size"
    for unit, step in (("bytes", 1024), ("KB", 1024), ("MB", 1024)):
        if n < step:
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} GB"


def log_lines(facts: dict) -> str:
    """Plain lines about the log's size and last write, with a warning when
    it is very large. Empty when there is nothing to say."""
    import time as _t
    n = facts.get("entries")
    if n is None and facts.get("bytes") is None:
        return ""
    when = facts.get("last_write")
    last = (_t.strftime("%Y-%m-%d %H:%M", _t.localtime(when))
            if isinstance(when, (int, float)) and when else "never")
    text = (f"  log size: {_size_words(facts.get('bytes'))}, "
            f"{n if n is not None else 'an unknown number of'} entries; "
            f"last write: {last}")
    if isinstance(n, int) and n > BIG_LOG_ENTRIES:
        text += ("\n  WARNING: the activity log is very large (over 50,000 entries). "
                 "Checking it is slow and it keeps growing. Start a fresh one with "
                 "`stuntkey audit reset` (the old log is kept beside it).")
    return text
