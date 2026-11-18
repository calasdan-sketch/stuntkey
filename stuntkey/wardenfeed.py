"""`stuntkey audit export --warden`: the activity log as two separate JSON Lines
files shaped for warden's `report` command.

The chained activity log (audit.log) is never changed: this only READS it and
writes different files. Only fields the log already holds are used (service,
method, the first two parts of the path, result, time); no query string, no
request or response body, no header, no key, no byte counts.

The two files follow the shapes read from warden's source:

  mcp-jail  (tool calls)  {run_id, agent_id, fleet, tool, server, args, allowed, at}
  planok    (approvals)   {run_id, agent_id, gate, decision, approver, requested_at, decided_at}
            decision is approved | denied | timeout

Honest limit: this is written to those shapes and has NOT been tried against a
live warden. The intended use is warden's `report --from mcp-jail --file ...`
and `report --from planok --file ...`. Only an approval a person REFUSED is in
the activity log, so only "denied" appears in the planok file.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os

FEED_NAME = "warden-feed.mcp-jail.jsonl"      # tool calls (the default --out)
PLANOK_SUFFIX = ".planok"                     # warden-feed.mcp-jail.jsonl -> warden-feed.mcp-jail.planok.jsonl
AGENT_ID = "stuntkey"
FLEET = "stuntkey"
MAX_FIELD = 200
MAX_LINE = 1_000_000          # bytes: warden reads lines up to about this size
MAX_SEGMENTS = 2              # path parts kept; the rest becomes a short hash


class FeedError(Exception):
    """A plain-words problem (bad --since, unreadable log)."""


def planok_path(out_path: str) -> str:
    base, ext = os.path.splitext(out_path)
    return base + PLANOK_SUFFIX + (ext or ".jsonl")


def parse_since(text: str | None) -> float | None:
    """Seconds since the epoch for an ISO 8601 date or time (no zone = UTC)."""
    if not text:
        return None
    try:
        when = datetime.datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except ValueError:
        raise FeedError("--since needs a date like 2026-11-14 or 2026-11-14T09:30:00Z") from None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when.timestamp()


def _rfc3339(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id(ts: float) -> str:
    """Stable for a whole day, so one day's calls group together."""
    return "stuntkey-" + datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")


def _text(value, limit: int = MAX_FIELD) -> str:
    """A plain printable string: control characters become ?, cut at `limit`."""
    return "".join(c if c.isprintable() else "?" for c in str(value if value is not None else ""))[:limit]


def _masked(text: str) -> str:
    """`text` with anything that looks like a key (known formats, and the
    stored keys when they can be read) replaced by [REDACTED]."""
    try:
        from . import scrub
        try:
            prints = scrub.load_fingerprints()
        except Exception:       # noqa: BLE001 - the formats still apply
            prints = (b"", frozenset())
        return scrub.mask_secrets(text, prints)[0]
    except Exception:           # noqa: BLE001
        return "[path withheld]"


def _path_only(value) -> str:
    """The path without a query string, fragment or `;` parameter (those can carry
    secrets), secrets masked, and only the first MAX_SEGMENTS parts kept; the
    rest is replaced by a short hash so two different deep paths stay apart
    without telling warden what is in them."""
    raw = str(value or "").split("?")[0].split("#")[0].split(";")[0]
    raw = _masked(raw)
    parts = [p for p in raw.split("/") if p]
    if len(parts) <= MAX_SEGMENTS:
        return _text("/" + "/".join(parts) if parts else "/")
    rest = "/".join(parts[MAX_SEGMENTS:])
    digest = hashlib.sha256(rest.encode("utf-8", "replace")).hexdigest()[:8]
    return _text("/" + "/".join(parts[:MAX_SEGMENTS]) + "/..." + digest)


def _int(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _ts(entry: dict) -> float:
    try:
        return max(0.0, float(entry.get("ts") or 0))
    except (TypeError, ValueError):
        return 0.0


def events_for(entry: dict) -> tuple:
    """(tool-call lines, approval lines) for one activity-log entry: two lists
    of 0 or 1 dicts each."""
    if not isinstance(entry, dict):
        return [], []
    service, method = entry.get("service"), entry.get("method")
    result = entry.get("result")
    if not service or not method or method == "-":
        return [], []                   # a marker line (rotation, post-check failure ...), not a call
    ts = _ts(entry)
    started = max(0.0, ts - _int(entry.get("ms")) / 1000.0)
    call = {"run_id": _run_id(ts), "agent_id": AGENT_ID, "fleet": FLEET,
            "tool": "http.request", "server": "stuntkey",
            "args": {"service": _text(service, 80), "method": _text(method, 10),
                     "path": _path_only(entry.get("path"))},
            "allowed": True, "at": _rfc3339(started)}
    if result in ("ok", "network-error"):
        return [call], []
    if result == "denied":
        # the person said no at an approval prompt: the call (not allowed) and the decision
        call["allowed"] = False
        approval = {"run_id": _run_id(ts), "agent_id": AGENT_ID, "gate": "broker-approval",
                    "decision": "denied", "approver": "person",
                    "requested_at": _rfc3339(started), "decided_at": _rfc3339(ts)}
        return [call], [approval]
    if result in ("refused", "refused-wrong-placeholder"):
        # a cap, route policy, kill switch or safety check said no before anything was sent
        call["allowed"] = False
        return [call], []
    return [], []


def build(entries, since: float | None = None) -> tuple:
    """(mcp-jail lines, planok lines)."""
    calls, approvals = [], []
    for e in entries:
        if since is not None:
            try:
                if float(e.get("ts") or 0) < since:
                    continue
            except (TypeError, ValueError, AttributeError):
                continue
        c, a = events_for(e)
        calls.extend(c)
        approvals.extend(a)
    return calls, approvals


def read_entries(log_path: str) -> list[dict]:
    try:
        with open(log_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return []
    except OSError as e:
        raise FeedError(f"could not read the activity log ({e.strerror or e})") from None
    rows = []
    for line in data.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _lines(events) -> str:
    out = []
    for e in events:
        line = json.dumps(e, sort_keys=True)
        if len(line.encode("utf-8")) < MAX_LINE:
            out.append(line + "\n")
    return "".join(out)


def _write(path: str, body: str) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    os.replace(tmp, path)


def export(log_path: str, out_path: str, since_text: str | None = None) -> int:
    """Write the two feeds (tool calls to `out_path`, approvals beside it, see
    planok_path); each is replaced whole, so a second run gives the same
    files. Returns how many lines in all. Never touches the activity log."""
    approvals_path = planok_path(out_path)
    for p in (out_path, approvals_path):
        if os.path.abspath(p) == os.path.abspath(log_path):
            raise FeedError("the feed must be a different file from the activity log")
    calls, approvals = build(read_entries(log_path), parse_since(since_text))
    try:
        _write(out_path, _lines(calls))
        _write(approvals_path, _lines(approvals))
    except OSError as e:
        raise FeedError(f"could not write {out_path} ({e.strerror or e})") from None
    return len(calls) + len(approvals)
