"""A small local record of WHEN each key was added - never the key.

~/.stuntkey/index.json (owner-only) remembers, per project folder and
service: when it was connected, where it was put (env file or keychain) and
when it was last rotated. `stuntkey status` uses it to say how old a key
is and to suggest rotating an old one. It holds no key, no part of a key and
no variable value: if it is lost, `status` just says "added before records".
"""

from __future__ import annotations

import datetime
import json
import os

from . import store as store_mod

MAX_BYTES = 1024 * 1024
STORES = ("env", "keychain")


def path() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "index.json")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _project_key(project_dir: str) -> str:
    return os.path.realpath(project_dir)


def load(index_path: str | None = None) -> dict:
    index_path = index_path or path()
    try:
        if os.path.islink(index_path) or not os.path.isfile(index_path):
            return {}
        with open(index_path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return {}
    projects = data.get("projects") if isinstance(data, dict) else None
    return projects if isinstance(projects, dict) else {}


def _save(projects: dict, index_path: str | None = None) -> None:
    index_path = index_path or path()
    store_mod.write_private(index_path, json.dumps({"version": 1, "projects": projects}, indent=2) + "\n")


def record(project_dir: str, service: str, store: str, rotated: bool = False,
           index_path: str | None = None, now: datetime.datetime | None = None) -> None:
    """Remember that `service` was just connected (or rotated)."""
    stamp = (now or _now()).replace(microsecond=0).isoformat()
    projects = load(index_path)
    entry = projects.setdefault(_project_key(project_dir), {}).get(service) or {}
    entry = {"created_at": entry.get("created_at") or stamp, "store": store,
             "updated_at": stamp, **({"events": entry["events"]}
                                     if isinstance(entry.get("events"), list) else {})}
    if rotated:
        entry["rotated_at"] = stamp
    projects[_project_key(project_dir)][service] = entry
    try:
        _save(projects, index_path)
    except OSError:
        pass            # the record is a convenience; the key is already safe


MAX_EVENTS = 50


def event(project_dir: str, service: str, step: str, result: str,
          index_path: str | None = None, now: datetime.datetime | None = None) -> None:
    """Note one step (e.g. a `panic` revoke) for the service: words only,
    never a key. The newest MAX_EVENTS are kept."""
    stamp = (now or _now()).replace(microsecond=0).isoformat()
    projects = load(index_path)
    entry = dict(projects.setdefault(_project_key(project_dir), {}).get(service) or {})
    old = entry.get("events") if isinstance(entry.get("events"), list) else []
    entry["events"] = (old + [{"at": stamp, "step": step, "result": result}])[-MAX_EVENTS:]
    projects[_project_key(project_dir)][service] = entry
    try:
        _save(projects, index_path)
    except OSError:
        pass


def events(project_dir: str, service: str, index_path: str | None = None) -> list:
    entry = load(index_path).get(_project_key(project_dir), {}).get(service)
    found = entry.get("events") if isinstance(entry, dict) else None
    return found if isinstance(found, list) else []


def forget(project_dir: str, service: str, index_path: str | None = None) -> None:
    projects = load(index_path)
    if projects.get(_project_key(project_dir), {}).pop(service, None) is not None:
        try:
            _save(projects, index_path)
        except OSError:
            pass


def get(project_dir: str, service: str, index_path: str | None = None) -> dict | None:
    entry = load(index_path).get(_project_key(project_dir), {}).get(service)
    if not isinstance(entry, dict):
        return None
    return {k: v for k, v in entry.items()
            if k in ("created_at", "updated_at", "rotated_at", "store")
            and isinstance(v, str)}


def age_days(entry: dict | None, now: datetime.datetime | None = None) -> int | None:
    """Whole days since the key was added (or last rotated), or None."""
    if not entry:
        return None
    stamp = entry.get("rotated_at") or entry.get("created_at")
    try:
        when = datetime.datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return max(0, ((now or _now()) - when).days)
