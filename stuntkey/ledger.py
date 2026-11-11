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
import re
import sys

from . import store as store_mod

MAX_BYTES = 1024 * 1024
STORES = ("env", "keychain")

# Format of index.json. A file made by a NEWER StuntKey is refused (never
# overwritten); an older one is brought forward by the functions in MIGRATIONS
# ({old_version: fn(data) -> data for version old_version + 1}).
CURRENT_VERSION = 1
MIGRATIONS: dict = {}


class LedgerError(OSError):
    """The key-dates file cannot be used. str() is plain words saying why
    and what to do."""

    def __init__(self, message: str, path: str | None = None):
        super().__init__(22, message)
        self.plain = message

    def __str__(self) -> str:
        return self.plain


def _tell(message: str) -> None:
    try:
        sys.stderr.write(f"stuntkey: {message}\n")
    except (OSError, ValueError):
        pass


def _signing_key(index_path: str, create: bool = False):
    from . import keychain
    return keychain.integrity_key(os.path.dirname(os.path.abspath(index_path)),
                                  create=create, purpose="ledger")[0]


def _signing_key_info(index_path: str):
    from . import keychain
    try:
        return keychain.integrity_key(os.path.dirname(os.path.abspath(index_path)),
                                      create=False, purpose="ledger")
    except Exception:
        return None, "unavailable"


def _canonical(version, projects) -> bytes:
    return json.dumps({"version": version, "projects": projects},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _v1_to_v2(data: dict) -> dict:
    """Skeleton for the first real format change: take a version-1 document
    and return it in version-2 shape (the caller sets "version"). It changes
    nothing yet. To use it, set CURRENT_VERSION = 2 and register it as
    MIGRATIONS = {1: _v1_to_v2}; a version-1 file is then read, brought
    forward in memory and written back as version 2 on the next save."""
    return dict(data)


def _migrate(data: dict, index_path: str) -> dict:
    try:
        return store_mod.migrate_document(data, CURRENT_VERSION, MIGRATIONS,
                                          "This key list", index_path)
    except OSError as e:
        raise LedgerError(e.strerror or "This key list cannot be read by this "
                          "StuntKey. Update StuntKey: pipx upgrade stuntkey",
                          index_path) from None


def reset(index_path: str | None = None) -> str | None:
    """Start the key dates afresh WITHOUT losing the old file: move it aside to
    index.json.old-<time> and return that path (None when there was no file).
    The file holds no keys, only dates; after this, old keys show as 'added
    before records'."""
    index_path = index_path or path()
    if not os.path.exists(index_path):
        return None
    base = f"{index_path}.old-{int(_now().timestamp())}"
    kept, i = base, 1
    while os.path.exists(kept):
        i += 1
        kept = f"{base}-{i}"
    os.replace(index_path, kept)
    return kept


def path() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "index.json")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _project_key(project_dir: str) -> str:
    return os.path.realpath(project_dir)


def _read_file(index_path: str):
    """The parsed file, or None when there is nothing usable."""
    try:
        if store_mod.private_path_problem(index_path) or not os.path.isfile(index_path):
            return None
        with open(index_path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return None
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _checked(index_path: str, resign: bool) -> dict:
    """projects, after the version and signature checks. Raises LedgerError."""
    data = _read_file(index_path)
    if data is None:
        return {}
    projects = data.get("projects")
    if not isinstance(projects, dict):
        return {}
    sig = data.get("sig")
    key, where = _signing_key_info(index_path)
    signed_version = data.get("version", 1)      # the signature covers THIS version,
    if isinstance(sig, str):                     # checked before any migration
        if key is not None:
            from . import keychain
            import hmac
            if not hmac.compare_digest(
                    sig, keychain.sign(key, _canonical(signed_version, projects))):
                raise LedgerError(
                    f"The key dates file ({index_path}) does not match its "
                    "signature: it was changed by something other than StuntKey. "
                    "It holds no keys. To start fresh, delete that file (or rename it to keep a copy) "
                    "and run the command again; "
                    "old keys will show as 'added before records'.", index_path)
        elif where in ("keychain", "file"):
            # signed once, but the signing key is gone: not the same as tampering
            raise LedgerError(
                f"The key dates file ({index_path}) was signed, but the signing "
                "key that goes with it is gone from this computer (a cleared "
                "keychain, or StuntKey is running under a different home folder). "
                "Nothing says the file was changed, but it cannot be checked. "
                "It holds no keys. To start fresh, delete that file (or rename it to keep a copy) "
                "and run the command again; "
                "old keys will show as 'added before records'.", index_path)
    elif key is not None:
        # a signing key exists, so this file WAS signed: a missing signature
        # means it was taken off, never "an old file from before signing"
        raise LedgerError(
            f"The key dates file ({index_path}) has lost its signature, so it "
            "cannot be trusted: something other than StuntKey took it off. "
            "It holds no keys. To start fresh, delete that file (or rename it to keep a copy) "
            "and run the command again; "
            "old keys will show as 'added before records'.", index_path)
    data = _migrate(data, index_path)
    projects = data.get("projects")
    if not isinstance(projects, dict):
        return {}
    if isinstance(sig, str):
        pass
    elif resign:
        # an unsigned file from an older StuntKey: accept it once, then sign it
        key = _signing_key(index_path, create=True)
        if key is not None:
            try:
                with store_mod.file_lock(index_path):
                    _save(projects, index_path)
                _tell("signed your key dates file so a later change can be noticed.")
            except OSError:
                pass
    return projects


def load(index_path: str | None = None, resign: bool = True) -> dict:
    index_path = index_path or path()
    return _checked(index_path, resign)


def _quiet_load(index_path: str | None, resign: bool = True) -> dict:
    """load(), but a refused file is reported in words and read as empty."""
    try:
        return load(index_path, resign)
    except LedgerError as e:
        _tell(str(e))
        return {}


def _save(projects: dict, index_path: str | None = None) -> None:
    index_path = index_path or path()
    problem = store_mod.private_path_problem(index_path)
    if problem:
        raise store_mod.EnvFileRefused(index_path, problem)
    doc = {"version": CURRENT_VERSION, "projects": projects}
    key = _signing_key(index_path, create=True)
    if key is not None:
        from . import keychain
        doc["sig"] = keychain.sign(key, _canonical(CURRENT_VERSION, projects))
    store_mod.write_private(index_path, json.dumps(doc, indent=2) + "\n")


def record(project_dir: str, service: str, store: str, rotated: bool = False,
           index_path: str | None = None, now: datetime.datetime | None = None) -> None:
    """Remember that `service` was just connected (or rotated)."""
    stamp = (now or _now()).replace(microsecond=0).isoformat()
    try:
        with store_mod.file_lock(index_path or path()):
            projects = load(index_path, resign=False)
            entry = projects.setdefault(_project_key(project_dir), {}).get(service) or {}
            entry = {"created_at": entry.get("created_at") or stamp, "store": store,
                     "updated_at": stamp, **({"events": entry["events"]}
                                             if isinstance(entry.get("events"), list) else {})}
            if rotated:
                entry["rotated_at"] = stamp
            projects[_project_key(project_dir)][service] = entry
            _save(projects, index_path)
    except LedgerError as e:
        _tell(str(e))   # never overwrite a file we do not trust
    except OSError:
        pass            # the record is a convenience; the key is already safe


MAX_EVENTS = 50


def event(project_dir: str, service: str, step: str, result: str,
          index_path: str | None = None, now: datetime.datetime | None = None) -> None:
    """Note one step (e.g. a `panic` revoke) for the service: words only,
    never a key. The newest MAX_EVENTS are kept."""
    stamp = (now or _now()).replace(microsecond=0).isoformat()
    try:
        with store_mod.file_lock(index_path or path()):
            projects = load(index_path, resign=False)
            entry = dict(projects.setdefault(_project_key(project_dir), {}).get(service) or {})
            old = entry.get("events") if isinstance(entry.get("events"), list) else []
            entry["events"] = (old + [{"at": stamp, "step": step, "result": result}])[-MAX_EVENTS:]
            projects[_project_key(project_dir)][service] = entry
            _save(projects, index_path)
    except LedgerError as e:
        _tell(str(e))
    except OSError:
        pass


def events(project_dir: str, service: str, index_path: str | None = None) -> list:
    entry = _quiet_load(index_path).get(_project_key(project_dir), {}).get(service)
    found = entry.get("events") if isinstance(entry, dict) else None
    return found if isinstance(found, list) else []


def forget(project_dir: str, service: str, index_path: str | None = None) -> None:
    try:
        with store_mod.file_lock(index_path or path()):
            projects = load(index_path, resign=False)
            if projects.get(_project_key(project_dir), {}).pop(service, None) is not None:
                _save(projects, index_path)
    except LedgerError as e:
        _tell(str(e))
    except OSError:
        pass


def get(project_dir: str, service: str, index_path: str | None = None) -> dict | None:
    entry = _quiet_load(index_path).get(_project_key(project_dir), {}).get(service)
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
