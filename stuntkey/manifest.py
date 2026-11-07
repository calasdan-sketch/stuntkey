"""`stuntkey.json`: which services a project needs, and nothing secret.

A project file you COMMIT, so a teammate (or you, on a new laptop) can run
`stuntkey setup` and be walked through every key the project needs:

    {
      "version": 1,
      "max_age_days": 90,
      "services": [
        {"service": "openai", "env_vars": ["OPENAI_API_KEY"]},
        {"service": "stripe", "env_vars": ["STRIPE_SECRET_KEY"], "store": "keychain"}
      ]
    }

It holds names only: service slugs, variable names, where each key is kept.
A file with any other member, or with something that looks like a key where
a name belongs, is refused - so it can never become a place a key hides.
"""

from __future__ import annotations

import json
import os
import re
import tempfile

from . import fsutil
from . import recipes as recipes_mod

FILE_NAME = "stuntkey.json"
LEGACY_FILE_NAME = "oathkey.json"     # 0.8's name: used when ours is absent
VERSION = 1
STORES = ("env", "keychain")
DEFAULT_MAX_AGE_DAYS = 90
MAX_BYTES = 256 * 1024
MAX_SERVICES = 200
TOP_KEYS = {"version", "max_age_days", "services", "env_file"}
SERVICE_KEYS = {"service", "env_vars", "store"}


class ManifestError(ValueError):
    """The manifest cannot be used. The text names the problem, never a value."""


def _git_root(start: str) -> str | None:
    """The nearest folder at or above `start` that has a .git."""
    here = start
    for _ in range(64):
        if os.path.lexists(os.path.join(here, ".git")):
            return here
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent
    return None


def _ours(path: str) -> bool:
    """A manifest owned by somebody else is not trusted (POSIX)."""
    try:
        return not hasattr(os, "geteuid") or os.stat(path).st_uid == os.geteuid()
    except OSError:
        return False


def project_root(start: str | None = None) -> str:
    """THE project folder, one rule for every command and tool: the folder of
    the nearest stuntkey.json (never above the git root), else the git
    root, else `start` itself. Always a real path."""
    here = os.path.realpath(start or os.getcwd())
    found = find(here)
    if found:
        return os.path.realpath(os.path.dirname(found))
    return os.path.realpath(_git_root(here) or here)


def path_in(folder: str) -> str:
    """The manifest's path in `folder`: stuntkey.json, or an old oathkey.json
    when only that one is there."""
    from .migrate import pick
    return pick(folder, FILE_NAME, LEGACY_FILE_NAME)


def find(start: str | None = None) -> str | None:
    """The nearest stuntkey.json at or above `start` (default: here), but
    never above the project: the search stops at the git work tree's root,
    and with no git root only `start` itself is looked at. (A manifest left
    in /tmp or a parent folder must not steer a project it does not belong
    to.) Use --project-dir to name the folder yourself."""
    here = os.path.realpath(start or os.getcwd())
    top = _git_root(here) or here
    for _ in range(64):
        candidate = path_in(here)
        if os.path.isfile(candidate) and _ours(candidate):
            return candidate
        if here == top:
            return None
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent
    return None


PUBLIC_DIRS = frozenset({"public", "static", "dist", "www", "build", "wwwroot", "public_html", "htdocs"})
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com\d|lpt\d)(\.|$)", re.I)


def env_file_problem(value) -> str | None:
    """Why `value` cannot be a manifest's env_file, or None. It must be a
    relative path inside the project whose last part is a .env-style name
    (.env, .env.local, prod.env): never a source file, never the manifest,
    never anything under .git."""
    if not (isinstance(value, str) and value and "\x00" not in value and len(value) < 260):
        return "env_file must be a relative path inside the project"
    if "\\" in value or re.match(r"^[A-Za-z]:", value) or value.startswith(("/", "~")):
        return "env_file must be a relative path with forward slashes, no drive letter"
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "env_file must not contain empty, '.' or '..' parts"
    if any(p.lower() == ".git" or _WINDOWS_RESERVED.match(p) for p in parts):
        return "env_file must not point into .git or at a device name"
    name = parts[-1].lower()
    if any(p.lower() in PUBLIC_DIRS for p in parts[:-1]):
        return "env_file must not be inside a folder a web server publishes (public, static, dist ...)"
    # ONE rule for what is a .env file, shared with the hook that protects it:
    # a name the hook would not recognise (.envfoo) is not accepted here
    from . import hook as hook_mod
    if not hook_mod.is_env_name(parts[-1]) or name in (".envrc",):
        return "env_file must be a .env-style file name (.env, .env.local, prod.env)"
    if name.endswith((".json", ".md", ".py", ".js", ".ts", ".yml", ".yaml", ".toml", ".sh")):
        return "env_file must be a .env-style file name"
    return None


def env_file_in(root: str, data: dict | None) -> str:
    """The .env file for the project at `root`: the manifest's env_file when
    it has one, else .env. Raises ManifestError when the real location (after
    following folder links) is outside the project."""
    rel = (data or {}).get("env_file") or ".env"
    problem = env_file_problem(rel)
    if problem:
        raise ManifestError(problem)
    full = os.path.join(root, *rel.split("/"))
    base = os.path.realpath(root)
    real = os.path.join(os.path.realpath(os.path.dirname(full)), os.path.basename(full))
    if os.path.commonpath([base, real]) != base:
        raise ManifestError("env_file leads outside the project (through a linked folder)")
    return full


def validate(data) -> dict:
    if not isinstance(data, dict):
        raise ManifestError("the manifest must be a JSON object")
    extra = set(data) - TOP_KEYS
    if extra:
        raise ManifestError(f"unknown member(s) in the manifest: "
                            f"{', '.join(sorted(recipes_mod.printable(k) for k in extra))}")
    if data.get("version", VERSION) != VERSION:
        raise ManifestError(f"this stuntkey reads manifest version {VERSION}")
    age = data.get("max_age_days", DEFAULT_MAX_AGE_DAYS)
    if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 3650:
        raise ManifestError("max_age_days must be a whole number of days (1-3650)")
    if data.get("env_file") is not None:
        problem = env_file_problem(data["env_file"])
        if problem:
            raise ManifestError(problem)
    services = data.get("services")
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise ManifestError("services must be a list")
    seen = set()
    for item in services:
        if not isinstance(item, dict):
            raise ManifestError("each service must be an object")
        extra = set(item) - SERVICE_KEYS
        if extra:
            raise ManifestError(f"unknown member(s) in a service: "
                                f"{', '.join(sorted(recipes_mod.printable(k) for k in extra))}")
        slug = item.get("service")
        if not isinstance(slug, str) or not recipes_mod.SLUG_RE.match(slug):
            raise ManifestError("each service needs a 'service' name like 'stripe'")
        if slug in seen:
            raise ManifestError(f"service '{slug}' is listed twice")
        seen.add(slug)
        names = item.get("env_vars", [])
        if not isinstance(names, list) or not all(
                isinstance(n, str) and recipes_mod.ENV_VAR_RE.match(n) and len(n) <= 100
                for n in names):
            raise ManifestError(f"service '{slug}': env_vars must be variable NAMES "
                                f"like OPENAI_API_KEY (never a value)")
        if item.get("store", "env") not in STORES:
            raise ManifestError(f"service '{slug}': store must be 'env' or 'keychain'")
    return data


def load(path: str) -> dict:
    try:
        if os.path.islink(path):
            raise ManifestError(f"{FILE_NAME} is a link; refusing to follow it")
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as e:
        raise ManifestError(f"cannot read {FILE_NAME}: {e.strerror or e}") from None
    if len(raw) > MAX_BYTES:
        raise ManifestError(f"{FILE_NAME} is too big")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ManifestError(f"{FILE_NAME} is not valid JSON") from None
    return validate(data)


def save(path: str, data: dict) -> None:
    """Write atomically. The file is meant to be committed, so it is a normal
    (not owner-only) file; validate() has just proved it holds names only."""
    validate(data)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".stuntkey.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        fsutil.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def service_vars(item: dict, recipe: dict | None) -> list[str]:
    """The variable names for a manifest service: its own list, else the recipe's."""
    if item.get("env_vars"):
        return list(item["env_vars"])
    return recipes_mod.env_vars(recipe) if recipe else []
