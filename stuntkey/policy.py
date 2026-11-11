"""Route rules: which methods and paths each key may be used for.

A file named `stuntkey.policy` (JSON) in ~/.stuntkey and, optionally, in the
project folder:

    {"openai": {"methods": ["GET", "POST"],
                "paths": ["/v1/chat/completions", "/v1/models"]}}

Once a service has a rule, anything the rule does not list is refused (deny
by default). Services without a rule keep the broker's normal rules. The
project file can only narrow the user file, never widen it: for a service
both name, a request must pass both.

An AI could edit these files, so a file is only obeyed after a person runs
`stuntkey policy approve`, which stores its sha256. A file that changed since
then stops every brokered call until it is approved again (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.parse

from .broker import BrokerError

FILE = "stuntkey.policy"
LEGACY_FILE = "oathkey.policy"     # 0.8's name: used when ours is absent
MAX_BYTES = 64_000
POLICY_REVIEW = 900       # longest policy file a person is asked to read in one window


def user_file(home: str) -> str:
    from .migrate import pick
    return pick(home, FILE, LEGACY_FILE)


def project_file(project_dir: str) -> str:
    from .migrate import pick
    return pick(project_dir, FILE, LEGACY_FILE)


def _approved_path(home: str) -> str:
    return os.path.join(home, "policy.approved")


def _read(path: str):
    """The file's bytes, or None when there is no file."""
    if not os.path.lexists(path):
        return None
    if os.path.islink(path) or not os.path.isfile(path):
        raise BrokerError(f"{path} is not a plain file, so no call was made.", 5)
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError:
        raise BrokerError(f"{path} cannot be read, so no call was made.", 5) from None
    if len(raw) > MAX_BYTES:
        raise BrokerError(f"{path} is too big to be a policy file.", 5)
    return raw


def _no_duplicates(pairs):
    """json object hook: the same name twice in one object is refused. The last one
    would win silently, so what the person read in a review could differ from what
    is enforced (a strict rule first, a wide one after it)."""
    seen = {}
    for k, v in pairs:
        key = k.lower() if isinstance(k, str) else k
        if key in seen:
            raise ValueError("duplicate name")
        seen[key] = v
    return dict(pairs)


def _plain_prefix(p: str) -> bool:
    """A path rule that is a plain absolute path: no `..` or `.` part, no encoded
    characters, no backslash, `;` or control character (see _clean_path)."""
    return p.startswith("/") and _clean_path(p) is not None


def parse(raw: bytes, where: str = FILE) -> dict:
    """{service: (frozenset(methods), tuple(path prefixes))}. Service names are kept in
    lower case (a rule written for "OpenAI" applies to "openai")."""
    bad = BrokerError(f"{where} is not a valid policy file (see `stuntkey policy "
                      "show` for the format; a service named twice, a path with `..` "
                      "or `%`, or a path that does not start with / is refused), "
                      "so no call was made.", 5)
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise bad from None
    if not isinstance(data, dict):
        raise bad
    rules = {}
    for service, rule in data.items():
        if not isinstance(rule, dict):
            raise bad
        methods, paths = rule.get("methods", []), rule.get("paths", [])
        if not (isinstance(methods, list) and isinstance(paths, list)
                and all(isinstance(m, str) for m in methods)
                and all(isinstance(p, str) and _plain_prefix(p) for p in paths)):
            raise bad
        rules[str(service).lower()] = (frozenset(m.upper() for m in methods), tuple(paths))
    return rules


def _clean_path(path: str) -> str | None:
    """The request path as the server will read it, or None when it uses a trick that
    could make a prefix rule say yes to a path the server reads differently: a `..` or
    `.` part (`/v1/models/../admin`), a second layer of %-encoding (`%252e%252e`), a
    backslash, a `;` parameter (`/v1/models;/../admin`), a control character or NUL.
    The query string and fragment are not part of the path."""
    if "#" in path.split("?")[0]:
        return None
    raw = path.split("?")[0]
    if any(ord(c) < 32 or ord(c) == 127 for c in raw) or "\\" in raw or ";" in raw:
        return None
    plain = urllib.parse.unquote(raw)
    if "%" in plain or "\\" in plain or ";" in plain or any(ord(c) < 32 or ord(c) == 127 for c in plain):
        return None
    if any(part in (".", "..") for part in plain.split("/")):
        return None
    return plain


def _shown(text: str, limit: int = 80) -> str:
    """A path as an error message shows it: control characters as ?, cut at `limit`."""
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


def _under(path: str, prefix: str) -> bool:
    """Prefix match on whole path segments: /v1/chat does not cover /v1/chatX."""
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


def narrow(user: dict, project: dict) -> dict:
    """The rules that pass both files."""
    out = dict(user)
    for service, (pm, pp) in project.items():
        if service not in user:
            out[service] = (pm, pp)
            continue
        um, up = user[service]
        paths = {p for p in pp if any(_under(p, u) for u in up)}
        paths |= {u for u in up if any(_under(u, p) for p in pp)}
        out[service] = (um & pm, tuple(sorted(paths)))
    return out


def _approved(home: str) -> dict:
    try:
        with open(_approved_path(home), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _checked(path: str, approved: dict):
    raw = _read(path)
    if raw is None:
        return {}
    if approved.get(_key(path)) != hashlib.sha256(raw).hexdigest():
        raise BrokerError(f"The policy file {path} is new or was changed and a "
                          "person has not approved it, so no call was made. "
                          "Run `stuntkey policy approve` to review it.", 5)
    return parse(raw, path)


def load(home: str, project_dir: str) -> dict:
    approved = _approved(home)
    user = _checked(user_file(home), approved)
    proj = project_file(project_dir)
    if _key(proj) == _key(user_file(home)):
        return user
    return narrow(user, _checked(proj, approved))


def check(rules: dict, service: str, method: str, path: str) -> None:
    service = str(service).lower()
    if service not in rules:
        return
    methods, prefixes = rules[service]
    plain = _clean_path(path)
    if plain is None:
        raise BrokerError(f"Your stuntkey policy refused {method.upper()} {_shown(path)} for "
                          f"'{service}': the path uses a trick (a `..` part, `%`-encoding "
                          "inside encoding, a backslash, a `;` or a control character) that "
                          "could reach a place the policy does not list, so it was not sent.", 5)
    if method.upper() in methods and any(_under(plain, p) for p in prefixes):
        return
    raise BrokerError(f"Your stuntkey policy does not allow {method.upper()} "
                      f"{_shown(path.split('?')[0])} for '{service}', so it was not "
                      "sent. A person can change stuntkey.policy and run "
                      "`stuntkey policy approve`.", 5)


def describe(rules: dict) -> str:
    """The rules exactly as they will be enforced, one line per service, for the
    review window: not the file's own text (which can hold escapes, repeated names
    or odd spacing), but what the program read from it."""
    lines = []
    for service in sorted(rules):
        methods, paths = rules[service]
        lines.append(f"{service}: {', '.join(sorted(methods)) or 'no methods (nothing allowed)'} "
                     f"on {', '.join(paths) or 'no paths (nothing allowed)'}")
    return "\n".join(lines) or "(no rules)"


def approve(home: str, project_dir: str, ask) -> int:
    """Show each policy file to the person; store the sha256 of each one they
    accept. Returns how many files were approved."""
    from .store import write_private
    approved = _approved(home)
    n = 0
    for path in dict.fromkeys((user_file(home), project_file(project_dir))):
        raw = _read(path)
        if raw is None:
            continue
        rules = parse(raw, path)               # never approve a broken file
        text = f"Use this route policy ({path}):\n" + describe(rules)
        if len(text) > POLICY_REVIEW:              # never ask about a cut-off file
            raise BrokerError(f"{path} is too long to review safely in one "
                              "window; make it shorter.", 5)
        if not ask(text):
            continue
        approved[_key(path)] = hashlib.sha256(raw).hexdigest()
        n += 1
    write_private(_approved_path(home), json.dumps(approved, indent=2) + "\n")
    return n
