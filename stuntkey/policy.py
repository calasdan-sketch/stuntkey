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

import difflib
import hashlib
import json
import os
import re
import urllib.parse

from .broker import BrokerError

FILE = "stuntkey.policy"
LEGACY_FILE = "oathkey.policy"     # 0.8's name: used when ours is absent
MAX_BYTES = 64_000
ALLOWED_KEYS = ("methods", "paths")
# An empty (or missing) "methods" or "paths" list means NOTHING is allowed for
# that service - deny by default, the same as describe() tells the person.
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
    def bad_because(why: str = "") -> BrokerError:
        return BrokerError(f"{where} is not a valid policy file{(': ' + why) if why else ''} "
                           "(see `stuntkey policy show` for the format; a service named twice, "
                           "a path with `..` or `%`, or a path that does not start with / is "
                           "refused), so no call was made.", 5)
    bad = bad_because()

    def _no_constant(name):
        raise ValueError(f"{name} is not a number a policy can use")
    try:
        # utf-8-sig: a file saved by Notepad starts with an invisible BOM mark
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise bad_because("it is not UTF-8 text (save it as UTF-8)") from None
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        raise bad from None
    if not isinstance(data, dict):
        raise bad
    rules = {}
    for service, rule in data.items():
        if not isinstance(rule, dict):
            raise bad
        unknown = [k for k in rule if k not in ALLOWED_KEYS]
        if unknown:
            # a misspelt key ("method") must not quietly leave the service with
            # "nothing allowed" or, worse, look like a rule that is not there
            name = _shown(unknown[0], 40)
            near = difflib.get_close_matches(str(unknown[0]).lower(), ALLOWED_KEYS, n=1, cutoff=0.5)
            hint = f" - did you mean \"{near[0]}\"?" if near else ""
            raise bad_because(f"'{_shown(service, 40)}' has an unknown key \"{name}\"{hint} "
                              f"(allowed: {', '.join(ALLOWED_KEYS)})")
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


# ---- GraphQL: a read and a write look the same on the wire ------------------------
#
# Every GraphQL call is a POST to one address, so "POST /graphql" says nothing
# about whether it reads or changes data. A rule can therefore name two extra
# "methods":
#     QUERY     a POST whose GraphQL body is provably only queries
#     MUTATION  a POST (or GET) that is a mutation, a subscription, or anything
#               that cannot be read with certainty as a query
# A rule that lists POST keeps meaning "any POST" (as before). A read-only
# GraphQL rule is {"methods": ["GET", "QUERY"], ...}: a mutation then fails,
# and so does a body the reader cannot understand (unknown = mutation).

_GQL_OPS = ("query", "mutation", "subscription")
MAX_GQL_CHARS = 200_000


def _gql_strip(doc: str) -> str | None:
    """`doc` without comments, and with every string's content removed (so a
    word inside a string is never read as a keyword). None when a string is
    not closed."""
    out, i, n = [], 0, len(doc)
    while i < n:
        c = doc[i]
        if c == "#":
            while i < n and doc[i] not in "\r\n":
                i += 1
        elif doc.startswith('"""', i):
            end = i + 3
            while True:
                end = doc.find('"""', end)
                if end < 0:
                    return None
                if doc[end - 1] == "\\":
                    end += 1
                    continue
                break
            out.append('""')
            i = end + 3
        elif c == '"':
            i += 1
            while i < n and doc[i] != '"':
                if doc[i] in "\r\n":
                    return None
                i += 2 if doc[i] == "\\" else 1
            if i >= n:
                return None
            out.append('""')
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _skip_braces(s: str, i: int) -> int | None:
    """Index just after the `}` that closes the `{` at s[i], or None."""
    depth = 0
    while i < len(s):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
            if depth < 0:
                return None
        i += 1
    return None


_GQL_NAME_RE = re.compile(r"[A-Za-z_]\w*")


def gql_operations(doc) -> set | None:
    """The operation types in a GraphQL document ({"query"}, {"mutation"} ...),
    or None when it cannot be read with certainty (callers treat None as a
    mutation). A body that is not GraphQL at all but has a "query" field (a
    REST search such as {"query": "shoes"} on a path that is not a GraphQL
    path) is also None: unreadable, so it is treated as a mutation (fails
    closed, on purpose). Linear in the size of the document."""
    if not isinstance(doc, str) or not doc.strip() or len(doc) > MAX_GQL_CHARS:
        return None
    s = _gql_strip(doc)
    if s is None:
        return None
    import re
    kinds: set = set()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace() or c in ",\ufeff":
            i += 1
            continue
        if c == "{":                                   # shorthand query
            kinds.add("query")
            i = _skip_braces(s, i)
            if i is None:
                return None
            continue
        m = _GQL_NAME_RE.match(s, i)        # (matched in place: the work stays linear)
        if not m:
            return None
        word = m.group()
        if word not in _GQL_OPS and word != "fragment":
            return None                                # SDL, extend, unknown: not plainly a query
        if word in _GQL_OPS:
            kinds.add(word)
        i += len(word)
        paren = 0
        while i < n and not (s[i] == "{" and paren == 0):     # name, ($vars), @directives
            if s[i] in "([":
                paren += 1
            elif s[i] in ")]":
                paren -= 1
                if paren < 0:
                    return None
            i += 1
        if i >= n:
            return None
        i = _skip_braces(s, i)
        if i is None:
            return None
    return kinds or None


_GQL_FIELDS = ("query", "operationname", "variables")


class _DuplicateField(ValueError):
    pass


def _gql_pairs(pairs):
    """json object hook: `query`, `operationName` or `variables` written twice in
    one object (also in another letter case) is refused - a server may read the
    first, the last or the other spelling, and the policy cannot tell which."""
    seen = set()
    for k, _v in pairs:
        key = k.lower() if isinstance(k, str) else k
        if key in _GQL_FIELDS:
            if key in seen:
                raise _DuplicateField(key)
            seen.add(key)
    return dict(pairs)


def _gql_docs(path: str, body, query) -> list | None:
    """The GraphQL documents a request carries: a list of strings (maybe empty
    when the request is not GraphQL at all), or None when it looks like
    GraphQL but the document cannot be found or read the same way twice
    (ambiguous: treated as a mutation)."""
    gql_path = path.split("?")[0].rstrip("/").lower().endswith("graphql")
    docs: list = []
    if isinstance(query, dict) and isinstance(query.get("query"), str):
        docs.append(query["query"])
    if "?" in path:
        # round 3: a document in the address itself (GET /graphql?query=mutation{a})
        qs = path.split("?", 1)[1].split("#", 1)[0]
        for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True):
            if k.lower() == "query" and (gql_path or gql_operations(v) is not None):
                # on a GraphQL address always; elsewhere only a value that reads as a
                # GraphQL document (a search page's ?query=shoes is not one)
                docs.append(v)
    if body is not None:
        raw = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "replace")
        try:
            data = json.loads(bytes(raw).decode("utf-8-sig"), object_pairs_hook=_gql_pairs)
        except _DuplicateField:
            return None
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None if gql_path else docs      # not JSON: unreadable GraphQL, or not GraphQL
        items = data if isinstance(data, list) else [data]       # a batch is a list
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("query"), str):
                docs.append(item["query"])
            elif gql_path:
                return None             # persisted-query hash only, or an unknown shape
    if gql_path and not docs:
        return None                     # a GraphQL address with no document: persisted query
    return docs


def graphql_kind(path: str, body=None, query=None) -> str | None:
    """None when the request is not GraphQL; "query" when every document in it
    is provably only queries; "mutation" for everything else (a mutation, a
    subscription, or a document that cannot be read with certainty)."""
    docs = _gql_docs(path, body, query)
    if docs is None:
        return "mutation"
    if not docs:
        return None
    for d in docs:
        ops = gql_operations(d)
        if ops is None or ops != {"query"}:
            return "mutation"
    return "query"


def check(rules: dict, service: str, method: str, path: str, body=None, query=None) -> None:
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
    m = method.upper()
    if any(_under(plain, p) for p in prefixes):
        kind = graphql_kind(path, body, query) if m in ("POST", "GET") else None
        if kind is None:
            ok = m in methods
        elif m == "POST":
            # POST keeps meaning "any POST"; QUERY / MUTATION say which kind
            ok = bool(methods & ({"POST", "QUERY"} if kind == "query" else {"POST", "MUTATION"}))
        else:                                    # GET carrying a GraphQL document
            ok = m in methods and (kind == "query" or "MUTATION" in methods)
        if ok:
            return
        if kind == "mutation":
            raise BrokerError(f"Your stuntkey policy does not allow a GraphQL mutation (or a "
                              f"GraphQL request that cannot be read as a plain query) "
                              f"{m} {_shown(path.split('?')[0])} for '{service}', so it was not "
                              "sent. Allow it with \"POST\" or \"MUTATION\" in the methods of "
                              "stuntkey.policy, then run `stuntkey policy approve`.", 5)
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
