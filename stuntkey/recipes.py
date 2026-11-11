"""Recipe schema + loader.

A recipe is the per-service memory Claude always forgets: where the key
lives, the exact steps to mint one, how to prove it works, and where it
goes. Recipes are plain JSON — community-contributable, diffable.

Schema:
{
  "service": "github",            # slug [a-z0-9_-], required
  "display": "GitHub",           # human name, required
  "key_url": "https://...",      # where to mint the key, required
  "env_var": "GITHUB_TOKEN",     # where the key lands in .env, required
  "steps": ["...", "..."],       # exact click path, required non-empty
  "scopes": ["repo"],            # scopes to select, optional
  "docs": "https://...",        # docs link, optional
  "validate": {                  # proof the key works, required
    "method": "GET",
    "url": "https://api.github.com/user",
    "auth": {"type": "bearer", "scheme": "Bearer"}   # scheme optional:
          | {"type": "header", "header": "X-Key"}    #   "Token", "Bot"
          | {"type": "basic", "username": "api"},    # username optional
    "expect": [200],
    "reject": [401, 403],        # optional: statuses meaning "bad key"
    "headers": {"X-Version": "2024-01-01"},   # optional static headers
    "trusted_hosts": ["api.vendor.net"]       # optional, BUILT-IN recipes
  }                              #   only: validation hosts of the same
}                                #   vendor under another domain

Credentials of more than one value (an App ID and a secret, an access key
and its secret) are listed in "fields"; without it the recipe has the one
field "key" stored as env_var:

  "fields": [
    {"name": "app_id", "env_var": "EBAY_APP_ID", "label": "App ID (Client ID)",
     "pattern": "^[A-Za-z0-9-]+-PRD-[0-9a-f-]+$"},     # optional: lets the
    {"name": "cert_id", "env_var": "EBAY_CERT_ID",     #   clipboard capture
     "label": "Cert ID (Client Secret)"}               #   recognise a copy
  ],                                    # env_var must be the first field's

More auth shapes, each naming the fields it uses (default "key"):
    {"type": "bearer", "field": "token"}
    {"type": "header", "header": "X-Key", "field": "key"}
    {"type": "headers", "headers": {"X-App-Id": "{app_id}", "X-Key": "{key}"}}
    {"type": "basic", "username_field": "sid", "password_field": "token"}
    {"type": "query", "param": "appid"}            # follows no redirect
    {"type": "oauth2_client_credentials", "token_url": "https://...",
     "client_id_field": "app_id", "client_secret_field": "cert_id",
     "scope": "...", "send": "basic" | "body", "token_only": false}
    {"type": "aws_sigv4", "region": "us-east-1", "service": "sts",
     "access_key_field": "access_key_id", "secret_key_field": "secret_access_key"}

Every field must be used by the auth, so nothing is collected that the
check does not prove. The token_url gets the only POST stuntkey makes.

Two different jobs for a key's shape, kept apart on purpose:

  "accept": "^sk_(test|live)_"   # the copy-and-go gate (--clipboard). It may
                                 #   only use a shape the vendor DOCUMENTS,
                                 #   and loosely, so a valid key is never
                                 #   refused. Leave it out when unsure.
  "capture_accept": "^sk_(test|live)_[A-Za-z0-9]{10,247}\\Z"   # agent capture (capture_key) only:
                                 #   STRICT - anchored with \\Z and the documented
                                 #   length - because there a stray clipboard value
                                 #   could otherwise be taken. A valid key it refuses
                                 #   is captured with `connect` instead.
  "detect": "gsk_[A-Za-z0-9_-]{16,}"      # `scan` only: a commonly used shape
  "detect_confidence": "guess" | "known"  #   used as a HEURISTIC (default
                                          #   "guess" when only "detect").
  "pattern"                      # older recipes: one regex doing both jobs

Verdicts beyond "works" / "rejected" (under "validate"):

  "limited": [{"status": 403, "meaning": "valid, but lacks permission X"}]
  "body_rules": [{"status": 401, "body_contains": "restricted_api_key",
                  "result": "limited", "meaning": "..."}]    # valid|limited|invalid

A recipe in ~/.stuntkey/recipes (made on this computer, by a person or a program)
is not used until the person approves it: `stuntkey recipe approve <service>`
(recipetrust.py). It then reads only the keychain entries stored under its own
service name; a .env file only for variables listed in
  "allow_env": ["VAR", ...]    # a subset of the recipe's own variables, AND
                               # listed again in the person's approval

Other optional top-level fields:

  "least_privilege": {"summary": "...", "url": "https://..."}  # what to pick
  "unverified": ["validate.url"]   # parts the vendor docs do not confirm

"revoke" (optional) is how `stuntkey panic` kills a leaked key: the vendor's
official API call, its revoke page with steps for the person, or both (the
page is the fallback). The API host must be one the key already goes to.
  "revoke": {"api": {"method": "DELETE", "url": "https://api.vercel.com/v3/user/tokens/current",
                     "auth": {"type": "bearer"} | {"type": "json_list", "field": "credentials"},
                     "expect": [200], "headers": {...}},
             "page": "https://...", "steps": ["..."]}

"cli_token" (BUILT-IN recipes only) gets the key from the vendor's own CLI
after its browser sign-in, so nothing is copied at all:
  "cli_token": {"login": ["gh", "auth", "login", "--web"], "token": ["gh", "auth", "token"]}
"""

from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
import urllib.parse

# Built-in recipes ship inside the package (so `pip install .` carries
# them); recipes you capture with `stuntkey add` go to the user dir,
# which also wins when both define the same service slug.
RECIPES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "recipes")


def user_recipes_dir() -> str:
    """~/.stuntkey/recipes, resolved at call time (honours HOME /
    USERPROFILE overrides)."""
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "recipes")

REQUIRED = ("service", "display", "key_url", "env_var", "steps", "validate")
VALIDATE_REQUIRED = ("method", "url", "auth", "expect")
AUTH_TYPES = ("bearer", "header", "headers", "basic", "query",
              "oauth2_client_credentials", "aws_sigv4")
DEFAULT_FIELD = "key"
FIELD_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,31}\Z")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}\Z")
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
MAX_FIELDS = 6
MAX_PATTERN = 200
# Programs a built-in recipe may run to fetch a key after the vendor's own
# browser sign-in. Fixed here, not in the recipe: a recipe never chooses
# what runs on your computer.
CLI_PROGRAMS = ("gh",)
# A validation call proves a key by READING something. A recipe from
# somebody else must not be able to make `connect` send the real key with a
# DELETE or a POST to an endpoint on the key's own domain, where the
# cross-domain prompt never fires.
ALLOWED_METHODS = ("GET", "HEAD")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

# An env_var ends up as a literal line "NAME=<key>" in the user's .env.
# Anything but a plain shell identifier (e.g. "GOOD=1\nEVIL=pwned") would
# inject attacker-controlled lines the runtime then loads, so the shape is
# enforced here at recipe load time — before anything is written.
ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")

# The service slug becomes the recipe FILE NAME (<slug>.json) and a CLI
# argument. Lowercase letters, digits, '-' and '_' only, 1-64 chars: a slug
# like "../../evil" could otherwise write outside the recipes directory.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\Z")

# On Windows `nul.json`, `con.json`, `com1.json` ... are not files: whatever
# the extension, the name is a DEVICE (NUL, CON, COM1), so "saving" such a
# recipe writes into the device and nothing is kept. Microsoft reserves CON,
# PRN, AUX, NUL, COM0-COM9 and LPT0-LPT9. The slug is the file name, and a
# recipe made on one machine should be one every machine can keep, so these
# are refused everywhere.
WINDOWS_DEVICE_NAMES = frozenset(
    ["con", "prn", "aux", "nul"]
    + [f"com{n}" for n in range(10)] + [f"lpt{n}" for n in range(10)])


def device_name_problem(slug: str) -> str | None:
    """One line (no full stop) saying why `slug` is refused when Windows keeps
    it for a device, else None."""
    if slug not in WINDOWS_DEVICE_NAMES:
        return None
    return (f"'{slug}' is a name Windows keeps for a device (con, prn, aux, "
            f"nul, com0-com9, lpt0-lpt9), so a file called {slug}.json cannot "
            f"be saved there - pick another slug, e.g. '{slug}-api'")


class RecipeError(ValueError):
    pass


# The recipe's own sentences: its name, its steps and its scopes. A person
# reads them, and ordinary writing needs two things Python does not call
# printable (see _word_character). Every other field - a URL, a host, a
# header, a method - is a machine's text and gets no such leeway.
WORD_FIELDS = ("display", "steps", "scopes")
JOINERS = ("\u200c", "\u200d")        # zero-width non-joiner, joiner


def _visible(ch: str) -> bool:
    """One character that shows as a mark: printable and not a blank."""
    return len(ch) == 1 and ch.isprintable() and not ch.isspace()


def _word_character(text: str, i: int) -> bool:
    """May text[i], which Python does not call printable, stand in a
    recipe's own sentences? Two kinds may:

    - a space of another width (category Zs: the no-break space of a French
      "Cl\u00e9 API : copiez", the narrow no-break space, the ideographic
      space). It cannot drive a terminal: it is a blank, as a space is.
    - the zero-width joiner or non-joiner BETWEEN two visible characters:
      it glues an emoji together (a woman and a laptop make a technologist)
      and shapes Persian and Indic words. At the start or end of a text,
      next to a blank or next to another joiner it only hides, so it is
      refused there."""
    ch = text[i]
    if unicodedata.category(ch) == "Zs":
        return True
    if ch in JOINERS:
        return _visible(text[i - 1:i]) and _visible(text[i + 1:i + 2])
    return False


def _plain(text: str, words: bool) -> bool:
    """Is `text` free of anything that must not reach a terminal?"""
    return text.isprintable() or (words and all(
        ch.isprintable() or _word_character(text, i)
        for i, ch in enumerate(text)))


def printable(text, *, words: bool = False) -> str:
    """`text` as it is safe to put on a terminal. A recipe is somebody
    else's text, and connect prints a lot of it (the steps, the scopes, the
    URLs) right next to the lines that protect the person: the validation
    preview and the cross-domain warning. A character that drives the
    terminal - ESC (colours, "conceal", a window title), a carriage return
    or newline that forges a line, a bidirectional override, a zero-width
    or no-break space - is therefore shown as a visible escape (``\\x1b``,
    ``\\u202e``) instead of being sent. Everything printable, accented and
    CJK letters and emoji included, comes back unchanged.

    With ``words=True`` - the recipe's own sentences: its name, steps and
    scopes - a space of another width and a joiner between two visible
    characters come back unchanged too (see _word_character). Everything
    else that prints text of unknown shape (a file name, a path, a URL, an
    error) leaves it off, so nothing there can hide."""
    if not isinstance(text, str):
        text = str(text)
    if text.isprintable():
        return text
    out = []
    for i, ch in enumerate(text):
        if ch.isprintable() or (words and _word_character(text, i)):
            out.append(ch)
            continue
        code = ord(ch)
        if code < 0x100:
            out.append(f"\\x{code:02x}")
        elif code < 0x10000:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    return "".join(out)


def _first_invisible(value, where: str = "", words: bool = False,
                    top: bool = True) -> tuple[str, str] | None:
    """(where, how it looks) for the first string anywhere in `value` (a
    key, a value, inside lists and objects) that holds a control or
    invisible character, or None. Both parts are safe to print. `words`
    lets the recipe's own sentences (WORD_FIELDS, at the top of the recipe)
    use a space of another width and a joiner between visible characters."""
    if isinstance(value, str):
        if _plain(value, words):
            return None
        shown = printable(value)
        if len(shown) > 60:
            shown = shown[:57] + "..."
        return where, shown
    if isinstance(value, dict):
        for key, item in value.items():
            name = printable(key)
            found = (_first_invisible(key, f"name {name}")
                     or _first_invisible(
                         item, f"{where}.{name}" if where else name,
                         words or (top and key in WORD_FIELDS), top=False))
            if found:
                return found
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found = _first_invisible(item, f"{where}[{i}]", words, top=False)
            if found:
                return found
    return None


def _invisible_problem(data) -> str | None:
    """The sentence for a recipe that holds a control or invisible character
    somewhere, or None. Safe to print."""
    found = _first_invisible(data)
    if found is None:
        return None
    where, shown = found
    service = data.get("service") if isinstance(data, dict) else None
    who = (f"recipe '{printable(service)}'"
           if isinstance(service, str) and service else "recipe")
    return (f"{who} field {where or '(the recipe itself)'} contains a control "
            f"or invisible character ({shown}) - a recipe is plain text")


def fields(recipe: dict) -> list[dict]:
    """The values a recipe collects, in order: [{name, env_var, label,
    accept, detect, detect_confidence, pattern}]. A recipe without "fields"
    has one: "key", stored as its env_var.

    accept: the copy-and-go gate (documented shapes only, loose).
    detect: what `scan` looks for (a heuristic unless detect_confidence is
    "known"). "pattern" is the older single field: it fills both."""
    listed = recipe.get("fields")
    if not listed:
        return [{"name": DEFAULT_FIELD, "env_var": recipe["env_var"],
                 "label": "API key", "pattern": None, "accept": None,
                 "detect": None, "detect_confidence": "known", "capture_accept": None}]
    out = []
    for f in listed:
        accept = f.get("accept") or f.get("pattern")
        detect = f.get("detect") or f.get("accept") or f.get("pattern")
        if f.get("detect"):
            confidence = f.get("detect_confidence", "guess")
        else:
            confidence = f.get("detect_confidence", "known")
        out.append({"name": f["name"], "env_var": f["env_var"],
                    "label": f.get("label") or f["name"],
                    "pattern": accept, "accept": accept, "detect": detect,
                    "capture_accept": f.get("capture_accept"),
                    "detect_confidence": confidence})
    return out


def env_vars(recipe: dict) -> list[str]:
    """Every variable the recipe stores, in field order."""
    return [f["env_var"] for f in fields(recipe)]


def attachments(recipe: dict) -> list[tuple[str, str]]:
    """[(variable name, how it is attached)] for every stored value the check
    sends or uses: plain words, for the pop-ups and for `recipe approve`. The
    variable NAMES are shown, never a value."""
    v = recipe.get("validate") or {}
    auth = v.get("auth") or {}
    names = {f["name"]: f["env_var"] for f in fields(recipe)}
    kind = auth.get("type")

    def var(key: str, default: str = DEFAULT_FIELD) -> str:
        return names.get(auth.get(key, default), "?")
    if kind == "bearer":
        scheme = printable(auth.get("scheme") or "Bearer")
        return [(var("field"), f"as a {scheme} token in the Authorization header")]
    if kind == "header":
        return [(var("field"), f"in the {printable(auth.get('header'))} header")]
    if kind == "headers":
        out = []
        for header, template in (auth.get("headers") or {}).items():
            for ref in PLACEHOLDER_RE.findall(template):
                out.append((names.get(ref, "?"), f"in the {printable(header)} header"))
        return out
    if kind == "basic":
        out = []
        if "username_field" in auth:
            out.append((var("username_field"), "as the user name in a Basic sign-in header"))
        out.append((var("password_field"), "as the password in a Basic sign-in header"))
        return out
    if kind == "query":
        return [(var("field"), f"in the web address, as ?{printable(auth.get('param'))}=")]
    if kind == "oauth2_client_credentials":
        host = urllib.parse.urlsplit(str(auth.get("token_url", ""))).hostname or "its token address"
        return [(var("client_id_field", "client_id"), f"sent to {printable(host)} to get a sign-in token"),
                (var("client_secret_field", "client_secret"), f"sent to {printable(host)} to get a sign-in token")]
    if kind == "aws_sigv4":
        return [(var("access_key_field", "access_key_id"), "used to sign requests (not sent as it is)"),
                (var("secret_key_field", "secret_access_key"), "used to sign requests (not sent as it is)")]
    return [(name, "in a way this recipe does not say") for name in env_vars(recipe)]


def ago(seconds: float) -> str:
    """'3 days ago' for a number of seconds (never negative)."""
    s = max(0, int(seconds))
    for size, unit in ((86400 * 365, "year"), (86400 * 30, "month"), (86400, "day"),
                       (3600, "hour"), (60, "minute")):
        if s >= size:
            n = s // size
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    return "just now"


def origin_words(recipe: dict, now: float | None = None) -> str:
    """Where a recipe comes from, in a few words: 'built-in recipe', or 'recipe
    made by a person or program on this computer (not built in), changed 3
    days ago'. A recipe that is not built in is NEVER described as built in."""
    if recipe.get("_builtin") is True:
        return "built-in recipe that comes with stuntkey"
    import time
    when = recipe.get("_modified")
    age = (f", created or last changed {ago((time.time() if now is None else now) - when)}"
           if isinstance(when, (int, float)) else "")
    return f"recipe made by a person or program on this computer (not built in){age}"


def trust_summary(recipe: dict, now: float | None = None) -> str:
    """One sentence for a permission window: what the recipe is, which stored
    value it attaches and how. e.g. "Recipe: built-in recipe that comes with
    stuntkey. It attaches GITHUB_TOKEN as a Bearer token in the Authorization
    header."""
    parts = "; ".join(f"{printable(name)} {how}" for name, how in attachments(recipe))
    return f"Recipe: {origin_words(recipe, now)}. It attaches {parts or 'no stored value'}."


try:                                        # Python 3.11+
    import re._parser as _sre_parse
except ImportError:                          # pragma: no cover - 3.10
    import sre_parse as _sre_parse

MAX_REPEAT_COUNT = 1000


def regex_risk(pattern: str) -> str | None:
    """Why a regular expression could take very long on a crafted input
    (catastrophic backtracking), or None. Python's `re` cannot be given a
    time limit, so the shapes that blow up are refused up front: a repeat
    inside a repeat ((a+)+, (a|aa)*, (.*a){9}), a back-reference, and a huge
    repeat count. A plain gate such as ^sk-[A-Za-z0-9_-]{20,} is fine."""
    try:
        tree = _sre_parse.parse(pattern)
    except Exception:
        return "does not compile"

    def walk(items, inside: bool) -> str | None:
        for op, av in items:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                lo, hi, sub = av
                if hi != _sre_parse.MAXREPEAT and hi > MAX_REPEAT_COUNT:
                    return "has a repeat count that is too large"
                many = hi == _sre_parse.MAXREPEAT or hi > 1
                if inside and many:
                    return "repeats something that is itself repeated"
                found = walk(sub, inside or many)
            elif name == "SUBPATTERN":
                found = walk(av[-1], inside)
            elif name == "BRANCH":
                found = "has an either/or inside a repeat" if inside else next((r for r in (walk(b, inside) for b in av[1]) if r), None)
            elif name in ("ASSERT", "ASSERT_NOT"):
                found = walk(av[1], inside)
            elif name == "ATOMIC_GROUP":
                found = walk(av, inside)
            elif name in ("GROUPREF", "GROUPREF_EXISTS"):
                found = "uses a back-reference"
            else:
                found = None
            if found:
                return found
        return None
    return walk(tree, False)


def _check_fields(data: dict) -> None:
    listed = data.get("fields")
    if listed is None:
        return
    if not isinstance(listed, list) or not 1 <= len(listed) <= MAX_FIELDS:
        raise RecipeError(f"'fields' must be a list of 1 to {MAX_FIELDS} fields")
    names, envs = set(), set()
    for f in listed:
        if not isinstance(f, dict):
            raise RecipeError("each entry in 'fields' must be an object")
        name, env = f.get("name"), f.get("env_var")
        if not isinstance(name, str) or not FIELD_NAME_RE.match(name):
            raise RecipeError(f"field name must be lowercase letters, digits or '_': {name!r}")
        if not isinstance(env, str) or not ENV_VAR_RE.match(env):
            raise RecipeError(f"field '{name}' env_var is not a valid shell variable name: {env!r}")
        if name in names or env in envs:
            raise RecipeError(f"field '{name}' repeats a name or env_var")
        names.add(name)
        envs.add(env)
        label = f.get("label")
        if label is not None and not (isinstance(label, str) and label.strip()):
            raise RecipeError(f"field '{name}' label must be text")
        for pkey in ("pattern", "accept", "detect", "capture_accept"):
            pattern = f.get(pkey)
            if pattern is None:
                continue
            if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN:
                raise RecipeError(f"field '{name}' {pkey} must be a regular expression "
                                  f"of at most {MAX_PATTERN} characters")
            try:
                re.compile(pattern)
            except re.error as e:
                raise RecipeError(f"field '{name}' {pkey} does not compile: {e}") from None
            risk = regex_risk(pattern)
            if risk:
                raise RecipeError(f"field '{name}' {pkey} {risk}; write a simpler "
                                  f"pattern (a prefix and a character class, like "
                                  f"^sk-[A-Za-z0-9]{{20,}})")
        if f.get("detect_confidence", "guess") not in ("known", "guess"):
            raise RecipeError(f"field '{name}' detect_confidence must be 'known' or 'guess'")
    if data["env_var"] != listed[0]["env_var"]:
        raise RecipeError("env_var must be the first field's env_var")


def _need(auth: dict, key: str, what: str) -> str:
    value = auth.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RecipeError(f"auth.type '{auth['type']}' needs auth.{key} ({what})")
    return value


def _check_auth(auth: dict, known: set[str]) -> None:
    """Every field the auth names exists, and every field is used."""
    atype = auth["type"]
    used: set[str] = set()

    def field(key: str, default: str = DEFAULT_FIELD) -> None:
        name = auth.get(key, default)
        if not isinstance(name, str) or name not in known:
            raise RecipeError(f"auth.{key} names field {name!r}, which is not in 'fields'")
        used.add(name)

    if atype == "header":
        header = _need(auth, "header", "a header name")
        if not HEADER_NAME_RE.match(header):
            raise RecipeError(f"auth.header is not a header name: {header!r}")
        field("field")
    elif atype == "bearer":
        field("field")
    elif atype == "headers":
        headers = auth.get("headers")
        if not isinstance(headers, dict) or not headers:
            raise RecipeError("auth.type 'headers' needs auth.headers {name: \"{field}\"}")
        for name, tpl in headers.items():
            if not isinstance(name, str) or not HEADER_NAME_RE.match(name) or not isinstance(tpl, str):
                raise RecipeError(f"auth.headers entry {name!r} is not a header name and template")
            refs = PLACEHOLDER_RE.findall(tpl)
            if not refs:
                raise RecipeError(f"auth.headers[{name}] must hold a {{field}} placeholder")
            for ref in refs:
                if ref not in known:
                    raise RecipeError(f"auth.headers[{name}] names unknown field {ref!r}")
                used.add(ref)
    elif atype == "basic":
        if "username_field" in auth:
            field("username_field")
        field("password_field")
    elif atype == "query":
        param = _need(auth, "param", "the query parameter name")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", param):
            raise RecipeError(f"auth.param is not a plain parameter name: {param!r}")
        field("field")
    elif atype == "oauth2_client_credentials":
        _need(auth, "token_url", "the vendor's OAuth2 token endpoint")
        field("client_id_field", "client_id")
        field("client_secret_field", "client_secret")
        if auth.get("send", "basic") not in ("basic", "body"):
            raise RecipeError("auth.send must be 'basic' or 'body'")
        scope = auth.get("scope")
        if scope is not None and not isinstance(scope, str):
            raise RecipeError("auth.scope must be text")
        if not isinstance(auth.get("token_only", False), bool):
            raise RecipeError("auth.token_only must be true or false")
    elif atype == "aws_sigv4":
        for key in ("region", "service"):
            if not re.fullmatch(r"[a-z0-9-]{2,32}", str(auth.get(key, ""))):
                raise RecipeError(f"auth.type 'aws_sigv4' needs auth.{key} (e.g. us-east-1 / sts)")
        field("access_key_field", "access_key_id")
        field("secret_key_field", "secret_access_key")
        if "session_token_field" in auth:
            field("session_token_field")
    unused = known - used
    if unused:
        raise RecipeError(f"fields {sorted(unused)} are collected but never checked by the auth")


def _check_cli_token(data: dict) -> None:
    cli = data.get("cli_token")
    if cli is None:
        return
    if not isinstance(cli, dict) or set(cli) - {"login", "token"} or "token" not in cli:
        raise RecipeError("cli_token must be {\"login\": [...], \"token\": [...]}")
    for key, argv in cli.items():
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) and a for a in argv)):
            raise RecipeError(f"cli_token.{key} must be a list of arguments")
        if argv[0] not in CLI_PROGRAMS:
            raise RecipeError(f"cli_token may only run {', '.join(CLI_PROGRAMS)}")
    if data.get("fields") and len(data["fields"]) > 1:
        raise RecipeError("cli_token works for single-key recipes only")


REVOKE_METHODS = ("POST", "DELETE")
REVOKE_AUTH = ("bearer", "json_list")


def _check_revoke(data: dict) -> None:
    rv = data.get("revoke")
    if rv is None:
        return
    if not (isinstance(rv, dict) and rv and set(rv) <= {"api", "page", "steps"}
            and ("api" in rv or "page" in rv)):
        raise RecipeError("revoke must be {api?, page?, steps?} with api or page")
    page = rv.get("page")
    if page is not None and not (isinstance(page, str) and page.startswith("https://")):
        raise RecipeError("revoke.page must be an https:// link")
    steps = rv.get("steps")
    if steps is not None and not (isinstance(steps, list) and all(
            isinstance(x, str) and x.strip() for x in steps)):
        raise RecipeError("revoke.steps must be a list of text")
    api = rv.get("api")
    if api is None:
        return
    if not isinstance(api, dict) or set(api) - {"method", "url", "auth", "expect", "headers"}:
        raise RecipeError("revoke.api must be {method, url, auth, expect, headers?}")
    if len(fields(data)) != 1:
        raise RecipeError("revoke.api works for single-key recipes only")
    if api.get("method") not in REVOKE_METHODS:
        raise RecipeError(f"revoke.api.method must be one of {REVOKE_METHODS}")
    url = api.get("url")
    try:
        parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    except ValueError:
        parts = None
    # the key may only go where it already goes: never a new server
    if (parts is None or parts.scheme != "https" or not parts.hostname
            or parts.hostname.lower() not in _hosts(data)):
        raise RecipeError("revoke.api.url must be https:// on the validation host")
    auth = api.get("auth")
    if not (isinstance(auth, dict) and auth.get("type") in REVOKE_AUTH):
        raise RecipeError(f"revoke.api.auth.type must be one of {REVOKE_AUTH}")
    if auth["type"] == "json_list" and not (isinstance(auth.get("field"), str)
                                            and FIELD_NAME_RE.match(auth["field"])):
        raise RecipeError("revoke.api.auth json_list needs a field name")
    expect = api.get("expect")
    if not (isinstance(expect, list) and expect and all(
            isinstance(c, int) and 200 <= c <= 299 for c in expect)):
        raise RecipeError("revoke.api.expect must be a list of 2xx statuses")
    headers = api.get("headers")
    if headers is not None and not (isinstance(headers, dict) and all(
            isinstance(k, str) and HEADER_NAME_RE.match(k) and isinstance(v, str)
            and not set(v) & {"\r", "\n"} for k, v in headers.items())):
        raise RecipeError("revoke.api.headers must be a {name: value} object")


def _check_mint(data: dict) -> None:
    """"mint": {vendor, permissions, account}. Only Cloudflare, and the new key
    is checked at the recipe's validate.url, so that must be Cloudflare's API:
    a minted key may never be sent to another server."""
    m = data.get("mint")
    if m is None:
        return
    if not (isinstance(m, dict) and set(m) == {"vendor", "permissions", "account"}):
        raise RecipeError("mint must be {vendor, permissions, account}")
    if m["vendor"] != "cloudflare":
        raise RecipeError("mint.vendor must be 'cloudflare'")
    perms = m["permissions"]
    if not (isinstance(perms, list) and perms and all(
            isinstance(p, str) and 0 < len(p) <= 100 and _plain(p, True) for p in perms)):
        raise RecipeError("mint.permissions must be a list of permission names")
    if not (isinstance(m["account"], str) and re.fullmatch(r"[0-9a-f]{32}", m["account"])):
        raise RecipeError("mint.account must be a 32-character Cloudflare account id")
    if _hosts(data) != frozenset({"api.cloudflare.com"}) or len(fields(data)) != 1:
        raise RecipeError("a mint recipe must be a single key checked at api.cloudflare.com")


RESULTS = ("valid", "limited", "invalid")
STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"


def _check_verdict_rules(v: dict) -> None:
    """validate.limited and validate.body_rules."""
    limited = v.get("limited")
    if limited is not None:
        if not isinstance(limited, list) or not all(
                isinstance(x, dict) and isinstance(x.get("status"), int)
                and 100 <= x["status"] <= 599
                and isinstance(x.get("meaning"), str) and x["meaning"].strip()
                for x in limited):
            raise RecipeError("validate.limited must be a list of "
                              "{status, meaning}")
        for x in limited:
            if x["status"] in v["expect"]:
                raise RecipeError("validate.limited repeats an expected status")
    rules = v.get("body_rules")
    if rules is not None:
        if not isinstance(rules, list) or not all(
                isinstance(x, dict) and isinstance(x.get("status"), int)
                and isinstance(x.get("body_contains"), str) and x["body_contains"]
                and len(x["body_contains"]) <= 100
                and x.get("result") in RESULTS
                and isinstance(x.get("meaning", ""), str) for x in rules):
            raise RecipeError("validate.body_rules must be a list of {status, "
                              "body_contains, result valid|limited|invalid, meaning}")


def _check_extras(data: dict) -> None:
    lp = data.get("least_privilege")
    if lp is not None:
        if not (isinstance(lp, dict) and isinstance(lp.get("summary"), str)
                and lp["summary"].strip()
                and set(lp) <= {"summary", "url"}):
            raise RecipeError("least_privilege must be {summary, url?}")
        url = lp.get("url")
        if url is not None and not (isinstance(url, str)
                                    and url.startswith("https://")):
            raise RecipeError("least_privilege.url must be an https:// link")
    un = data.get("unverified")
    if un is not None and not (isinstance(un, list) and all(
            isinstance(x, str) and x for x in un)):
        raise RecipeError("unverified must be a list of text")
    # "untested": true - made by `stuntkey get <any site>`: the key is saved
    # without a check call, because nobody knows the site's API yet. It can
    # only make stuntkey send the key LESS, never somewhere new.
    if not isinstance(data.get("untested", False), bool):
        raise RecipeError("untested must be true or false")


def _check_allow_env(data: dict) -> None:
    """"allow_env": a recipe made on this computer may read a key from a .env
    file ONLY for the variables named here AND approved by the person
    (`stuntkey recipe approve`). Without it such a recipe reads only the
    keychain entries stored under its own service name. (Run after
    _check_fields, so env_vars() can be trusted.)"""
    allow = data.get("allow_env")
    if allow is not None:
        if not (isinstance(allow, list) and allow and all(
                isinstance(x, str) and ENV_VAR_RE.match(x) for x in allow)):
            raise RecipeError("allow_env must be a list of variable names")
        if not set(allow) <= set(env_vars(data)):
            raise RecipeError("allow_env may only name variables the recipe itself stores")


def validate_recipe(data: dict) -> dict:
    problem = _invisible_problem(data)
    if problem:
        # before anything else, so no later message can echo such a character
        raise RecipeError(problem)
    for field in REQUIRED:
        if field not in data or data[field] in (None, "", []):
            raise RecipeError(f"recipe missing required field: {field}")
    slug = data["service"]
    if not isinstance(slug, str) or not SLUG_RE.match(slug):
        raise RecipeError(
            f"recipe field 'service' must be a slug of lowercase letters, "
            f"digits, '-' or '_' (1-64 chars), got {slug!r}")
    reserved = device_name_problem(slug)
    if reserved:
        raise RecipeError(f"recipe field 'service': {reserved}")
    env_var = data["env_var"]
    if not isinstance(env_var, str) or not ENV_VAR_RE.match(env_var):
        raise RecipeError(
            f"recipe '{data['service']}' field 'env_var' is not a valid "
            f"shell variable name: {env_var!r} — refusing it so a recipe "
            f"can never inject extra lines into .env")
    if not isinstance(data["steps"], list) or not data["steps"]:
        raise RecipeError("recipe 'steps' must be a non-empty list")
    v = data["validate"]
    for field in VALIDATE_REQUIRED:
        if field not in v:
            raise RecipeError(f"validate missing required field: {field}")
    method = v["method"]
    if (isinstance(method, str) and method.upper() == "POST"
            and v.get("auth", {}).get("type") == "aws_sigv4"
            and v.get("auth", {}).get("service") == "sts"
            and v.get("body") == STS_BODY):
        pass            # AWS documents GetCallerIdentity as a POST; it reads only
    elif not isinstance(method, str) or method.upper() not in ALLOWED_METHODS:
        raise RecipeError(
            f"validate.method must be GET or HEAD - a validation call only "
            f"reads - got {printable(method)!r}")
    auth = v["auth"]
    if auth.get("type") not in AUTH_TYPES:
        raise RecipeError(f"auth.type must be one of {AUTH_TYPES}")
    if auth["type"] == "header" and not auth.get("header"):
        raise RecipeError("auth.type 'header' needs auth.header name")
    if not isinstance(v["expect"], list) or not v["expect"]:
        raise RecipeError("validate.expect must be a non-empty status list")
    for field in ("expect", "reject"):
        codes = v.get(field, [])
        if codes is not None and not (isinstance(codes, list) and all(
                isinstance(c, int) and 100 <= c <= 599 for c in codes)):
            raise RecipeError(f"validate.{field} must be a list of HTTP statuses")
    headers = v.get("headers")
    if headers is not None and not (isinstance(headers, dict) and all(
            isinstance(k, str) and isinstance(val, str)
            for k, val in headers.items())):
        raise RecipeError("validate.headers must be a {name: value} object")
    for field in ("scheme", "username"):
        if field in auth and (not isinstance(auth[field], str)
                              or not auth[field].strip()
                              or any(ch in auth[field] for ch in " \r\n:")):
            raise RecipeError(f"auth.{field} must be a single token")
    hosts = v.get("trusted_hosts")
    if hosts is not None and not (isinstance(hosts, list) and all(
            isinstance(h, str) and h for h in hosts)):
        raise RecipeError("validate.trusted_hosts must be a list of hostnames")
    _check_verdict_rules(v)
    _check_extras(data)
    _check_fields(data)
    _check_allow_env(data)
    _check_auth(auth, {f["name"] for f in fields(data)})
    _check_cli_token(data)
    _check_revoke(data)
    _check_mint(data)
    # A pasted key must never travel in cleartext: the mint page, the
    # validation endpoint and any token endpoint must all be HTTPS.
    # Exception: a "local": true recipe (a router on this computer, such as
    # freellmapi) may use http, but only to a loopback address, so the key
    # never leaves the machine.
    local = data.get("local", False)
    if not isinstance(local, bool):
        raise RecipeError("local must be true or false")
    urls = [("key_url", data["key_url"]), ("validate.url", v["url"])]
    if auth["type"] == "oauth2_client_credentials":
        urls.append(("validate.auth.token_url", auth["token_url"]))
    for label, url in urls:
        try:
            scheme = urllib.parse.urlsplit(url).scheme.lower()
        except ValueError:
            # urlsplit refuses some malformed addresses ("https://[bad/").
            # Say so as a recipe problem, not as a traceback out of
            # `stuntkey add` or a whole broken catalog.
            raise RecipeError(
                f"{label} is not a valid URL: {url}") from None
        if local:
            if (scheme not in ("http", "https")
                    or urllib.parse.urlsplit(url).hostname not in LOOPBACK_HOSTS):
                raise RecipeError(
                    f"{label} of a local recipe must point at this computer "
                    f"(127.0.0.1, localhost or [::1]). Offending URL: {url}")
        elif scheme != "https":
            raise RecipeError(
                f"{label} must use https:// — a key sent there would travel "
                f"in cleartext. Offending URL: {url}")
    return data


_LOAD_WARNINGS: list = []


def _warn(text: str) -> None:
    """Say it on stderr as before AND remember it for `doctor`."""
    _LOAD_WARNINGS.append(text)
    try:
        sys.stderr.write(text + "\n")
    except (OSError, ValueError):
        pass


def load_warnings() -> list:
    """Plain sentences about recipes the LAST load_recipes() skipped or
    ignored (empty when all loaded). For `doctor` to show."""
    return list(_LOAD_WARNINGS)


def _read_one(directory: str, fname: str, builtin: bool = False,
              user: bool = False, previous: dict | None = None) -> dict | None:
    """One recipe file as a recipe dict, or None (with a warning) when it is
    bad. `user` is the person's own recipe folder (~/.stuntkey/recipes): what
    is in there was made on this computer, by a person or by a program, so the
    recipe is marked "_needs_approval" and carries the fingerprint (sha256) of
    the very bytes that were read, which is what an approval is tied to."""
    import hashlib
    path = os.path.join(directory, fname)
    try:
        with open(path, "rb") as f:
            raw = f.read()
        modified = os.path.getmtime(path)
        # utf-8-sig: Windows PowerShell 5.1 and older Notepad start a UTF-8
        # file with a byte-order mark, which json.load refuses ("Unexpected
        # UTF-8 BOM"). This drops one at the very start and nothing else.
        data = json.loads(raw.decode("utf-8-sig"))
        validate_recipe(data)
    except (json.JSONDecodeError, RecipeError, OSError, UnicodeDecodeError,
            AttributeError, TypeError, RecursionError) as e:
        _warn(f"[stuntkey] skipping bad recipe "
              f"{printable(fname)}: {printable(e)}")
        return None
    # Names starting with "_" are StuntKey's own marks (_builtin, _needs_approval,
    # _sha256 ...). A file can never bring its own: "_needs_approval": false in a
    # planted recipe must not switch the check off.
    data = {k: v for k, v in data.items() if not str(k).startswith("_")}
    if user and fname[:-5] != data["service"]:
        # The approval is kept per service and the file is found by that
        # name: a file whose name says something else is not one StuntKey wrote.
        _warn(f"[stuntkey] skipping recipe {printable(fname)}: its file name must "
              f"be {printable(data['service'])}.json, the service it describes")
        return None
    # Only recipes shipped INSIDE the package may vouch for a
    # validation host under another domain (trusted_hosts): they were
    # reviewed with the code. A user-dir recipe never gets that.
    data["_builtin"] = builtin
    data["_file"] = path
    data["_sha256"] = hashlib.sha256(raw).hexdigest()
    data["_modified"] = modified
    if user:
        data["_needs_approval"] = True
    data["_overrides_builtin"] = bool(previous and previous.get("_builtin")
                                      and not builtin)
    return data


def _load_dir(directory: str, recipes: dict[str, dict],
              builtin: bool = False, user: bool = False) -> None:
    """Read every recipe file in `directory` into `recipes` (see _read_one)."""
    if not os.path.isdir(directory):
        return
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".json"):
            continue
        data = _read_one(directory, fname, builtin, user,
                         recipes.get(fname[:-5]))
        if data is None:
            continue
        previous = recipes.get(data["service"])
        data["_overrides_builtin"] = bool(previous and previous.get("_builtin")
                                          and not builtin)
        recipes[data["service"]] = data


def load_user_recipe(service: str):
    """(recipe, problem) for the one file ~/.stuntkey/recipes/<service>.json,
    read as a user recipe (marked "_needs_approval", fingerprinted), and
    checked like load_recipes() checks it against the built-in ones. The
    problem is a plain sentence, or None."""
    if not isinstance(service, str) or not SLUG_RE.match(service):
        return None, "that is not a service name (lowercase letters, digits, - and _)"
    directory = user_recipes_dir()
    fname = f"{service}.json"
    if not os.path.isfile(os.path.join(directory, fname)):
        return None, f"there is no recipe of yours called '{service}' ({os.path.join(directory, fname)})"
    _LOAD_WARNINGS.clear()
    recipe = _read_one(directory, fname, user=True)
    if recipe is None:
        return None, "; ".join(_LOAD_WARNINGS) or f"the recipe '{service}' cannot be read"
    builtins: dict = {}
    _load_dir(RECIPES_DIR, builtins, builtin=True)
    problem = merge_problem(service, recipe, builtins)
    if problem:
        return None, problem
    if service in builtins:
        recipe["_builtin_env_vars"] = env_vars(builtins[service])
        recipe["_overrides_builtin"] = True
    return recipe, None


def _is_builtin_dir(directory: str) -> bool:
    return os.path.realpath(directory) == os.path.realpath(RECIPES_DIR)


def _is_user_dir(directory: str) -> bool:
    return os.path.normcase(os.path.realpath(directory)) == os.path.normcase(
        os.path.realpath(user_recipes_dir()))


def hosts_of(recipe: dict) -> frozenset:
    """Every server a recipe can send its key to (public name of _hosts)."""
    return _hosts(recipe)


def _hosts(recipe: dict) -> frozenset:
    """Every server a recipe can send its key to."""
    import urllib.parse
    v = recipe.get("validate") or {}
    out = set()
    for u in [v.get("url"), v.get("token_url"), (v.get("auth") or {}).get("token_url")]:
        if isinstance(u, str) and u:
            h = urllib.parse.urlsplit(u).hostname
            if h:
                out.add(h.lower())
    for h in v.get("trusted_hosts") or []:
        if isinstance(h, str):
            out.add(h.lower())
    return frozenset(out)


def _merge_user_recipes(recipes: dict, user: dict) -> None:
    """Put user recipes on top of the built-in ones - but never let one send
    a built-in service's key to a different server. A planted
    ~/.stuntkey/recipes/github.json (or a new recipe that reuses the
    OPENAI_API_KEY variable name) could otherwise steal the key."""
    for slug, r in user.items():
        problem = merge_problem(slug, r, recipes)
        if problem:
            _warn(problem)
            continue
        if slug in recipes and recipes[slug].get("_builtin"):
            # the one variable list a same-name override may still read from a
            # .env file: what the built-in recipe already reads there
            r["_builtin_env_vars"] = env_vars(recipes[slug])
        r["_overrides_builtin"] = slug in recipes and bool(recipes[slug].get("_builtin"))
        recipes[slug] = r


def merge_problem(slug: str, r: dict, recipes: dict) -> str | None:
    """Why a user recipe `r` may not sit beside the built-in ones in `recipes`
    (it would send a built-in key to another server), as a plain sentence, or
    None when it may."""
    builtin_hosts = {s: _hosts(b) for s, b in recipes.items() if b.get("_builtin")}
    builtin_vars: dict = {}
    for s, b in recipes.items():
        if b.get("_builtin"):
            for var in env_vars(b):
                builtin_vars.setdefault(var, builtin_hosts[s])
    if slug in builtin_hosts and _hosts(r) != builtin_hosts[slug]:
        return (f"stuntkey: ignored your recipe '{slug}': it would send the "
                f"built-in {slug} key to a different server. Use another "
                "name for it.")
    clash = [v for v in env_vars(r) if v in builtin_vars and builtin_vars[v] != _hosts(r)
             and slug not in builtin_hosts]
    if clash:
        return (f"stuntkey: ignored your recipe '{slug}': it reuses the key "
                f"name {clash[0]} of a built-in service but talks to a "
                "different server.")
    return None


def load_recipes(directory: str | None = None) -> dict[str, dict]:
    """Load all valid recipes. Invalid files are skipped with a warning on
    stderr - one bad recipe must never break the whole catalog.

    With `directory`, only that directory is read. Without it, the
    built-in recipes are loaded first and the user directory
    (~/.stuntkey/recipes) on top, so a user recipe overrides a
    built-in one with the same slug."""
    recipes: dict[str, dict] = {}
    _LOAD_WARNINGS.clear()
    if directory is not None:
        _load_dir(directory, recipes, builtin=_is_builtin_dir(directory),
                  user=_is_user_dir(directory))
        return recipes
    _load_dir(RECIPES_DIR, recipes, builtin=True)
    user: dict[str, dict] = {}
    _load_dir(user_recipes_dir(), user, user=True)
    _merge_user_recipes(recipes, user)
    return recipes


def save_recipe(data: dict, directory: str | None = None) -> str:
    """Write a recipe as <slug>.json. Default destination is the user
    recipes dir, never the installed package."""
    validate_recipe(data)
    data = {k: v for k, v in data.items() if not k.startswith("_")}
    directory = directory or user_recipes_dir()
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{data['service']}.json")
    # a temporary file in the same folder, then a rename: a crash or a full disk
    # leaves the old recipe whole, never half of a new one
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=f".{data['service']}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(data, indent=2) + "\n")
            f.flush()
            os.fsync(f.fileno())
        # (no import of store: store imports this module; retry while an
        # antivirus scanner briefly holds the file)
        import time
        for attempt in range(40):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 39:
                    raise
                time.sleep(0.05)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path
