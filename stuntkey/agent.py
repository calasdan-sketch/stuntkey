"""What an AI agent may ask for, and the only things it gets back.

The handshake: the agent says WHICH key it needs; a person gets the key from
the vendor into the project using `stuntkey connect`. The agent never
sees, reads or writes a key, so a key is never in its chat or its logs.

Every answer here is built from a short fixed list of fields - a service
name, a variable NAME, a status word, a sentence for the human - and is then
passed through guard_text(), which blanks any secret value this process can
reach (a variable in its environment, a value in the project's .env), in its
raw form and the common re-writings (redact.py). It is two locks: the answer
is never built from a value, and if one ever got in, it would be removed.
"""

from __future__ import annotations

import json
import os
import time

from . import capture as capture_mod
from . import clipboard as clipboard_mod
from . import detect as detect_mod
from . import manifest as manifest_mod
from . import presence as presence_mod
from . import recipes as recipes_mod
from . import redact as redact_mod
from . import scan as scan_mod
from . import store as store_mod

MAX_SERVICES = 100
OPEN_COOLDOWN = 30.0         # seconds between two openings of one key page
_LAST_OPEN: dict[str, float] = {}
MAX_OPENS_PER_MINUTE = 3     # across all services: an agent cannot flood the browser
_OPEN_TIMES: list[float] = []
STATUSES = ("present", "missing", "unknown")
AGENT_RULE = ("Do not ask the person to paste a key into chat, and do not read or "
              "write .env files or any file holding keys. Ask the person to run "
              "the command below in their own terminal; the key goes from the "
              "vendor page straight to the project without passing through you.")


CAPTURE_RULES = (
    "Never look at the key. Do not use any tool that returns page content, the DOM, an "
    "accessibility tree, text or a screenshot of the page area that shows the key. Click the "
    "vendor's own Copy button only; stuntkey takes the key from the clipboard.",
    "Never type, paste or send the key anywhere; you do not need it.",
    "Never enter a password, a 2FA code or solve a CAPTCHA. If the page asks for a login, "
    "2FA, a CAPTCHA or a password prompt (for example GitHub's sudo mode), stop and ask the "
    "person to do that step in the browser, then continue.",
    "If you have no browser tool that can click, stop and use the human route: ask the "
    "person to run `stuntkey connect <service>` in their own terminal.",
    "Choose the smallest permissions that work, one project or repository only, and a "
    "short expiry (30 to 90 days).",
    "Do not copy anything else while capture is armed: the next key-shaped copy is taken.",
)


def browser_steps(recipe: dict) -> dict:
    """What the agent does in the browser, from the recipe (plain text only)."""
    steps = [recipes_mod.printable(x, words=True) for x in recipe.get("steps", [])]
    out = {"open": recipe["key_url"], "steps": steps}
    least = recipe.get("least_privilege")
    if isinstance(least, dict) and least.get("summary"):
        out["least_privilege"] = recipes_mod.printable(least["summary"], words=True)
    if recipe.get("scopes"):
        out["scopes"] = [recipes_mod.printable(x) for x in recipe["scopes"]]
    return out


AGENT_RULE_CAPTURE = ("Do not ask the person to paste a key into chat, and do not read or "
                      "write .env files or any file holding keys.")


def _secret_like(name: str, value: str) -> bool:
    """Only a value that is probably a secret is blanked from an answer: its
    name says so, or it is a long key-shaped string. An ordinary setting
    (NODE_ENV=production, a port, a URL) is left alone, or words in the
    answer would turn into [REDACTED]."""
    if scan_mod.NOT_SECRET_NAME_RE.search(name):
        return False
    if scan_mod.SECRET_NAME_RE.search(name) or scan_mod.PASSWORD_NAME_RE.search(name):
        return True
    return clipboard_mod.looks_like(value, None)


def secrets_in_reach(catalog: dict, cwd: str | None = None, environ=None) -> list[str]:
    """Secret-looking values this process can reach: the catalog's variables in
    its environment, and every value in the project's .env (not the keychain:
    reading that can pop an unlock dialog). Only used to blank them out."""
    environ = os.environ if environ is None else environ
    found: list[str] = []
    for recipe in catalog.values():
        for var in recipes_mod.env_vars(recipe):
            value = environ.get(var)
            if value and len(value) >= redact_mod.MIN_LENGTH:
                found.append(value)
    cwd = cwd or os.getcwd()
    path = os.path.join(cwd, ".env")
    try:
        store_mod.refuse_link(path)
        if os.path.isfile(path):
            for name, value in list(store_mod.load_env(path).items())[:200]:
                if len(value) >= redact_mod.MIN_LENGTH and _secret_like(name, value):
                    found.append(value)
    except (OSError, ValueError):
        pass
    return found


def _scrub_json(value, scrub):
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, list):
        return [_scrub_json(v, scrub) for v in value]
    if isinstance(value, dict):
        return {k: _scrub_json(v, scrub) for k, v in value.items()}      # keys are kept as they are
    return value


def guard_text(text: str, catalog: dict, cwd: str | None = None, environ=None) -> str:
    """`text` with every reachable secret value (and its common re-writings)
    replaced by [REDACTED]. When the text is JSON only the string VALUES are
    scrubbed - never the member names - and it stays valid JSON."""
    values = secrets_in_reach(catalog, cwd, environ)
    if not values:
        return text
    red = redact_mod.Redactor(values)
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return red.text(text)
    if not isinstance(data, (dict, list)):
        return red.text(text)
    indent = 2 if "\n" in text.strip() else None
    return json.dumps(_scrub_json(data, red.text), indent=indent)


def clean_slug(service) -> str | None:
    """The service name if it is a plain slug, else None. An argument that is
    not one is never echoed back (it could be a key pasted by mistake)."""
    return service if isinstance(service, str) and recipes_mod.SLUG_RE.match(service) else None


def _bad_service(catalog: dict) -> dict:
    return {"error": "service must be a short name from list_services, like 'stripe'",
            "isError": True}


def _status(variables, env_file: str, store: str) -> str:
    if store == "keychain":
        return "unknown"        # not checked from here: asking the keychain can prompt the person
    have = presence_mod.env_names(env_file)
    return "present" if all(v in have for v in variables) else "missing"


def _project_manifest(root: str):
    path = manifest_mod.path_in(root)
    if not os.path.isfile(path):
        return None
    try:
        return manifest_mod.load(path)
    except manifest_mod.ManifestError:
        return None


def request_connect(service, catalog: dict, open_key_page: bool = False,
                    opener=None, cwd: str | None = None) -> dict:
    """The agent asks for a key. Returns only {service, env_var(s), status,
    instructions}. `open_key_page` opens the vendor's key page in the
    person's own browser (nothing else is started)."""
    slug = clean_slug(service)
    recipe = catalog.get(slug) if slug else None
    if recipe is None:
        return {"error": "no such service. Call list_services for the names I know.",
                "isError": True}
    root = manifest_mod.project_root(cwd)
    manifest = _project_manifest(root)
    store = "env"
    env_file = os.path.join(root, ".env")
    if manifest:
        try:
            env_file = manifest_mod.env_file_in(root, manifest)
        except manifest_mod.ManifestError:
            return {"error": "stuntkey.json has an env_file that is not allowed; "
                             "ask the person to fix it", "isError": True}
        for item in manifest["services"]:
            if item["service"] == slug:
                store = item.get("store", "env")
    variables = recipes_mod.env_vars(recipe)
    status = _status(variables, env_file, store)
    out = {"service": slug, "env_var": recipe["env_var"], "env_vars": variables,
           "status": status}
    if status == "present":
        out["instructions"] = (f"{recipe['display']} is already set up. Use the variable "
                               f"{recipe['env_var']} from the environment; do not read its value.")
        return out
    out["instructions"] = (
        f"Preferred: call capture_key with service={slug} (the person must have allowed it "
        f"once with `stuntkey allow-agent {slug}`; capture_key tells you if not). Then "
        f"you drive the browser steps below and click Copy; stuntkey takes the key from "
        f"the clipboard, tests and stores it as {recipe['env_var']} and tells you only "
        f"that it is stored. Only if capture_key says it is unavailable (no clipboard "
        f"access, headless), ask the person to run, in their own terminal: "
        f"stuntkey connect {slug}{' --store keychain' if store == 'keychain' else ''}. "
        f"Once it is stored, ask the person to start the program with "
        f"`stuntkey run {slug} -- <command>`; do not run it with the key yourself, and "
        f"do not print or transform the variable. " + AGENT_RULE_CAPTURE)
    out["browser"] = browser_steps(recipe)
    out["rules"] = list(CAPTURE_RULES)
    out["key_page"] = recipe["key_url"]
    if open_key_page:
        if opener is None:
            import webbrowser
            opener = webbrowser.open
        now = time.monotonic()
        _OPEN_TIMES[:] = [t for t in _OPEN_TIMES if now - t < 60.0]
        if now - _LAST_OPEN.get(slug, -1e9) < OPEN_COOLDOWN:
            out["opened_key_page"] = False      # an agent cannot make tabs pile up
            out["note"] = "the key page was opened a moment ago"
        elif len(_OPEN_TIMES) >= MAX_OPENS_PER_MINUTE:
            out["opened_key_page"] = False
            out["note"] = "too many key pages were opened in the last minute"
        else:
            _LAST_OPEN[slug] = now
            _OPEN_TIMES.append(now)
            try:
                opener(recipe["key_url"])
                out["opened_key_page"] = True
            except Exception:
                out["opened_key_page"] = False
    return out


def needs_keys(project, catalog: dict, cwd: str | None = None) -> dict:
    """Which keys does this project use, and which are not stored yet? Reads
    variable NAMES from stuntkey.json, .env.example-style templates and
    source code (never a real .env's contents), and only checks whether a
    value exists."""
    root = cwd or os.getcwd()
    if project not in (None, ""):
        if not isinstance(project, str) or "\x00" in project:
            return {"error": "project must be a folder path", "isError": True}
        root = os.path.realpath(os.path.join(cwd or os.getcwd(), project))
        here = os.path.realpath(cwd or os.getcwd())
        top = manifest_mod._git_root(here) or here
        if os.path.commonpath([top, root]) != top:
            return {"error": "project must be the folder you are working in, or a folder "
                             "inside it", "isError": True}
    if not os.path.isdir(root):
        return {"error": "that folder does not exist", "isError": True}
    manifest = _project_manifest(root)
    try:
        env_file = manifest_mod.env_file_in(root, manifest)
    except manifest_mod.ManifestError:
        return {"error": "stuntkey.json has an env_file that is not allowed; "
                         "ask the person to fix it", "isError": True}
    wanted: dict[str, dict] = {}
    for item in (manifest or {}).get("services", []):
        recipe = catalog.get(item["service"])
        wanted[item["service"]] = {
            "service": item["service"],
            "env_vars": manifest_mod.service_vars(item, recipe),
            "store": item.get("store", "env")}
    for found in detect_mod.detect(root, catalog)[0]:
        wanted.setdefault(found["service"], dict(found, store="env"))
    services = []
    for slug in sorted(wanted)[:MAX_SERVICES]:
        info = wanted[slug]
        services.append({"service": slug, "env_vars": info["env_vars"],
                         "status": _status(info["env_vars"], env_file, info["store"])})
    missing = [s["service"] for s in services if s["status"] == "missing"]
    out = {"services": services, "missing": missing,
           "source": "stuntkey.json" if manifest else "variable names found in the project"}
    if missing:
        out["instructions"] = (
            "Ask the person to run, in their own terminal: stuntkey setup "
            "(or stuntkey connect <service> for one). " + AGENT_RULE)
    else:
        out["instructions"] = "Nothing is missing."
    return out


def as_text(payload: dict, catalog: dict, cwd: str | None = None) -> str:
    """The JSON text of an answer, with reachable secrets blanked."""
    return guard_text(json.dumps(payload), catalog, cwd)


CAPTURE_ACTIONS = ("start", "status", "cancel")


def _truthy(value) -> bool:
    """A real boolean, or the words a client may send for one: the string
    "false" is False (bool("false") is True)."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value == 1)


def capture_key(args: dict, catalog: dict, cwd: str | None = None, manager=None) -> dict:
    """The agent-driven capture (capture.py, experimental). `action`: start
    (default), status or cancel. Returns state words and names only - never a
    value."""
    manager = manager or capture_mod.default_manager()
    action = args.get("action") or "start"
    if action not in CAPTURE_ACTIONS:
        return {"error": "action must be start, status or cancel", "isError": True}
    if action == "status":
        return manager.status(args.get("wait_seconds"))
    if action == "cancel":
        return manager.cancel()
    slug = clean_slug(args.get("service"))
    recipe = catalog.get(slug) if slug else None
    if recipe is None:
        return {"error": "action=start needs a service from list_services, like 'github'.",
                "isError": True}
    out = manager.start(slug, recipe, cwd, args.get("timeout_seconds"),
                        _truthy(args.get("replace")))
    if out.get("state") == "waiting":
        out["browser"] = browser_steps(recipe)
        out["rules"] = list(CAPTURE_RULES)
    return out
