"""The guided connect flow: steps -> hidden paste -> validate -> store.

Nothing in this module ever prints or logs the key. The key lives in
three places only: the user's clipboard, this function's local variable,
and the destination file.
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import shutil
import subprocess
import sys
import urllib.parse
import webbrowser

from . import clipboard as clipboard_mod
from . import doctor as doctor_mod
from . import procs
from . import safeprompt
from . import store as store_mod
from . import validate as validate_mod
from .recipes import DEFAULT_FIELD, fields as recipe_fields, printable

OVERRIDE_NOTE = "(your recipe, replaces the built-in)"
MAX_ATTEMPTS = 3
# Typed confirmation required when the validation URL is on a different
# domain than the key page. Not case-sensitive, but it must be the whole
# word — Enter alone or "y" aborts.
CONFIRM_WORD = "yes"

# Whose host is it? The "registrable domain" is the name one party registers:
# api.example.co.uk and dashboard.example.co.uk are both example.co.uk (one
# owner); a.co.uk and b.co.uk are two, and so are a.github.io and b.github.io,
# because a hosting platform hands a sub-domain to anyone - evil.github.io is
# NOT trusted by good.github.io.
#
# The three tables below (PUBLIC_SUFFIXES, GENERIC_SECOND_LEVEL,
# PER_HOST_DOMAINS) are a COMPACT SNAPSHOT, not the Public Suffix List
# (publicsuffix.org: thousands of rules, changed every week). A registry or
# platform they do not list is treated as an ordinary domain.

# Multi-label public suffixes under which the NEXT label is the registrant.
# Country registries that GENERIC_SECOND_LEVEL below also catches are listed
# anyway; the platforms are the names under which anyone can open a
# sub-domain. (wordpress.com, railway.app, glitch.me and surge.sh are not on
# the Public Suffix List, but their sub-domains are customers' too.)
PUBLIC_SUFFIXES = frozenset({
    # country second-level registries
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "web.za",
    "co.in", "net.in", "org.in", "firm.in",
    "co.kr", "or.kr", "ne.kr",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "org.tw", "idv.tw",
    "com.hk", "org.hk", "edu.hk",
    "com.sg", "org.sg", "edu.sg",
    "com.mx", "org.mx",
    "com.ar", "org.ar",
    "com.tr", "org.tr",
    "co.id", "or.id", "web.id",
    "co.il", "org.il",
    "com.pl", "net.pl",
    "co.th", "in.th",
    "com.my", "org.my",
    "com.ph", "org.ph",
    "com.vn", "net.vn",
    "com.ua", "net.ua",
    "com.ru", "net.ru", "org.ru",
    "co.ke", "or.ke",
    "com.ng", "org.ng",
    "com.eg",
    "com.sa",
    "com.pk",
    "com.bd",
    "com.pe", "com.co", "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
    "com.gt", "com.do",
    # hosting platforms: every sub-domain is a different customer
    "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app",
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "appspot.com",
    "azurewebsites.net", "cloudfront.net", "onrender.com",
    "fly.dev", "railway.app", "ngrok.io", "ngrok.app", "ngrok-free.app",
    "trycloudflare.com", "repl.co", "replit.app", "glitch.me", "surge.sh",
    "now.sh", "deno.dev", "supabase.co",
    # more platforms: site builders, shops, blogs
    "blogspot.com", "wordpress.com", "myshopify.com", "wixsite.com",
    "webflow.io", "notion.site", "carrd.co", "bubbleapps.io", "framer.app",
    "framer.website", "lovable.app", "lovableproject.com", "bolt.host",
    # more platforms: functions, apps, containers, storage
    "cloudfunctions.net", "azurestaticapps.net", "azureedge.net",
    "cloudapp.net", "trafficmanager.net", "azure-api.net",
    "blob.core.windows.net", "elasticbeanstalk.com", "ondigitalocean.app",
    "githubusercontent.com", "r2.dev",
    # more platforms: notebooks, tunnels, hosted demos and docs
    "vercel.dev", "csb.app", "pythonanywhere.com", "ngrok.dev",
    "ngrok-free.dev", "replit.dev", "hf.space", "streamlit.app",
    "readthedocs.io", "repl.run", "duckdns.org", "ts.net", "bitbucket.io",
    "gitbook.io", "codeberg.page", "streamlitapp.com",
    # more platforms: app and backend builders, previews
    "amplifyapp.com", "azurefd.net", "convex.app", "convex.cloud",
    "convex.site", "expo.app", "flutterflow.app", "hasura.app", "val.run",
    "vusercontent.net", "v0.build", "windsurf.app", "deno.net", "lovable.run",
    "vercel.run", "zeabur.app", "leapcell.app",
})

# Country registries as a rule: <one of these>.<two-letter country code> is a
# public suffix (co.uk, com.au, com.gr, gob.mx, ne.jp ...). Registries with
# other structures (info.pl, ...) are not recognised; see PUBLIC_SUFFIXES.
GENERIC_SECOND_LEVEL = frozenset({
    "co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob",
    "nom", "mil", "sch", "ltd", "plc",
})

# Domains under which EVERY host is a different customer's, at any depth (the
# customer's name sits in bucket.s3.<region>.amazonaws.com and in
# svc-1.a.run.app alike): below one of these a host is its own owner.
PER_HOST_DOMAINS = frozenset({
    "amazonaws.com", "amazonaws.com.cn", "on.aws", "awsapprunner.com",
    "run.app", "r.appspot.com", "gateway.dev", "hosted.app",
    "azurecontainer.io", "oraclecloudapps.com", "northflank.app", "code.run",
    "digitaloceanspaces.com", "linodeobjects.com", "vultrobjects.com",
})


def _print_steps(recipe: dict, out=None, opens_browser: bool = True) -> None:
    """The recipe's own words. Every one goes through printable(): a recipe
    is somebody else's text and must not be able to drive the terminal (hide
    the validation preview that follows, forge a line, retitle the window).
    Its name, steps and scopes are sentences (words=True); the URL is not.
    `opens_browser` says whether the key page is opened for the person (it is
    not with --no-browser: then the header says to open it themselves)."""
    out = out or sys.stdout
    where = ("(the key page opens in your browser)" if opens_browser
             else "(open the key page yourself - the address is below)")
    out.write(f"\n  Connect {printable(recipe['display'], words=True)}  {where}\n\n")
    for i, step in enumerate(recipe["steps"], 1):
        out.write(f"    {i}. {printable(step, words=True)}\n")
    if recipe.get("scopes"):
        scopes = ", ".join(printable(s, words=True) for s in recipe["scopes"])
        out.write(f"\n  Select these scopes: {scopes}\n")
    least = recipe.get("least_privilege")
    if least:
        out.write(f"\n  Least privilege: {printable(least['summary'], words=True)}\n")
        if least.get("url"):
            out.write(f"    ({printable(least['url'])})\n")
    if recipe.get("unverified"):
        # The field names (validate.url ...) are deliberately not shown: they
        # mean nothing to a person who is not a programmer.
        out.write("\n  I could not check this site's key test settings. "
                  "If the screen looks different, trust the screen.\n")
    out.write(f"\n  Key page: {printable(recipe['key_url'])}\n\n")
    out.flush()


def render_validation_preview(recipe: dict, out=None) -> None:
    """Print exactly where the key will be sent for validation — the HTTP
    method and the full URL. Shown BEFORE the key is ever asked for, so a
    poisoned recipe can't turn `stuntkey connect` into a key harvest."""
    out = out or sys.stdout
    v = recipe["validate"]
    if recipe.get("untested"):
        out.write(f"\n  This key will NOT be tested: stuntkey does not know this site's "
                  f"API yet, so nothing is sent now.\n"
                  f"  Later calls go only to {printable(_host(v['url']))}.\n")
        out.flush()
        return
    auth = v.get("auth", {})
    method = printable(str(v.get("method", "GET")).upper())
    if auth.get("type") == "oauth2_client_credentials":
        out.write(f"\n  This key will be validated with: POST "
                  f"{printable(auth['token_url'])}  (exchanged for a short-lived token)\n")
        if not auth.get("token_only"):
            out.write(f"    then {method} {printable(v['url'])}  (with that token)\n")
    else:
        out.write(f"\n  This key will be validated with: {method} "
                  f"{printable(v['url'])}\n")
    out.flush()


def destinations(recipe: dict) -> list[str]:
    """Every URL the credentials are sent to while checking them."""
    v = recipe["validate"]
    auth = v.get("auth", {})
    urls = []
    if auth.get("type") == "oauth2_client_credentials":
        urls.append(auth["token_url"])
        if auth.get("token_only"):
            return urls
    urls.append(v["url"])
    return urls


def _normalize_host(host: str) -> str:
    """A hostname in the one spelling used to compare hosts: lower case, no
    trailing dot, and - for an internationalised name - its ASCII (IDNA /
    punycode, ``xn--``) form, so ``bücher.example`` and
    ``xn--bcher-kva.example`` are the same host. That is also the name
    Python's own HTTP stack resolves and puts in the Host header
    (``str.encode("idna")``), so the comparison sees the host the key will
    really go to. A name the codec rejects (an empty or over-long label, a
    forbidden character) stays as lower-case text: it then equals only
    itself, the safe direction for an "is this the same owner?" test."""
    host = (host or "").lower().rstrip(".")
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return host


def _to_unicode(host: str) -> str:
    """The display spelling of a normalized host: ``xn--`` labels decoded.
    A name that is not valid punycode (or never was ASCII) is returned as is."""
    try:
        return host.lower().encode("ascii").decode("idna")
    except UnicodeError:
        return host


def describe_domain(domain: str) -> str:
    """How a domain is named in a warning: itself, or - when it is an
    internationalised one - the Unicode spelling with its ``xn--`` form in
    brackets beside it, so a look-alike letter (a Cyrillic "a" in
    "apple.com") cannot hide behind a name that looks identical."""
    shown = _to_unicode(domain)
    return domain if shown == domain else f"{shown} [{domain}]"


def _host(url: str) -> str:
    """The URL's host in comparison form (see _normalize_host). urlsplit has
    already dropped user:password@ and the :port, and lower-cased the name."""
    return _normalize_host(urllib.parse.urlsplit(url).hostname or "")


def _is_ip(host: str) -> bool:
    """An IP address, in any spelling ``ipaddress`` reads. (Cut at the dots,
    ``::ffff:1.2.3.4`` and ``::ffff:5.6.3.4`` would both end in ``3.4``.)"""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _suffix_labels(labels: list[str]) -> int:
    """How many trailing labels of a host are its public suffix: the longest
    match in PUBLIC_SUFFIXES or the country-registry rule, else the last one
    (the TLD)."""
    for i in range(len(labels) - 1):            # longest candidate first
        tail = labels[i:]
        if ".".join(tail) in PUBLIC_SUFFIXES:
            return len(tail)
        if (len(tail) == 2 and tail[0] in GENERIC_SECOND_LEVEL
                and len(tail[1]) == 2):
            return 2
    return 1


def registrable_domain(host: str) -> str:
    """The part of a hostname one party registers: the last two labels, or
    one label more under a public suffix (co.uk, com.gr, github.io, ...; see
    the tables above - a compact snapshot, not the full Public Suffix List).
    Under PER_HOST_DOMAINS (amazonaws.com, run.app, ...) the host is its own
    owner.

        api.github.com        -> github.com
        dashboard.stripe.com  -> stripe.com
        api.example.co.uk     -> example.co.uk
        x.com.gr              -> x.com.gr         (country registry)
        evil.github.io        -> evil.github.io   (platform: per-customer)
        a.run.app             -> a.run.app        (every host its own)
        www.bücher.example    -> xn--bcher-kva.example   (punycode form)

    IP addresses, localhost and single labels are returned unchanged.
    """
    host = _normalize_host(host)
    labels = host.split(".")
    if (len(labels) < 3 or all(part.isdigit() for part in labels)
            or _is_ip(host)):
        return host
    if any(".".join(labels[i:]) in PER_HOST_DOMAINS
           for i in range(1, len(labels))):
        return host
    size = _suffix_labels(labels)
    # one label more than the suffix; a host that IS a suffix (co.uk,
    # blob.core.windows.net) has no such label and stays whole
    return ".".join(labels[-(size + 1):])


def same_owner(url_a: str, url_b: str) -> bool:
    """Do two URLs live under the same registrable domain?"""
    a, b = registrable_domain(_host(url_a)), registrable_domain(_host(url_b))
    return bool(a) and a == b


def _require_cross_domain_confirmation(recipe: dict, out,
                                       confirm_in=input) -> bool:
    """If the validation URL belongs to a different owner than the key
    page (different registrable domain — api.stripe.com and
    dashboard.stripe.com are both stripe.com and need no prompt), require
    the user to type the confirmation word. Returns True when the flow may
    proceed."""
    v = recipe["validate"]
    private = [_host(u) for u in destinations(recipe)
               if doctor_mod.private_host_reason(u)]
    if private and not recipe.get("_builtin"):
        out.write(f"  \u26a0 This recipe sends your key to {printable(private[0])}, which is "
                  f"a program on THIS computer or on a private network,\n"
                  f"    not a public vendor. Only go on if you set that up yourself.\n")
        try:
            answer = confirm_in(f"  Type '{CONFIRM_WORD}' to continue: ")
        except (EOFError, KeyboardInterrupt):
            out.write("\ncancelled.\n")
            return False
        if (answer or "").strip().lower() != CONFIRM_WORD:
            out.write("  cancelled \u2014 no key was asked for, nothing was sent.\n")
            return False
    trusted = {_normalize_host(h) for h in v.get("trusted_hosts") or []}
    foreign = []
    for url in destinations(recipe):
        if same_owner(url, recipe["key_url"]):
            continue
        host = _host(url)
        if recipe.get("_builtin") and host in trusted:
            # A built-in (reviewed, shipped-with-the-code) recipe may vouch for
            # its vendor's second domain: api.anthropic.com for a key page on
            # claude.com. A recipe from ~/.stuntkey never gets this shortcut.
            out.write(f"  (validation host {printable(describe_domain(host))} is "
                      f"this vendor's API domain — built-in recipe)\n")
            continue
        foreign.append(host)
    if not foreign:
        return True
    host = foreign[0]
    domains = [registrable_domain(host),
               registrable_domain(_host(recipe["key_url"]))]
    spelled = [describe_domain(d) for d in domains]
    shown = [printable(s) for s in spelled]
    out.write(f"  ⚠ The validation URL is on a DIFFERENT domain than the key "
              f"page above ({shown[0]} vs {shown[1]}).\n")
    if spelled != domains:
        out.write("    Names with letters from other alphabets can look "
                  "exactly like another site's; the xn-- spelling in "
                  "brackets is the real one.\n")
    out.write("    Your key will be sent to both domains. Make sure you "
              "trust both.\n")
    try:
        answer = confirm_in(f"  Type '{CONFIRM_WORD}' to continue: ")
    except (EOFError, KeyboardInterrupt):
        out.write("\ncancelled.\n")
        return False
    if (answer or "").strip().lower() != CONFIRM_WORD:
        out.write("  cancelled — no key was asked for, nothing was sent.\n")
        return False
    return True


class SaveDeclined(Exception):
    """The key must not be saved where the person did not choose: raised by
    a store function (for example the keychain one, when the keychain failed
    and the person did not agree to a plain-text .env file). The text is a
    plain sentence and never contains the key."""


def store_in_env_file(env_file: str):
    """Default store: ENV_VAR=<key> in `env_file`, owner-only. Returns a
    callable (env_var, key) -> description for the success line."""
    def _store(env_var: str, key: str) -> str:
        stored = store_mod.store_key_result(env_var, key, env_file)
        verb = "updated" if stored.updated else "added"
        text = (f"{verb} {env_var} in {stored.path} "
                f"({stored.protection} - never displayed, never logged)")
        if store_mod.env_not_git_ignored(stored.path):
            text += "\n    " + store_mod.GIT_WARNING.format(
                path=stored.path, name=os.path.basename(stored.path))
        if stored.duplicates:
            # Said plainly, because the person may not know: of several
            # lines for one variable the last one is the one that counts.
            text += (f"\n    note: {env_var} appears "
                     f"{store_mod.times(stored.duplicates + 1)} in "
                     f"{stored.path}; I updated the one that takes effect "
                     f"(the last one).")
        return text
    return _store


def _ask_one(field: dict, single: bool, prompt, out, clip, taken: set,
             confirm=None) -> str | None:
    """One value: from the clipboard when copy-and-go is on, else the hidden
    prompt. Returns None when the person cancelled. Never shows the value.
    Ctrl-C while waiting for a Copy cancels; it does not fall through to the
    prompt. The clipboard is emptied after the prompt fallback too."""
    label = printable(field["label"], words=True)
    if clip is not None:
        get, clear = clip
        rounds = max(1, int(clipboard_mod.AUTO_ROUNDS))
        out.write(f"  Copy the {label} on the page - I'll take it from the clipboard "
                  f"and EMPTY it.\n    The next single-word thing you copy is taken "
                  f"as the key, so copy nothing else\n    (I keep waiting for you, "
                  f"up to {rounds * clipboard_mod.WAIT_SECONDS // 60} minutes in all; "
                  f"nothing is shown; Ctrl-C stops)\n")
        out.flush()
        value = None
        try:
            for turn in range(1, rounds + 1):
                value = clipboard_mod.wait_for_key(field.get("accept"), taken,
                                                   get, clear)
                if value or turn == rounds:
                    break
                # The window ran out before anything was copied. Not a
                # failure: say so in plain words and keep waiting. Only
                # key-shaped text is ever taken, and Ctrl-C stops it.
                out.write(f"  Still waiting for you to copy the {label} "
                          f"(try {turn + 1} of {rounds}). Ctrl-C stops.\n")
                out.flush()
        except KeyboardInterrupt:
            _safe_clear(clear)
            out.write("\ncancelled.\n")
            return None
        if value:
            # No "press Enter to save" step (Dan, 2026-11-08: it confused
            # people). A wrong copy is caught by the check that follows: it
            # goes only to the vendor's own address, and nothing is saved
            # unless the vendor accepts it.
            out.write(f"  ✓ Got your {label} from the clipboard "
                      f"({clipboard_mod.describe(value)}; hidden) - clipboard emptied.\n")
            out.flush()
            return value
        out.write("  Nothing was copied in time. Paste the key here instead "
                  "(nothing is shown):\n")
    text = "  Paste your API key (hidden): " if single else f"  Paste the {label} (hidden): "
    try:
        return safeprompt.strip_paste_marks(prompt(text)).strip()
    except (EOFError, KeyboardInterrupt):
        return None
    finally:
        if clip is not None:
            _safe_clear(clip[1])


def _safe_clear(clear) -> None:
    try:
        clear()
    except Exception:
        pass


def _cli_token(recipe: dict, out, run=subprocess.run, call=subprocess.call,
               which=shutil.which) -> str | None:
    """The key from the vendor's own CLI after its browser sign-in (built-in
    recipes only, programs fixed in recipes.CLI_PROGRAMS). The token goes
    from the program's output to this variable and nowhere else."""
    cli = recipe["cli_token"]
    # The program by its full path, found without looking in the current
    # folder: a cloned repository must not be able to ship its own gh.exe.
    exe = procs.find_program(cli["token"][0], which)
    if not exe:
        out.write(f"  {printable(cli['token'][0])} is not installed - "
                  f"use the normal steps instead (drop --via-cli).\n")
        return None
    token_cmd = [exe] + list(cli["token"][1:])
    if cli.get("login"):
        out.write("  Signing in with the vendor's own tool (it opens your browser)...\n")
        out.flush()
        if call([exe] + list(cli["login"][1:])) != 0:
            out.write("  sign-in did not finish.\n")
            return None
    try:
        done = run(token_cmd, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        out.write("  couldn't ask the vendor's tool for the key.\n")
        return None
    token = done.stdout.decode("utf-8", "replace").strip() if done.returncode == 0 else ""
    done = None
    if not token:
        out.write("  the vendor's tool gave no key.\n")
        return None
    return token


def connect(
    recipe: dict,
    env_file: str = ".env",
    browser_open=webbrowser.open,
    prompt=safeprompt.read_hidden,
    out=None,
    validate_fn=validate_mod.validate_key,
    confirm_in=None,
    store_fn=None,
    clipboard=None,
    via_cli: bool = False,
    cli_token_fn=None,
    opens_browser: bool = True,
) -> int:
    """Run the guided flow. Returns 0 on success, 1 on failure.

    `store_fn(env_var, key) -> description` decides where each validated
    value goes (default: the .env file). `clipboard` is a (get, clear) pair
    for copy-and-go, None for the hidden prompt. `via_cli` takes the key
    from the vendor's own CLI (built-in recipes with cli_token only).
    Injectable browser_open / prompt / validate_fn / confirm_in / store_fn /
    clipboard / cli_token_fn exist for tests and the CLI.
    """
    out = out or sys.stdout
    # the question after a key was taken is read without echo (safeprompt);
    # an injected confirm_in answers both kinds of question, for tests
    key_confirm = confirm_in
    confirm_in = confirm_in or input
    fields = recipe_fields(recipe)
    single = len(fields) == 1 and fields[0]["name"] == DEFAULT_FIELD
    if store_fn is None:
        # The key is headed for the .env file. If that file is one we will
        # not edit (a link, a UTF-16 file) say so NOW - before the browser
        # opens and before a key is pasted and sent to the API - instead of
        # after the person has done all of it.
        try:
            store_mod.check_env_file(env_file)
        except OSError as e:
            out.write(f"\n  ✗ {env_file}: {e.strerror or e}.\n"
                      f"    Nothing was asked for and nothing was sent.\n")
            return 1
    if recipe.get("_overrides_builtin"):
        out.write(f"  {OVERRIDE_NOTE}\n")
    if via_cli and not (recipe.get("_builtin") and recipe.get("cli_token")):
        out.write("  --via-cli works only for built-in recipes that have a vendor CLI "
                  "(e.g. github).\n")
        return 1
    if not via_cli:
        _print_steps(recipe, out, opens_browser)
        try:
            browser_open(recipe["key_url"])
        except Exception as e:
            out.write(f"  (couldn't open a browser: {e} — open the URL above manually)\n")

    # Preview exactly where the key will go BEFORE asking for it.
    render_validation_preview(recipe, out)
    if not _require_cross_domain_confirmation(recipe, out, confirm_in):
        return 1

    values: dict[str, str] | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        values = {}
        taken: set[str] = set()
        cancelled = again = False
        for field in fields:
            if via_cli:
                value = (cli_token_fn or _cli_token)(recipe, out)
                if value is None:
                    return 1
            else:
                value = _ask_one(field, single, prompt, out, clipboard, taken, key_confirm)
            if value is None:
                cancelled = True
                break
            if not value:
                out.write("  empty — try again.\n")
                again = True
                break
            problem = None if store_fn is not None else store_mod.unsafe_reason(value)
            if problem:
                # Said right after the paste - before the key goes anywhere: the
                # .env file cannot hold this key in a form every reader agrees
                # on (see store.unsafe_reason), so asking the API about it would
                # only waste the paste. A keychain store_fn has no such rule.
                what = "that key" if single else f"the {printable(field['label'], words=True)}"
                out.write(f"  ✗ {what} contains {problem}, which .env readers "
                          f"do not agree on -\n"
                          f"    real API keys do not have one. Nothing was sent. "
                          f"Check what you pasted\n"
                          f"    (a copied quote mark or an invisible character?) "
                          f"and try again.\n")
                again = True
                break
            values[field["name"]] = value
            taken.add(value)
        if cancelled:
            values = None
            out.write("\ncancelled.\n")
            return 1
        if again:
            values = None
            continue
        if recipe.get("untested"):
            break                 # nothing is sent; said in the preview and below
        out.write("  validating…\n")
        out.flush()
        try:
            ok = validate_fn(recipe["validate"],
                             values[DEFAULT_FIELD] if single else values)
        except validate_mod.UnsendableKey as e:
            # The key cannot go into an HTTP request (see validate.py): said
            # before anything was sent, without repeating the key, and the
            # person can paste again - this is not "couldn't reach the API".
            label = next((f["label"] for f in fields if f["name"] == e.field), None)
            what = f"the {printable(label, words=True)}" if label else "that key"
            out.write(f"  ✗ {what} contains {printable(e.reason)}. "
                      f"Nothing was sent. Check what you\n"
                      f"    pasted (a copied quote mark or an invisible "
                      f"character?) and try again.\n")
            values = None
            continue
        except validate_mod.ClockSkew as e:
            values = None
            out.write(f"  \u2717 {printable(e)}\n  Nothing was saved.\n")
            return 1
        except validate_mod.ValidationError as e:
            values = None
            out.write(f"  couldn't reach the API: {printable(e)}\n")
            return 1
        if ok:
            note = getattr(ok, "note", None)
            if note:
                out.write(f"  \u2713 the key is real, but: {printable(note, words=True)}\n")
            break
        left = MAX_ATTEMPTS - attempt
        what = "key" if single else "credentials"
        out.write(f"  {what} rejected by the API."
                  f"{f' {left} tries left.' if left else ''}\n")
        # Scrub the rejected values immediately.
        values = None
        if via_cli:
            return 1
    else:
        out.write("  giving up — double-check the key and run me again.\n")
        return 1

    store_fn = store_fn or store_in_env_file(env_file)
    saved: list[str] = []
    try:
        for field in fields:
            saved.append(store_fn(field["env_var"], values[field["name"]]))
    except SaveDeclined as e:
        out.write(f"\n  \u2717 the key was validated but NOT saved: {e}\n"
                  f"    {_partly(saved)}\n")
        return 1
    except store_mod.UnsafeValue as e:
        # Only reachable when the key was headed elsewhere first (the
        # keychain falling back to the .env file): the paste loop stops an
        # unstorable key before it is sent when the .env file is the target.
        out.write(f"\n  ✗ the key was validated but could NOT be saved: "
                  f"{e.strerror}\n"
                  f"    {_partly(saved)}\n")
        return 1
    except OSError as e:
        # e.g. --env-file in a folder that is a file, or not writable.
        # The error names the path, never the key. The key is NOT saved, and
        # it is not kept anywhere (copy-and-go emptied the clipboard): the
        # person gets it again from the vendor page.
        out.write(f"\n  ✗ the key was validated but could NOT be saved: "
                  f"{e.strerror or e} ({e.filename or env_file})\n"
                  f"    {_partly(saved)} Fix the path (or pass "
                  f"--env-file) and run me again. The key is not kept anywhere - "
                  f"copy it again from the vendor page.\n")
        return 1
    finally:
        # Scrub the values from this frame whatever happens.
        values = None
        del values
    for description in saved:
        out.write(f"\n  ✓ {description}\n")
    out.write(f"\n  ✓ Your {printable(recipe['display'], words=True)} key has been added.\n")
    if recipe.get("untested"):
        out.write("\n  Saved. Not tested - stuntkey doesn't know this site's API yet, "
                  "so it cannot say the key works.\n"
                  "  `stuntkey add` teaches it how to check a key.\n")
        return 0
    try:
        import urllib.parse as _up
        _path = _up.urlsplit((recipe.get("validate") or {}).get("url", "")).path or "/"
    except ValueError:
        _path = "/"
    if len(fields) == 1 and fields[0]["name"] == DEFAULT_FIELD and _path.isprintable():
        out.write(f"\n  Next:  stuntkey call {printable(recipe['service'])} GET {_path}"
                  "     (a test call; the key stays hidden)\n"
                  "         stuntkey install     (plug stuntkey into Claude, Cursor or VS Code)\n")
    return 0


def _partly(saved: list[str]) -> str:
    if not saved:
        return "Nothing was written."
    return ("Only part was written: " + "; ".join(saved) +
            " - run `stuntkey forget` for this service and connect again.")
