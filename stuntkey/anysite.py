"""`stuntkey get <any site>`: a key for a site with no built-in recipe.

The site is worked out from what the person typed (a web address, or a name
looked up in the public-apis list and confirmed), the browser opens a search
for that site's API key page, the key is taken from the clipboard, and a
recipe is saved so run/call/forget work. The key is never tested - nobody
knows the site's API - and the saved recipe can only send it to that one
site's api. host.
"""
from __future__ import annotations

import re
import sys
import urllib.parse

from . import connect as connect_mod
from . import recipes as recipes_mod

# "mailgun.com", "https://app.mailgun.com/x", "api.mailgun.net:443" - ASCII
# only; an internationalised name is typed as its xn-- form or asked for.
# The top-level label is letters only (2-24) and every label at most 63, so a
# key pasted here by mistake (a JWT is dot-separated too) is not taken for a
# site and sent to a search engine.
_DOMAIN_RE = re.compile(
    r"^(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"
    r"(?::\d{1,5})?(?:[/?#].*)?\Z", re.I)


def site_domain(text: str) -> str | None:
    """The registrable domain of a typed address, or None."""
    text = (text or "").strip()
    m = _DOMAIN_RE.match(text) if len(text) <= 200 else None
    return connect_mod.registrable_domain(m.group(1)) if m else None


def looks_like_site(name: str, catalog: dict | None = None) -> bool:
    """Worth the any-site flow: an address, or a short plain name that is not
    a near-typo of a known service ("githb" still gets "Did you mean")."""
    if site_domain(name):
        return True
    if not (len(name) <= 24 and recipes_mod.SLUG_RE.match(name)):
        return False
    import difflib
    return not difflib.get_close_matches(name.lower(), list(catalog or ()), n=1, cutoff=0.8)


def _catalog_domain(name: str) -> str | None:
    """The domain the public-apis list gives for a name, or None (no match,
    or the list cannot be fetched)."""
    from . import publicapis
    try:
        entry = publicapis.find_by_name(publicapis.parse(publicapis.fetch()), name)
    except Exception:            # offline, bad cache: just ask instead
        return None
    return site_domain(entry["url"]) if entry else None


def resolve(name: str, ask=input, out=None, lookup=_catalog_domain) -> str | None:
    """The site's registrable domain, or None when the person stopped."""
    out = out or sys.stdout
    domain = site_domain(name)
    if domain:
        return domain
    domain = lookup(name)
    if domain:
        answer = ask(f"  Is this the right site: {recipes_mod.printable(domain)}? [y/N] ")
        if (answer or "").strip().lower() in ("y", "yes"):
            return domain
        out.write("  Stopped - nothing was asked for, nothing was saved. "
                  "Run it again with the site's address, e.g. stuntkey get example.com\n")
        return None
    answer = ask(f"  What is {recipes_mod.printable(name)}'s website (e.g. example.com)? ")
    domain = site_domain(answer or "")
    if not domain:
        out.write("  That is not a web address. Nothing was saved.\n")
    return domain


def _owned_by(recipe: dict, domain: str) -> bool:
    site = f"https://{domain}/"
    return any(connect_mod.same_owner(u, site) for u in
               ((recipe.get("validate") or {}).get("url", ""), recipe.get("key_url", "")))


def build_recipe(domain: str, catalog: dict) -> dict:
    """A known recipe for this site (built-in or saved earlier), else a new one."""
    base = re.sub(r"[^a-z0-9_-]", "-", domain.split(".")[0].lower()).strip("-") or "site"
    for slug in (base, re.sub(r"[^a-z0-9_-]", "-", domain.lower())):
        slug = slug[:64]
        known = catalog.get(slug)
        if known and _owned_by(known, domain):
            return known
        if not known and not recipes_mod.device_name_problem(slug):
            break
    else:
        raise recipes_mod.RecipeError(f"no free name for {domain}")
    used = {v for r in catalog.values() for v in recipes_mod.env_vars(r)}
    env_var = re.sub(r"[^A-Z0-9_]", "_", slug.upper()) + "_API_KEY"
    if env_var[0].isdigit() or env_var in used:
        env_var = "KEY_" + re.sub(r"[^A-Z0-9_]", "_", domain.upper()) + "_API_KEY"
    recipe = {
        "service": slug,
        "display": domain,
        "key_url": f"https://{domain}/",
        "env_var": env_var,
        "steps": [f"Sign in to {domain} (the page that opens is a search for its API key page)",
                  "Create an API key, or open one you have - pick the fewest "
                  "permissions it offers",
                  "Copy the key"],
        "validate": {"method": "GET", "url": f"https://api.{domain}/",
                     "auth": {"type": "bearer"}, "expect": [200]},
        "unverified": ["validate.url", "validate.auth"],
        "untested": True,
    }
    return recipes_mod.validate_recipe(recipe)


def search_url(domain: str) -> str:
    return "https://duckduckgo.com/?q=" + urllib.parse.quote(f"!ducky {domain} API key")


def _save_approved(data: dict, directory: str | None = None) -> str:
    """Save a recipe the person just made with `stuntkey get <site>`, and approve it
    (they are at a terminal and asked for it); an AI tool or script gets it saved
    but not approved."""
    from . import remote
    path, _approved = remote.recipe_save_and_approve(data, directory)
    return path


def cmd_get(name: str, catalog: dict, connect_one, ask=input, out=None,
            lookup=_catalog_domain, save=_save_approved) -> int:
    """`connect_one(recipe, open_url)` runs the normal copy-and-go connect."""
    out = out or sys.stdout
    try:
        domain = resolve(name, ask, out, lookup)
    except (EOFError, KeyboardInterrupt):
        out.write("\ncancelled.\n")
        return 1
    if not domain:
        return 1
    try:
        recipe = build_recipe(domain, catalog)
    except recipes_mod.RecipeError as e:
        out.write(f"  ✗ {recipes_mod.printable(e)}. Nothing was saved.\n")
        return 1
    known = recipe.get("service") in catalog
    if known:
        out.write(f"  stuntkey already knows {recipes_mod.printable(domain)} "
                  f"as '{recipe['service']}'.\n")
    code = connect_one(recipe, search_url(domain) if recipe.get("untested") else None)
    if code == 0 and not known:
        save(recipe)
    return code
