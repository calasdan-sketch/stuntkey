"""`stuntkey get` with no name: a short menu, forgiving typing, and keys
recognised by their shape.

  - "open ai", "OpenAI", "chatgpt", "git hub" all find the service.
  - A copied key is recognised by how it starts ("sk-ant-..." is Anthropic,
    "ghp_..." is GitHub) and the service is NAMED for the person. Nothing is
    ever printed from the key itself.
  - The default way in is the clipboard: copy the key, run the command.

Leaf-ish module: it imports nothing from stuntkey at load time except what a
function needs when it runs.
"""
from __future__ import annotations

import difflib
import re
import sys

# The ones people ask for most, in the order shown.
EVERYDAY = ["openai", "anthropic", "github", "stripe", "google-gemini", "resend",
            "sendgrid", "twilio", "supabase", "vercel", "cloudflare", "notion"]

# Words people say that are not the slug. Only unambiguous ones.
SAYINGS = {"chatgpt": "openai", "gpt": "openai", "claude": "anthropic",
           "gemini": "google-gemini", "googlegemini": "google-gemini",
           "git": "github", "stripekey": "stripe"}


def norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


def best(text: str, catalog: dict) -> str | None:
    """The service slug when `text` clearly means one: same letters ignoring
    spaces, dashes and case ("open ai"), one of the sayings, or a clear start
    of exactly one name. None when unsure (typos are left to "Did you mean")."""
    n = norm(text)
    if not n or len(n) > 40 or "." in str(text) or "/" in str(text):
        return None             # an address (example.com) is a site, not a spelling
    names = {}
    for slug, r in catalog.items():
        names.setdefault(norm(slug), slug)
        names.setdefault(norm(r.get("display", "")), slug)
    if n in names:
        return names[n]
    say = SAYINGS.get(n)
    if say and say in catalog:
        return say
    if len(n) >= 3:
        hits = {slug for k, slug in names.items() if k.startswith(n)}
        if len(hits) == 1:
            return hits.pop()
    return None


def close(text: str, catalog: dict, n: int = 3) -> list:
    """Likely services for a half-typed or mistyped name, best first."""
    key = norm(text)
    if not key:
        return []
    scored = []
    for slug, r in catalog.items():
        for name in {norm(slug), norm(r.get("display", ""))}:
            if not name:
                continue
            if key in name or name in key:
                scored.append((0.95, slug))
            else:
                scored.append((difflib.SequenceMatcher(None, key, name).ratio(), slug))
    out = []
    for score, slug in sorted(scored, key=lambda t: -t[0]):
        if score >= 0.6 and slug not in out:
            out.append(slug)
    return out[:n]


def _literal_prefix(pattern: str) -> int:
    """How many characters a pattern spells out before its first special one."""
    n = 0
    for ch in pattern.lstrip("^"):
        if ch in "[](){}|*+?.\\$":
            break
        n += 1
    return n


def _detect_rank(recipe: dict, value: str):
    """(known?, matched length) when `value` starts like one of the recipe's
    keys, else None."""
    from . import recipes as recipes_mod
    best_rank = None
    for f in recipes_mod.fields(recipe):
        pat = f.get("detect")
        if not pat:
            continue
        try:
            m = re.match(pat, value)
        except re.error:
            continue
        if m:
            # known shapes first; then the more specific start ("sk-ant-" beats
            # "sk-"); then the longer match
            rank = (f.get("detect_confidence") == "known", _literal_prefix(pat),
                    len(m.group(0)))
            if best_rank is None or rank > best_rank:
                best_rank = rank
    return best_rank


def service_for_key(value: str, catalog: dict) -> list:
    """Services whose key shape fits `value`, best first (known shapes before
    guesses). Empty when none fits. One line, no spaces, 16+ characters only."""
    value = (value or "").strip()
    if not (16 <= len(value) <= 4096) or re.search(r"[\s\x00-\x1f\x7f]", value):
        return []
    ranked = []
    for slug, r in catalog.items():
        rank = _detect_rank(r, value)
        if rank:
            ranked.append((rank, slug))
    return [slug for _rank, slug in sorted(ranked, reverse=True)]


def looks_like_a_key(value: str) -> bool:
    """A long, spaceless, mixed-character word: probably a key, not a name."""
    from . import clipboard
    return clipboard.looks_like((value or "").strip(), None)


def render_menu(catalog: dict) -> str:
    lines = ["", "  Which service is the key for?", ""]
    shown = [s for s in EVERYDAY if s in catalog]
    for i, slug in enumerate(shown, 1):
        from . import recipes as recipes_mod
        lines.append(f"    {i:>2}. {recipes_mod.printable(catalog[slug]['display'], words=True)}")
    lines += ["", "  Type a number or a name (like \"open ai\" or \"stripe\"), "
                  "or a website address.",
              "  `stuntkey list` shows every service I know.", ""]
    return "\n".join(lines)


def _read_clipboard(clip):
    """(value, clear) or (None, None): never raises."""
    if clip is None:
        try:
            from . import clipboard
            clip = clipboard.backend()
        except Exception:               # noqa: BLE001 - no clipboard here
            return None, None
    try:
        return (clip[0]() or "").strip(), clip
    except Exception:                   # noqa: BLE001
        return None, None


def choose(catalog: dict, out=None, ask=None, clip=None, reader=None):
    """Walk the person to a choice. Returns ("key", slug, value, clear) for a
    key found on the clipboard they agreed to use; ("service", text) for a
    typed choice; None when they stopped. `ask(prompt)` reads a typed line;
    `reader` answers yes/no questions (both for tests)."""
    from . import recipes as recipes_mod
    from . import safeprompt
    out = out or sys.stdout
    p = recipes_mod.printable
    value, clear = _read_clipboard(clip)
    if value:
        # one-value services only: a service that needs two values (an ID and
        # a secret) is walked through the normal steps instead
        slugs = [s for s in service_for_key(value, catalog)
                 if len(recipes_mod.fields(catalog[s])) == 1]
        if slugs:
            name = p(catalog[slugs[0]]["display"], words=True)
            out.write(f"\n  What you copied looks like a {name} key "
                      "(I did not show it, and I read it only to name it).\n")
            answer = safeprompt.ask(f"  Save it as {name}? [Y/n] ", out,
                                    enter_means=True, reader=reader)
            if answer is None:
                return None
            if answer:
                return ("key", slugs[0], value, clear)
        elif looks_like_a_key(value):
            out.write("\n  You have something copied that looks like a key, but I do "
                      "not know which service it is for.\n"
                      "  Choose the service below and I will use what you copied.\n")
            return _typed(catalog, out, ask, value, clear)
    out.write(render_menu(catalog))
    return _typed(catalog, out, ask, None, None)


def _typed(catalog, out, ask, value, clear):
    from . import recipes as recipes_mod
    p = recipes_mod.printable
    shown = [s for s in EVERYDAY if s in catalog]
    ask = ask or input
    if value is not None:
        out.write(render_menu(catalog))
    for _ in range(3):
        try:
            text = ask("  Service: ").strip()
        except (EOFError, KeyboardInterrupt):
            out.write("\n  Stopped. Nothing was saved.\n")
            return None
        if not text:
            out.write("  Stopped. Nothing was saved.\n")
            return None
        if looks_like_a_key(text) and not re.match(r"https?://", text, re.I):
            out.write("  That looked like a key. Do not type keys here: copy the key "
                      "and run `stuntkey get` again. Nothing was saved.\n")
            return None
        slug = None
        if text.isdigit() and 1 <= int(text) <= len(shown):
            slug = shown[int(text) - 1]
        slug = slug or best(text, catalog)
        if slug:
            if value is not None and len(recipes_mod.fields(catalog[slug])) == 1:
                return ("key", slug, value, clear)
            if value is not None:
                out.write("  That service needs more than one value, so I will walk you "
                          "through it step by step.\n")
            return ("service", slug)
        from . import anysite
        if anysite.site_domain(text):
            return ("service", text)
        near = close(text, catalog)
        if near:
            out.write("  I am not sure which you mean. Did you mean: "
                      + ", ".join(p(n) for n in near) + "?\n")
        else:
            out.write("  I do not know that one. Try again, or type a website address.\n")
    out.write("  Stopped. Nothing was saved.\n")
    return None
