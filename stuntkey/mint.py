"""`stuntkey mint <service>`: make a fresh, narrowly scoped key at the vendor
by API, check it, and save it in the keychain - nobody copies or pastes it.

Cloudflare only. A one-time "key-maker" token (service cloudflare-keymaker,
saved once with `stuntkey get cloudflare-keymaker`) may create API tokens;
mint uses it to create a token with only the permissions the recipe's "mint"
block names, for one account. The key-maker token goes only to
api.cloudflare.com over the broker's pinned HTTPS (public address, no proxy,
no redirect). The new key is never printed. After a re-mint has been checked
and saved, the token made last time is deleted at Cloudflare.
"""

from __future__ import annotations

import datetime
import json
import os
import time
import urllib.parse
import urllib.request

from . import broker, keychain as keychain_mod, store as store_mod
from . import validate as validate_mod
from .recipes import printable

API_HOST = "api.cloudflare.com"
KEYMAKER = ("cloudflare-keymaker", "CLOUDFLARE_KEYMAKER_TOKEN")



class MintFailed(Exception):
    pass


def add_parser(sub) -> None:
    mp = sub.add_parser("mint", help="Make a fresh key at the vendor by API and save it "
                                     "(no copy, no paste). Cloudflare only.")
    mp.add_argument("service", help="A service whose recipe has a \"mint\" block.")


def _state_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "minted.json")


def _load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _call(method: str, path: str, token: str, body=None, send=None, resolver=None):
    """One Cloudflare API call with `token`. Returns "result"; raises MintFailed.
    The error text never carries the token."""
    req = urllib.request.Request(
        f"https://{API_HOST}/client/v4{path}",
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "User-Agent": "stuntkey"}, method=method)
    try:
        ip = broker.resolve_public(API_HOST, 443, resolver)
        status, _, raw = (send or broker._real_send)(req, ip, 20.0)
    except (broker.BrokerError, OSError) as e:
        raise MintFailed(printable(str(e).replace(token, "[key]"))) from None
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        data = {}
    if not (200 <= status < 300 and isinstance(data, dict) and data.get("success")):
        errs = data.get("errors") if isinstance(data, dict) else None
        msg = "; ".join(str(e.get("message", "")) for e in errs or [] if isinstance(e, dict))
        raise MintFailed(printable(f"Cloudflare answered HTTP {status}"
                                   + (f": {msg}" if msg else "")).replace(token, "[key]"))
    return data.get("result")


def mint(recipe: dict, keychain=keychain_mod, send=None, resolver=None,
         validate_fn=validate_mod.validate_key, out=print, state_path: str | None = None,
         sleep=time.sleep) -> None:
    service, env_var, spec = recipe["service"], recipe["env_var"], recipe["mint"]
    parent = keychain.read(*KEYMAKER)
    if not parent:
        raise MintFailed("No key-maker yet. Run `stuntkey get cloudflare-keymaker` once.")
    groups = _call("GET", "/user/tokens/permission_groups", parent, send=send, resolver=resolver)
    by_name = {str(g.get("name", "")).lower(): g.get("id") for g in groups or [] if isinstance(g, dict)}
    ids = []
    for name in spec["permissions"]:
        if not by_name.get(name.lower()):
            raise MintFailed(f"Cloudflare has no permission called '{printable(name)}'. "
                             "Nothing was made.")
        ids.append({"id": by_name[name.lower()]})
    body = {"name": f"stuntkey {service} {datetime.date.today()}",
            "policies": [{"effect": "allow", "permission_groups": ids,
                          "resources": {f"com.cloudflare.api.account.{spec['account']}": "*"}}]}
    made = _call("POST", "/user/tokens", parent, body, send=send, resolver=resolver)
    value, new_id = (made or {}).get("value"), (made or {}).get("id")
    if not (isinstance(value, str) and value and isinstance(new_id, str)):
        raise MintFailed("Cloudflare did not hand back a token. Nothing was saved.")
    try:
        status = None
        for _ in range(5):              # a brand-new token can take a moment to work
            status = getattr(validate_fn(recipe["validate"], value), "status", None)
            if status == "valid":
                break
            sleep(1.0)
        if status != "valid":
            raise MintFailed(f"The new key did not pass its check ({status}). It was deleted.")
        keychain.store(service, env_var, value)
    except BaseException:
        try:
            _call("DELETE", f"/user/tokens/{urllib.parse.quote(new_id)}", parent,
                  send=send, resolver=resolver)
        except MintFailed:
            pass
        raise
    finally:
        value = None
    state_path = state_path or _state_path()
    state = _load_state(state_path)
    old = state.get(service)
    state[service] = new_id
    store_mod.write_private(state_path, json.dumps(state, indent=2) + "\n")
    out(f"Made a new {printable(recipe['display'], words=True)} key, checked it and saved "
        "it in the keychain (not shown).")
    if isinstance(old, str) and old and old != new_id:
        try:
            _call("DELETE", f"/user/tokens/{urllib.parse.quote(old)}", parent,
                  send=send, resolver=resolver)
            out("Deleted the key made last time.")
        except MintFailed as e:
            out(f"Could not delete the key made last time ({e}); remove it on Cloudflare's "
                "API Tokens page.")


def cmd_mint(args, catalog: dict) -> int:
    recipe = catalog.get(args.service)
    if not recipe or "mint" not in recipe:
        print(f"error: '{printable(args.service)}' cannot be minted (its recipe has no "
              "\"mint\" block).")
        return 3
    try:
        mint(recipe)
    except MintFailed as e:
        print(f"error: {e}")
        return 1
    except keychain_mod.KeychainError as e:
        print(f"error: the keychain refused the new key ({printable(e)}). It was deleted.")
        return 1
    return 0
