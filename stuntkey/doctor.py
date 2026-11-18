"""`stuntkey doctor-recipes`: have the recipes rotted?

A recipe is a list of web addresses: the page where a key is made, the
vendor's docs, and the server a key is tested against. Vendors move pages.
This visits each address over HTTPS WITHOUT any key and reports what it
finds, so a moved page is caught by a weekly check instead of by a person
halfway through connecting.

Nothing secret is involved: no key is read or sent, and the test server is
asked the question a stranger could ask. A login page counts as alive.

Verdicts per address:
  ok     the page answered (200 to 399)
  moved  it redirected to another page; the final address is shown - fix the
         recipe if it is a different place. A redirect to a sign-in page is
         normal for a dashboard and counts as ok
  warn   answered, but not in a way that proves rot (403, 429, 5xx, or a
         site that refuses scripts) - look by hand
  ROT    gone or unreachable: 404 / 410, a name that does not resolve, a
         refused connection, a broken certificate, or too many redirects

Exit status: 0 nothing rotted, 1 at least one address ROT, 2 could not run.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from . import logfacts
from . import recipes as recipes_mod

USER_AGENT = f"stuntkey-doctor/{__version__} (+https://github.com/calasdan-sketch/stuntkey)"
MAX_HOPS = 10
TIMEOUT = 15.0
OK, MOVED, WARN, ROT = "ok", "moved", "warn", "ROT"
GONE = (404, 410)


class _NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def private_host_reason(url: str) -> str | None:
    """Why `url` must not be visited (it names this computer or a private
    network), or None. Looks only at the text of the address."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").strip("[]").lower()
    except ValueError:
        return "an address that could not be read"
    if not host:
        return "no host name"
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return "a local host name"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return _ip_reason(ip)


def _ip_reason(ip) -> str | None:
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return "a private or local network address"
    return None


def resolves_private(host: str, resolver=socket.getaddrinfo) -> bool:
    """True when the name points at a private address (checked before the
    real request, so a public-looking name cannot lead the check inside)."""
    try:
        infos = resolver(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        try:
            if _ip_reason(ipaddress.ip_address(info[4][0].split("%")[0])):
                return True
        except ValueError:
            continue
    return False


def fetch(url: str, timeout: float = TIMEOUT) -> tuple[int | None, str | None, str | None]:
    """One request, no redirect followed, no credentials: (status, Location,
    problem). `problem` is a short sentence when nothing answered. HEAD
    first; GET when the server dislikes HEAD."""
    if resolves_private(urllib.parse.urlsplit(url).hostname or ""):
        return None, None, "name points at a private network address - not visited"
    opener = urllib.request.build_opener(_NoFollow)
    last_status = None
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers.get("Location"), None
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location") if e.headers else None
            status = e.code
            e.close()
            if method == "HEAD" and status in (400, 403, 404, 405, 501):
                last_status = status
                continue        # some servers refuse HEAD but serve GET
            return status, location, None
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLError):
                return None, None, "TLS certificate problem"
            if isinstance(reason, socket.gaierror):
                return None, None, "name does not resolve"
            if isinstance(reason, (socket.timeout, TimeoutError)):
                return None, None, "timed out"
            if isinstance(reason, ConnectionRefusedError):
                return None, None, "connection refused"
            return None, None, f"could not connect ({type(reason).__name__})"
        except (http.client.HTTPException, OSError, ValueError) as e:
            return None, None, f"could not connect ({type(e).__name__})"
    return last_status, None, None


def check_url(url: str, fetch_fn=None, timeout: float = TIMEOUT) -> dict:
    """Follow redirects by hand (up to MAX_HOPS) and judge the end."""
    fetch_fn = fetch_fn or fetch
    hops = []
    seen = {url}
    current = url
    for _ in range(MAX_HOPS + 1):
        reason = private_host_reason(current)
        if reason:
            return {"url": url, "verdict": ROT if current == url else WARN,
                    "detail": f"{'is' if current == url else 'redirects to'} {reason} - not visited",
                    "final": current, "status": None, "hops": len(hops)}
        status, location, problem = fetch_fn(current, timeout)
        if problem:
            return {"url": url, "verdict": ROT, "detail": problem, "final": current,
                    "status": None, "hops": len(hops)}
        if status is not None and 300 <= status < 400 and location:
            nxt = urllib.parse.urljoin(current, location)
            if urllib.parse.urlsplit(nxt).scheme.lower() != "https":
                return {"url": url, "verdict": ROT, "detail": "redirects to a non-HTTPS address",
                        "final": nxt, "status": status, "hops": len(hops)}
            if nxt in seen:
                return {"url": url, "verdict": ROT, "detail": "redirect loop",
                        "final": nxt, "status": status, "hops": len(hops)}
            seen.add(nxt)
            hops.append(nxt)
            current = nxt
            continue
        break
    else:
        # a long chain that keeps finding new addresses is a sign-in flow
        # (some dashboards hop through several auth hosts), not a dead page
        return {"url": url, "verdict": WARN,
                "detail": f"more than {MAX_HOPS} redirects (a sign-in flow?) - check by hand",
                "final": current, "status": None, "hops": len(hops)}
    verdict, detail = _judge(status, hops, current)
    return {"url": url, "verdict": verdict, "detail": detail, "final": current,
            "status": status, "hops": len(hops)}


SIGN_IN_RE = re.compile(r"(?i)(?:log[-_]?in|sign[-_]?in|signin|/auth|accounts\.google\.com|sso)")


def _judge(status, hops, final: str = "") -> tuple[str, str]:
    if status in GONE:
        return ROT, f"HTTP {status} (page gone)"
    if status is None or status >= 500 or status in (403, 429, 401, 400, 405):
        # 401/400/405 from a test server mean "alive, wants a key / a different
        # request"; 403/429/5xx might be bot protection or an outage.
        if status in (400, 401, 405):
            return (MOVED if hops else OK), f"HTTP {status} (alive)"
        return WARN, f"HTTP {status} - check by hand"
    if hops and SIGN_IN_RE.search(final):
        return OK, f"HTTP {status}, sign-in page (expected for a dashboard)"
    if hops:
        return MOVED, f"HTTP {status} after {len(hops)} redirect(s)"
    return OK, f"HTTP {status}"


def addresses(recipe: dict) -> list[tuple[str, str]]:
    """[(what, url)] a recipe depends on. Only addresses; never a key."""
    out = [("key page", recipe["key_url"])]
    if recipe.get("docs"):
        out.append(("docs", recipe["docs"]))
    v = recipe["validate"]
    auth = v.get("auth", {})
    if auth.get("type") == "oauth2_client_credentials":
        out.append(("token server", auth["token_url"]))
        if auth.get("token_only"):
            return out
    out.append(("check server", _without_query(v["url"])))
    lp = (recipe.get("least_privilege") or {}).get("url")
    if lp:
        out.append(("least-privilege link", lp))
    return out


def _without_query(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(parts._replace(query="", fragment=""))


SERVICE_BUDGET = 90.0       # seconds one service may take in all


def run(catalog: dict, fetch_fn=None, only: list[str] | None = None,
        timeout: float = TIMEOUT, now=time.monotonic, budget: float = SERVICE_BUDGET) -> list[dict]:
    fetch_fn = fetch_fn or fetch
    rows = []
    seen: dict[str, dict] = {}
    for slug in sorted(catalog):
        if only and slug not in only:
            continue
        started = now()
        for what, url in addresses(catalog[slug]):
            if url not in seen:
                if now() - started > budget:
                    seen[url] = {"url": url, "verdict": WARN, "final": url, "status": None, "hops": 0,
                                 "detail": f"skipped - this service took more than {int(budget)}s"}
                else:
                    seen[url] = check_url(url, fetch_fn, timeout)
            row = dict(seen[url])
            row.update(service=slug, what=what)
            rows.append(row)
    return rows


def render(rows: list[dict]) -> str:
    lines = [f"  {'service':14} {'address':20} {'verdict':6} detail"]
    for r in rows:
        lines.append(f"  {recipes_mod.printable(r['service']):14} {r['what']:20} "
                     f"{r['verdict']:6} {recipes_mod.printable(r['detail'])}")
        if r["verdict"] in (MOVED, ROT, WARN) and r["final"] != r["url"]:
            lines.append(f"  {'':14} {'':20} {'':6} now at {recipes_mod.printable(r['final'])}")
        if r["verdict"] == ROT:
            lines.append(f"  {'':14} {'':20} {'':6} was {recipes_mod.printable(r['url'])}")
    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in (OK, MOVED, WARN, ROT)}
    lines.append("")
    lines.append(f"  {len(rows)} addresses: {counts[OK]} ok, {counts[MOVED]} moved, "
                 f"{counts[WARN]} to look at, {counts[ROT]} rotted")
    return "\n".join(lines) + "\n"


def exit_code(rows: list[dict]) -> int:
    return 1 if any(r["verdict"] == ROT for r in rows) else 0


def cmd_doctor(args, catalog: dict, out=None, fetch_fn=None) -> int:
    out = out or sys.stdout
    fetch_fn = fetch_fn or fetch
    unknown = [s for s in (args.service or []) if s not in catalog]
    if unknown:
        out.write(f"unknown service: {', '.join(recipes_mod.printable(u) for u in unknown)}\n")
        return 2
    rows = run(catalog, fetch_fn, args.service or None, args.timeout)
    try:
        shapes = logfacts.shape_unverified_count()
    except Exception:           # noqa: BLE001 - a side note, never a reason to fail
        shapes = 0
    if args.json:
        out.write(json.dumps({"rows": rows, "rotted": exit_code(rows) == 1,
                              "hook_shape_unverified": shapes}, indent=2) + "\n")
    else:
        out.write("\n" + render(rows))
        if shapes:
            out.write(f"\n  Note: {shapes} file-read / search output(s) came back in a shape "
                      "stuntkey could not check or could\n  only check unverified, so the "
                      "after-the-fact key hiding may not have covered them.\n")
        out.write("\n")
    return exit_code(rows)
