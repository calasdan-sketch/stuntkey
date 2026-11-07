"""`stuntkey proxy -- <command>`: run a program that talks to AI APIs through
the broker, without ever giving it a key.

The program gets base-URL variables pointing at a loopback server
(OPENAI_BASE_URL=http://127.0.0.1:P/openai/v1, ...) and *_API_KEY set to a
random session token. That token is only the proxy's password; the real key
is added by the proxy and never enters the program's environment. There is
no TLS interception: the program speaks plain HTTP to 127.0.0.1, the proxy
speaks HTTPS to the recipe's own host.

Per request: /<service>/<path> picks the recipe (the host comes from the
recipe); the route policy, kill switch and caps are checked; POST and other
writes go only to the usual LLM endpoints unless stuntkey.policy allows more
(nobody is asked: a consent window cannot show a long prompt); the client's
own credential headers are dropped and only a short list of headers passes
either way; the answer is streamed back through the Scrubber; one line goes
to the activity log. If the proxy dies, the program's calls fail (its base
URL points at a closed port): fail closed.
"""
from __future__ import annotations

import contextlib
import hmac
import http.client
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler

from . import broker, caps, httpd
from . import policy as route
from . import recipes as recipes_mod
from . import validate as _v
from .scrub import Scrubber, loosely_contains

# SDK base-URL variables checked against each official SDK's _client.py
# (openai-python, anthropic-sdk-python, groq-python, together-py), with the
# suffix that makes the SDK's own paths land on the recipe host's paths.
# Other recipes (openrouter, mistral, ...) still work at /<service>/... with
# --print-env, but no base-URL variable is set for them.
ENV = {"openai": ("OPENAI_BASE_URL", "/openai/v1"),
       "anthropic": ("ANTHROPIC_BASE_URL", "/anthropic"),
       "groq": ("GROQ_BASE_URL", "/groq"),
       "together": ("TOGETHER_BASE_URL", "/together")}
EXTRA_DROP = ("ANTHROPIC_AUTH_TOKEN",)     # makes the Anthropic SDK send its own Bearer

SAFE_WRITES = {"/v1/chat/completions", "/v1/completions", "/v1/responses",
               "/v1/messages", "/v1/messages/count_tokens", "/v1/embeddings",
               "/openai/v1/chat/completions", "/openai/v1/embeddings",
               "/api/v1/chat/completions"}
REQ_HEADERS = {"content-type", "accept", "anthropic-version", "anthropic-beta",
               "openai-beta", "idempotency-key"}
RESP_HEADERS = {"content-type", "retry-after", "request-id", "x-request-id"}
RESP_PREFIXES = ("x-ratelimit-", "anthropic-ratelimit-")
NO_PROXY_AUTH = {"oauth2_client_credentials", "aws_sigv4"}
MAX_BODY = 16_000_000          # a long chat history; nobody reviews it
MAX_CALLS = 100_000            # the caps in caps.json are the real limit
PER_MINUTE = 600
UPSTREAM_TIMEOUT = 300.0       # long model answers


def child_env(catalog: dict, base: str, token: str, environ=None) -> dict:
    env = dict(os.environ if environ is None else environ)
    for recipe in catalog.values():
        for var in recipes_mod.env_vars(recipe):
            env.pop(var, None)          # no real key reaches the program
    for var in EXTRA_DROP:
        env.pop(var, None)
    for service, (var, suffix) in ENV.items():
        if service in catalog:
            env[var] = base + suffix
            for key_var in recipes_mod.env_vars(catalog[service]):
                env[key_var] = token
    return env


def _given_token(headers) -> str:
    auth = headers.get("Authorization") or ""
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (headers.get("x-api-key") or headers.get("api-key") or "").strip()


def make_proxy(catalog: dict, get_values, token: str, policy: broker.Policy,
               audit=None, port: int = 0, resolver=None, connect=None,
               timeout: float = UPSTREAM_TIMEOUT):
    class Handler(BaseHTTPRequestHandler):
        server_version = "stuntkey"
        sys_version = ""
        timeout = 60

        def log_message(self, *a):
            pass

        def _fail(self, code: int, message: str) -> None:
            data = json.dumps({"error": {"type": "stuntkey", "message": message}}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _handle(self):
            if not httpd.local_only(self.headers, self.server.server_address[1]):
                return self._fail(403, "forbidden")
            if not hmac.compare_digest(_given_token(self.headers).encode(), token.encode()):
                return self._fail(401, "unauthorized: use the key stuntkey proxy gave you")
            service, _, rest = self.path.lstrip("/").partition("/")
            recipe = catalog.get(service)
            if not recipe:
                return self._fail(404, "unknown service; the path starts with /<service>/")
            path, _, query = ("/" + rest).partition("?")
            try:
                self._forward(recipe, self.command, path, query)
            except broker.BrokerError as e:
                self._fail(403 if e.code == 5 else 502, str(e))
            except (ValueError, KeyError):
                self._fail(400, "bad request")
            except TypeError:
                # A TypeError here is almost always OUR bug (a wrong call
                # signature), not a malformed request. Catching it as 400 "bad
                # request" is how a broken proxy ships looking healthy: a
                # signature change once made every call -- including STOP
                # kill-switch refusals -- return a generic 400, and the client
                # blamed itself. Fail loudly as a server error instead, and say
                # where to look.
                self._fail(500, "stuntkey internal error; run `stuntkey selftest`")
                raise

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        def _forward(self, recipe, method, path, query):
            service = recipe["service"]
            # Bound before the lambda so the closure can see it, and rebound at
            # the get_values() call below. _log scrubs the path with these, so
            # refusals that happen before a key is fetched log with none (there
            # is no secret in play yet), and everything after logs scrubbed.
            values = None
            log = lambda result, host="?", status=0, size=0, ms=0: broker._log(
                audit, recipe, values, method, host, path, status, size, result, ms=ms)
            try:
                host, url, body = self._check(recipe, method, path, query)
            except broker.BrokerError:
                log("refused")
                raise
            try:
                values = get_values(recipe)
            except Exception:
                log("refused")
                raise broker.BrokerError(f"no key is stored for '{service}'. Run "
                                         f"`stuntkey get {service}` first.", 5) from None
            spec = dict(recipe["validate"], url=url)
            req = _v._build_request(spec, broker.credentials(recipe, values))
            headers = {k: v for k, v in self.headers.items() if k.lower() in REQ_HEADERS}
            for k, v in req.header_items():          # static + credential headers win
                headers = {h: x for h, x in headers.items() if h.lower() != k.lower()}
                headers[k] = v
            parts = urllib.parse.urlsplit(req.full_url)
            target = parts.path + (f"?{parts.query}" if parts.query else "")
            try:
                ip = broker.resolve_public(host, 443, resolver)
                if audit is not None:
                    audit.ready()
            except broker.BrokerError:
                log("refused", host)
                raise
            started = time.time()
            try:
                conn, resp = broker.open_stream(host, ip, method, target, headers,
                                                body, timeout, connect)
            except broker.BrokerError:
                log("network-error", host)
                raise
            with contextlib.closing(conn):
                secrets_ = [v for v in values.values() if isinstance(v, str)]
                size, result = self._relay(resp, secrets_, service)
            log(result, host, resp.status, size, int((time.time() - started) * 1000))

        def _check(self, recipe, method, path, query):
            service = recipe["service"]
            if method not in broker.READ_METHODS | broker.WRITE_METHODS:
                raise broker.BrokerError("method not supported", 5)
            auth = (recipe.get("validate") or {}).get("auth", {}).get("type", "bearer")
            if auth in NO_PROXY_AUTH:
                raise broker.BrokerError(f"'{service}' signs its requests or needs a "
                                         "sign-in token; the proxy cannot carry it.", 5)
            policy.count()
            host, url = broker.build_url(
                recipe, path, dict(urllib.parse.parse_qsl(query, keep_blank_values=True)))
            if method in broker.WRITE_METHODS and path not in SAFE_WRITES:
                rules = route.load(policy.limits_home(), policy.project_dir or os.getcwd())
                if service not in rules:
                    raise broker.BrokerError(
                        f"The proxy only sends {method} to the usual AI endpoints (chat, "
                        f"responses, messages, embeddings), so {path[:80]} was not sent. A "
                        "person can allow it in stuntkey.policy and run `stuntkey policy "
                        "approve`.", 5)
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                raise broker.BrokerError("request body missing a length or too large", 5)
            if n and method in broker.READ_METHODS:
                raise broker.BrokerError("GET/HEAD may not have a body", 5)
            body = self.rfile.read(n) if n else None
            policy.gate(service, method, path, body)
            return host, url, body

        def _relay(self, resp, secrets_, service):
            enc = (resp.getheader("content-encoding") or "").lower()
            if enc not in ("", "identity"):
                raise broker.BrokerError("the API sent a compressed answer; not passed on", 7)
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                low = k.lower()
                if low in RESP_HEADERS or low.startswith(RESP_PREFIXES):
                    hs = Scrubber(secrets_)
                    val = (hs.feed(v.encode()) + hs.flush()).decode("utf-8", "replace")
                    if not loosely_contains(val, secrets_):
                        self.send_header(k, val)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            # ponytail: streamed bodies get the streaming Scrubber only, not the
            # whole-body disguise check (loosely_contains) broker.call adds.
            sc, meter, size, result = Scrubber(secrets_), caps.TokenMeter(
                resp.getheader("content-type") or ""), 0, "ok"
            try:
                while True:
                    chunk = resp.read1(8192)
                    if not chunk:
                        break
                    size += len(chunk)
                    meter.feed(chunk)
                    out = sc.feed(chunk)
                    if out:
                        self.wfile.write(out)
                        self.wfile.flush()
                self.wfile.write(sc.flush())
            except (OSError, http.client.HTTPException):
                result = "network-error"
            policy.add_tokens(service, meter.total())
            return size, result

    srv = httpd.DoorServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


# ---- commands --------------------------------------------------------------------

def add_parsers(sub) -> None:
    import argparse
    pr = sub.add_parser("proxy", help="Run a program with AI base URLs pointing at a "
                                      "local proxy; it never gets the real key.",
                        usage="stuntkey proxy [--env-file F] [--print-env] [-- COMMAND ...]")
    pr.add_argument("--env-file", default=".env")
    pr.add_argument("--print-env", action="store_true",
                    help="Print the variables to set and keep the proxy open "
                         "(for tools you start yourself).")
    pr.add_argument("command", nargs=argparse.REMAINDER)
    cp = sub.add_parser("caps", help="Show or set per-key call and token caps.")
    cps = cp.add_subparsers(dest="caps_cmd", required=True)
    cps.add_parser("show", help="Caps and today's usage.")
    cs = cps.add_parser("set", help="Set caps for one service (asks you first).")
    cs.add_argument("service")
    cs.add_argument("--calls-session", dest="calls_session", type=int)
    cs.add_argument("--calls-hour", dest="calls_hour", type=int,
                    help="Calls per clock hour: a quick brake for a runaway loop.")
    cs.add_argument("--calls-day", dest="calls_day", type=int)
    cs.add_argument("--tokens-day", dest="tokens_day", type=int)
    cs.add_argument("--tokens-call", dest="tokens_call", type=int,
                    help="Refuse a call that asks for more output tokens than this "
                         "(max_tokens and its spellings).")
    cs.add_argument("--clear", action="store_true", help="Remove this service's caps.")
    sub.add_parser("stop", help="Kill switch: no API call is made through stuntkey "
                                "until `stuntkey resume`.")
    sub.add_parser("resume", help="Undo `stuntkey stop` (asks you first).")
    po = sub.add_parser("policy", help="Show or approve the route policy (stuntkey.policy).")
    po.add_argument("policy_cmd", choices=["show", "approve"])


COMMANDS = {"proxy", "caps", "stop", "resume", "policy"}


def dispatch(args, catalog: dict):
    if args.cmd not in COMMANDS:
        return None
    from . import approve as approve_mod
    from . import remote
    home = remote.home_dir()
    try:
        if args.cmd == "caps":
            return caps.cmd_caps(args, home, approve_mod.ask_person)
        if args.cmd == "stop":
            return caps.cmd_stop(home)
        if args.cmd == "resume":
            return caps.cmd_resume(home, approve_mod.ask_person)
        if args.cmd == "policy":
            return _cmd_policy(args.policy_cmd, home, approve_mod.ask_person)
    except broker.BrokerError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    return cmd_proxy(catalog, args, home)


EXAMPLE = '{"openai": {"methods": ["GET", "POST"], "paths": ["/v1/chat/completions", "/v1/models"]}}'


def _cmd_policy(action: str, home: str, ask) -> int:
    if action == "approve":
        n = route.approve(home, os.getcwd(), ask)
        print(f"approved {n} policy file(s).")
        return 0
    rules = route.load(home, os.getcwd())
    if not rules:
        print(f"no route policy. To add one, write {route.user_file(home)} "
              f"(or ./{route.FILE}, which can only narrow it), e.g.\n  {EXAMPLE}\n"
              "then run `stuntkey policy approve`.")
    for service, (methods, paths) in sorted(rules.items()):
        print(f"  {service:14} {' '.join(sorted(methods)) or '(nothing)'}  "
              f"{' '.join(paths) or '(no paths)'}")
    return 0


def cmd_proxy(catalog: dict, args, home: str) -> int:
    from . import remote
    command = list(args.command or [])
    if command[:1] == ["--"]:
        command = command[1:]
    token = "ok-" + secrets.token_urlsafe(24)
    policy = broker.Policy(max_calls=MAX_CALLS, max_per_minute=PER_MINUTE)
    audit = broker.AuditLog(os.path.join(home, "audit.log"))
    srv = make_proxy(catalog, lambda r: remote.collect_values(r, args.env_file),
                     token, policy, audit)
    env = child_env(catalog, f"http://127.0.0.1:{srv.server_address[1]}", token)
    if args.print_env or not command:
        for service, (var, _s) in ENV.items():
            if service in catalog:
                print(f"{var}={env[var]}")
                for key_var in recipes_mod.env_vars(catalog[service]):
                    print(f"{key_var}={token}")
        print("stuntkey proxy is open (other services: /<service>/...). These "
              "values are not your keys. Ctrl+C to close.", file=sys.stderr)
        httpd.serve_forever(srv)
        return 0
    httpd.start_background(srv)
    try:
        return subprocess.call(command, env=env)
    except OSError as e:
        print(f"error: could not start {command[0]!r}: {e.strerror or e}", file=sys.stderr)
        return 127
    finally:
        srv.shutdown()
        srv.server_close()
