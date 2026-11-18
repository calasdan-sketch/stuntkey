"""`stuntkey selftest` - the tool attacks itself and shows pass or fail.

Everything here is local and harmless: a made-up key, a pretend server
(no network is used) and a throw-away log file. No real key is touched.

What it proves: the broker's rules hold against the attacks listed below,
and each refusal happens for the RIGHT reason (not just "something failed").
What it does NOT prove: that nothing else can go wrong, or that the real
network code, the web door, the MCP server or `run` are safe (see SECURITY.md).
"""
from __future__ import annotations

import base64
import codecs
import json
import os
import secrets
import tempfile
import threading
import unicodedata
import urllib.parse

from . import approve, broker, clipboard

HOST = "selftest.example"
PUBLIC_IP = "93.184.216.34"


def _recipe() -> dict:
    return {"service": "selftest", "display": "Selftest", "env_var": "SELFTEST_KEY",
            "fields": [{"env_var": "SELFTEST_KEY", "label": "key", "name": "key"}],
            "validate": {"method": "GET", "url": f"https://{HOST}/user",
                         "auth": {"type": "bearer"}, "expect": [200]}}


def _aws_recipe() -> dict:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "recipes", "aws.json"), encoding="utf-8") as f:
        return json.load(f)


def _resolver(*ips):
    def r(host, port, type=None):
        return [(2, 1, 6, "", (ip, port)) for ip in ips]
    return r


def _fake_server(body_fn, headers=None):
    """A pretend API. Records what it was sent and answers with body_fn()."""
    seen = []

    def send(req, ip, timeout):
        seen.append((req, ip))
        h = {"content-type": "application/json"}
        h.update(headers or {})
        return 200, h, body_fn(req)
    send.seen = seen
    return send


_HOME = None     # a throw-away ~/.stuntkey: the person's STOP file or caps never apply


def _pol(**kw):
    return broker.Policy(home=_HOME, project_dir=_HOME, **kw)


def _approve_all():
    return _pol(approve=lambda s: True)


def _call(key, send, path="/user", method="GET", policy=None, audit=None,
          resolver=None, query=None, body=None, recipe=None, values=None):
    return broker.call(recipe or _recipe(), values or {"SELFTEST_KEY": key}, method,
                       path, query, body, policy=policy or _approve_all(),
                       audit=audit, send=send, resolver=resolver or _resolver(PUBLIC_IP))


def _refused(fn, why: str) -> tuple[bool, str]:
    """Pass only if the call was refused AND the reason contains `why`."""
    try:
        fn()
    except broker.BrokerError as e:
        msg = str(e)
        if why.lower() in msg.lower():
            return True, f"refused: {msg[:70]}"
        return False, f"refused, but for the wrong reason: {msg[:70]}"
    return False, "it was ALLOWED"


# ---- "is the key still visible?" (independent of the scrubber's own check) ----

def _squash(text: str) -> str:
    t = unicodedata.normalize("NFKD", text.replace("\x00", ""))
    return "".join(c for c in t.lower() if c.isascii() and c.isalnum())


def _visible(key: str, shown: str) -> bool:
    if key in shown:
        return True
    sq = _squash(shown)
    raw = key.encode()
    candidates = [key, key[::-1], raw.hex(), urllib.parse.quote(key, safe=""),
                  urllib.parse.quote_plus(key), json.dumps(key)[1:-1],
                  codecs.encode(key, "rot13"), base64.b32encode(raw).decode()]
    for i in range(3):
        candidates.append(base64.b64encode(b"x" * i + raw).decode()[4:])
    for c in candidates:
        s = _squash(c)
        if len(s) >= 12 and s in sq:
            return True
    return False


def _leak_case(label, transform, ctype="application/json"):
    def run(key):
        def body(req):
            out = transform(key)
            return out if isinstance(out, bytes) else json.dumps({"echo": out}).encode()
        send = _fake_server(body, headers={"content-type": ctype})
        out = _call(key, send)
        shown = json.dumps(out, ensure_ascii=False)
        bad = _visible(key, shown)
        return (not bad), ("key not visible in the reply" if not bad else "KEY VISIBLE in the reply")
    return (f"A server that echoes the key back ({label}) is hidden", run)


def _leak_attacks():
    zw = "​"
    cases = [
        ("plain text", lambda k: k),
        ("base64", lambda k: base64.b64encode(k.encode()).decode()),
        ("base64, shifted by one byte", lambda k: base64.b64encode(b"x" + k.encode()).decode()),
        ("hex", lambda k: k.encode().hex()),
        ("upper-case hex", lambda k: k.encode().hex().upper()),
        ("URL-encoded", lambda k: urllib.parse.quote(k, safe="")),
        ("URL-encoded with +", lambda k: urllib.parse.quote_plus(k)),
        ("JSON-escaped", lambda k: json.dumps(k)),
        ("reversed", lambda k: k[::-1]),
        ("with dashes between letters", lambda k: "-".join(k)),
        ("with spaces between letters", lambda k: " ".join(k)),
        ("with dots between letters", lambda k: ".".join(k)),
        ("with invisible characters between letters", lambda k: zw.join(k)),
        ("upper-cased", lambda k: k.upper()),
        ("base32", lambda k: base64.b32encode(k.encode()).decode()),
        ("rot13", lambda k: codecs.encode(k, "rot13")),
        ("cut in two fields", lambda k: {"a": k[:len(k) // 2], "b": k[len(k) // 2:]}),
    ]
    out = [_leak_case(n, t) for n, t in cases]
    out.append(_leak_case("as UTF-16 text", lambda k: json.dumps({"e": k}).encode("utf-16-le"),
                          ctype="application/json; charset=utf-16"))
    return out


def _header_leak(key):
    send = _fake_server(lambda req: b"{}", headers={"content-type": "application/json; k=" + key})
    out = _call(key, send)
    return key not in json.dumps(out), "key not visible in the reply headers"


def _attack_reaches_api(key):
    send = _fake_server(lambda req: b"{}")
    _call(key, send)
    req, ip = send.seen[0]
    ok = (req.get_header("Authorization") == "Bearer " + key
          and urllib.parse.urlsplit(req.full_url).hostname == HOST and ip == PUBLIC_IP)
    return ok, "the key goes only to the recipe's own host, on the checked address"


def _paths():
    bad = [("/a/../b", ". or .. segments"), ("/a/./b", ". or .. segments"),
           ("//evil.example/x", "may not start with //"), ("/a%2fb", "encoding or character"),
           ("/a;x", "encoding or character"), ("/%252e%252e/x", "encoding or character"),
           ("/a\\b", "path must start with /"), ("http://evil.example/x", "path must start with /"),
           ("user", "path must start with /"), ("/a%00b", "encoding or character")]
    out = []
    for p, why in bad:
        def run(key, p=p, why=why):
            send = _fake_server(lambda req: b"{}")
            ok, detail = _refused(lambda: _call(key, send, path=p), why)
            return ok and not send.seen, detail
        out.append((f"Odd path {p!r} is refused", run))
    return out


def _private_ips():
    cases = [("127.0.0.1", ("127.0.0.1",)), ("10.0.0.5", ("10.0.0.5",)),
             ("192.168.1.9", ("192.168.1.9",)), ("0.0.0.0", ("0.0.0.0",)),
             ("100.64.0.1 (shared address space)", ("100.64.0.1",)),
             ("169.254.169.254 (cloud secrets)", ("169.254.169.254",)),
             ("::1", ("::1",)), ("fe80::1", ("fe80::1",)), ("fd00::1", ("fd00::1",)),
             ("::ffff:127.0.0.1", ("::ffff:127.0.0.1",)),
             ("64:ff9b::7f00:1 (127.0.0.1 inside IPv6)", ("64:ff9b::7f00:1",)),
             ("2002:7f00:1:: (127.0.0.1 inside IPv6)", ("2002:7f00:1::",)),
             ("public + private mixed (rebinding)", (PUBLIC_IP, "127.0.0.1"))]
    out = []
    for label, ips in cases:
        def run(key, ips=ips):
            send = _fake_server(lambda req: b"{}")
            ok, detail = _refused(lambda: _call(key, send, resolver=_resolver(*ips)),
                                  "private or internal")
            return ok and not send.seen, detail
        out.append((f"Server name pointing at {label} is refused", run))
    return out


def _override_query(key):
    send = _fake_server(lambda req: b"{}")
    ok, d = _refused(lambda: _call(key, send, query={"_method": "DELETE"}), "can change what a get")
    return ok and not send.seen, d


def _write_denied(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: False)
    ok, d = _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol,
                                   body={"a": 1}), "did not approve")
    return ok and not send.seen, d


def _write_no_prompt(key):
    send = _fake_server(lambda req: b"{}")
    ok, d = _refused(lambda: _call(key, send, method="DELETE", path="/x",
                                   policy=_pol(approve=None)), "did not approve")
    return ok and not send.seen, d


def _three_noes(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: False)
    for _ in range(3):
        _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol, body={}),
                 "did not approve")
    ok, d = _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol, body={}),
                     "said no three times")
    return ok and not send.seen, d


def _prompt_shows_everything(key):
    seen = []
    pol = _pol(approve=lambda s: (seen.append(s), True)[1])
    send = _fake_server(lambda req: b"{}")
    q = {f"p{i}": "v" for i in range(14)}
    _call(key, send, method="POST", path="/x", policy=pol, query=q, body={"danger": "yes"})
    text = seen[-1] if seen else ""
    ok = all(f"'p{i}'=" in text for i in range(14)) and "sha256" in text and "danger" in text
    return ok, "the approval text lists every parameter and the start of the body"


def _prompt_cannot_be_padded(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: True)
    q = {("junk" + "x" * 40 + str(i)): "y" * 60 for i in range(12)}
    ok, d = _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol,
                                   query=q, body={"a": 1}), "too long")
    return ok and not send.seen, d


def _query_value_not_cut(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: True)
    ok, d = _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol,
                                   query={"note": "a" * 300}), "too long")
    return ok and not send.seen, d


def _body_tail_not_cut(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: True)
    body = {"note": "harmless words " * 3 + "x" * 600 + " and a hostile tail"}
    ok, d = _refused(lambda: _call(key, send, method="POST", path="/x", policy=pol,
                                   body=body), "too long")
    return ok and not send.seen, d


def _refusals_use_the_limit(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: True, max_calls=3)
    for _ in range(3):
        _refused(lambda: _call(key, send, path="/a/../b", policy=pol), ". or ..")
    ok, d = _refused(lambda: _call(key, send, policy=pol), "limit of 3")
    return ok and not send.seen, d


def _read_with_body(key):
    send = _fake_server(lambda req: b"{}")
    ok, d = _refused(lambda: _call(key, send, body={"a": 1}), "may not have a body")
    return ok and not send.seen, d


def _flood(key):
    send = _fake_server(lambda req: b"{}")
    pol = _pol(approve=lambda s: True, max_calls=3)
    for _ in range(3):
        _call(key, send, policy=pol)
    ok, d = _refused(lambda: _call(key, send, policy=pol), "limit of 3")
    return ok and len(send.seen) == 3, d


def _aws_cases():
    vals = {"AWS_ACCESS_KEY_ID": "AKIA" + "ABCDEFGHIJKLMNOP",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + secrets.token_hex(5)}
    out = []
    for action in ("GetSessionToken", "AssumeRole", "GetFederationToken", "AssumeRoleWithSAML"):
        def run(key, action=action):
            send = _fake_server(lambda req: b"<x/>")
            ok, d = _refused(lambda: _call(key, send, path="/", recipe=_aws_recipe(), values=vals,
                                           query={"Action": action, "Version": "2011-06-15"}),
                             "create new keys")
            return ok and not send.seen, d
        out.append((f"AWS: '{action}' (makes new keys) is refused", run))

    def no_action(key):
        send = _fake_server(lambda req: b"<x/>")
        ok, d = _refused(lambda: _call(key, send, path="/", recipe=_aws_recipe(), values=vals),
                         "getcalleridentity")
        return ok and not send.seen, d
    out.append(("AWS: a request with no Action is refused", no_action))

    def allowed(key):
        send = _fake_server(lambda req: b"<x/>")
        _call(key, send, path="/", recipe=_aws_recipe(), values=vals,
              query={"Action": "GetCallerIdentity", "Version": "2011-06-15"})
        return len(send.seen) == 1, "the harmless look-up still works"
    out.append(("AWS: 'GetCallerIdentity' (who am I) still works", allowed))
    return out


def _log_tests():
    def with_log(fn):
        def run(key):
            d = tempfile.mkdtemp(prefix="stuntkey-selftest-")
            path = os.path.join(d, "audit.log")
            try:
                return fn(key, broker.AuditLog(path), path)
            finally:
                for name in os.listdir(d):
                    try:
                        os.remove(os.path.join(d, name))
                    except OSError:
                        pass
                try:
                    os.rmdir(d)
                except OSError:
                    pass
        return run

    def fill(key, log, n=4):
        send = _fake_server(lambda req: b"{}")
        for _ in range(n):
            _call(key, send, audit=log)

    def read(path):
        with open(path, encoding="utf-8") as f:
            return f.read().splitlines()

    def write(path, lines):
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    def keyless(key, log, path):
        send = _fake_server(lambda req: b"{}")
        for _ in range(3):
            _call(key, send, audit=log, query={"token": "x"})
        text = "\n".join(read(path))
        ok, n = log.verify()
        return (key not in text and "token" not in text and ok and n == 3), \
            "log holds no key and no query text, and verifies"

    def edited(key, log, path):
        fill(key, log)
        lines = read(path)
        lines[1] = lines[1].replace('"ok"', '"ok "')
        write(path, lines)
        return (not log.verify()[0]), "an edited log line is detected"

    def removed(key, log, path):
        fill(key, log)
        lines = read(path)
        del lines[1]
        write(path, lines)
        return (not log.verify()[0]), "a deleted log line is detected"

    def tail_cut(key, log, path):
        fill(key, log)
        write(path, read(path)[:-2])
        return (not log.verify()[0]), "cutting entries off the end is detected"

    def file_gone(key, log, path):
        fill(key, log)
        os.remove(path)
        return (not log.verify()[0]), "deleting the whole log is detected"

    def head_gone(key, log, path):
        fill(key, log)
        os.remove(log.anchor_path)
        write(path, read(path)[:-2])
        return (not log.verify()[0]), "deleting the end-marker file and cutting the log is detected"

    def junk(key, log, path):
        fill(key, log)
        with open(path, "a", encoding="utf-8") as f:
            f.write('{"fake": "entry"}\n')
        return (not log.verify()[0]), "a forged extra line is detected"

    def unwritable(key, log, path):
        send = _fake_server(lambda req: b"{}")
        bad = broker.AuditLog(os.path.dirname(path))     # a folder cannot be a file
        ok, d = _refused(lambda: _call(key, send, audit=bad), "cannot be written")
        return ok and not send.seen, d

    def refusals_logged(key, log, path):
        send = _fake_server(lambda req: b"{}")
        _refused(lambda: _call(key, send, path="/a/../b", audit=log), ". or ..")
        ok, n = log.verify()
        return (ok and n == 1 and "refused" in "\n".join(read(path))), \
            "a refused request is written to the log"

    def stays_broken(key, log, path):
        fill(key, log)
        write(path, read(path)[:-2])
        send = _fake_server(lambda req: b"{}")
        _call(key, send, audit=log)              # later calls must not
        _call(key, send, audit=log)              # make the log look healthy
        text = "\n".join(read(path))
        return (not log.verify()[0] and "LOG-PROBLEM-FOUND" in text), \
            "after a cut, later calls cannot make the log look healthy again"

    return [("The activity log holds no key", with_log(keyless)),
            ("After tampering the log stays flagged, even after more calls",
             with_log(stays_broken)),
            ("Editing the activity log is detected", with_log(edited)),
            ("Deleting from the activity log is detected", with_log(removed)),
            ("Cutting the end off the activity log is detected", with_log(tail_cut)),
            ("Deleting the activity log file is detected", with_log(file_gone)),
            ("Deleting the end-marker file as well as cutting the log is detected",
             with_log(head_gone)),
            ("A forged extra log line is detected", with_log(junk)),
            ("If the log cannot be written, nothing is sent", with_log(unwritable)),
            ("Refused requests are recorded in the log", with_log(refusals_logged))]


def _helpers():
    def popup_ignores_path(key):
        import inspect
        src = inspect.getsource(approve)
        return ("shutil.which" not in src), "the approval pop-up is never looked up on PATH"

    def tool_needs_absolute(key):
        return approve._tool("zenity", "./kdialog") is None, \
            "a program named in the current folder is not trusted"

    def url_not_a_key(key):
        return (not clipboard.looks_like("https://evil.example/x?a=1", None)
                and clipboard.looks_like("sk_live_" + "a1b2c3d4e5" * 3, None)), \
            "a copied web address is not taken as a key"
    return [("The approval pop-up is found by full path, not PATH", popup_ignores_path),
            ("A look-alike program in the current folder is not trusted", tool_needs_absolute),
            ("Copy-and-go does not take a web address as a key", url_not_a_key)]


def _proxy_attacks():
    """The base-URL proxy, on 127.0.0.1 with a pretend upstream (no network)."""
    import http.client
    import io
    from . import proxy

    class Resp(io.BytesIO):
        status = 200

        def getheader(self, name, default=None):
            return {"content-type": "text/event-stream"}.get(name.lower(), default)

        def getheaders(self):
            return [("Content-Type", "text/event-stream")]

    def run(key, path="/selftest/v1/chat/completions", auth=None, headers=None):
        seen = []

        class Conn:
            def __init__(self, host, timeout=None):
                pass

            def request(self, method, target, body=None, headers=None):
                seen.append((method, target, dict(headers or {})))

            def getresponse(self):
                return Resp(("data: " + json.dumps({"echo": key}) + "\n\n").encode())

            def close(self):
                pass
        tok = "ok-" + secrets.token_urlsafe(16)
        recipe = _recipe()
        srv = proxy.make_proxy({"selftest": recipe}, lambda r: {"SELFTEST_KEY": key},
                               tok, _pol(max_calls=50), resolver=_resolver(PUBLIC_IP),
                               connect=Conn)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            h = {"Authorization": f"Bearer {auth or tok}", "Content-Type": "application/json"}
            h.update(headers or {})
            c.request("POST", path, body=b"{}", headers=h)
            r = c.getresponse()
            return r.status, r.read().decode("utf-8", "replace"), seen
        finally:
            srv.shutdown()
            srv.server_close()

    def wrong_token(key):
        status, _b, seen = run(key, auth="ok-guess")
        return status == 401 and not seen, "a wrong proxy key is refused"

    def odd_write(key):
        status, _b, seen = run(key, path="/selftest/v1/files")
        return status == 403 and not seen, "a write to a non-LLM endpoint is refused"

    def echo_hidden(key):
        status, body, _s = run(key)
        return status == 200 and not _visible(key, body), "a key echoed in a stream is hidden"

    def client_auth_dropped(key):
        _st, _b, seen = run(key, headers={"Cookie": "c=1", "X-Api-Key": "mine"})
        sent = {k.lower(): v for k, v in (seen[0][2] if seen else {}).items()}
        return (bool(seen) and sent.get("authorization") == f"Bearer {key}"
                and "cookie" not in sent and "x-api-key" not in sent),             "the program's own credential headers are not passed on"
    return [("A wrong proxy key is refused", wrong_token),
            ("A write to a non-LLM endpoint through the proxy is refused", odd_write),
            ("A key echoed in a streamed answer is hidden", echo_hidden),
            ("The program's own credential headers are not passed on", client_auth_dropped)]


def _sections():
    return [
        ("Key leaks", _leak_attacks() + [
            ("A server that echoes the key in a header is hidden", _header_leak),
            ("The key reaches only the recipe's own server", _attack_reaches_api)]),
        ("Addresses and paths", _paths() + _private_ips() + [
            ("A query that changes the HTTP method is refused", _override_query)]),
        ("Approval and limits", [
            ("A write is refused when the person says no", _write_denied),
            ("A write is refused when no one can be asked", _write_no_prompt),
            ("After three 'no' answers, nothing more is sent", _three_noes),
            ("The approval text shows every parameter and the body", _prompt_shows_everything),
            ("A request padded to hide its body from the approval text is refused",
             _prompt_cannot_be_padded),
            ("A long query value is refused, never shown cut off", _query_value_not_cut),
            ("A long body is refused, never shown cut off", _body_tail_not_cut),
            ("A read request with a body is refused", _read_with_body),
            ("A flood of calls is stopped at the limit", _flood),
            ("Refused requests count toward the limit too", _refusals_use_the_limit)]),
        ("AWS key-minting", _aws_cases()),
        ("Activity log", _log_tests()),
        ("Helper programs", _helpers()),
        ("Base-URL proxy", _proxy_attacks()),
    ]


def attacks():
    return [pair for _g, items in _sections() for pair in items]


def run_all() -> list[dict]:
    global _HOME
    with tempfile.TemporaryDirectory(prefix="oksel") as home:
        _HOME = home
        try:
            return _run_all()
        finally:
            _HOME = None


def _run_all() -> list[dict]:
    # a made-up key with awkward characters, used nowhere else
    key = "sk_selftest_" + secrets.token_hex(12) + "+/=&%"
    results = []
    for group, items in _sections():
        for name, fn in items:
            try:
                ok, detail = fn(key)
            except Exception as e:                       # a crash is a failure
                ok, detail = False, f"crashed: {type(e).__name__}: {str(e)[:60]}"
            results.append({"group": group, "attack": name, "pass": bool(ok),
                            "detail": detail})
    return results


CACHE_NAME = "selftest-cache.json"
CACHE_SECONDS = 600         # a clean result is reused for ten minutes, no longer


def attack_count() -> int:
    try:
        return len(attacks())
    except Exception:           # noqa: BLE001 - only a number for a message
        return 0


def _code_stamp() -> str:
    """Changes when stuntkey's own files change, so an edit is never hidden
    behind an old clean result."""
    import hashlib
    from . import __version__
    here = os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256()
    h.update(__version__.encode("utf-8"))
    try:
        for root, dirs, files in os.walk(here):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(root, name)
                h.update(os.path.relpath(full, here).replace("\\", "/").encode("utf-8"))
                h.update(b"\0")
                try:
                    with open(full, "rb") as f:
                        h.update(f.read())
                except OSError:
                    h.update(b"unreadable")
                h.update(b"\0")
    except OSError:
        h.update(b"walk-failed")
    return f"{__version__}|{h.hexdigest()}"


def _cache_path() -> str:
    from . import remote
    return os.path.join(remote.home_dir(), CACHE_NAME)


def checked(say=None, use_cache: bool = True, now=None) -> tuple:
    """(passed, total, from_cache). Runs the attack tests, saying one line
    first (`say(text)`), unless a clean result from the last few minutes is
    still good: same stuntkey files, and only a full pass is ever kept. A
    replaced run_all (a test) is never cached."""
    import time
    now = now or time.time
    real = getattr(run_all, "__module__", "") == __name__
    path = _cache_path() if (use_cache and real) else None
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                c = json.load(f)
            if (c.get("stamp") == _code_stamp() and c.get("passed") == c.get("total")
                    and 0 <= now() - float(c.get("at", 0)) < CACHE_SECONDS):
                return int(c["passed"]), int(c["total"]), True
        except (OSError, ValueError, TypeError, KeyError):
            pass
    if say is not None:
        n = attack_count()
        say(f"Checking {n} attack tests (about 6 seconds)..." if n
            else "Checking the attack tests (about 6 seconds)...")
    results = run_all()
    passed = sum(1 for r in results if r["pass"])
    if path and passed == len(results):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"stamp": _code_stamp(), "at": now(), "passed": passed,
                           "total": len(results)}, f)
        except OSError:
            pass
    return passed, len(results), False


BETA_NOTICE = ("Beta: not independently security-reviewed yet. "
               "Use at your own risk; MIT, no warranty.")


def cmd_selftest(as_json: bool = False, verbose: bool = False) -> int:
    results = run_all()
    failed = [r for r in results if not r["pass"]]
    if as_json:
        print(json.dumps({"passed": len(results) - len(failed), "total": len(results),
                          "results": results}))
    else:
        print("\nstuntkey selftest - attacking itself with a made-up key and a "
              "pretend server\n(no network, no real key used)\n" + BETA_NOTICE + "\n")
        groups = []
        for r in results:
            if r["group"] not in groups:
                groups.append(r["group"])
        for g in groups:
            rs = [r for r in results if r["group"] == g]
            good = sum(1 for r in rs if r["pass"])
            print(f"  {g:<22} {good} of {len(rs)} stopped")
            for r in rs:
                if verbose or not r["pass"]:
                    print(f"      {'PASS' if r['pass'] else 'FAIL'}  {r['attack']}")
                    if not r["pass"]:
                        print(f"            -> {r['detail']}")
        print(f"\n{len(results) - len(failed)} of {len(results)} attacks stopped.")
        if failed:
            print("Some attacks got through. Please report this (see https://github.com/calasdan-sketch/stuntkey/blob/main/SECURITY.md).\n")
        else:
            print("These are simulated attacks on stuntkey's rules, using a pretend "
                  "server. They do not\ntest the live network layer, and cannot show "
                  "that nothing else can go wrong. See https://github.com/calasdan-sketch/stuntkey/blob/main/SECURITY.md\n"
                  "(Add --verbose to see every attack.)\n")
    return 1 if failed else 0
