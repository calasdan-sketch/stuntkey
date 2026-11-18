"""`stuntkey verify`: prove, on this computer, that the safety promises hold.

It starts stuntkey's own proxy for a moment on a spare port, in a throwaway
folder, with a MADE-UP key and a pretend service (nothing real is used, nothing
goes out of this computer), and checks three things:

  1. a request with no password, or the wrong one, is refused;
  2. the answer and the environment of a program stuntkey starts hold no key;
  3. with the proxy switched off, a call fails with a clear error and there is
     no key lying around for the program to fall back on.

One plain line per check; exit 0 when all pass, 1 when one fails. Never prints
a key: the made-up key is checked for, not shown.
"""
from __future__ import annotations

import contextlib
import http.client
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("104.18.6.192", port))]   # noqa: E731


class _Upstream(BaseHTTPRequestHandler):
    """The pretend service: it answers and, to make the test hard, tries to
    echo back the key it was sent (in the body and in a header)."""
    hits: list = []

    def log_message(self, *a):
        pass

    def _answer(self):
        size = int(self.headers.get("Content-Length") or 0)
        if size:
            self.rfile.read(min(size, 100_000))
        sent = self.headers.get("Authorization", "")
        type(self).hits.append(sent)
        body = json.dumps({"ok": True, "you_sent": sent}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Echo", sent)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _answer

    def do_POST(self):
        self._answer()


@contextlib.contextmanager
def _throwaway_home():
    """Point every 'home' lookup at a temporary folder while the check runs,
    so nothing here can touch the real ~/.stuntkey, whatever it is."""
    folder = tempfile.mkdtemp(prefix="skverify")
    names = ("USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA")
    saved = {n: os.environ.get(n) for n in names}
    for n in names:
        os.environ[n] = folder
    try:
        yield folder
    finally:
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v
        shutil.rmtree(folder, ignore_errors=True)


def _request(port: int, method: str, path: str, token: str | None, body: bytes = b"{}"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read().decode("utf-8", "replace")
        return r.status, data, str(list(r.getheaders()))
    finally:
        conn.close()


def run_checks() -> list:
    """[{"name", "ok", "text"}], three checks. Never raises."""
    from . import broker, proxy
    from . import recipes as recipes_mod
    fake = "sk-verify-" + secrets.token_hex(16)
    results: list = []

    def add(name: str, ok: bool, text: str) -> None:
        results.append({"name": name, "ok": bool(ok), "text": text})

    try:
        catalog = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        service = next((s for s in ("openai", "anthropic") if s in catalog
                        and proxy.proxyable(catalog[s])),
                       next((s for s, r in sorted(catalog.items()) if proxy.proxyable(r)), None))
        if service is None:
            raise RuntimeError("no service that the proxy can carry")
        recipe = catalog[service]
        var = recipes_mod.env_vars(recipe)[0]
        with _throwaway_home() as home:
            _Upstream.hits = []
            up = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
            threading.Thread(target=up.serve_forever, daemon=True).start()
            tokens = proxy.mint_tokens(catalog)
            policy = broker.Policy(home=home, project_dir=home, max_calls=100)
            connect = lambda host, timeout: http.client.HTTPConnection(   # noqa: E731
                "127.0.0.1", up.server_address[1], timeout=timeout)
            srv = proxy.make_proxy(catalog, lambda r: {var: fake}, tokens, policy, None,
                                   port=0, resolver=PUBLIC, connect=connect)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            path = f"/{service}/v1/chat/completions"
            stopped = False
            try:
                # 1. no password, and a wrong one
                none_status = _request(port, "POST", path, None)[0]
                wrong_status = _request(port, "POST", path, "not-the-password")[0]
                reached = len(_Upstream.hits)
                refused = none_status in (401, 403) and wrong_status in (401, 403) and reached == 0
                add("refuses strangers", refused,
                    "A request with no password, or the wrong one, was refused and nothing "
                    "reached the service." if refused else
                    f"A request without the right password was NOT refused (answers "
                    f"{none_status} and {wrong_status}).")
                # 2. the answer and the program's environment hold no key
                status, body, heads = _request(port, "POST", path, tokens[service])
                got_key = bool(_Upstream.hits) and fake in _Upstream.hits[-1]
                leaked = fake in body or fake in heads
                env = proxy.child_env(catalog, f"http://127.0.0.1:{port}", tokens)
                child_leak, child_note = False, ""
                try:
                    done = subprocess.run(
                        [sys.executable, "-c",
                         "import os, json; print(json.dumps(dict(os.environ)))"],
                        env=env, capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
                    seen = done.stdout.decode("utf-8", "replace")
                    child_leak = fake in seen or env.get(var) == fake
                    if done.returncode != 0:
                        child_note = " (the test program could not start, so its environment was checked directly)"
                        child_leak = any(fake in str(v) for v in env.values())
                except (OSError, subprocess.SubprocessError):
                    child_note = " (the test program could not start, so its environment was checked directly)"
                    child_leak = any(fake in str(v) for v in env.values())
                ok2 = status == 200 and got_key and not leaked and not child_leak
                if ok2:
                    text = ("The service got the key, but the answer and the environment of a "
                            "program stuntkey starts hold none of it" + child_note + ".")
                elif status != 200 or not got_key:
                    text = (f"The pretend call did not go through as expected (answer {status}), "
                            "so this could not be checked.")
                else:
                    text = "The key showed up in the answer or in a program's environment."
                add("hides the key", ok2, text)
            finally:
                srv.shutdown()
                srv.server_close()
                up.shutdown()
                up.server_close()
                stopped = True
            # 3. proxy off: a clear failure, and no key to fall back on
            try:
                _request(port, "POST", path, tokens[service])
                add("fails safe", False, "With the proxy off, a call still got an answer.")
            except (ConnectionError, OSError, http.client.HTTPException):
                no_fallback = fake not in "".join(str(v) for v in env.values())
                add("fails safe", stopped and no_fallback,
                    "With the proxy off, the call failed (nothing answered) and no key was "
                    "left in the program's environment to fall back on." if no_fallback else
                    "With the proxy off, the call failed but a key was left in the "
                    "program's environment.")
    except Exception as e:      # noqa: BLE001 - a check must answer, not crash
        have = {r["name"] for r in results}
        for name in ("refuses strangers", "hides the key", "fails safe"):
            if name not in have:
                add(name, False, f"Could not run this check ({type(e).__name__}).")
    return results


def cmd_verify(args=None, out=None) -> int:
    out = out or sys.stdout
    results = run_checks()
    ok = all(r["ok"] for r in results)
    if getattr(args, "json", False):
        out.write(json.dumps({"ok": ok, "checks": results}, indent=2) + "\n")
    else:
        out.write("\n  stuntkey verify: a pretend service, a made-up key, nothing leaves "
                  "this computer.\n")
        for r in results:
            out.write(f"  {'PASS' if r['ok'] else 'FAIL'}: {r['text']}\n")
        out.write("  " + ("All three checks passed." if ok else
                          "Something did not hold. Run `stuntkey doctor`, and do not "
                          "rely on stuntkey until this passes.") + "\n")
    return 0 if ok else 1
