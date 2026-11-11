"""Round 14, proxy seat: per-service placeholders, session grants (time limit,
revoke), --max-calls, plain refusals.

Safety: synthetic keys only; HOME etc. redirected by `import _isolation`; the
keychain is the in-memory one; every session folder lives in a temp dir; the
real approval windows are stubs that fail the test if called.
"""
import base64
import http.client
import json
import os
import socket
import sys
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import approve, broker, caps, proxy, recipes
from stuntkey import session as sess

CATALOG = recipes.load_recipes()
CANARY = "sk-" + "FAKE0000TEST1111CANARY2222abcd3333"
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("104.18.6.192", port))]


def _no_window(*a, **k):
    raise AssertionError("a REAL approval window / console prompt was requested")


class Upstream(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        Upstream.hits.append(self.path)
        data = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class _Base(unittest.TestCase):
    def setUp(self):
        os.environ["STUNTKEY_KEYCHAIN"] = "memory"
        for name in ("console", "dialog"):
            p = mock.patch.object(approve, name, _no_window)
            p.start()
            self.addCleanup(p.stop)
        approve._shown.clear()
        self.addCleanup(approve._shown.clear)
        Upstream.hits = []
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.home = _isolation.mktemp()
        self.clock = Clock()
        self.tokens = proxy.mint_tokens(CATALOG)

    def start(self, ttl=3600.0, max_calls=0, tunnel=None, session=True):
        self.pol = proxy.RunPolicy(home=self.home, project_dir=self.home, max_calls=100,
                                   run_cap=max_calls)
        self.audit = broker.AuditLog(os.path.join(self.home, "audit.log"))
        self.guard = (sess.create(self.home, self.tokens, ttl, max_calls, clock=self.clock)
                      if session else None)
        connect = lambda host, timeout: http.client.HTTPConnection(
            "127.0.0.1", self.up.server_address[1], timeout=timeout)
        self.srv = proxy.make_proxy(
            CATALOG, lambda r: {recipes.env_vars(r)[0]: CANARY}, self.tokens, self.pol,
            self.audit, resolver=PUBLIC, connect=connect, tunnel=tunnel, session=self.guard,
            tunnel_connect=lambda ip, port: socket.create_connection(("127.0.0.1", 9), 1))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (self.srv.shutdown(), self.srv.server_close(),
                                 self.up.shutdown(), self.up.server_close()))

    def post(self, service, token, path="/v1/chat/completions"):
        if service == "openai":
            path = "/v1/chat/completions"
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", f"/{service}{path}", body=b"{}",
                  headers={"Authorization": "Bearer " + token,
                           "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read().decode()

    def audit_text(self):
        with open(self.audit.path, encoding="utf-8") as f:
            return f.read()


class Placeholders(_Base):
    def test_one_per_service_right_shape_and_nothing_real(self):
        t = self.tokens
        self.assertEqual(len(set(t.values())), len(t))
        self.assertTrue(t["openai"].startswith("sk_ph_openai_"))
        self.assertTrue(t[sess.TUNNEL].startswith("sk_ph_tunnel_"))
        for v in t.values():
            self.assertRegex(v, r"^sk_ph_[a-z0-9]+_[A-Za-z0-9_-]{20,}$")
            self.assertNotIn("FAKE0000", v)

    def test_environment_gets_each_services_own_placeholder(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:5", self.tokens, {}, tunnel=True,
                              generic=True)
        self.assertEqual(env["OPENAI_API_KEY"], self.tokens["openai"])
        self.assertEqual(env["ANTHROPIC_API_KEY"], self.tokens["anthropic"])
        self.assertNotEqual(env["OPENAI_API_KEY"], env["ANTHROPIC_API_KEY"])
        self.assertIn(self.tokens[sess.TUNNEL] + "@127.0.0.1:5", env["HTTPS_PROXY"])
        self.assertNotIn("FAKE0000", json.dumps(env))

    def test_a_placeholder_works_for_its_own_service_only(self):
        self.start()
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)
        status, text = self.post("anthropic", self.tokens["openai"], "/v1/messages")
        self.assertEqual(status, 403)
        self.assertIn("'openai'", text)
        self.assertNotIn(CANARY, text)
        self.assertEqual(Upstream.hits, ["/v1/chat/completions"])     # only the good one went
        self.assertIn("refused-wrong-placeholder", self.audit_text())  # and the bad one is counted
        # the tunnel's password is not a key for any service either
        self.assertEqual(self.post("openai", self.tokens[sess.TUNNEL])[0], 403)

    def test_unknown_placeholder_says_run_again(self):
        self.start()
        status, text = self.post("openai", "sk_ph_openai_stale0000000000000000")
        self.assertEqual(status, 401)
        self.assertIn("Run your program again", text)

    def test_one_string_token_still_works_for_every_service(self):
        self.start(session=False)
        self.srv.shutdown()
        old = proxy.make_proxy(CATALOG, lambda r: {recipes.env_vars(r)[0]: CANARY},
                               "ok-legacy-token-000000", self.pol, self.audit,
                               resolver=PUBLIC)
        threading.Thread(target=old.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (old.shutdown(), old.server_close()))
        c = http.client.HTTPConnection("127.0.0.1", old.server_address[1], timeout=5)
        c.request("GET", "/nosuch/x", headers={"Authorization": "Bearer ok-legacy-token-000000"})
        self.assertEqual(c.getresponse().status, 404)        # passed the password check

    def test_error_answers_close_the_connection(self):
        self.start()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", "/openai/v1/chat/completions", body=b"x" * 5000,
                  headers={"Authorization": "Bearer nope"})
        r = c.getresponse()
        self.assertEqual(r.status, 401)
        self.assertEqual(r.getheader("Connection"), "close")


class Tunnel(_Base):
    def connect(self, target, password):
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        auth = base64.b64encode(f"stuntkey:{password}".encode()).decode()
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                  f"Proxy-Authorization: Basic {auth}\r\n\r\n".encode())
        s.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                break
            head += chunk
        s.close()
        return head.split(b"\r\n")[0]

    def test_tunnel_and_service_placeholders(self):
        hosts = proxy.tunnel_hosts(CATALOG, [], only_services={"github", "openai"})
        self.start(tunnel=hosts)
        # a service placeholder is refused for another service's host
        line = self.connect("api.github.com:443", self.tokens["openai"])
        self.assertIn(b" 403 ", line)
        self.assertIn("refused-wrong-placeholder", self.audit_text())
        # nothing real or valid: 407
        self.assertIn(b" 407 ", self.connect("api.github.com:443", "sk_ph_x_nope"))
        # the right service placeholder and the tunnel password both pass the password
        # check (the fake upstream then fails to connect: 502, not 403/407)
        self.assertIn(b" 502 ", self.connect("api.github.com:443", self.tokens["github"]))
        self.assertIn(b" 502 ", self.connect("api.github.com:443", self.tokens[sess.TUNNEL]))


class Sessions(_Base):
    def test_time_limit_uses_the_injected_clock(self):
        self.start(ttl=60)
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)
        self.clock.t += 61
        status, text = self.post("openai", self.tokens["openai"])
        self.assertEqual(status, 401)
        self.assertIn("session has ended", text)
        self.assertIn("time ran out", text)
        self.assertEqual(Upstream.hits, ["/v1/chat/completions"])
        # once ended, always ended (even if the clock were set back)
        self.clock.t -= 120
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 401)

    def test_ttl_zero_means_no_limit(self):
        self.start(ttl=0)
        self.clock.t += 10 ** 9
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)

    def test_revoke_all_stops_every_service_at_once(self):
        self.start()
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)
        rc = sess.cmd_revoke(types.SimpleNamespace(all=True, service=None), self.home)
        self.assertEqual(rc, 0)
        status, text = self.post("openai", self.tokens["openai"])
        self.assertEqual(status, 401)
        self.assertIn("revoke", text)
        self.assertEqual(len(Upstream.hits), 1)

    def test_revoke_one_service_leaves_the_others(self):
        self.start()
        self.assertEqual(sess.revoke(self.home, "openai"), 1)
        status, text = self.post("openai", self.tokens["openai"])
        self.assertEqual(status, 401)
        self.assertIn("'openai'", text)
        # another service is still served (it reaches the fake upstream)
        self.assertEqual(self.post("groq", self.tokens["groq"], "/v1/chat/completions")[0], 200)

    def test_revoke_needs_a_target(self):
        self.assertEqual(sess.cmd_revoke(types.SimpleNamespace(all=False, service=None),
                                         self.home), 2)
        self.assertEqual(sess.cmd_revoke(types.SimpleNamespace(all=True, service="x"),
                                         self.home), 2)
        self.assertEqual(sess.cmd_revoke(types.SimpleNamespace(all=False, service="a b"),
                                         self.home), 2)

    def test_a_forged_file_is_not_believed(self):
        self.start()
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)
        # someone who can write the folder replaces the file with a made-up one
        with open(self.guard.path, encoding="utf-8") as f:
            doc = json.load(f)
        doc["expires"] = 0
        doc["revoked"] = []
        doc["mac"] = "0" * 64
        with open(self.guard.path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        status, text = self.post("openai", self.tokens["openai"])
        self.assertEqual(status, 401)
        self.assertIn("changed from outside", text)

    def test_putting_an_old_signed_copy_back_does_not_undo_a_revoke(self):
        self.start()
        with open(self.guard.path, "rb") as f:
            old = f.read()
        sess.revoke(self.home, "openai")
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 401)  # proxy saw it
        with open(self.guard.path, "wb") as f:                                 # replay
            f.write(old)
        self.assertEqual(self.post("groq", self.tokens["groq"])[0], 401)       # whole run ends

    def test_a_file_made_without_the_secret_is_listed_as_not_trusted(self):
        os.makedirs(sess.sessions_dir(self.home), exist_ok=True)
        with open(os.path.join(sess.sessions_dir(self.home), "4242.json"), "w") as f:
            json.dump({"v": 1, "pid": os.getpid(), "gen": 1, "services": ["openai"],
                       "hashes": {}, "revoked": [], "expires": 0, "mac": "00"}, f)
        rows = sess.list_sessions(self.home, self.clock)
        self.assertEqual([r["state"] for r in rows], ["not-trusted"])

    def test_two_runs_at_once_have_their_own_files_and_both_are_revoked(self):
        t2 = proxy.mint_tokens(CATALOG)
        g1 = sess.create(self.home, self.tokens, 600, clock=self.clock)
        g2 = sess.create(self.home, t2, 1200, 5, clock=self.clock)
        self.assertNotEqual(g1.path, g2.path)
        rows = sess.list_sessions(self.home, self.clock)
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(r["max_calls"] for r in rows), [0, 5])
        g1.check("openai")
        g2.check("openai")
        sess.revoke(self.home, "openai")
        for g in (g1, g2):
            with self.assertRaises(sess.SessionEnded):
                g.check("openai")
            g.check("groq")
        sess.revoke(self.home)
        for g in (g1, g2):
            with self.assertRaises(sess.SessionEnded):
                g.check("groq")
        self.assertEqual(sess.list_sessions(self.home, self.clock), [])

    def test_two_proxies_have_separate_placeholders(self):
        # a second run's placeholder is not accepted by the first run's proxy
        self.start()
        other = proxy.mint_tokens(CATALOG)
        self.assertEqual(self.post("openai", other["openai"])[0], 401)

    def test_sessions_listing_shows_services_and_never_placeholders(self):
        self.start(ttl=7200, max_calls=9)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = sess.cmd_sessions(types.SimpleNamespace(), self.home, self.clock)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("openai", out)
        self.assertIn("max 9 calls", out)
        self.assertIn("2h 0m left", out)
        self.assertIn(str(os.getpid()), out)
        for t in self.tokens.values():
            self.assertNotIn(t, out)
        with open(self.guard.path, encoding="utf-8") as f:
            raw = f.read()
        for t in self.tokens.values():
            self.assertNotIn(t, raw)                  # only fingerprints on disk

    def test_stale_sessions_of_dead_processes_are_cleaned(self):
        g = sess.create(self.home, self.tokens, 600, pid=2_000_000_000, clock=self.clock)
        self.assertTrue(os.path.exists(g.path))
        with mock.patch.object(sess, "pid_alive", lambda pid: False):
            self.assertEqual(sess.list_sessions(self.home, self.clock), [])
        self.assertFalse(os.path.exists(g.path))

    def test_no_signing_secret_means_no_run(self):
        with mock.patch.object(sess, "_key", lambda home, create: None):
            with self.assertRaises(sess.SessionError):
                sess.create(self.home, self.tokens)

    def test_parse_ttl(self):
        self.assertEqual(sess.parse_ttl("30m"), 1800)
        self.assertEqual(sess.parse_ttl("2h"), 7200)
        self.assertEqual(sess.parse_ttl("90s"), 90)
        self.assertEqual(sess.parse_ttl("1d"), 86400)
        self.assertEqual(sess.parse_ttl("0"), 0)
        self.assertEqual(sess.parse_ttl("15"), 900)
        for bad in ("", "-5m", "5x", "m", "1.5h", "abc"):
            with self.assertRaises(ValueError):
                sess.parse_ttl(bad)


class MaxCalls(_Base):
    def test_run_stops_at_the_limit_with_plain_words(self):
        self.start(max_calls=2)
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)
        self.assertEqual(self.post("openai", self.tokens["openai"])[0], 200)
        status, text = self.post("openai", self.tokens["openai"])
        self.assertEqual(status, 403)
        self.assertIn("--max-calls", text)
        self.assertEqual(len(Upstream.hits), 2)


class CmdProxy(_Base):
    def args(self, **kw):
        base = dict(command=["--", sys.executable, "-c", "pass"], env_file=".env",
                    print_env=False, keep_env=None, map=None, generic=False, tunnel=False,
                    allow_host=None, ttl=None, max_calls=None, port=0)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_bad_ttl_and_bad_max_calls_are_plain_errors(self):
        for kw in ({"ttl": "soon"}, {"max_calls": 0}):
            self.assertEqual(proxy.cmd_proxy(CATALOG, self.args(**kw), self.home), 2)

    def test_child_gets_per_service_placeholders_and_the_file_is_removed_after(self):
        out = os.path.join(self.home, "env.json")
        code = ("import os,json,sys; json.dump(dict(os.environ), open(sys.argv[1],'w'));"
                "print(sorted(os.listdir(sys.argv[2])))")
        a = self.args(command=["--", sys.executable, "-c", code, out,
                               os.path.join(self.home, "sessions")], ttl="30m")
        with mock.patch("stuntkey.remote.collect_values",
                        lambda r, f: {"OPENAI_API_KEY": CANARY}):
            self.assertEqual(proxy.cmd_proxy(CATALOG, a, self.home), 0)
        with open(out, encoding="utf-8") as f:
            env = json.load(f)
        self.assertTrue(env["OPENAI_API_KEY"].startswith("sk_ph_openai_"))
        self.assertTrue(env["ANTHROPIC_API_KEY"].startswith("sk_ph_anthropic_"))
        self.assertNotIn("FAKE0000", json.dumps(env))
        self.assertEqual(sess.list_sessions(self.home, prune=False), [])   # ended: file gone


class Registered(unittest.TestCase):
    def test_commands_exist_and_parse(self):
        import argparse
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="cmd")
        proxy.add_parsers(sub)
        a = p.parse_args(["proxy", "--ttl", "30m", "--max-calls", "5", "--", "x"])
        self.assertEqual((a.ttl, a.max_calls), ("30m", 5))
        self.assertTrue(p.parse_args(["revoke", "--all"]).all)
        self.assertEqual(p.parse_args(["revoke", "openai"]).service, "openai")
        self.assertEqual(p.parse_args(["sessions"]).cmd, "sessions")
        self.assertTrue({"revoke", "sessions"} <= proxy.COMMANDS)


if __name__ == "__main__":
    unittest.main()
