import json
import os
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME for the whole run)
from stuntkey import broker, caps, mcp, recipes, remote

KEY = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # built at run time
CATALOG = recipes.load_recipes()
RECIPE = CATALOG["github"]
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.5", port))]


def big(n):
    return lambda req, ip, t: (200, {"content-type": "application/json"}, n)


def go(body, **kw):
    return broker.call(RECIPE, {"GITHUB_TOKEN": KEY}, "GET", "/user",
                       send=big(body), resolver=PUBLIC, **kw)


class ReturnCap(unittest.TestCase):
    def test_big_body_is_cut_to_the_cap(self):
        r = go(b'{"a":"' + b"x" * 720_000 + b'"}', max_chars=broker.RETURN_CAP)
        self.assertLessEqual(len(r["body"]), 24_000)
        self.assertTrue(r["truncated"])
        self.assertIn("limit", r["body"][-150:])

    def test_larger_max_chars_returns_that_much(self):
        r = go(b"x" * 720_000, max_chars=100_000)
        self.assertEqual(len(r["body"]), 100_000)

    def test_small_body_not_truncated(self):
        r = go(b"{}", max_chars=24_000)
        self.assertEqual((r["body"], r["truncated"]), ("{}", False))

    def test_key_before_and_after_the_cut_is_masked(self):
        body = (b"a" * 100 + KEY.encode() + b"b" * 29_000 + KEY.encode()
                + b"c" * 1000 + KEY[:20].encode())
        r = go(body, max_chars=24_000)
        self.assertNotIn(KEY, r["body"])
        edge = b"z" * (24_000 - len(CUT_PAD) - 10) + KEY.encode() + b"z" * 500
        r = go(edge, max_chars=24_000)
        self.assertNotIn(KEY[:20], r["body"])

    def test_mcp_default_and_validation(self):
        seen = {}

        def fake_call(*a, **k):
            seen.update(k)
            return {"status": 200, "headers": {}, "body": "{}", "truncated": False}
        args = {"service": "github", "method": "GET", "path": "/user"}
        with mock.patch.object(broker, "call", fake_call), \
                mock.patch.object(remote, "collect_values", lambda *a: {}):
            mcp._call_api(CATALOG, dict(args))
            self.assertEqual(seen["max_chars"], 24_000)
            mcp._call_api(CATALOG, dict(args, max_chars=100_000))
            self.assertEqual(seen["max_chars"], 100_000)
            for bad in (0, -1, 10**9, True, "5", 2.5):
                r = mcp._call_api(CATALOG, dict(args, max_chars=bad))
                self.assertTrue(r.get("isError"), bad)
                self.assertIn("max_chars", r["content"][0]["text"])


CUT_PAD = broker.CUT_NOTE


class ListServices(unittest.TestCase):
    def rows(self, args):
        r = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "list_services", "arguments": args}},
                       CATALOG)
        return json.loads(r["result"]["content"][0]["text"])

    def test_connected_only_and_no_duplicate_env_var(self):
        def has(recipe, _f):
            if recipe["service"] != "github":
                raise remote.RemoteError("none")
            return {}
        with mock.patch.object(remote, "collect_values", has):
            everything = self.rows({})
            mine = self.rows({"connected_only": True})
        self.assertEqual([r["service"] for r in mine], ["github"])
        self.assertGreater(len(everything), 1)
        self.assertNotIn("env_var", everything[0])
        self.assertTrue(all(r["env_vars"] for r in everything))
        self.assertLess(len(json.dumps(everything)), 7_082)


class ToolListSize(unittest.TestCase):
    def test_tools_list_under_3kb_and_rules_kept(self):
        r = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, CATALOG)
        self.assertLess(len(json.dumps(r["result"]["tools"])), 3_000)
        d = {t["name"]: t["description"].lower() for t in r["result"]["tools"]}
        self.assertIn("never ask anyone to paste a key into chat", d["request_connect"])
        self.assertIn("never read, type or screenshot the key", d["capture_key"])
        self.assertIn("do not retry after a refusal", d["capture_key"])
        self.assertIn("do not retry", d["call_api"])
        self.assertIn("never put keys in any argument", d["call_api"])

    def test_long_explanation_moves_into_the_reply(self):
        from stuntkey import agent
        r = agent.request_connect("github", CATALOG, cwd=_isolation.mktemp())
        self.assertIn("consent_pending", r["capture_help"])


class CapsFailClosed(unittest.TestCase):
    def home(self, text):
        h = _isolation.mktemp()
        with open(caps.caps_path(h), "w") as f:
            f.write(text)
        return h

    def test_bad_caps_values_refuse(self):
        for bad in ('{"github": {"calls_day": "5"}}', '{"github": {"tokens_day": 1.5}}',
                    '{"github": {"calls_session": true}}', '{"github": {"nope": 1}}',
                    '{"github": {"calls_day": -1}}'):
            with self.assertRaises(broker.BrokerError, msg=bad) as cm:
                caps.load_caps(self.home(bad))
            self.assertEqual(cm.exception.code, 5)
            self.assertIn("github", str(cm.exception))

    def test_good_caps_load(self):
        h = self.home('{"github": {"calls_day": 5, "tokens_day": 0}}')
        self.assertEqual(caps.load_caps(h), {"github": {"calls_day": 5, "tokens_day": 0}})

    def test_corrupt_usage_refuses_without_traceback(self):
        for raw in ("null", '"x"', "1e999"):
            h = _isolation.mktemp()
            path = caps.usage_path(h, "github")
            with open(path, "w") as f:
                f.write('{"day": "%s", "calls": %s}' % (caps._today(), raw))
            with self.assertRaises(broker.BrokerError, msg=raw) as cm:
                caps.begin(h, "github", 0)
            self.assertEqual(cm.exception.code, 5)

    def test_negative_usage_is_zero_and_still_counts(self):
        h = _isolation.mktemp()
        path = caps.usage_path(h, "github")
        with open(path, "w") as f:
            f.write('{"day": "%s", "calls": -5, "tokens": -9}' % caps._today())
        caps.begin(h, "github", 0)
        self.assertEqual(caps.usage(h, "github")["calls"], 1)
        self.assertEqual(caps.usage(h, "github")["tokens"], 0)


if __name__ == "__main__":
    unittest.main()


class InstallPerFolder(unittest.TestCase):
    def test_no_terminal_is_a_message_not_a_traceback(self):
        d = _isolation.mktemp()
        out = []

        def eof(_):
            raise EOFError
        from stuntkey import clients
        rc = clients.run(["claude-code"], False, ask=eof, out=out.append,
                         home=d, cwd=d, env={"APPDATA": d})
        self.assertEqual(rc, 1)
        self.assertIn("no terminal to answer on; re-run with --yes", out)
        self.assertEqual(os.listdir(d), [])
        rc = clients.remove(["cursor"], False, ask=eof, out=out.append, home=d, cwd=d)
        self.assertEqual(rc, 0)          # nothing installed, nothing to ask

    def test_doctor_names_the_folder_for_per_folder_clients(self):
        from stuntkey import clients, gitscan
        d = _isolation.mktemp()
        old = os.getcwd()
        os.chdir(d)
        try:
            with mock.patch.object(clients, "plugged", lambda: ["claude-code", "cursor"]):
                row = [c for c in gitscan.doctor()["checks"] if c["check"] == "AI tools"][0]
        finally:
            os.chdir(old)
        self.assertIn(f"claude-code (this folder only: {d}", row["detail"] if "detail" in row else str(row))
        self.assertNotIn("cursor (this", str(row))


class GluedKeys(unittest.TestCase):
    def setUp(self):
        from stuntkey import scrub
        self.scrub = scrub
        self.fp = os.path.join(_isolation.mktemp(), "fingerprints.json")
        self.key = "Zq9" + "k3Xw7Lm2Pa8Vb4Nc6Rd1Sf5Tg0Uh" + "Jy2Qe9ABC"   # 40 chars, no known format
        self.assertEqual(len(self.key), 40)
        scrub.remember_key("svc/KEY", self.key, self.fp)
        self.prints = scrub.load_fingerprints(self.fp)

    def mask(self, text):
        return self.scrub.mask_secrets(text, self.prints)

    def test_glued_forms_are_masked(self):
        k = self.key
        for text in (f"https://api.telegram.org/bot{k}/getMe", f"GET /v1/{k}/x", f"/{k}",
                     f"id-{k}", f"{k}+suffix", f"pre+{k}", f"curl -v {k}", k, f"a={k}"):
            out, n = self.mask(text)
            self.assertNotIn(k, out, text)
            self.assertGreaterEqual(n, 1, text)

    def test_unrelated_text_untouched(self):
        for text in ("https://api.telegram.org/botNOTTHEKEY123456789/getMe",
                     "GET /v1/" + self.key[:-1] + "x/y", "hello world " * 50):
            self.assertEqual(self.mask(text), (text, 0))

    def test_old_fingerprint_file_without_lengths_still_works(self):
        data = json.load(open(self.fp))
        del data["lengths"]
        json.dump(data, open(self.fp, "w"))
        prints = self.scrub.load_fingerprints(self.fp)
        self.assertEqual(self.scrub.mask_secrets(self.key, prints)[1], 1)
        self.assertEqual(self.scrub.mask_secrets("x/" + self.key, prints)[1], 0)   # old behaviour

    def test_file_holds_lengths_not_keys(self):
        self.assertNotIn(self.key, open(self.fp).read())
        self.assertEqual(json.load(open(self.fp))["lengths"], {"svc/KEY": [40]})

    def test_one_megabyte_is_fast(self):
        import time
        text = ("The quick brown fox jumps over 13 lazy dogs /usr/lib/python3/site-packages "
                "https://example.com/some/long/path?x=1 ") * 10_000
        text = text[:1_000_000]
        t = time.time()
        out, n = self.mask(text)
        self.assertEqual(n, 0)
        self.assertLess(time.time() - t, 1.0)
