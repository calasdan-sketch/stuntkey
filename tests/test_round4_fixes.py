"""Panel round 4 regressions.

A-1 the cross-domain prompt compares registrable domains (api.stripe.com and
    dashboard.stripe.com are one owner); built-in recipes may vouch for a
    vendor's second domain, user recipes may not.
A-2 a validated key whose .env cannot be written is a clean exit 1, never a
    traceback, never a printed key.
A-3 a non-HTTP reply from the validation endpoint is a ValidationError.
A-4 the Windows success line is honest about a failed icacls.
A-5 values are quoted so every dotenv reader gets the whole key back.
A-6 `export KEY=` lines are recognised and updated in place.
A-7 recipe slugs are validated (no ../../evil), `add` has clean errors.
A-8 the MCP server never answers notifications; non-objects get -32600.
forget <service> removes the key from the keychain and the .env file.
Catalog: every shipped recipe parses, is https, and matches its file name.
"""

import io
import json
import os
import socket
import threading
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import _isolation
from stuntkey import cli as cli_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import mcp as mcp_mod
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod
from stuntkey import validate as validate_mod

REPO = _isolation.REPO
FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": [], "docs": "",
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


def boom(_prompt):
    raise AssertionError("the confirmation prompt must not appear")


def connect(r, env_file, confirm=boom, key=FAKE_KEY, validate=lambda s, k: True):
    out = io.StringIO()
    code = connect_mod.connect(r, env_file=env_file, browser_open=lambda u: None,
                               prompt=lambda _: key, out=out, validate_fn=validate,
                               confirm_in=confirm)
    return code, out.getvalue()


# ------------------------------------------------------------------ A-1


class TestRegistrableDomain(unittest.TestCase):
    def test_same_owner_across_sub_domains(self):
        rd = connect_mod.registrable_domain
        self.assertEqual(rd("api.github.com"), "github.com")
        self.assertEqual(rd("github.com"), "github.com")
        self.assertEqual(rd("dashboard.stripe.com"), "stripe.com")
        self.assertEqual(rd("API.Stripe.COM."), "stripe.com")
        self.assertEqual(rd("api.example.co.uk"), "example.co.uk")
        self.assertEqual(rd("www.example.com.au"), "example.com.au")
        self.assertEqual(rd("127.0.0.1"), "127.0.0.1")
        self.assertEqual(rd("localhost"), "localhost")
        self.assertEqual(rd(""), "")
        for a, b in (("https://github.com/settings/tokens", "https://api.github.com/user"),
                     ("https://dashboard.stripe.com/apikeys", "https://api.stripe.com/v1/balance"),
                     ("https://resend.com/api-keys", "https://api.resend.com/api-keys"),
                     ("https://openrouter.ai/keys", "https://openrouter.ai/api/v1/auth/key"),
                     ("https://console.example.co.uk/keys", "https://api.example.co.uk/me")):
            self.assertTrue(connect_mod.same_owner(a, b), (a, b))

    def test_different_owners(self):
        for a, b in (("https://acme.test/keys", "https://validator.evil.test/check"),
                     ("https://a.co.uk/", "https://b.co.uk/"),
                     ("https://good.github.io/", "https://evil.github.io/"),   # platform
                     ("https://app.vercel.app/", "https://other.vercel.app/"),
                     ("https://acme.com/", "https://acme.net/"),
                     ("https://acme.test/", "https://acme.test.evil.example/")):
            self.assertFalse(connect_mod.same_owner(a, b), (a, b))

    def test_sub_domain_recipes_need_no_typed_yes(self):
        for key_url, val_url in (("https://github.com/settings/tokens",
                                  "https://api.github.com/user"),
                                 ("https://dashboard.stripe.com/apikeys",
                                  "https://api.stripe.com/v1/balance")):
            r = recipe(key_url=key_url)
            r["validate"]["url"] = val_url
            code, out = connect(r, os.path.join(_isolation.mktemp(), ".env"))
            self.assertEqual(code, 0, key_url)
            self.assertNotIn("DIFFERENT domain", out)

    def test_other_owner_still_prompts_and_names_both(self):
        r = recipe()
        r["validate"]["url"] = "https://validator.evil.test/check"
        code, out = connect(r, os.path.join(_isolation.mktemp(), ".env"),
                            confirm=lambda _: "no")
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENT domain", out)
        self.assertIn("evil.test vs acme.test", out)

    def test_every_shipped_recipe_connects_without_a_prompt(self):
        catalog = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        self.assertGreaterEqual(len(catalog), 29)
        for slug, r in catalog.items():
            out = io.StringIO()
            ok = connect_mod._require_cross_domain_confirmation(r, out, confirm_in=boom)
            self.assertTrue(ok, slug)
            self.assertNotIn("DIFFERENT", out.getvalue(), slug)

    def test_trusted_hosts_only_for_builtin_recipes(self):
        builtin = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)["anthropic"]
        self.assertTrue(builtin["_builtin"])
        self.assertIn("api.anthropic.com", builtin["validate"]["trusted_hosts"])
        # the same recipe saved by the user is NOT trusted: it prompts
        user_dir = _isolation.mktemp()
        recipes_mod.save_recipe(builtin, user_dir)
        with open(os.path.join(user_dir, "anthropic.json"), encoding="utf-8") as f:
            self.assertNotIn("_builtin", json.load(f))
        user = recipes_mod.load_recipes(user_dir)["anthropic"]
        self.assertFalse(user["_builtin"])
        out = io.StringIO()
        self.assertFalse(connect_mod._require_cross_domain_confirmation(
            user, out, confirm_in=lambda _: "no"))
        self.assertIn("DIFFERENT domain", out.getvalue())
        out = io.StringIO()
        self.assertTrue(connect_mod._require_cross_domain_confirmation(
            builtin, out, confirm_in=boom))
        self.assertIn("built-in recipe", out.getvalue())
        # a user recipe overriding a built-in slug loses the trust too
        path = recipes_mod.save_recipe(builtin)   # -> ~/.stuntkey/recipes
        try:
            self.assertFalse(recipes_mod.load_recipes()["anthropic"]["_builtin"])
        finally:
            os.remove(path)
        self.assertTrue(recipes_mod.load_recipes()["anthropic"]["_builtin"])
        # a user recipe cannot claim built-in status from inside the file
        forged = {k: v for k, v in builtin.items() if k != "_builtin"}
        forged["_builtin"] = True
        with open(os.path.join(user_dir, "anthropic.json"), "w", encoding="utf-8") as f:
            json.dump(forged, f)
        self.assertFalse(recipes_mod.load_recipes(user_dir)["anthropic"]["_builtin"])
        # and trusted_hosts never covers an unrelated host
        poisoned = dict(builtin)
        poisoned["validate"] = dict(builtin["validate"], url="https://evil.example/x")
        out = io.StringIO()
        self.assertFalse(connect_mod._require_cross_domain_confirmation(
            poisoned, out, confirm_in=lambda _: ""))


# ------------------------------------------------------------------ A-2


class TestUnwritableEnvFile(unittest.TestCase):
    def test_validated_key_that_cannot_be_saved_is_a_clean_exit_1(self):
        tmp = _isolation.mktemp()
        blocker = os.path.join(tmp, "afile")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        env = os.path.join(blocker, ".env")   # parent is a FILE
        code, out = connect(recipe(), env)
        self.assertEqual(code, 1)
        self.assertIn("could NOT be saved", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("✓", out)

    def test_missing_parent_directory_is_created(self):
        env = os.path.join(_isolation.mktemp(), "deep", "er", ".env")
        code, out = connect(recipe(), env)
        self.assertEqual(code, 0)
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], FAKE_KEY)

    def test_cli_env_file_in_file_parent_no_traceback(self):
        tmp = _isolation.mktemp()
        with open(os.path.join(tmp, "afile"), "w", encoding="utf-8") as f:
            f.write("x")
        env = os.path.join(tmp, "afile", ".env")
        cat = {"acme": recipe()}
        out, err = io.StringIO(), io.StringIO()
        real = connect_mod.connect

        def connect_with_fakes(*a, **kw):   # the CLI's call, minus the terminal
            return real(*a, prompt=lambda _: FAKE_KEY,
                        validate_fn=lambda s, k: True, **kw)

        with mock.patch.object(recipes_mod, "load_recipes", return_value=cat), \
                mock.patch.object(connect_mod, "connect", connect_with_fakes), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["connect", "acme", "--no-browser", "--store", "env",
                                "--env-file", env])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", out.getvalue() + err.getvalue())
        self.assertNotIn(FAKE_KEY, out.getvalue() + err.getvalue())


# ------------------------------------------------------------------ A-3


class TestNonHttpReply(unittest.TestCase):
    def test_garbage_reply_is_a_validation_error(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def talk():
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(b"HELLO I AM NOT HTTP\r\n")
            conn.close()

        threading.Thread(target=talk, daemon=True).start()
        try:
            with self.assertRaises(validate_mod.ValidationError) as cm:
                validate_mod.validate_key(
                    {"method": "GET", "url": f"http://127.0.0.1:{port}/me",
                     "auth": {"type": "bearer"}, "expect": [200]}, FAKE_KEY)
        finally:
            srv.close()
        self.assertIn("did not speak HTTP", str(cm.exception))
        self.assertNotIn(FAKE_KEY, str(cm.exception))

    def test_connect_reports_it_without_a_traceback(self):
        def garbage(spec, key):
            raise validate_mod.ValidationError("validation endpoint did not speak HTTP")
        code, out = connect(recipe(), os.path.join(_isolation.mktemp(), ".env"),
                            validate=garbage)
        self.assertEqual(code, 1)
        self.assertIn("couldn't reach the API", out)


# ------------------------------------------------------------------ A-4


class TestHonestWindowsLine(unittest.TestCase):
    def _store(self, icacls_rc):
        env = os.path.join(_isolation.mktemp(), ".env")

        def fake_run(argv, **kw):
            return types.SimpleNamespace(returncode=icacls_rc)

        with mock.patch.object(store_mod.os, "name", "nt"), \
                mock.patch.object(store_mod.subprocess, "run", fake_run), \
                mock.patch.dict(os.environ, {"USERNAME": "dan"}):
            return connect_mod.store_in_env_file(env)("ACME_API_KEY", FAKE_KEY)

    def test_acl_success_and_failure_are_told_apart(self):
        self.assertIn("owner-only ACL", self._store(0))
        failed = self._store(1)
        self.assertIn("could not restrict ACL", failed)
        self.assertNotIn("owner-only ACL", failed)
        self.assertNotIn(FAKE_KEY, failed)

    def test_describe_protection_takes_the_outcome(self):
        with mock.patch.object(store_mod.os, "name", "nt"):
            self.assertEqual(store_mod.describe_protection(True), "owner-only ACL")
            self.assertIn("could not restrict ACL", store_mod.describe_protection(False))
        with mock.patch.object(store_mod.os, "name", "posix"):
            self.assertEqual(store_mod.describe_protection(False), "mode 0600")

    def test_store_key_result_carries_protection(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        r = store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertEqual((r.path, r.updated), (env, False))
        if os.name != "nt":
            self.assertTrue(r.protected)
            self.assertEqual(r.protection, "mode 0600")
        # the compatibility tuple is unchanged
        self.assertEqual(store_mod.store_key("ACME_API_KEY", FAKE_KEY, env), (env, True))


# ------------------------------------------------------------------ A-5


class TestValueQuoting(unittest.TestCase):
    def test_plain_values_stay_bare(self):
        for v in (FAKE_KEY, "sk_live_abc123", "a.b+c/d=e:f-g_h", "AIzaSy0"):
            self.assertEqual(store_mod.quote_value(v), v)

    def test_risky_values_are_quoted_and_round_trip(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        # (a single quote, a backslash or a tab is refused instead - see
        # test_env_quoting.py)
        risky = ['ab#c d"e', " leading space", "semi;colon", "dollar$sign", "",
                 "hash#only", "sp ace"]
        for i, value in enumerate(risky):
            store_mod.store_key(f"V{i}", value, env)
        loaded = store_mod.load_env(env)
        for i, value in enumerate(risky):
            self.assertEqual(loaded[f"V{i}"], value, repr(value))
        with open(env, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("V0='ab#c d\"e'", text)
        self.assertIn("V3='dollar$sign'", text)
        # what Node dotenv / python-dotenv do with an UNQUOTED `ab#c d"e`:
        # stop at the ' #' or the space. Quoted, nothing is lost.
        self.assertNotIn("\nV0=ab#c", text)

    def test_parse_value_dialects(self):
        pv = store_mod.parse_value
        self.assertEqual(pv('"a b"'), "a b")
        self.assertEqual(pv('"a\\"b\\\\c"'), 'a"b\\c')
        self.assertEqual(pv("'lit\\eral'"), "lit\\eral")
        self.assertEqual(pv("bare # comment"), "bare")
        self.assertEqual(pv("  spaced  "), "spaced")
        self.assertEqual(pv('"unterminated'), "unterminated")


# ------------------------------------------------------------------ A-6


class TestExportLines(unittest.TestCase):
    def test_export_assignment_is_updated_in_place(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        with open(env, "w", encoding="utf-8") as f:
            f.write("export OTHER=1\nexport ACME_API_KEY=old\nTAIL=x\n")
        path, updated = store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        self.assertTrue(updated)
        with open(env, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, ["export OTHER=1", f"export ACME_API_KEY={FAKE_KEY}",
                                 "TAIL=x"])
        self.assertEqual(store_mod.read_env(env)[1], {"OTHER": 0, "ACME_API_KEY": 1,
                                                      "TAIL": 2})
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], FAKE_KEY)


# ------------------------------------------------------------------ A-7


class TestSlugAndExpect(unittest.TestCase):
    def test_bad_slugs_rejected_good_accepted(self):
        for bad in ("../../evil", "Evil", "has space", "", "-dash", "a" * 65, "a/b",
                    "x.json"):
            with self.assertRaises(recipes_mod.RecipeError, msg=bad):
                recipes_mod.validate_recipe(recipe(service=bad))
        for good in ("acme", "my-api_2", "a", "a" * 64, "0day"):
            recipes_mod.validate_recipe(recipe(service=good))

    def test_save_recipe_cannot_escape_the_directory(self):
        tmp = _isolation.mktemp()
        inner = os.path.join(tmp, "a", "b")     # ../../evil would land in tmp
        os.makedirs(inner)
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.save_recipe(recipe(service="../../evil"), inner)
        self.assertEqual(os.listdir(inner), [])
        self.assertEqual(os.listdir(tmp), ["a"])
        self.assertFalse(os.path.exists(os.path.join(tmp, "evil.json")))

    def _add(self, answers, recipes_dir):
        answers = list(answers)
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *_: answers.pop(0)), \
                redirect_stdout(out):
            code = cli_mod._cmd_add(recipes_dir)
        return code, out.getvalue()

    def test_add_rejects_path_slug_cleanly(self):
        tmp = _isolation.mktemp()
        code, out = self._add(["../../evil"], tmp)
        self.assertEqual(code, 1)
        self.assertIn("not a valid slug", out)
        self.assertEqual(os.listdir(tmp), [])

    def test_add_rejects_bad_expect_cleanly(self):
        tmp = _isolation.mktemp()
        answers = ["acme", "Acme", "https://acme.test/keys", "ACME_API_KEY", "",
                   "", "Click new key", "", "GET", "https://acme.test/me", "bearer",
                   "200, abc"]
        code, out = self._add(answers, tmp)
        self.assertEqual(code, 1)
        self.assertIn("expected HTTP status codes", out)
        self.assertNotIn("Traceback", out)
        self.assertEqual(os.listdir(tmp), [])

    def test_add_happy_path_writes_the_recipe(self):
        tmp = _isolation.mktemp()
        answers = ["My API", "My API", "https://my.test/keys", "my_key", "read",
                   "", "Click new key", "", "", "https://my.test/me", "header",
                   "200,201", "X-Key"]
        code, out = self._add(answers, tmp)
        self.assertEqual(code, 0, out)
        saved = recipes_mod.load_recipes(tmp)["my-api"]
        self.assertEqual(saved["validate"]["expect"], [200, 201])
        self.assertEqual(saved["validate"]["auth"], {"type": "header", "header": "X-Key"})
        self.assertEqual(saved["env_var"], "MY_KEY")

    def test_parse_expect(self):
        self.assertEqual(cli_mod._parse_expect("200"), [200])
        self.assertEqual(cli_mod._parse_expect(" 200 , 201"), [200, 201])
        for bad in ("200, abc", "99", "abc", "", "2000"):
            with self.assertRaises(ValueError, msg=bad):
                cli_mod._parse_expect(bad)


# ------------------------------------------------------------------ A-8


class TestJsonRpcHygiene(unittest.TestCase):
    def serve(self, *lines):
        stdin = io.BytesIO("".join(line + "\n" for line in lines).encode("utf-8"))
        stdout = io.BytesIO()
        mcp_mod.serve({}, pa_loader=lambda: [], stdin=stdin, stdout=stdout)
        return [json.loads(line) for line in
                stdout.getvalue().decode("utf-8").splitlines() if line]

    def test_notifications_never_answered(self):
        for req in ({"jsonrpc": "2.0", "method": "notifications/cancelled",
                     "params": {"requestId": 1}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "method": "notifications/roots/list_changed"},
                    {"jsonrpc": "2.0", "method": "tools/list"},         # no id
                    {"jsonrpc": "2.0", "id": 3, "method": "notifications/cancelled"}):
            self.assertIsNone(mcp_mod.handle(req, {}), req)
        lines = self.serve(json.dumps({"jsonrpc": "2.0",
                                       "method": "notifications/cancelled"}),
                           json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}))
        self.assertEqual(lines, [{"jsonrpc": "2.0", "id": 5, "result": {}}])

    def test_non_objects_and_parse_errors(self):
        lines = self.serve("[1, 2]", '"str"', "7", "{not json",
                           json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}))
        self.assertEqual([r["error"]["code"] for r in lines[:-1]],
                         [-32600, -32600, -32600, -32700])
        for r in lines[:-1]:
            self.assertIsNone(r["id"])
            self.assertNotIn("object has no attribute", r["error"]["message"])
        self.assertEqual(lines[-1]["id"], 9)
        self.assertEqual(mcp_mod.handle({"jsonrpc": "2.0", "id": 1}, {})["error"]["code"],
                         -32600)
        self.assertEqual(mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"}, {})
                         ["error"]["code"], -32601)


# ---------------------------------------------------------------- forget


class TestForget(unittest.TestCase):
    def test_forget_removes_keychain_entry_and_env_line(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        with open(env, "w", encoding="utf-8") as f:
            f.write(f"OTHER=1\nACME_API_KEY={FAKE_KEY}\nTAIL=x\n")
        deleted = []
        fake = types.SimpleNamespace(
            detect_backend=lambda: keychain_mod.LINUX,
            delete=lambda s, v, b: deleted.append((s, v, b)) or True,
            label=keychain_mod.label)
        out = io.StringIO()
        code = cli_mod._cmd_forget(recipe(), env, out=out, keychain=fake)
        self.assertEqual(code, 0)
        self.assertEqual(deleted, [("acme", "ACME_API_KEY", keychain_mod.LINUX)])
        self.assertIn("Secret Service", out.getvalue())
        self.assertIn("ACME_API_KEY from", out.getvalue())
        self.assertNotIn(FAKE_KEY, out.getvalue())
        with open(env, encoding="utf-8") as f:
            self.assertEqual(f.read(), "OTHER=1\nTAIL=x\n")

    def test_forget_with_nothing_stored(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        fake = types.SimpleNamespace(detect_backend=lambda: None,
                                     delete=lambda *a: False, label=keychain_mod.label)
        out = io.StringIO()
        self.assertEqual(cli_mod._cmd_forget(recipe(), env, out=out, keychain=fake), 0)
        self.assertIn("nothing stored", out.getvalue())
        self.assertFalse(os.path.exists(env))

    def test_remove_key_keeps_the_file_private_and_handles_last_line(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        self.assertTrue(store_mod.remove_key("ACME_API_KEY", env))
        self.assertFalse(store_mod.remove_key("ACME_API_KEY", env))
        with open(env, encoding="utf-8") as f:
            self.assertEqual(f.read(), "")
        if os.name != "nt":
            self.assertEqual(store_mod.file_mode(env), 0o600)

    def test_cli_wiring(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        cat = {"acme": recipe()}
        out = io.StringIO()
        with mock.patch.object(recipes_mod, "load_recipes", return_value=cat), \
                mock.patch.object(keychain_mod, "detect_backend", return_value=None), \
                redirect_stdout(out):
            code = cli_mod.main(["forget", "acme", "--yes", "--env-file", env])
        self.assertEqual(code, 0)
        self.assertIn("forgot acme", out.getvalue())
        self.assertNotIn("ACME_API_KEY", store_mod.load_env(env))
        with mock.patch.object(recipes_mod, "load_recipes", return_value=cat), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli_mod.main(["forget", "nope"]), 3)


# ------------------------------------------------------- validation shapes


class _Echo(BaseHTTPRequestHandler):
    seen: list = []
    status = 200

    def do_GET(self):
        _Echo.seen.append(dict(self.headers))
        self.send_response(_Echo.status)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class TestValidationShapes(unittest.TestCase):
    def setUp(self):
        _Echo.seen, _Echo.status = [], 200
        self.srv = HTTPServer(("127.0.0.1", 0), _Echo)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)      # runs after the shutdown
        self.addCleanup(self.srv.shutdown)

    def spec(self, **over):
        s = {"method": "GET", "url": f"http://127.0.0.1:{self.srv.server_port}/me",
             "auth": {"type": "bearer"}, "expect": [200]}
        s.update(over)
        return s

    def test_scheme_username_and_static_headers(self):
        validate_mod.validate_key(self.spec(auth={"type": "bearer", "scheme": "Token"}), "k1")
        self.assertEqual(_Echo.seen[-1]["Authorization"], "Token k1")
        validate_mod.validate_key(self.spec(auth={"type": "bearer", "scheme": "Bot"}), "k2")
        self.assertEqual(_Echo.seen[-1]["Authorization"], "Bot k2")
        validate_mod.validate_key(self.spec(auth={"type": "basic", "username": "api"}), "k3")
        import base64
        self.assertEqual(_Echo.seen[-1]["Authorization"],
                         "Basic " + base64.b64encode(b"api:k3").decode())
        validate_mod.validate_key(self.spec(auth={"type": "basic"}), "k4")
        self.assertEqual(_Echo.seen[-1]["Authorization"],
                         "Basic " + base64.b64encode(b"k4:").decode())
        validate_mod.validate_key(self.spec(
            auth={"type": "header", "header": "x-api-key"},
            headers={"anthropic-version": "2023-06-01", "Accept": "application/json"}), "k5")
        h = {k.lower(): v for k, v in _Echo.seen[-1].items()}
        self.assertEqual((h["x-api-key"], h["anthropic-version"], h["accept"]),
                         ("k5", "2023-06-01", "application/json"))
        # a static header can never override the credential header
        validate_mod.validate_key(self.spec(headers={"Authorization": "Bearer stale"}), "k6")
        self.assertEqual(_Echo.seen[-1]["Authorization"], "Bearer k6")

    def test_reject_statuses(self):
        _Echo.status = 400
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod.validate_key(self.spec(), FAKE_KEY)          # default: a crash
        self.assertFalse(validate_mod.validate_key(self.spec(reject=[400, 401]), FAKE_KEY))
        _Echo.status = 422
        self.assertFalse(validate_mod.validate_key(self.spec(reject=[422]), FAKE_KEY))
        _Echo.status = 401
        self.assertFalse(validate_mod.validate_key(self.spec(), FAKE_KEY))

    def test_schema_rejects_bad_shapes(self):
        for bad in ({"reject": ["401"]}, {"headers": ["a"]}, {"headers": {"a": 1}},
                    {"trusted_hosts": "api.x.com"}, {"expect": [99]}):
            r = recipe()
            r["validate"].update(bad)
            with self.assertRaises(recipes_mod.RecipeError, msg=bad):
                recipes_mod.validate_recipe(r)
        for bad_auth in ({"type": "bearer", "scheme": "Bearer x"},
                         {"type": "basic", "username": "a:b"},
                         {"type": "bearer", "scheme": ""}):
            r = recipe()
            r["validate"]["auth"] = bad_auth
            with self.assertRaises(recipes_mod.RecipeError, msg=bad_auth):
                recipes_mod.validate_recipe(r)
        r = recipe()
        r["validate"].update({"reject": [400], "headers": {"X-V": "1"},
                              "trusted_hosts": ["api.acme.net"],
                              "auth": {"type": "basic", "username": "api"}})
        recipes_mod.validate_recipe(r)


# --------------------------------------------------------------- catalog


class TestShippedCatalog(unittest.TestCase):
    EXPECTED = {"paypal-sandbox", "github", "stripe", "resend", "openrouter", "openai", "anthropic",
                "google-gemini", "groq", "mistral", "cohere", "huggingface",
                "together", "elevenlabs", "deepgram", "assemblyai", "replicate",
                "supabase", "vercel", "netlify", "cloudflare", "cloudflare-keymaker", "sendgrid", "mailgun",
                "postmark", "notion", "airtable", "pinecone", "tavily",
                "brave-search", "discord",
                # 0.4.0: two-value credentials and the other check types
                "ebay", "twilio", "paypal", "spotify", "aws", "openweather"}

    def test_every_recipe_parses_is_https_and_matches_its_file(self):
        err = io.StringIO()
        with redirect_stderr(err):
            catalog = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        self.assertEqual(err.getvalue(), "", "a shipped recipe was skipped")
        self.assertEqual(set(catalog), self.EXPECTED)
        files = {n[:-5] for n in os.listdir(recipes_mod.RECIPES_DIR) if n.endswith(".json")}
        self.assertEqual(files, self.EXPECTED)
        for slug, r in catalog.items():
            self.assertTrue(recipes_mod.SLUG_RE.match(slug), slug)
            self.assertTrue(r["_builtin"], slug)
            for url in (r["key_url"], r["validate"]["url"], r.get("docs")):
                self.assertTrue(url.startswith("https://"), (slug, url))
            self.assertTrue(r["display"] and r["steps"] and r["env_var"], slug)
            self.assertEqual(r["validate"]["method"], "POST" if slug == "aws" else "GET", slug)
            for host in r["validate"].get("trusted_hosts", []):
                self.assertEqual(host, connect_mod._host(r["validate"]["url"]), slug)
            # validation requests are buildable with every shape used, and
            # the credential lands in the header the recipe names
            atype = r["validate"]["auth"]["type"]
            creds = {f["name"]: "k" + f["name"] for f in recipes_mod.fields(r)}
            req = validate_mod._build_request(r["validate"], creds, bearer_token="ktoken")
            if atype == "query":
                self.assertIn("k" + recipes_mod.DEFAULT_FIELD, req.full_url, slug)
                continue
            cred = validate_mod._credential_header(r["validate"])
            self.assertTrue(req.has_header(cred.capitalize()), (slug, cred))
            sent = req.get_header(cred.capitalize())
            if atype == "basic":
                import base64
                sent = base64.b64decode(sent.split(" ", 1)[1]).decode()
            self.assertIn("k", sent, slug)

    def test_recipe_files_are_valid_json_without_escape_bytes(self):
        for name in os.listdir(recipes_mod.RECIPES_DIR):
            with open(os.path.join(recipes_mod.RECIPES_DIR, name), "rb") as f:
                raw = f.read()
            self.assertNotIn(b"\x1b", raw, name)
            data = json.loads(raw.decode("utf-8"))
            self.assertEqual(data["service"] + ".json", name)


# ------------------------------------------------------------------ docs


class TestReadme(unittest.TestCase):
    def test_windows_first_wording(self):
        with open(os.path.join(REPO, "docs", "guide.md"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("python3", text)
        self.assertNotIn("alias seapi", text)
        self.assertNotIn("git clone <repo>", text)
        self.assertIn("pip install git+https://github.com/calasdan-sketch/stuntkey", text)
        self.assertIn('"command": "python"', text)
        self.assertIn("winpty", text)
        self.assertIn("stuntkey forget", text)
        self.assertIn("registrable", text)
        for slug in TestShippedCatalog.EXPECTED:
            self.assertIn(f"`{slug}`", text, slug)


if __name__ == "__main__":
    unittest.main()
