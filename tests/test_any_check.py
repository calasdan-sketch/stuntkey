"""0.4.0: every common way an API proves a credential, and copy-and-go.

Each auth shape is run against a fake API on 127.0.0.1 that records exactly
what arrived, so the tests check both that the right request is sent and
that a credential goes NOWHERE else:

- headers / basic with two fields / query / OAuth2 client credentials
  (Basic or body, token_only) / AWS SigV4
- the token POST and the query request follow NO redirect (the secret is in
  the body or the URL and cannot be stripped); header credentials are
  stripped on an off-origin redirect, every header of a multi-header auth
- a bad recipe is refused at load time: an unknown or unused field, a token
  endpoint over http, a cli_token program that isn't allowed
- connect collects every field, sends them together, stores each, and
  never prints a value; a rejected pair is asked for again
- copy-and-go takes only a key-shaped value, honours a field pattern,
  ignores stale clipboard text, and empties the clipboard
- `run` injects every stored value; `forget` removes every one
"""

import base64
import io
import json
import os
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import clipboard as clip_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import recipes as recipes_mod
from stuntkey import validate as validate_mod

APP, SECRET = "FAKE-APP-ID-0001", "FAKE-SECRET-0002"


class Api(BaseHTTPRequestHandler):
    """Records every request. /token answers like an OAuth2 server, /me
    accepts the right credentials, /bounce redirects to another port."""
    seen: list = []
    other_port = 0
    token_status = 200

    def _record(self, body=b""):
        Api.seen.append({"method": self.command, "path": self.path,
                         "headers": {k.lower(): v for k, v in self.headers.items()},
                         "body": body.decode()})

    def _answer(self, status, body=b"", location=None):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._record(body)
        if self.path.startswith("/bounce"):
            return self._answer(302, location=f"http://127.0.0.1:{Api.other_port}/token")
        form = dict(urllib.parse.parse_qsl(body.decode()))
        basic = self.headers.get("Authorization", "")
        good_basic = basic == "Basic " + base64.b64encode(f"{APP}:{SECRET}".encode()).decode()
        good_body = form.get("client_id") == APP and form.get("client_secret") == SECRET
        if form.get("grant_type") == "client_credentials" and (good_basic or good_body):
            return self._answer(Api.token_status, json.dumps({"access_token": "TEMP-TOKEN-XYZ"}).encode())
        return self._answer(401, b'{"error":"invalid_client"}')

    def do_GET(self):
        self._record()
        if self.path.startswith("/bounce"):
            return self._answer(302, location=f"http://127.0.0.1:{Api.other_port}/me")
        h = self.headers
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        ok = (h.get("Authorization") == "Bearer TEMP-TOKEN-XYZ"
              or (h.get("X-App-Id") == APP and h.get("X-Key") == SECRET)
              or h.get("Authorization") == "Basic " + base64.b64encode(f"{APP}:{SECRET}".encode()).decode()
              or q.get("appid") == SECRET
              or (h.get("Authorization", "").startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")))
        self._answer(200 if ok else 401)

    def log_message(self, *a):
        pass


class Servers:
    def __enter__(self):
        Api.seen = []
        Api.token_status = 200
        self.other = HTTPServer(("127.0.0.1", 0), Api)
        self.main = HTTPServer(("127.0.0.1", 0), Api)
        Api.other_port = self.other.server_port
        for s in (self.main, self.other):
            threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.main.server_port}"
        return self

    def __exit__(self, *exc):
        for s in (self.main, self.other):
            s.shutdown()
            s.server_close()

    def to_other(self):
        return [r for r in Api.seen if r.get("port") == "other"]


TWO = [{"name": "app_id", "env_var": "X_APP_ID", "label": "App ID"},
       {"name": "secret", "env_var": "X_SECRET", "label": "Secret"}]


def recipe(auth, url="https://api.example.com/me", fields=TWO, **extra):
    data = {"service": "x", "display": "X", "key_url": "https://example.com/keys",
            "env_var": fields[0]["env_var"] if fields else "X_KEY", "steps": ["s"],
            "validate": {"method": "GET", "url": url, "auth": auth, "expect": [200]}}
    if fields:
        data["fields"] = fields
    data.update(extra)
    return data


CREDS = {"app_id": APP, "secret": SECRET}


class AuthShapes(unittest.TestCase):
    def spec(self, auth, path="/me"):
        return {"method": "GET", "url": self.s.base + path, "auth": auth, "expect": [200]}

    def setUp(self):
        self.s = Servers().__enter__()

    def tearDown(self):
        self.s.__exit__()

    def test_headers_two_fields(self):
        spec = self.spec({"type": "headers", "headers": {"X-App-Id": "{app_id}", "X-Key": "{secret}"}})
        self.assertTrue(validate_mod.validate_key(spec, CREDS))
        self.assertFalse(validate_mod.validate_key(spec, {"app_id": APP, "secret": "wrong"}))

    def test_basic_with_username_field(self):
        spec = self.spec({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        self.assertTrue(validate_mod.validate_key(spec, CREDS))

    def test_query_param(self):
        spec = self.spec({"type": "query", "param": "appid"}, "/me?q=London")
        self.assertTrue(validate_mod.validate_key(spec, SECRET))
        self.assertIn("q=London", Api.seen[-1]["path"])

    def test_oauth2_basic_then_bearer(self):
        spec = self.spec({"type": "oauth2_client_credentials", "token_url": self.s.base + "/token",
                          "client_id_field": "app_id", "client_secret_field": "secret", "scope": "read"})
        self.assertTrue(validate_mod.validate_key(spec, CREDS))
        post, get = Api.seen
        self.assertEqual((post["method"], get["method"]), ("POST", "GET"))
        self.assertIn("scope=read", post["body"])
        self.assertNotIn(SECRET, post["body"])           # Basic: the secret is not in the body
        self.assertEqual(get["headers"]["authorization"], "Bearer TEMP-TOKEN-XYZ")
        self.assertNotIn(SECRET, json.dumps(get))        # the secret never reaches the API call

    def test_oauth2_body_and_token_only(self):
        spec = self.spec({"type": "oauth2_client_credentials", "token_url": self.s.base + "/token",
                          "client_id_field": "app_id", "client_secret_field": "secret",
                          "send": "body", "token_only": True})
        self.assertTrue(validate_mod.validate_key(spec, CREDS))
        self.assertEqual(len(Api.seen), 1)               # token only: no second call
        self.assertNotIn("authorization", Api.seen[0]["headers"])

    def test_oauth2_wrong_secret_is_a_rejection_not_a_crash(self):
        spec = self.spec({"type": "oauth2_client_credentials", "token_url": self.s.base + "/token",
                          "client_id_field": "app_id", "client_secret_field": "secret"})
        self.assertFalse(validate_mod.validate_key(spec, {"app_id": APP, "secret": "nope"}))
        self.assertEqual(len(Api.seen), 1)               # no API call without a token

    def test_oauth2_token_answer_without_token(self):
        Api.token_status = 500
        spec = self.spec({"type": "oauth2_client_credentials", "token_url": self.s.base + "/token",
                          "client_id_field": "app_id", "client_secret_field": "secret"})
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod.validate_key(spec, CREDS)

    def test_aws_sigv4_reaches_api(self):
        spec = self.spec({"type": "aws_sigv4", "region": "us-east-1", "service": "sts"},
                         "/?Action=GetCallerIdentity&Version=2011-06-15")
        creds = {"access_key_id": "AKIDEXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
        self.assertTrue(validate_mod.validate_key(spec, creds))
        sent = json.dumps(Api.seen)
        self.assertNotIn("wJalrXUtnFEMI", sent)          # the secret signs; it is never sent


class NoLeaks(unittest.TestCase):
    def setUp(self):
        self.s = Servers().__enter__()

    def tearDown(self):
        self.s.__exit__()

    def paths_on_other(self):
        return [r for r in Api.seen if r["headers"].get("host", "").endswith(f":{Api.other_port}")]

    def test_token_post_follows_no_redirect(self):
        spec = {"method": "GET", "url": self.s.base + "/me", "expect": [200],
                "auth": {"type": "oauth2_client_credentials", "token_url": self.s.base + "/bounce",
                         "client_id_field": "app_id", "client_secret_field": "secret"}}
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod.validate_key(spec, CREDS)
        self.assertEqual(self.paths_on_other(), [])

    def test_query_key_follows_no_redirect(self):
        spec = {"method": "GET", "url": self.s.base + "/bounce", "expect": [200],
                "auth": {"type": "query", "param": "appid"}}
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod.validate_key(spec, SECRET)
        self.assertEqual(self.paths_on_other(), [])

    def test_every_credential_header_stripped_on_redirect(self):
        spec = {"method": "GET", "url": self.s.base + "/bounce", "expect": [200],
                "auth": {"type": "headers", "headers": {"X-App-Id": "{app_id}", "X-Key": "{secret}"}}}
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod.validate_key(spec, CREDS)
        for r in self.paths_on_other():
            self.assertNotIn("x-app-id", r["headers"])
            self.assertNotIn("x-key", r["headers"])

    def test_unsendable_value_named_by_field_and_never_repeated(self):
        spec = {"method": "GET", "url": self.s.base + "/me", "expect": [200],
                "auth": {"type": "headers", "headers": {"X-App-Id": "{app_id}", "X-Key": "{secret}"}}}
        with self.assertRaises(validate_mod.UnsendableKey) as cm:
            validate_mod.validate_key(spec, {"app_id": APP, "secret": "bad’key"})
        self.assertEqual(cm.exception.field, "secret")
        self.assertNotIn("bad", str(cm.exception))
        self.assertEqual(Api.seen, [])


class RecipeRules(unittest.TestCase):
    def ok(self, data):
        recipes_mod.validate_recipe(data)

    def bad(self, data, words):
        with self.assertRaises(recipes_mod.RecipeError) as cm:
            recipes_mod.validate_recipe(data)
        self.assertIn(words, str(cm.exception))

    def test_good_shapes_load(self):
        self.ok(recipe({"type": "headers", "headers": {"X-A": "{app_id}", "X-B": "{secret}"}}))
        self.ok(recipe({"type": "oauth2_client_credentials", "token_url": "https://api.example.com/t",
                        "client_id_field": "app_id", "client_secret_field": "secret"}))
        self.ok(recipe({"type": "query", "param": "appid"}, fields=None))

    def test_unknown_or_unused_field(self):
        self.bad(recipe({"type": "headers", "headers": {"X-A": "{app_id}", "X-B": "{nope}"}}), "unknown field")
        self.bad(recipe({"type": "headers", "headers": {"X-A": "{app_id}"}}), "never checked")

    def test_token_url_must_be_https(self):
        self.bad(recipe({"type": "oauth2_client_credentials", "token_url": "http://api.example.com/t",
                         "client_id_field": "app_id", "client_secret_field": "secret"}), "https")

    def test_env_var_must_be_first_field(self):
        r = recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        r["env_var"] = "X_SECRET"
        self.bad(r, "first field")

    def test_field_rules(self):
        dup = [dict(TWO[0]), dict(TWO[0], name="other")]
        self.bad(recipe({"type": "basic", "username_field": "app_id", "password_field": "other"}, fields=dup),
                 "repeats")
        bad_pattern = [dict(TWO[0], pattern="(("), TWO[1]]
        self.bad(recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"},
                        fields=bad_pattern), "compile")

    def test_cli_token_programs_are_fixed(self):
        r = recipe({"type": "bearer"}, fields=None, cli_token={"token": ["curl", "evil.example"]})
        self.bad(r, "may only run")

    def test_header_name_injection_refused(self):
        self.bad(recipe({"type": "headers", "headers": {"X-A\r\nEvil": "{app_id}", "X-B": "{secret}"}}),
                 "")

    def test_all_builtin_recipes_load(self):
        loaded = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        files = [f for f in os.listdir(recipes_mod.RECIPES_DIR) if f.endswith(".json")]
        self.assertEqual(len(loaded), len(files))
        for slug in ("ebay", "twilio", "paypal", "spotify", "aws", "openweather"):
            self.assertIn(slug, loaded)


class ConnectFlow(unittest.TestCase):
    def run_connect(self, rec, answers, validate=None, **kw):
        out = io.StringIO()
        stored = {}
        it = iter(answers)

        def prompt(text):
            out.write(text + "<typed>\n")       # what getpass would show (never the value)
            return next(it)
        code = connect_mod.connect(
            dict(rec, _builtin=False), browser_open=lambda u: None, prompt=prompt,
            out=out, validate_fn=validate or (lambda spec, creds: creds == CREDS),
            store_fn=lambda var, val: stored.setdefault(var, val) and f"stored {var}", **kw)
        return code, out.getvalue(), stored

    def test_two_fields_stored_and_never_printed(self):
        rec = recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        code, text, stored = self.run_connect(rec, [APP, SECRET])
        self.assertEqual(code, 0)
        self.assertEqual(stored, {"X_APP_ID": APP, "X_SECRET": SECRET})
        self.assertNotIn(APP, text)
        self.assertNotIn(SECRET, text)
        self.assertIn("Paste the App ID (hidden)", text)

    def test_rejected_pair_asked_again(self):
        rec = recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        code, text, stored = self.run_connect(rec, [APP, "wrong", APP, SECRET])
        self.assertEqual(code, 0)
        self.assertIn("credentials rejected", text)

    def test_preview_shows_token_endpoint_before_asking(self):
        rec = recipe({"type": "oauth2_client_credentials", "token_url": "https://api.example.com/oauth/token",
                      "client_id_field": "app_id", "client_secret_field": "secret"})
        _, text, _ = self.run_connect(rec, [APP, SECRET])
        self.assertLess(text.index("POST https://api.example.com/oauth/token"), text.index("Paste the App ID"))

    def test_foreign_token_endpoint_needs_typed_yes(self):
        rec = recipe({"type": "oauth2_client_credentials", "token_url": "https://evil.example.net/token",
                      "client_id_field": "app_id", "client_secret_field": "secret"})
        out = io.StringIO()
        code = connect_mod.connect(dict(rec, _builtin=False), browser_open=lambda u: None,
                                   prompt=lambda p: self.fail("asked for a key"), out=out,
                                   confirm_in=lambda p: "", store_fn=lambda v, k: "")
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENT domain", out.getvalue())

    def test_via_cli_only_for_builtin(self):
        rec = recipe({"type": "bearer"}, fields=None, cli_token={"token": ["gh", "auth", "token"]})
        code, text, _ = self.run_connect(rec, [], via_cli=True)
        self.assertEqual(code, 1)
        self.assertIn("built-in", text)

    def test_via_cli_token_validated_and_stored(self):
        rec = dict(recipe({"type": "bearer"}, fields=None, cli_token={"token": ["gh", "auth", "token"]}),
                   _builtin=True)
        out, stored = io.StringIO(), {}
        code = connect_mod.connect(rec, browser_open=lambda u: self.fail("browser"), out=out,
                                   validate_fn=lambda s, k: k == "ghp_FAKE", via_cli=True,
                                   cli_token_fn=lambda r, o: "ghp_FAKE",
                                   store_fn=lambda v, k: stored.setdefault(v, k) and "ok")
        self.assertEqual((code, stored), (0, {"X_KEY": "ghp_FAKE"}))
        self.assertNotIn("ghp_FAKE", out.getvalue())


class FakeClipboard:
    def __init__(self, timeline):
        self.timeline, self.cleared = list(timeline), 0
        self.value = self.timeline.pop(0) if self.timeline else ""

    def get(self):
        return self.value

    def clear(self):
        self.cleared += 1
        self.value = ""

    def sleep(self, _):
        if self.timeline:
            self.value = self.timeline.pop(0)


class CopyAndGo(unittest.TestCase):
    REAL_WAIT = staticmethod(clip_mod.wait_for_key)

    def wait(self, clip, pattern=None, taken=()):
        ticks = iter(range(10_000))
        return self.REAL_WAIT(pattern, set(taken), clip.get, clip.clear, wait=50, poll=0,
                                     now=lambda: next(ticks), sleep=clip.sleep)

    def test_takes_new_key_and_empties_clipboard(self):
        clip = FakeClipboard(["some old text", "some old text", "sk_live_abcdefghijklmnop"])
        self.assertEqual(self.wait(clip), "sk_live_abcdefghijklmnop")
        self.assertEqual((clip.cleared, clip.value), (1, ""))

    def test_ignores_stale_and_non_key_text(self):
        clip = FakeClipboard(["sk_live_STALEVALUE12345", "hello world with spaces", "short", "REALKEY-1234567890"])
        self.assertEqual(self.wait(clip), "REALKEY-1234567890")

    def test_pattern_accepts_early_copy_and_rejects_other_keys(self):
        sid = "AC" + "0123456789abcdef" * 2
        self.assertEqual(self.wait(FakeClipboard([sid]), r"^AC[0-9a-fA-F]{32}$"), sid)
        clip = FakeClipboard(["", "sk_live_notasid1234567", sid])
        self.assertEqual(self.wait(clip, r"^AC[0-9a-fA-F]{32}$"), sid)

    def test_second_field_needs_a_different_value(self):
        clip = FakeClipboard(["", "SAMEVALUE-12345678", "SAMEVALUE-12345678", "OTHERVALUE-87654321"])
        self.assertEqual(self.wait(clip, taken={"SAMEVALUE-12345678"}), "OTHERVALUE-87654321")

    def test_times_out_to_none(self):
        self.assertIsNone(self.wait(FakeClipboard(["", "not a key at all"])))

    def test_connect_with_clipboard_never_prints_value(self):
        clip = FakeClipboard(["", APP, SECRET])
        rec = recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        out, stored = io.StringIO(), {}
        with mock.patch.object(clip_mod, "wait_for_key",
                               lambda p, t, g, c, **k: self.wait(clip, p, t)):
            code = connect_mod.connect(dict(rec, _builtin=False), browser_open=lambda u: None,
                                       prompt=lambda p: self.fail("prompted"), out=out,
                                       validate_fn=lambda s, c: c == CREDS, clipboard=(clip.get, clip.clear),
                                       confirm_in=lambda p: "", store_fn=lambda v, k: stored.setdefault(v, k) and "ok")
        self.assertEqual(code, 0)
        self.assertEqual(stored, {"X_APP_ID": APP, "X_SECRET": SECRET})
        self.assertNotIn(APP, out.getvalue())
        self.assertIn("clipboard emptied", out.getvalue())


class RunAndForget(unittest.TestCase):
    def test_run_injects_every_value(self):
        rec = recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        store = {"X_APP_ID": APP, "X_SECRET": SECRET}
        seen = {}
        code = keychain_mod.run_with_key(rec, ["prog"], backend="fake", env={},
                                         read_fn=lambda svc, var, b: store.get(var),
                                         call=lambda cmd, env: seen.update(env) or 0)
        self.assertEqual(code, 0)
        self.assertEqual({k: seen[k] for k in store}, store)

    def test_run_refuses_when_one_value_missing(self):
        rec = recipe({"type": "basic", "username_field": "app_id", "password_field": "secret"})
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.run_with_key(rec, ["prog"], backend="fake", env={},
                                      read_fn=lambda svc, var, b: APP if var == "X_APP_ID" else None,
                                      call=lambda cmd, env: 0)


class AwsSignatureMatchesBotocore(unittest.TestCase):
    def test_against_botocore(self):
        try:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials
        except ImportError:
            self.skipTest("botocore not installed")
        import datetime
        creds = {"access_key_id": "AKIDEXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                 "tok": "FQoGZXIvYXdzEXAMPLE+token/=="}
        for url, token in (("https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", None),
                           ("https://sts.amazonaws.com/?Version=2011-06-15&Action=GetCallerIdentity", "tok"),
                           ("https://example.amazon.com/a%20b/c?x=a%2Fb", None)):
            req = AWSRequest(method="GET", url=url, headers={})
            SigV4Auth(Credentials(creds["access_key_id"], creds["secret_access_key"],
                                  creds[token] if token else None), "sts", "us-east-1").add_auth(req)
            when = datetime.datetime.strptime(req.headers["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(
                tzinfo=datetime.timezone.utc)
            auth = {"type": "aws_sigv4", "region": "us-east-1", "service": "sts"}
            if token:
                auth["session_token_field"] = token
            mine = validate_mod._sigv4_headers(auth, creds, "GET", url, when)
            self.assertEqual(mine["Authorization"], req.headers["Authorization"], url)


if __name__ == "__main__":
    unittest.main()
