"""0.11 (expert round 2): `guard` (learn fingerprints of keys not yet moved),
`adopt` (move .env keys into the keychain with no copying), hex-key detection,
nested-YAML masking, calls_hour / tokens_call caps, and leakbench's new
probes and profiles."""

import io
import json
import os
import random
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import adopt as adopt_mod
from stuntkey import broker, caps, guard, recipes, scan, scrub
from stuntkey import hook as hook_mod
from stuntkey import keychain as keychain_mod

CATALOG = recipes.load_recipes(recipes.RECIPES_DIR)
OPAQUE = "%040x" % random.Random(5).getrandbits(160)     # 40 random hex chars, built at run time
GH = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zA7bC"
OPENAI = "sk-proj-" + "Zq8Lm3Vt7Kp2Wn9Yb4Qe6Rx1Hd5Gs0"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


class FakeKeychain:
    KeychainError = keychain_mod.KeychainError

    def __init__(self, backend="fake", saved=None):
        self.backend, self.saved = backend, dict(saved or {})

    def detect_backend(self):
        return self.backend

    def read(self, service, var, _b):
        return self.saved.get((service, var))

    def store(self, service, var, key, _b):
        self.saved[(service, var)] = key
        return "fake"


class HexKeys(unittest.TestCase):
    def test_random_hex_keys_are_recognised(self):
        rng = random.Random(11)
        for n, allowed in ((32, 0.002), (40, 0.001), (64, 0.001)):
            miss = sum(not scan._secret_value_ok("%0*x" % (n, rng.getrandbits(4 * n)))
                       for _ in range(4000))
            self.assertLessEqual(miss / 4000, allowed, n)

    def test_patterns_and_short_hex_are_still_refused(self):
        for bad in ("deadbeef" * 3, "ab" * 16, "a1" * 14, "1234567890123456789012345a",
                    "a" * 40, "0000000000000000000000000000000a"):
            self.assertFalse(scan._secret_value_ok(bad), bad)

    def test_nested_yaml_key_is_masked(self):
        text = f"github.com:\n    oauth_token: {OPAQUE}\n"
        out, n = scrub.mask_secrets(text, (b"", frozenset()))
        self.assertNotIn(OPAQUE, out)
        self.assertEqual(n, 1)

    def test_assignment_does_not_swallow_the_next_line(self):
        out, _ = scrub.mask_secrets(f"name:\napi_key = {OPAQUE}\n", (b"", frozenset()))
        self.assertNotIn(OPAQUE, out)


class Replace(unittest.TestCase):
    def test_group_is_replaced_and_other_entries_kept(self):
        path = os.path.join(_isolation.mktemp(), "fp.json")
        scrub.remember_key("svc/KEY", "own-" + OPAQUE, path)
        added, dropped = scrub.replace_group("guard/", {"guard/a": OPAQUE, "guard/b": GH}, path)
        self.assertEqual((added, dropped), (2, 0))
        added, dropped = scrub.replace_group("guard/", {"guard/a": OPAQUE}, path)
        self.assertEqual((added, dropped), (1, 1))
        prints = scrub.load_fingerprints(path)
        self.assertTrue(scrub.has_stored_key("x " + OPAQUE, prints))
        self.assertTrue(scrub.has_stored_key("own-" + OPAQUE, prints))
        self.assertFalse(scrub.has_stored_key(GH, prints))
        self.assertNotIn(OPAQUE, read(path))       # fingerprints only, never the value

    def test_other_names_are_refused(self):
        path = os.path.join(_isolation.mktemp(), "fp.json")
        self.assertEqual(scrub.replace_group("guard/", {"svc/KEY": OPAQUE}, path)[0], 0)


class Guard(unittest.TestCase):
    def setUp(self):
        self.home, self.root = _isolation.mktemp(), _isolation.mktemp()
        write(os.path.join(self.root, ".env"), f"DB_KEY={OPAQUE}\nDEBUG=true\nPORT=8080\n")
        write(os.path.join(self.home, ".npmrc"), f"//registry.npmjs.org/:_authToken={GH}\n")
        write(os.path.join(self.home, ".bash_history"), f"export SVC_TOKEN={OPAQUE[::-1]}\n")
        write(os.path.join(self.home, ".claude", "history.jsonl"),
              json.dumps({"display": "the api key is " + OPAQUE[1:] + "x1"}) + "\n")
        self.fp = os.path.join(self.home, ".stuntkey", scrub.FINGERPRINT_FILE)

    def args(self, **kw):
        base = dict(path=self.root, dry_run=False, no_home=False, no_env=True,
                    quiet=False, forget=False)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def run_guard(self, **kw):
        out = io.StringIO()
        code = guard.cmd_guard(self.args(**kw), CATALOG, out, environ={}, home=self.home)
        return code, out.getvalue()

    def test_learns_project_dotfiles_and_history_without_printing_a_key(self):
        code, text = self.run_guard()
        self.assertEqual(code, 0)
        for secret in (OPAQUE, GH, OPAQUE[::-1], OPAQUE[1:] + "x1"):
            self.assertNotIn(secret, text)
            self.assertNotIn(secret, read(self.fp))
        prints = scrub.load_fingerprints(self.fp)
        for secret in (OPAQUE, GH, OPAQUE[::-1], OPAQUE[1:] + "x1"):
            self.assertTrue(scrub.has_stored_key(f"error: bad {secret} rejected", prints), secret)
        self.assertIn("In your home folder", text)

    def test_non_secret_settings_are_not_learned(self):
        self.run_guard()
        prints = scrub.load_fingerprints(self.fp)
        for plain in ("true", "8080", "DEBUG"):
            self.assertFalse(scrub.has_stored_key(plain, prints))

    def test_dry_run_writes_nothing(self):
        code, text = self.run_guard(dry_run=True)
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.fp))
        self.assertIn("would learn", text)

    def test_second_run_drops_a_value_that_is_gone(self):
        self.run_guard()
        os.remove(os.path.join(self.home, ".npmrc"))
        _code, text = self.run_guard()
        self.assertIn("dropped", text)
        self.assertFalse(scrub.has_stored_key(GH, scrub.load_fingerprints(self.fp)))

    def test_forget_keeps_keys_saved_with_get(self):
        scrub.remember_key("openai/OPENAI_API_KEY", "own-" + OPAQUE, self.fp)
        self.run_guard()
        self.run_guard(forget=True)
        prints = scrub.load_fingerprints(self.fp)
        self.assertFalse(scrub.has_stored_key(OPAQUE, prints))
        self.assertTrue(scrub.has_stored_key("own-" + OPAQUE, prints))

    def test_environment_variables_that_look_like_keys(self):
        out = io.StringIO()
        guard.cmd_guard(self.args(no_env=False, no_home=True), CATALOG, out,
                        environ={"PATH": "/usr/bin", "SVC_API_KEY": OPAQUE[::-1], "LANG": "C"},
                        home=self.home)
        self.assertNotIn(OPAQUE[::-1], out.getvalue())
        self.assertIn("$SVC_API_KEY", out.getvalue())

    def test_not_a_folder_is_refused(self):
        code, _ = self.run_guard(path=os.path.join(self.root, "nope"))
        self.assertEqual(code, 2)

    def test_a_project_full_of_fake_keys_cannot_crowd_out_the_shell(self):
        rng = random.Random(3)
        mine = "%040x" % rng.getrandbits(160)
        write(os.path.join(self.root, ".env"),
              "".join(f"K{i}_TOKEN={'%040x' % rng.getrandbits(160)}\n" for i in range(30)))
        with mock.patch.object(guard, "MAX_LEARNED", 10):
            res = guard.collect(self.root, self.home, CATALOG, {"MY_API_KEY": mine},
                                include_home=False)
        self.assertIn(mine, res.values.values())
        self.assertLessEqual(len(res.values), 10)
        self.assertGreater(res.over_limit, 0)

    def test_limit_keeps_the_file_small(self):
        with mock.patch.object(guard, "MAX_LEARNED", 2):
            write(os.path.join(self.root, ".env"),
                  "".join(f"K{i}_TOKEN={OPAQUE[:-2]}{i:02d}\n" for i in range(5)))
            _code, text = self.run_guard(no_home=True)
        self.assertIn("were not learned", text)

    def test_hook_then_masks_and_refuses_the_learned_value(self):
        self.run_guard()
        with mock.patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home}):
            status, out = hook_mod.check(json.dumps({
                "hook_event_name": "PostToolUse", "tool_name": "Bash",
                "tool_input": {"command": "python app.py"},
                "tool_response": {"stdout": f"Traceback\nValueError: {OPAQUE}\n",
                                  "stderr": "", "interrupted": False, "isImage": False}}))
            self.assertEqual(status, 0)
            self.assertNotIn(OPAQUE, out)
            status, out = hook_mod.check(json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": "Write",
                "tool_input": {"file_path": "t.py", "content": f"KEY = '{OPAQUE}'\n"}}))
            self.assertIn("deny", out)


class HookKeepsAgentsOut(unittest.TestCase):
    def test_agent_cannot_run_adopt_or_guard(self):
        for cmd in ("stuntkey adopt --yes --remove", "stuntkey guard --forget",
                    "python -m stuntkey guard"):
            status, out = hook_mod.check(json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": cmd}}))
            self.assertIn("deny", out, cmd)


class Adopt(unittest.TestCase):
    def setUp(self):
        self.root = _isolation.mktemp()
        self.env = os.path.join(self.root, ".env")
        write(self.env, f"# my app\nOPENAI_KEY={OPENAI}\nGITHUB_TOKEN=\"{GH}\"\nDEBUG=1\n")
        self.kc = FakeKeychain()

    def args(self, **kw):
        base = dict(path=self.root, dry_run=False, remove=False, yes=True)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def run_adopt(self, **kw):
        out = io.StringIO()
        code = adopt_mod.cmd_adopt(self.args(**kw), CATALOG, out, ask=lambda p: "y",
                                   keychain=self.kc)
        return code, out.getvalue()

    def test_stores_under_the_usual_name_and_leaves_the_file(self):
        before = read(self.env)
        code, text = self.run_adopt()
        self.assertEqual(code, 0)
        self.assertEqual(self.kc.saved[("openai", "OPENAI_API_KEY")], OPENAI)
        self.assertEqual(self.kc.saved[("github", "GITHUB_TOKEN")], GH)
        self.assertEqual(read(self.env), before)
        self.assertNotIn(OPENAI, text)
        self.assertNotIn(GH, text)
        self.assertIn("--remove", text)

    def test_dry_run_changes_nothing(self):
        code, text = self.run_adopt(dry_run=True)
        self.assertEqual((code, self.kc.saved), (0, {}))
        self.assertIn("OpenAI", text)

    def test_remove_comments_the_lines_out_and_keeps_the_rest(self):
        write(self.env, f"A=1\r\nOPENAI_KEY={OPENAI}\r\nexport GITHUB_TOKEN=\"{GH}\"\r\nDEBUG=1\r\n")
        code, _ = self.run_adopt(remove=True)
        self.assertEqual(code, 0)
        text = read(self.env)
        self.assertNotIn(OPENAI, text)
        self.assertNotIn(GH, text)
        self.assertIn("A=1\r\n", text)
        self.assertIn("DEBUG=1\r\n", text)
        self.assertIn("# OPENAI_KEY moved to the stuntkey keychain", text)

    def test_declined_question_stores_nothing(self):
        out = io.StringIO()
        code = adopt_mod.cmd_adopt(self.args(yes=False), CATALOG, out, ask=lambda p: "n",
                                   keychain=self.kc)
        self.assertEqual((code, self.kc.saved), (5, {}))

    def test_no_keychain_means_no_move(self):
        self.kc = FakeKeychain(backend=None)
        code, text = self.run_adopt()
        self.assertEqual(code, 1)
        self.assertEqual(read(self.env).count(OPENAI), 1)
        self.assertIn("No OS keychain", text)

    def test_already_stored_service_is_not_replaced(self):
        self.kc = FakeKeychain(saved={("openai", "OPENAI_API_KEY"): "old-" + OPENAI})
        self.run_adopt()
        self.assertEqual(self.kc.saved[("openai", "OPENAI_API_KEY")], "old-" + OPENAI)

    def test_example_files_and_non_env_files_are_never_edited(self):
        for name in (".env.example", "notes.md"):
            self.assertFalse(adopt_mod._editable_env(name), name)
        for name in (".env", ".env.local", "prod.env"):
            self.assertTrue(adopt_mod._editable_env(name), name)

    def test_file_changed_since_the_scan_is_left_alone(self):
        picked, _ = adopt_mod.plan(self.root, CATALOG, "fake", self.kc)
        write(self.env, "OPENAI_KEY=rotated\n")
        out = io.StringIO()
        n = adopt_mod._remove_lines(self.root, picked, out)
        self.assertEqual(n, 0)
        self.assertEqual(read(self.env), "OPENAI_KEY=rotated\n")

    def test_service_with_two_values_is_left_to_get(self):
        write(self.env, "AWS_ACCESS_KEY_ID=AKIA" + "Q7ZP4LMV3KXW9N2R\n")
        _, text = self.run_adopt()
        self.assertEqual(self.kc.saved, {})

    def test_a_keychain_that_refuses_is_reported(self):
        class Refusing(FakeKeychain):
            def store(self, *a, **k):
                raise keychain_mod.KeychainError("no")
        self.kc = Refusing()
        code, text = self.run_adopt()
        self.assertEqual(code, 1)
        self.assertIn("refused", text)


class MoreCaps(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()

    def set_caps(self, **limits):
        write(caps.caps_path(self.home), json.dumps({"svc": limits}))

    def test_requested_tokens_spellings(self):
        self.assertEqual(caps.requested_tokens({"max_tokens": 50}), 50)
        self.assertEqual(caps.requested_tokens(b'{"max_completion_tokens": 7}'), 7)
        self.assertEqual(caps.requested_tokens('{"generationConfig":{"maxOutputTokens":9}}'), 9)
        self.assertEqual(caps.requested_tokens({"max_tokens": 5, "max_output_tokens": 6}), 6)
        for none in ({}, [], "not json", b"\xff\xfe", {"max_tokens": True},
                     {"max_tokens": -4}, {"max_tokens": "9"}, None):
            self.assertIsNone(caps.requested_tokens(none), none)

    def test_tokens_per_call(self):
        self.set_caps(tokens_call=100)
        caps.begin(self.home, "svc", 0, request_tokens=100)
        with self.assertRaises(broker.BrokerError) as e:
            caps.begin(self.home, "svc", 0, request_tokens=101)
        self.assertIn("101", str(e.exception))
        caps.begin(self.home, "svc", 0)               # names no limit: not checked

    def test_daily_tokens_count_what_a_call_may_use(self):
        self.set_caps(tokens_day=1000)
        caps.add_tokens(self.home, "svc", 900)
        with self.assertRaises(broker.BrokerError):
            caps.begin(self.home, "svc", 0, request_tokens=200)
        caps.begin(self.home, "svc", 0, request_tokens=100)

    def test_calls_per_hour_ignores_the_session_counter(self):
        self.set_caps(calls_hour=3)
        for _ in range(3):
            caps.begin(self.home, "svc", 0)
        with self.assertRaises(broker.BrokerError) as e:
            caps.begin(self.home, "svc", 0)
        self.assertIn("this hour", str(e.exception))

    def test_calls_per_hour_resets_next_hour(self):
        self.set_caps(calls_hour=1)
        caps.begin(self.home, "svc", 0)
        with mock.patch.object(caps, "_hour", return_value="2999-01-01T00"):
            caps.begin(self.home, "svc", 0)

    def test_old_usage_files_without_an_hour_still_load(self):
        write(caps.usage_path(self.home, "svc"),
              json.dumps({"day": caps._today(), "calls": 4, "tokens": 9}))
        self.set_caps(calls_hour=2)
        caps.begin(self.home, "svc", 0)

    def test_broker_call_refuses_a_giant_request_before_sending(self):
        write(caps.caps_path(self.home), json.dumps({"openai": {"tokens_call": 4096}}))
        pol = broker.Policy(allow_write=True, home=self.home)
        sent = []
        with self.assertRaises(broker.BrokerError):
            broker.call(recipes.load_recipes()["openai"], {"OPENAI_API_KEY": GH}, "POST",
                        "/v1/chat/completions", body={"max_tokens": 10 ** 6}, policy=pol,
                        send=lambda *a, **k: sent.append(1),
                        resolver=lambda h, p, **k: [(2, 1, 6, "", ("104.18.6.192", p))])
        self.assertEqual(sent, [])

    def test_caps_set_accepts_the_new_flags(self):
        from stuntkey import cli
        a = cli._build_parser().parse_args(
            ["caps", "set", "openai", "--calls-hour", "5", "--tokens-call", "100"])
        self.assertEqual((a.calls_hour, a.tokens_call), (5, 100))
        self.assertEqual(set(caps.LIMITS),
                         {"calls_session", "calls_hour", "calls_day", "tokens_day", "tokens_call"})


class LeakbenchRound2(unittest.TestCase):
    def test_new_probes_are_loaded_and_unique(self):
        from leakbench import loader
        probes = loader.load()
        ids = [p.id for p in probes]
        self.assertEqual(len(ids), len(set(ids)))
        cats = {p.category for p in probes}
        self.assertTrue({"evasion", "agent footprint"} <= cats)
        self.assertGreaterEqual(len(probes), 140)

    def test_opaque_canary_has_no_vendor_shape(self):
        from leakbench import sandbox
        c = sandbox.new_canary("opaque")
        self.assertEqual(len(c), 40)
        self.assertFalse(c.startswith("sk-"))
        with self.assertRaises(ValueError):
            sandbox.new_canary("nope")

    def test_guard_closes_what_an_unseen_opaque_key_leaks(self):
        from leakbench import harness, report
        unseen = report.summary(harness.run("stuntkey-hook-unseen", canary_style="opaque"))
        learned = report.summary(harness.run("stuntkey-hook-learned", canary_style="opaque"))
        self.assertGreater(unseen["leaked"], learned["leaked"] + 8)
        self.assertLessEqual(learned["leaked"], 6)

    def test_orphan_key_in_notes_still_leaks_even_when_learned(self):
        from leakbench import harness
        got = {r.probe_id: r.status
               for r in harness.run("stuntkey-hook-learned", canary_style="opaque")}
        self.assertEqual(got["notes-file-says-key"], "leaked")

    def test_caps_stop_the_two_new_spend_shapes(self):
        from leakbench import harness
        got = {r.probe_id: r.status for r in harness.run("stuntkey-full")}
        self.assertEqual(got["giant-max-tokens-call"], "blocked")
        self.assertEqual(got["fresh-session-loop"], "blocked")
        hook = {r.probe_id: r.status for r in harness.run("stuntkey-hook")}
        self.assertEqual(hook["giant-max-tokens-call"], "leaked")

    def test_profile_spend_with_one_argument_still_works(self):
        from leakbench import runner, sandbox
        sbx = sandbox.build()
        self.addCleanup(sandbox.destroy, sbx)
        self.assertEqual(runner._call_spend(lambda s: "old style", sbx, {}), "old style")
        self.assertEqual(runner._call_spend(lambda s, r: r["spend"], sbx, {"spend": "x"}), "x")


if __name__ == "__main__":
    unittest.main()


class BigHistory(unittest.TestCase):
    def test_a_history_file_past_the_scanner_limit_is_still_read_in_pieces(self):
        home, root = _isolation.mktemp(), _isolation.mktemp()
        rng = random.Random(9)
        early = "%032x" % rng.getrandbits(128)
        lines = [json.dumps({"m": f"line {i} the key is {early if i == 3 else 'none'}"})
                 for i in range(40)]
        pad = json.dumps({"m": "x" * 5000})
        write(os.path.join(home, ".claude", "history.jsonl"),
              "\n".join(lines[:5] + [pad] * 600 + lines[5:]) + "\n")
        self.assertGreater(os.path.getsize(os.path.join(home, ".claude", "history.jsonl")), 3_000_000)
        res = guard.collect(root, home, CATALOG, {})
        self.assertIn(early, res.values.values())
        self.assertTrue(any("history.jsonl:4" in item.where for item in res.learned))

    def test_a_binary_or_missing_home_file_is_skipped(self):
        home, root = _isolation.mktemp(), _isolation.mktemp()
        with open(os.path.join(home, ".bash_history"), "wb") as f:
            f.write(b"\0\1\2" * 100)
        os.makedirs(os.path.join(home, ".netrc"))          # a folder where a file is expected
        self.assertEqual(guard.collect(root, home, CATALOG, {}).values, {})
