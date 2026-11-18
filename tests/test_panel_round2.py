"""Panel round 2 (builder A): clipboard / hidden prompt, Grep and Read checks,
Read / Grep output masking, strict policy loading, the warden feed and
GraphQL-aware route rules.

Everything is synthetic: fake keys, a throwaway HOME, the in-memory keychain.
"""

import io
import json
import os
import sys
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import broker, cmds, connect as connect_mod, hook as hook_mod
from stuntkey import clipboard as clip_mod, keychain, policy, safeprompt, scrub, wardenfeed

K = "zq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1Jf"                  # 30 characters, no known key format
K40 = K + "AbCdEfGhIj"
CANARY = "CANARYzq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1JfZZ"


def _memory_keychain(case):
    os.environ["STUNTKEY_KEYCHAIN"] = "memory"
    keychain._memory.clear()
    case.addCleanup(keychain._memory.clear)
    case.addCleanup(lambda: os.environ.pop("STUNTKEY_KEYCHAIN", None))   # else it leaks into later tests

    def rm():
        folder = os.path.dirname(scrub.fingerprint_path())
        for name in ("fingerprints.json", "integrity-fingerprint.key", "audit.log", "audit.log.head"):
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass
    case.addCleanup(rm)


# ============================================================ 1. clipboard / hidden prompt

FIELD_GENERIC = {"name": "api_key", "label": "API key", "env_var": "X_API_KEY", "accept": None}
FIELD_KNOWN = {"name": "api_key", "label": "API key", "env_var": "X_API_KEY", "accept": "^sk-ant-"}


class ClipboardEmptiedClaim(unittest.TestCase):
    def _run(self, field, cleared: bool, **kw):
        out = io.StringIO()
        state = {"text": K40}

        def get():
            return state["text"]

        def clear():
            if cleared:
                state["text"] = ""
            return cleared
        real = clip_mod.clear_verified
        with mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: K40), \
                mock.patch.object(clip_mod, "clear_verified",
                                  lambda g, c: real(g, c, wait=0, sleep=lambda s: None)):
            value = connect_mod._ask_one(field, True, lambda t: "", out, (get, clear), set(), **kw)
        return value, out.getvalue()

    def test_says_emptied_only_when_it_was(self):
        value, text = self._run(FIELD_KNOWN, True)
        self.assertEqual(value, K40)
        self.assertIn("clipboard emptied", text)
        self.assertNotIn(K40, text)

    def test_warns_loudly_when_it_could_not_be_emptied(self):
        value, text = self._run(FIELD_KNOWN, False)
        self.assertEqual(value, K40)
        self.assertIn("could NOT empty the clipboard", text)
        self.assertNotIn("clipboard emptied", text)
        self.assertNotIn(K40, text)


class UnknownSiteConfirm(unittest.TestCase):
    def _run(self, field, answer, generic):
        out, asked = io.StringIO(), []

        def reader(prompt):
            asked.append(prompt)
            return answer
        with mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: K40):
            value = connect_mod._ask_one(field, True, lambda t: "", out, (lambda: "", lambda: True),
                                         set(), reader, generic=generic, where="into .env")
        return value, out.getvalue(), asked

    def test_unknown_site_shows_three_characters_and_length_then_typing_them_saves(self):
        value, text, asked = self._run(FIELD_GENERIC, "zq9", True)
        self.assertEqual(value, K40)
        self.assertEqual(len(asked), 1)
        self.assertIn('"zq9"', text)
        self.assertIn(f"{len(K40)} characters", text)
        self.assertIn("into .env", text)
        self.assertNotIn(K40, text)
        self.assertNotIn(K40[:8], text)

    def test_unknown_site_no_throws_it_away(self):
        value, text, _ = self._run(FIELD_GENERIC, "n", True)
        self.assertIsNone(value)
        self.assertIn("Nothing was saved", text)

    def test_a_key_pasted_at_the_question_is_not_taken_as_yes(self):
        value, text, _ = self._run(FIELD_GENERIC, K40, True)
        self.assertIsNone(value)
        self.assertNotIn(K40, text)

    def test_known_recipe_stays_zero_prompt(self):
        value, text, asked = self._run(FIELD_KNOWN, "", False)
        self.assertEqual(value, K40)
        self.assertEqual(asked, [])

    def test_a_known_field_with_no_pattern_but_a_built_in_recipe_is_not_asked(self):
        value, _t, asked = self._run(FIELD_GENERIC, "", False)       # generic=False: a recipe we know
        self.assertEqual(value, K40)
        self.assertEqual(asked, [])


class HiddenPromptNeedsATerminal(unittest.TestCase):
    def test_no_terminal_stops_before_asking(self):
        with mock.patch.object(sys, "stdin", io.StringIO("")), \
                mock.patch.object(safeprompt.getpass, "getpass") as gp:
            with self.assertRaises(EOFError):
                safeprompt.read_hidden("x: ")
        self.assertFalse(gp.called)

    def test_closed_input_does_not_hang_and_connect_says_so(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", None):
            value = connect_mod._ask_one(FIELD_KNOWN, True, safeprompt.read_hidden, out, None, set())
        self.assertIsNone(value)
        self.assertIn("normal terminal window", out.getvalue())
        self.assertIn("Nothing was saved", out.getvalue())

    def _tty(self, answer):
        return types.SimpleNamespace(isatty=lambda: True, readline=lambda: answer,
                                     fileno=lambda: 0)

    def test_a_terminal_that_cannot_hide_typing_says_so_and_wants_a_yes(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stdin", self._tty("n\n")), mock.patch.object(sys, "stderr", err), \
                mock.patch.object(safeprompt, "stdin_is_terminal", lambda: True), \
                mock.patch.object(safeprompt, "_read_masked", side_effect=ImportError), \
                mock.patch.object(safeprompt, "_drain_input", lambda: None), \
                mock.patch.object(safeprompt.getpass, "getpass") as gp:
            with self.assertRaises(EOFError):
                safeprompt.read_hidden("x: ")
        self.assertIn("VISIBLE", err.getvalue())
        self.assertFalse(gp.called)

    def test_yes_goes_on_to_the_plain_prompt(self):
        with mock.patch.object(sys, "stdin", self._tty("yes\n")), mock.patch.object(sys, "stderr", io.StringIO()), \
                mock.patch.object(safeprompt, "stdin_is_terminal", lambda: True), \
                mock.patch.object(safeprompt, "_read_masked", side_effect=ImportError), \
                mock.patch.object(safeprompt, "_drain_input", lambda: None), \
                mock.patch.object(safeprompt.getpass, "getpass", lambda p: "typed"):
            self.assertEqual(safeprompt.read_hidden("x: "), "typed")


# ============================================================ 2a. Grep key-prefix probes

def decision(tool, **args):
    status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                                             "tool_input": args}))
    assert status == 0
    if not out:
        return None
    spec = json.loads(out)["hookSpecificOutput"]
    return spec["permissionDecisionReason"] if spec["permissionDecision"] == "deny" else None


class KeyProbeShape(unittest.TestCase):
    def test_prefixes_and_shapes_are_probes(self):
        for p in ("sk-", "^sk-ant-", r"\bAKIA[0-9A-Z]", "ghp_", "xox[bp]-", "github_pat_", "AIza",
                  "[A-Za-z0-9]{32,}", "(?i)SK-", "eyJ"):
            with self.subTest(p=p):
                self.assertTrue(hook_mod.is_key_probe(p))

    def test_ordinary_searches_are_not(self):
        for p in ("def main", "TODO", "import os", "", None, 5, "asia", "skip", "{5}"):
            with self.subTest(p=p):
                self.assertFalse(hook_mod.is_key_probe(p))


class GrepProbeCheck(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K40)
        self.dir = _isolation.mktemp()

    def _file(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_probe_over_a_folder_that_holds_a_stored_key_is_refused(self):
        self._file("notes.txt", "token is " + K40 + "\n")
        why = decision("Grep", pattern="sk-", path=self.dir, output_mode="content")
        self.assertIsNotNone(why)
        self.assertIn("start of a key", why)
        self.assertNotIn(K40, why)

    def test_probe_over_a_single_file_that_holds_one_is_refused(self):
        p = self._file("a.txt", "x\n" + K40)
        self.assertIsNotNone(decision("Grep", pattern="AKIA", path=p))

    def test_probe_over_a_clean_folder_passes(self):
        self._file("a.txt", "nothing to see\n")
        self.assertIsNone(decision("Grep", pattern="sk-", path=self.dir))

    def test_an_ordinary_pattern_over_the_same_folder_may_list_files_but_not_print_lines(self):
        self._file("notes.txt", "token is " + K40 + "\n")
        self.assertIsNone(decision("Grep", pattern="token", path=self.dir,
                                   output_mode="files_with_matches"))
        self.assertIsNone(decision("Grep", pattern="token", path=self.dir, output_mode="count"))
        self.assertIsNotNone(decision("Grep", pattern="token", path=self.dir))     # default = content
        self.assertIsNotNone(decision("Grep", pattern="token", path=self.dir, output_mode="content"))

    def test_too_many_files_fails_closed(self):
        for i in range(5):
            self._file(f"f{i}.txt", "clean\n")
        with mock.patch.object(hook_mod, "PROBE_SCAN_FILES", 3):
            self.assertIsNotNone(decision("Grep", pattern="ghp_", path=self.dir))

    def test_a_file_too_big_to_check_fails_closed(self):
        self._file("big.txt", "clean\n" * 50)
        with mock.patch.object(hook_mod, "PROBE_FILE_CAP", 100):
            self.assertIsNotNone(decision("Grep", pattern="ghp_", path=self.dir))

    def test_out_of_time_fails_closed(self):
        self._file("a.txt", "clean\n")
        with mock.patch.object(hook_mod, "PROBE_BUDGET_S", -1):
            self.assertIsNotNone(decision("Grep", pattern="ghp_", path=self.dir))

    def test_a_probe_with_no_path_checks_the_current_folder(self):
        self._file("a.txt", K40)
        here = os.getcwd()
        os.chdir(self.dir)
        try:
            self.assertIsNotNone(decision("Grep", pattern="sk-"))
        finally:
            os.chdir(here)

    def test_a_missing_path_is_left_to_grep(self):
        self.assertIsNone(decision("Grep", pattern="sk-", path=os.path.join(self.dir, "nope")))


# ============================================================ 2b. Read scans the whole file

class ReadScansTheWholeFile(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K40)
        self.dir = _isolation.mktemp()

    def _file(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_a_key_past_the_old_600k_window_is_found(self):
        p = self._file("report.txt", "x" * (hook_mod.SCAN_BUDGET + 50_000) + "\n" + K40 + "\n")
        self.assertIsNotNone(decision("Read", file_path=p))

    def test_oversized_file_in_a_secret_place_is_refused(self):
        p = self._file("secrets_dump.txt", "clean line\n" * 400)
        with mock.patch.object(hook_mod, "READ_SCAN_CAP", 1000):
            why = decision("Read", file_path=p)
        self.assertIsNotNone(why)
        self.assertIn("too large to check", why)

    def test_oversized_file_elsewhere_is_scanned_as_far_as_the_cap_only(self):
        p = self._file("notes.txt", "clean line\n" * 400)
        never = __import__("re").compile(r"(?!x)x")
        with mock.patch.object(hook_mod, "READ_SCAN_CAP", 1000), \
                mock.patch.object(hook_mod, "_TEMP_PATH_RE", never):
            self.assertIsNone(decision("Read", file_path=p))

    def test_secret_places_are_recognised(self):
        for p in ("/home/a/.aws/config", "C:\\Users\\a\\.ssh\\known", "/x/my_token.txt", "/x/api_key.json",
                  "/x/id_rsa", "/x/prod.pem", "/x/.stuntkey/state"):
            with self.subTest(p=p):
                self.assertTrue(hook_mod._secret_likely_path(p))
        self.assertFalse(hook_mod._secret_likely_path("/home/a/project/readme.md"))


# ============================================================ 2c. Read / Grep output masking

def read_resp(content, **over):
    r = {"type": "text", "file": {"filePath": "/p/a.txt", "content": content, "numLines": 3,
                                  "startLine": 1, "totalLines": 3}}
    r.update(over)
    return r


def grep_resp(content, **over):
    r = {"mode": "content", "numFiles": 1, "filenames": ["/p/a.txt"], "content": content,
         "numLines": 2}
    r.update(over)
    return r


def post(tool, response):
    status, out = hook_mod.check(json.dumps({"hook_event_name": "PostToolUse", "tool_name": tool,
                                             "tool_input": {}, "tool_response": response}))
    assert status == 0
    return json.loads(out)["hookSpecificOutput"] if out else None


class ReadGrepOutputMasking(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K40)

    def test_the_matcher_includes_read_and_grep(self):
        import re
        for tool in ("Read", "Grep", "Bash", "mcp__x__y"):
            self.assertTrue(re.match(hook_mod.POST_MATCHER, tool), tool)
        self.assertFalse(re.match(hook_mod.POST_MATCHER, "Glob"))

    def test_read_shape_is_masked_and_other_fields_are_untouched(self):
        resp = read_resp("line one\nkey=" + K40 + "\nline three\n")
        spec = post("Read", resp)
        new = spec["updatedToolOutput"]
        self.assertNotIn(K40, json.dumps(spec))
        self.assertIn("[REDACTED]", new["file"]["content"])
        for k in ("filePath", "numLines", "startLine", "totalLines"):
            self.assertEqual(json.dumps(new["file"][k]), json.dumps(resp["file"][k]))
        self.assertEqual(new["type"], "text")
        self.assertEqual(set(new), {"type", "file"})
        self.assertEqual(set(new["file"]), set(resp["file"]))

    def test_a_clean_read_is_left_alone(self):
        self.assertIsNone(post("Read", read_resp("nothing secret here\n")))

    def test_wrong_shapes_return_nothing(self):
        bad = [
            "plain string " + K40,
            {"content": K40},
            {"type": "file_unchanged", "file": {"filePath": "/p"}},
            {"type": "image", "file": read_resp(K40)["file"]},
            {"type": "text", "file": dict(read_resp(K40)["file"], numLines="3")},   # wrong type
            {"type": "text", "file": dict(read_resp(K40)["file"], content=[K40])},  # not a string
            [read_resp(K40)],
            None,
        ]
        for resp in bad:
            with self.subTest(resp=str(resp)[:60]):
                self.assertIsNone(post("Read", resp))

    def test_grep_content_mode_is_masked_and_other_fields_untouched(self):
        resp = grep_resp("a.txt:1:key=" + K40 + "\na.txt:2:ok\n")
        new = post("Grep", resp)["updatedToolOutput"]
        self.assertIn("[REDACTED]", new["content"])
        self.assertNotIn(K40, json.dumps(new))
        for k in ("mode", "numFiles", "filenames", "numLines"):
            self.assertEqual(json.dumps(new[k]), json.dumps(resp[k]))
        self.assertEqual(set(new), set(resp))

    def test_grep_other_modes_and_odd_shapes_return_nothing(self):
        for resp in ({"mode": "files_with_matches", "numFiles": 1, "filenames": [K40]},
                     {"mode": "count", "content": K40, "numFiles": 1},
                     grep_resp(K40, numLines="2"),
                     K40):                       # (round 4: {"content": ...} with no mode is content: masked)
            with self.subTest(resp=str(resp)[:60]):
                self.assertIsNone(post("Grep", resp))

    def test_a_format_key_with_no_stored_copy_is_masked_too(self):
        fake = "ghp_" + "A1b2C3d4E5" * 4          # fake GitHub-shaped token
        out = post("Read", read_resp("x " + fake + " y"))
        if out is not None:                          # only if the format rules know it
            self.assertNotIn(fake, json.dumps(out))

    def test_non_secret_text_is_byte_identical_around_the_mask(self):
        before, after = "alpha \u00e9\u4e2d\n\tbeta ", " gamma  \n"
        new = post("Read", read_resp(before + K40 + after))["updatedToolOutput"]["file"]["content"]
        self.assertTrue(new.startswith(before))
        self.assertTrue(new.endswith(after))

    def test_a_locked_fingerprint_withholds_with_the_shape_kept(self):
        resp = read_resp("secret")
        payload = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": resp}
        with mock.patch.object(scrub, "load_fingerprints", side_effect=scrub.FingerprintLocked("locked")):
            out = json.loads(hook_mod.post_check(payload, err=io.StringIO()))["hookSpecificOutput"]
        self.assertEqual(out["updatedToolOutput"]["file"]["content"], hook_mod.LOCKED_NOTICE)
        self.assertEqual(out["updatedToolOutput"]["file"]["numLines"], 3)


# ============================================================ 4. strict policy loading

def parse(raw: bytes):
    return policy.parse(raw)


class StrictPolicy(unittest.TestCase):
    def test_unknown_key_is_refused_with_a_hint(self):
        with self.assertRaises(broker.BrokerError) as ctx:
            parse(b'{"openai": {"method": ["GET"], "paths": ["/v1/models"]}}')
        msg = str(ctx.exception)
        self.assertIn('did you mean "methods"', msg)
        self.assertIn("allowed: methods, paths", msg)
        with self.assertRaises(broker.BrokerError) as ctx:
            parse(b'{"openai": {"methods": ["GET"], "paths": ["/"], "allow": ["x"]}}')
        self.assertIn("unknown key", str(ctx.exception))

    def test_other_case_key_is_refused_not_ignored(self):
        with self.assertRaises(broker.BrokerError) as ctx:
            parse(b'{"openai": {"Methods": ["GET"], "paths": ["/"]}}')
        self.assertIn('"methods"', str(ctx.exception))

    def test_nan_and_infinity_are_refused(self):
        for raw in (b'{"a": {"methods": ["GET"], "paths": ["/"], "x": NaN}}',
                    b'{"a": {"methods": [Infinity], "paths": ["/"]}}',
                    b'{"a": {"methods": ["GET"], "paths": [-Infinity]}}'):
            with self.subTest(raw=raw):
                with self.assertRaises(broker.BrokerError):
                    parse(raw)

    def test_a_utf8_bom_is_accepted(self):
        rules = parse(b"\xef\xbb\xbf" + b'{"openai": {"methods": ["get"], "paths": ["/v1/models"]}}')
        self.assertEqual(rules["openai"][0], frozenset({"GET"}))

    def test_non_utf8_has_a_clear_error(self):
        raw = '{"openai": {"methods": ["GET"], "paths": ["/caf\u00e9"]}}'.encode("utf-16")
        with self.assertRaises(broker.BrokerError) as ctx:
            parse(raw)
        self.assertIn("UTF-8", str(ctx.exception))
        with self.assertRaises(broker.BrokerError) as ctx:
            parse(b'{"a": {"methods": ["GET"], "paths": ["/\xff"]}}')
        self.assertIn("UTF-8", str(ctx.exception))

    def test_case_insensitive_duplicate_names_are_still_refused(self):
        with self.assertRaises(broker.BrokerError):
            parse(b'{"OpenAI": {"methods": ["GET"], "paths": ["/a"]}, "openai": {"methods": ["GET"], "paths": ["/"]}}')
        with self.assertRaises(broker.BrokerError):
            parse(b'{"a": {"methods": ["GET"], "METHODS": ["POST"], "paths": ["/"]}}')

    def test_an_empty_list_means_nothing_is_allowed(self):
        rules = parse(b'{"openai": {"methods": [], "paths": ["/v1/models"]}}')
        with self.assertRaises(broker.BrokerError):
            policy.check(rules, "openai", "GET", "/v1/models")
        rules = parse(b'{"openai": {"methods": ["GET"], "paths": []}}')
        with self.assertRaises(broker.BrokerError):
            policy.check(rules, "openai", "GET", "/v1/models")
        self.assertIn("nothing allowed", policy.describe(parse(b'{"openai": {}}')))

    def test_a_good_file_still_loads(self):
        rules = parse(b'{"openai": {"methods": ["GET", "POST"], "paths": ["/v1/chat/completions"]}}')
        policy.check(rules, "openai", "POST", "/v1/chat/completions")


# ============================================================ 5. the warden feed

LOG_LINES = [
    {"service": "github", "method": "GET", "host": "api.github.com", "path": "/user?token=" + CANARY,
     "status": 200, "bytes": 512, "result": "ok", "ms": 250, "ts": 1_800_000_000, "note": CANARY},
    {"service": "github", "method": "GET", "host": "api.github.com", "path": "/nope", "status": 404,
     "bytes": 20, "result": "ok", "ms": 10, "ts": 1_800_000_100},
    {"service": "github", "method": "POST", "host": "api.github.com", "path": "/repos", "status": 0,
     "bytes": 0, "result": "denied", "ms": 0, "ts": 1_800_000_200},
    {"service": "stripe", "method": "GET", "host": "api.stripe.com", "path": "/v1/x", "status": 0,
     "bytes": 0, "result": "refused", "ms": 0, "ts": 1_800_000_300},
    {"service": "stripe", "method": "GET", "host": "api.stripe.com", "path": "/v1/y", "status": 0,
     "bytes": 0, "result": "network-error", "ms": 0, "ts": 1_800_000_400},
    {"service": None, "method": "-", "host": "-", "path": "-", "status": 0, "bytes": 0,
     "result": "LOG-ROTATED", "ms": 0, "ts": 1_800_000_500, "note": "rotated"},
    {"service": "stripe", "method": "GET", "host": "x", "path": "/", "status": 1, "bytes": 0,
     "result": "something-new", "ms": 0, "ts": 1_800_000_600},
]


class WardenFeed(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()
        self.log = os.path.join(self.dir, "audit.log")
        with open(self.log, "w", encoding="utf-8") as f:
            for line in LOG_LINES:
                f.write(json.dumps(line) + "\n")
            f.write("this line is not json\n")
        self.out = os.path.join(self.dir, wardenfeed.FEED_NAME)

    def _read(self, path=None):
        with open(path or self.out, encoding="utf-8") as f:
            return [json.loads(line) for line in f.read().splitlines()]

    def test_every_call_line_has_warden_mcp_jail_fields(self):
        n = wardenfeed.export(self.log, self.out)
        rows = self._read()
        approvals = self._read(wardenfeed.planok_path(self.out))
        self.assertEqual(n, len(rows) + len(approvals))
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(set(r), {"run_id", "agent_id", "fleet", "tool", "server", "args",
                                      "allowed", "at"})
            self.assertEqual(r["agent_id"], "stuntkey")
            self.assertRegex(r["run_id"], r"^stuntkey-\d{4}-\d\d-\d\d$")
            self.assertRegex(r["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
            self.assertIsInstance(r["allowed"], bool)

    def test_first_call_is_allowed_and_has_no_query_string(self):
        wardenfeed.export(self.log, self.out)
        first = self._read()[0]
        self.assertEqual(first["args"]["service"], "github")
        self.assertEqual(first["args"]["method"], "GET")
        self.assertEqual(first["args"]["path"], "/user")
        self.assertTrue(first["allowed"])

    def test_denials_and_approvals_by_result(self):
        wardenfeed.export(self.log, self.out)
        calls = self._read()
        approvals = self._read(wardenfeed.planok_path(self.out))
        self.assertIn(False, [c["allowed"] for c in calls])             # refused and denied calls
        self.assertEqual(len(approvals), 1)
        a = approvals[0]
        self.assertEqual(set(a), {"run_id", "agent_id", "gate", "decision", "approver",
                                  "requested_at", "decided_at"})
        self.assertEqual(a["decision"], "denied")
        self.assertEqual(a["approver"], "person")

    def test_no_query_string_no_canary_and_markers_are_skipped(self):
        wardenfeed.export(self.log, self.out)
        for path in (self.out, wardenfeed.planok_path(self.out)):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn(CANARY, text)
            self.assertNotIn("?", text)
            self.assertNotIn("LOG-ROTATED", text)
            self.assertNotIn("something-new", text)
            self.assertNotIn("net.egress", text)
            self.assertNotIn("net_bytes", text)

    def test_running_twice_gives_the_same_file_and_the_log_is_unchanged(self):
        with open(self.log, "rb") as f:
            before = f.read()
        wardenfeed.export(self.log, self.out)
        with open(self.out, "rb") as f:
            one = f.read()
        wardenfeed.export(self.log, self.out)
        with open(self.out, "rb") as f:
            two = f.read()
        self.assertEqual(one, two)
        with open(self.log, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_since_keeps_only_newer_entries(self):
        all_n = wardenfeed.export(self.log, self.out)
        newer = wardenfeed.export(self.log, self.out, "2027-01-15T08:00:00Z")   # ts 1_800_000_000 = 2027-01-15T08:00:00Z
        self.assertLessEqual(newer, all_n)
        none = wardenfeed.export(self.log, self.out, "2100-01-01")
        self.assertEqual(none, 0)
        with self.assertRaises(wardenfeed.FeedError):
            wardenfeed.export(self.log, self.out, "last tuesday")

    def test_cannot_overwrite_the_activity_log(self):
        with self.assertRaises(wardenfeed.FeedError):
            wardenfeed.export(self.log, self.log)

    def test_the_command(self):
        class Stub:
            path = self.log

            def verify(self):
                return True, 3
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cmds.broker, "AuditLog", lambda p: Stub()), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            code = cmds.cmd_audit("export", False, warden=True, out_path=self.out)
            self.assertEqual(code, 0)
            self.assertIn("wrote", out.getvalue())
            self.assertEqual(cmds.cmd_audit("export", False, warden=False), cmds.USAGE)
            self.assertEqual(cmds.cmd_audit("export", False, warden=True, since="nope",
                                            out_path=self.out), cmds.USAGE)
        self.assertTrue(os.path.exists(self.out))


# ============================================================ 6. GraphQL query or mutation

def gql(doc, **extra):
    return json.dumps(dict({"query": doc}, **extra)).encode()


class GraphqlKind(unittest.TestCase):
    def kind(self, body, path="/graphql", query=None):
        return policy.graphql_kind(path, body, query)

    def test_queries(self):
        for doc in ("{ viewer { login } }", "query { viewer { login } }",
                    "query Q($a: Int = 3) { x(a: $a) { id } }", "# hi\n{ a }",
                    "query A { a } query B { b }", "{ a(s: \"mutation { x }\") }",
                    "fragment F on T { id } query { ...F }", "query Q @dir(a: {b: 1}) { a }"):
            with self.subTest(doc=doc):
                self.assertEqual(self.kind(gql(doc)), "query")

    def test_mutations_and_unreadable_are_mutations(self):
        for doc in ("mutation { deleteAll }", "mutation M($x: ID!) { del(id: $x) }",
                    "subscription { tick }", "query { a } mutation { b }", "",
                    "{ a ", "schema { query: Q }", "extend type Q { x: Int }", "query",
                    "query { a } }", "{ a(s: \"unterminated) }", "nonsense",
                    "\ufeffmutation { x }"):
            with self.subTest(doc=doc):
                self.assertEqual(self.kind(gql(doc)), "mutation")

    def test_a_batch_is_a_mutation_if_any_member_is(self):
        batch = json.dumps([{"query": "{ a }"}, {"query": "mutation { b }"}]).encode()
        self.assertEqual(self.kind(batch), "mutation")
        ok = json.dumps([{"query": "{ a }"}, {"query": "{ b }"}]).encode()
        self.assertEqual(self.kind(ok), "query")

    def test_ambiguous_bodies_on_a_graphql_path_are_mutations(self):
        for body in (b"not json", b'{"extensions": {"persistedQuery": {"sha256Hash": "ab"}}}',
                     b'{"query": 5}', b"[1]", b"\xff\xfe"):
            with self.subTest(body=body):
                self.assertEqual(self.kind(body), "mutation")

    def test_not_graphql_at_all(self):
        self.assertIsNone(self.kind(None, "/v1/models"))
        self.assertIsNone(self.kind(b'{"name": "x"}', "/v1/things"))
        self.assertIsNone(self.kind(b"plain", "/v1/things"))
        self.assertEqual(self.kind(None, "/graphql"), "mutation")    # round 3: no document = persisted query = unknown

    def test_a_get_with_a_query_parameter(self):
        self.assertEqual(self.kind(None, "/graphql", {"query": "{ a }"}), "query")
        self.assertEqual(self.kind(None, "/graphql", {"query": "mutation { a }"}), "mutation")

    def test_a_huge_document_is_a_mutation(self):
        self.assertEqual(self.kind(gql("{ a }" + " " * 300_000)), "mutation")


class GraphqlRouteRules(unittest.TestCase):
    def rules(self, methods):
        return policy.parse(json.dumps({"shop": {"methods": methods, "paths": ["/graphql"]}}).encode())

    def go(self, rules, method, body=None, query=None, path="/graphql"):
        policy.check(rules, "shop", method, path, body=body, query=query)

    def no(self, rules, method, body=None, query=None, path="/graphql"):
        with self.assertRaises(broker.BrokerError) as ctx:
            policy.check(rules, "shop", method, path, body=body, query=query)
        return str(ctx.exception)

    def test_read_only_graphql_rule_lets_queries_through_and_stops_mutations(self):
        r = self.rules(["GET", "QUERY"])
        self.go(r, "POST", gql("{ shop { name } }"))
        why = self.no(r, "POST", gql("mutation { productDelete(id: 1) { id } }"))
        self.assertIn("GraphQL mutation", why)
        self.assertIn("MUTATION", why)

    def test_unknown_or_ambiguous_graphql_is_treated_as_a_mutation(self):
        r = self.rules(["GET", "QUERY"])
        for body in (b"garbage", b'{"extensions": {}}', gql("nonsense"), gql("{ a "), gql("")):
            with self.subTest(body=body):
                self.no(r, "POST", body)

    def test_a_plain_post_without_graphql_needs_post(self):
        r = policy.parse(json.dumps({"shop": {"methods": ["GET", "QUERY"], "paths": ["/v1"]}}).encode())
        with self.assertRaises(broker.BrokerError):
            policy.check(r, "shop", "POST", "/v1/things", body=b'{"a": 1}')
        with self.assertRaises(broker.BrokerError):
            policy.check(r, "shop", "POST", "/v1/things")

    def test_mutation_rule_allows_mutations_but_not_unrelated_methods(self):
        r = self.rules(["QUERY", "MUTATION"])
        self.go(r, "POST", gql("mutation { a }"))
        self.go(r, "POST", gql("{ a }"))
        self.no(r, "DELETE")
        self.no(r, "GET")

    def test_post_keeps_meaning_any_post(self):
        r = self.rules(["GET", "POST"])
        self.go(r, "POST", gql("mutation { a }"))
        self.go(r, "POST", gql("{ a }"))
        self.go(r, "POST", b"whatever")

    def test_a_get_carrying_a_mutation_needs_mutation_in_the_rule(self):
        r = self.rules(["GET", "QUERY"])
        self.go(r, "GET", query={"query": "{ a }"})
        self.no(r, "GET", query={"query": "mutation { a }"})
        r2 = self.rules(["GET", "MUTATION"])
        self.go(r2, "GET", query={"query": "mutation { a }"})

    def test_batch_with_one_mutation_is_stopped(self):
        r = self.rules(["GET", "QUERY"])
        batch = json.dumps([{"query": "{ a }"}, {"query": "mutation { b }"}]).encode()
        self.no(r, "POST", batch)

    def test_a_service_without_a_rule_is_unchanged(self):
        policy.check({}, "shop", "POST", "/graphql", body=gql("mutation { a }"))

    def test_the_path_rule_still_applies_first(self):
        r = self.rules(["GET", "QUERY"])
        self.no(r, "POST", gql("{ a }"), path="/admin/graphql")

    def test_old_calls_without_a_body_still_work(self):
        r = self.rules(["GET"])
        self.go(r, "GET", path="/graphql/status")        # not a GraphQL address: an ordinary GET
        self.no(r, "GET")                                # round 3: a GET to /graphql with no document

    def test_the_gate_passes_the_body_on(self):
        home, proj = _isolation.mktemp(), _isolation.mktemp()
        with open(policy.user_file(home), "w", encoding="utf-8") as f:
            f.write('{"shop": {"methods": ["QUERY"], "paths": ["/graphql"]}}')
        policy.approve(home, proj, lambda s: True)
        gate = broker.Policy(home=home, project_dir=proj)
        gate.gate("shop", "POST", "/graphql", body=gql("{ a }"))
        with self.assertRaises(broker.BrokerError):
            gate.gate("shop", "POST", "/graphql", body=gql("mutation { a }"))


if __name__ == "__main__":
    unittest.main()
