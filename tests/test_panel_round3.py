"""Security panel, round 3: the verified round-2 findings.

1 attack-test cache keyed on a hash of the whole package   2 long lines, look-alikes, forms
3 Read / Grep shape: required keys only                    4 Grep over a key-holding place
5 GraphQL in the address, duplicate fields, persisted      6 warden feed paths and file shapes
7 key places: .env copy, locked keychain                   8 unknown site: type 3 characters
9 hints agree (overview / status / fix)                    10 setup ends in one state
11 completion, start, call, status                         12 leakbench usability probes
14 approval timeout                                        15 docs and the network-import list

Everything is synthetic: fake keys, a throwaway HOME, the in-memory keychain.
"""
import argparse
import contextlib
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import approve, broker, cli, clipboard as clip_mod, cmds, connect as connect_mod
from stuntkey import fixcmd, hook as hook_mod, keychain, policy, recipes as recipes_mod
from stuntkey import scrub, selftest, setupcmd, wardenfeed

REPO = _isolation.REPO
K = "zq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1JfAbCdEfGhIj"            # no known key format, not an example


def _memory_keychain(case):
    os.environ["STUNTKEY_KEYCHAIN"] = "memory"
    keychain._memory.clear()
    case.addCleanup(keychain._memory.clear)
    case.addCleanup(lambda: os.environ.pop("STUNTKEY_KEYCHAIN", None))

    def rm():
        folder = os.path.dirname(scrub.fingerprint_path())
        for name in ("fingerprints.json", "integrity-fingerprint.key", "audit.log", "audit.log.head"):
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass
    case.addCleanup(rm)


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def _hook(event, tool, **kw):
    status, out = hook_mod.check(json.dumps({"hook_event_name": event, "tool_name": tool, **kw}))
    assert status == 0
    return json.loads(out)["hookSpecificOutput"] if out else None


def decision(tool, **args):
    spec = _hook("PreToolUse", tool, tool_input=args)
    return spec["permissionDecisionReason"] if spec and spec["permissionDecision"] == "deny" else None


def read_resp(content, **over):
    r = {"type": "text", "file": {"filePath": "/p/a.txt", "content": content, "numLines": 3,
                                  "startLine": 1, "totalLines": 3}}
    r.update(over)
    return r


def post(tool, response):
    return _hook("PostToolUse", tool, tool_input={}, tool_response=response)


# ============================================================ 1. the attack-test cache

class SelftestCacheIsKeyedOnContent(unittest.TestCase):
    def _fake_package(self):
        d = _isolation.mktemp()
        for name, text in (("a.py", "x = 1\n"), ("recipes/r.json", "{}\n"), ("web/p.html", "<p>\n")):
            path = os.path.join(d, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return d

    def _stamp(self, d):
        with mock.patch.object(selftest, "__file__", os.path.join(d, "selftest.py")):
            return selftest._code_stamp()

    def test_the_stamp_is_a_sha256_of_everything(self):
        stamp = selftest._code_stamp()
        self.assertRegex(stamp, r"\|[0-9a-f]{64}$")

    def test_a_change_in_any_file_changes_the_stamp_even_with_the_same_date(self):
        d = self._fake_package()
        before = self._stamp(d)
        for name in ("a.py", os.path.join("recipes", "r.json"), os.path.join("web", "p.html")):
            path = os.path.join(d, name)
            st = os.stat(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write("# changed\n")
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))      # put the old date back
            after = self._stamp(d)
            self.assertNotEqual(before, after, name)
            before = after

    def test_a_planted_cache_with_a_wrong_hash_is_ignored(self):
        calls = []

        def fake_run_all():
            calls.append(1)
            return [{"pass": True}]
        fake_run_all.__module__ = selftest.__name__          # counts as the real one
        path = selftest._cache_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"stamp": "0.9.4|" + "0" * 64, "at": 1000.0, "passed": 77, "total": 77}, f)
        with mock.patch.object(selftest, "run_all", fake_run_all):
            got = selftest.checked(now=lambda: 1001.0)
            self.assertEqual(got, (1, 1, False))             # it ran: the planted cache was not believed
            self.assertEqual(calls, [1])
            again = selftest.checked(now=lambda: 1002.0)      # its own, honest cache is used
            self.assertEqual(again, (1, 1, True))
            self.assertEqual(calls, [1])


# ============================================================ 2. long lines, look-alikes, forms

class ReadMaskingOfOddFiles(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K)

    def _masked(self, text):
        out = post("Read", read_resp(text))
        self.assertIsNotNone(out, "the output was shown unchecked")
        return out["updatedToolOutput"]["file"]["content"]

    def test_a_key_across_a_piece_boundary_of_one_long_line_is_masked(self):
        for offset in (480, 500, 511, 512, 513, 700, 1023, 1024):
            with self.subTest(offset=offset):
                new = self._masked("y" * offset + K + "z" * 2000)
                self.assertNotIn(K, new)

    def test_a_key_on_the_last_long_line_of_a_big_file_is_masked(self):
        text = ("an ordinary line of text number 12345 here\n" * 20000) + "x" * 3000 + K + "\n"
        self.assertNotIn(K, self._masked(text))

    def test_a_text_that_cannot_be_checked_in_time_is_withheld_not_passed(self):
        with mock.patch.object(hook_mod, "POST_BUDGET", -1.0):
            new = self._masked("y" * 5000 + K)
        self.assertNotIn(K, new)
        self.assertEqual(new, scrub.WITHHELD_NOTICE)

    def test_fullwidth_and_cyrillic_lookalike_keys_are_masked(self):
        wide = "".join(chr(ord(c) + 0xFEE0) if c.isalnum() or c == "-" else c
                       for c in "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        self.assertNotIn(wide, self._masked("a\n" + wide + "\n"))
        self.assertIn("[REDACTED]", self._masked("a\n" + wide + "\n"))
        look = K.replace("p", chr(0x440)).replace("C", chr(0x421)).replace("X", chr(0x425))
        self.assertNotEqual(look, K)
        self.assertNotIn(look, self._masked("k=" + look + "\n"))

    def test_base64_and_hex_forms_of_a_stored_key_are_not_shown(self):
        import base64
        for form in (base64.b64encode(K.encode()).decode(), K.encode().hex()):
            with self.subTest(form=form[:12]):
                out = post("Read", read_resp("data: " + form + "\n"))
                self.assertIsNotNone(out)
                self.assertNotIn(form, json.dumps(out))


# ============================================================ 3. Read / Grep shape

class ShapeNeedsOnlyTheTextField(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K)

    def test_extra_keys_are_copied_through_and_the_text_is_masked(self):
        resp = read_resp("key=" + K, newField={"a": 1})
        resp["file"]["extra"] = [1, 2]
        new = post("Read", resp)["updatedToolOutput"]
        self.assertNotIn(K, json.dumps(new))
        self.assertEqual(new["newField"], {"a": 1})
        self.assertEqual(new["file"]["extra"], [1, 2])
        self.assertEqual(new["file"]["numLines"], 3)

    def test_grep_extra_keys_too(self):
        resp = {"mode": "content", "content": "a:1:" + K, "numLines": 1, "surprise": True}
        new = post("Grep", resp)["updatedToolOutput"]
        self.assertNotIn(K, json.dumps(new))
        self.assertTrue(new["surprise"])

    def test_a_missing_text_field_or_a_wrong_type_is_still_left_alone(self):
        self.assertIsNone(post("Read", {"type": "text", "file": {"filePath": "/p"}}))
        self.assertIsNone(post("Read", {"type": "text", "file": {"content": K, "numLines": "x"}}))
        self.assertIsNone(post("Grep", {"mode": "content", "content": 5}))

    def test_unknown_shapes_are_counted_for_doctor(self):
        before = hook_mod.shape_unverified_count()
        post("Read", {"type": "text", "file": {"filePath": "/p"}})
        self.assertEqual(hook_mod.shape_unverified_count(), before + 1)

    def test_the_count_reads_the_marker_in_a_log(self):
        d = _isolation.mktemp()
        path = os.path.join(d, "audit.log")
        line = json.dumps({"result": "HOOK-POST-SHAPE-UNVERIFIED"})
        with open(path, "w", encoding="utf-8") as f:
            f.write(line + "\n" + line + "\n" + json.dumps({"result": "ok"}) + "\n")
        self.assertEqual(hook_mod.shape_unverified_count(path), 2)

    def test_doctor_shows_the_count(self):
        from stuntkey import doctor
        out = io.StringIO()
        args = argparse.Namespace(service=None, timeout=1, json=True)
        with mock.patch.object(doctor.logfacts, "shape_unverified_count", lambda *a: 3), \
                mock.patch.object(doctor, "run", lambda *a, **k: []):
            doctor.cmd_doctor(args, {}, out=out)
        self.assertEqual(json.loads(out.getvalue())["hook_shape_unverified"], 3)


# ============================================================ 4. Grep over a key-holding place

class GrepContentOverAKeyPlace(unittest.TestCase):
    PATTERNS = ("s(?:k)-", "s[jk]-", "s.k-", "[A-Za-z0-9_-]+", "token", r"\w+", ".", "(?i)tok.n",
                "key")

    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K)
        self.dir = _isolation.mktemp()
        with open(os.path.join(self.dir, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("my token is " + K + "\n")
        self.clean = _isolation.mktemp()
        with open(os.path.join(self.clean, "a.txt"), "w", encoding="utf-8") as f:
            f.write("nothing here\n")

    def test_any_pattern_printing_lines_over_the_folder_is_refused(self):
        for pattern in self.PATTERNS:
            for kw in ({}, {"output_mode": "content"}):
                with self.subTest(pattern=pattern, kw=kw):
                    self.assertIsNotNone(decision("Grep", pattern=pattern, path=self.dir, **kw))

    def test_a_single_file_too(self):
        p = os.path.join(self.dir, "notes.txt")
        self.assertIsNotNone(decision("Grep", pattern="s.k-", path=p))

    def test_file_names_and_counts_are_allowed_there(self):
        for pattern in self.PATTERNS:
            for mode in ("files_with_matches", "count"):
                with self.subTest(pattern=pattern, mode=mode):
                    self.assertIsNone(decision("Grep", pattern=pattern, path=self.dir, output_mode=mode))

    def test_the_key_prefix_refusal_is_kept_in_every_mode(self):
        for pattern in ("sk-", "ghp_", "AKIA"):
            for mode in ("files_with_matches", "count", "content"):
                with self.subTest(pattern=pattern, mode=mode):
                    self.assertIsNotNone(decision("Grep", pattern=pattern, path=self.dir,
                                                  output_mode=mode))

    def test_a_clean_folder_is_not_in_the_way(self):
        for pattern in self.PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertIsNone(decision("Grep", pattern=pattern, path=self.clean))

    def test_with_no_stored_key_nothing_is_refused(self):
        scrub.forget_key("svc/API_KEY")
        self.assertIsNone(decision("Grep", pattern="token", path=self.dir))


# ============================================================ 5. GraphQL

def gql(doc, **extra):
    return json.dumps(dict({"query": doc}, **extra)).encode()


class GraphqlRound3(unittest.TestCase):
    def rules(self, methods):
        return policy.parse(json.dumps({"shop": {"methods": methods, "paths": ["/graphql"]}}).encode())

    def refused(self, rules, method, path="/graphql", body=None, query=None):
        with self.assertRaises(broker.BrokerError):
            policy.check(rules, "shop", method, path, body=body, query=query)

    def test_a_document_in_the_address_is_read(self):
        self.assertEqual(policy.graphql_kind("/graphql?query=mutation%7Ba%7D"), "mutation")
        self.assertEqual(policy.graphql_kind("/graphql?query=%7Ba%7D"), "query")
        self.assertEqual(policy.graphql_kind("/graphql?query=mutation{a}"), "mutation")
        r = self.rules(["GET", "QUERY"])
        self.refused(r, "GET", "/graphql?query=mutation{a}")
        policy.check(r, "shop", "GET", "/graphql?query=%7Ba%7D")

    def test_two_query_parameters_are_both_read(self):
        self.assertEqual(policy.graphql_kind("/graphql?query=%7Ba%7D&query=mutation%7Bb%7D"), "mutation")

    def test_duplicate_fields_in_a_json_body_count_as_a_mutation(self):
        for body in (b'{"query": "{ a }", "query": "mutation { b }"}',
                     b'{"query": "{ a }", "Query": "mutation { b }"}',
                     b'{"query": "{ a }", "operationName": "x", "OPERATIONNAME": "y"}',
                     b'{"query": "{ a }", "variables": {}, "Variables": {"x": 1}}'):
            with self.subTest(body=body):
                self.assertEqual(policy.graphql_kind("/graphql", body), "mutation")
                self.refused(self.rules(["GET", "QUERY"]), "POST", body=body)

    def test_one_of_each_is_still_a_query(self):
        body = gql("{ a }", operationName="a", variables={})
        self.assertEqual(policy.graphql_kind("/graphql", body), "query")

    def test_a_get_to_a_graphql_address_with_no_document_is_a_mutation(self):
        self.assertEqual(policy.graphql_kind("/graphql"), "mutation")
        self.assertEqual(policy.graphql_kind("/graphql?extensions=%7B%7D"), "mutation")
        self.refused(self.rules(["GET", "QUERY"]), "GET")
        policy.check(self.rules(["GET", "MUTATION"]), "shop", "GET", "/graphql")

    def test_other_addresses_are_not_graphql(self):
        self.assertIsNone(policy.graphql_kind("/v1/models"))
        self.assertIsNone(policy.graphql_kind("/v1/models?query=anything"))     # a search page, not GraphQL
        self.assertEqual(policy.graphql_kind("/v1/search?query=%7Ba%7D"), "query")
        self.assertEqual(policy.graphql_kind("/v1/search?query=mutation%7Ba%7D"), "mutation")


# ============================================================ 6. the warden feed

class WardenFeedPathsAndShapes(unittest.TestCase):
    def test_path_is_cut_masked_and_short(self):
        token = "ghp_" + "A1b2C3d4E5" * 4
        got = wardenfeed._path_only("/v1/" + token + "/a/b/c;jsessionid=abc?x=1#frag")
        self.assertNotIn(token, got)
        self.assertNotIn(";", got)
        self.assertNotIn("jsessionid", got)
        self.assertNotIn("?", got)
        parts = [p for p in got.split("/") if p]
        self.assertEqual(parts[0], "v1")
        self.assertEqual(len(parts), 3)                  # two kept parts and one short hash
        self.assertRegex(parts[2], r"^\.\.\.[0-9a-f]{8}$")

    def test_a_short_path_is_unchanged(self):
        self.assertEqual(wardenfeed._path_only("/user"), "/user")
        self.assertEqual(wardenfeed._path_only("/repos/x"), "/repos/x")
        self.assertEqual(wardenfeed._path_only(""), "/")

    def test_different_deep_paths_get_different_hashes(self):
        self.assertNotEqual(wardenfeed._path_only("/a/b/c/d"), wardenfeed._path_only("/a/b/c/e"))
        self.assertEqual(wardenfeed._path_only("/a/b/c/d"), wardenfeed._path_only("/a/b/c/d"))

    def test_the_file_shapes(self):
        entry = {"service": "github", "method": "POST", "host": "api.github.com",
                 "path": "/repos/o/r/issues?token=SECRETQ", "status": 0, "bytes": 5,
                 "result": "denied", "ms": 1000, "ts": 1_800_000_000}
        calls, approvals = wardenfeed.events_for(entry)
        self.assertEqual(len(calls), 1)
        self.assertEqual(set(calls[0]), {"run_id", "agent_id", "fleet", "tool", "server", "args",
                                         "allowed", "at"})
        self.assertFalse(calls[0]["allowed"])
        self.assertEqual(calls[0]["run_id"], "stuntkey-2027-01-15")
        self.assertEqual(set(approvals[0]), {"run_id", "agent_id", "gate", "decision", "approver",
                                             "requested_at", "decided_at"})
        self.assertIn(approvals[0]["decision"], ("approved", "denied", "timeout"))
        text = json.dumps([calls, approvals])
        self.assertNotIn("SECRETQ", text)
        self.assertNotIn("bytes", text)

    def test_lines_stay_under_a_megabyte(self):
        entry = {"service": "x" * 10_000_000, "method": "GET", "path": "/" + "p" * 10_000_000,
                 "result": "ok", "ts": 1_800_000_000}
        calls, _ = wardenfeed.events_for(entry)
        for c in calls:
            self.assertLess(len(json.dumps(c)), 1_000_000)
            self.assertLess(len(json.dumps(c)), 2000)

    def test_no_doc_claims_warden_reads_the_old_feed(self):
        for name in (("README.md",), ("docs", "guide.md"), ("stuntkey", "extras.py"),
                     ("stuntkey", "cmds.py"), ("stuntkey", "wardenfeed.py")):
            text = _read(*name)
            self.assertNotIn("warden-feed.jsonl", text, name)
            self.assertNotIn("net.egress", text, name)
        guide = _read("docs", "guide.md")
        self.assertIn("unverified against a live warden", guide)
        self.assertIn("report --from mcp-jail", guide)


# ============================================================ 7. where keys are

def _env_dir(case, text):
    d = tempfile.mkdtemp(prefix="r3env")
    case.addCleanup(_isolation.rmtree, d)
    with open(os.path.join(d, ".env"), "w", encoding="utf-8") as f:
        f.write(text)
    return os.path.join(d, ".env")


class KeyPlaces(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        self.catalog = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)

    def test_a_plaintext_copy_is_reported_even_when_the_keychain_has_the_key(self):
        env = _env_dir(self, f"OPENAI_API_KEY={K}\n")
        keychain.store("openai", "OPENAI_API_KEY", K, keychain.detect_backend())
        r = fixcmd.key_places_full(self.catalog, env)
        self.assertEqual((r["safe"], r["both"], r["loose"]), (["openai"], ["openai"], []))
        self.assertEqual(fixcmd.key_places(self.catalog, env), (["openai"], []))
        with mock.patch.object(fixcmd, "key_places_full", lambda *a, **k: r):
            item = fixcmd._keys_item(self.catalog)
        self.assertIn("plaintext copy", item.text)
        self.assertEqual(item.level, fixcmd.YELLOW)
        self.assertNotIn(K, item.text)

    def test_a_locked_keychain_is_not_called_no_key_saved(self):
        env = _env_dir(self, "")
        with mock.patch.object(keychain, "read", side_effect=keychain.KeychainUnavailable("locked")):
            r = fixcmd.key_places_full(self.catalog, env)
        self.assertTrue(r["unavailable"])
        self.assertEqual(r["safe"], [])
        with mock.patch.object(fixcmd, "key_places_full", lambda *a, **k: r):
            item = fixcmd._keys_item(self.catalog)
        self.assertIn("Keychain unavailable", item.text)
        self.assertNotIn("No key is saved yet", item.text)

    def test_nothing_anywhere_still_says_no_key_is_saved(self):
        env = _env_dir(self, "")
        r = fixcmd.key_places_full(self.catalog, env)
        self.assertEqual(r["unavailable"], [])
        with mock.patch.object(fixcmd, "key_places_full", lambda *a, **k: r):
            self.assertIn("No key is saved yet", fixcmd._keys_item(self.catalog).text)


# ============================================================ 8. an unknown site

FIELD_GENERIC = {"name": "api_key", "label": "API key", "env_var": "X_API_KEY", "accept": None}


class UnknownSiteNeedsTyping(unittest.TestCase):
    def _run(self, answer, reader="given", stdin_tty=True):
        out, asked = io.StringIO(), []

        def read(prompt):
            asked.append(prompt)
            return answer
        stdin = mock.Mock(isatty=lambda: stdin_tty)
        with mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: K), \
                mock.patch.object(sys, "stdin", stdin):
            value = connect_mod._ask_one(FIELD_GENERIC, True, lambda t: "", out,
                                         (lambda: "", lambda: True), set(),
                                         read if reader == "given" else None,
                                         generic=True, where="in your keychain")
        return value, out.getvalue(), asked

    def test_typing_the_first_three_characters_saves(self):
        value, text, asked = self._run(K[:3])
        self.assertEqual(value, K)
        self.assertEqual(len(asked), 1)
        self.assertNotIn(K, text)
        self.assertNotIn(K[:6], text)                    # no more characters than before

    def test_enter_means_no(self):
        value, text, _ = self._run("")
        self.assertIsNone(value)
        self.assertIn("Thrown away", text)

    def test_the_wrong_characters_or_the_wrong_case_mean_no(self):
        for answer in (K[:3].upper(), K[:2], "yes", "y", "n", K, "abc"):
            with self.subTest(answer=answer):
                value, text, _ = self._run(answer)
                self.assertIsNone(value)
                self.assertNotIn(K, text)

    def test_a_window_that_cannot_ask_refuses(self):
        value, text, asked = self._run("", reader=None, stdin_tty=False)
        self.assertIsNone(value)
        self.assertEqual(asked, [])
        self.assertIn("NOT kept", text)


# ============================================================ 9. the hints agree

class Hints(unittest.TestCase):
    def _missing_cli(self):
        from stuntkey import claudecode
        return (mock.patch.object(claudecode, "detected", lambda *a, **k: True),
                mock.patch.object(claudecode, "state", lambda *a, **k: "missing"),
                mock.patch.object(claudecode, "cli_path", lambda *a, **k: None))

    def test_fix_prints_the_exact_line_and_the_desktop_route(self):
        from stuntkey import claudecode
        item = fixcmd.Item("claude-code:user", fixcmd.YELLOW, "x", "Type this one command: y")
        text = fixcmd.manual_steps([item])
        self.assertIn(claudecode.one_command(), text)
        self.assertIn("Claude Desktop", text)
        self.assertEqual(fixcmd.manual_steps([fixcmd.Item("keys", fixcmd.GREEN, "ok")]), "")

    def test_cmd_fix_with_nothing_to_repair_still_shows_it(self):
        from stuntkey import claudecode
        item = fixcmd.Item("claude-code:user", fixcmd.YELLOW, "stuntkey is not plugged in", "Type it")
        out = io.StringIO()
        fixcmd.cmd_fix(argparse.Namespace(json=False, yes=False), collector=lambda c: [item], out=out)
        self.assertIn(claudecode.one_command(), out.getvalue())

    def test_overview_points_to_the_line_not_to_fix(self):
        from stuntkey import claudecode
        a, b, c = self._missing_cli()
        with a, b, c:
            text = cmds._next_step()
        self.assertIn(claudecode.one_command(), text)
        self.assertNotIn("`stuntkey fix`", text)

    def test_overview_otherwise_says_setup(self):
        from stuntkey import claudecode
        with mock.patch.object(claudecode, "detected", lambda *a, **k: False):
            self.assertIn("stuntkey setup", cmds._next_step())

    def test_status_with_no_setup_says_setup_not_init(self):
        d = _isolation.mktemp()
        here = os.getcwd()
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                cli.main(["--project-dir", d, "status", "--json"])
        finally:
            os.chdir(here)
        note = json.loads(out.getvalue())["note"]
        self.assertIn("stuntkey setup", note)
        self.assertNotIn("init", note)

    def test_no_run_stuntkey_init_in_the_status_and_fix_screens(self):
        for name in ("fixcmd.py", "cmds.py"):
            self.assertNotIn("stuntkey init", _read("stuntkey", name), name)


# ============================================================ 10. setup ends in one state

class SetupEnds(unittest.TestCase):
    def _final(self, problems, changed=True, ok_steps=("1 key(s) moved into your keychain",)):
        out = io.StringIO()
        code = setupcmd._final(out, list(ok_steps), problems, changed)
        return code, out.getvalue()

    def test_all_done_says_restart_once(self):
        code, text = self._final([])
        self.assertEqual(code, 0)
        self.assertIn("All done", text)
        self.assertIn("close Claude", text)
        self.assertNotIn("Almost done", text)
        self.assertNotIn("FAIL", text)

    def test_almost_done_never_says_restart_or_fail(self):
        code, text = self._final([("stuntkey is not plugged into any AI app yet", "Run `stuntkey fix`"),
                                  ("a .env still holds a key", "delete the lines")])
        self.assertEqual(code, 1)
        self.assertIn("Almost done: 2 steps left", text)
        self.assertNotIn("close Claude", text)
        self.assertNotIn("FAIL", text)
        self.assertNotIn("All done", text)

    def test_one_step_is_singular(self):
        _code, text = self._final([("x", "y")])
        self.assertIn("Almost done: 1 step left", text)

    def test_the_whole_command_never_mixes_a_fail_line_with_restart_words(self):
        # a setup whose final pretend call fails
        fail = setupcmd.Result(False, "FAIL: the pretend call was refused. Next: run doctor.",
                               ["the pretend call was refused. Next: run doctor."], fault=True)
        item = mock.Mock(level=fixcmd.GREEN, fixer=None, key="x")
        out = io.StringIO()
        args = argparse.Namespace(yes=True, dry_run=False)
        root = _isolation.mktemp()
        with mock.patch.object(setupcmd, "run_check", lambda c=None: fail), \
                mock.patch.object(fixcmd, "collect", lambda c=None, port=0: []), \
                mock.patch.object(setupcmd, "_scan_env", lambda *a, **k: {
                    "new": [], "have": [], "skipped": [], "unknown": [], "files": [], "backend": None}):
            code = setupcmd.cmd_setup_all(args, {}, out=out, root=root)
        text = out.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("Almost done", text)
        self.assertNotIn("FAIL", text)
        self.assertNotIn("close Claude", text)


# ============================================================ 11. completion, start, call, status

class SmallCommands(unittest.TestCase):
    def test_bare_completion_prints_an_install_hint_not_an_argparse_error(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["completion"])
        self.assertEqual(code, 2)
        self.assertIn("Install: stuntkey completion powershell >> $PROFILE", out.getvalue())
        self.assertNotIn("usage:", err.getvalue())
        self.assertNotIn("error:", err.getvalue())

    def test_completion_with_a_shell_still_works(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["completion", "bash"]), 0)
        self.assertIn("complete -F _stuntkey stuntkey", out.getvalue())

    def test_start_says_start_here_once(self):
        _memory_keychain(self)
        out = io.StringIO()
        cat = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        with mock.patch.object(fixcmd, "key_places", lambda *a, **k: ([], [])), \
                contextlib.redirect_stdout(out):
            cmds.cmd_start(cat, os.path.join(_isolation.mktemp(), ".env"))
        text = out.getvalue()
        self.assertEqual(text.count("Start here"), 1)
        self.assertNotIn("Ready. Next: stuntkey setup", text)

    def _call(self, status, as_json=False):
        recipe = {"service": "github"}
        args = argparse.Namespace(method="GET", path="/user", query=None, data=None,
                                  env_file=".env", json=as_json)
        out, err = io.StringIO(), io.StringIO()
        from stuntkey import remote
        with mock.patch.object(remote, "collect_values", lambda *a, **k: {"X": "v"}), \
                mock.patch.object(broker, "call", lambda *a, **k: {"status": status, "headers": {},
                                                                    "body": '{"a": 1}\n\n'}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cmds.cmd_call(recipe, args)
        return code, out.getvalue(), err.getvalue()

    def test_a_401_or_403_prints_one_plain_hint(self):
        for status in (401, 403):
            with self.subTest(status=status):
                code, out, err = self._call(status)
                self.assertEqual(err.count("The key was rejected. Run `stuntkey rotate github`."), 1)
                self.assertNotEqual(code, 0)

    def test_other_statuses_print_no_hint(self):
        for status in (200, 404, 500):
            with self.subTest(status=status):
                _code, _out, err = self._call(status)
                self.assertNotIn("rejected", err)

    def test_output_has_no_double_blank_lines_and_json_is_compact(self):
        _code, out, _err = self._call(200)
        self.assertNotIn("\n\n", out)
        _code, out, _err = self._call(200, as_json=True)
        self.assertIn('"status":200', out)                  # no spaces after : or ,
        self.assertEqual(json.loads(out)["status"], 200)

    def test_a_busy_port_note_is_not_marked_ok(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.addCleanup(s.close)
        item = fixcmd._port_item(s.getsockname()[1])
        self.assertEqual(item.level, fixcmd.GREEN)
        line = fixcmd._line(item)
        self.assertNotIn("[ok]", line)
        self.assertNotIn("✓", line)
        self.assertIn("Note, not a problem", line)


# ============================================================ 12. the usability probes

class UsabilityProbes(unittest.TestCase):
    def test_there_are_27_harmless_probes_and_64_attack_probes(self):
        from leakbench import loader
        benign = loader.load_benign()
        self.assertEqual(len(benign), 27)
        self.assertEqual(len(loader.load()), 64)                  # the published number is unchanged
        for p in benign:
            self.assertEqual((p.check, p.expect), ("benign", "allow"))
            self.assertTrue(p.must_contain)
        ids = {p.id for p in benign}
        self.assertEqual(len(ids), 27)
        wanted = ("ls", "pwd", "echo hello", "cat README.md", "cat package.json", ".env.example",
                  "git status", "git log -3", "print(2+2)", "node -e", "grep -r TODO src/",
                  "API_KEY", "echo $PATH", "env | grep ^PATH", "curl", "npm test",
                  "cat src/config.py", "LICENSE", "sort file.txt", "printenv NODE_ENV", "kubectl config view",
                  "terraform plan", "docker compose config", "npm run build", "pytest")
        blob = json.dumps([p.tool for p in benign])
        for w in wanted:
            self.assertIn(w, blob, w)
        self.assertTrue(any(p.tool["tool_name"] == "Write" for p in benign))

    def test_a_benign_probe_must_be_complete(self):
        from leakbench import loader
        d = _isolation.mktemp()
        with open(os.path.join(d, "x.json"), "w", encoding="utf-8") as f:
            json.dump([{"id": "a", "category": "benign", "attack": "x", "tool": {}, "check": "benign"}], f)
        with self.assertRaises(ValueError):
            loader.load_benign(d)

    def _r(self, status, probe="p"):
        from leakbench.runner import Result
        return Result(probe, "c", "prof", status, "d")

    def test_perfect_needs_no_leak_and_no_over_block(self):
        from leakbench import report
        good = [self._r("blocked"), self._r("masked")]
        ok = [self._r("allowed")] * 20
        self.assertTrue(report.perfect(good, ok))
        self.assertFalse(report.perfect(good + [self._r("leaked")], ok))
        self.assertFalse(report.perfect(good, ok[:19] + [self._r("over-blocked")]))
        self.assertFalse(report.perfect(good, []))                  # never measured: not perfect
        self.assertTrue(report.perfect(good, ok[:19] + [self._r("over-masked")]))   # only over-blocked counts

    def test_the_two_lines(self):
        from leakbench import report
        lines = report.lines_two([self._r("blocked")] * 60 + [self._r("masked")] * 4,
                                 [self._r("allowed")] * 19 + [self._r("over-blocked")])
        self.assertTrue(lines[0].startswith("Protection: blocked before the call 60, masked after the call 4"))
        self.assertTrue(lines[1].startswith("Usability: allowed 19 of 20"))
        self.assertIn("not perfect", lines[2])
        table = report.to_table([self._r("blocked")], "x", [self._r("allowed")])
        self.assertIn("Usability: allowed 1 of 1", table)
        data = json.loads(report.to_json([self._r("blocked")], "x", [self._r("allowed")]))
        self.assertTrue(data["benign"]["perfect"])

    def test_nothing_blocked_nothing_masked_under_the_baseline(self):
        from leakbench import harness, report
        res = harness.run_benign("none")
        s = report.benign_summary(res)
        self.assertEqual(len(res), 27)
        self.assertEqual(s["over-blocked"], 0)
        self.assertEqual(s["over-masked"], 0)
        self.assertGreaterEqual(s["allowed"], 12)             # a missing tool reads n/a, never a fail

    def test_the_readme_gives_the_measured_numbers(self):
        text = _read("README.md")
        self.assertIn("harmless everyday commands", text)   # the over-block count is published
        self.assertIn("env | grep ^PATH", text)
        lb = _read("leakbench", "README.md")
        self.assertIn("over-blocked", lb)
        self.assertIn("docker compose config", lb)   # the known over-block is named


# ============================================================ 14. approval timeout

class ApproveTimeout(unittest.TestCase):
    def t(self, value):
        return approve.timeout_seconds({approve.TIMEOUT_VAR: value} if value is not None else {})

    def test_default_and_clamps(self):
        self.assertEqual(self.t(None), 120)
        self.assertEqual(self.t(""), 120)
        self.assertEqual(self.t("abc"), 120)
        self.assertEqual(self.t("300"), 300)
        self.assertEqual(self.t("1"), 10)
        self.assertEqual(self.t("0"), 10)
        self.assertEqual(self.t("-5"), 10)
        self.assertEqual(self.t("99999"), 900)
        self.assertEqual(self.t(" 45 "), 45)
        self.assertEqual(self.t("nan"), 120)

    def test_it_is_read_from_the_environment_at_use_time(self):
        with mock.patch.dict(os.environ, {approve.TIMEOUT_VAR: "77"}):
            self.assertEqual(approve.timeout_seconds(), 77)
        self.assertEqual(approve.timeout_seconds(), 120)

    def test_the_variable_is_the_one_documented(self):
        self.assertEqual(approve.TIMEOUT_VAR, "STUNTKEY_APPROVE_TIMEOUT")
        self.assertNotIn("timeout=TIMEOUT", _read("stuntkey", "approve.py"))


# ============================================================ 15. docs and the network-import list

# Every module that imports a network library, and why. A new entry here is a decision a
# person makes on purpose; a module not listed that starts importing one fails the test.
NETWORK_MODULES = {
    "broker.py": "the brokered call itself (the calls you ask for)",
    "proxy.py": "the local proxy and its outbound call",
    "httpd.py": "the local web page (`serve`), listens on this machine only",
    "validate.py": "the key test `get` runs against the vendor you chose",
    "doctor.py": "`doctor` checks recipe addresses, when you run it",
    "publicapis.py": "`find`: a public list on GitHub, when you run it",
    "fixcmd.py": "`update-check --online` (pypi.org) and the local port check",
    "mint.py": "`mint`: asks the vendor to make a key, when you run it",
    "panic.py": "`panic`: asks the vendor to revoke a key, when you run it",
    "selftest.py": "attack tests against a pretend server on this machine",
    "setupcmd.py": "`test`: a pretend call to a server on this machine",
    "verify.py": "`verify`: calls its own proxy and a pretend server, both on this machine",
}
_NETWORK_ROOTS = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "xmlrpc", "telnetlib"}


def _network_imports(source):
    import ast
    found = set()
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for n in names:
            if n.split(".")[0] in _NETWORK_ROOTS and n != "urllib.parse":     # urllib.parse only splits text
                found.add(n)
    return found


class NetworkImportsAreListed(unittest.TestCase):
    def test_only_the_listed_modules_import_a_network_library(self):
        folder = os.path.join(REPO, "stuntkey")
        found = {}
        for name in sorted(os.listdir(folder)):
            if name.endswith(".py"):
                with open(os.path.join(folder, name), encoding="utf-8") as f:
                    mods = _network_imports(f.read())
                if mods:
                    found[name] = sorted(mods)
        self.assertEqual(sorted(found), sorted(NETWORK_MODULES),
                         "a module started (or stopped) importing a network library: if it is meant "
                         "to, add it to NETWORK_MODULES with the reason, and check the README claim")

    def test_the_detector_sees_an_import(self):
        self.assertEqual(_network_imports("import socket\nfrom urllib.request import urlopen\n"
                                          "import urllib.parse\n"), {"socket", "urllib.request"})
        self.assertEqual(_network_imports("def f():\n    import ssl\n"), {"ssl"})
        self.assertEqual(_network_imports("import json, os\n"), set())


class DocsSayWhatIsTrue(unittest.TestCase):
    def test_tamper_evident_not_unrewritable(self):
        readme = _read("README.md")
        self.assertNotIn("can't be rewritten", readme)
        self.assertIn("tamper-evident", readme)

    def test_the_telemetry_claim_is_the_honest_one(self):
        for name in (("README.md",), ("docs", "THREAT_MODEL.md")):
            text = _read(*name)
            self.assertNotIn("sends no telemetry", text, name)
            self.assertIn("sends nothing except the calls you ask for", text, name)

    def test_the_guide_no_longer_says_nothing_was_run_on_windows(self):
        guide = _read("docs", "guide.md")
        self.assertNotIn("Nothing\n  here was run on Windows", guide)
        self.assertNotIn("Nothing of\n  the Windows clipboard-history check was run on Windows", guide)
        self.assertIn("real Windows machine", guide)

    def test_one_unreleased_block_in_the_changelog(self):
        log = _read("CHANGELOG.md")
        self.assertEqual(len(re.findall(r"^## Unreleased\s*$", log, re.M)), 1)
        self.assertNotIn("(unreleased)", log)
        top = log.index("## Unreleased")
        nxt = re.search(r"^## \d", log[top:], re.M)
        block = log[top: top + nxt.start()]
        for word in ("Security panel, round 3", "Round 14", "warden", "tamper-evident"):
            self.assertIn(word, block)


if __name__ == "__main__":
    unittest.main()
