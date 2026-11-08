"""Round 5 (secrets-management, incident-response, DX and Windows
credential-store specialists): the author line is pinned everywhere it ships;
the keychain refuses what it cannot hold faithfully (a line break would start a
second `security` command on macOS; Windows keeps 1280 characters); the hook
looks at a tool call whose shape is odd instead of ignoring it (idea 12);
`keep` saves a key for a service with no recipe; seeded property tests.

No key-shaped text is stored in this file: every key is built at run time."""

import contextlib
import io
import json
import os
import random
import re
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import hook as hook_mod
from stuntkey import keep as keep_mod
from stuntkey import keychain as keychain_mod
from stuntkey import safeprompt
from stuntkey import scrub as scrub_mod
from test_round3_fixes import _FakeRun, _fake_windows_ctypes

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTHOR = "Calas Automations Inc."


def fake_key(n=30, seed="k"):
    """Built at run time, never a real vendor format."""
    rnd = random.Random(seed)
    return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ author

class AuthorLine(unittest.TestCase):
    def test_every_manifest_names_the_company_only(self):
        self.assertIn(f"Copyright (c) 2026 {AUTHOR}", read("LICENSE"))
        self.assertIn(f'"author": "{AUTHOR}"', read("packaging", "npm", "package.json"))
        for toml in ("pyproject.toml", "shim/pyproject.toml", "shim-oathkey/pyproject.toml"):
            self.assertIn(f'authors = [{{ name = "{AUTHOR}" }}]', read(*toml.split("/")), toml)
            self.assertNotIn("email", read(*toml.split("/")).split("[project.urls]")[0].lower()
                             .replace("keywords", ""), toml)

    def test_about_text_and_code_use_the_same_name(self):
        from stuntkey import aboutcmd
        text = open(aboutcmd.__file__, encoding="utf-8").read()
        self.assertIn(f"Made by {AUTHOR}", text)

    def test_no_personal_name_or_old_company_in_shipped_files(self):
        old = re.compile(r"(?i)dan calas|DC Enterprises|\bcalasdan\b(?!-sketch)")
        for folder in ("stuntkey", "leakbench"):
            for root, _dirs, files in os.walk(os.path.join(REPO, folder)):
                for name in files:
                    if name.endswith((".py", ".json", ".md")):
                        path = os.path.join(root, name)
                        with open(path, encoding="utf-8") as f:
                            self.assertIsNone(old.search(f.read()), path)


# ----------------------------------------------------------------- keychain

class KeychainRefusesWhatItCannotHold(unittest.TestCase):
    def test_a_line_break_cannot_start_a_second_macos_command(self):
        run = _FakeRun(stdout=b"x\n")
        evil = fake_key(12) + '"\nadd-generic-password -a evil -s evil -w ' + fake_key(8)
        with self.assertRaises(keychain_mod.KeychainError) as cm:
            keychain_mod.store("acme", "ACME_API_KEY", evil, keychain_mod.MACOS, run=run)
        self.assertIn("line breaks", str(cm.exception))
        self.assertEqual(run.calls, [])            # the OS tool was never started
        self.assertNotIn(evil, str(cm.exception))  # and the key is not in the message

    def test_a_keychain_that_keeps_something_else_is_an_error(self):
        run = _FakeRun(stdout=b"not-the-key\n")
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.store("acme", "ACME_API_KEY", fake_key(), keychain_mod.MACOS, run=run)

    def test_carriage_return_and_nul_are_refused_everywhere(self):
        for backend in (keychain_mod.MACOS, keychain_mod.LINUX, keychain_mod.WINDOWS):
            for bad in ("abc\x00defghij", ""):
                with self.assertRaises(keychain_mod.KeychainError):
                    keychain_mod.check_storable(backend, bad)
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.check_storable(keychain_mod.MACOS, "abcdefgh\rij")
        keychain_mod.check_storable(keychain_mod.LINUX, "line1\nline2 (a PEM)")  # fine here

    def test_a_lone_surrogate_is_a_plain_error_not_a_traceback(self):
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.check_storable(keychain_mod.LINUX, "abcdef\ud800ghij")

    def test_windows_limit_is_1280_characters(self):
        ct = _fake_windows_ctypes()
        ok = fake_key(1280)
        keychain_mod.store("acme", "ACME_API_KEY", ok, keychain_mod.WINDOWS, ctypes_mod=ct)
        too_long = fake_key(1281)
        with self.assertRaises(keychain_mod.KeychainError) as cm:
            keychain_mod.store("acme2", "ACME_API_KEY", too_long,
                               keychain_mod.WINDOWS, ctypes_mod=ct)
        self.assertIn("1280", str(cm.exception))
        self.assertEqual(len(ct.vault), 1)            # nothing half-written

    def test_non_bmp_characters_count_as_two_utf16_units(self):
        ct = _fake_windows_ctypes()
        key = "\U0001f511" * 641                  # 1282 UTF-16 units
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.store("acme", "ACME_API_KEY", key, keychain_mod.WINDOWS, ctypes_mod=ct)

    def test_windows_failure_gives_a_hint_for_the_documented_codes(self):
        ct = _fake_windows_ctypes()
        ct.windll.advapi32.CredWriteW = staticmethod(lambda ref, flags: 0)
        ct.GetLastError = lambda: 1312
        with self.assertRaises(keychain_mod.KeychainError) as cm:
            keychain_mod.store("acme", "ACME_API_KEY", fake_key(), keychain_mod.WINDOWS,
                               ctypes_mod=ct)
        self.assertIn("1312", str(cm.exception))
        self.assertIn("signed-in desktop", str(cm.exception))

    def test_windows_entry_in_another_encoding_is_not_read_as_missing(self):
        ct = _fake_windows_ctypes()
        keychain_mod.store("acme", "ACME_API_KEY", fake_key(), keychain_mod.WINDOWS, ctypes_mod=ct)
        target = keychain_mod.target_name("acme")
        kind, persist, user, blob = ct.vault[target]
        ct.vault[target] = (kind, persist, user, blob + b"x")        # odd length
        with self.assertRaises(keychain_mod.KeychainUnavailable):
            keychain_mod.read("acme", "ACME_API_KEY", keychain_mod.WINDOWS, ctypes_mod=ct)

    def test_windows_write_buffer_is_wiped(self):
        ct = _fake_windows_ctypes()
        seen = []
        real = ct.create_string_buffer

        def spy(*a, **k):
            buf = real(*a, **k)
            seen.append(buf)
            return buf
        ct.create_string_buffer = spy
        ct.memset = __import__("ctypes").memset
        key = fake_key(20)
        keychain_mod.store("acme", "ACME_API_KEY", key, keychain_mod.WINDOWS, ctypes_mod=ct)
        wiped = [b for b in seen if key.encode("utf-16-le") in bytes(b)]
        self.assertEqual(wiped, [])        # no write buffer still holds the key


# --------------------------------------------------------------- idea 12

def tool(name, tool_input):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": name,
                       "tool_input": tool_input})


def verdict(raw):
    code, out = hook_mod.check(raw)
    if not out:
        return code, None
    return code, json.loads(out)["hookSpecificOutput"]["permissionDecision"]


class OddlyShapedToolCalls(unittest.TestCase):
    """Decision (round 5): a malformed call is LOOKED AT, not refused for being
    malformed. A hook that refuses every call it does not recognise would stop
    all work the day Claude Code renames a field; one that ignores them lets
    `{"command": ["cat", ".env"]}` straight through."""

    def test_a_command_sent_as_a_list_is_read(self):
        self.assertEqual(verdict(tool("Bash", {"command": ["cat", ".env"]})), (0, "deny"))

    def test_the_words_of_a_list_are_judged_together(self):
        self.assertEqual(verdict(tool("Bash", {"command": ["stuntkey", "run", "github", "--", "ls"]})),
                         (0, "deny"))

    def test_a_renamed_command_field_is_read(self):
        self.assertEqual(verdict(tool("Bash", {"cmd": "cat .env"})), (0, "deny"))
        self.assertEqual(verdict(tool("PowerShell", {"script": "Get-Content .env"})), (0, "deny"))

    def test_tool_input_sent_as_text_is_read(self):
        self.assertEqual(verdict(tool("Bash", "cat .env")), (0, "deny"))
        self.assertEqual(verdict(tool("Bash", json.dumps({"command": "cat .env"}))), (0, "deny"))
        self.assertEqual(verdict(tool("Read", "/work/.env")), (0, "deny"))
        self.assertEqual(verdict(tool("Bash", ["cat", ".env"])), (0, "deny"))

    def test_a_read_with_another_field_name_is_read(self):
        self.assertEqual(verdict(tool("Read", {"filepath": "/work/.env"})), (0, "deny"))

    def test_nothing_to_run_is_still_not_blocked(self):
        for shape in ({}, {"command": 5}, {"command": None}, {"command": ["ls", "-la"]},
                      {"command": 5, "description": "explains why .env is ignored"}, "ls", [], ["ls", "-la"]):
            self.assertEqual(verdict(tool("Bash", shape)), (0, None), shape)
        self.assertEqual(verdict(json.dumps({"tool_name": "Bash"})), (0, None))

    def test_well_formed_calls_are_judged_as_before(self):
        self.assertEqual(verdict(tool("Bash", {"command": "ls", "description": "see .env docs"})),
                         (0, None))
        self.assertEqual(verdict(tool("Grep", {"pattern": r"\.env"})), (0, None))
        self.assertEqual(verdict(tool("Read", {"file_path": "/work/app.py", "note": ".env"})),
                         (0, None))

    def test_not_json_is_still_not_a_block(self):
        self.assertEqual(hook_mod.check("not json"), (1, ""))


# --------------------------------------------------------------------- keep

class FakeKeychain:
    def __init__(self):
        self.vault = {}

    def patch(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(keychain_mod, "detect_backend",
                                              lambda *a, **k: keychain_mod.LINUX))
        stack.enter_context(mock.patch.object(
            keychain_mod, "store",
            lambda svc, var, key, backend=None, **k: self.vault.__setitem__((svc, var), key)
            or backend))
        return stack


class Args(types.SimpleNamespace):
    def __init__(self, name=None, **kw):
        kw.setdefault("list", False)
        super().__init__(name=name, env_var=None, **kw)


class HiddenPasteFromAPipe(unittest.TestCase):
    def test_a_pipe_with_no_terminal_is_read_without_the_echo_warning(self):
        err = io.StringIO()
        with mock.patch.object(safeprompt, "_piped_with_no_terminal", lambda: True), \
                mock.patch.object(safeprompt.sys, "stdin", io.StringIO("pasted-value\n")), \
                mock.patch.object(safeprompt.getpass, "getpass",
                                  side_effect=AssertionError("getpass must not run")), \
                contextlib.redirect_stderr(err):
            self.assertEqual(safeprompt.read_hidden("key: "), "pasted-value")
        self.assertNotIn("echoed", err.getvalue())

    def test_end_of_input_is_a_cancel(self):
        with mock.patch.object(safeprompt, "_piped_with_no_terminal", lambda: True), \
                mock.patch.object(safeprompt.sys, "stdin", io.StringIO("")), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(EOFError):
                safeprompt.read_hidden("key: ")


class Keep(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        env = mock.patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home})
        env.start()
        self.addCleanup(env.stop)
        self.kc = FakeKeychain()
        stack = self.kc.patch()
        stack.__enter__()
        self.addCleanup(stack.close)

    def keep(self, name, key=None, catalog=None, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = keep_mod.cmd_keep(Args(name, **kw), catalog or {}, out=out, err=err,
                                 read=lambda prompt: key if key is not None else "",
                                 ask=lambda *a, **k: kw.get("yes"))
        return code, out.getvalue(), err.getvalue()

    def test_names(self):
        n = keep_mod.names_for
        self.assertEqual(n("ACME_API_KEY"), ("acme", "ACME_API_KEY"))
        self.assertEqual(n("acme"), ("acme", "ACME_API_KEY"))
        self.assertEqual(n("MY_SERVICE_TOKEN"), ("my-service", "MY_SERVICE_TOKEN"))
        self.assertEqual(n("my-api"), ("my-api", "MY_API_API_KEY"))
        self.assertEqual(n("KEY"), ("key", "KEY"))
        for bad in ("", "has space", "../../etc", "a" * 80, "CON", "ünï"):
            with self.assertRaises(ValueError, msg=bad):
                n(bad)

    def test_saves_in_the_keychain_and_remembers_only_the_name(self):
        key = fake_key(32)
        code, out, err = self.keep("ACME_API_KEY", key)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.kc.vault, {("acme", "ACME_API_KEY"): key})
        self.assertNotIn(key, out)
        listed = read_text(keep_mod.kept_path())
        self.assertNotIn(key, listed)
        self.assertEqual(json.loads(listed)["acme"]["env_var"], "ACME_API_KEY")
        self.assertEqual(keep_mod.recipe("acme")["env_var"], "ACME_API_KEY")
        self.assertIsNone(keep_mod.recipe("nothing"))

    def test_a_service_stuntkey_knows_is_sent_to_get(self):
        code, out, err = self.keep("github", fake_key(), catalog={"github": {}})
        self.assertEqual(code, 3)
        self.assertIn("stuntkey get github", err)
        self.assertEqual(self.kc.vault, {})

    def test_bad_pastes_save_nothing(self):
        for pasted in ("", "   ", "short", "yes", "two\nlines-of-key", "x" * 5000, "a\x1b[31mbcdefgh"):
            code, out, err = self.keep("ACME_API_KEY", pasted)
            self.assertEqual(code, 1, repr(pasted))
            self.assertEqual(self.kc.vault, {}, repr(pasted))
            self.assertNotIn("x" * 50, err)          # never echoes a long paste back

    def test_no_keychain_means_no_file_fallback(self):
        with mock.patch.object(keychain_mod, "detect_backend", lambda *a, **k: None):
            code, out, err = self.keep("ACME_API_KEY", fake_key())
        self.assertEqual(code, 1)
        self.assertIn("never writes a key to a file", err)
        self.assertFalse(os.path.exists(keep_mod.kept_path()))
        self.assertEqual(os.listdir(self.home), [])          # nothing written at all

    def test_keychain_refusal_is_reported_and_not_listed(self):
        def refuse(*a, **k):
            raise keychain_mod.KeychainError("secret-tool store failed (exit 1)")
        with mock.patch.object(keychain_mod, "store", refuse):
            code, out, err = self.keep("ACME_API_KEY", fake_key())
        self.assertEqual(code, 1)
        self.assertIn("not saved", err)
        self.assertEqual(keep_mod.load(), {})

    def test_replacing_asks_first(self):
        first, second = fake_key(20, "a"), fake_key(20, "b")
        self.keep("acme", first)
        code, out, err = self.keep("acme", second, yes=False)
        self.assertEqual(self.kc.vault[("acme", "ACME_API_KEY")], first)
        code, out, err = self.keep("acme", second, yes=True)
        self.assertEqual((code, self.kc.vault[("acme", "ACME_API_KEY")]), (0, second))

    def test_list_shows_names_never_keys(self):
        key = fake_key(24)
        self.keep("acme", key)
        out = io.StringIO()
        keep_mod.cmd_keep(Args(None, list=True), {}, out=out)
        self.assertIn("acme", out.getvalue())
        self.assertNotIn(key, out.getvalue())

    def test_damaged_list_is_empty_not_a_crash(self):
        os.makedirs(os.path.dirname(keep_mod.kept_path()), exist_ok=True)
        for junk in ("{not json", "[]", '{"../x": {"env_var": "A"}, "ok": {"env_var": "lower"}}'):
            with open(keep_mod.kept_path(), "w", encoding="utf-8") as f:
                f.write(junk)
            self.assertEqual(keep_mod.load(), {})

    def test_run_and_forget_find_a_kept_service_through_the_cli(self):
        key = fake_key(26)
        self.keep("acme", key)
        seen = {}

        def fake_run(recipes, command, env_file, redact, prefer):
            seen["recipe"] = recipes[0]
            return 0
        with mock.patch.object(cli_mod, "_cmd_run", fake_run):
            self.assertEqual(cli_mod.main(["run", "acme", "--", "true"]), 0)
        self.assertEqual(seen["recipe"]["env_var"], "ACME_API_KEY")
        forgot = []
        with mock.patch.object(cli_mod, "_cmd_forget",
                               lambda recipe, env_file: forgot.append(recipe["service"]) or 0):
            self.assertEqual(cli_mod.main(["forget", "acme"]), 0)
        self.assertEqual(forgot, ["acme"])
        self.assertEqual(keep_mod.load(), {})                 # name dropped with the key

    def test_connect_does_not_accept_a_kept_name(self):
        self.keep("acme", fake_key())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli_mod.main(["connect", "acme"]), 3)


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# --------------------------------------------------------- property tests

def parse_security_line(line):
    """What `security -i` does with one add-generic-password line (quoted words,
    backslash escapes), just enough to prove the quoting round-trips."""
    words, cur, quoted, i = [], "", False, 0
    while i < len(line):
        c = line[i]
        if quoted:
            if c == "\\" and i + 1 < len(line):
                cur += line[i + 1]
                i += 1
            elif c == '"':
                quoted = False
            else:
                cur += c
        elif c == '"':
            quoted = True
        elif c == " ":
            if cur:
                words.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur or quoted:
        words.append(cur)
    return words


ALPHABET = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            "-_.~+/=!@#$%^&*()\"'\\ é漢\U0001f511")


class Properties(unittest.TestCase):
    def keys(self, count, seed):
        rnd = random.Random(seed)
        for _ in range(count):
            yield "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(8, 90)))

    def test_macos_quoting_round_trips_any_single_line_key(self):
        for key in self.keys(400, 11):
            run = _FakeRun(stdout=(key + "\n").encode())
            keychain_mod.store("acme", "ACME_API_KEY", key, keychain_mod.MACOS, run=run)
            line = run.calls[0][1].decode("utf-8")
            self.assertEqual(line.count("\n"), 1, "one command only")
            words = parse_security_line(line.rstrip("\n"))
            self.assertEqual(words[-1], key)
            self.assertEqual(words[0], "add-generic-password")

    def test_windows_store_then_read_gives_the_key_back(self):
        ct = _fake_windows_ctypes()
        for n, key in enumerate(self.keys(200, 12)):
            keychain_mod.store(f"svc{n}", "ACME_API_KEY", key, keychain_mod.WINDOWS, ctypes_mod=ct)
            self.assertEqual(keychain_mod.read(f"svc{n}", "ACME_API_KEY",
                                               keychain_mod.WINDOWS, ctypes_mod=ct), key)

    def test_scrubber_removes_every_form_even_when_split_in_two_chunks(self):
        import base64
        import urllib.parse
        rnd = random.Random(13)
        for key in self.keys(300, 14):
            raw = key.encode()
            forms = {"plain": key, "url": urllib.parse.quote(key, safe=""),
                     "json": json.dumps(key)[1:-1], "hex": raw.hex(),
                     "b64": base64.b64encode(raw).decode()}
            if key.isascii():
                forms["rev"] = key[::-1]
            for name, form in forms.items():
                if len(form) < 8:
                    continue
                text = f"x {form} y"
                self.assertNotIn(form, scrub_mod.scrub_text(text, [key]), name)
                s = scrub_mod.Scrubber([key])
                cut = rnd.randint(0, len(text))
                out = s.feed(text[:cut].encode()) + s.feed(text[cut:].encode()) + s.flush()
                self.assertNotIn(form.encode(), out, name)

    def test_the_hook_never_raises_and_never_echoes_a_pasted_key(self):
        rnd = random.Random(15)
        pieces = ["cat", ".env", "'", '"', "\\", "$(", ")", "{", "}", "\x00", "\ud800",
                  "‮", "\x1b[31m", "%", "``", ";", "|", "&&", " ", "\n"]
        for _ in range(600):
            text = "".join(rnd.choice(pieces) for _ in range(rnd.randint(1, 25)))
            shape = rnd.choice([{"command": text}, {"command": [text, text]}, text,
                                {"cmd": text}, {"file_path": text}, [text], {"command": {"a": text}}])
            raw = json.dumps({"hook_event_name": "PreToolUse",
                              "tool_name": rnd.choice(["Bash", "Read", "Grep", "PowerShell", "Write", "mcp__x__y"]),
                              "tool_input": shape}, ensure_ascii=rnd.random() < .5)
            code, out = hook_mod.check(raw)
            self.assertIn(code, (0, 1))
            self.assertNotIn("\x1b", out)
            self.assertNotIn("‮", out)


class LoneSurrogate(unittest.TestCase):
    """Found by the seeded fuzz above: JSON can carry "\\ud800", and with a
    stored key on file the content check raised UnicodeEncodeError."""

    def test_write_content_with_a_lone_surrogate_does_not_crash_the_check(self):
        scrub_mod.remember_key("regression/ACME", fake_key(24, "s"))
        raw = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Write",
                          "tool_input": {"file_path": "/work/a.py",
                                         "content": ".env\ud800 and more words here"}})
        raw = raw.replace("\\\\ud800", "\\ud800")
        self.assertIn("\\ud800", raw)
        code, out = hook_mod.check(raw)
        self.assertIn(code, (0, 1))
        self.assertIsInstance(scrub_mod._fp(b"salt", "a\ud800b"), str)


# ----------------------------------------------------------------- goldens

class GoldenOutputs(unittest.TestCase):
    def test_hook_deny_answer(self):
        code, out = hook_mod.check(tool("Bash", {"command": "cat .env"}))
        answer = json.loads(out)
        self.assertEqual(sorted(answer), ["hookSpecificOutput"])
        inner = answer["hookSpecificOutput"]
        self.assertEqual(sorted(inner), ["hookEventName", "permissionDecision",
                                         "permissionDecisionReason"])
        self.assertEqual((inner["hookEventName"], inner["permissionDecision"]),
                         ("PreToolUse", "deny"))
        self.assertTrue(out.endswith("\n") and out.count("\n") == 1)

    def test_prompt_block_answer(self):
        key = "sk-" + "ant-api03-" + fake_key(40)
        raw = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": f"use {key}"})
        code, out = hook_mod.check(raw)
        answer = json.loads(out)
        self.assertEqual(answer["decision"], "block")
        self.assertEqual(answer["hookSpecificOutput"],
                         {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True})
        self.assertNotIn(key, out)

    def test_audit_export_csv_header(self):
        code = io.StringIO()
        with contextlib.redirect_stdout(code):
            cli_mod.main(["audit", "export"])
        self.assertEqual(code.getvalue().splitlines()[0],
                         "time_utc,service,method,host,path,status,bytes,result,ms")

    def test_scan_json_field_names(self):
        folder = _isolation.mktemp()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli_mod.main(["--project-dir", folder, "scan", "--json"])
        self.assertEqual(sorted(json.loads(out.getvalue())),
                         ["files_not_considered", "files_scanned", "findings", "incomplete",
                          "root", "skipped", "tool", "validated", "version"])


if __name__ == "__main__":
    unittest.main()
