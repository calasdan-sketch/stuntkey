"""Round 11: the CLI in plain words. Only fake keys; everything isolated."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME for the whole run)
from stuntkey import clipboard as clip_mod
from stuntkey import cli, connect as connect_mod, connect_import, connect_try
from stuntkey import keychain, recipes

FAKE = "sk-FAKE-TEST-0000-abcdefghijklmnop"


def run(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as st:
        st.enter_context(contextlib.redirect_stdout(out))
        st.enter_context(contextlib.redirect_stderr(err))
        if stdin is not None:
            st.enter_context(mock.patch.object(sys, "stdin", io.StringIO(stdin)))
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def memory_keychain():
    old = os.environ.get("STUNTKEY_KEYCHAIN")
    os.environ["STUNTKEY_KEYCHAIN"] = "memory"
    keychain._memory.clear()
    try:
        yield
    finally:
        keychain._memory.clear()
        if old is None:
            os.environ.pop("STUNTKEY_KEYCHAIN", None)
        else:
            os.environ["STUNTKEY_KEYCHAIN"] = old


@contextlib.contextmanager
def in_empty_dir():
    old = os.getcwd()
    d = tempfile.mkdtemp(prefix="r11")
    os.chdir(d)
    try:
        yield d
    finally:
        os.chdir(old)


class PlainErrors(unittest.TestCase):
    def test_unknown_command_is_short_and_plain(self):
        code, _o, err = run(["getx"])
        self.assertEqual(code, 2)
        self.assertIn("I don't know 'getx'. Did you mean: stuntkey get?", err)
        self.assertIn("`stuntkey --help`", err)
        self.assertNotIn("choose from", err)
        self.assertLess(len(err.splitlines()), 4)

    def test_bad_method(self):
        with memory_keychain():
            code, _o, err = run(["call", "github", "FETCH", "/user"])
        self.assertEqual(code, 2)
        self.assertIn("FETCH is not a method I know. Use GET, POST, PUT, PATCH or DELETE.", err)

    def test_status_outside_a_project(self):
        with in_empty_dir():
            code, out, _e = run(["status"])
            self.assertEqual(code, 0)
            self.assertIn("This folder has no stuntkey setup. Run `stuntkey init` to create one.", out)
            code, out, _e = run(["status", "--json"])
            self.assertEqual(json.loads(out)["services"], [])

    def test_project_dir_names_folder_and_reason(self):
        with in_empty_dir() as d:
            missing = os.path.join(d, "nope")
            code, _o, err = run(["--project-dir", missing, "status"])
            self.assertEqual(code, 2)
            self.assertIn("nope", err)
            self.assertIn("no such folder", err)
            afile = os.path.join(d, "f.txt")
            open(afile, "w").close()
            code, _o, err = run(["--project-dir", afile, "status"])
            self.assertIn("a file, not a folder", err)

    def test_no_key_saved_for_run_and_forget(self):
        with memory_keychain(), in_empty_dir():
            for argv in (["run", "zzqq", "--", "echo"], ["forget", "zzqq", "--yes"],
                         ["run", "zzqq.example.org", "--", "echo"],
                         ["forget", "zzqq.example.org", "--yes"]):
                code, _o, err = run(argv)
                self.assertEqual(code, 3, argv)
                self.assertIn("No key saved for", err)
                self.assertIn("Run `stuntkey get ", err)
                self.assertNotIn("(not shown)", err)

    def test_unverified_note_is_plain(self):
        out = io.StringIO()
        recipe = dict(recipes.load_recipes()["github"], unverified=["validate.url"])
        connect_mod._print_steps(recipe, out)
        text = out.getvalue()
        self.assertIn("I could not check this site's key test settings. "
                      "If the screen looks different, trust the screen.", text)
        self.assertNotIn("validate.url", text)

    def test_header_matches_browser_flag(self):
        recipe = recipes.load_recipes()["github"]
        a, b = io.StringIO(), io.StringIO()
        connect_mod._print_steps(recipe, a, True)
        connect_mod._print_steps(recipe, b, False)
        self.assertIn("opens in your browser", a.getvalue())
        self.assertNotIn("opens in your browser", b.getvalue())
        self.assertIn("open the key page yourself", b.getvalue())


class GetForSitesWithoutARecipe(unittest.TestCase):
    def test_get_run_forget_example_com(self):
        with memory_keychain(), in_empty_dir():
            code, out, err = run(["get", "example.com", "--key-from-stdin"], stdin=FAKE + "\n")
            self.assertEqual(code, 0, out + err)
            self.assertIn("keychain", out)
            self.assertNotIn(FAKE, out + err)
            self.assertNotIn("opens in your browser", out)
            self.assertNotIn("Click Copy", out)
            self.assertIn("This will", out)
            # the key really is in the (memory) keychain, not in a .env file
            self.assertFalse(os.path.exists(".env"))
            self.assertIn(FAKE, keychain._memory.values())
            # run finds it by the address
            code, out, err = run(["run", "example.com", "--", sys.executable, "-c",
                                  "import os;print(os.environ['EXAMPLE_API_KEY'][:3])"])
            self.assertEqual(code, 0, out + err)
            self.assertNotIn(FAKE, out + err)
            # forget finds it by the address too
            code, out, err = run(["forget", "example.com", "--yes"])
            self.assertEqual(code, 0, out + err)
            self.assertNotIn(FAKE, keychain._memory.values())

    def test_stdin_key_refused_at_a_terminal(self):
        with mock.patch.object(cli, "_stdin_is_terminal", return_value=True):
            code, _o, err = run(["get", "example.com", "--key-from-stdin"])
        self.assertEqual(code, 2)
        self.assertIn("for scripts and tests", err)

    def test_get_default_store_is_keychain(self):
        seen = {}
        with mock.patch.object(cli, "connect_service",
                               lambda recipe, **kw: seen.update(kw) or 0):
            run(["get", "github"])
        self.assertEqual(seen["store"], "keychain")
        with mock.patch.object(cli, "connect_service",
                               lambda recipe, **kw: seen.update(kw) or 0):
            run(["get", "github", "--store", "env"])
        self.assertEqual(seen["store"], "env")

    def test_screen_text_follows_flags(self):
        r = recipes.load_recipes()["github"]
        line = cli._what_will_happen(r, "keychain", ".env", True, False, False, False)
        self.assertNotIn("open the key page", line)
        self.assertIn("paste", line)
        line = cli._what_will_happen(r, "keychain", ".env", False, True, False, False)
        self.assertIn("open the key page", line)
        self.assertIn("copy", line)

    def test_version_comes_from_the_package(self):
        from stuntkey import __version__
        code, out, err = run(["--version"])
        self.assertIn(__version__, out + err)


class ClipboardKeepsWaiting(unittest.TestCase):
    def test_lapsed_window_retries_then_takes_the_key(self):
        calls = []

        def fake_wait(pattern, taken, get, clear, **_k):
            calls.append(1)
            return FAKE if len(calls) == 3 else None
        out = io.StringIO()
        with mock.patch.object(clip_mod, "wait_for_key", fake_wait):
            value = connect_mod._ask_one(
                {"label": "API key", "name": "key", "env_var": "X"}, True,
                lambda _t: "never", out, (lambda: "", lambda: None), set())
        self.assertEqual(value, FAKE)
        self.assertEqual(len(calls), 3)
        self.assertIn("Still waiting", out.getvalue())
        self.assertNotIn(FAKE, out.getvalue())

    def test_after_all_rounds_it_asks_for_a_paste(self):
        out = io.StringIO()
        with mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: None):
            value = connect_mod._ask_one(
                {"label": "API key", "name": "key", "env_var": "X"}, True,
                lambda _t: "pasted-value", out, (lambda: "", lambda: None), set())
        self.assertEqual(value, "pasted-value")
        self.assertIn("Paste the key here instead", out.getvalue())


class PracticeRun(unittest.TestCase):
    def test_try_touches_nothing_real(self):
        home_before = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE", "APPDATA",
                                                      "STUNTKEY_KEYCHAIN")}
        cwd = os.getcwd()
        with in_empty_dir() as d:
            code, out, err = run(["try", "--auto"])
            self.assertEqual(code, 0, out + err)
            self.assertEqual(os.listdir(d), [])           # the project folder is untouched
        self.assertEqual(os.getcwd(), cwd)
        self.assertEqual(home_before, {k: os.environ.get(k) for k in home_before})
        self.assertIn("ADD a key", out)
        self.assertIn("FORGET the key", out)
        self.assertNotIn(connect_try.FAKE_KEY, out)       # even the pretend key is hidden
        self.assertEqual(keychain._memory, {})

    def test_try_stops_on_ctrl_c(self):
        def stop(_t):
            raise KeyboardInterrupt
        out = io.StringIO()
        self.assertEqual(connect_try.cmd_try(ask=stop, out=out), 0)
        self.assertIn("Nothing was saved anywhere", out.getvalue())


class ImportKeys(unittest.TestCase):
    def setUp(self):
        self.catalog = recipes.load_recipes()
        self.var = recipes.env_vars(self.catalog["openai"])[0]

    def _import(self, text, name=".env", **kw):
        d = tempfile.mkdtemp(prefix="r11")
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        args = mock.Mock(file=path, paste=False, yes=True, delete_source=False)
        for k, v in kw.items():
            setattr(args, k, v)
        out = io.StringIO()
        with memory_keychain():
            code = connect_import.cmd_import(args, self.catalog, out=out)
            stored = dict(keychain._memory)
        return code, out.getvalue(), stored, path

    def test_env_file(self):
        code, out, stored, path = self._import(
            f"# comment\nexport {self.var}='{FAKE}'\nSOME_OTHER=abc\n")
        self.assertEqual(code, 0, out)
        self.assertIn(self.var, out)
        self.assertIn("SOME_OTHER", out)                   # named as left alone
        self.assertNotIn(FAKE, out)
        self.assertIn(FAKE, stored.values())
        self.assertIn("Remove-Item", out)                  # told to delete the file
        self.assertTrue(os.path.exists(path))

    def test_json_doppler_and_bitwarden(self):
        code, out, stored, _p = self._import(json.dumps({self.var: FAKE}), "d.json")
        self.assertEqual(code, 0, out)
        self.assertIn(FAKE, stored.values())
        bw = {"items": [{"name": "OpenAI", "login": {"password": FAKE}}]}
        code, out, stored, _p = self._import(json.dumps(bw), "b.json")
        self.assertEqual(code, 0, out)
        self.assertIn(FAKE, stored.values())

    def test_csv_1password(self):
        code, out, stored, _p = self._import(
            f"Title,Url,Username,Password,Notes\nOpenAI,,,{FAKE},\n", "x.csv")
        self.assertEqual(code, 0, out)
        self.assertIn(FAKE, stored.values())
        self.assertNotIn(FAKE, out)

    def test_nothing_known_saves_nothing(self):
        code, out, stored, _p = self._import("FOO=bar-bar-bar-bar\n")
        self.assertEqual(code, 1)
        self.assertEqual(stored, {})

    def test_refuses_without_yes_when_not_interactive(self):
        code, out, stored, _p = self._import(f"{self.var}={FAKE}\n", yes=False)
        self.assertEqual(code, 2)
        self.assertEqual(stored, {})

    def test_delete_source_removes_the_file(self):
        code, out, _s, path = self._import(f"{self.var}={FAKE}\n", delete_source=True)
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(path))

    def test_missing_file_is_plain(self):
        args = mock.Mock(file=os.path.join(tempfile.gettempdir(), "no-such-r11.env"),
                         paste=False, yes=True, delete_source=False)
        out = io.StringIO()
        self.assertEqual(connect_import.cmd_import(args, self.catalog, out=out), 1)
        self.assertIn("Nothing was saved", out.getvalue())


if __name__ == "__main__":
    unittest.main()
