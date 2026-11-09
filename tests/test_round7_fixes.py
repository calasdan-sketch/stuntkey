"""Review round 7 regressions: the LOW items the third panel left open.

A1  A directory cache dated in the future (a clock that was wrong, a VM
    snapshot) is not trusted, and the cache is replaced in one step.
A2  A recipe saved with a UTF-8 byte-order mark loads.
A3  A slug that Windows keeps for a device (nul, con, com1 ...) is refused.
A4  `forget` looks the Secret Service entry up before it clears it.
A5  The README names --no-browser, --category and --refresh.
A6  (found in the 0.4.0 merge) The HTTP error response of a validation call
    is closed, not left to the garbage collector (Python 3.14 warns).
"""

import contextlib
import errno
import functools
import io
import json
import os
import re
import stat
import subprocess
import sys
import time
import types
import unittest
import urllib.error
import urllib.request
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import __version__
from stuntkey import cli as cli_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import publicapis as pa_mod
from stuntkey import recipes as recipes_mod
from stuntkey import validate as validate_mod

REPO = _isolation.REPO


def readme_text():
    """The README as one line of single-spaced text (CRLF or LF alike)."""
    with open(os.path.join(REPO, "docs", "guide.md"), encoding="utf-8") as f:
        return " ".join(f.read().split())


# ------------------------------------------------------------------ A1

OLD, NEW = "OLD LIST\n", "NEW LIST\n"
DAY = 24 * 3600


class FakeReply:
    """What urlopen hands back: a context manager with read()."""

    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestTheDirectoryCache(unittest.TestCase):
    """`find` keeps the downloaded directory for seven days. The age was
    `now - mtime < 7 days`, which a FUTURE mtime (the clock was wrong when the
    file was written, a VM snapshot came back) also satisfies: the old list
    was served until that date. And the file was written in place, so a crash
    could leave half a list with a fresh date."""

    def setUp(self):
        self.folder = _isolation.mktemp()
        self.path = os.path.join(self.folder, "public-apis.md")
        self.downloads = []

        def urlopen(req, timeout=None):
            self.downloads.append(req.full_url)
            return FakeReply(NEW.encode("utf-8"))

        for patch in (mock.patch.object(pa_mod, "cache_path",
                                        return_value=self.path),
                      mock.patch.object(urllib.request, "urlopen", urlopen)):
            patch.start()
            self.addCleanup(patch.stop)

    def cache(self, age, text=OLD):
        """Write the cache, `age` seconds old (negative: dated in the
        future)."""
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(text)
        when = time.time() - age
        os.utime(self.path, (when, when))

    def held(self):
        with open(self.path, encoding="utf-8") as f:
            return f.read()

    def test_a_cache_from_yesterday_is_used(self):
        self.cache(age=DAY)
        self.assertEqual(pa_mod.fetch(), OLD)
        self.assertEqual(self.downloads, [])

    def test_a_cache_older_than_the_ttl_is_downloaded_again(self):
        self.cache(age=pa_mod.CACHE_TTL + 3600)
        self.assertEqual(pa_mod.fetch(), NEW)
        self.assertEqual(len(self.downloads), 1)
        self.assertEqual(self.held(), NEW)

    def test_a_cache_dated_in_the_future_is_downloaded_again(self):
        for days in (1, 30, 400):
            with self.subTest(days=days):
                self.downloads.clear()
                self.cache(age=-days * DAY)
                self.assertEqual(pa_mod.fetch(), NEW)
                self.assertEqual(len(self.downloads), 1)
                # the new file carries today's date: the next call trusts it
                self.assertEqual(pa_mod.fetch(), NEW)
                self.assertEqual(len(self.downloads), 1)

    def test_a_copy_a_little_ahead_of_the_clock_is_used(self):
        # Windows: time.time() moves in 15 ms steps but the file system
        # stamps finer, so the list just downloaded was dated a few
        # milliseconds AHEAD of "now" and the next call downloaded it again
        # (the first Windows run of 0.4.1 failed the test above at random, on
        # a different day each time). A network drive whose clock runs fast
        # does the same for longer.
        for ahead in (0.02, 2, 600, 3000):
            with self.subTest(ahead=ahead):
                self.downloads.clear()
                self.cache(age=-ahead)
                self.assertEqual(pa_mod.fetch(), OLD)
                self.assertEqual(self.downloads, [])

    def test_a_copy_hours_ahead_of_the_clock_is_not(self):
        for ahead in (2 * 3600, 20 * 3600):
            with self.subTest(ahead=ahead):
                self.downloads.clear()
                self.cache(age=-ahead)
                self.assertEqual(pa_mod.fetch(), NEW)
                self.assertEqual(len(self.downloads), 1)

    def test_the_list_just_downloaded_is_used_by_a_clock_that_runs_behind(self):
        # the same Windows case, made to happen on every system: a clock 50 ms
        # behind the file system's, so the file written by the download is
        # dated ahead of "now" when the next call looks at it
        self.cache(age=pa_mod.CACHE_TTL + 3600)
        real = time.time
        with mock.patch.object(time, "time", lambda: real() - 0.05):
            self.assertEqual(pa_mod.fetch(), NEW)
            self.assertEqual(len(self.downloads), 1)
            self.assertEqual(pa_mod.fetch(), NEW)
            self.assertEqual(len(self.downloads), 1)

    def test_refresh_downloads_whatever_the_cache_says(self):
        self.cache(age=60)
        self.assertEqual(pa_mod.fetch(refresh=True), NEW)
        self.assertEqual(len(self.downloads), 1)
        self.assertEqual(self.held(), NEW)

    def test_without_a_cache_it_downloads_and_keeps_the_list(self):
        self.assertEqual(pa_mod.fetch(), NEW)
        self.assertEqual(self.held(), NEW)
        self.assertEqual(os.listdir(self.folder), ["public-apis.md"])

    def test_the_cache_is_swapped_in_whole(self):
        self.cache(age=pa_mod.CACHE_TTL + 3600)
        seen = {}
        real_replace = os.replace

        def spy(src, dst, *args, **kwargs):
            seen["src"], seen["dst"] = src, dst
            with open(src, encoding="utf-8") as f:
                seen["new"] = f.read()          # complete before the swap
            seen["old"] = self.held()           # the old file, still whole
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch.object(os, "replace", spy):
            pa_mod.fetch()
        self.assertEqual(seen["dst"], self.path)
        self.assertNotEqual(seen["src"], self.path)
        # next to the cache: the same file system, so the rename is atomic
        self.assertEqual(os.path.dirname(seen["src"]), self.folder)
        self.assertEqual((seen["old"], seen["new"]), (OLD, NEW))
        self.assertEqual(os.listdir(self.folder), ["public-apis.md"])

    def test_a_write_that_fails_leaves_the_old_cache_and_no_litter(self):
        self.cache(age=pa_mod.CACHE_TTL + 3600)

        def refuse(*args, **kwargs):
            raise OSError(errno.ENOSPC, "No space left on device")

        with mock.patch.object(os, "replace", refuse):
            with self.assertRaises(OSError):
                pa_mod.fetch()
        self.assertEqual(self.held(), OLD)
        self.assertEqual(os.listdir(self.folder), ["public-apis.md"])


class TestTheReadmeAboutTheCache(unittest.TestCase):
    def test_it_says_when_the_list_is_downloaded_again(self):
        flat = readme_text()
        for phrase in ("cached locally for 7 days",
                       "dated in the future",
                       "is downloaded again"):
            self.assertTrue(phrase in flat,
                            f"the README does not say: {phrase!r}")


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


# ------------------------------------------------------------------ A2

BOM = b"\xef\xbb\xbf"


class TestARecipeWithAByteOrderMark(unittest.TestCase):
    """Windows PowerShell 5.1 (`Set-Content -Encoding utf8`) and older Notepad
    put a UTF-8 byte-order mark in front of the text. json.load refused it
    ("Unexpected UTF-8 BOM"), so such a recipe was skipped with a warning.
    CRLF line ends always worked; the README promises the mark for .env."""

    def folder_with(self, raw, name="acme.json"):
        folder = _isolation.mktemp()
        with open(os.path.join(folder, name), "wb") as f:
            f.write(raw)
        return folder

    def load(self, folder):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            catalog = recipes_mod.load_recipes(folder)
        return catalog, err.getvalue()

    def text(self, **over):
        return json.dumps(recipe(**over), indent=2, ensure_ascii=False)

    def test_a_recipe_that_starts_with_a_bom_loads(self):
        raw = BOM + self.text().encode("utf-8")
        catalog, err = self.load(self.folder_with(raw))
        self.assertEqual((set(catalog), err), ({"acme"}, ""))
        self.assertEqual(catalog["acme"]["display"], "Acme")

    def test_with_the_crlf_line_ends_powershell_writes(self):
        raw = BOM + self.text().replace("\n", "\r\n").encode("utf-8")
        catalog, err = self.load(self.folder_with(raw))
        self.assertEqual((set(catalog), err), ({"acme"}, ""))

    def test_a_recipe_without_one_loads_as_before(self):
        catalog, err = self.load(
            self.folder_with(self.text().encode("utf-8")))
        self.assertEqual((set(catalog), err), ({"acme"}, ""))

    def test_a_name_with_accents_survives_the_mark(self):
        raw = BOM + self.text(display="Cl" + chr(0xE9) + " API").encode("utf-8")
        catalog, err = self.load(self.folder_with(raw))
        self.assertEqual(catalog["acme"]["display"], "Cl" + chr(0xE9) + " API")

    def test_only_the_mark_in_front_of_the_file_is_forgiven(self):
        # a mark inside a value is an invisible character, refused as before
        raw = BOM + self.text(display="Ac" + chr(0xFEFF) + "me").encode("utf-8")
        catalog, err = self.load(self.folder_with(raw))
        self.assertEqual(catalog, {})
        self.assertIn("skipping bad recipe acme.json", err)
        self.assertIn("invisible character", err)
        # and a second one in front is not "the" mark
        raw = BOM + BOM + self.text().encode("utf-8")
        catalog, err = self.load(self.folder_with(raw))
        self.assertEqual(catalog, {})
        self.assertIn("skipping bad recipe acme.json", err)

    def test_the_other_recipes_still_load_around_a_bad_one(self):
        folder = self.folder_with(BOM + self.text().encode("utf-8"))
        with open(os.path.join(folder, "bad.json"), "wb") as f:
            f.write(b"{not json")
        catalog, err = self.load(folder)
        self.assertEqual(set(catalog), {"acme"})
        self.assertEqual(err.count("skipping bad recipe"), 1)
        self.assertIn("bad.json", err)

    def test_list_shows_it(self):
        folder = self.folder_with(BOM + self.text().encode("utf-8"))
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(recipes_mod, "user_recipes_dir",
                               return_value=folder), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = cli_mod.main(["list"])
        self.assertEqual(code, 0)
        self.assertIn("acme", out.getvalue())
        self.assertNotIn("skipping", err.getvalue())

    def test_the_readme_says_so(self):
        flat = readme_text()
        for phrase in ("byte-order mark", "a recipe saved with one loads"):
            self.assertTrue(phrase in flat,
                            f"the README does not say: {phrase!r}")


# ------------------------------------------------------------------ A3

DEVICE_NAMES = (["con", "prn", "aux", "nul"]
                + [f"com{i}" for i in range(10)]
                + [f"lpt{i}" for i in range(10)])


class TestASlugWindowsKeepsForADevice(unittest.TestCase):
    """The slug is the file name (<slug>.json), and on Windows `nul.json`,
    `con.json`, `com1.json` ... are not files: saving one writes into the
    device and nothing is kept. They matched the slug pattern, so `add`
    reported "saved" for a recipe that was not. Checked here on Linux: the
    names are refused whatever the platform, so a recipe made on one machine
    is one every machine can keep."""

    def add(self, answers, recipes_dir):
        answers = list(answers)
        out = io.StringIO()
        with mock.patch("builtins.input", lambda *_: answers.pop(0)), \
                contextlib.redirect_stdout(out):
            code = cli_mod._cmd_add(recipes_dir)
        return code, out.getvalue()

    def test_a_recipe_with_such_a_service_is_refused_in_one_line(self):
        for name in DEVICE_NAMES:
            with self.subTest(name):
                with self.assertRaises(recipes_mod.RecipeError) as cm:
                    recipes_mod.validate_recipe(recipe(service=name))
                text = str(cm.exception)
                self.assertEqual(text.splitlines(), [text])
                self.assertIn(f"'{name}'", text)
                self.assertIn("Windows", text)
                self.assertIn(f"{name}.json", text)

    def test_save_recipe_writes_nothing(self):
        folder = _isolation.mktemp()
        for name in DEVICE_NAMES:
            with self.subTest(name):
                with self.assertRaises(recipes_mod.RecipeError):
                    recipes_mod.save_recipe(recipe(service=name), folder)
        self.assertEqual(os.listdir(folder), [])

    def test_add_says_why_and_writes_nothing(self):
        for name in ("nul", "con", "com1", "lpt9", "aux", "prn"):
            with self.subTest(name):
                folder = _isolation.mktemp()
                code, out = self.add([name], folder)
                self.assertEqual(code, 1)
                said = [line for line in out.splitlines()
                        if f"'{name}'" in line]
                self.assertEqual(len(said), 1, out)
                self.assertIn("Windows", said[0])
                self.assertNotIn("Traceback", out)
                self.assertEqual(os.listdir(folder), [])

    def test_add_matches_the_slug_the_way_it_always_did(self):
        # the service is lower-cased and spaces become '-': "NUL" is "nul"
        folder = _isolation.mktemp()
        code, out = self.add(["NUL"], folder)
        self.assertEqual(code, 1)
        self.assertIn("Windows", out)
        self.assertEqual(os.listdir(folder), [])

    def test_names_that_only_look_like_them_are_fine(self):
        for name in ("com10", "lpt10", "console", "nulls", "aux-api", "my-con",
                     "com", "lpt", "prn2", "conn", "nul-api", "com1x",
                     "acme", "0day"):
            with self.subTest(name):
                recipes_mod.validate_recipe(recipe(service=name))

    def test_a_file_already_there_is_skipped_with_the_reason(self):
        folder = _isolation.mktemp()
        with open(os.path.join(folder, "nul.json"), "w",
                  encoding="utf-8") as f:
            json.dump(recipe(service="nul"), f)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            catalog = recipes_mod.load_recipes(folder)
        self.assertEqual(catalog, {})
        self.assertIn("skipping bad recipe nul.json", err.getvalue())
        self.assertIn("Windows", err.getvalue())

    def test_no_shipped_recipe_is_one(self):
        shipped = set(recipes_mod.load_recipes(recipes_mod.RECIPES_DIR))
        self.assertTrue(shipped)
        self.assertEqual(shipped & set(DEVICE_NAMES), set())

    def test_the_list_is_the_one_windows_documents(self):
        self.assertEqual(sorted(recipes_mod.WINDOWS_DEVICE_NAMES),
                         sorted(DEVICE_NAMES))

    def test_the_readme_says_so(self):
        flat = readme_text()
        for phrase in ("a name Windows keeps for a device",
                       "a file called `nul.json` cannot be saved there"):
            self.assertTrue(phrase in flat,
                            f"the README does not say: {phrase!r}")


# ------------------------------------------------------------------ A4

SECRET = "sk-forget-me-4417"


class FakeSecretTool:
    """libsecret's secret-tool as its source reads: `clear` exits 0 whether or
    not an item matched, `lookup` exits 1 and prints nothing when none did.
    (Real libsecret is not installed here: this is the behaviour the panel
    described, not a recording of it.)"""

    def __init__(self, clear_exit=0):
        self.items, self.calls, self.clear_exit = {}, [], clear_exit

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        verb = argv[1]
        account = argv[argv.index("account") + 1]
        done = types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if verb == "store":
            self.items[account] = kwargs["input"]
        elif verb == "lookup":
            if account in self.items:
                done.stdout = self.items[account]
            else:
                done.returncode = 1
        elif verb == "clear":
            done.returncode = self.clear_exit
            if self.clear_exit == 0:
                self.items.pop(account, None)
        else:
            raise AssertionError(f"unexpected secret-tool call: {argv}")
        return done

    def verbs(self):
        return [call[1] for call in self.calls]


def holding(tool, service="acme", account="ACME_API_KEY"):
    keychain_mod.store(service, account, SECRET, keychain_mod.LINUX, run=tool)
    return tool


class TestForgetAskedTheSecretServiceFirst(unittest.TestCase):
    """`secret-tool clear` exits 0 whether or not it found anything, and
    forget read that as "removed": a second `forget` still said it had removed
    the Secret Service entry. The entry is looked up first now."""

    def delete(self, tool):
        return keychain_mod.delete("acme", "ACME_API_KEY",
                                   keychain_mod.LINUX, run=tool)

    def test_removed_once_then_nothing_stored(self):
        tool = holding(FakeSecretTool())
        self.assertIs(self.delete(tool), True)
        self.assertIs(self.delete(tool), False)

    def test_a_hit_is_looked_up_and_then_cleared(self):
        tool = holding(FakeSecretTool())
        self.delete(tool)
        self.assertEqual(tool.verbs(), ["store", "lookup", "lookup", "clear"])
        self.assertEqual(tool.items, {})

    def test_nothing_stored_is_found_out_before_anything_is_cleared(self):
        tool = FakeSecretTool()
        self.assertIs(self.delete(tool), False)
        self.assertEqual(tool.verbs(), ["lookup"])

    def test_another_services_entry_is_not_taken_for_this_one(self):
        tool = holding(FakeSecretTool(), account="OTHER_API_KEY")
        self.assertIs(self.delete(tool), False)
        self.assertEqual(sorted(tool.items), ["OTHER_API_KEY"])

    def test_a_clear_that_fails_after_a_hit_is_an_error_not_nothing_stored(self):
        tool = holding(FakeSecretTool(clear_exit=1))
        with self.assertRaises(keychain_mod.KeychainError) as cm:
            self.delete(tool)
        self.assertIn("secret-tool clear failed (exit 1)", str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertEqual(tool.verbs(), ["store", "lookup", "lookup", "clear"])

    def test_the_key_is_never_on_a_command_line(self):
        tool = holding(FakeSecretTool())
        self.delete(tool)
        for call in tool.calls:
            self.assertNotIn(SECRET, " ".join(call))

    def test_macos_is_asked_once_as_before(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(list(argv))
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        self.assertIs(keychain_mod.delete("acme", "ACME_API_KEY",
                                          keychain_mod.MACOS, run=run), True)
        self.assertEqual([c[:2] for c in calls],
                         [["security", "delete-generic-password"]])


class TestForgetSaysSo(unittest.TestCase):
    RECIPE = {"service": "acme", "display": "Acme", "env_var": "ACME_API_KEY"}

    def forget(self, tool):
        folder = _isolation.mktemp()
        env = os.path.join(folder, ".env")
        keychain = types.SimpleNamespace(
            detect_backend=lambda: keychain_mod.LINUX,
            label=keychain_mod.label,
            delete=functools.partial(keychain_mod.delete, run=tool),
            KeychainError=keychain_mod.KeychainError)
        out = io.StringIO()
        code = cli_mod._cmd_forget(self.RECIPE, env, out=out,
                                   keychain=keychain)
        return code, out.getvalue(), env

    def test_the_second_forget_does_not_claim_to_remove_anything(self):
        tool = holding(FakeSecretTool())
        code, text, env = self.forget(tool)
        self.assertEqual(code, 0, text)
        self.assertIn("forgot acme: removed the Secret Service keyring "
                      "(secret-tool) entry", text)
        code, text, env = self.forget(tool)
        self.assertEqual(code, 0, text)
        self.assertNotIn("removed", text)
        self.assertIn("nothing stored for 'acme' (checked Secret Service "
                      "keyring (secret-tool) and ", text)

    def test_a_failed_clear_is_said_and_exits_1(self):
        tool = holding(FakeSecretTool(clear_exit=1))
        code, text, env = self.forget(tool)
        self.assertEqual(code, 1, text)
        self.assertIn("could not remove the Secret Service keyring "
                      "(secret-tool) entry", text)
        self.assertIn("secret-tool clear failed (exit 1)", text)
        self.assertNotIn("nothing stored", text)
        self.assertNotIn(SECRET, text)

    def test_the_readme_says_so(self):
        flat = readme_text()
        for phrase in ("secret-tool clear", "looks the entry up first",
                       "`nothing stored`"):
            self.assertTrue(phrase in flat,
                            f"the README does not say: {phrase!r}")


FAKE_SECRET_TOOL = """#!/bin/sh
# libsecret's secret-tool as the panel described it: one file per account in
# $FAKE_SECRETS; `clear` exits 0 whether or not there was anything to clear
cmd=$1; shift
[ "$cmd" = store ] && shift 2           # --label LABEL
account=$4                              # service S account A slug X
case "$cmd" in
  store)  cat > "${FAKE_SECRETS:?}/${account:?}" ;;
  lookup) [ -s "${FAKE_SECRETS:?}/${account:?}" ] && cat "${FAKE_SECRETS:?}/${account:?}" || exit 1 ;;
  clear)  rm -f "${FAKE_SECRETS:?}/${account:?}"; exit 0 ;;
  *)      exit 2 ;;
esac
"""


@unittest.skipUnless(sys.platform.startswith("linux") and os.name == "posix",
                     "the secret-tool stand-in is for the Linux backend")
class TestForgetTwiceWithARealCommand(unittest.TestCase):
    def test_second_forget_says_nothing_stored(self):
        tools, secrets, work = (_isolation.mktemp() for _ in range(3))
        tool = os.path.join(tools, "secret-tool")
        with open(tool, "w", newline="\n") as f:
            f.write(FAKE_SECRET_TOOL)
        os.chmod(tool, os.stat(tool).st_mode | stat.S_IXUSR)
        env = {k: v for k, v in os.environ.items()
               if k != "PYTHONUNBUFFERED"}
        env.update(PATH=tools + os.pathsep + env.get("PATH", ""),
                   FAKE_SECRETS=secrets, PYTHONPATH=REPO)
        subprocess.run([tool, "store", "--label", "x", "service",
                        "stuntkey", "account", "GITHUB_TOKEN", "slug",
                        "github"], input=SECRET.encode(), env=env, check=True,
                       cwd=work, timeout=60)
        self.assertEqual(os.listdir(secrets), ["GITHUB_TOKEN"])

        def forget():
            proc = subprocess.run(
                [sys.executable, "-m", "stuntkey", "forget", "github", "--yes",
                 "--env-file", os.path.join(work, ".env")],
                capture_output=True, env=env, cwd=work, timeout=120)
            return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
                    proc.stderr.decode("utf-8", "replace"))

        code, out, err = forget()
        self.assertEqual((code, err), (0, ""), out)
        self.assertIn("forgot github: removed the Secret Service keyring",
                      out)
        self.assertEqual(os.listdir(secrets), [])
        code, out, err = forget()
        self.assertEqual((code, err), (0, ""), out)
        self.assertNotIn("removed", out)
        self.assertIn("nothing stored for 'github'", out)
        self.assertNotIn(SECRET, out)


# ------------------------------------------------------------------ A5

DIRECTORY = """# Public APIs

### Weather
API | Description | Auth | HTTPS | CORS
|:---|:---|:---|:---|:---|
| [7Timer!](http://www.7timer.info/doc.php) | Weather forecast | No | Yes | Yes |

### Animals
API | Description | Auth | HTTPS | CORS
|:---|:---|:---|:---|:---|
| [Cat Facts](https://catfact.ninja/) | Random cat facts | No | Yes | Yes |
| [Weather Cats](https://example.test/) | Forecasts for cats | No | Yes | Yes |
"""


def long_options(parser):
    """Every --option of the parser and of all its sub-commands."""
    found = set()
    for action in parser._actions:
        found.update(s for s in action.option_strings if s.startswith("--"))
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):           # the sub-commands: name -> parser
            for sub in choices.values():
                found |= long_options(sub)
    return found


class TestEveryOptionIsInTheReadme(unittest.TestCase):
    """--no-browser, --category and --refresh were in `--help` only. Every
    long option of every command is named in the README now, and a new one
    cannot be forgotten."""

    def test_every_option_is_named(self):
        options = long_options(cli_mod._build_parser()) - {"--help"}
        for expected in ("--no-browser", "--category", "--refresh", "--store",
                         "--env-file", "--recipes-dir", "--auth", "--limit",
                         "--version"):
            self.assertIn(expected, options)    # the walk sees them all
        flat = readme_text()
        missing = sorted(o for o in options if o not in flat)
        self.assertEqual(missing, [],
                         "options the README never names: " + " ".join(missing))


class TestTheOptionsDoWhatTheReadmeSays(unittest.TestCase):
    def find(self, *argv):
        asked = []

        def fetch(refresh=False):
            asked.append(refresh)
            return DIRECTORY

        out = io.StringIO()
        with mock.patch.object(pa_mod, "fetch", fetch), \
                contextlib.redirect_stdout(out):
            code = cli_mod.main(["find", *argv])
        return code, out.getvalue(), asked

    def test_category_keeps_only_that_category_in_any_case(self):
        code, out, _ = self.find("weather")
        self.assertEqual(code, 0)
        self.assertIn("7Timer!", out)
        self.assertIn("Weather Cats", out)
        for value in ("Animals", "animals", "anim"):
            with self.subTest(value):
                code, out, _ = self.find("weather", "--category", value)
                self.assertEqual(code, 0)
                self.assertIn("Weather Cats", out)
                self.assertNotIn("7Timer!", out)

    def test_refresh_asks_for_a_new_download(self):
        self.assertEqual(self.find("weather")[2], [False])
        self.assertEqual(self.find("weather", "--refresh")[2], [True])

    def urls_opened(self, command, *flags):
        with mock.patch.object(recipes_mod, "load_recipes",
                               return_value={"acme": recipe()}), \
                mock.patch.object(connect_mod, "connect",
                                  return_value=0) as connect, \
                mock.patch("webbrowser.open") as opened, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_mod.main([command, "acme", *flags]), 0)
            connect.call_args.kwargs["browser_open"]("https://acme.test/keys")
        return [call.args[0] for call in opened.call_args_list]

    def test_no_browser_leaves_the_browser_alone(self):
        for command in ("connect", "rotate"):
            with self.subTest(command):
                self.assertEqual(self.urls_opened(command, "--no-browser"), [])
                self.assertEqual(self.urls_opened(command),
                                 ["https://acme.test/keys"])

    def test_the_key_page_is_still_printed_without_the_browser(self):
        out = io.StringIO()
        data = recipe()
        connect_mod._print_steps(data, out)
        self.assertIn("Key page: https://acme.test/keys", out.getvalue())

    def test_the_readme_says_what_each_one_does(self):
        flat = readme_text()
        for phrase in ("`--no-browser`", "does not open the key page",
                       "`--category`", "`--refresh`",
                       "downloads the directory again now"):
            self.assertTrue(phrase in flat,
                            f"the README does not say: {phrase!r}")


# ------------------------------------------------------------------ version


class TestTheReadmeNamesThisVersion(unittest.TestCase):
    """The version is written in pyproject.toml, the package, the MCP
    serverInfo and the User-Agents (pinned together in test_round5_fixes),
    and in the heading of the README's limits."""

    def test_the_limits_heading_has_the_package_version(self):
        with open(os.path.join(REPO, "docs", "guide.md"), encoding="utf-8") as f:
            found = re.search(r"^## Scope / limits \(v([0-9][0-9.]*)\)",
                              f.read(), re.M)
        self.assertTrue(found, "no 'Scope / limits (vX.Y.Z)' heading")
        self.assertEqual(found.group(1), __version__)

    def test_the_limits_say_what_was_not_checked_here(self):
        flat = readme_text()
        for phrase in ("`secret-tool` is driven through stand-ins",
                       "refusal of device names"):
            self.assertTrue(phrase in flat,
                            f"the README does not say: {phrase!r}")


# ------------------------------------------------- the error response is closed


class TestAnHttpErrorResponseIsClosed(unittest.TestCase):
    """validate._send turns an HTTP error status into a number and must close
    the response the error object owns. Python 3.14 reports one that is only
    garbage-collected ("Implicitly cleaning up <HTTPError ...>")."""

    def _send_failing_with(self, status):
        body = io.BytesIO(b"{}")
        err = urllib.error.HTTPError("https://api.example.test/v1/me", status,
                                     "No", {}, body)
        req = urllib.request.Request("https://api.example.test/v1/me")
        scrubber = validate_mod._CredentialScrubbingRedirectHandler("Authorization")
        with mock.patch.object(urllib.request.OpenerDirector, "open",
                               side_effect=err):
            result = validate_mod._send(req, scrubber, 5.0)
        return result, body

    def test_the_response_is_closed_after_a_401(self):
        (status, text), body = self._send_failing_with(401)
        self.assertEqual((status, text), (401, b""))
        self.assertTrue(body.closed)

    def test_the_response_is_closed_after_a_500(self):
        (status, _), body = self._send_failing_with(500)
        self.assertEqual(status, 500)
        self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
