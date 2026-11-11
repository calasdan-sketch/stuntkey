"""Round 13, security and encryption: what the hook, scrub, approve, consent, caps and
policy modules now catch that they did not.

Every test runs in the throw-away home folder `_isolation` sets up, with the keychain in
memory and synthetic fake keys. No real pop-up can open: `approve.subprocess.run` is
replaced by a stub that RECORDS the call (and the test fails loudly if anything but the
stub is reached), and STUNTKEY_NO_WINDOW is never relied on for the code paths that are
under test.
"""
import base64
import codecs
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import types
import zlib
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import approve, caps, consent, hook as hook_mod, keychain, policy, scrub
from stuntkey.broker import BrokerError

KEY = "sk-proj-Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz"          # fake
KEY2 = "zq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1Jf"                   # fake, 30 characters


def deny(command: str, tool: str = "Bash") -> bool:
    status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                                             "tool_input": {"command": command}}))
    assert status == 0, status
    return bool(out) and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ======================================================================= hook

CLOSED = [          # the pinned misses of rounds 11 and 12 that a text reader can now close
    ("PowerShell", "$d='.claude'; $f='settings.json'; Set-Content \"$d/$f\" '{}'"),
    ("PowerShell", "$p = Join-Path $HOME '.claude'; Set-Content (Join-Path $p 'settings.json') '{}'"),
    ("Bash", "python -c \"import os; os.system('del %USERPROFILE%\\\\.claude\\\\settings.json')\""),
    ("Bash", "python -c \"import os;h=os.path.expanduser('~');d='.cla'+'ude';open(h+'/'+d+'/settings.json','w').write('{}')\""),
    ("Bash", "node -e \"const p=require('path');require('fs').writeFileSync(p.join(require('os').homedir(),'.claude','settings.json'),'{}')\""),
    ("Bash", "echo done; rm -f \"$(python -c 'import stuntkey,sys;print(stuntkey.__file__)')\""),
    ("Bash", "s=stuntkey; $s proxy --print-env"),
    ("Bash", "alias sk=stuntkey; sk proxy --print-env"),
    ("Bash", "echo ${!OPENAI*}"),
    ("Bash", "eval \"echo \\$OPENAI_API_$(echo KEY)\""),
    ('Bash', 'cmd /c "set a=cmd&& set b=key&& call %a%%b% /list"'),
    ("PowerShell", "powershell -c \"-join ('yekdmc'[5..0])\""),
]
NEW_ATTACKS = [      # shapes the old rules did not look at
    ("Bash", "x=.claude; y=settings.json; echo {} > ~/$x/$y"),
    ("Bash", "d=$HOME/.cla; d=${d}ude; echo {} > $d/settings.json"),
    ("Bash", "f(){ stuntkey \"$@\"; }; f proxy --print-env"),
    ("Bash", "c=cmd; k=key; $c$k /list"),
    ("PowerShell", "$x='stuntkey'; & $x proxy --print-env"),
    ("PowerShell", "$n = 'Set-Con' + 'tent'; & $n $HOME\\.claude\\settings.json '{}'"),
    ("PowerShell", "$a='.cla';$b='ude';Remove-Item \"$HOME\\$a$b\\settings.json\""),
    ("PowerShell", "$p=[IO.Path]::Combine($HOME,'.stuntkey','fingerprints.json'); gc $p"),
    ("Bash", "python -c \"import os;k='OPENAI_API_'+'KEY';print(os.environ[k])\""),
    ("Bash", "python -c \"import pathlib as p; (p.Path.home()/'.claude'/'settings.json').write_text('{}')\""),
    ("Bash", "echo pzqxrl /list | tr a-zA-Z n-za-mN-ZA-M | sh"),
    ("Bash", "echo yekdmc | rev | sh"),
    ("Bash", "node -e \"String.fromCharCode(99,109,100,107,101,121)\""),
    ("Bash", "python -c \"print(bytes([99,109,100,107,101,121]))\""),
    ("Bash", "printf '\\143\\155\\144\\153\\145\\171 /list' | sh"),
    ("Bash", "rm \"$(which stuntkey)\""),
    ("PowerShell", "Remove-Item (Get-Command stuntkey).Source"),
    ("Bash", "reg query HKCU\\Environment"),
    ("PowerShell", "Get-ItemProperty -Path 'HKCU:\\Environment'"),
    ("PowerShell", "Get-CimInstance Win32_Environment | Out-String"),
    ("Bash", "wmic environment list"),
    ("PowerShell", "[Environment]::GetEnvironmentVariables()"),
    ("Bash", "echo " + base64.b64encode(gzip.compress(b"cmdkey /list")).decode() + " | base64 -d | gunzip | sh"),
    ("PowerShell", "iex ([Text.Encoding]::UTF8.GetString((New-Object IO.Compression.GzipStream("
                   "(New-Object IO.MemoryStream(,[Convert]::FromBase64String('"
                   + base64.b64encode(gzip.compress(b"cmdkey /list")).decode() + "'))),"
                   "[IO.Compression.CompressionMode]::Decompress))))"),
    ("Bash", "echo " + base64.b64encode(zlib.compress(b"rm ~/.claude/settings.json")).decode() + " | base64 -d | sh"),
]
STILL_ORDINARY = [   # look a little like the above and must keep working
    ("Bash", "x=5; echo $x"), ("Bash", "d=src; ls $d/main"), ("Bash", "alias ll='ls -la'; ll"),
    ("Bash", "f(){ echo \"$@\"; }; f hi"), ("Bash", "name=world; echo hello $name"),
    ("Bash", "export PATH=$PATH:/opt/bin; python app.py"), ("Bash", "set -e; make test"),
    ("PowerShell", "$p = Join-Path $HOME 'projects'; Set-Content (Join-Path $p 'a.txt') 'x'"),
    ("PowerShell", "$n='Set-Con'+'tent'; & $n notes.txt 'x'"),
    ("Bash", "python -c \"import os;h=os.path.expanduser('~');open(h+'/notes.txt','w').write('x')\""),
    ("Bash", "node -e \"require('fs').writeFileSync(require('path').join(require('os').homedir(),'notes.txt'),'x')\""),
    ("Bash", "echo ${!arr[@]}"), ("Bash", "echo ${#arr[@]}"), ("Bash", "echo ${name:-default}"),
    ("Bash", "reg query HKCU\\Software\\Microsoft\\Windows"), ("PowerShell", "Get-ChildItem env"),
    ("Bash", "cat env/settings.txt"), ("Bash", "ls venv/bin"), ("Bash", "python -m venv env"),
    ("Bash", "echo hello | rev"), ("Bash", "echo 'a b c' | tr a-z A-Z"),
    ("Bash", "node -e \"console.log(String.fromCharCode(72,101,108,108,111))\""),
    ("Bash", "python -c \"print(bytes([72,101,108,108,111]))\""),
    ("Bash", "which python"), ("Bash", "where git"), ("PowerShell", "Get-Command git"),
    ("Bash", "git apply --check nonexistent.patch"), ("Bash", "patch -p1 --dry-run < nofile.diff"),
    ("Bash", "echo aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l | base64 -d"),
    ("Bash", "echo " + base64.b64encode(gzip.compress(b"hello world, nothing here")).decode() + " | base64 -d | gunzip"),
    ("PowerShell", "iex 'Get-Date'"), ("Bash", "python -c \"exec('print(1)')\""),
]


class ClosedMisses(unittest.TestCase):
    def test_every_pinned_miss_that_text_can_close_is_denied(self):
        missed = [c for t, c in CLOSED if not deny(c, t)]
        self.assertEqual(missed, [])

    def test_new_attack_shapes_are_denied(self):
        missed = [c[:90] for t, c in NEW_ATTACKS if not deny(c, t)]
        self.assertEqual(missed, [])

    def test_lookalike_ordinary_commands_are_not_denied(self):
        wrong = [c[:90] for t, c in STILL_ORDINARY if deny(c, t)]
        self.assertEqual(wrong, [])

    def test_corpus_sizes(self):
        self.assertGreaterEqual(len(CLOSED) + len(NEW_ATTACKS), 35)
        self.assertGreaterEqual(len(STILL_ORDINARY), 30)


class NamedFiles(unittest.TestCase):
    """A command that runs what a FILE holds: the file is read first."""

    def setUp(self):
        self.dir = _isolation.mktemp()

    def _write(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_git_apply_of_a_patch_that_touches_settings_is_denied(self):
        p = self._write("evil.patch", "diff --git a/.claude/settings.json b/.claude/settings.json\n"
                                      "--- a/.claude/settings.json\n+++ b/.claude/settings.json\n@@ -1 +1 @@\n-{}\n+{\"hooks\":{}}\n")
        for cmd in (f"git apply {p}", f'git apply "{p}"', f"git -C . am {p}", f"patch -p1 < {p}"):
            with self.subTest(cmd=cmd):
                self.assertTrue(deny(cmd))

    def test_git_apply_of_an_ordinary_patch_is_allowed(self):
        p = self._write("fix.patch", "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-a\n+b\n")
        self.assertFalse(deny(f"git apply {p}"))
        self.assertFalse(deny(f"patch -p1 < {p}"))

    def test_a_patch_given_in_the_command_itself_is_checked(self):
        self.assertTrue(deny("git apply <<'EOF'\n--- a/.claude/settings.json\n+++ b/.claude/settings.json\nEOF"))

    def test_exec_of_a_file_that_steals_is_denied(self):
        bad = self._write("p.py", "import os\nprint(dict(os.environ))\nprint(os.environ)\n")
        bad_ps = self._write("a.ps1", "Get-ChildItem env: | Out-String\ngci env:\n")
        self.assertTrue(deny(f"python -c \"exec(open(r'{bad}').read())\""))
        self.assertTrue(deny(f"powershell -c \"$s=Get-Content {bad_ps}; iex $s\"", "PowerShell"))
        self.assertTrue(deny(f"Get-Content {bad_ps} | iex", "PowerShell"))
        self.assertTrue(deny(f"iex (Get-Content {bad_ps})", "PowerShell"))

    def test_exec_of_an_ordinary_file_is_allowed(self):
        good = self._write("ok.py", "print('hello')\n")
        good_ps = self._write("ok.ps1", "Get-Date\n")
        self.assertFalse(deny(f"python -c \"exec(open(r'{good}').read())\""))
        self.assertFalse(deny(f"iex (Get-Content {good_ps})", "PowerShell"))

    def test_exec_of_a_file_the_same_command_writes_is_denied(self):
        missing = os.path.join(self.dir, "later.ps1")
        self.assertTrue(deny(f"'whatever' > {missing}; iex (Get-Content {missing})", "PowerShell"))
        # ...but a missing file on its own (the command would just fail) is not
        self.assertFalse(deny(f"iex (Get-Content {missing})", "PowerShell"))


class Speed(unittest.TestCase):
    def test_the_new_readings_stay_linear(self):
        shapes = {
            "assign": "a=b; " * 16000, "quotes": "'a'+" * 20000, "dollar": "$(echo a) " * 8000,
            "alias": "alias a=b;" * 8000, "func": "f(){ x; };" * 6000, "join": "p.join('a','b') " * 5000,
            "slice": "'abc'[0..1] " * 6000, "set": "set a=b&&" * 8000, "rev": "echo a | rev;" * 6000,
            "tr": "tr a-z n-za-m " * 5000, "bracket": "[" * 80000, "eqs": "=" * 80000,
        }
        for name, text in shapes.items():
            with self.subTest(shape=name):
                t0 = time.monotonic()
                deny(text)
                self.assertLess(time.monotonic() - t0, hook_mod.HOOK_BUDGET + 1.0)


class Inflate(unittest.TestCase):
    def test_a_decompression_bomb_is_cut_off(self):
        bomb = zlib.compress(b"A" * 50_000_000)
        out = hook_mod._inflate(bomb)
        self.assertLessEqual(len(out or b""), hook_mod.MAX_INFLATED)

    def test_ordinary_bytes_are_not_inflated(self):
        self.assertIsNone(hook_mod._inflate(b"just some bytes that are not compressed at all"))


# ======================================================================= scrub

CYR = str.maketrans({"o": "\u043e", "p": "\u0440", "a": "\u0430", "e": "\u0435", "c": "\u0441",
                     "x": "\u0445", "y": "\u0443", "s": "\u0455", "i": "\u0456", "j": "\u0458"})


def _disguises(key: str) -> dict:
    return {
        "cyrillic": key.translate(CYR),
        "cyrillic_in_a_sentence": "your key is " + key.translate(CYR) + " (keep it safe)",
        "greek": key.replace("o", "\u03bf").replace("a", "\u03b1").replace("p", "\u03c1"),
        "decimal_spaces": " ".join(str(ord(c)) for c in key),
        "decimal_commas": ",".join(str(ord(c)) for c in key),
        "hex_0x": ",".join("0x%02x" % ord(c) for c in key),
        "hex_backslash_x": "".join("\\x%02x" % ord(c) for c in key),
        "binary": " ".join(format(ord(c), "08b") for c in key),
        "octal": "".join("\\%03o" % ord(c) for c in key),
        "gzip_base64": base64.b64encode(gzip.compress(key.encode())).decode(),
        "zlib_base64": base64.b64encode(zlib.compress(key.encode())).decode(),
        "deflate_base64": base64.b64encode(zlib.compress(key.encode())[2:-4]).decode(),
        "gzip_hex": gzip.compress(key.encode()).hex(),
        "rot47": scrub._rot47(key),
        "rot47_reversed": scrub._rot47(key[::-1]),
        "hex_of_reversed": key[::-1].encode().hex(),
        "base64_of_reversed": base64.b64encode(key[::-1].encode()).decode(),
        "rot13_of_reversed": codecs.encode(key[::-1], "rot13"),
        "every_other_character": "".join(c + "X" for c in key),
        "every_third_character": "".join(c + "Qz" for c in key),
        "every_other_with_spaces": " ".join(c + "#" for c in key),
        "base64_inside_text": "result: " + base64.b64encode(("token=" + key + " end").encode()).decode(),
        "full_width": "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in key),
        "zero_width_between": "\u200b".join(key),
    }


class Disguises(unittest.TestCase):
    def test_every_new_disguise_is_found(self):
        for key in (KEY, KEY2):
            for name, text in _disguises(key).items():
                with self.subTest(key=key[:6], disguise=name):
                    self.assertTrue(scrub.loosely_contains(text, [key]), name)

    def test_arabic_indic_digits_are_found(self):
        text = KEY2.replace("9", "\u0669").replace("4", "\u0664").replace("2", "\u0662")
        self.assertTrue(scrub.loosely_contains(text, [KEY2]))

    def test_ordinary_text_is_not_withheld(self):
        samples = [
            "The quick brown fox jumps over the lazy dog. " * 4000,
            "def f(x):\n    return [ord(c) for c in x]  # 104 101 108 108 111 32 119 111 114 108 100 33 10",
            "Пример текста на русском языке без секретов, просто обычное предложение.",
            "Καλημέρα κόσμε, αυτό είναι ένα απλό κείμενο χωρίς μυστικά.",
            json.dumps({"id": 12345, "items": list(range(30, 126))}),
            "sha256: " + "ab12" * 16, "a1b2c3 d4e5f6 " * 300,
            base64.b64encode(b"hello world, this is perfectly ordinary text").decode(),
            gzip.compress(b"nothing secret in here, just words").hex(),
        ]
        for text in samples:
            with self.subTest(text=text[:30]):
                self.assertFalse(scrub.loosely_contains(text, [KEY, KEY2, "correct-horse-battery-staple-9"]))

    def test_look_alikes_keep_their_length(self):
        for s in ("sk-" + KEY.translate(CYR), "\u0661\u0662\u0663abc", "plain ascii", "\u0391\u0392\u0393"):
            self.assertEqual(len(scrub._fold_confusables(s)), len(s))

    def test_rot47_round_trip(self):
        self.assertEqual(scrub._rot47(scrub._rot47(KEY)), KEY)

    def test_interleave_search_is_bounded(self):
        text = "x" * (scrub.INTERLEAVE_MAX + 10)
        t0 = time.monotonic()
        self.assertFalse(scrub.loosely_contains(text, [KEY]))
        self.assertLess(time.monotonic() - t0, 5)

    def test_decoded_texts_are_bounded(self):
        bomb = base64.b64encode(zlib.compress(b"A" * 80_000_000)).decode()
        t0 = time.monotonic()
        self.assertFalse(scrub.loosely_contains(bomb, [KEY]))
        self.assertLess(time.monotonic() - t0, 5)


class FingerprintLookAlikes(unittest.TestCase):
    def setUp(self):
        os.environ["STUNTKEY_KEYCHAIN"] = "memory"
        keychain._memory.clear()
        self.addCleanup(keychain._memory.clear)
        self.path = os.path.join(_isolation.mktemp(), "fingerprints.json")
        scrub.remember_key("svc/API_KEY", KEY, self.path)

    def test_a_key_written_with_look_alike_letters_is_masked(self):
        prints = scrub.load_fingerprints(self.path)
        text = "the key: " + KEY.translate(CYR) + " thanks"
        out, n = scrub.mask_secrets(text, prints)
        self.assertEqual(n, 1)
        self.assertNotIn(KEY.translate(CYR), out)
        self.assertTrue(scrub.has_stored_key(text, prints))

    def test_ordinary_non_latin_text_is_untouched(self):
        prints = scrub.load_fingerprints(self.path)
        text = "Привет мир, это обычный текст. Καλημέρα κόσμε."
        self.assertEqual(scrub.mask_secrets(text, prints), (text, 0))

    def test_the_new_wrappings_are_among_the_stored_forms(self):
        forms = scrub._fingerprint_forms(KEY)
        for want in (KEY[::-1].encode().hex(), scrub._rot47(KEY), base64.b64encode(KEY[::-1].encode()).decode().rstrip("=")):
            self.assertIn(want, forms)


# ======================================================================= approve

class _Recorder:
    """Stands in for subprocess.run inside approve: records, never opens a window."""
    def __init__(self, code=1):
        self.calls, self.code = [], code

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, self.code, b"", b"")


def _boom(*a, **k):
    raise AssertionError("a real subprocess was started from approve (a real pop-up could have opened)")


def _fake_subprocess(run):
    """What approve sees as `subprocess` while a test runs: only `run` is replaced, and the
    real module (which the rest of the test process uses) is not touched."""
    return types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired,
                                 SubprocessError=subprocess.SubprocessError, CompletedProcess=subprocess.CompletedProcess)


class ApproveSpoofing(unittest.TestCase):
    def setUp(self):
        os.environ.pop("STUNTKEY_NO_WINDOW", None)
        approve._shown.clear()
        self.addCleanup(approve._shown.clear)
        patcher = mock.patch.object(approve, "subprocess", _fake_subprocess(_boom))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_stub_really_raises_when_the_real_call_is_reached(self):
        with mock.patch.object(approve, "_tool", return_value=sys.executable):
            with self.assertRaises(AssertionError):
                approve.dialog("a short request") if os.name == "nt" or sys.platform == "darwin" else _boom()

    def test_invisible_and_direction_characters_are_spelled_out(self):
        shown = approve._safe("pay \u202eevil.com\u202c to \u200bgithub.com")
        self.assertNotIn("\u202e", shown)
        self.assertNotIn("\u200b", shown)
        self.assertIn("<U+202E>", shown)
        self.assertIn("<U+200B>", shown)
        self.assertIn("invisible or look like other letters", shown)

    def test_look_alike_letters_are_spelled_out(self):
        shown = approve._safe("connect to g\u0456thub.com")
        self.assertIn("<U+0456>", shown)
        self.assertNotIn("\u0456", shown)

    def test_ordinary_text_is_shown_as_it_is(self):
        self.assertEqual(approve._safe("Use the 'openai' key for api.openai.com (GET /v1/models)"),
                         "Use the 'openai' key for api.openai.com (GET /v1/models)")
        self.assertEqual(approve._safe("caf\u00e9 r\u00e9sum\u00e9 na\u00efve"), "caf\u00e9 r\u00e9sum\u00e9 na\u00efve")

    def test_blank_padding_cannot_push_the_real_words_out_of_view(self):
        shown = approve._safe("Allow harmless thing" + " " * 400 + "\n\n\n\n" + "and send ALL keys")
        self.assertLess(len(shown), 60)
        self.assertIn("and send ALL keys", shown)

    def test_a_line_break_cannot_start_a_forged_question(self):
        shown = approve._safe("innocent\n\nAllow this? Yes, it is safe.")
        self.assertNotIn("\n", shown)

    def test_a_request_too_long_to_read_whole_is_refused_not_cut(self):
        rec = _Recorder(0)
        with mock.patch.object(approve, "subprocess", _fake_subprocess(rec)):
            self.assertIs(approve.dialog("x" * (approve.MAX_SHOWN + 1)), False)
            self.assertIs(approve.console("x" * (approve.MAX_SHOWN + 1)), False)
            self.assertIs(approve.ask_person("x" * (approve.MAX_SHOWN + 1)), False)
        self.assertEqual(rec.calls, [])

    def test_a_request_that_grows_too_long_once_spelled_out_is_refused(self):
        rec = _Recorder(0)
        with mock.patch.object(approve, "subprocess", _fake_subprocess(rec)):
            self.assertIs(approve.dialog("\u200b" * 400), False)      # 400 raw characters, 3200 spelled out
        self.assertEqual(rec.calls, [])

    @unittest.skipUnless(os.name == "nt", "the Windows pop-up")
    def test_the_windows_window_gets_the_full_exact_text_and_is_on_top(self):
        rec = _Recorder(1)                                        # the person clicks No
        text = "Send the 'openai' key to g\u0456thub.com \u202e"
        with mock.patch.object(approve, "subprocess", _fake_subprocess(rec)):
            self.assertIs(approve.dialog(text), False)
        (cmd, kw), = rec.calls
        script = cmd[-1]
        self.assertIn("TopMost=$true", script)
        self.assertIn("MessageBox]::Show($o,$env:SEA_MSG", script)
        self.assertIn("'YesNo','Warning','Button2'", script)       # No is the default button
        self.assertIn("stuntkey - permission needed", script)      # fixed title
        shown = kw["env"]["SEA_MSG"]
        self.assertIn("<U+0456>", shown)
        self.assertIn("<U+202E>", shown)
        self.assertTrue(shown.endswith("\n\nAllow this?"))
        self.assertNotIn(text, shown)                              # not the raw text with its tricks
        self.assertEqual(set(kw["env"]), {"SystemRoot", "windir", "PATH", "SEA_MSG"})

    @unittest.skipUnless(os.name == "nt", "the Windows pop-up")
    def test_yes_is_only_an_exit_status_of_zero(self):
        with mock.patch.object(approve, "subprocess", _fake_subprocess(_Recorder(0))):
            self.assertIs(approve.dialog("ok"), True)
        approve._shown.clear()
        with mock.patch.object(approve, "subprocess", _fake_subprocess(_Recorder(1))):
            self.assertIs(approve.dialog("ok"), False)

    @unittest.skipUnless(os.name == "nt", "PowerShell parser")
    def test_the_windows_script_is_valid_powershell(self):
        # the parser reads the text; nothing in it is run and no window can open
        root = os.environ.get("SystemRoot", r"C:\Windows")
        ps = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        if not os.path.isfile(ps):
            self.skipTest("no powershell.exe")
        parse = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseInput("
                 "$env:SCRIPT,[ref]$t,[ref]$e);if($e.Count -gt 0){$e|%{$_.Message};exit 1}else{'ok'}")
        done = subprocess.run(             # the test's own (approve's copy is stubbed), only ever given the PARSER
            [ps, "-NoProfile", "-NonInteractive", "-Command", parse],
                        env=dict(os.environ, SCRIPT=approve.WIN_SCRIPT), capture_output=True, text=True, timeout=90)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "ok"), done.stderr)


# ======================================================================= consent

class ConsentHardening(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        self.dir = os.path.join(self.home, ".stuntkey")
        consent._HARDENED.clear()
        self.addCleanup(consent._HARDENED.clear)

    def test_only_the_stuntkey_folder_is_hardened(self):
        rec = _Recorder(0)
        other = os.path.join(self.home, "elsewhere")
        os.makedirs(other)
        self.assertFalse(consent.harden_acl(other, run=rec))
        self.assertEqual(rec.calls, [])

    @unittest.skipUnless(os.name == "nt", "Windows ACLs")
    def test_icacls_is_asked_for_the_owner_and_system_only_without_a_window(self):
        os.makedirs(self.dir)
        rec = _Recorder(0)
        self.assertTrue(consent.harden_acl(self.dir, run=rec))
        (cmd, kw), = rec.calls
        self.assertTrue(cmd[0].lower().endswith(r"system32\icacls.exe"))
        self.assertIn("/inheritance:r", cmd)
        grants = [a for a in cmd if a.startswith("*S-1-")]
        self.assertEqual(len(grants), 2)
        self.assertTrue(grants[1].startswith("*S-1-5-18:"))
        self.assertTrue(all(g.endswith("(OI)(CI)F") for g in grants))     # a folder: files made later inherit
        self.assertEqual(kw["creationflags"], subprocess.CREATE_NO_WINDOW)
        # done once per path per run
        self.assertTrue(consent.harden_acl(self.dir, run=_boom))

    @unittest.skipUnless(os.name == "nt", "Windows ACLs")
    def test_the_real_acl_is_owner_and_system_only_and_still_works(self):
        os.makedirs(self.dir)
        self.assertTrue(consent.harden_acl(self.dir))
        shown = subprocess.run([os.path.join(os.environ["SystemRoot"], "System32", "icacls.exe"), self.dir],
                               capture_output=True, text=True, timeout=30).stdout
        for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users", "BUILTIN\\Administrators"):
            self.assertNotIn(broad, shown)
        self.assertIn("NT AUTHORITY\\SYSTEM", shown)
        store = consent.FileSecret(os.path.join(self.dir, "consent.key"))
        store.save(os.urandom(40))                    # the owner can still write and read it
        self.assertEqual(len(store.load()), 40)

    @unittest.skipUnless(os.name == "nt", "Windows ACLs")
    def test_the_switch_that_turns_it_off_works(self):
        os.makedirs(self.dir)
        with mock.patch.dict(os.environ, {"STUNTKEY_NO_ACL": "1"}):
            self.assertFalse(consent.harden_acl(self.dir, run=_boom))

    @unittest.skipUnless(os.name == "nt", "Windows ACLs")
    def test_the_sid_is_a_user_sid(self):
        sid = consent._current_sid()
        self.assertRegex(sid or "", r"^S-1-5-21(-\d+){4}$|^S-1-5-\d+(-\d+)*$")

    def test_a_link_where_the_secret_should_be_is_not_the_secret(self):
        os.makedirs(self.dir)
        target = os.path.join(self.dir, "real")
        with open(target, "wb") as f:
            f.write(os.urandom(48))
        link = os.path.join(self.dir, "consent.key")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("no permission to make a symbolic link here")
        self.assertIsNone(consent.FileSecret(link).load())

    def test_a_grant_can_end_and_one_without_an_end_stays(self):
        store = consent.FileSecret(os.path.join(self.dir, "consent.key"))
        path = os.path.join(self.dir, "agent-consent.json")
        proj = _isolation.mktemp()
        import datetime
        past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        consent.grant(proj, "openai", path=path, store=store, now=past, days=30)        # ended in 2020
        consent.grant(proj, "github", path=path, store=store, now=past)                  # no end
        consent.grant(proj, "stripe", path=path, store=store, days=30)                   # ends in 30 days
        got = {g["service"] for g in consent.read_grants(path, store)[0]}
        self.assertEqual(got, {"github", "stripe"})
        self.assertIsNone(consent.consent_for(proj, "openai", path, store))

    def test_an_end_date_that_cannot_be_read_counts_as_ended(self):
        self.assertTrue(consent._expired({"expires": "not a date"}))
        self.assertTrue(consent._expired({"expires": 12}))
        self.assertFalse(consent._expired({}))

    def test_a_forged_or_edited_file_is_still_refused(self):
        store = consent.FileSecret(os.path.join(self.dir, "consent.key"))
        path = os.path.join(self.dir, "agent-consent.json")
        proj = _isolation.mktemp()
        consent.grant(proj, "openai", path=path, store=store)
        data = json.load(open(path, encoding="utf-8"))
        data["grants"][0]["service"] = "stripe"
        json.dump(data, open(path, "w", encoding="utf-8"))
        self.assertEqual(consent.read_grants(path, store), ([], "forged"))


# ======================================================================= caps

class CapsHardening(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()

    def test_a_service_name_cannot_point_the_record_outside_the_usage_folder(self):
        usage = os.path.realpath(os.path.join(self.home, "usage"))
        for name in ("../../evil", "..\\..\\evil", "a/b", "C:\\x", "con", "NUL", "com1", "x.", "a\nb", "", "x" * 200,
                     "\u202eevil", "a:b"):
            with self.subTest(service=name):
                p = os.path.realpath(caps.usage_path(self.home, name))
                self.assertEqual(os.path.dirname(p), usage)
                self.assertTrue(p.endswith(".json"))

    def test_ordinary_names_keep_their_file_name(self):
        for name in ("openai", "github", "my-svc", "my_svc", "svc.v2", "OpenAI"):
            self.assertTrue(caps.usage_path(self.home, name).endswith(name + ".json"))

    def test_different_odd_names_do_not_share_a_record(self):
        self.assertNotEqual(caps.usage_path(self.home, "a/b"), caps.usage_path(self.home, "a\\b"))

    def test_a_cap_typed_in_other_case_still_applies(self):
        with open(caps.caps_path(self.home), "w", encoding="utf-8") as f:
            json.dump({"OpenAI": {"calls_day": 2}}, f)
        self.assertEqual(caps.effective_caps(self.home, "openai")["calls_day"], 2)
        caps.begin(self.home, "openai", 0)
        caps.begin(self.home, "openai", 0)
        with self.assertRaises(BrokerError):
            caps.begin(self.home, "openai", 0)

    def test_a_damaged_hourly_record_stops_calls_instead_of_clearing_the_cap(self):
        caps.begin(self.home, "openai", 0)
        hour = caps._hour_path(caps.usage_path(self.home, "openai"))
        self.assertTrue(os.path.isfile(hour))
        with open(hour, "w", encoding="utf-8") as f:
            f.write("{ not json")
        with self.assertRaises(BrokerError) as ctx:
            caps.begin(self.home, "openai", 0)
        self.assertIn(".hourly", str(ctx.exception))
        os.unlink(hour)                                    # the person deletes it: calls work again
        caps.begin(self.home, "openai", 0)

    def test_no_hourly_record_yet_or_an_old_hour_starts_at_zero(self):
        caps.begin(self.home, "openai", 0)                 # no file before: fine
        hour = caps._hour_path(caps.usage_path(self.home, "openai"))
        with open(hour, "w", encoding="utf-8") as f:
            json.dump({"hour": "2001-01-01T00", "calls": 99999}, f)
        caps.begin(self.home, "openai", 0)                 # an earlier hour: a new one starts

    def test_the_hourly_cap_still_stops_the_calls(self):
        with open(caps.caps_path(self.home), "w", encoding="utf-8") as f:
            json.dump({"openai": {"calls_hour": 1}}, f)
        caps.begin(self.home, "openai", 0)
        with self.assertRaises(BrokerError):
            caps.begin(self.home, "openai", 0)


# ======================================================================= policy

def _rules(**services):
    return policy.parse(json.dumps(services).encode())


class PolicyHardening(unittest.TestCase):
    def setUp(self):
        self.rules = _rules(openai={"methods": ["GET"], "paths": ["/v1/models"]})

    def _ok(self, path, method="GET"):
        policy.check(self.rules, "openai", method, path)

    def _no(self, path, method="GET"):
        with self.assertRaises(BrokerError):
            policy.check(self.rules, "openai", method, path)

    def test_listed_paths_still_pass(self):
        for p in ("/v1/models", "/v1/models/gpt-x", "/v1/models?limit=5", "/v1/models/a%20b"):
            with self.subTest(path=p):
                self._ok(p)

    def test_paths_that_slip_past_a_prefix_are_refused(self):
        for p in ("/v1/models/../files", "/v1/models/./../files", "/v1/models/%2e%2e/files",
                  "/v1/models/%2E%2E/files", "/v1/models/%252e%252e/files", "/v1/models/..%2ffiles",
                  "/v1/models/..%5cfiles", "/v1/models\\..\\files", "/v1/models;/../files",
                  "/v1/models#/../files", "/v1/models/\x00/../files", "/v1/models/%00", "/v1/models/..",
                  "/v1/models/%2e", "/v1/models/%0d%0aX:1"):
            with self.subTest(path=p):
                self._no(p)

    def test_method_and_prefix_rules_still_apply(self):
        self._no("/v1/modelsX")
        self._no("/v1/models", "POST")
        self._no("/v1/files")

    def test_a_rule_written_in_other_case_still_applies(self):
        rules = _rules(OpenAI={"methods": ["get"], "paths": ["/v1/models"]})
        with self.assertRaises(BrokerError):
            policy.check(rules, "openai", "GET", "/v1/files")
        with self.assertRaises(BrokerError):
            policy.check(rules, "OPENAI", "GET", "/v1/files")
        policy.check(rules, "openai", "get", "/v1/models")

    def test_a_service_named_twice_is_refused(self):
        raw = (b'{"openai": {"methods": ["GET"], "paths": ["/v1/models"]},'
               b' "openai": {"methods": ["GET","POST"], "paths": ["/"]}}')
        with self.assertRaises(BrokerError):
            policy.parse(raw)
        raw2 = (b'{"openai": {"methods": ["GET"], "paths": ["/a"]}, "OpenAI": {"methods": ["GET"], "paths": ["/"]}}')
        with self.assertRaises(BrokerError):
            policy.parse(raw2)

    def test_a_rule_with_a_trick_in_its_own_path_is_refused(self):
        for bad in ("/v1/../admin", "/v1/%2e%2e/admin", "/v1\\x", "/v1;x", "v1/models", "/v1/\x01"):
            with self.subTest(path=bad):
                with self.assertRaises(BrokerError):
                    policy.parse(json.dumps({"openai": {"methods": ["GET"], "paths": [bad]}}).encode())

    def test_services_without_a_rule_are_left_alone(self):
        policy.check(self.rules, "github", "DELETE", "/../anything")

    def test_the_review_shows_what_is_enforced(self):
        shown = []
        home, proj = _isolation.mktemp(), _isolation.mktemp()
        with open(policy.user_file(home), "w", encoding="utf-8") as f:
            f.write('{"OpenAI": {"methods": ["post", "get"], "paths": ["/v1/chat", "/v1/models"]}}')
        n = policy.approve(home, proj, lambda s: shown.append(s) or True)
        self.assertEqual(n, 1)
        self.assertIn("openai: GET, POST on /v1/chat, /v1/models", shown[0])
        self.assertEqual(policy.load(home, proj)["openai"][0], frozenset({"GET", "POST"}))

    def test_a_changed_file_needs_approval_again(self):
        home, proj = _isolation.mktemp(), _isolation.mktemp()
        path = policy.user_file(home)
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"openai": {"methods": ["GET"], "paths": ["/v1/models"]}}')
        policy.approve(home, proj, lambda s: True)
        policy.load(home, proj)
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"openai": {"methods": ["GET"], "paths": ["/"]}}')
        with self.assertRaises(BrokerError):
            policy.load(home, proj)


class FindThenChange(unittest.TestCase):
    def test_finding_the_program_then_deleting_it_is_refused(self):
        for cmd in ("rm $(which stuntkey)", "which stuntkey && del C:\\x\\stuntkey.exe",
                    "python -c \"import stuntkey,os;os.remove(stuntkey.__file__)\""):
            with self.subTest(cmd=cmd):
                self.assertTrue(deny(cmd), cmd)

    def test_finding_the_program_then_installing_something_else_is_fine(self):
        for cmd in ("which stuntkey && pip install requests", "which stuntkey && git pull"):
            with self.subTest(cmd=cmd):
                self.assertFalse(deny(cmd), cmd)


if __name__ == "__main__":
    unittest.main()
