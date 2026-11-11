"""Round 14: release plumbing. The Windows installer script, the release builder that fills a
COPY of the winget manifest, the placeholder gate, and the test tiers."""
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLACEHOLDER = "REPLACE_WITH_THE_SHA256_OF_THE_ZIP_FROM_SHA256SUMS"
INSTALLER = os.path.join(ROOT, "packaging", "windows", "install.ps1")


def _version():
    with open(os.path.join(ROOT, "stuntkey", "__init__.py"), encoding="utf-8") as f:
        return re.search(r'__version__ = "([^"]+)"', f.read()).group(1)


def _committed_manifest_dir():
    return os.path.join(ROOT, "packaging", "winget", "manifests", "c", "Calas", "StuntKey",
                        _version())


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _powershell():
    return shutil.which("powershell") or shutil.which("pwsh")


def _load_make_release():
    spec = importlib.util.spec_from_file_location(
        "make_release_under_test", os.path.join(ROOT, "packaging", "make_release.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- 1. the winget manifest placeholder ---------------------------------------------

class WingetPlaceholderGate(unittest.TestCase):
    """The committed manifest keeps a placeholder. A manifest meant for release (run with
    SK_RELEASE_CHECK=1, SK_MANIFEST_DIR=<filled copy>) must not."""

    def _installer_text(self, folder):
        with open(os.path.join(folder, "Calas.StuntKey.installer.yaml"), encoding="utf-8") as f:
            return f.read()

    def test_release_check_fails_while_the_placeholder_remains(self):
        if os.environ.get("SK_RELEASE_CHECK") != "1":
            self.skipTest("only enforced with SK_RELEASE_CHECK=1 (see docs/_work/release-checklist.md)")
        folder = os.environ.get("SK_MANIFEST_DIR") or _committed_manifest_dir()
        text = self._installer_text(folder)
        self.assertNotIn(PLACEHOLDER, text, "the winget manifest still has its SHA256 placeholder; "
                         "run packaging/make_release.py and point SK_MANIFEST_DIR at its copy")
        m = re.search(r"InstallerSha256:\s*(\S+)", text)
        self.assertTrue(m and re.fullmatch(r"[0-9A-Fa-f]{64}", m.group(1)), "InstallerSha256 is not a sha256")

    def test_committed_manifest_is_the_placeholder_or_a_real_hash_never_half_filled(self):
        text = self._installer_text(_committed_manifest_dir())
        m = re.search(r"InstallerSha256:\s*(\S+)", text)
        self.assertTrue(m)
        self.assertTrue(m.group(1) == PLACEHOLDER or re.fullmatch(r"[0-9A-Fa-f]{64}", m.group(1)),
                        "InstallerSha256 must be the placeholder or a full 64-hex hash")


# ---- 2. make_release.py -------------------------------------------------------------

class MakeRelease(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_make_release()
        cls.before = {n: _read_bytes(os.path.join(_committed_manifest_dir(), n))
                      for n in os.listdir(_committed_manifest_dir())}
        cls.out = tempfile.mkdtemp(prefix="sk-r14-release-")
        cls.res = cls.mod.make_release(cls.out, skip_wheel=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out, ignore_errors=True)

    def test_zip_and_sums_agree(self):
        zip_path = self.res["zip"]
        self.assertTrue(zipfile.is_zipfile(zip_path))
        with zipfile.ZipFile(zip_path) as z:
            self.assertEqual(sorted(z.namelist()), ["LICENSE", "stuntkey.cmd", "stuntkey.pyz"])
        want = hashlib.sha256(_read_bytes(zip_path)).hexdigest()
        with open(self.res["sums"], encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertIn("%s  %s" % (want, os.path.basename(zip_path)), lines)

    def test_the_copy_is_filled_and_valid(self):
        want = hashlib.sha256(_read_bytes(self.res["zip"])).hexdigest().upper()
        copy = os.path.join(self.res["manifest_dir"], "Calas.StuntKey.installer.yaml")
        with open(copy, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn(PLACEHOLDER, text)
        self.assertIn("InstallerSha256: " + want, text)
        self.assertEqual(sorted(os.listdir(self.res["manifest_dir"])), sorted(self.before))

    def test_the_committed_manifest_is_untouched(self):
        for name, data in self.before.items():
            self.assertEqual(_read_bytes(os.path.join(_committed_manifest_dir(), name)), data)

    def test_it_refuses_a_bad_hash(self):
        with self.assertRaises(ValueError):
            self.mod.fill_manifest(_committed_manifest_dir(), os.path.join(self.out, "x"), "nothex")

    def test_the_filled_copy_passes_the_release_gate(self):
        env = dict(os.environ, SK_RELEASE_CHECK="1", SK_MANIFEST_DIR=self.res["manifest_dir"])
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            os.path.join(HERE, "test_r14_release.py"), "-k",
                            "release_check_fails_while_the_placeholder_remains"],
                           capture_output=True, text=True, env=env, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stdout[-600:] + r.stderr[-300:])
        env["SK_MANIFEST_DIR"] = _committed_manifest_dir()
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            os.path.join(HERE, "test_r14_release.py"), "-k",
                            "release_check_fails_while_the_placeholder_remains"],
                           capture_output=True, text=True, env=env, cwd=ROOT)
        if PLACEHOLDER in open(os.path.join(_committed_manifest_dir(),
                                            "Calas.StuntKey.installer.yaml"), encoding="utf-8").read():
            self.assertNotEqual(r.returncode, 0, "the gate must fail on the committed placeholder")


# ---- 3. install.ps1 -----------------------------------------------------------------

class WindowsInstaller(unittest.TestCase):
    def setUp(self):
        with open(INSTALLER, "rb") as f:
            self.raw = f.read()
        self.text = self.raw.decode("ascii")      # plain ASCII: Windows PowerShell 5.1 reads it right

    def test_it_only_uses_the_allowed_sources(self):
        low = self.text.lower()
        for banned in ("invoke-webrequest", "invoke-restmethod", "iwr ", "downloadstring",
                       "downloadfile", "curl ", "wget ", "start-bitsTransfer".lower(), "iex "):
            self.assertNotIn(banned, low)
        urls = set(re.findall(r"https?://[^\s'\")]+", self.text))
        for u in urls:
            self.assertIn("python.org", u, "unexpected URL in the installer: " + u)

    def test_no_admin_needed(self):
        low = self.text.lower()
        self.assertNotIn("runas", low)
        self.assertNotIn("-verb", low)
        self.assertIn("--scope", low)
        self.assertIn("--user", low)

    def test_the_plan_steps_are_there_and_it_asks_once(self):
        for needle in ("Python.Python.3.12", "pip\", \"install\", \"--user\"", "pipx", "ensurepath",
                       "\"install\", \"--force\"", "stuntkey start", "Read-Host", "-WhatIf"):
            self.assertIn(needle, self.text, needle)
        self.assertEqual(self.text.count("Read-Host"), 1)

    @unittest.skipUnless(_powershell(), "PowerShell is not available")
    def test_it_parses(self):
        ps = _powershell()
        code = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
                "'%s',[ref]$t,[ref]$e);if($e.Count){$e|%%{$_.Message};exit 1}" % INSTALLER)
        r = subprocess.run([ps, "-NoProfile", "-Command", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    @pytest.mark.slow
    @unittest.skipUnless(_powershell(), "PowerShell is not available")
    def test_dry_run_prints_the_plan_and_changes_nothing(self):
        home = tempfile.mkdtemp(prefix="sk-r14-ps-")
        try:
            env = {k: v for k, v in os.environ.items() if not k.startswith("STUNTKEY_")}
            env.update(HOME=home, USERPROFILE=home, APPDATA=os.path.join(home, "a"),
                       LOCALAPPDATA=os.path.join(home, "l"), STUNTKEY_KEYCHAIN="memory")
            r = subprocess.run([_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                INSTALLER, "-WhatIf"], capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("Nothing is changed", r.stdout)
            self.assertIn("pipx install --force stuntkey", r.stdout)
            self.assertIn("pipx ensurepath", r.stdout)
            # PowerShell itself may create an AppData folder; the plan must add nothing else
            self.assertEqual([n for n in os.listdir(home) if n.lower() != "appdata"], [],
                             "the dry run wrote into the home folder")
            for n in ("pipx", "Python", "stuntkey", ".stuntkey"):
                self.assertFalse(os.path.exists(os.path.join(home, "l", n)))
        finally:
            shutil.rmtree(home, ignore_errors=True)


# ---- 4. test tiers and docs ---------------------------------------------------------

class TiersAndDocs(unittest.TestCase):
    def test_slow_marker_and_fast_option_exist(self):
        with open(os.path.join(HERE, "conftest.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("slow:", text)
        self.assertIn("--fast", text)

    def test_the_review_brief_exists_and_does_not_claim_a_review(self):
        path = os.path.join(ROOT, "docs", "SECURITY_REVIEW_BRIEF.md")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("No independent review has been done", text)
        self.assertIn("security/advisories/new", text)

    def test_the_checklist_has_a_rollback_and_the_release_gate(self):
        with open(os.path.join(ROOT, "docs", "_work", "release-checklist.md"), encoding="utf-8") as f:
            text = f.read()
        for needle in ("## C. Rollback", "SK_RELEASE_CHECK", "make_release.py", "--fast"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
