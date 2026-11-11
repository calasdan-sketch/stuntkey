"""What is packaged: the wheel and the sdist, built from a clean copy.

Panel finding (SEA-8):
- the sdist left out tests/_isolation.py (setuptools adds only tests/test*.py
  by itself), so the tests inside it could not even be imported;
- the wheel test built the working tree in place. A gitignored build/ left
  there by an earlier build is reused: setuptools packs everything it finds in
  build/lib - a module since deleted or renamed included - into the wheel.

Every build here is of _isolation.clean_source_copy(), and runs offline: it
needs a setuptools >= 77 installed in this interpreter and is skipped without.
"""

import ast
import os
import shutil
import subprocess
import sys
import tarfile
import unittest
import zipfile

import _isolation

LEFTOVERS = ["build/lib/stuntkey/stale.py",
             "dist/stuntkey-0.0.1-py3-none-any.whl",
             "stuntkey.egg-info/PKG-INFO",
             ".git/config", ".venv/pyvenv.cfg", ".pytest_cache/README",
             "stuntkey/__pycache__/cli.cpython-311.pyc",
             "stuntkey/__pycache__/notes.txt",
             "stuntkey/legacy.pyc",
             "tests/__pycache__/test_a.cpython-311.pyc"]
KEPT = ["pyproject.toml", "README.md", "MANIFEST.in",
        "stuntkey/__init__.py", "stuntkey/recipes/github.json",
        "tests/_isolation.py", "tests/test_a.py"]


def write(root, rel, text="x\n"):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def listing(root):
    return sorted(os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/")
                  for d, _dirs, files in os.walk(root) for f in files)


def project():
    root = _isolation.mktemp()
    for rel in KEPT + LEFTOVERS:
        write(root, rel)
    return root


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    subprocess.run(["git", "-C", root, *args], env=env, check=True,
                   capture_output=True)


def child_env():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


class TestCleanSourceCopy(unittest.TestCase):
    def test_without_git_the_build_leftovers_stay_behind(self):
        copy = _isolation.clean_source_copy(project(), use_git=False)
        self.assertEqual(listing(copy), sorted(KEPT))

    def test_only_the_top_level_folders_are_leftovers(self):
        # a package may have a folder of its own called build
        root = project()
        write(root, "stuntkey/build/step.py")
        copy = _isolation.clean_source_copy(root, use_git=False)
        self.assertIn("stuntkey/build/step.py", listing(copy))
        self.assertNotIn("build/lib/stuntkey/stale.py", listing(copy))

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_with_git_it_is_what_git_would_commit(self):
        root = project()
        git(root, "init", "-q")
        write(root, ".gitignore",
              "build/\ndist/\n*.egg-info/\n.venv/\n.pytest_cache/\n"
              "__pycache__/\n*.py[cod]\n*.log\n")
        write(root, "stuntkey/new_module.py")     # untracked, not ignored
        write(root, "debug.log")                     # ignored, and not on any list
        git(root, "add", "pyproject.toml")
        names = listing(_isolation.clean_source_copy(root))
        self.assertIn("stuntkey/new_module.py", names)
        self.assertIn(".gitignore", names)
        self.assertNotIn("debug.log", names)
        for leftover in LEFTOVERS:
            if not leftover.startswith(".git/"):
                self.assertNotIn(leftover, names)
        self.assertFalse([n for n in names if n.startswith(".git/")], names)

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_when_git_cannot_say_the_walk_is_used(self):
        # the .git folder here is not a repository
        copy = _isolation.clean_source_copy(project())
        self.assertEqual(listing(copy), sorted(KEPT))

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_a_folder_inside_somebody_elses_checkout_is_not_asked_of_git(self):
        outer = _isolation.mktemp()
        git(outer, "init", "-q")
        write(outer, ".gitignore", "inner/pyproject.toml\n")
        inner = os.path.join(outer, "inner")
        for rel in KEPT:
            write(inner, rel)
        # git, asked about inner/, would leave out the file the outer
        # checkout ignores
        names = listing(_isolation.clean_source_copy(inner))
        self.assertEqual(names, sorted(KEPT))

    def test_the_real_checkout_gives_the_package_and_no_leftovers(self):
        names = listing(_isolation.clean_source_copy())
        for needed in ("pyproject.toml", "MANIFEST.in",
                       "stuntkey/cli.py", "stuntkey/recipes/github.json",
                       "tests/_isolation.py"):
            self.assertIn(needed, names)
        junk = [n for n in names
                if n.split("/")[0] in _isolation.BUILD_LEFTOVERS
                or ".egg-info" in n or "__pycache__" in n
                or n.endswith((".pyc", ".pyo"))]
        self.assertEqual(junk, [])


class TestManifest(unittest.TestCase):
    def test_the_tests_and_their_helper_are_listed(self):
        with open(os.path.join(_isolation.REPO, "MANIFEST.in"),
                  encoding="utf-8") as f:
            lines = [ln.split() for ln in f.read().splitlines()
                     if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertIn(["recursive-include", "tests", "*.py"], lines)


class TestNothingIsDownloaded(unittest.TestCase):
    """pip, asked to build with build isolation, fetches the build backend from
    the package index: the one way a test here could leave this computer."""

    def test_pip_runs_only_here_and_never_with_build_isolation(self):
        here = os.path.dirname(os.path.abspath(__file__))
        runs = []
        for name in sorted(os.listdir(here)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(here, name), encoding="utf-8") as f:
                tree = ast.parse(f.read(), name)
            for node in ast.walk(tree):
                if isinstance(node, (ast.List, ast.Tuple)):
                    words = [e.value for e in node.elts
                             if isinstance(e, ast.Constant)]
                    if "pip" in words:
                        runs.append((name, words))
        self.assertEqual({name for name, _ in runs}, {"test_packaging.py"}, runs)
        for name, words in runs:
            self.assertIn("--no-build-isolation", words, (name, words))


@unittest.skipUnless(_isolation.have_setuptools(77),
                     "needs setuptools >= 77 installed (nothing is downloaded)")
class TestBuilt(unittest.TestCase):
    def sdist(self, src):
        out = _isolation.mktemp()
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; from setuptools import build_meta; "
             "print(build_meta.build_sdist(sys.argv[1]))", out],
            cwd=src, env=child_env(), capture_output=True, text=True,
            timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr[-1500:])
        return os.path.join(out, proc.stdout.strip().splitlines()[-1])

    def wheel(self, src):
        out = _isolation.mktemp()
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", src, "-w", out, "--no-deps",
             "--no-build-isolation", "-q"], cwd=out, env=child_env(),
            capture_output=True, text=True, timeout=600)
        self.assertEqual(proc.returncode, 0, proc.stderr[-1500:])
        wheels = [n for n in os.listdir(out) if n.endswith(".whl")]
        self.assertEqual(len(wheels), 1, wheels)
        with zipfile.ZipFile(os.path.join(out, wheels[0])) as zf:
            names = set(zf.namelist())
            entry_points = b"".join(zf.read(n) for n in sorted(names)
                                    if n.endswith("entry_points.txt"))
        return names, entry_points

    def test_the_sdist_carries_every_test_and_their_helper(self):
        src = _isolation.clean_source_copy()
        want = [n for n in listing(src)
                if n.startswith("tests/") and n.endswith(".py")]
        with tarfile.open(self.sdist(src)) as tar:
            names = {n.split("/", 1)[1] for n in tar.getnames() if "/" in n}
        self.assertIn("tests/_isolation.py", want)
        self.assertEqual([n for n in want if n not in names], [])
        for needed in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in",
                       "stuntkey/cli.py", "stuntkey/recipes/github.json"):
            self.assertIn(needed, names)
        self.assertEqual([n for n in names
                          if n.startswith(("build/", "dist/", ".git/"))
                          or "__pycache__" in n or n.endswith(".pyc")], [])

    def test_the_tests_in_the_sdist_run(self):
        path = self.sdist(_isolation.clean_source_copy())
        where = _isolation.mktemp()
        with tarfile.open(path) as tar:
            if sys.version_info >= (3, 12):
                tar.extractall(where, filter="data")
            else:
                tar.extractall(where)
        root = os.path.join(where, os.listdir(where)[0])
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_recipes.py"], cwd=root, env=child_env(),
            capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr[-1500:])
        self.assertIn("OK", proc.stderr)

    def test_a_stale_build_directory_cannot_reach_the_wheel(self):
        planted = _isolation.clean_source_copy()
        write(planted, "build/lib/stuntkey/zzz_stale.py", "STALE = 1\n")
        write(planted, "stuntkey.egg-info/PKG-INFO", "Metadata-Version: 2.1\n")
        names, _ = self.wheel(_isolation.clean_source_copy(planted, use_git=False))
        self.assertIn("stuntkey/cli.py", names)
        self.assertNotIn("stuntkey/zzz_stale.py", names)

    def test_the_wheel_has_the_package_and_nothing_else(self):
        src = _isolation.clean_source_copy()
        want = {n for n in listing(src)
                if n.startswith("stuntkey/")
                and (n.endswith(".py") or n.startswith(("stuntkey/recipes/", "stuntkey/skill/", "stuntkey/web/")))}
        names, entry_points = self.wheel(src)
        package = {n for n in names if not n.split("/")[0].endswith(".dist-info")}
        self.assertEqual(package, want)
        self.assertIn(b"stuntkey = stuntkey.cli:main", entry_points)


if __name__ == "__main__":
    unittest.main()
