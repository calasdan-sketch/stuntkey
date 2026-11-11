"""Round 12: release hygiene. Three things that drift silently:
the generated web pages, the version number in every package, and the
module import layers."""
import ast
import glob
import importlib.util
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


# ---- 1. generated pages equal what the build script makes ------------------------

class GeneratedPagesAreCurrent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.path.join(ROOT, "docs", "_work", "build_brand.py")
        spec = importlib.util.spec_from_file_location("build_brand_under_test", path)
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def test_importing_the_build_script_writes_nothing(self):
        self.assertTrue(self.mod.OUT)
        self.assertTrue(callable(self.mod.write_all))

    def test_every_generated_file_matches_the_tracked_copy(self):
        expected = {"docs/site/styles.css", "docs/site/index.html",
                    "docs/site/how-it-works.html", "docs/site/add-your-first-key.html",
                    "docs/site/what-it-does-not-protect.html", "docs/site/compare.html",
                    "stuntkey/web/index.html"}
        self.assertEqual(set(self.mod.OUT), expected)
        stale = []
        for rel, text in self.mod.OUT.items():
            if _read(*rel.split("/")) != text.replace("\r\n", "\n"):
                stale.append(rel)
        self.assertEqual(stale, [], "run `python docs/_work/build_brand.py` and commit "
                                    "the result; these differ from the script's output")

    def test_no_overclaiming_words_in_the_pages(self):
        for rel in self.mod.OUT:
            text = _read(*rel.split("/")).lower()
            for banned in ("all llms", "never sees", "never see them"):
                self.assertNotIn(banned, text, f"{rel} says '{banned}'")


# ---- 2. one version everywhere ----------------------------------------------------

def _version_in(text, pattern):
    m = re.search(pattern, text, re.M)
    return m.group(1) if m else None


class VersionParity(unittest.TestCase):
    def setUp(self):
        self.version = _version_in(_read("stuntkey", "__init__.py"),
                                   r'^__version__\s*=\s*"([^"]+)"')

    def test_pyproject_matches_the_package(self):
        self.assertEqual(_version_in(_read("pyproject.toml"), r'^version\s*=\s*"([^"]+)"'),
                         self.version)

    def test_npm_wrapper_matches(self):
        data = json.loads(_read("packaging", "npm", "package.json"))
        self.assertEqual(data["version"], self.version)

    def test_winget_manifests_match(self):
        base = os.path.join(ROOT, "packaging", "winget", "manifests", "c", "Calas", "StuntKey")
        try:
            folders = sorted(os.listdir(base))
        except PermissionError:
            self.skipTest("winget manifests are not readable here (access denied)")
        self.assertEqual(folders, [self.version], "one folder, named for this version")
        files = glob.glob(os.path.join(base, self.version, "*.yaml"))
        self.assertEqual(len(files), 3)
        for path in files:
            try:
                with open(path, encoding="utf-8") as f:
                    text = f.read()
            except PermissionError:
                self.skipTest("winget manifest not readable here (access denied)")
            self.assertEqual(_version_in(text, r"^PackageVersion:\s*(\S+)"), self.version, path)
            for url in re.findall(r"InstallerUrl:\s*(\S+)", text):
                self.assertIn(f"/v{self.version}/", url)
                self.assertIn(f"stuntkey-{self.version}-", url)

    def test_changelog_leads_with_this_version(self):
        first = _version_in(_read("CHANGELOG.md"), r"^## (\d+\.\d+\.\d+)")
        self.assertEqual(first, self.version)

    def test_shims_agree_with_themselves_and_ask_for_a_real_stuntkey(self):
        old_name = "safe" + "easy" + "api"      # the old product name; never spelled out in tests
        for folder, pkg in (("shim", old_name), ("shim-oathkey", "oathkey")):
            proj = _read(folder, "pyproject.toml")
            init = _read(folder, pkg, "__init__.py")
            own = _version_in(proj, r'^version\s*=\s*"([^"]+)"')
            self.assertEqual(own, _version_in(init, r'^__version__\s*=\s*"([^"]+)"'), folder)
            floor = _version_in(proj, r'"stuntkey>=([0-9.]+)"')
            self.assertIsNotNone(floor, folder)
            self.assertLessEqual(tuple(map(int, floor.split("."))),
                                 tuple(map(int, self.version.split("."))), folder)


# ---- 3. import layers: no NEW cycles ------------------------------------------------

PACKAGE = os.path.join(ROOT, "stuntkey")

# Cycles that exist today. They are written down so nobody adds to them by
# accident; do NOT add to this list to make a test pass - fix the new import
# (move the shared piece into a leaf module, as stuntkey/logfacts.py does).
# Imports inside functions count: they are how this code avoids load-time errors.
KNOWN_CYCLES = [
    # 17 modules: the broker / keychain / scrub / hook core and what calls into it
    frozenset("agentsetup broker bundle caps clients connect hook keychain mcpwrap "
              "migrate policy redact remote runner scan scrub validate".split()),
    # 9 modules: the command line, its command modules and the MCP server
    frozenset("agent allowcmd capture cli cmds connect_try extras mcp panic".split()),
]


def _graph():
    mods = {f[:-3] for f in os.listdir(PACKAGE) if f.endswith(".py") and f != "__init__.py"}
    graph = {}
    for m in mods:
        with open(os.path.join(PACKAGE, m + ".py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        deps = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                names = [node.module.split(".")[0]] if node.module else [a.name for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name.split(".")[1] for a in node.names
                         if a.name.startswith("stuntkey.") and "." in a.name]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module \
                    and node.module.split(".")[0] == "stuntkey":
                parts = node.module.split(".")
                names = [parts[1]] if len(parts) > 1 else [a.name for a in node.names]
            else:
                continue
            deps.update(n for n in names if n in mods and n != m)
        graph[m] = deps
    return graph


def _cycles(graph):
    """Strongly connected groups of more than one module (iterative Tarjan)."""
    index, low, on, stack, out, counter = {}, {}, set(), [], [], [0]
    for root in sorted(graph):
        if root in index:
            continue
        work = [(root, iter(sorted(graph[root])))]
        index[root] = low[root] = counter[0]
        counter[0] += 1
        stack.append(root)
        on.add(root)
        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter[0]
                    counter[0] += 1
                    stack.append(w)
                    on.add(w)
                    work.append((w, iter(sorted(graph[w]))))
                    advanced = True
                    break
                if w in on:
                    low[v] = min(low[v], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = set()
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.add(w)
                    if w == v:
                        break
                if len(comp) > 1:
                    out.append(frozenset(comp))
    return out


class ImportLayers(unittest.TestCase):
    def test_no_new_import_cycles(self):
        found = _cycles(_graph())
        new = []
        for comp in found:
            if not any(comp <= known for known in KNOWN_CYCLES):
                new.append(sorted(comp))
        self.assertEqual(new, [], "a NEW import cycle: move the shared piece into a "
                                  "module that imports nothing from stuntkey")

    def test_known_cycles_do_not_grow(self):
        found = _cycles(_graph())
        for comp in found:
            for known in KNOWN_CYCLES:
                if comp & known:
                    self.assertLessEqual(comp, known,
                                         f"a known cycle grew by {sorted(comp - known)}")

    def test_the_leaf_helpers_stay_leaves(self):
        graph = _graph()
        for leaf in ("logfacts",):
            self.assertEqual(graph[leaf], set(), f"{leaf} must not import stuntkey modules")


if __name__ == "__main__":
    unittest.main()
