"""leakbench/ mirrors keycanary's CORE probes (same ids, same JSON); fail if they drift.

The extended set and the benign (harmless-command) set exist only in StuntKey's leakbench: keycanary has no such sets, so they are not compared.
Skipped when keycanary is not importable (a stranger who only cloned StuntKey)."""
import json
import os
import unittest

try:
    import keycanary
except ImportError:
    keycanary = None

HERE = os.path.dirname(os.path.abspath(__file__))
MIRROR = os.path.join(os.path.dirname(HERE), "leakbench", "probes")


def _core(path):
    out = {}
    for name in sorted(os.listdir(path)):
        if name.endswith(".json"):
            with open(os.path.join(path, name), encoding="utf-8") as fh:
                out[name] = json.load(fh)
    return out


@unittest.skipIf(keycanary is None, "keycanary is not installed")
class Mirror(unittest.TestCase):
    def test_core_probe_files_are_identical_to_keycanary(self):
        theirs = os.path.join(os.path.dirname(os.path.abspath(keycanary.__file__)), "probes")
        self.assertEqual(_core(MIRROR), _core(theirs))


if __name__ == "__main__":
    unittest.main()
