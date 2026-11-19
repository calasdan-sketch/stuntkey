"""leakbench/ is a frozen mirror of keycanary's probes; fail if they drift."""
import unittest

from leakbench import loader as lb

try:
    from keycanary import loader as kc
except ImportError:
    kc = None


@unittest.skipIf(kc is None, "keycanary is not installed")
class Mirror(unittest.TestCase):
    def test_probe_ids_match_keycanary(self):
        for extended in (False, True):
            self.assertEqual([p.id for p in lb.load(extended=extended)],
                             [p.id for p in kc.load(extended=extended)])


