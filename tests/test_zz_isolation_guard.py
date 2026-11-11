"""The suite never touches the real ~/.stuntkey, and no STUNTKEY_* variable crosses a test boundary."""
import os
import unittest

import _isolation


class TestIsolationGuard(unittest.TestCase):
    def test_real_stuntkey_folder_is_unchanged(self):
        # compared read-only: sizes, mtimes and the sha256 of index.json (this includes
        # the activity log) as they were when the first test module was imported
        now = _isolation.real_stuntkey_state(_isolation.REAL_HOME)
        self.assertEqual(now, _isolation.REAL_STATE_AT_START)

    def test_home_is_not_the_real_one(self):
        self.assertNotEqual(os.path.normcase(os.path.expanduser("~")),
                            os.path.normcase(_isolation.REAL_HOME))

    def test_exported_stuntkey_variables_never_reach_a_test(self):
        leftovers = [k for k in os.environ
                     if k.startswith("STUNTKEY_") and k != "STUNTKEY_TEST_HOME"]
        self.assertEqual(leftovers, [])

    def test_restore_env_undoes_what_a_test_sets(self):
        snap = _isolation.snapshot_env()
        os.environ["STUNTKEY_KEYCHAIN"] = "memory"
        _isolation.restore_env(snap)
        self.assertNotIn("STUNTKEY_KEYCHAIN", os.environ)

    def test_scrub_env_removes_exported_values(self):
        snap = _isolation.snapshot_env()
        try:
            os.environ["STUNTKEY_KEYCHAIN"] = "memory"
            _isolation.scrub_env()
            self.assertNotIn("STUNTKEY_KEYCHAIN", os.environ)
        finally:
            _isolation.restore_env(snap)


if __name__ == "__main__":
    unittest.main()
