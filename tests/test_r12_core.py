"""Round 12, core: the activity log's signing key made early, quick writes that
re-check only the end of the log, monthly files that still chain, the key-dates
file refusing a stripped signature and telling a lost key from a changed file,
format versions, atomic recipe saves, a lock that expires after a crash, and
cloud placeholder files not being read as links.

Every test works in a throwaway folder with only synthetic keys."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from stuntkey import broker, consent, ledger, recipes, store

ENTRY = {"service": "t", "method": "GET", "host": "h", "path": "/p",
         "status": 200, "bytes": 1, "result": "ok", "ms": 1}


def _dir():
    return tempfile.mkdtemp(prefix="stuntkey-r12c-")


def _log(n=3, d=None):
    d = d or _dir()
    log = broker.AuditLog(os.path.join(d, "audit.log"))
    for _ in range(n):
        log.write(dict(ENTRY))
    return log


def _lines(path):
    with open(path, "rb") as f:
        return [json.loads(x) for x in f.read().splitlines()]


def _plain_chain(count, path):
    """What 0.9.x wrote: SHA-256 chain, no key."""
    prev, out = "0" * 64, []
    for i in range(count):
        e = dict(ENTRY, ts=1, prev=prev)
        if i == 0:
            e["anchored"] = True
        h = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        out.append(dict(e, hash=h))
        prev = h
    with open(path, "w") as f:
        for e in out:
            f.write(json.dumps(e, sort_keys=True) + "\n")
    with open(path + ".head", "w") as f:
        f.write(f"{len(out)} {prev}\n")


class SigningKeyMadeEarly(unittest.TestCase):
    def test_no_key_yet_is_not_reported_as_unable_to_keep_one(self):
        path = os.path.join(_dir(), "audit.log")
        _plain_chain(2, path)
        log = broker.AuditLog(path)
        self.assertEqual(log.key_state(), "none_yet")
        d = log.verify_detail()
        self.assertTrue(d["ok"])
        self.assertIn("will be created", d["note"])
        self.assertNotIn("could not keep one", d["note"])
        self.assertIn("will be created", log.describe())

    def test_ensure_key_creates_once(self):
        log = broker.AuditLog(os.path.join(_dir(), "audit.log"))
        self.assertEqual(log.ensure_key()["state"], "created")
        self.assertEqual(log.key_state(), "present")
        self.assertEqual(log.ensure_key()["state"], "ready")

    def test_an_older_log_gets_its_marker_and_the_next_write_is_clean(self):
        path = os.path.join(_dir(), "audit.log")
        _plain_chain(2, path)
        log = broker.AuditLog(path)
        self.assertEqual(log.ensure_key()["state"], "created")
        self.assertEqual(_lines(path)[-1]["result"], "CHAIN-NOW-SIGNED")
        log.write(dict(ENTRY))
        self.assertIsNone(log.broken_reason())
        self.assertTrue(log.verify()[0])
        self.assertEqual(log.verify_detail()["mode"], "signed")

    def test_a_keychain_that_cannot_keep_a_key_still_says_so(self):
        log = broker.AuditLog(os.path.join(_dir(), "audit.log"))
        with mock.patch.object(broker.AuditLog, "_key_info", lambda self, create=False: (None, "unavailable")):
            self.assertEqual(log.key_state(), "unavailable")
            r = log.ensure_key()
        self.assertEqual(r["state"], "unavailable")
        self.assertIn("could not keep one", r["note"])

    def test_lost_key_is_not_called_a_changed_line(self):
        log = _log(3)
        os.remove(os.path.join(os.path.dirname(log.path), "integrity-audit.key"))
        d = log.verify_detail()
        self.assertFalse(d["ok"])
        self.assertNotIn("a line was changed", d["reason"])
        self.assertIn("key", d["reason"])
        log.write(dict(ENTRY))                    # a new key is made; the old entries cannot be checked
        reason = log.broken_reason()
        self.assertIn("signing key was lost", reason)
        self.assertIn("audit reset", reason)
        self.assertFalse(log.verify()[0])
        kept = log.reset()                        # the way out keeps the old file
        self.assertTrue(os.path.exists(kept))
        log.write(dict(ENTRY))
        self.assertTrue(log.verify()[0])


class QuickWrites(unittest.TestCase):
    def test_a_write_does_not_read_the_whole_log(self):
        log = _log(6)
        with mock.patch.object(broker.AuditLog, "_scan_full", side_effect=AssertionError("full scan")):
            log.write(dict(ENTRY))
            log.write(dict(ENTRY))
        self.assertTrue(log.verify()[0])
        self.assertEqual(log.verify()[1], 8)

    def test_cutting_off_the_end_is_seen_by_the_next_write(self):
        log = _log(5)
        with open(log.path, "rb") as f:
            lines = f.read().splitlines(keepends=True)
        with open(log.path, "wb") as f:
            f.write(b"".join(lines[:-1]))
        log.write(dict(ENTRY))
        self.assertIsNotNone(log.broken_reason())
        self.assertFalse(log.verify()[0])

    def test_cutting_out_a_line_at_the_front_is_seen_by_the_next_write(self):
        log = _log(5)
        with open(log.path, "rb") as f:
            lines = f.read().splitlines(keepends=True)
        with open(log.path, "wb") as f:
            f.write(b"".join(lines[1:]))
        log.write(dict(ENTRY))
        self.assertIsNotNone(log.broken_reason())

    def test_deleting_the_end_marker_is_seen_by_the_next_write(self):
        log = _log(4)
        os.remove(log.anchor_path)
        log.write(dict(ENTRY))
        self.assertIsNotNone(log.broken_reason())
        self.assertFalse(log.verify()[0])

    def test_a_same_length_edit_in_the_middle_is_found_by_verify(self):
        log = _log(6)
        with open(log.path, "rb") as f:
            raw = f.read()
        with open(log.path, "wb") as f:
            f.write(raw.replace(b'"host": "h"', b'"host": "x"', 1))
        log.write(dict(ENTRY))                    # a write only re-reads the end
        self.assertFalse(log.verify()[0])         # the full check does not miss it

    def test_stats_are_cheap_and_plain(self):
        log = _log(4)
        st = log.stats()
        self.assertEqual(st["entries"], 4)
        self.assertGreater(st["bytes"], 0)
        self.assertIsInstance(st["last_write"], int)
        self.assertEqual(st["rotated_files"], [])
        self.assertEqual(st["key"], "present")

    def test_a_busy_log_waits_then_says_so_plainly(self):
        log = _log(1)
        with broker._file_lock(log.path, timeout=5) as got:
            self.assertTrue(got)
            with mock.patch.object(broker, "LOCK_WAIT", 0.3):
                with self.assertRaises(broker.BrokerError) as ctx:
                    log.write(dict(ENTRY))
        self.assertIn("busy", str(ctx.exception))
        self.assertIn("try again", str(ctx.exception))


class MonthlyFiles(unittest.TestCase):
    def _two_months(self):
        log = broker.AuditLog(os.path.join(_dir(), "audit.log"))
        october = 1792000000          # 2026-10-14
        with mock.patch.object(broker.time, "time", return_value=october):
            for _ in range(3):
                log.write(dict(ENTRY))
        november = october + 40 * 86400
        with mock.patch.object(broker.time, "time", return_value=november):
            log.write(dict(ENTRY))
        return log

    def test_a_new_month_starts_a_new_file_that_still_chains(self):
        log = self._two_months()
        self.assertEqual(log.rotated_files(), ["audit.log.2026-10"])
        rows = _lines(log.path)
        self.assertEqual(rows[0]["result"], "LOG-ROTATED")
        self.assertEqual(rows[0]["rotated_file"], "audit.log.2026-10")
        d = log.verify_detail()
        self.assertTrue(d["ok"], d["reason"])
        self.assertEqual(d["rotated_files"], ["audit.log.2026-10"])
        log.write(dict(ENTRY))                    # and keeps going quickly
        self.assertTrue(log.verify()[0])
        self.assertEqual(log.stats()["rotated_files"], ["audit.log.2026-10"])

    def test_a_missing_or_changed_monthly_file_is_seen(self):
        log = self._two_months()
        old = log.path + ".2026-10"
        with open(old, "rb") as f:
            raw = f.read()
        with open(old, "wb") as f:
            f.write(raw.replace(b'"host": "h"', b'"host": "x"', 1))
        d = log.verify_detail()
        self.assertFalse(d["ok"])
        self.assertIn("monthly", d["reason"])
        os.remove(old)
        self.assertIn("missing", log.verify_detail()["reason"])


class KeyDatesFile(unittest.TestCase):
    def setUp(self):
        self.d = _dir()
        self.idx = os.path.join(self.d, "index.json")
        ledger.record(self.d, "svc", "env", index_path=self.idx)

    def test_removing_the_signature_and_editing_is_refused(self):
        doc = json.load(open(self.idx))
        proj = next(iter(doc["projects"]))
        doc.pop("sig")
        doc["projects"][proj]["svc"]["created_at"] = "1999-01-01T00:00:00+00:00"
        json.dump(doc, open(self.idx, "w"))
        with self.assertRaises(ledger.LedgerError) as ctx:
            ledger.load(self.idx)
        self.assertIn("lost its signature", str(ctx.exception))
        with mock.patch.object(sys, "stderr", io.StringIO()):
            ledger.record(self.d, "other", "env", index_path=self.idx)   # never re-signs it
        self.assertNotIn("sig", json.load(open(self.idx)))

    def test_a_lost_key_is_not_called_tampering(self):
        os.remove(os.path.join(self.d, "integrity-ledger.key"))
        with self.assertRaises(ledger.LedgerError) as ctx:
            ledger.load(self.idx)
        msg = str(ctx.exception)
        self.assertIn("gone from this computer", msg)
        self.assertNotIn("changed by something", msg)
        kept = ledger.reset(self.idx)            # the old file is kept, not deleted
        self.assertTrue(os.path.exists(kept))
        self.assertFalse(os.path.exists(self.idx))
        ledger.record(self.d, "svc", "env", index_path=self.idx)
        self.assertEqual(ledger.get(self.d, "svc", self.idx)["store"], "env")

    def test_a_signed_old_version_file_migrates_and_still_checks(self):
        with mock.patch.object(ledger, "CURRENT_VERSION", 2), \
                mock.patch.dict(ledger.MIGRATIONS, {1: ledger._v1_to_v2}):
            projects = ledger.load(self.idx)         # signed as version 1, read as 2
            self.assertEqual(next(iter(projects.values()))["svc"]["store"], "env")
            self.assertEqual(ledger._migrate({"version": 1, "projects": {}}, self.idx)["version"], 2)

    def test_the_v1_to_v2_skeleton_changes_nothing_yet(self):
        data = {"version": 1, "projects": {"p": {}}}
        self.assertEqual(ledger._v1_to_v2(data), data)

    def test_a_newer_format_is_a_plain_error(self):
        with self.assertRaises(OSError) as ctx:
            store.migrate_document({"schema_version": 9}, 2, {}, "This file", "x")
        self.assertIn("newer StuntKey", str(ctx.exception))
        with self.assertRaises(OSError) as ctx:
            store.migrate_document({}, 2, {}, "This file", "x")
        self.assertIn("old format", str(ctx.exception))
        out = store.migrate_document({"schema_version": 1}, 2, {1: lambda d: dict(d, a=1)}, "F")
        self.assertEqual((out["schema_version"], out["a"]), (2, 1))


class Recipes(unittest.TestCase):
    def _recipe(self):
        r = next(r for r in recipes.load_recipes().values() if r.get("_builtin"))
        return {k: v for k, v in r.items() if not k.startswith("_")}

    def test_save_goes_through_a_temporary_file_and_survives_a_failure(self):
        d, data = _dir(), self._recipe()
        path = recipes.save_recipe(data, d)
        first = open(path, "rb").read()
        with mock.patch.object(recipes.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                recipes.save_recipe(data, d)
        self.assertEqual(open(path, "rb").read(), first)
        self.assertEqual([n for n in os.listdir(d) if n.endswith(".tmp")], [])
        recipes.save_recipe(data, d)             # and a later save still works
        self.assertEqual(open(path, "rb").read(), first)

    def test_skipped_recipes_are_listed_for_doctor(self):
        d = _dir()
        open(os.path.join(d, "bad.json"), "w").write("{not json")
        with mock.patch.object(sys, "stderr", io.StringIO()):
            recipes.load_recipes(d)
        warnings = recipes.load_warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("bad.json", warnings[0])
        with mock.patch.object(sys, "stderr", io.StringIO()):
            recipes.load_recipes(_dir())
        self.assertEqual(recipes.load_warnings(), [])


class ConsentLock(unittest.TestCase):
    def test_a_lock_left_by_a_crashed_run_is_taken_over_quickly(self):
        folder = _dir()
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()
        lock = os.path.join(folder, ".lock")
        with open(lock, "w") as f:
            f.write(f"{gone.pid}\n")
        old = time.time() - 10
        os.utime(lock, (old, old))
        started = time.monotonic()
        with consent._FolderLock(folder):
            pass
        self.assertLess(time.monotonic() - started, 5)

    def test_a_lock_of_a_running_process_is_not_stale_until_it_is_old(self):
        folder = _dir()
        lock = os.path.join(folder, ".lock")
        with open(lock, "w") as f:
            f.write(f"{os.getpid()}\n")
        old = time.time() - 10
        os.utime(lock, (old, old))
        self.assertFalse(consent._lock_is_stale(lock, 180))
        older = time.time() - 400
        os.utime(lock, (older, older))
        self.assertTrue(consent._lock_is_stale(lock, 180))


class CloudPlaceholders(unittest.TestCase):
    ATTR_REPARSE, ATTR_FILE = 0x400, 0x20
    CLOUD_TAG = 0x9000601A         # a OneDrive placeholder

    def test_only_symlinks_and_junctions_count_as_links(self):
        self.assertTrue(store.reparse_is_link(self.ATTR_REPARSE, store.TAG_SYMLINK))
        self.assertTrue(store.reparse_is_link(self.ATTR_REPARSE, store.TAG_MOUNT_POINT))
        self.assertFalse(store.reparse_is_link(self.ATTR_REPARSE, self.CLOUD_TAG))
        self.assertFalse(store.reparse_is_link(self.ATTR_FILE, None))
        self.assertTrue(store.reparse_is_link(self.ATTR_REPARSE, None))     # unreadable: refuse

    def test_is_reparse_point_uses_the_tag(self):
        d = _dir()
        cloud = lambda p: (self.ATTR_REPARSE | self.ATTR_FILE, self.CLOUD_TAG)       # noqa: E731
        link = lambda p: (self.ATTR_REPARSE, store.TAG_SYMLINK)                       # noqa: E731
        self.assertFalse(store.is_reparse_point(d, read_attrs=cloud))
        self.assertTrue(store.is_reparse_point(d, read_attrs=link))
        self.assertFalse(store.is_reparse_point(d))


if __name__ == "__main__":
    unittest.main()
