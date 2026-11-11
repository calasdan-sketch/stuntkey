"""Round 11, core security: a signed (HMAC) activity log and key-dates file,
links/junctions refused, version check, safe test keychain, lock back-off.

Every test works in a throwaway folder with only synthetic keys."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from stuntkey import broker, keychain, ledger, remote, store

ENTRY = {"service": "t", "method": "GET", "host": "h", "path": "/p",
         "status": 200, "bytes": 1, "result": "ok", "ms": 1}
FAKE = "sk-FAKE-TEST-0000"


def _dir():
    return tempfile.mkdtemp(prefix="stuntkey-r11c-")


def _log(n=3, d=None):
    d = d or _dir()
    log = broker.AuditLog(os.path.join(d, "audit.log"))
    for _ in range(n):
        log.write(dict(ENTRY))
    return log


def _lines(path):
    with open(path, "rb") as f:
        return [json.loads(x) for x in f.read().splitlines()]


def _plain_chain(entries, path):
    """What 0.9.x wrote: SHA-256 chain, no key."""
    prev = "0" * 64
    out = []
    for i, e in enumerate(entries):
        e = dict(e, ts=1, prev=prev)
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


class SignedLog(unittest.TestCase):
    def test_entries_are_signed_and_verify(self):
        log = _log()
        rows = _lines(log.path)
        self.assertTrue(all(r.get("k") == 1 for r in rows))
        d = log.verify_detail()
        self.assertTrue(d["ok"])
        self.assertEqual(d["mode"], "signed")
        self.assertEqual(log.describe(), "")
        self.assertEqual(len(open(log.anchor_path).read().split()), 3)

    def test_rewriting_the_whole_log_without_the_key_is_seen(self):
        log = _log()
        rows = _lines(log.path)
        _plain_chain([{k: v for k, v in r.items() if k not in ("hash", "prev", "ts", "anchored", "k")}
                      for r in rows], log.path)
        self.assertFalse(log.verify()[0])

    def test_rewriting_log_and_head_in_plain_form_is_seen(self):
        log = _log()
        _plain_chain([dict(ENTRY)], log.path)           # log and .head both forged, plain
        self.assertFalse(log.verify()[0])

    def test_head_without_signature_is_seen(self):
        log = _log()
        n, h = open(log.anchor_path).read().split()[:2]
        with open(log.anchor_path, "w") as f:
            f.write(f"{n} {h}\n")
        self.assertFalse(log.verify()[0])

    def test_head_changed_or_deleted_is_seen(self):
        log = _log()
        n, h, mac = open(log.anchor_path).read().split()
        with open(log.anchor_path, "w") as f:
            f.write(f"{int(n) - 1} {h} {mac}\n")
        self.assertFalse(log.verify()[0])
        log2 = _log()
        os.remove(log2.anchor_path)
        self.assertFalse(log2.verify()[0])

    def test_deleting_the_broken_flag_does_not_heal_the_log(self):
        log = _log()
        rows = _lines(log.path)
        rows[1]["host"] = "evil"
        with open(log.path, "w") as f:
            f.write("\n".join(json.dumps(r) for r in rows) + "\n")
        log.write(dict(ENTRY))                           # notices, flags
        self.assertIsNotNone(log.broken_reason())
        os.remove(log.broken_path)
        self.assertFalse(log.verify()[0])
        log.write(dict(ENTRY))                           # re-flags
        self.assertIsNotNone(log.broken_reason())

    def test_flag_deleted_after_chain_got_a_problem_line(self):
        log = _log()
        with open(log.path, "ab") as f:                  # forged tail line
            f.write(b'{"forged": 1, "hash": "x", "prev": "y"}\n')
        log.write(dict(ENTRY))
        self.assertIsNotNone(log.broken_reason())
        self.assertFalse(log.verify()[0])

    def test_missing_key_is_a_problem_not_a_pass(self):
        log = _log()
        with mock.patch.object(broker.AuditLog, "_key", lambda self, create=False: None):
            self.assertFalse(log.verify()[0])


class OldLogsStillWork(unittest.TestCase):
    def test_old_plain_log_verifies_then_migrates_with_a_marker(self):
        d = _dir()
        path = os.path.join(d, "audit.log")
        _plain_chain([dict(ENTRY), dict(ENTRY)], path)
        log = broker.AuditLog(path)
        self.assertTrue(log.verify()[0])
        self.assertEqual(log.verify_detail()["mode"], "unkeyed")
        log.write(dict(ENTRY))
        rows = _lines(path)
        self.assertEqual([r.get("k") for r in rows], [None, None, 1, 1])
        self.assertEqual(rows[2]["result"], "CHAIN-NOW-SIGNED")
        self.assertTrue(log.verify()[0])
        self.assertEqual(log.verify_detail()["mode"], "signed")

    def test_old_part_is_still_protected_after_migration(self):
        d = _dir()
        path = os.path.join(d, "audit.log")
        _plain_chain([dict(ENTRY), dict(ENTRY)], path)
        log = broker.AuditLog(path)
        log.write(dict(ENTRY))
        rows = _lines(path)
        rows[0]["host"] = "evil"
        with open(path, "w") as f:
            f.write("\n".join(json.dumps(r) for r in rows) + "\n")
        self.assertFalse(log.verify()[0])


class Unkeyed(unittest.TestCase):
    def test_no_key_means_a_marker_and_a_visible_note(self):
        d = _dir()
        log = broker.AuditLog(os.path.join(d, "audit.log"))
        with mock.patch.object(broker.AuditLog, "_key", lambda self, create=False: None):
            log.write(dict(ENTRY))
            log.write(dict(ENTRY))
            rows = _lines(log.path)
            self.assertEqual(rows[0]["result"], "CHAIN-UNKEYED")
            self.assertEqual(sum(r["result"] == "CHAIN-UNKEYED" for r in rows), 1)
            detail = log.verify_detail()
        self.assertTrue(detail["ok"])
        self.assertEqual(detail["mode"], "unkeyed")
        self.assertIn("not signed", detail["note"])


class LinksAndJunctions(unittest.TestCase):
    def test_reparse_point_on_the_folder_is_refused(self):
        log = _log(1)
        with mock.patch.object(store, "is_reparse_point",
                               lambda p: os.path.abspath(p) == os.path.dirname(os.path.abspath(log.path))):
            with self.assertRaises(broker.BrokerError) as ctx:
                log.ready()
            self.assertIn("link", str(ctx.exception))

    def test_reparse_point_on_the_file_is_refused(self):
        log = _log(1)
        with mock.patch.object(store, "is_reparse_point", lambda p: p == log.path):
            with self.assertRaises(broker.BrokerError):
                log.ready()

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows thing")
    def test_a_real_junction_is_seen(self):
        base = _dir()
        target = os.path.join(base, "elsewhere")
        os.mkdir(target)
        junction = os.path.join(base, "dot")
        done = subprocess.run(["cmd", "/c", "mklink", "/J", junction, target],
                              capture_output=True)
        if done.returncode != 0:
            self.skipTest("cannot make a junction here")
        self.assertTrue(store.is_reparse_point(junction))
        self.assertIsNotNone(store.private_path_problem(os.path.join(junction, "audit.log")))
        with self.assertRaises(broker.BrokerError):
            broker.AuditLog(os.path.join(junction, "audit.log")).ready()

    def test_plain_folder_is_fine(self):
        d = _dir()
        self.assertFalse(store.is_reparse_point(d))
        self.assertIsNone(store.private_path_problem(os.path.join(d, "index.json")))

    def test_index_in_a_linked_folder_reads_as_empty_and_is_not_written(self):
        d = _dir()
        idx = os.path.join(d, "index.json")
        with mock.patch.object(store, "is_reparse_point", lambda p: True):
            self.assertEqual(ledger.load(idx), {})
            ledger.record(d, "svc", "env", index_path=idx)
        self.assertFalse(os.path.exists(idx))


class Ledger(unittest.TestCase):
    def setUp(self):
        self.d = _dir()
        self.idx = os.path.join(self.d, "index.json")

    def test_signed_on_write_and_reads_back(self):
        ledger.record(self.d, "svc", "env", index_path=self.idx)
        self.assertIn("sig", json.load(open(self.idx)))
        self.assertEqual(ledger.get(self.d, "svc", self.idx)["store"], "env")

    def test_tampered_signed_file_is_a_clear_error(self):
        ledger.record(self.d, "svc", "env", index_path=self.idx)
        doc = json.load(open(self.idx))
        proj = next(iter(doc["projects"]))
        doc["projects"][proj]["svc"]["created_at"] = "1999-01-01T00:00:00+00:00"
        json.dump(doc, open(self.idx, "w"))
        with self.assertRaises(ledger.LedgerError) as ctx:
            ledger.load(self.idx)
        msg = str(ctx.exception)
        self.assertIn("delete that file", msg)
        self.assertNotIn("Traceback", msg)
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            self.assertIsNone(ledger.get(self.d, "svc", self.idx))     # reads: words, no crash
            ledger.record(self.d, "other", "env", index_path=self.idx)  # never overwrites it
        self.assertIn("delete that file", err.getvalue())
        self.assertEqual(json.load(open(self.idx))["projects"][proj]["svc"]["created_at"][:4], "1999")

    def test_old_unsigned_file_is_accepted_once_then_signed(self):
        proj = ledger._project_key(self.d)
        json.dump({"version": 1, "projects": {proj: {"svc": {"created_at": "2026-01-01T00:00:00+00:00",
                                                           "store": "env"}}}}, open(self.idx, "w"))
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            self.assertEqual(ledger.get(self.d, "svc", self.idx)["store"], "env")
        self.assertIn("signed", err.getvalue())
        self.assertIn("sig", json.load(open(self.idx)))
        self.assertEqual(ledger.get(self.d, "svc", self.idx)["store"], "env")

    def test_newer_version_is_refused_in_plain_words_and_kept(self):
        raw = json.dumps({"version": 2, "projects": {}})
        open(self.idx, "w").write(raw)
        with self.assertRaises(ledger.LedgerError) as ctx:
            ledger.load(self.idx)
        self.assertIn("made by a newer StuntKey", str(ctx.exception))
        self.assertIn("pipx upgrade stuntkey", str(ctx.exception))
        with mock.patch.object(sys, "stderr", io.StringIO()):
            ledger.record(self.d, "svc", "env", index_path=self.idx)
        self.assertEqual(open(self.idx).read(), raw)

    def test_migration_hook_runs(self):
        open(self.idx, "w").write(json.dumps({"version": 1, "projects": {"p": {"s": {"store": "env"}}}}))
        with mock.patch.object(ledger, "CURRENT_VERSION", 2), \
                mock.patch.dict(ledger.MIGRATIONS, {1: lambda data: dict(data, migrated=True)}):
            self.assertEqual(ledger._migrate(json.load(open(self.idx)), self.idx)["version"], 2)
            self.assertTrue(ledger._migrate(json.load(open(self.idx)), self.idx)["migrated"])


class TestKeychain(unittest.TestCase):
    def test_env_wins_even_when_a_real_backend_is_named(self):
        class Boom:
            def __getattr__(self, name):
                raise AssertionError("the real keychain was touched")
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "memory"}):
            keychain._dispatch("store", keychain.WINDOWS, "svc-r11", "V", FAKE,
                               subprocess.run, Boom())
            self.assertEqual(keychain._dispatch("read", keychain.MACOS, "svc-r11", "V", None,
                                                subprocess.run, Boom()), FAKE)
            keychain._dispatch("delete", keychain.LINUX, "svc-r11", "V", None, subprocess.run, Boom())

    def test_file_backend_keeps_every_entry_under_contention(self):
        d = _dir()
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "file:" + d}):
            errors = []

            def put(i):
                try:
                    keychain._dispatch("store", keychain.TEST_FILE + d, f"s{i}", "V", FAKE + str(i),
                                       subprocess.run, None)
                except Exception as e:      # noqa: BLE001
                    errors.append(e)
            ts = [threading.Thread(target=put, args=(i,)) for i in range(8)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            self.assertEqual(errors, [])
            for i in range(8):
                self.assertEqual(keychain._dispatch("read", keychain.TEST_FILE + d, f"s{i}", "V",
                                                    None, subprocess.run, None), FAKE + str(i))
        left = [n for n in os.listdir(d) if n.endswith(".tmp")]
        self.assertEqual(left, [])
        json.load(open(os.path.join(d, "stuntkey-test-keychain.json")))

    def test_integrity_key_in_a_plain_folder_is_a_private_file(self):
        d = _dir()
        key, where = keychain.integrity_key(d, create=True)
        self.assertEqual(where, "file")
        self.assertEqual(len(key), 32)
        self.assertEqual(keychain.integrity_key(d)[0], key)
        self.assertNotEqual(keychain.integrity_key(d, create=True, purpose="ledger")[0], key)

    def test_integrity_key_for_the_real_home_uses_the_test_keychain_when_set(self):
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "memory"}):
            home = remote.home_dir()
            key, where = keychain.integrity_key(home, create=True)
            self.assertEqual(where, "keychain")
            self.assertEqual(keychain.read(keychain.INTEGRITY_SERVICE, "AUDIT_HMAC_KEY",
                                           keychain.TEST_MEMORY), key.hex())
            keychain._dispatch("delete", keychain.TEST_MEMORY, keychain.INTEGRITY_SERVICE,
                               "AUDIT_HMAC_KEY", None, subprocess.run, None)

    def test_test_run_never_writes_the_real_activity_log(self):
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "memory"}):
            real = os.path.join(remote.home_dir(), "audit.log")
            log = broker.AuditLog(real)
            self.assertNotEqual(os.path.normcase(log.path), os.path.normcase(real))
            log.write(dict(ENTRY))
            self.assertFalse(os.path.exists(real))
            self.assertTrue(log.verify()[0])
        d = _dir()
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "file:" + d}):
            log = broker.AuditLog(os.path.join(remote.home_dir(), "audit.log"))
            self.assertEqual(os.path.dirname(log.path), d)


class LockBackoff(unittest.TestCase):
    def test_backoff_grows_and_is_capped(self):
        steps = [store._backoff(i) for i in range(12)]
        self.assertEqual(steps, sorted(steps))
        self.assertLessEqual(max(steps), 0.4)
        self.assertLess(steps[0], steps[5])

    def test_busy_message_is_plain(self):
        text = str(store.EnvFileBusy("x"))
        self.assertIn("antivirus", text)
        self.assertIn("try again", text)

    def test_waits_for_a_short_hold_then_gets_the_lock(self):
        path = os.path.join(_dir(), "f.txt")
        held = threading.Event()

        def hold():
            with store.file_lock(path):
                held.set()
                time.sleep(0.5)
        t = threading.Thread(target=hold)
        t.start()
        held.wait(5)
        start = time.monotonic()
        with store.file_lock(path, timeout=10):
            waited = time.monotonic() - start
        t.join()
        self.assertGreater(waited, 0.2)

    def test_gives_up_with_the_plain_error(self):
        path = os.path.join(_dir(), "f.txt")
        held, done = threading.Event(), threading.Event()

        def hold():
            with store.file_lock(path):
                held.set()
                done.wait(10)
        t = threading.Thread(target=hold)
        t.start()
        held.wait(5)
        try:
            with self.assertRaises(store.EnvFileBusy):
                with store.file_lock(path, timeout=0.4):
                    pass
        finally:
            done.set()
            t.join()


if __name__ == "__main__":
    unittest.main()
