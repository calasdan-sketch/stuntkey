"""Round 13, infrastructure and reliability: a log cut off by a power loss, an
anchor file that survives a crash, a clock set back, key dates that cannot be
read, Windows Credential Manager failures in plain words, stale temp files.

Every test works in a throwaway folder with synthetic keys only; nothing here
reaches the real keychain, the real log or a real pop-up."""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401  (points HOME and friends at a throwaway folder)
from stuntkey import broker, keychain, ledger, store

ENTRY = {"service": "t", "method": "GET", "host": "h", "path": "/p",
         "status": 200, "bytes": 1, "result": "ok", "ms": 1}


def _dir():
    return tempfile.mkdtemp(prefix="stuntkey-r13i-")


def _log(n=3):
    log = broker.AuditLog(os.path.join(_dir(), "audit.log"))
    for _ in range(n):
        log.write(dict(ENTRY))
    return log


def _lines(path):
    with open(path, "rb") as f:
        return [json.loads(x) for x in f.read().splitlines()]


class TestTornTail(unittest.TestCase):
    def test_half_a_line_does_not_make_the_log_look_tampered(self):
        log = _log(3)
        with open(log.path, "ab") as f:
            f.write(b'{"service": "x", "method": "GE')       # power loss mid-write
        self.assertTrue(log._torn())
        log.write(dict(ENTRY))
        ok, n = log.verify()
        self.assertTrue(ok, log.verify_detail())
        self.assertIsNone(log.broken_reason())
        self.assertFalse(log._torn())
        results = [e["result"] for e in _lines(log.path)]
        self.assertIn("LOG-TAIL-REPAIRED", results)
        self.assertEqual(n, len(results))

    def test_the_fragment_is_kept_as_evidence(self):
        log = _log(2)
        with open(log.path, "ab") as f:
            f.write(b'{"half": ')
        log.write(dict(ENTRY))
        kept = [n for n in os.listdir(os.path.dirname(log.path)) if ".torn-" in n]
        self.assertEqual(len(kept), 1)
        with open(os.path.join(os.path.dirname(log.path), kept[0]), "rb") as f:
            self.assertEqual(f.read(), b'{"half": ')

    def test_a_cut_that_hides_a_real_entry_is_still_caught(self):
        log = _log(3)
        with open(log.path, "rb") as f:
            data = f.read()
        with open(log.path, "wb") as f:
            f.write(data[:-1])          # only the last newline removed: entry 3 looks torn
        log.write(dict(ENTRY))
        ok, _n = log.verify()
        self.assertFalse(ok)            # the end marker still says three entries

    def test_ensure_key_repairs_too(self):
        log = _log(2)
        with open(log.path, "ab") as f:
            f.write(b"{")
        log.ensure_key()
        self.assertFalse(log._torn())
        self.assertTrue(log.verify()[0])

    def test_verify_says_when_the_end_is_torn(self):
        log = _log(2)
        with open(log.path, "ab") as f:
            f.write(b"{")
        self.assertTrue(log.verify_detail()["torn_tail"])


class TestAnchorSurvivesCrash(unittest.TestCase):
    def test_the_end_marker_is_flushed_to_disk(self):
        log = _log(1)
        with mock.patch.object(os, "fsync", wraps=os.fsync) as fs:
            log._save_anchor(1, "0" * 64)
        self.assertGreaterEqual(fs.call_count, 1)

    def test_a_failed_anchor_save_leaves_no_temp_file(self):
        log = _log(1)
        with mock.patch.object(store, "_replace", side_effect=OSError(5, "no")):
            log._save_anchor(1, "0" * 64)
        self.assertFalse(os.path.exists(log.anchor_path + ".tmp"))


class TestClockSetBack(unittest.TestCase):
    def test_a_clock_set_back_does_not_file_the_log_away(self):
        d = _dir()
        log = broker.AuditLog(os.path.join(d, "audit.log"))
        future = time.time() + 70 * 86400
        with mock.patch.object(time, "time", return_value=future):
            log.write(dict(ENTRY))
            log.write(dict(ENTRY))
        log.write(dict(ENTRY))          # the real (earlier) time again
        self.assertEqual(log.rotated_files(), [])
        self.assertTrue(log.verify()[0])


class TestLedgerKeepsWhatItCannotRead(unittest.TestCase):
    def test_a_cut_off_file_is_moved_aside_not_overwritten(self):
        d = _dir()
        index = os.path.join(d, "index.json")
        with open(index, "w", encoding="utf-8") as f:
            f.write('{"version": 1, "projects": {"C:/p": {"acme": {"crea')
        project = os.path.join(d, "proj")
        os.makedirs(project)
        with mock.patch("sys.stderr"):
            ledger.record(project, "acme", "env", index_path=index)
        kept = [n for n in os.listdir(d) if ".unreadable-" in n]
        self.assertEqual(len(kept), 1)
        with open(os.path.join(d, kept[0]), encoding="utf-8") as f:
            self.assertIn('"crea', f.read())
        self.assertIsNotNone(ledger.get(project, "acme", index_path=index))

    def test_an_empty_file_is_just_replaced(self):
        d = _dir()
        index = os.path.join(d, "index.json")
        open(index, "w").close()
        ledger.record(d, "acme", "env", index_path=index)
        self.assertEqual([n for n in os.listdir(d) if ".unreadable-" in n], [])


def _fake_ct(read_ok=True, last_error=5, blob=b"", write_ok=True):
    import ctypes
    import ctypes.wintypes  # noqa: F401
    import types
    keep = []
    refs = []

    class Adv:
        @staticmethod
        def CredWriteW(ref, flags):
            return 1 if write_ok else 0

        @staticmethod
        def CredReadW(target, ctype, flags, pref):
            if not read_ok:
                return 0
            pcred = refs[-1]
            cred = pcred._type_()
            buf = ctypes.create_string_buffer(blob, len(blob))
            keep.extend([buf, cred])
            cred.CredentialBlobSize = len(blob)
            cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
            pcred.contents = cred
            return 1

        @staticmethod
        def CredFree(p):
            return None

        @staticmethod
        def CredDeleteW(target, ctype, flags):
            return 0

    ct = types.SimpleNamespace(
        Structure=ctypes.Structure, POINTER=ctypes.POINTER, c_ubyte=ctypes.c_ubyte,
        c_void_p=ctypes.c_void_p, create_string_buffer=ctypes.create_string_buffer,
        cast=ctypes.cast, string_at=ctypes.string_at, wintypes=ctypes.wintypes,
        windll=types.SimpleNamespace(advapi32=Adv), GetLastError=lambda: last_error)

    def byref(obj):
        refs.append(obj)
        return ctypes.byref(obj)
    ct.byref = byref
    return ct


class TestWindowsCredentialManagerWords(unittest.TestCase):
    def _run(self, op, **kw):
        ct = _fake_ct(**kw)
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": ""}):
            return keychain._windows(op, "acme", "ACME_API_KEY",
                                     "k" if op == "store" else None, ct)

    def test_an_entry_in_another_format_is_not_a_traceback(self):
        with self.assertRaises(keychain.KeychainError) as cm:
            self._run("read", blob=b"abc")          # odd length: not UTF-16
        self.assertIn("not in a format", str(cm.exception))

    def test_no_logon_session_is_unavailable_not_not_stored(self):
        with self.assertRaises(keychain.KeychainUnavailable) as cm:
            self._run("read", read_ok=False, last_error=1312)
        self.assertIn("service", str(cm.exception))

    def test_a_plain_miss_is_still_none(self):
        self.assertIsNone(self._run("read", read_ok=False, last_error=1168))

    def test_a_failed_write_says_why_in_words(self):
        with self.assertRaises(keychain.KeychainError) as cm:
            self._run("store", write_ok=False, last_error=1312)
        self.assertNotIn("CredWriteW", str(cm.exception))
        self.assertIn(".env", str(cm.exception))

    def test_a_failed_delete_with_no_logon_session_raises(self):
        with self.assertRaises(keychain.KeychainUnavailable):
            self._run("delete", last_error=1312)

    def test_a_very_long_variable_name_is_refused_in_words(self):
        ct = _fake_ct()
        with self.assertRaises(keychain.KeychainError):
            keychain._windows("store", "acme", "V" * 600, "k", ct)


class TestHomeFolder(unittest.TestCase):
    def test_a_profile_with_no_home_does_not_make_a_folder_called_tilde(self):
        from stuntkey import remote
        appdata = os.path.abspath(_dir())
        with mock.patch("os.path.expanduser", return_value="~"), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": appdata}):
            self.assertEqual(remote.home_dir(), os.path.join(appdata, ".stuntkey"))
            self.assertEqual(ledger.path(), os.path.join(appdata, ".stuntkey", "index.json"))
            self.assertEqual(broker.Policy().limits_home(), os.path.join(appdata, ".stuntkey"))

    def test_a_normal_home_is_used_as_before(self):
        from stuntkey import remote
        home = os.path.abspath(_dir())
        with mock.patch("os.path.expanduser", return_value=home):
            self.assertEqual(remote.home_dir(), os.path.join(home, ".stuntkey"))

    def test_remembering_two_hosts_at_once_keeps_both(self):
        from stuntkey import remote
        home = os.path.abspath(_dir())
        with mock.patch("os.path.expanduser", return_value=home):
            threads = [threading.Thread(target=remote.remember_host, args=(f"u@h{i}", "acme"))
                       for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(remote.known_hosts()), 8)


class TestStaleTempFiles(unittest.TestCase):
    def test_an_old_leftover_is_removed_and_a_fresh_one_kept(self):
        d = _dir()
        old = os.path.join(d, "..env.abc123.tmp")
        new = os.path.join(d, "..env.def456.tmp")
        other = os.path.join(d, "..other.xyz.tmp")
        for p in (old, new, other):
            open(p, "w").close()
        past = time.time() - 2 * store.STALE_TEMP_SECONDS
        os.utime(old, (past, past))
        os.utime(other, (past, past))
        store.write_private(os.path.join(d, ".env"), "A=1\n")
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new))
        self.assertTrue(os.path.exists(other))      # another file's: never touched


class TestTornTailBytes(unittest.TestCase):
    def test_a_fragment_that_is_not_text_is_kept_byte_for_byte(self):
        log = _log(2)
        frag = b'{"a": "\xff\xfe\x80'
        with open(log.path, "ab") as f:
            f.write(frag)
        log.write(dict(ENTRY))
        folder = os.path.dirname(log.path)
        name = [n for n in os.listdir(folder) if ".torn-" in n][0]
        with open(os.path.join(folder, name), "rb") as f:
            self.assertEqual(f.read(), frag)
        self.assertTrue(log.verify()[0])


import io  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import threading  # noqa: E402
import types  # noqa: E402
import urllib.error  # noqa: E402
import http.client  # noqa: E402

from stuntkey import httpd, mcp, proxy  # noqa: E402


class TestRequestBodies(unittest.TestCase):
    def test_a_body_that_dribbles_in_is_cut_off(self):
        class Slow:
            def read1(self, n):
                return b"x"
        with self.assertRaises(broker.BrokerError) as cm:
            proxy.read_body(Slow(), 1000, seconds=-1)
        self.assertIn("too slowly", str(cm.exception))

    def test_a_body_that_ends_early_is_refused(self):
        with self.assertRaises(broker.BrokerError) as cm:
            proxy.read_body(io.BytesIO(b"abc"), 10)
        self.assertIn("ended early", str(cm.exception))

    def test_a_whole_body_is_read(self):
        self.assertEqual(proxy.read_body(io.BytesIO(b"x" * 200000), 200000), b"x" * 200000)

    def test_a_socket_timeout_is_a_refusal_not_a_traceback(self):
        class Dead:
            def read1(self, n):
                raise socket.timeout("timed out")
        with self.assertRaises(broker.BrokerError):
            proxy.read_body(Dead(), 5)


class _Conn:
    """A stand-in connection: fails with `error` the first `fails` times."""
    made = []

    def __init__(self, error, fails):
        self.error, self.fails, self.closed = error, fails, False

    def request(self, *a, **k):
        _Conn.made.append(self)
        if len([c for c in _Conn.made if c.error is self.error]) <= self.fails:
            raise self.error

    def getresponse(self):
        return "RESPONSE"

    def close(self):
        self.closed = True


class TestRetries(unittest.TestCase):
    def setUp(self):
        _Conn.made = []
        p = mock.patch.object(time, "sleep")
        p.start()
        self.addCleanup(p.stop)

    def _open(self, method, error, fails=1):
        connect = lambda host, timeout: _Conn(error, fails)  # noqa: E731
        return broker.open_stream("h", "1.2.3.4", method, "/", {}, None, 5, connect)

    def test_a_read_is_tried_again_after_a_dropped_connection(self):
        conn, resp = self._open("GET", ConnectionResetError("reset"))
        self.assertEqual(resp, "RESPONSE")
        self.assertEqual(len(_Conn.made), 2)

    def test_a_write_is_never_tried_again(self):
        with self.assertRaises(broker.BrokerError):
            self._open("POST", ConnectionResetError("reset"))
        self.assertEqual(len(_Conn.made), 1)

    def test_a_timeout_is_not_tried_again(self):
        with self.assertRaises(broker.BrokerError) as cm:
            self._open("GET", socket.timeout("slow"))
        self.assertEqual(len(_Conn.made), 1)
        self.assertIn("did not answer in time", str(cm.exception))

    def test_a_certificate_problem_is_never_tried_again_and_says_why(self):
        with self.assertRaises(broker.BrokerError) as cm:
            self._open("GET", ssl.SSLCertVerificationError("bad"))
        self.assertEqual(len(_Conn.made), 1)
        self.assertIn("certificate", str(cm.exception))
        self.assertIn("firewall", str(cm.exception))

    def test_the_plain_words(self):
        w = broker._net_words
        self.assertIn("looked up", w(urllib.error.URLError(socket.gaierror(11001, "x"))))
        self.assertIn("refused", w(ConnectionRefusedError()))
        self.assertIn("dropped", w(ConnectionAbortedError()))
        self.assertEqual(w(OSError("x")), "network error talking to the API")

    def test_real_send_retries_a_read_only(self):
        calls = []

        class Resp:
            status = 200
            headers = {"Content-Type": "text/plain"}

            def read(self, n):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class Opener:
            def open(self, req, timeout=None):
                calls.append(req.get_method())
                if len(calls) == 1:
                    raise urllib.error.URLError(ConnectionResetError("reset"))
                return Resp()

        for method, expect_calls in (("GET", 2), ("POST", 1)):
            calls.clear()
            req = types.SimpleNamespace(get_method=lambda m=method: m)
            with mock.patch("urllib.request.build_opener", return_value=Opener()):
                if method == "GET":
                    status, _h, body = broker._real_send(req, "1.2.3.4", 5)
                    self.assertEqual((status, body), (200, b"ok"))
                else:
                    with self.assertRaises(broker.BrokerError):
                        broker._real_send(req, "1.2.3.4", 5)
            self.assertEqual(len(calls), expect_calls)


class TestProxyFraming(unittest.TestCase):
    TOKEN = "ok-r13-token-0000000000000000"

    def setUp(self):
        from stuntkey import approve, recipes
        os.environ["STUNTKEY_KEYCHAIN"] = "memory"

        def real_window(*a, **k):
            raise AssertionError("a REAL approval window was requested")
        for name in ("dialog", "console"):
            p = mock.patch.object(approve, name, real_window)
            p.start()
            self.addCleanup(p.stop)
        catalog = recipes.load_recipes()
        self.reached = []

        def connect(host, timeout):
            self.reached.append(host)
            raise AssertionError("the request must not reach the upstream")
        home = _dir()
        pol = broker.Policy(home=home, project_dir=home, max_calls=50, approve=None)
        self.srv = proxy.make_proxy(
            catalog, lambda r: {recipes.env_vars(r)[0]: "sk-" + "FAKE0000R13CANARY1111abcd"},
            self.TOKEN, pol, broker.AuditLog(os.path.join(home, "audit.log")),
            resolver=lambda h, p, **k: [(2, 1, 6, "", ("104.18.6.192", p))], connect=connect)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.port = self.srv.server_address[1]

    def _raw(self, extra, body=b""):
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        s.settimeout(5)
        head = (f"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                f"Authorization: Bearer {self.TOKEN}\r\nContent-Type: application/json\r\n"
                f"{extra}\r\n").encode()
        s.sendall(head + body)
        s.shutdown(socket.SHUT_WR)          # nothing more is coming: the server need not wait
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
        return data

    def test_a_chunked_body_is_refused_in_words(self):
        out = self._raw("Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n")
        self.assertIn(b"403", out.split(b"\r\n")[0])
        self.assertIn(b"Content-Length", out)
        self.assertEqual(self.reached, [])

    def test_two_different_lengths_are_refused(self):
        out = self._raw("Content-Length: 5\r\nContent-Length: 50\r\n", b"hello")
        self.assertIn(b"403", out.split(b"\r\n")[0])
        self.assertIn(b"two different lengths", out)
        self.assertEqual(self.reached, [])

    def test_a_body_shorter_than_its_length_is_refused(self):
        out = self._raw("Content-Length: 500\r\nConnection: close\r\n", b'{"a":1}')
        # the client half-closes: nothing more is coming
        self.assertEqual(self.reached, [])
        self.assertTrue(out == b"" or b"403" in out.split(b"\r\n")[0])


class TestMcpWire(unittest.TestCase):
    PING = b'{"jsonrpc":"2.0","id":7,"method":"tools/list"}\n'

    def _serve(self, data, writer=None, max_line=None):
        out = writer or io.BytesIO()
        with mock.patch.object(mcp, "MAX_LINE", max_line or mcp.MAX_LINE):
            code = mcp._serve({}, None, io.BytesIO(data), out)
        return code, out

    def test_a_byte_order_mark_from_a_shell_is_ignored(self):
        code, out = self._serve(b"\xef\xbb\xbf" + self.PING)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue().splitlines()[0])["id"], 7)

    def test_a_huge_line_is_refused_not_stored_and_the_next_one_is_served(self):
        code, out = self._serve(b"x" * 5000 + b"\n" + self.PING, max_line=200)
        replies = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(replies[0]["error"]["code"], mcp.INVALID_REQUEST)
        self.assertEqual(replies[1]["id"], 7)

    def test_a_huge_line_with_no_newline_at_the_end_still_ends(self):
        code, out = self._serve(b"y" * 5000, max_line=200)
        self.assertEqual(code, 0)

    def test_a_closed_pipe_ends_the_server_quietly(self):
        class Gone(io.BytesIO):
            def write(self, b):
                raise BrokenPipeError(32, "pipe closed")
        code, _ = self._serve(self.PING * 3, writer=Gone())
        self.assertEqual(code, 0)

    def test_a_read_error_is_the_end_of_input(self):
        class Bad(io.BytesIO):
            def readline(self, *a):
                raise OSError(22, "bad pipe")
        with mock.patch.object(mcp, "_serve", wraps=mcp._serve):
            self.assertEqual(mcp._serve({}, None, Bad(), io.BytesIO()), 0)


class TestDoor(unittest.TestCase):
    def test_every_server_agrees_on_one_token(self):
        path = os.path.join(_dir(), "token")
        got = []
        threads = [threading.Thread(target=lambda: got.append(httpd.load_or_make_token(path)))
                   for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(got)), 1)
        self.assertGreaterEqual(len(got[0]), 40)
        with open(path, encoding="ascii") as f:
            self.assertEqual(f.read().strip(), got[0])

    def test_a_cut_off_token_file_is_replaced(self):
        path = os.path.join(_dir(), "token")
        with open(path, "w") as f:
            f.write("abc")
        tok = httpd.load_or_make_token(path)
        self.assertGreaterEqual(len(tok), 40)

    def test_too_many_connections_get_a_plain_busy_answer(self):
        release = threading.Event()

        class Hold(httpd.BaseHTTPRequestHandler):
            timeout = 5

            def do_GET(self):
                release.wait(5)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        class Small(httpd.DoorServer):
            MAX_CONNECTIONS = 2
        srv = Small(("127.0.0.1", 0), Hold)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.addCleanup(release.set)
        port = srv.server_address[1]
        held = []
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", port), 5)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            held.append(s)
        time.sleep(0.3)
        third = socket.create_connection(("127.0.0.1", port), 5)
        third.settimeout(5)
        self.assertIn(b"503", third.recv(100))
        third.close()
        release.set()
        for s in held:
            s.close()
        time.sleep(0.3)
        fourth = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        fourth.request("GET", "/")
        self.assertEqual(fourth.getresponse().status, 200)     # the slots came back

    def test_a_stop_request_ends_serve_forever_like_ctrl_c(self):
        import signal
        before = signal.getsignal(signal.SIGTERM)
        restore = httpd._stop_on_signals()
        try:
            self.assertNotEqual(signal.getsignal(signal.SIGTERM), before)
            with self.assertRaises(KeyboardInterrupt):
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        finally:
            restore()
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)


if __name__ == "__main__":
    unittest.main()
