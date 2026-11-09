"""Hide secrets in anything an AI is about to read.

A key can come back in a program's output or an API response in more than
one shape: as it is, URL-encoded, base64 (at any of three alignments),
hex, JSON-escaped, or backwards. `Scrubber` removes all of them, also when a
key is split across two chunks of a stream. Best effort, and said so: it
cannot catch a secret an API transforms in some way we did not think of.
"""
from __future__ import annotations

import base64
import contextlib
import hmac
import json
import os
import re
import secrets as secrets_mod
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote, quote_plus

REDACTED = b"[REDACTED]"
MIN_LEN = 6          # shorter "secrets" would mangle ordinary text
MIN_B64 = 8          # a base64 piece shorter than this is left alone


def _b64_pieces(raw: bytes) -> set[bytes]:
    """The base64 text of `raw` as it can sit inside a longer base64 string:
    only the characters that depend on `raw` alone, at each of the three
    alignments (k bytes before it), standard and URL-safe. At alignment 0
    also the whole encoding, padded and not (`raw` encoded on its own)."""
    out: set[bytes] = set()
    for k in (0, 1, 2):
        first, last = -(-8 * k // 6), 8 * (k + len(raw)) // 6
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            whole = enc(b"x" * k + raw)
            out.add(whole[first:last])
            if k == 0:
                out.update((whole, whole.rstrip(b"=")))
    return {p for p in out if len(p) >= MIN_B64}


def forms(secret: str) -> list[bytes]:
    """Every byte-string we will remove for this secret, longest first: as
    it is, reversed, upper / lower case, UTF-16, URL-encoded, JSON-escaped,
    hex and base64."""
    if len(secret) < MIN_LEN:
        return []
    raw = secret.encode("utf-8", "surrogateescape")
    out: set[bytes] = {raw, raw[::-1]}
    for alt in (secret.lower(), secret.upper()):
        out.add(alt.encode("utf-8", "surrogateescape"))
    if secret.isascii():
        out.add(secret.encode("utf-16-le"))
    for text in (quote(secret, safe=""), quote_plus(secret),
                 json.dumps(secret)[1:-1]):
        out.add(text.encode("utf-8"))
    out.add(json.dumps(secret, ensure_ascii=False)[1:-1].encode("utf-8", "surrogateescape"))
    out.add(raw.hex().encode())
    out.add(raw.hex().upper().encode())
    out |= _b64_pieces(raw)
    return sorted((f for f in out if len(f) >= MIN_LEN),
                  key=len, reverse=True)


class Scrubber:
    """Streaming remover. feed() returns bytes that are safe to show; flush()
    at the end. A secret split across two chunks is still caught: text at
    the end of a chunk that could be the START of a form is held back until
    the next feed() (ordinary output is never delayed). `hits` counts what
    was removed. Also exported as redact.Redactor."""

    def __init__(self, secrets):
        found: set[bytes] = set()
        for s in secrets:
            found.update(forms(s))
        # longest first, so a long form is not half-replaced by a short one
        self._forms = sorted(found, key=len, reverse=True)
        self._hold = max((len(f) for f in self._forms), default=1) - 1
        self._prefixes = {f[:k] for f in self._forms for k in range(1, len(f))}
        self._buf = b""
        self.hits = 0

    def _clean(self, data: bytes) -> bytes:
        for f in self._forms:
            if f in data:
                self.hits += data.count(f)
                data = data.replace(f, REDACTED)
        return data

    def feed(self, chunk: bytes) -> bytes:
        if not self._forms:
            return chunk
        data = self._clean(self._buf + chunk)
        keep = 0
        for k in range(min(self._hold, len(data)), 0, -1):
            if data[-k:] in self._prefixes:
                keep = k
                break
        self._buf = data[len(data) - keep:] if keep else b""
        return data[:len(data) - keep]

    def flush(self) -> bytes:
        data, self._buf = self._clean(self._buf), b""
        return data

    def text(self, s: str) -> str:
        """One-shot scrub of a string (messages, logs); the stream is untouched."""
        return self._clean(s.encode("utf-8", "surrogateescape")).decode("utf-8", "replace")


def scrub_text(text: str, secrets) -> str:
    return Scrubber(secrets).text(text)


def _pump(src, dst, scrubber: Scrubber) -> None:
    try:
        while True:
            chunk = src.read1(8192) if hasattr(src, "read1") else src.read(8192)
            if not chunk:
                break
            dst.write(scrubber.feed(chunk))
            dst.flush()
        dst.write(scrubber.flush())
        dst.flush()
    except (OSError, ValueError):
        pass


def run_scrubbed(cmd, env, secrets, out=None, err=None) -> int:
    """Like subprocess.call, but the child's stdout and stderr go through
    a Scrubber before anyone (an AI) can read them."""
    out = out or sys.stdout.buffer
    err = err or sys.stderr.buffer
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    threads = [threading.Thread(target=_pump, args=(proc.stdout, out,
                                                    Scrubber(secrets))),
               threading.Thread(target=_pump, args=(proc.stderr, err,
                                                    Scrubber(secrets)))]
    for t in threads:
        t.start()
    try:
        status = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        status = proc.wait()
    for t in threads:
        t.join()
    return status


# ---- fail-closed second check ---------------------------------------------------------

def _normalize(text: str) -> str:
    """Undo the common disguises: whitespace splits, escaped slashes,
    unicode escapes, percent-encoding (any case, repeated), HTML entities."""
    import html
    import re
    from urllib.parse import unquote
    t = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    t = t.replace("\\/", "/")
    for _ in range(3):
        nxt = html.unescape(unquote(t))
        if nxt == t:
            break
        t = nxt
    return re.sub(r"\s+", "", t)


def _squash(text: str) -> str:
    """Only letters and digits, lower case. Defeats dashes, dots, zero-width
    characters, NUL bytes (UTF-16 text), accents and upper/lower-case games."""
    import re
    import unicodedata
    t = unicodedata.normalize("NFKD", text.replace("\x00", ""))
    return re.sub(r"[^0-9a-z]", "", t.lower())


def _extra_forms(secret: str) -> list[str]:
    import base64
    import codecs
    raw = secret.encode("utf-8")
    out = [codecs.encode(secret, "rot13")]
    out.append(base64.b32encode(raw).decode().rstrip("="))
    out.append(base64.b32hexencode(raw).decode().rstrip("="))
    out.append(base64.b85encode(raw).decode())
    out.append(base64.a85encode(raw).decode())
    return out


PARTIAL_RUN = 32     # letters and digits of a secret in a row that count as a leak
PARTIAL_OFFSETS = 64  # most start offsets tried per secret, whatever its length


def loosely_contains(text: str, secrets) -> bool:
    """True if, after undoing common disguises, any secret (in a plain,
    base64 or hex form) is still in the text. The caller then withholds the
    whole text instead of trying to patch it.

    A long enough PIECE of a secret counts too: an API that echoes half a key
    has still given most of it away, and Scrubber only removes whole forms. The
    run must be PARTIAL_RUN characters, far longer than the 6 to 12 character
    hint vendors show on purpose ("sk-...Zk"), so a key hint does not trip it."""
    text = text.replace("\x00", "")
    norm = _normalize(text)
    squashed = _squash(norm)
    for s in secrets:
        if len(s) < MIN_LEN:
            continue
        whole = _squash(s)
        if len(whole) > PARTIAL_RUN:
            # Every start offset for a key of ordinary length (step stays 1
            # below ~2 kB), but never more than PARTIAL_OFFSETS searches over a
            # body the other end chose: a very long secret must not turn one
            # reply into minutes of scanning. A bigger step only means a run
            # has to be that much longer than PARTIAL_RUN to be noticed.
            span = len(whole) - PARTIAL_RUN + 1
            step = max(1, -(-span // PARTIAL_OFFSETS))
            if any(whole[i:i + PARTIAL_RUN] in squashed
                   for i in range(0, span, step)):
                return True
        for f in forms(s):
            try:
                needle = _normalize(f.decode("utf-8"))
            except UnicodeDecodeError:
                continue
            if len(needle) >= MIN_LEN and needle in norm:
                return True
            sq = _squash(needle)
            if len(sq) >= 14 and sq in squashed:
                return True
        for extra in _extra_forms(s):
            sq = _squash(extra)
            if len(sq) >= 14 and sq in squashed:
                return True
    return False


# ---- what the PostToolUse hook masks in tool output -------------------------------
#
# The hook runs once per tool call and must not load every stored key in
# plain text to do it. Instead ~/.stuntkey/fingerprints.json keeps, for each
# stored key, HMAC-SHA256(salt, form) of a few whole-word forms of it (as it
# is, URL-encoded, base64) under a random local salt. A word in the output is
# masked when its HMAC is one of them. On top of that, any text in a known
# key format (scan.py's patterns) is masked whether or not it is stored.

FINGERPRINT_FILE = "fingerprints.json"
MAX_WORD = 512
_WORD_RE = re.compile(r"[^\s\"'`,;()\[\]{}<>|&\\]{%d,%d}" % (MIN_LEN, MAX_WORD))


def fingerprint_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey", FINGERPRINT_FILE)


def _fingerprint_forms(secret: str) -> set[str]:
    raw = secret.encode("utf-8", "surrogateescape")
    return {secret, quote(secret, safe=""), base64.b64encode(raw).decode(),
            base64.b64encode(raw).decode().rstrip("=")}


def _fp(salt: bytes, word: str) -> str:
    return hmac.digest(salt, word.encode("utf-8", "surrogateescape"), "sha256").hex()


def _read_fingerprints(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    if not (isinstance(data, dict) and isinstance(data.get("salt"), str)
            and isinstance(data.get("keys"), dict)):
        raise ValueError(f"{path} is not a stuntkey fingerprint file")
    return data


REPLACE_TRIES = 6


def _write_fingerprints(path: str, data: dict) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fp-", suffix=".tmp", dir=folder)  # 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        for attempt in range(REPLACE_TRIES):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:      # Windows antivirus or indexer holds the file briefly
                if attempt == REPLACE_TRIES - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class _Prints(frozenset):
    """The fingerprints, plus the distinct lengths of the stored keys (a
    frozenset still, so every caller that passes it around is unchanged)."""
    lengths: tuple = ()


MAX_LENGTHS = 8     # ponytail: window scan costs words x lengths x offsets; more keys than
                    # this with distinct lengths -> only the 8 shortest are searched inside words


def remember_key(name: str, secret: str, path: str | None = None) -> None:
    """Record the fingerprints of a key just stored or rotated (`name`:
    "service/ENV_VAR"; a second call for the same name replaces the first).
    Call after every keychain / .env save."""
    path = path or fingerprint_path()
    from . import store as store_mod     # lazy: the hook only reads, and starts faster
    with store_mod.file_lock(path):
        data = _read_fingerprints(path) or {"salt": secrets_mod.token_hex(32), "keys": {}}
        salt = bytes.fromhex(data["salt"])
        data["keys"][name] = (sorted(_fp(salt, f) for f in _fingerprint_forms(secret))
                              if len(secret) >= MIN_LEN else [])
        data.setdefault("lengths", {})[name] = [len(secret)] if len(secret) >= MIN_LEN else []
        _write_fingerprints(path, data)


def forget_key(name: str, path: str | None = None) -> bool:
    """Drop a forgotten key's fingerprints. True when there were some."""
    path = path or fingerprint_path()
    from . import store as store_mod     # lazy: the hook only reads, and starts faster
    with store_mod.file_lock(path):
        data = _read_fingerprints(path)
        if name not in data.get("keys", {}):
            return False
        del data["keys"][name]
        if isinstance(data.get("lengths"), dict):
            data["lengths"].pop(name, None)
        _write_fingerprints(path, data)
        return True


def load_fingerprints(path: str | None = None) -> tuple[bytes, frozenset]:
    """(salt, every fingerprint), or (b"", empty) when nothing is stored."""
    data = _read_fingerprints(path or fingerprint_path())
    if not data:
        return b"", frozenset()
    prints = _Prints(h for hs in data["keys"].values() if isinstance(hs, list) for h in hs)
    lens = data.get("lengths")
    if isinstance(lens, dict):
        prints.lengths = tuple(sorted({n for ls in lens.values() if isinstance(ls, list)
                                       for n in ls if isinstance(n, int) and n >= MIN_LEN}))[:MAX_LENGTHS]
    return bytes.fromhex(data["salt"]), prints


def _stored_spans(text: str, salt: bytes, prints: frozenset):
    """(start, end) of every word, or the part after = or : in it, whose
    fingerprint is a stored key's."""
    for m in _WORD_RE.finditer(text):
        word, base = m.group(), m.start()
        cands = {(0, len(word))}
        for i, ch in enumerate(word):
            if ch in "=:":
                cands.update(((i + 1, len(word)), (0, i)))
        for a, b in cands:
            piece = word[a:b].rstrip(".")
            if len(piece) >= MIN_LEN and _fp(salt, piece) in prints:
                yield base + a, base + a + len(piece)
        # always: a key glued inside the word (URL path, id-KEY, ...), even when
        # another copy of it matched whole above. Overlaps are skipped in mask_secrets.
        for n in getattr(prints, "lengths", ()):
            i = 0
            while i + n <= len(word):
                if n < len(word) and _fp(salt, word[i:i + n]) in prints:
                    yield base + i, base + i + n
                    i += n
                else:
                    i += 1


def has_stored_key(text: str, prints: tuple[bytes, frozenset]) -> bool:
    """Does `text` hold a stored key (by fingerprint only, never by format)?"""
    salt, hashes = prints
    return bool(hashes) and next(_stored_spans(text, salt, hashes), None) is not None


_RULES = None


def _format_rules():
    """scan.py's key patterns (shipped recipes and well-known prefixes only:
    a pattern from YOUR recipe could be slow and has no timer here)."""
    global _RULES
    if _RULES is None:
        from . import recipes as recipes_mod
        from . import scan as scan_mod
        _RULES = [r.regex for r in scan_mod.build_rules(recipes_mod.load_recipes())
                  if r.trusted and not r.disabled]
    return _RULES


# a cheap first look: without one of these there is no key format to find
_MAYBE_KEY_RE = re.compile(r"[A-Za-z0-9_\-+/=.~]{16,}|PRIVATE KEY|://[^\s@/]+:|"
                           r"[=:]\s*[\"']?[A-Za-z0-9_\-+/=.~]{8,}")


def _format_spans(text: str):
    from . import scan as scan_mod
    for rx in _format_rules():
        for m in rx.finditer(text):
            yield m.span()
    for m in scan_mod.PRIVATE_KEY_RE.finditer(text):
        end = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----").search(text, m.end())
        yield m.start(), end.end() if end else len(text)
    for m in scan_mod.BEARER_RE.finditer(text):
        yield m.span("value")
    for m in scan_mod.URL_PASSWORD_RE.finditer(text):
        if not scan_mod.is_placeholder(m.group("password")):
            yield m.span("password")
    for m in scan_mod.ASSIGN_RE.finditer(text):
        name, value = m.group("name"), m.group("value")
        if scan_mod.NOT_SECRET_NAME_RE.search(name):
            continue
        if ((scan_mod.SECRET_NAME_RE.search(name) and scan_mod._secret_value_ok(value))
                or (scan_mod.PASSWORD_NAME_RE.search(name) and scan_mod._password_value_ok(value))):
            yield m.span("value")


def mask_secrets(text: str, prints: tuple[bytes, frozenset] | None = None) -> tuple[str, int]:
    """`text` with every stored key (by fingerprint) and every text in a
    known key format replaced by [REDACTED]; and how many were. `prints` is
    load_fingerprints() (read here when not given)."""
    salt, hashes = prints if prints is not None else load_fingerprints()
    spans = list(_stored_spans(text, salt, hashes)) if hashes else []
    if _MAYBE_KEY_RE.search(text):
        spans += _format_spans(text)
    if not spans:
        return text, 0
    out, last, n = [], 0, 0
    for a, b in sorted(spans):
        if b <= last:
            continue                           # inside a span already masked
        out.append(text[last:max(a, last)])
        out.append(REDACTED.decode())
        last, n = b, n + 1
    out.append(text[last:])
    return "".join(out), n
