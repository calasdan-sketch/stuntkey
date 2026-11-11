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
import itertools
import json
import os
import re
import secrets as secrets_mod
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from urllib.parse import quote, quote_plus

REDACTED = b"[REDACTED]"
MIN_LEN = 6          # shorter "secrets" would mangle ordinary text
MIN_B64 = 8          # a base64 piece shorter than this is left alone

# Hard time limits. The text a scrubber reads is chosen by someone else (a
# program, a web server, a prompt-injected agent), so no input may make it run
# for minutes. Work grows in a straight line with the size of the text, and a
# deadline is checked between every small step; when it runs out the WHOLE text
# is replaced by WITHHELD_NOTICE. Never a half-checked text.
MASK_BUDGET_S = 4.0          # one text masked (the PostToolUse hook has 10 s in all)
LOOSE_BUDGET_S = 8.0         # one loosely_contains() call
MASK_MAX_CHARS = 32 * 1024 * 1024
WITHHELD_NOTICE = ("[stuntkey withheld this output: it was too large or too odd to "
                   "check for secrets in time, so none of it is shown. Ask for a "
                   "smaller piece, for example only the first lines.]")


class CheckTimeout(Exception):
    """The time allowance for a check ran out."""


def _tick(deadline) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise CheckTimeout


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


def loosely_contains(text: str, secrets, deadline: float | None = None) -> bool:
    """`_loosely_contains` under a time limit (LOOSE_BUDGET_S, or `deadline`,
    a time.monotonic() value). Out of time counts as True: the caller then
    withholds the whole text, which is the safe answer for a text this odd."""
    if deadline is None:
        deadline = time.monotonic() + LOOSE_BUDGET_S
    try:
        return _loosely_contains(text, secrets, deadline)
    except (CheckTimeout, MemoryError, RecursionError):
        return True


def _loosely_contains(text: str, secrets, deadline) -> bool:
    """True if, after undoing common disguises, any secret (in a plain,
    base64 or hex form) is still in the text. The caller then withholds the
    whole text instead of trying to patch it.

    A long enough PIECE of a secret counts too: an API that echoes half a key
    has still given most of it away, and Scrubber only removes whole forms. The
    run must be PARTIAL_RUN characters, far longer than the 6 to 12 character
    hint vendors show on purpose ("sk-...Zk"), so a key hint does not trip it."""
    text = text.replace("\x00", "")
    _tick(deadline)
    norm = _normalize(text)
    _tick(deadline)
    squashed = _squash(norm)
    for s in secrets:
        _tick(deadline)
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
            for i in range(0, span, step):
                _tick(deadline)
                if whole[i:i + PARTIAL_RUN] in squashed:
                    return True
        for f in forms(s):
            _tick(deadline)
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
            _tick(deadline)
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
    frozenset still, so every caller that passes it around is unchanged).
    `delimited`: ((length, fingerprints), ...) for keys that hold a character
    _WORD_RE splits on (see _delimited_spans)."""
    lengths: tuple = ()      # key lengths searched for inside a word by HMAC (older files)
    delimited: tuple = ()
    crcs: tuple = ()         # ((length, {16-bit checksums}), ...): the quick way to find them


# A key with one of these in it is cut into pieces by _WORD_RE, so no word of
# the output is the whole key. (A key that holds whitespace itself is not
# recorded: it cannot sit inside one whitespace-delimited run.)
_DELIM_RE = re.compile(r"[\"'`,;()\[\]{}<>|&\\]")


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
        # a 16-bit salted checksum of the key: only a first filter that says
        # "try the real fingerprint here" (the HMAC still decides), and it
        # makes the search inside a long word about 8 times quicker
        crc = data.setdefault("crc", {})
        if len(secret) >= MIN_LEN:
            crc[name] = {"n": len(secret), "c": _crc(zlib.crc32(salt),
                                                     secret.encode("utf-8", "surrogateescape"))}
        else:
            crc.pop(name, None)
        delimited = data.setdefault("delimited", {})
        if len(secret) >= MIN_LEN and _DELIM_RE.search(secret) and not re.search(r"\s", secret):
            delimited[name] = {"length": len(secret), "fp": _fp(salt, secret),
                               "roll": _roll(secret, _roll_base(salt))}
        else:
            delimited.pop(name, None)
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
        if isinstance(data.get("crc"), dict):
            data["crc"].pop(name, None)
        if isinstance(data.get("delimited"), dict):
            data["delimited"].pop(name, None)
        _write_fingerprints(path, data)
        return True


def load_fingerprints(path: str | None = None) -> tuple[bytes, frozenset]:
    """(salt, every fingerprint), or (b"", empty) when nothing is stored."""
    data = _read_fingerprints(path or fingerprint_path())
    if not data:
        return b"", frozenset()
    prints = _Prints(h for hs in data["keys"].values() if isinstance(hs, list) for h in hs)
    lens = data.get("lengths")
    # (a file with no "lengths" is from before glued keys were searched for:
    # its checksums, if any, are not used either)
    sums = data.get("crc") if isinstance(data.get("crc"), dict) and isinstance(lens, dict) else {}
    by_len: dict[int, set] = {}
    for d in sums.values():
        if (isinstance(d, dict) and isinstance(d.get("n"), int) and d["n"] >= MIN_LEN
                and isinstance(d.get("c"), int)):
            by_len.setdefault(d["n"], set()).add(d["c"])
    prints.crcs = tuple((n, frozenset(by_len[n])) for n in sorted(by_len)[:MAX_LENGTHS])
    if isinstance(lens, dict):
        # keys stored before checksums existed are still found, by HMAC
        prints.lengths = tuple(sorted({n for name, ls in lens.items() if isinstance(ls, list)
                                       and name not in sums
                                       for n in ls if isinstance(n, int) and n >= MIN_LEN}))[:MAX_LENGTHS]
    found: dict[int, dict] = {}
    delimited = data.get("delimited")
    for d in (delimited.values() if isinstance(delimited, dict) else ()):
        if (isinstance(d, dict) and isinstance(d.get("length"), int)
                and d["length"] >= MIN_LEN and isinstance(d.get("fp"), str)
                and isinstance(d.get("roll"), int)):
            found.setdefault(d["length"], {})[d["roll"]] = d["fp"]
    prints.delimited = tuple((n, found[n]) for n in sorted(found)[:MAX_LENGTHS])
    return bytes.fromhex(data["salt"]), prints


CRC_MASK = 0xFFFF


def _crc(seed: int, data: bytes) -> int:
    return zlib.crc32(data, seed) & CRC_MASK


_ROLL_MOD = (1 << 61) - 1


def _roll_base(salt: bytes) -> int:
    return int.from_bytes(hmac.digest(salt, b"roll", "sha256")[:8], "big") % (_ROLL_MOD - 2) + 2


def _roll(word: str, base: int) -> int:
    """A salted polynomial hash of `word`: only a cheap first filter that
    lets a window be tried, which the real fingerprint then confirms."""
    h = 0
    for ch in word:
        h = (h * base + ord(ch)) % _ROLL_MOD
    return h


_RUN_PIECE = 4096   # a long run of non-space characters is looked at in pieces this long


def _pieces_of(word: str, start: int, overlap: int):
    """(offset, piece) of `word` in overlapping pieces: no piece is more than
    max(_RUN_PIECE, 2 x overlap) long, so the work per piece is fixed."""
    size = max(_RUN_PIECE, 2 * overlap + 1)
    if len(word) <= size:
        yield start, word
        return
    step = size - overlap
    for i in range(0, len(word), step):
        yield start + i, word[i:i + size]
        if i + size >= len(word):
            break


def _delimited_spans(text: str, salt: bytes, entries, deadline=None):
    """Where a stored key that holds delimiter characters sits in `text`.
    `entries`: ((length, {rolling hash: fingerprint}), ...). A window of the
    key's length is slid over each whitespace-delimited run (the key has no
    whitespace in it); a window is looked at only when its cheap rolling hash
    matches, then confirmed with the fingerprint."""
    base = _roll_base(salt)
    shortest = min(n for n, _ in entries)
    longest = max(n for n, _ in entries)
    for run in re.finditer(r"\S{%d,}" % shortest, text):
        for start, word in _pieces_of(run.group(), run.start(), longest):
            _tick(deadline)
            if not _DELIM_RE.search(word):
                continue
            pre = list(itertools.accumulate(word, lambda h, ch: (h * base + ord(ch)) % _ROLL_MOD,
                                            initial=0))
            for n, table in entries:
                if n > len(word):
                    continue
                top = pow(base, n, _ROLL_MOD)
                last = 0
                for i in [i for i in range(len(word) - n + 1)
                          if (pre[i + n] - pre[i] * top) % _ROLL_MOD in table]:
                    if i >= last and _fp(salt, word[i:i + n]) == table[(pre[i + n] - pre[i] * top) % _ROLL_MOD]:
                        yield start + i, start + i + n
                        last = i + n


MAX_SPLITS = 16      # "=" and ":" in one word that are tried as the start of a key


def _stored_spans(text: str, salt: bytes, prints: frozenset, deadline=None):
    """(start, end) of every word, or the part after = or : in it, whose
    fingerprint is a stored key's. The work per word is fixed (at most
    MAX_SPLITS splits and MAX_LENGTHS key lengths), so the time grows in a
    straight line with the text."""
    seed = zlib.crc32(salt)
    crcs = getattr(prints, "crcs", ())
    legacy = getattr(prints, "lengths", ())
    for m in _WORD_RE.finditer(text):
        _tick(deadline)
        word, base = m.group(), m.start()
        size = len(word)
        cands = {(0, size)}
        splits = 0
        for i, ch in enumerate(word):
            if ch in "=:":
                cands.update(((i + 1, size), (0, i)))
                splits += 1
                if splits >= MAX_SPLITS:
                    break
        for a, b in cands:
            piece = word[a:b].rstrip(".")
            if len(piece) >= MIN_LEN and _fp(salt, piece) in prints:
                yield base + a, base + a + len(piece)
        # always: a key glued inside the word (URL path, id-KEY, ...), even when
        # another copy of it matched whole above. Overlaps are skipped in mask_secrets.
        raw = word.encode("ascii") if word.isascii() else None
        for n, table in crcs:
            if n >= size:
                continue
            if raw is not None:
                hits = [i for i in range(size - n + 1)
                        if zlib.crc32(raw[i:i + n], seed) & CRC_MASK in table]
            else:
                hits = [i for i in range(size - n + 1)
                        if zlib.crc32(word[i:i + n].encode("utf-8", "surrogateescape"), seed)
                        & CRC_MASK in table]
            last = 0
            for i in hits:
                if i >= last and _fp(salt, word[i:i + n]) in prints:
                    yield base + i, base + i + n
                    last = i + n
        for n in legacy:
            i = 0
            while i + n <= size:
                if i % 256 == 0:
                    _tick(deadline)
                if n < size and _fp(salt, word[i:i + n]) in prints:
                    yield base + i, base + i + n
                    i += n
                else:
                    i += 1


def _all_stored_spans(text: str, salt: bytes, prints: frozenset, deadline=None):
    yield from _stored_spans(text, salt, prints, deadline)
    entries = getattr(prints, "delimited", ())
    if entries:
        yield from _delimited_spans(text, salt, entries, deadline)


def has_stored_key(text: str, prints: tuple[bytes, frozenset], deadline: float | None = None) -> bool:
    """Does `text` hold a stored key (by fingerprint only, never by format)?
    Out of time counts as yes: whoever asks refuses or withholds the text."""
    salt, hashes = prints
    if not hashes:
        return False
    if deadline is None:
        deadline = time.monotonic() + MASK_BUDGET_S
    try:
        return next(_all_stored_spans(text, salt, hashes, deadline), None) is not None
    except (CheckTimeout, MemoryError, RecursionError):
        return True


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

FORMAT_WINDOW = 65536    # the key-format patterns run on pieces this long ...
FORMAT_OVERLAP = 2048    # ... that overlap by this much (a key is shorter than that)
_PEM_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def _windows(text: str):
    if len(text) <= FORMAT_WINDOW:
        yield 0, text, True
        return
    step = FORMAT_WINDOW - FORMAT_OVERLAP
    for i in range(0, len(text), step):
        last = i + FORMAT_WINDOW >= len(text)
        yield i, text[i:i + FORMAT_WINDOW], last
        if last:
            break


def _format_spans(text: str, deadline=None):
    import bisect
    from . import scan as scan_mod
    # a private key block: from its BEGIN line to its END line (or to the end of
    # the text when it has none). Found over the whole text in one pass, so a
    # text of nothing but BEGIN lines costs no more than any other.
    ends = [(m.start(), m.end()) for m in _PEM_END_RE.finditer(text)]
    starts = [e[0] for e in ends]
    covered = 0
    for k, m in enumerate(scan_mod.PRIVATE_KEY_RE.finditer(text)):
        if k % 256 == 0:
            _tick(deadline)
        if m.start() < covered:
            continue
        at = bisect.bisect_left(starts, m.end())
        covered = ends[at][1] if at < len(ends) else len(text)
        yield m.start(), covered
    rules = _format_rules()
    for off, win, final in _windows(text):
        def span(a, b):
            # a match that runs into the end of a piece, and is longer than the
            # overlap, may go on in the next piece: not safe to cut it here
            if not final and b >= len(win) and b - a >= FORMAT_OVERLAP:
                raise CheckTimeout
            return a + off, b + off
        for rx in rules:
            _tick(deadline)
            for m in rx.finditer(win):
                yield span(*m.span())
        _tick(deadline)
        for m in scan_mod.BEARER_RE.finditer(win):
            yield span(*m.span("value"))
        _tick(deadline)
        for m in scan_mod.URL_PASSWORD_RE.finditer(win):
            if not scan_mod.is_placeholder(m.group("password")):
                yield span(*m.span("password"))
        _tick(deadline)
        for m in scan_mod.ASSIGN_RE.finditer(win):
            name, value = m.group("name"), m.group("value")
            if scan_mod.NOT_SECRET_NAME_RE.search(name):
                continue
            if ((scan_mod.SECRET_NAME_RE.search(name) and scan_mod._secret_value_ok(value))
                    or (scan_mod.PASSWORD_NAME_RE.search(name) and scan_mod._password_value_ok(value))):
                yield span(*m.span("value"))


def mask_secrets(text: str, prints: tuple[bytes, frozenset] | None = None,
                 deadline: float | None = None) -> tuple[str, int]:
    """`text` with every stored key (by fingerprint) and every text in a
    known key format replaced by [REDACTED]; and how many were. `prints` is
    load_fingerprints() (read here when not given).

    Time-limited (MASK_BUDGET_S, or `deadline`, a time.monotonic() value; a
    caller masking several texts passes one deadline for all). A text too big,
    or too odd to check in time, is replaced WHOLE by WITHHELD_NOTICE (counted
    as one hit): it is never shown half checked."""
    salt, hashes = prints if prints is not None else load_fingerprints()
    if len(text) > MASK_MAX_CHARS:
        return WITHHELD_NOTICE, 1
    if deadline is None:
        deadline = time.monotonic() + MASK_BUDGET_S
    try:
        spans = list(_all_stored_spans(text, salt, hashes, deadline)) if hashes else []
        if _MAYBE_KEY_RE.search(text):
            spans += _format_spans(text, deadline)
        _tick(deadline)
    except (CheckTimeout, MemoryError, RecursionError):
        return WITHHELD_NOTICE, 1
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
