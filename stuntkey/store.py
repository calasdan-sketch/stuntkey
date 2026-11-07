"""Secret storage: .env handling with locked-down permissions.

Rules:
- The key value is NEVER printed, logged, or returned to callers.
- The file is private from its first byte: the content is written to a
  randomly named temp file created with O_CREAT|O_EXCL and mode 0o600 in
  the same directory, fsync'd, then atomically renamed over the target.
  There is no moment at which a partial or world-readable .env exists,
  and a pre-planted file (or link) at a guessable name is never written
  through.
- Existing keys are updated in place (``export KEY=`` lines included);
  nothing else in the file moves - not even a byte of it. A variable set
  more than once is updated on its LAST line - the one python-dotenv,
  docker compose and a shell ``source`` end up using - and the earlier
  lines are left alone; ``forget`` removes every one of them. Every
  other line comes back out exactly as it went in: a Windows cp1252 file
  with an accented comment stays cp1252 (bytes that are not UTF-8
  survive through ``surrogateescape``), and every line keeps its own
  line ending - a CRLF file stays CRLF, an LF file stays LF. The line we
  add or change takes the file's own style, and a missing last newline
  is added in that style.
- A quoted value that runs over several lines belongs to its variable, as
  python-dotenv, Node dotenv and a shell read it: a line inside it that
  looks like ``NAME=`` is never rewritten or removed, and a variable whose
  own value runs over several lines is replaced or removed as a whole.
- A ``.env`` that is a symbolic link is refused (``refuse_link``): never
  written through, never silently replaced. So is a file that is not plain
  text (UTF-16 from PowerShell's ``>``), because appending UTF-8 to it
  would wreck it. Both refusals change nothing and say why.
- Values are written so that sourcing the file in a shell can never run
  anything, and so that no reader loses part of the key: a value made only
  of ``[A-Za-z0-9_.+/=:-]`` is written bare; anything else is wrapped in
  single quotes, inside which a POSIX shell takes every character
  literally (inside double quotes it would still run ``$(...)`` and
  backticks). A value that readers do not agree on - one with a single
  quote, a backslash, ``${`` or a character that cannot be seen - is
  refused (``UnsafeValue``) instead of being written in a form some reader
  would misread; real API keys have none of these. Files written by 0.3.1
  and earlier used double quotes: they are still read, and a line is
  rewritten in the new form the next time its key is saved.
- On Windows, mode bits are meaningless; the file's ACL is reduced to
  the current user instead (best effort, via icacls) — and the success
  line says so honestly when that did not work.
"""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import errno
import getpass
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

from . import fsutil
from . import procs
from .recipes import ENV_VAR_RE

OWNER_ONLY = 0o600

# The file is UTF-8 (python-dotenv, Node dotenv and docker compose all read
# it that way), but one saved by Notepad on a Windows code page is not. Its
# other bytes must come back out untouched, so decoding maps every byte that
# is not UTF-8 to a lone surrogate and encoding maps it straight back: the
# round trip is exact for any input.
_ENCODING = "utf-8"
_UNDECODABLE = "surrogateescape"

# Characters that are safe unquoted in every dotenv dialect we know of (a
# shell would expand a bare ~, so it is not among them). \Z, not $: "$" also
# matches in front of a final newline.
_PLAIN_VALUE_RE = re.compile(r"^[A-Za-z0-9_.+/=:-]+\Z")

# `KEY=` or `export KEY=`; group 1 is everything before the name: an optional
# byte-order mark (Windows editors and PowerShell's `Out-File -Encoding utf8`
# put one at the very start of a UTF-8 file, and without this the first line
# is never recognised - a second ACME_API_KEY= line gets added instead of the
# first one being updated), indentation and the optional `export`. Because
# the whole prefix is written back unchanged, the mark stays where it was.
_ASSIGN_RE = re.compile(
    r"^(\ufeff?\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=")

# A line ending is CRLF, LF or a lone CR (what python-dotenv and Node dotenv
# both accept) and nothing else: str.splitlines() would also cut at \x0c,
# \x1c-\x1e, \x85 and U+2028/9 and then rewrite those lines with "\n".
_EOL_RE = re.compile(r"\r\n|\n|\r")

PROTECTION_POSIX = "mode 0600"
PROTECTION_WINDOWS = "owner-only ACL"
PROTECTION_WINDOWS_FAILED = ("could not restrict ACL - icacls failed; the file "
                             "has the folder's default permissions")

LINK_REASON = ("it is a link to another file, so stuntkey will not edit it "
               "- delete the link, or point --env-file at the real file")
DIRECTORY_REASON = ("it is a folder, not a file - rename or remove the folder, "
                    "or pass --env-file with a file name")
NOT_TEXT_REASON = ("it is not a plain UTF-8 text file (Windows PowerShell's > "
                   "saves UTF-16), so stuntkey will not edit it - save it "
                   "as UTF-8 first")


class EnvFileRefused(OSError):
    """The .env file is one stuntkey will not edit: a link, or not plain
    text. Nothing was changed. ``strerror`` is a single plain-language
    sentence with the reason and the way out; ``filename`` is the path.
    An OSError so every existing "could not save" handler already copes."""

    def __init__(self, path: str, reason: str):
        super().__init__(errno.EINVAL, reason, path)


class UnsafeValue(OSError):
    """The key has a character that cannot be written to a .env file in a
    form every reader agrees on (see ``unsafe_reason``), so nothing was
    written. ``strerror`` is one plain sentence - it never contains the key -
    and ``filename`` is the .env path when it is known. An OSError, like
    EnvFileRefused, so every existing "could not save" handler already
    copes."""

    def __init__(self, reason: str, path: str | None = None):
        message = (f"it contains {reason}, which .env readers do not agree "
                   f"on - real API keys do not have one")
        if path is None:
            super().__init__(errno.EINVAL, message)
        else:
            super().__init__(errno.EINVAL, message, path)
        self.reason = reason


def refuse_link(path: str) -> None:
    """Raise EnvFileRefused when `path` is a symbolic link (a dangling one
    too). Called before anything is read or written.

    Why refuse - rather than write through the link, or replace it:
    - A link can point anywhere: another project's .env, ~/.ssh/config, a
      system file. A cloned repository can ship a `.env` link as a trap.
      Writing "through" it would put the key somewhere the person never
      looked at, and reading through it would copy the target's contents
      into this folder.
    - Replacing it (all that os.replace() can do to a link) silently breaks
      whatever the link was for - a shared secrets file, a dotfile manager -
      and leaves the other files that rely on it without the new key.
    - Allowing "links that stay inside the same folder" was rejected: it needs
      realpath() comparisons that differ per platform (case folding, 8.3
      names, junctions, bind mounts) to protect a case, a link to a sibling
      file, that is no easier to explain than naming that file in
      --env-file. A person who really wants a linked file edited can do
      exactly that, and it is their own explicit choice.
    So the rule is one line for every write: a link is stopped, with a
    message that says what to do instead."""
    if os.path.islink(path):
        raise EnvFileRefused(path, LINK_REASON)


def _windows_owner_only(path: str) -> bool:
    """Replace the file's ACL with 'current user: full control' only.
    Returns True on success; never raises (Windows ACLs are best effort)."""
    try:
        user = os.environ.get("USERNAME") or getpass.getuser()
    except Exception:  # pragma: no cover - getuser can fail in odd sessions
        return False
    try:
        proc = subprocess.run(
            [procs.system32_tool("icacls.exe"), path, "/inheritance:r",
             "/grant:r", f"{user}:(F)"],
            capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _lock_down(path: str) -> bool:
    """Owner-only permissions on `path`, the regular file we just wrote:
    chmod 0600 (on Windows that only clears the read-only bit, so the ACL is
    restricted too). Returns True when the protection this platform
    promises is in place.

    chmod and icacls both FOLLOW a link, so a path that is not a regular
    file by now - something swapped a link in after our rename - is left
    alone (False): a permission change must never land on whatever a link
    points at. On POSIX the mode is set through a descriptor opened with
    O_NOFOLLOW, which closes the gap between the check and the change;
    Windows has no such handle for icacls, so the check is all it gets."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
    except OSError:
        return False
    if os.name == "nt":
        os.chmod(path, OWNER_ONLY)
        return _windows_owner_only(path)
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        os.fchmod(fd, OWNER_ONLY)
    finally:
        os.close(fd)
    return True


def describe_protection(protected: bool = True) -> str:
    """Human wording for the success line, honest per platform AND per
    outcome: on Windows a failed `icacls` must not be reported as an
    owner-only ACL."""
    if os.name == "nt":
        return PROTECTION_WINDOWS if protected else PROTECTION_WINDOWS_FAILED
    return PROTECTION_POSIX


UNPRINTABLE = ("a character that is not printable (a tab, a line break or "
               "another invisible character)")


def unsafe_reason(value: str) -> str | None:
    """Why `value` cannot be written to a .env file, or None when it can.
    The wording completes "it contains ...".

    Why these, and nothing else (every other character is safe inside single
    quotes; checked by hand with sh, bash, python-dotenv 1.2.3, Node dotenv
    17.4.2 and docker compose 5.5.1 - see the README):
    - a single quote: single quotes are what make a value safe to
      ``source``, and there is no way to put one inside them that every
      reader understands (the shell's ``'\\''`` is not dotenv syntax);
    - a backslash: python-dotenv reads two in a row as one, and a final one
      as an escaped closing quote, even inside single quotes; docker compose
      refuses a final one;
    - ``${``: python-dotenv expands ``${NAME}`` even inside single quotes;
    - anything that cannot be seen (a tab, a line break, a control or
      zero-width character, a no-break space): it ends or splits the line in
      some readers, and in a pasted key it is nearly always an accident.
    Real API keys contain none of these."""
    if not value.isprintable():
        return UNPRINTABLE
    if "'" in value:
        return "a single quote"
    if "\\" in value:
        return "a backslash"
    if "${" in value:
        return "the characters ${"
    return None


def quote_value(value: str) -> str:
    """The on-disk form of a value: bare when it is plain, otherwise in
    single quotes - inside which a shell that sources the file takes every
    character literally, and Node dotenv and docker compose do too. Raises
    UnsafeValue for a value that has no form every reader agrees on, so no
    caller can ever write one."""
    reason = unsafe_reason(value)
    if reason:
        raise UnsafeValue(reason)
    if value and _PLAIN_VALUE_RE.match(value):
        return value
    return "'" + value + "'"


def parse_value(raw: str) -> str:
    """Read a value back the way dotenv readers do: a single-quoted one is
    literal (what is written now); a double-quoted value is unescaped (what
    0.3.1 and earlier wrote); a bare value ends at the first ` #` comment
    and is stripped."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"':
        end = _closing_quote(s)
        body = s[1:end]
        return re.sub(r'\\(["\\])', r"\1", body)
    if len(s) >= 2 and s[0] == "'" and s.endswith("'"):
        return s[1:-1]
    return re.split(r"\s+#", s, maxsplit=1)[0].strip()


def _closing_quote(s: str) -> int:
    """Index of the closing unescaped `"` in s (which starts with `"`),
    or len(s) when it is missing."""
    i = 1
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == '"':
            return i
        i += 1
    return len(s)


def _read_bytes(path: str) -> bytes:
    """The file's raw bytes; a missing file is empty."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return b""
    except OSError as e:
        if getattr(e, "errno", None) == errno.ELOOP:
            raise EnvFileRefused(path, LINK_REASON)
        if os.path.isdir(path) or not os.path.exists(path):
            return b""
        raise
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return b""
        return f.read()


def _split_lines(text: str) -> list[list[str]]:
    """[[content, ending], ...] - the text cut at CRLF / LF / CR only, each
    line paired with its own ending ("" for a last line without one)."""
    entries: list[list[str]] = []
    pos = 0
    for m in _EOL_RE.finditer(text):
        entries.append([text[pos:m.start()], m.group()])
        pos = m.end()
    if pos < len(text):
        entries.append([text[pos:], ""])
    return entries


# What may follow the quote that closes a multi-line value, on its last line.
_AFTER_CLOSING_QUOTE_RE = re.compile(r"\s*(?:#.*)?\Z")


def _quote_end(text: str, quote: str, start: int) -> int:
    """Index of the first unescaped `quote` in `text` at or after `start`, or
    -1. Inside double quotes a backslash escapes the next character; inside
    single quotes nothing does."""
    i = start
    while i < len(text):
        c = text[i]
        if c == "\\" and quote == '"':
            i += 2
            continue
        if c == quote:
            return i
        i += 1
    return -1


def _value_end(entries: list[list[str]], first: int, rest: str) -> int:
    """The last line of the value that starts on line `first` (`rest` is the
    text after its `NAME=`): that same line, or - for a quoted value that
    runs over several lines - the line that closes it.

    python-dotenv, Node dotenv and a shell read a value that opens with a
    single or double quote (blanks after the = are allowed) and is not closed
    on its own line as running on to the first unescaped quote of that kind,
    provided only blanks or a #comment follow that quote; every line in
    between, whatever it looks like, is part of the value. A quote that is
    never closed, or whose closing line has other text after the quote, does
    not open a multi-line value: they read a one-line value and the next
    line as a new assignment."""
    value = rest.lstrip()
    quote = value[:1]
    if quote not in ('"', "'"):
        return first
    if _quote_end(value, quote, 1) != -1:
        return first                                    # closed on its own line
    for j in range(first + 1, len(entries)):
        end = _quote_end(entries[j][0], quote, 0)
        if end != -1:
            closes = _AFTER_CLOSING_QUOTE_RE.match(entries[j][0], end + 1)
            return j if closes else first
    return first


def _occurrences(entries: list[list[str]]) -> dict[str, list[tuple[int, int]]]:
    """{VAR: [(first line, last line) of every assignment of it, in file
    order]}. The two differ for a value that runs over several lines; a line
    inside such a value is part of it, never an assignment."""
    found: dict[str, list[tuple[int, int]]] = {}
    i = 0
    while i < len(entries):
        m = _ASSIGN_RE.match(entries[i][0])
        if not m:
            i += 1
            continue
        last = _value_end(entries, i, entries[i][0][m.end():])
        found.setdefault(m.group(2), []).append((i, last))
        i = last + 1
    return found


def _index(entries: list[list[str]]) -> dict[str, int]:
    """{VAR: index of the line that takes effect}: the (first line of the)
    LAST one. python-dotenv, Node dotenv, docker compose and a shell `source`
    all let a later assignment of a variable override an earlier one, so that
    is the line that has to hold the key."""
    return {var: spans[-1][0] for var, spans in _occurrences(entries).items()}


def times(count: int) -> str:
    """How often, for the notes about a variable set more than once."""
    return "twice" if count == 2 else f"{count} times"


def _newline_style(entries: list[list[str]]) -> str:
    """The line ending this file uses: its most common one (the first seen
    wins a tie). A file with no line ending at all - new, empty, or a single
    unterminated line - gets LF, which every dotenv reader, docker compose
    and a shell `source` all take (a shell would keep a CR as part of the
    value)."""
    seen = [ending for _content, ending in entries if ending]
    if not seen:
        return "\n"
    return collections.Counter(seen).most_common(1)[0][0]


def _render(entries: list[list[str]], newline: str) -> str:
    """The text to write: every line exactly as it was, the last one ended
    in the file's own style."""
    if entries and not entries[-1][1]:
        entries[-1][1] = newline
    return "".join(content + ending for content, ending in entries)


def _load_for_edit(path: str) -> list[list[str]]:
    """The file's lines, ready to be edited - or EnvFileRefused when editing
    it would be unsafe. A missing file is no lines."""
    refuse_link(path)
    if os.path.isdir(path):
        raise EnvFileRefused(path, DIRECTORY_REASON)
    data = _read_bytes(path)
    if b"\x00" in data:
        # UTF-16/32 (or binary). Without this, decoding "works" and a UTF-8
        # line appended to a UTF-16 file silently wrecks it.
        raise EnvFileRefused(path, NOT_TEXT_REASON)
    return _split_lines(data.decode(_ENCODING, _UNDECODABLE))


def check_env_file(path: str) -> None:
    """Raise OSError (EnvFileRefused for a link or a non-text file) unless
    `path` can be edited. connect() runs this BEFORE the browser opens and
    a key is pasted, so a refusal costs the person nothing."""
    _load_for_edit(path)


def read_env(path: str) -> tuple[list[str], dict[str, int]]:
    """Return (lines, {VAR: line_index}). Missing file -> ([], {}).
    `export VAR=...` lines count as definitions of VAR; when a variable is
    set more than once the index is the last line, the one that takes
    effect. Lines come without their line endings; bytes that are not UTF-8
    show up as lone surrogates (they are only ever written back, never
    displayed)."""
    entries = _split_lines(_read_bytes(path).decode(_ENCODING, _UNDECODABLE))
    return [content for content, _ending in entries], _index(entries)


def load_env(path: str) -> dict[str, str]:
    """Parse a .env file into {VAR: value} (quoted values decoded; a variable
    set twice has the value of its last line, as in every dotenv reader).
    For tests and tooling — the CLI itself never reads keys back into memory
    except to hand them to a child process."""
    entries = _split_lines(_read_bytes(path).decode(_ENCODING, _UNDECODABLE))
    values: dict[str, str] = {}
    for var, spans in _occurrences(entries).items():
        first, last = spans[-1]
        raw = entries[first][0][_ASSIGN_RE.match(entries[first][0]).end():]
        for k in range(first, last):            # a value over several lines
            raw += entries[k][1] + entries[k + 1][0]
        values[var] = parse_value(raw)
    return values


LOCK_SECONDS = 15.0


class EnvFileBusy(OSError):
    """Another stuntkey has had the file locked for too long."""

    def __init__(self, path: str):
        super().__init__(errno.EAGAIN, "another stuntkey is writing this file right now - "
                                       "try again in a moment", path)


def _windows() -> bool:
    return sys.platform == "win32"


def _lock_once(path: str, lock_path: str, deadline: float):
    """Open and lock the lock file; return its fd, or None when the file was
    swapped for a new one while waiting (the caller tries again)."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        if _windows():
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            while True:
                try:
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise EnvFileBusy(path) from None
                    time.sleep(0.05)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise EnvFileBusy(path) from None
                    time.sleep(0.02)
        try:
            same = os.path.samestat(os.fstat(fd), os.stat(lock_path))
        except OSError:
            same = False
        if not same:        # the holder removed it as it left: lock the new one
            os.close(fd)
            return None
        return fd
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def file_lock(path: str, timeout: float | None = None):
    """Hold an exclusive lock for a read-modify-replace of `path`. Without
    it two runs at once each read the old file and the last write wins,
    silently dropping the other's key. The lock is on a small sibling file
    (never on `path` itself: that is replaced by a rename); it is removed
    when the last holder leaves."""
    timeout = LOCK_SECONDS if timeout is None else timeout
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    base = os.path.basename(path)
    lock_path = os.path.join(directory, f"{base}.lock" if base.startswith(".") else f".{base}.lock")
    deadline = time.monotonic() + timeout
    fd = None
    while fd is None:
        fd = _lock_once(path, lock_path, deadline)
    try:
        yield
    finally:
        if not _windows():
            try:
                os.unlink(lock_path)        # while still locked: waiters re-check (see _lock_once)
            except OSError:
                pass
        else:
            try:
                import msvcrt
                os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        os.close(fd)
        if _windows():
            try:
                os.unlink(lock_path)
            except OSError:
                pass


def write_private(path: str, text: str) -> bool:
    """Atomically replace `path` with `text`, private from the start.

    mkstemp() picks an unguessable name in the target directory and
    creates it with O_CREAT|O_EXCL and mode 0o600, so nobody can pre-create
    the file we write through and no reader ever sees a half-written or
    world-readable key. On any failure the temp file is removed and the
    old `path` is left exactly as it was. The parent directory is created
    when missing. Returns whether the platform's protection (mode 0600 /
    owner-only ACL) is fully in place.

    A `path` that is a link is refused (EnvFileRefused): the callers check
    first, this is the last line of defence for any other caller. `text`
    goes out byte-exact: line endings are not translated, and bytes that
    came in as lone surrogates go back out as the bytes they were.
    """
    refuse_link(path)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    base = os.path.basename(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{base}.", suffix=".tmp", dir=directory)
    try:
        # Owner-only BEFORE the key goes in: on Windows mkstemp's mode does
        # not restrict the ACL, and the file would hold the key with the
        # ACL its folder gives it until the check after the rename.
        _lock_down(tmp)
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode(_ENCODING, _UNDECODABLE))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, OWNER_ONLY)  # mkstemp already did; belt and braces
        fsutil.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return _lock_down(path)


def env_not_git_ignored(path: str, find=procs.find_program,
                        run=subprocess.run) -> bool:
    """True only when git is installed, `path` is inside a git work tree and
    git does NOT ignore it - the one case where `git add .` would commit the
    key. Anything else (no git, not a repository, git failing) is False:
    nothing to warn about, and never an error."""
    git = find("git")
    if not git:
        return False
    full = os.path.abspath(path)
    try:
        done = run([git, "-C", os.path.dirname(full) or ".", "check-ignore",
                    "-q", "--", os.path.basename(full)],
                   capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 1         # 0 = ignored, 128 = not a repository


GIT_WARNING = ("warning: {path} is inside a git repository and is NOT in "
               ".gitignore - `git add .` would commit your key.\n"
               "    Add a line `{name}` to .gitignore first.")


@dataclasses.dataclass
class Stored:
    path: str
    updated: bool          # an existing entry was replaced
    protected: bool        # mode 0600 / owner-only ACL fully applied
    duplicates: int = 0    # EARLIER lines that set the same variable (left as they were)

    @property
    def protection(self) -> str:
        return describe_protection(self.protected)


def store_key_result(env_var: str, key: str, env_file: str = ".env") -> Stored:
    """Write key to env_file as ENV_VAR=<key> (quoted when needed) with
    owner-only permissions; returns what happened. The key value never
    leaves this function except into the file.

    Refuses a malformed env_var (anything but a shell identifier):
    writing it verbatim would let a hostile recipe inject extra lines
    into the user's .env. Recipe validation normally catches this at
    load time; this is the last line of defense. Refuses a key with a
    character the readers disagree on (UnsafeValue, an OSError) before
    anything is touched.
    """
    if not isinstance(env_var, str) or not ENV_VAR_RE.match(env_var):
        raise ValueError(
            f"refusing to write invalid env var name to {env_file}: "
            f"{env_var!r}")
    reason = unsafe_reason(key)
    if reason:
        raise UnsafeValue(reason, env_file)
    with file_lock(env_file):
        existed = os.path.isfile(env_file)
        entries = _load_for_edit(env_file)      # refuses a link / a non-text file
        newline = _newline_style(entries)
        spans = _occurrences(entries).get(env_var, [])
        value = quote_value(key)
        if spans:
            # The LAST assignment is the one every reader ends up using, so it
            # is the one that gets the key; earlier ones are not touched. If its
            # old value ran over several lines, they all become this one line.
            first, last = spans[-1]
            prefix = _ASSIGN_RE.match(entries[first][0]).group(1)
            # keeps `export` and the ending of the last line it took up
            entries[first][0] = f"{prefix}{env_var}={value}"
            entries[first][1] = entries[last][1]
            del entries[first + 1:last + 1]
            updated = True
        else:
            if entries and not entries[-1][1]:
                entries[-1][1] = newline        # end the last line before ours
            if entries and entries[-1][0].strip():
                entries.append(["", newline])
            entries.append([f"{env_var}={value}", ""])
            updated = False
        protected = write_private(env_file, _render(entries, newline))
        if env_var not in _occurrences(_split_lines(_read_bytes(env_file).decode(_ENCODING, _UNDECODABLE))):
            raise OSError(errno.EIO, "the key was not found in the file after writing it - "
                                      "another program changed it; run me again", env_file)
        # Scrub our own reference.
        del value
        return Stored(env_file, updated and existed, protected,
                      max(len(spans) - 1, 0))


def store_key(env_var: str, key: str, env_file: str = ".env") -> tuple[str, bool]:
    """Compatibility form of store_key_result(): (path, updated_existing)."""
    r = store_key_result(env_var, key, env_file)
    return r.path, r.updated


def remove_key(env_var: str, env_file: str = ".env") -> int:
    """Delete every ENV_VAR= line from env_file (for `stuntkey forget`)
    and return how many there were: 0 (false) when the variable is not
    there. All of them, not just the one that takes effect - otherwise an
    older line would spring back and the "forgotten" key would still be
    live - and all the lines of one whose value runs over several lines,
    but never a line inside ANOTHER variable's multi-line value. The rest of
    the file is kept byte-for-byte (line endings included); the file stays
    private. A link or a non-text file is refused, as when saving
    (EnvFileRefused)."""
    if not os.path.lexists(env_file):
        return 0
    with file_lock(env_file):
        entries = _load_for_edit(env_file)
        spans = _occurrences(entries).get(env_var)
        if not spans:
            return 0
        newline = _newline_style(entries)
        bom = spans[0][0] == 0 and entries[0][0].startswith("\ufeff")
        for first, last in reversed(spans):
            del entries[first:last + 1]
        if bom and entries:
            # The byte-order mark belongs to the file, not to the line we took
            # out: the next line becomes the first and keeps it.
            entries[0][0] = "\ufeff" + entries[0][0]
        write_private(env_file, _render(entries, newline))
        return len(spans)


@dataclasses.dataclass
class OtherLinks:
    names: list[str]       # other names of the file, in its own folder
    elsewhere: int         # further names we cannot see (other folders)


# Do not walk a folder of more than this many entries looking for links.
_SCAN_LIMIT = 20000


def other_links(path: str) -> OtherLinks | None:
    """The other hard links to the file at `path`, or None when it has none
    (or is missing, or is not a plain file - a symbolic link is never looked
    through).

    Why it matters for `forget`: a file is rewritten by renaming a new one
    over it, and that leaves every other name of the OLD file as it was - old
    contents, key included. Those names (a `.env.bak` made with `ln`, a
    backup tool's snapshot) are not stuntkey's to delete; it can only say
    they are there. Call this BEFORE rewriting: afterwards `path` is a new
    file with one name."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink < 2:
        return None
    names: list[str] = []
    if info.st_ino:
        base = os.path.basename(path)
        try:
            with os.scandir(os.path.dirname(os.path.abspath(path))) as listing:
                for count, entry in enumerate(listing):
                    if count >= _SCAN_LIMIT:
                        break
                    if entry.name == base:
                        continue
                    try:
                        other = os.lstat(entry.path)
                    except OSError:
                        continue
                    if (stat.S_ISREG(other.st_mode)
                            and (other.st_ino, other.st_dev)
                            == (info.st_ino, info.st_dev)):
                        names.append(entry.name)
        except OSError:
            pass
    names.sort()
    return OtherLinks(names, max(info.st_nlink - 1 - len(names), 0))


# A temp file is only read when it is smaller than this.
_LEFTOVER_MAX_BYTES = 4 * 1024 * 1024


def _holds_variable(path: str, env_var: str) -> bool:
    """Does the plain file at `path` assign `env_var`? (Nothing else about
    it is ever looked at, and it is not followed if it is a link.)"""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _LEFTOVER_MAX_BYTES:
            return False
        with open(path, "rb") as f:
            data = f.read(_LEFTOVER_MAX_BYTES)
    except OSError:
        return False
    entries = _split_lines(data.decode(_ENCODING, _UNDECODABLE))
    return env_var in _occurrences(entries)


def remove_leftovers(env_var: str, env_file: str = ".env",
                     unlink=os.unlink) -> tuple[list[str], list[tuple[str, str]]]:
    """Delete the temp files an interrupted write of `env_file` left in its
    folder - a write killed (SIGKILL, power cut) between creating the temp
    file and renaming it into place leaves ``.<name>.<8 letters>.tmp``, a
    complete copy of the file - when they still assign `env_var`. Only files
    with exactly the name write_private() gives its temp files are touched,
    and only plain files; any other file, a backup say, is somebody else's.

    Returns ([paths removed], [(path, why not) for those that could not be]).
    Never raises: a folder that cannot be listed has nothing to remove."""
    base = os.path.basename(env_file)
    directory = os.path.dirname(os.path.abspath(env_file))
    mine = re.compile(r"^\." + re.escape(base) + r"\.[a-z0-9_]{8}\.tmp\Z")
    removed: list[str] = []
    failed: list[tuple[str, str]] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return removed, failed
    for name in names:
        path = os.path.join(directory, name)
        if not mine.match(name) or not _holds_variable(path, env_var):
            continue
        try:
            unlink(path)
        except OSError as e:
            failed.append((path, e.strerror or str(e)))
        else:
            removed.append(path)
    return removed, failed


def file_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777
