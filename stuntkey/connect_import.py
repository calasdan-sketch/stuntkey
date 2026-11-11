"""`stuntkey import`: move keys you already have into the OS keychain.

Reads a .env file, a Doppler or Bitwarden JSON export, a 1Password or
Bitwarden CSV export, or lines you paste. Shows the NAMES it found (never a
value), asks, saves each one in the keychain, and tells you to delete the
file you read them from. A name stuntkey has no service for is left alone and
listed by name. Nothing is ever written to a .env file or printed.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys

from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import safeprompt

MAX_BYTES = 2_000_000
_NAME_COLS = ("name", "title", "label", "key", "env", "variable")
_VALUE_COLS = ("password", "login_password", "value", "secret", "credential",
               "api key", "api_key")
# Linear-time on purpose: no lazy group followed by a space run (a 40,000-space
# line made the older pattern take seconds). The value is stripped by hand.
_ASSIGN = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(.*)$")
_COMMENT = re.compile(r"[ \t]+#")
MAX_JSON_DEPTH = 100


class ImportProblem(Exception):
    """A plain-sentence reason the file cannot be used."""


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] in ("'", "\""):
        quote, i = raw[0], 1
        while i < len(raw):
            if quote == "\"" and raw[i] == "\\":
                i += 2
                continue
            if raw[i] == quote:
                return raw[1:i]          # whatever follows (a # comment) is dropped
            i += 1
        # no closing quote: treat it as plain text below
    # an unquoted value ends at a space-hash comment
    return _COMMENT.split(raw, maxsplit=1)[0].strip()


def parse_env(text: str) -> list[tuple[str, str]]:
    """NAME=value lines. A name given twice: the LAST one wins (the .env
    convention), and a later empty value cancels an earlier one."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = _ASSIGN.match(line)
        if not m:
            continue
        name, val = m.group(1), _unquote(m.group(2))
        found.pop(name, None)            # last wins, and the order is the last one's
        if val:
            found[name] = val
    return list(found.items())


def _scalar(v) -> str:
    """A secret's text, or "" when the cell is not text (a true/false flag, a
    list, an object, nothing): those are never keys."""
    if isinstance(v, str):
        return v
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    return ""


def _envify(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "_", str(name)).strip("_").upper()
    return ("K_" + name) if name[:1].isdigit() else name


def parse_json(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except RecursionError:
        raise ImportProblem("that JSON file is nested too deeply to be a key export") from None
    except ValueError:
        raise ImportProblem("that file is not valid JSON") from None
    if _too_deep(data):
        raise ImportProblem("that JSON file is nested too deeply to be a key export")
    out: list[tuple[str, str]] = []
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        for item in data["items"]:          # Bitwarden
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            login = item.get("login") if isinstance(item.get("login"), dict) else {}
            if name and _scalar(login.get("password")):
                out.append((_envify(name), _scalar(login["password"])))
            fields = item.get("fields")
            for f in (fields if isinstance(fields, list) else []):
                if isinstance(f, dict) and f.get("name") and _scalar(f.get("value")):
                    out.append((_envify(f["name"]), _scalar(f["value"])))
        return out
    if isinstance(data, dict):              # Doppler: {"NAME": "value"}
        for k, v in data.items():
            if isinstance(v, dict):         # `doppler secrets --json`: {"NAME": {"computed": ..., "raw": ...}}
                v = v.get("computed") or v.get("raw")
            if _scalar(v):
                out.append((str(k), _scalar(v)))
        return out
    if isinstance(data, list):              # [{"name":..., "value":...}]
        for row in data:
            if isinstance(row, dict):
                out.extend(_from_row({str(k).lower(): v for k, v in row.items()}))
        return out
    raise ImportProblem("I do not recognise this JSON layout")


def _too_deep(data, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when lists/objects nest deeper than `limit` (checked without
    recursion, so a hostile file cannot crash this check either)."""
    stack = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            kids = node.values()
        elif isinstance(node, list):
            kids = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((k, depth + 1) for k in kids if isinstance(k, (dict, list)))
    return False


def _from_row(row: dict) -> list[tuple[str, str]]:
    name = next((_scalar(row[c]) for c in _NAME_COLS if _scalar(row.get(c))), None)
    value = next((_scalar(row[c]) for c in _VALUE_COLS if _scalar(row.get(c))), None)
    return [(_envify(name), value)] if name and value else []


def parse_csv(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ImportProblem("that CSV file is empty")
        for row in reader:
            out.extend(_from_row({str(k).strip().lower(): v for k, v in row.items()
                                  if k is not None and isinstance(v, str)}))
    except csv.Error:
        raise ImportProblem("that CSV file has a cell that is far too big, or "
                            "is not a normal CSV file") from None
    return out


def last_wins(pairs) -> list[tuple[str, str]]:
    """A name listed twice keeps its last value."""
    found: dict[str, str] = {}
    for name, value in pairs:
        found.pop(name, None)
        found[name] = value
    return list(found.items())


def parse_text(text: str, kind: str) -> list[tuple[str, str]]:
    if len(text) > MAX_BYTES:
        raise ImportProblem("that is too much text to be a key file (over 2 MB)")
    pairs = {"json": parse_json, "csv": parse_csv}.get(kind, parse_env)(text)
    return last_wins(p for p in pairs if p[0])    # an entry whose name is all punctuation has no name


def sniff(path: str, text: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json" or text.lstrip().startswith(("{", "[")):
        return "json"
    if ext == ".csv":
        return "csv"
    return "env"


def read_source(path: str) -> str:
    try:
        size = os.path.getsize(path)
    except OSError:
        raise ImportProblem(f"I cannot open {recipes_mod.printable(path)}: "
                            "no such file, or no permission") from None
    if size > MAX_BYTES:
        raise ImportProblem(f"{recipes_mod.printable(path)} is too big to be a key "
                            "file (over 2 MB)")
    try:
        with open(path, "rb") as f:
            return decode_text(f.read(MAX_BYTES + 1))
    except OSError as e:
        raise ImportProblem(f"I cannot read {recipes_mod.printable(path)}: "
                            f"{e.strerror or e}") from None


def decode_text(raw: bytes) -> str:
    """Text from a file. Windows PowerShell's `>` writes UTF-16 (with or
    without a byte-order mark); other editors add a UTF-8 mark. All read."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    if len(raw) >= 4 and len(raw) % 2 == 0:       # UTF-16 with no mark: every other byte is 0
        even, odd = raw[0::2].count(0), raw[1::2].count(0)
        half = len(raw) // 2
        if odd > half * 0.8 and even == 0:
            return raw.decode("utf-16-le", "replace")
        if even > half * 0.8 and odd == 0:
            return raw.decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace")


def shape_problem(recipe: dict, var: str, value: str, strict_name: bool = True):
    """None when the value looks like this service's key (or the recipe has no
    shape to check); otherwise a plain reason. `strict_name`: the entry was
    matched by its exact variable name, so only a documented shape (or a
    known one) is held against it; a match by title alone must also pass the
    looser `detect` shape."""
    for f in recipes_mod.fields(recipe):
        if f["env_var"] != var:
            continue
        pat = f.get("accept")
        if not pat and (not strict_name or f.get("detect_confidence") == "known"):
            pat = f.get("detect")
        if not pat:
            return None
        try:
            if re.search(pat, value):
                return None
        except re.error:
            return None
        name = recipe.get("display") or recipe.get("service") or var
        return f"does not look like a {recipes_mod.printable(str(name))} key"
    return None


def match_services(pairs, catalog: dict):
    """(matched, unknown_names): matched is [(recipe, env_var, value)]; a name
    must be one a recipe stores, so `stuntkey run <service>` can use it."""
    matched, unknown, _info = match_services_ex(pairs, catalog)
    return matched, unknown


def match_services_ex(pairs, catalog: dict):
    """Like match_services, plus info: {"by_title": set of env vars matched only
    by a title, "merged": names that collapsed into another entry}."""
    pairs = last_wins(pairs)
    info = {"by_title": set(), "merged": []}
    by_var = {}
    for recipe in catalog.values():
        for var in recipes_mod.env_vars(recipe):
            by_var.setdefault(var, recipe)
    matched, unknown, seen = [], [], {}
    for name, value in pairs:
        key = name.upper()
        recipe = by_var.get(key)
        if recipe is None:
            # a password-manager entry is often titled just "OpenAI" or
            # "Stripe API key": match the service's name, one-value recipes only
            plain = re.sub(r"[^a-z0-9]", "", name.lower())
            for slug, r in catalog.items():
                names = {re.sub(r"[^a-z0-9]", "", slug.lower()),
                         re.sub(r"[^a-z0-9]", "", str(r.get("display", "")).lower())}
                vars_ = recipes_mod.env_vars(r)
                if len(vars_) == 1 and any(
                        n and (plain == n or plain in (n + "apikey", n + "key", n + "token"))
                        for n in names):
                    recipe, key = r, vars_[0]
                    break
        if recipe is None:
            if name not in unknown:
                unknown.append(name)
        elif key not in seen:
            seen[key] = name
            matched.append((recipe, key, value))
            if name.upper() != key:
                info["by_title"].add(key)
        else:
            info["merged"].append(name)       # a second name for the same key: not saved
    return matched, unknown, info


def _shred(path: str) -> None:
    """Overwrite with zeros, then delete. (On an SSD or a synced folder an
    overwrite is not a guarantee - the message says so.)"""
    size = os.path.getsize(path)
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    try:
        os.write(fd, b"\0" * size)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.remove(path)


def delete_advice(path: str) -> str:
    shown = recipes_mod.printable(os.path.abspath(path))
    return ("  The file you imported from still holds every key in plain text:\n"
            f"    {shown}\n"
            "  Delete it now. In Explorer or Finder a deleted file waits in the\n"
            "  Recycle Bin or Trash, so use the command (Windows PowerShell):\n"
            f"    Remove-Item -LiteralPath \"{shown}\"\n"
            "  (macOS/Linux: rm). Also delete the export from any download or\n"
            "  sync folder, and empty the Recycle Bin / Trash.\n")


def _read_pasted(out, reader=None) -> str:
    reader = reader or safeprompt.read_quiet
    out.write("  Paste NAME=value lines, one per line (nothing is shown). "
              "An empty line ends it.\n")
    lines = []
    while True:
        try:
            line = reader("  > ")
        except (EOFError, KeyboardInterrupt):
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def cmd_import(args, catalog: dict, out=None, reader=None, keychain=keychain_mod,
               interactive=None) -> int:
    """Run the import. Whatever goes wrong, the person gets a plain sentence
    (never a traceback, never a value) and the file is left alone."""
    out = out or sys.stdout
    try:
        return _cmd_import(args, catalog, out, reader, keychain, interactive)
    except KeyboardInterrupt:
        out.write("\n  Stopped. Your file was not touched. Run `stuntkey overview` "
                  "to see which keys are saved.\n")
        return 1
    except BaseException as e:           # noqa: BLE001 - last line of defence
        if isinstance(e, SystemExit):
            raise
        out.write("\n  Something unexpected went wrong while importing "
                  f"({type(e).__name__}). Your file was not deleted. Some keys may "
                  "already be saved: `stuntkey overview` shows which.\n")
        return 1


def _cmd_import(args, catalog, out, reader, keychain, interactive) -> int:
    if interactive is None:
        try:
            interactive = bool(sys.stdin and sys.stdin.isatty())
        except (OSError, ValueError):
            interactive = False
    if bool(args.file) == bool(args.paste):
        out.write("  Say where the keys are: `stuntkey import FILE`, or "
                  "`stuntkey import --paste`.\n")
        return 2
    out.write("  This will read the keys, save them in your computer's keychain "
              "and show only their names.\n")
    try:
        if args.paste:
            text, kind, source = _read_pasted(out, reader), "env", None
        else:
            text = read_source(args.file)
            kind, source = sniff(args.file, text), args.file
        pairs = parse_text(text, kind)
    except ImportProblem as e:
        out.write(f"  {e}. Nothing was saved.\n")
        return 1
    finally:
        text = ""
    names_in_file = len(pairs)
    matched, unknown, info = match_services_ex(pairs, catalog)
    pairs = None
    skipped = []                      # (name, why): right name, wrong-looking value
    good = []
    for recipe, var, value in matched:
        why = shape_problem(recipe, var, value, strict_name=var not in info["by_title"])
        if why:
            skipped.append((var, why))
        else:
            good.append((recipe, var, value))
    matched = good
    for var, why in skipped:
        out.write(f"  skipped: {recipes_mod.printable(var)} {why}\n")
    # the file may only be erased when EVERY name in it was saved
    leftovers = bool(unknown or skipped or info["merged"])
    if not matched:
        out.write("  I found no key for a service stuntkey knows.\n")
        if unknown:
            out.write("  Names I did not recognise (left alone): "
                      + ", ".join(recipes_mod.printable(n) for n in unknown[:20])
                      + ("..." if len(unknown) > 20 else "") + "\n"
                      "  For a site not in the list: `stuntkey get <site>`.\n")
        return 1
    backend = keychain.detect_backend()
    if backend is None:
        out.write("  This computer has no OS keychain I can use, so nothing was "
                  "saved. (I never put imported keys in a plain file.)\n")
        return 1
    out.write(f"\n  Found {len(matched)} key(s) I can save in the "
              f"{keychain.label(backend)}:\n")
    for recipe, var, _v in matched:
        try:
            had = bool(keychain.read(recipe["service"], var, backend))
        except Exception:
            had = False
        out.write(f"    {recipes_mod.printable(var):28} -> "
                  f"{recipes_mod.printable(recipe['service'])}"
                  f"{'   (replaces the one already saved)' if had else ''}\n")
    if unknown:
        out.write("  Left alone (no service for them): "
                  + ", ".join(recipes_mod.printable(n) for n in unknown[:20])
                  + ("..." if len(unknown) > 20 else "") + "\n")
    if not args.yes:
        if not interactive and reader is None:
            out.write("\n  Not asking in a script: add --yes to go ahead. "
                      "Nothing was saved.\n")
            return 2
        answer = safeprompt.ask("\n  Save these in the keychain? [y/N] ", out,
                                enter_means=False, reader=reader)
        if answer is not True:
            out.write("  Nothing was saved.\n")
            return 1
    done, failed = [], []
    for recipe, var, value in matched:
        try:
            keychain.store(recipe["service"], var, value, backend)
            done.append(var)
        except keychain.KeychainError as e:
            failed.append((var, str(e)))
        except Exception:           # noqa: BLE001 - never show a value or a traceback
            failed.append((var, "the keychain refused it"))
    matched = None
    for var in done:
        out.write(f"  ✓ saved {recipes_mod.printable(var)}\n")
    for var, why in failed:
        out.write(f"  ✗ could not save {recipes_mod.printable(var)}: "
                  f"{recipes_mod.printable(why)}\n")
    if source:
        if args.delete_source and leftovers and not failed:
            out.write("  I did NOT delete the file: it still holds names I did not "
                      "save (listed above), and they would be lost.\n")
            out.write("\n" + delete_advice(source))
        elif args.delete_source and not failed:
            try:
                _shred(source)
                out.write("  ✓ the file was overwritten and deleted. On an SSD or "
                          "a synced folder an old copy may remain: delete the export "
                          "from there too.\n")
            except OSError as e:
                out.write(f"  I could not delete the file ({e.strerror or e}).\n"
                          + delete_advice(source))
        else:
            out.write("\n" + delete_advice(source))
    return 1 if failed else 0
