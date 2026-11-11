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
_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class ImportProblem(Exception):
    """A plain-sentence reason the file cannot be used."""


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    # an unquoted value ends at a space-hash comment
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def parse_env(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = _ASSIGN.match(line)
        if m and (val := _unquote(m.group(2))):
            out.append((m.group(1), val))
    return out


def _envify(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "_", str(name)).strip("_").upper()
    return ("K_" + name) if name[:1].isdigit() else name


def parse_json(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        raise ImportProblem("that file is not valid JSON") from None
    out: list[tuple[str, str]] = []
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        for item in data["items"]:          # Bitwarden
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            login = item.get("login") if isinstance(item.get("login"), dict) else {}
            if name and login.get("password"):
                out.append((_envify(name), str(login["password"])))
            for f in item.get("fields") or []:
                if isinstance(f, dict) and f.get("name") and f.get("value"):
                    out.append((_envify(f["name"]), str(f["value"])))
        return out
    if isinstance(data, dict):              # Doppler: {"NAME": "value"}
        for k, v in data.items():
            if isinstance(v, (str, int)) and str(v):
                out.append((str(k), str(v)))
        return out
    if isinstance(data, list):              # [{"name":..., "value":...}]
        for row in data:
            if isinstance(row, dict):
                out.extend(_from_row({str(k).lower(): v for k, v in row.items()}))
        return out
    raise ImportProblem("I do not recognise this JSON layout")


def _from_row(row: dict) -> list[tuple[str, str]]:
    name = next((row[c] for c in _NAME_COLS if row.get(c)), None)
    value = next((row[c] for c in _VALUE_COLS if row.get(c)), None)
    return [(_envify(name), str(value))] if name and value else []


def parse_csv(text: str) -> list[tuple[str, str]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ImportProblem("that CSV file is empty")
    out: list[tuple[str, str]] = []
    for row in reader:
        out.extend(_from_row({str(k).strip().lower(): v for k, v in row.items()
                              if k is not None and isinstance(v, str)}))
    return out


def parse_text(text: str, kind: str) -> list[tuple[str, str]]:
    return {"json": parse_json, "csv": parse_csv}.get(kind, parse_env)(text)


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
            return f.read().decode("utf-8-sig", "replace")
    except OSError as e:
        raise ImportProblem(f"I cannot read {recipes_mod.printable(path)}: "
                            f"{e.strerror or e}") from None


def match_services(pairs, catalog: dict):
    """(matched, unknown_names): matched is [(recipe, env_var, value)]; a name
    must be one a recipe stores, so `stuntkey run <service>` can use it."""
    by_var = {}
    for recipe in catalog.values():
        for var in recipes_mod.env_vars(recipe):
            by_var.setdefault(var, recipe)
    matched, unknown, seen = [], [], set()
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
            seen.add(key)
            matched.append((recipe, key, value))
    return matched, unknown


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
    out = out or sys.stdout
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
    matched, unknown = match_services(pairs, catalog)
    pairs = None
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
    matched = None
    for var in done:
        out.write(f"  ✓ saved {recipes_mod.printable(var)}\n")
    for var, why in failed:
        out.write(f"  ✗ could not save {recipes_mod.printable(var)}: "
                  f"{recipes_mod.printable(why)}\n")
    if source:
        if args.delete_source and not failed:
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
