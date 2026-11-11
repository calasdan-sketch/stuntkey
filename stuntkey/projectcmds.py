"""`init`, `setup` and `status`: the project-level commands.

  init     write stuntkey.json from the variable names the project uses
  setup    connect every service in it that has no key yet, in order
  status   list the services, where each key lives, how old it is

None of them prints, returns or logs a key; they only ask whether one is
stored (presence.py) and read dates from the local record (ledger.py).
"""

from __future__ import annotations

import json
import os
import sys

from . import detect as detect_mod
from . import keychain as keychain_mod
from . import ledger as ledger_mod
from . import manifest as manifest_mod
from . import presence as presence_mod
from .recipes import printable


def wants_keychain(item: dict, root: str, index_path: str | None = None) -> bool:
    """Should the OS keychain be asked about this service? Only when the
    manifest says it lives there, or the local record says it was put there:
    asking costs an unlock prompt (macOS) or a wait (a Secret Service that
    does not answer), so a service kept in .env never pays it."""
    if item.get("store") == "keychain":
        return True
    entry = ledger_mod.get(root, item["service"], index_path)
    return bool(entry and entry.get("store") == "keychain")


def _env_file(manifest: dict, root: str, override: str | None) -> str:
    if override:
        return override
    return manifest_mod.env_file_in(root, manifest)


# ------------------------------------------------------------------- init

def cmd_init(args, catalog: dict, out=None) -> int:
    out = out or sys.stdout
    root = os.getcwd()
    target = os.path.join(root, manifest_mod.FILE_NAME)
    source = manifest_mod.path_in(root)     # an old oathkey.json is read, ours is written
    existing = None
    if os.path.exists(source):
        if not args.force and not args.add:
            out.write(f"  {manifest_mod.FILE_NAME} already exists. Use --add to add newly "
                      f"found services to it, or --force to start over.\n")
            return 1
        if args.add:
            try:
                existing = manifest_mod.load(source)
            except manifest_mod.ManifestError as e:
                out.write(f"  cannot use the existing manifest: {printable(e)}\n")
                return 1
    found, read = detect_mod.detect(root, catalog)
    services = list(existing["services"]) if existing else []
    have = {s["service"] for s in services}
    added = [f for f in found if f["service"] not in have]
    services += added
    if not services:
        out.write("  No variable names matching a known service were found in this folder.\n"
                  "  (I read source files and .env.example-style templates, never a real .env.)\n"
                  "  List services yourself: `stuntkey list`, then edit stuntkey.json.\n")
        if not args.write:
            return 0
    data = dict(existing or {"version": manifest_mod.VERSION})
    data["services"] = services
    out.write(f"  Looked at {len(read)} file(s) (never a real .env).\n")
    if added:
        out.write("  Found:\n")
        for f in added:
            out.write(f"    {printable(f['service']):14} {', '.join(f['env_vars'])}\n")
    elif found:
        out.write("  Nothing new to add.\n")
    if not args.write:
        out.write(f"\n  This is a preview. Run `stuntkey init --write` to save "
                  f"{manifest_mod.FILE_NAME}.\n")
        return 0
    manifest_mod.save(target, data)
    out.write(f"\n  ✓ wrote {manifest_mod.FILE_NAME} (names only - safe to commit).\n"
              f"    Next: `stuntkey setup`\n")
    return 0


# ------------------------------------------------------------------ setup

def _load_manifest(out):
    path = manifest_mod.find()
    if not path:
        out.write(f"  No {manifest_mod.FILE_NAME} here. Run `stuntkey init` first.\n")
        return None, None
    try:
        return path, manifest_mod.load(path)
    except manifest_mod.ManifestError as e:
        out.write(f"  {printable(e)}\n")
        return None, None


def cmd_setup(args, catalog: dict, connect_fn, out=None,
              check_keychain=True, read=keychain_mod.read) -> int:
    """Connect every missing service, in the manifest's order. A service that
    already has all its variables (keychain or .env) is skipped; one that
    fails does not stop the others; running it again picks up where it left."""
    out = out or sys.stdout
    path, manifest = _load_manifest(out)
    if manifest is None:
        return 1
    root = os.path.dirname(path)
    try:
        env_file = _env_file(manifest, root, args.env_file)
    except manifest_mod.ManifestError as e:
        out.write(f"  {printable(e)}\n")
        return 1
    wanted = set(args.service or [])
    rows = []
    for item in manifest["services"]:
        slug = item["service"]
        if wanted and slug not in wanted:
            continue
        recipe = catalog.get(slug)
        if recipe is None:
            rows.append((slug, "no recipe", None))
            continue
        variables = manifest_mod.service_vars(item, recipe)
        where = presence_mod.locate(slug, variables, env_file,
                                    check_keychain and wants_keychain(item, root), read)
        if where["complete"]:
            rows.append((slug, "already there", None))
        else:
            rows.append((slug, "needed", (item, recipe, where)))
    todo = [r for r in rows if r[1] == "needed"]
    out.write(f"\n  {len(rows)} service(s) in {manifest_mod.FILE_NAME}: "
              f"{len(todo)} need a key, {len(rows) - len(todo)} done or skipped.\n")
    if args.dry_run:
        for slug, state, _ in rows:
            out.write(f"    {printable(slug):14} {state}\n")
        return 0
    results = {}
    interrupted = False
    for n, (slug, state, payload) in enumerate(todo, 1):
        item, recipe, _ = payload
        out.write(f"\n  [{n}/{len(todo)}] {printable(recipe['display'], words=True)}\n")
        try:
            code = connect_fn(recipe, item.get("store", "env"), env_file)
        except KeyboardInterrupt:
            interrupted = True
            results[slug] = "interrupted"
            break
        results[slug] = "connected" if code == 0 else "failed"
    # summary
    out.write("\n  Summary\n")
    for slug, state, payload in rows:
        shown = results.get(slug, state)
        if payload is not None and slug not in results:
            shown = "not reached (run `stuntkey setup` again)"
        out.write(f"    {printable(slug):14} {shown}\n")
    failed = [s for s, r in results.items() if r != "connected"]
    unknown = [s for s, st, _ in rows if st == "no recipe"]
    if failed or interrupted or unknown:
        out.write("\n  Run `stuntkey setup` again to pick up where this stopped; "
                  "services already connected are skipped.\n")
        return 1
    out.write("\n  ✓ all keys are in place.\n")
    return 0


# ----------------------------------------------------------------- status

def status_rows(manifest: dict, root: str, catalog: dict, env_file: str,
                max_age: int, check_keychain: bool = True,
                read=keychain_mod.read, index_path: str | None = None,
                now=None) -> list[dict]:
    rows = []
    for item in manifest["services"]:
        slug = item["service"]
        recipe = catalog.get(slug)
        variables = manifest_mod.service_vars(item, recipe)
        where = presence_mod.locate(
            slug, variables, env_file,
            check_keychain and wants_keychain(item, root, index_path), read)
        places = []
        if where["env"]:
            places.append(os.path.relpath(env_file, root) if root else env_file)
        if where["keychain"]:
            places.append("OS keychain")
        entry = ledger_mod.get(root, slug, index_path)
        age = ledger_mod.age_days(entry, now)
        if recipe is None and not variables:
            state = "no recipe"
        elif where["complete"]:
            state = "stored"
        elif places:
            state = "partly stored"
        else:
            state = "missing"
        hint = None
        if state == "missing":
            hint = f"stuntkey connect {slug}"
        elif age is not None and age >= max_age:
            hint = (f"{age} days old (limit {max_age}) - consider `stuntkey rotate {slug}`"
                    f" (or `stuntkey panic {slug}` if it may have leaked)")
        elif state == "partly stored":
            hint = f"missing {', '.join(where['missing'])} - stuntkey connect {slug}"
        rows.append({"service": slug, "state": state, "where": places,
                     "missing": where["missing"],
                     "added": (entry or {}).get("created_at"),
                     "rotated": (entry or {}).get("rotated_at"),
                     "age_days": age, "hint": hint,
                     "recipe": recipe is not None})
    return rows


def cmd_status(args, catalog: dict, out=None, check_keychain=True,
               read=keychain_mod.read, index_path=None, now=None) -> int:
    out = out or sys.stdout
    path, manifest = _load_manifest(out)
    if manifest is None:
        return 1
    root = os.path.dirname(path)
    try:
        env_file = _env_file(manifest, root, args.env_file)
    except manifest_mod.ManifestError as e:
        out.write(f"  {printable(e)}\n")
        return 1
    max_age = args.max_age or manifest.get("max_age_days", manifest_mod.DEFAULT_MAX_AGE_DAYS)
    rows = status_rows(manifest, root, catalog, env_file, max_age, check_keychain,
                       read, index_path, now)
    if args.json:
        out.write(json.dumps({"max_age_days": max_age, "services": rows}, indent=2) + "\n")
    else:
        out.write(f"\n  {'service':14} {'state':14} {'where':24} {'added':11} age\n")
        for r in rows:
            added = (r["added"] or "")[:10] or "(before records)"
            age = f"{r['age_days']}d" if r["age_days"] is not None else "-"
            out.write(f"  {printable(r['service']):14} {r['state']:14} "
                      f"{printable(', '.join(r['where']) or '-'):24} {added:11} {age}\n")
            if r["hint"]:
                out.write(f"  {'':14} -> {printable(r['hint'])}\n")
        out.write("\n")
        try:        # say so plainly when the activity log is not signed
            from . import broker, remote
            alog = broker.AuditLog(os.path.join(remote.home_dir(), "audit.log"))
            note = alog.describe()
            from . import logfacts
            facts_text = logfacts.log_lines(logfacts.log_facts(alog))
        except Exception:
            note, facts_text = "", ""
        if facts_text:
            out.write(f"{facts_text}\n\n")
        if note:
            out.write(f"  {printable(note)}\n\n")
        try:        # recent limit / first-use notices from the proxy
            from . import caps as caps_mod
            notices = caps_mod.recent_notices(remote.home_dir(), 5)
        except Exception:
            notices = []
        if notices:
            out.write("  Recent notices:\n")
            for line in notices:
                out.write(f"    {printable(line)}\n")
            out.write("\n")
    bad = [r for r in rows if r["state"] != "stored"]
    old = [r for r in rows if r["state"] == "stored" and r["hint"]]
    return 1 if bad or old else 0
