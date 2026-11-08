"""Mutation sanity check: break one key condition at a time in a COPY of the
program and confirm the tests notice. A mutant the tests miss ("survived")
means a check that no test would miss if it vanished.

    python scripts/mutation_check.py            # all mutants
    python scripts/mutation_check.py hook       # only those whose name starts with hook

Nothing in the repository is changed (the copy lives in a temporary folder).
Takes a few minutes. Exit status 1 if any mutant survived.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOOK_TESTS = ["tests/test_hook.py", "tests/test_v011_round5.py", "tests/test_hook_wave3.py"]
KEY_TESTS = ["tests/test_v011_round5.py", "tests/test_round3_fixes.py", "tests/test_keychain_failures.py"]
SCRUB_TESTS = ["tests/test_v011_round5.py", "tests/test_scrub.py", "tests/test_rigour_seat.py"]

# (name, file, old text, new text, tests to run)
MUTANTS = [
    ("hook-env-name-inverted", "stuntkey/hook.py", "    return not _is_template(m)", "    return _is_template(m)", HOOK_TESTS),
    ("hook-shell-field-skipped", "stuntkey/hook.py", 'if tool in ("Bash", "PowerShell"):\n        return _strings(args.get("command"))',
     'if tool in ("Bash_",):\n        return _strings(args.get("command"))', HOOK_TESTS),
    ("hook-odd-command-ignored", "stuntkey/hook.py", 'and not isinstance(args.get("command"), str):', 'and False:', HOOK_TESTS),
    ("hook-string-input-ignored", "stuntkey/hook.py", "if isinstance(args, str) and tool in _READ_OR_RUN_TOOLS:", "if False:", HOOK_TESTS),
    ("hook-list-not-joined", "stuntkey/hook.py", 'found.append(" ".join(v))', "pass", HOOK_TESTS),
    ("keychain-cr-allowed", "stuntkey/keychain.py", '("\\n" in key or "\\r" in key)', '("\\n" in key)', KEY_TESTS),
    ("keychain-newline-allowed", "stuntkey/keychain.py", 'if backend == MACOS and', 'if False and', KEY_TESTS),
    ("keychain-win-limit-off", "stuntkey/keychain.py", "> WIN_MAX_BLOB_BYTES", "> 10 ** 9", KEY_TESTS),
    ("keychain-win-limit-off-by-one", "stuntkey/keychain.py", "> WIN_MAX_BLOB_BYTES", ">= WIN_MAX_BLOB_BYTES", KEY_TESTS),
    ("keychain-readback-skipped", "stuntkey/keychain.py", "    if back != key:", "    if False:", KEY_TESTS),
    ("keychain-win-decode-swallowed", "stuntkey/keychain.py", "except UnicodeDecodeError:", "except KeyError:", KEY_TESTS),
    ("scrub-reverse-form-dropped", "stuntkey/scrub.py", "out: set[bytes] = {raw, raw[::-1]}", "out: set[bytes] = {raw}", SCRUB_TESTS),
    ("scrub-hex-form-dropped", "stuntkey/scrub.py", "    out.add(raw.hex().encode())\n", "", SCRUB_TESTS),
    ("scrub-url-form-dropped", "stuntkey/scrub.py", "for text in (quote(secret, safe=\"\"), quote_plus(secret),", "for text in (quote_plus(secret),", SCRUB_TESTS),
    ("scrub-surrogate-guard-off", "stuntkey/scrub.py", "    except UnicodeEncodeError:\n        # a lone", "    except KeyError:\n        # a lone", SCRUB_TESTS),
    ("keep-known-service-allowed", "stuntkey/keep.py", "    if slug in catalog:", "    if False:", ["tests/test_v011_round5.py"]),
    ("keep-short-key-allowed", "stuntkey/keep.py", "if len(key) < MIN_KEY:", "if False:", ["tests/test_v011_round5.py"]),
    ("keep-control-chars-allowed", "stuntkey/keep.py", "if any(ord(c) < 32 or ord(c) == 127 for c in key):", "if False:", ["tests/test_v011_round5.py"]),
    ("keep-file-fallback", "stuntkey/keep.py", "    if backend is None:\n        err.write", "    if False:\n        err.write", ["tests/test_v011_round5.py"]),
]


def main(argv: list[str]) -> int:
    prefix = argv[0] if argv else ""
    chosen = [m for m in MUTANTS if m[0].startswith(prefix)]
    survived, killed = [], []
    with tempfile.TemporaryDirectory(prefix="mut-") as tmp:
        for name, rel, old, new, tests in chosen:
            work = os.path.join(tmp, name)
            shutil.copytree(REPO, work, ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "dist", "build", "*.egg-info", ".pytest_cache"))
            path = os.path.join(work, rel)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if text.count(old) != 1:
                print(f"{name}: SKIPPED (text to change found {text.count(old)} times)")
                continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace(old, new))
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            env.pop("PYTHONPATH", None)
            proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests],
                                  cwd=work, env=env, capture_output=True, text=True)
            (killed if proc.returncode != 0 else survived).append(name)
            print(f"{name}: {'killed' if proc.returncode != 0 else 'SURVIVED'}", flush=True)
            shutil.rmtree(work, ignore_errors=True)
    print(f"\n{len(killed)} killed, {len(survived)} survived of {len(killed) + len(survived)}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
