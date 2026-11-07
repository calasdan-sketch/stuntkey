# Round 4: what a stranger gets from `pip install`

Date: 2026-11-07 (UTC). Branch `expert-2`. Honest note first: the sandbox this ran in
had no tool for starting independent reviewers, so one author played every role
below in turn. The roles changed what was run; they are not independent opinions.
Nothing was run on Windows or macOS. Python 3.10 was not installed (syntax-checked
with `ast.parse(feature_version=(3,10))`: clean); 3.11, 3.12 and 3.13 ran.

Baseline: 2,047 passed / 6 timing failures (`test_padded_prompts_check_in_under_two_seconds`,
`test_typical_output_is_fast`; the machine's load average was 6-16 on 2 cores, so the
timings are not meaningful). leakbench: hook 121/31/4, hook+caps 125/31/0 of 156.

## Specialists and findings

| Role | What it ran | Found |
|---|---|---|
| First-time user (README only, clean venv, folder with spaces) | `python -m build`, install wheel, `--version`, `start`, `doctor`, `list`, `selftest`, `get`, `gett` | Works. `doctor` said FIX for a missing `ssh`/`git` (optional) and the keychain line gave no command. `get` with no keychain and no terminal fails with a clear sentence and writes nothing. |
| Release engineer | `twine check --strict` on sdist and wheel; listing both; entry point; PyPI/npm lookups | Metadata consistent (author, URLs, MIT, Python >=3.10, version 0.11.0 in pyproject, `__init__`, npm package.json). Registry has 0.9.0 only; npm name `stuntkey` is unpublished (404). No tests/secrets/personal paths in the wheel. No `py.typed`: not added, it is a command-line program, not a typed library. |
| Supply-chain reviewer | wheel contents, imports of all 51 modules in a clean venv, `test_stdlib_only` | No runtime dependencies; stdlib only. sdist carries `.github`, tests, leakbench (intended). |
| Docs/DX writer | link check of the README as PyPI shows it | Four relative links broke on PyPI; `python -m leakbench` is not in the wheel but the README implied it was. Fixed. |
| Hostile-input fuzzer | 55 odd command lines (escape and bidi characters, bad numbers, `..` paths); 30 MB file, binary file, symlink loop, dangling link; invalid UTF-8; hook input of 20 MB, invalid UTF-8, 100,000 `[` | One terminal code echoed by `find`. Everything else: no traceback, no key in any output (`scan --json` checked for the fake key: 0 hits). |
| Environment tester | `HOME=/dev/null/x`, `HOME=/proc/...`, `LC_ALL=C/POSIX`, `PYTHONIOENCODING=cp1252/ascii`, unicode folder names | Tracebacks from `overview`, `audit show`, `stop` when the home folder is unusable. Encodings and locales fine. (Running as root, a read-only chmod does not bite, so a true read-only disk was simulated with a path under a file.) |
| Windows reviewer (static only) | grepped signals, `fcntl`/`termios`/`pwd`, `os.replace`, `O_NOFOLLOW`, quoting | Earlier rounds already guard `SIGALRM`, `fcntl`, `pwd`, `O_BINARY`, quoting of hook paths. One gap: `os.replace` onto a briefly open file has no retry (except in `consent.py`). Fixed with `fsutil.replace`. A paste prompt on a terminal without echo control would show the key. Fixed. Not run on Windows. |
| CI/CD integrator | read `ci.yml`, `release.yml`; built the `.pyz` and Windows zip in scratch | CI already builds, `twine check --strict`s and installs the wheel on Linux, and runs tests on 3 OSes x Python 3.10/3.12/3.14. The `.pyz` builds, runs from a folder with spaces and includes the new module. `install` exits 0 even when it skipped a broken config: fixed (exit 1). |
| Competitor maintainer (read-only, 2026-11-07) | fetched Infisical Agent Vault and Pipelock pages | Agent Vault: forward proxy keeps the key out of the agent; account and an enrolled proxy needed; listed as preview. Nothing stated about `.env` blocking or masking. Pipelock: 65 DLP patterns, filesystem sentinel, Ed25519-signed checkpoints, cites a public attack corpus, publishes no score. README comparison cells updated to say so. 1Password and ggshield cells were not re-fetched (unverified this round). |
| Performance engineer | timing of `--version` and `hook check` x5 | About 0.1 s CPU per start-up; the console entry is pinned, so a lighter one was not built (unchanged from round 3). |

## Ideas, scored (value / difference from others / effort / risk: H M L)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Plain sentence instead of traceback for unusable home folder / unexpected error | H | L | L | L | DONE |
| 2 | Refuse the key paste when the terminal cannot hide typing | H | H | L | L | DONE |
| 3 | `doctor`: ssh/git are information; keychain advice per system | H | L | L | L | DONE |
| 4 | Windows rename retry (shared helper) | M | L | L | L | DONE (unrun on Windows) |
| 5 | README links work on PyPI (+ test) | M | L | L | L | DONE |
| 6 | Say `leakbench` is not in the wheel | M | L | L | L | DONE |
| 7 | `install` keeps file permissions, explains bad JSON, exit 1 on skip | M | L | L | L | DONE |
| 8 | Note that Claude Code/VS Code entries are per folder | M | L | L | L | DONE |
| 9 | `find` escapes terminal codes | L | L | L | L | DONE |
| 10 | Re-check competitor cells | M | M | L | L | DONE (2 of 6) |
| 11 | Remove unused imports | L | L | L | M | DONE |
| 12 | Hook refuses a tool call whose command is not text (fail closed) | M | M | L | M | NOT-DONE: a prior test says bad shapes must not block; a format change in Claude Code would then block every command. Needs Dan's decision. |
| 13 | Faster `hook check` start-up (lazy imports) | M | M | M | M | NOT-DONE (entry pinned by tests/installs) |
| 14 | Ship `leakbench` inside the wheel as `stuntkey bench` | M | H | M | M | NOT-DONE (a new command, grows the wheel) |
| 15 | `install` keeps CRLF/BOM of a config file (it rewrites with LF, no BOM) | L | L | L | L | NOT-DONE (JSON stays valid) |
| 16 | Per-user Claude Code install (not per folder) | H | M | M | H | NOT-DONE: needs Claude Code's documented user-level config, not verified here |
| 17 | Signed audit checkpoints | M | H | H | M | NOT-DONE (needs Ed25519; stdlib lacks it) |
| 18 | Time-bound agent sessions / per-agent identity | M | H | H | M | NOT-DONE (server feature) |
| 19 | Strict opt-in block of `curl -H "Authorization: ..." other-host` | M | H | M | M | NOT-DONE |
| 20 | Real-Windows and real-macOS manual test pass | H | L | M | L | NOT-DONE (no machine) |
| 21 | Publish a Python 3.10 CI result in the checklist | M | L | L | L | NOT-DONE (CI runs it; look at the run) |
| 22 | npm package publish | L | L | M | M | NOT-DONE (needs the `.pyz` in the package; Dan's call) |
| 23 | winget manifest for 0.11.0 | L | L | M | L | NOT-DONE (needs a release asset hash) |
| 24 | Re-fetch 1Password / ggshield / agent-airlock pages | M | L | L | L | NOT-DONE |

## What could not be tested

Windows and macOS (keychain, permission windows, rename retry, echo behaviour).
Python 3.10 at run time. A real `stuntkey get` against a real service: this
sandbox's network proxy answered 200 to a made-up GitHub token, so one `get` run
sent a fake, runtime-built token to api.github.com; after that, network was
pointed at a dead address. No real key was used or stored. Live keychains (none on
this host). Timing tests under a quiet machine.

## Not changed on purpose

Round 3's "Not built" list stands. Version stays 0.11.0.
