# Round 5: saving any key, and reading odd-shaped tool calls

Date: 2026-11-08 (UTC). Branch `expert-2`. As in round 4, no tool for starting
independent reviewers was available: one author played each role in turn and ran
real commands for each. Nothing was run on Windows or macOS; Python 3.10 was not
installed (3.13 ran). The author line was already "Calas Automations Inc." on
arrival (pyproject, package.json, LICENSE, `about`, shims); a test now pins it.

Baseline (before changes): 2,063 passed, 3 timing failures (load average 6-12 on
2 cores). leakbench: hook 121/31/4, hook+caps 125/31/0 of 156.
After: see CHANGELOG "Measured". leakbench 159 probes: hook 124/31/4, hook+caps 128/31/0.

## Specialists and findings

| Role | Proving command | Found |
|---|---|---|
| Secrets-management engineer | `echo KEY \| stuntkey keep ACME_API_KEY` in a clean venv with a fake `secret-tool`; 30 concurrent `keep`s | Only ~40 services had a path; any other needed a 10-question `stuntkey add`. Built `keep`. 30/30 names survive concurrent runs (lock). |
| Incident responder | `hook check` with a pasted fake key; `panic --dry-run`; searched the home folder for the key bytes after a `keep` | Prompt block already tells the person to run `panic`. After `keep`, `forget`, no file under HOME holds the key. No defect. |
| DX designer (non-programmer) | `get` with stdin from /dev/null; `echo KEY \| keep` | "Password input may be echoed" warning appeared on a pipe, though nothing is echoed. Fixed. Unknown-service message now points at `keep`. |
| Windows credential-store specialist (static) | read `keychain._windows`, fake-ctypes tests | No size check (Credential Manager limit 2,560 bytes = 1,280 characters, per Microsoft's CREDENTIAL page; not run), bare error number, odd-length blob raised a raw decode error, key copy left in memory. All fixed. |
| macOS keychain reviewer | `keychain.store(..., MACOS, run=fake)` with a key holding a newline | Real defect: the key goes to `security -i` on stdin, so a line break started a second command. Now refused first. |
| Property-test / fuzz engineer | `tests/test_v011_round5.py::Properties` (seeded) | Found a crash: a lone surrogate (`"\ud800"` in JSON) raised in the hook's content check once any key was stored. Fixed. Scrubber: 1,500 keys x 9 forms x split points, no leak. |
| Mutation tester | `python scripts/mutation_check.py` | 19 deliberate breakages; 2 survived at first (read-back check, list joining); tests added; 19/19 caught. |
| Hook protocol reviewer (idea 12) | `hook check` with `command` as a list, renamed field, string input | Old hook let all three through (leakbench probes now leak-proof). Decision below. |
| Competitor maintainer (read-only, 2026-11-08) | fetched 1Password secure-AI-access and GitGuardian ggshield pages | 1Password cells confirmed (OpenShell placeholder gateway is labelled beta; hook only validates `.env` mounts). ggshield: blocks prompts and pre-tool actions, withholds or notifies after; allows the call with a warning when it cannot scan or log in; needs an API key. Cell updated. |

## Idea 12 decision: should the hook block malformed calls?

No blanket block; inspect instead. Reason: Claude Code's tool formats can change,
and a hook that refuses every shape it does not know would stop all work for a
non-programmer who cannot debug it (the hook is installed fail-closed). The
real danger is the opposite, a call that is ignored. So a Bash/PowerShell call
with a missing or non-text `command`, a text `tool_input`, a list `tool_input`,
or a Read without `file_path` gets every string judged with the normal rules
(list words joined). A call with nothing to run is still allowed. Anything too
large or too deep already fails closed (round 3/4). Revisit if Claude Code
documents a strict schema.

## Upgrade path (registry 0.9.0 to this tree)

`pip download stuntkey==0.9.0`, install in a clean venv, `hook install` there, then
install this wheel and run `hook status` / `hook install`: the old hook entry is
recognised as stuntkey's, replaced (one group, no duplicate), and the old file is
backed up. The keychain entry names (`stuntkey:<service>`) are unchanged. 0.9.0
left no other state to migrate in that run (no keychain on this host, so a stored
key was not carried across: unverified).

## Ideas, scored (value / difference / effort / risk: H M L)

| # | Idea | V | D | E | R | Status |
|---|---|---|---|---|---|---|
| 1 | `keep`: save any key with no recipe | H | M | M | L | DONE |
| 2 | Refuse macOS values with line breaks | H | L | L | L | DONE |
| 3 | Windows size limit, plain errors, wipe buffer | M | L | L | L | DONE (unrun) |
| 4 | Hook reads odd-shaped calls (idea 12) | H | M | L | L | DONE |
| 5 | Lone-surrogate crash fix | M | L | L | L | DONE |
| 6 | No echo warning for piped keys | M | L | L | L | DONE |
| 7 | 3 new leakbench probes | M | M | L | L | DONE |
| 8 | Property tests (seeded) | M | L | M | L | DONE |
| 9 | Mutation check script | M | M | M | L | DONE |
| 10 | Golden tests (hook answers, audit CSV header, scan JSON) | M | L | L | L | DONE |
| 11 | Author line pinned by tests | M | L | L | L | DONE |
| 12 | Upgrade-path test from 0.9.0 | M | L | L | L | DONE (hook only) |
| 13 | Competitor re-check (1Password, ggshield) | M | L | L | L | DONE |
| 14 | `keep` with copy-and-go clipboard | M | M | M | L | NOT-DONE (hidden paste is enough; clipboard history risk) |
| 15 | Brokered `call` for kept services | H | H | H | M | NOT-DONE (needs an auth shape per service) |
| 16 | macOS hex mode (`security -X`) to store multi-line keys | L | L | M | M | NOT-DONE (cannot test on Linux) |
| 17 | Clear Windows clipboard history | M | M | M | M | NOT-DONE (no documented simple API; warning stays) |
| 18 | Key age / rotation reminder for kept keys | M | M | L | L | NOT-DONE |
| 19 | `keep --from-env VAR` import | M | L | L | M | NOT-DONE (adopt covers .env) |
| 20 | Per-user Claude Code install | H | M | M | H | NOT-DONE (round 4 row 16) |
| 21 | Ship leakbench in the wheel | M | H | M | M | NOT-DONE (round 4 row 14) |
| 22 | Signed audit checkpoints | M | H | H | M | NOT-DONE (needs Ed25519) |
| 23 | Faster `hook check` start-up | M | M | M | M | NOT-DONE (entry pinned) |
| 24 | Real Windows / macOS manual pass | H | L | M | L | NOT-DONE (no machine) |
| 25 | npm and winget publish | L | L | M | M | NOT-DONE |

## What could not be tested

Windows and macOS entirely (Credential Manager limit and error codes, `security -i`
parsing: the macOS quoting is checked against a small parser written here, not the
real tool). Python 3.10 at run time. A real libsecret keychain (a fake
`secret-tool` was used). Timing tests under a quiet machine (they fail when load
is high). No type checker was run (none installed); pyflakes is clean.
