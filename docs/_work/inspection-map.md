# StuntKey inspection map (2026-11-10)

Base: branch `fix/stuntkey-perfect` = `improve/expert-rounds` @ 93be93d (version 0.9.1). Tests: 1978 passed, 98 skipped, 2 xfailed, 1624 subtests, 157s (HOME/USERPROFILE/APPDATA/LOCALAPPDATA/STUNTKEY_* in a temp dir).

## Installed 0.9.0
- C:\Users\danie\AppData\Local\pipx\pipx\venvs\stuntkey\Lib\site-packages\stuntkey (+ stuntkey-0.9.0.dist-info), exe C:\Users\danie\.local\bin\stuntkey.exe, Python 3.13.14. No direct_url.json: plain wheel (PyPI or local wheel), not editable.
- 50 .py modules + recipes/*.json + skill/SKILL.md. Every .py is byte-identical (git blob hash) to branch feat/oathkey-0.9 (ff13711). Differs from main in 6 files (broker, extras, mcp, proxy, scan, scrub: main = four leak fixes), from release/0.9.1 in 13 files, from improve/expert-rounds in 20 files. Missing vs repo: anysite.py, mint.py (0.9.1 additions).
- shim-0.9.0 branch is the old `safeeasyapi` shim package (pyproject 0.8.0), not what is installed.

## Commit 1060d70
Does not exist: `git cat-file -t` fails; not in `git log --all`, reflog, fsck dangling objects, any worktree, stash (empty). Nothing is missing from improve/expert-rounds.

## Branch graph
improve/expert-rounds is a linear superset: every other branch has 0 commits not in it (main 10 behind, release/0.9.1 5, feat/oathkey-0.9 15, install-wave2 30, wave3 25, fix/sdist-leakbench 12, other feat/* 39-40, shim 43). Working tree clean. No merge needed. Tip commits: 93be93d hook status flags old post matcher; 714baf9 work alongside Monomem; 098fd6c expert round 3; b840cec round 2; 97746e2 round 1; 08fd7c3 (release/0.9.1) get: no Enter after copied key. Tests test_round2..11 exist.

## Package map (stuntkey/, bytes)
- cli.py 57118: main() :814, argparse :55-370, `get` registered :187, dispatched :967-968
- anysite.py 6198: `get` for sites without recipe (:122)
- connect.py 30691 guided connect; capture.py 42666 agent-driven capture; clipboard.py 12564 copy-and-go; safeprompt.py 7433 post-key prompts; consent.py 20096; allowcmd.py 5519; dialog.py 15956 OS yes/no; approve.py 6015
- store.py 37108 .env + locks; keychain.py 22999 Windows Credential Manager via ctypes; ledger.py 5271 key dates (index.json); presence.py 2162
- broker.py 33060 (class AuditLog :555); policy.py 6456; caps.py 10470; proxy.py 17287 (child_env :66; caps/stop/resume/policy cmds); runner.py 5220; httpd.py 6892
- mcp.py 31056 stdio MCP; mcpwrap.py 34481; agent.py 16397; agentsetup.py 11374; clients.py 10379
- hook.py 71751 (.env guard, env dumps, PostToolUse mask, matcher); scrub.py 21179; redact.py 1749
- scan.py 61271; bundle.py 10968; gitscan.py 15444; detect.py 4641
- recipes.py 41215 (+recipes/*.json); validate.py 27759; doctor.py 11721; export.py 9593; mint.py 6469; panic.py 11154; remote.py 18999; selftest.py 26304
- extras.py 12669 (parsers: remote, scan-git, doctor, install, uninstall, start, overview, audit, call, serve, selftest); cmds.py 11886 handlers; projectcmds.py 10688 init/setup/status; manifest.py 9950; migrate.py 10053; aboutcmd.py 1122; skillcmd.py 3994 + skill/SKILL.md; publicapis.py 6492; procs.py, safeexec.py helpers
- Other dirs: leakbench/, tests/ (85 files), shim/, shim-oathkey/, packaging/ (npm, winget, pyz), .github/workflows.

## CLI commands
get, list, forget, allow-agent, add, run, init, setup, status, export, skill install, mcp, setup-agent, about, migrate, find, hook (subcommands), scan, wrap, remote, scan-git, doctor, install, uninstall, start, overview, audit, call, serve, selftest, mint, proxy, caps show/set, stop, resume, policy. Entry: `stuntkey = stuntkey.cli:main`.

## Docs / branding
README.md 186 lines, docs/guide.md 1285, THREAT_MODEL.md, packaging.md, CHANGELOG, SECURITY, docs/demo.svg (only image). No HTML/CSS/landing page in the repo; only a tiny local httpd door. Homepage URL https://calasautomations.com/devtools/stuntkey/ is external. No brand assets (crest/logo/colours) in repo; branding is text only (Calas Automations Inc. in metadata and `about`). Error messages: cli.py (:52-56), mcp.py:368, mcpwrap.py:744, per-module.
