# Changelog

## Unreleased

### Changed (fewer tokens in the AI's context)

- **`call_api` cuts long answers at 24,000 characters** by default (`truncated: true`
  plus a short note to ask for less with the service's `limit` or fields parameters).
  New optional argument `max_chars` (1 to 1,000,000) raises or lowers it. The whole
  answer is still scrubbed for the key before it is cut. This applies to the MCP tool
  only; `stuntkey call`, the web door and the proxy are unchanged.
- **`list_services` takes `connected_only: true`** (only services with a saved key). The
  duplicate `env_var` field is gone from each row: use `env_vars` (its first entry is the
  old `env_var`). Nothing in this repo read it.
- **The MCP `tools/list` text is under 3,000 characters** (was about 5,000). The long
  `capture_key` explanation (states, waiting times) now comes in the reply to
  `request_connect` and `capture_key start` as `capture_help`. Tool names and
  parameters are unchanged; the rules (never paste a key into chat, do not retry after a
  refusal) are still in the descriptions.

### Fixed

- **A second copy of a stored key glued inside a word was left in Bash output** when
  another copy of it matched whole in the same word (`<KEY>=bot<KEY>/x`,
  `https://h/<KEY>/a?t=<KEY>`). The inside-a-word search now always runs.
- **Two stuntkey runs at once could drop a key's fingerprints or a record.**
  `fingerprints.json` and the `index.json` record are now updated under the same file lock
  the `.env` writer uses, and the fingerprint file's rename is retried a few times on
  Windows when antivirus or an indexer holds it briefly.
- `get --store` help said `.env` was the default; `get` defaults to the keychain
  (`connect` to `.env`; `rotate` keeps the key where it is).
- `stuntkey` with no command prints the four steps and exits 0 instead of an argparse
  error. A mistyped command gets a "Did you mean" line (still exit 2).
- `install` / `uninstall --help` now say it in their own description (Claude Code and
  VS Code per folder, Claude Desktop and Cursor once for all projects); `start --help`
  says to run it in your project folder; `install` with an unknown target points at
  `stuntkey setup-agent codex` (or gemini).
- `tools/list` has short descriptions again for `capture_key` `timeout_seconds` and
  `wait_seconds`, `needs_keys` `project`, and `find_public_apis` `auth` (now an enum:
  `No`, `apiKey`, `OAuth`); the list is 2,910 characters, still under the 3,000 cap.
  The server already clamps both numbers to their ranges.

### Fixed (earlier in this release)

- **Caps fail closed.** `caps.json` with a value that is not a whole number (text,
  decimal, true/false), a negative number or a limit name stuntkey does not know now
  refuses calls ("so no call was made") naming the service, instead of silently
  ignoring that cap. A usage record with a non-number now refuses the same way; a
  negative count is read as 0.
- **A key glued inside a word is now masked in Bash output** (`/bot<KEY>/getMe`,
  `/v1/<KEY>/x`, `id-<KEY>`, `<KEY>+x`). `fingerprints.json` records each stored key's
  length (not the key) for this; a file from an older version works as before until the
  key is saved again. It searches up to 8 distinct key lengths, and only the key as
  typed (not its URL-encoded or base64 form). With one stored key, 1 MB of
  ordinary prose masked in 0.02-0.04 s; 1 MB of token- or path-like text in
  0.7-1.8 s; 1 MB of 512-character words in 2.4-2.8 s (measured on one PC, timings
  vary). A hook that times out fails open: the output is shown unmasked.
- `stuntkey install` / `uninstall` with no terminal to answer on now says "no terminal
  to answer on; re-run with --yes" and exits 1, instead of a traceback.
- The README, `install --help` and `doctor` say that Claude Code and VS Code are set up
  per folder (run `install` in your project folder) and Claude Desktop and Cursor once
  for all projects; `doctor` names the folder for the per-folder ones.

### Docs

- SECURITY.md and the README now say what the Bash output mask does not detect (changed
  case, reversed text, hex, URL-safe base64, keys split across lines, keys inside a `Basic`
  header) and that stuntkey's file protection covers `.env`, `.pem`/`.key` and `~/.ssh`
  shapes plus a named list of other tools' files by name only (`.netrc`, `.npmrc`, Docker
  `config.json`, `.kube/config`, `.aws/credentials`: plain Read, `cat`, `head`, `type`
  refused; copies and scripts pass), and not GitHub CLI's `hosts.yml` or `gh auth token`.
  Each was checked with a temp key or temp home. The leakbench report footer and the
  README say `leaked=0` counts Bash output only; PowerShell and Monitor output is not
  masked.
- README: after `install`, restart the AI app; the permission window's title is shown.
- SECURITY.md named "5 leaks"; the measured numbers are `stuntkey-hook` 2 (named) and
  `stuntkey-full` 0. The documented command is now `python -m leakbench --profile
  stuntkey-hook` (the default profile `none` is the unprotected baseline). Known limits
  added, each checked with a local repro: output masking is Bash-only; glob forms
  (`cat ./.e*`, `cat .en[v]`) and paths built at run time pass the pre-call hook; stored
  keys over 512 characters, or containing a space or one of `; , ( ) & |` or a quote, are
  not masked by the hook.
- leakbench: 63 probes (two new: key in a URL path, `curl -v` request line). `none` 0/0/56,
  `stuntkey-hook` 47 blocked / 14 masked / 2 leaked, `stuntkey-full` 49/14/0. README no
  longer says "every `.env` read" is blocked, and says the spend probes test the counter,
  not an agent loop.

## 0.9.1

### Added

- **`stuntkey mint <service>`** makes a fresh key at the vendor by API, checks it and saves it
  in the keychain: no copy, no paste, never shown. Cloudflare only. It needs a one-time
  key-maker token (`stuntkey get cloudflare-keymaker`, new built-in recipe) that may only
  create API tokens, and goes only to api.cloudflare.com. A recipe's `"mint"` block names
  the permissions and account. A re-mint deletes the key made last time.
- **`stuntkey get` takes any site.** `stuntkey get example.com` (or a name) opens a
  search for the site's key page, takes the key when you click Copy, and saves it
  in the keychain with a recipe that sends it only to that site's `api.` host.
  The key is saved untested, and stuntkey says so.

### Fixed

- **The hook now reads code before it is saved.** A Write, Edit, MultiEdit or
  NotebookEdit whose new text would print the environment (`print(os.environ)`,
  `console.log(process.env)`) or open a `.env` file is blocked, because a
  saved script's output cannot be masked afterwards. Prose and ignore files
  (`.md`, `.rst`, `.gitignore`, `.dockerignore`) are not scanned. A `.env`
  name counts only on a line that also prints or dumps a file, so
  `load_dotenv('.env')`, `cp .env.example .env` and `COPY .env .` stay
  writable. A `.env` read into a variable that a later line prints is caught
  too. Environment dumps are recognised in Python (`environ`, `.items()`,
  `pprint`, `logging`), JavaScript (`JSON.stringify(process.env)`,
  `process["env"]`), Go (`os.Environ()`), Ruby (`puts ENV`) and code that
  runs `env`/`printenv`. Code that hides what it does can still get past it.
- A write larger than 2,000,000 characters is refused, so padding a file can
  not carry code past the scan.
- The hook no longer crashes on a `tool_name` that is not text.
- `get`: no more "Press Enter to save it" after the key is taken from the clipboard.
  A wrong copy is still caught: the vendor check must pass before anything is
  saved. The hidden paste prompt now shows a `*` per character and takes a paste
  without Enter. A plain "Your <service> key has been added." ends a good save.
- Windows: many programs saving keys to the same `.env` at once could fail
  with "Permission denied" while another one was releasing the lock. They
  now wait and retry.
- `scan` no longer reports MCP tool names in a settings allow-list
  (`mcp__plugin__tool`) or AWS's documented sample key pair as keys.
- leakbench: `stuntkey-hook` 47 blocked / 12 masked / 2 leaked (was 44/12/5);
  `stuntkey-full` 49/12/0 (was 46/12/3).

## 0.9.0

### Renamed

- **OathKey is now StuntKey.** The command, the Python package and the PyPI project
  are `stuntkey` (formerly OathKey, and before that SafeEasyAPI). The home page is
  https://calasautomations.com/devtools/stuntkey/ and the code moves to
  https://github.com/calasdan-sketch/stuntkey.
- **Your 0.8 data comes along; nothing old is deleted unless you ask.**
  - The first run copies `~/.oathkey` to `~/.stuntkey` (only when `~/.stuntkey`
    does not exist yet) and says so once. The old folder stays as it was.
  - Keys saved in the keychain as `oathkey:<service>` are still found there.
    `stuntkey migrate` copies each one to its new name, reads the copy back, and
    never shows a key; `--remove-old` then deletes the old entries. `stuntkey
    doctor` reminds you until it has run cleanly.
  - An old `oathkey.json` or `oathkey.policy` is used when the new file is absent,
    with a note.
  - `stuntkey install` and `stuntkey hook install` find the `oathkey` MCP entry and
    hook that 0.8 wrote, show the change, ask, and replace them (`hook install --yes`
    does not ask). `doctor` points out any that are left. The project rules block
    0.8 added is replaced too.
  - The hook keeps guarding the old `~/.oathkey` folder and the old `oathkey`
    command as well as the new ones.
  - `pip install oathkey` (0.9.0) now installs stuntkey; the `oathkey` command says
    "oathkey is now stuntkey" and passes the command on. The `safeeasyapi` package
    (0.10.0) points at stuntkey too.
- Environment variables are now `STUNTKEY_*` (for example `STUNTKEY_HOOK_ALLOW_WRITE`).

### New

- **Use a key from ordinary code without handing it over.** `stuntkey proxy -- CMD`
  (or `--print-env` for a tool you start yourself) points the OpenAI, Anthropic, Groq
  and Together SDKs at a local stuntkey address and gives them a throwaway password;
  stuntkey adds the real key on the way out and scrubs it from the answers. No
  certificate tricks: it only works with SDKs that let you change the base address.
- **Spending limits and a kill switch.** `caps show|set` puts a per-key limit on calls
  per session, calls per day and tokens per day, counted across every program that
  uses the key. `stop` refuses every brokered and proxied call at once; `resume`
  (asks you first) lets them through again.
- **Route policy.** A `stuntkey.policy` file lists which methods and paths each service
  may use. A project's file can only narrow your own, and a new or changed file is
  obeyed only after `policy approve`. `policy show` prints what is in force.
- **"I leaked a key": `panic <service>`.** Asks first, revokes the key (through the
  official API for GitHub and Vercel; for others it opens the revoke page and waits),
  gets a new one with the `get` flow, then shows where the old key is still written
  (the project, .env files, MCP configs, git history). Terminal only, never offered to
  an AI. Recipes can name their revoke page with the new `revoke` field, and `status`
  now suggests `rotate` (or `panic`) when a key is past its age limit.
- **Keys in MCP server settings.** `scan` now reads the MCP configs of Claude Desktop,
  Claude Code, Cursor, VS Code, Windsurf, Codex, Gemini and Zed. `wrap` moves a key
  from a server's `env` into the keychain and starts the server through `stuntkey run`;
  `--all --dry-run` previews every server, `--undo` restores the old settings, and
  `--file` picks a config file.
- **Keys your website ships to visitors.** `scan --bundle dist/` or
  `scan --bundle https://your-app.com` finds secret keys in built front-end code
  (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_` and known key formats).
- **Local recipes.** A recipe marked `"local": true` may use plain http, but only to
  this computer (127.0.0.1, localhost or [::1]), so the key never leaves the machine.
  For AI routers on your PC such as freellmapi or OmniRoute.
- **A stronger Claude Code hook.** It now blocks commands that dump the environment
  and reads of private keys and credentials files, and after a Bash command it masks
  stored keys (and text in a known key format) in the output before the AI sees it.
  `hook install --project` can also add a short "use stuntkey for keys" block to the
  project's CLAUDE.md / AGENTS.md / .cursorrules. Hook commands now start the same
  stuntkey that installed them, so `hook install` works from `stuntkey.pyz` too.
- **One scrubber.** Key scrubbing now goes through one shared scrubber, which also
  catches a key written backwards or in UTF-16.
- **Easier installs.** Each release has `stuntkey.pyz` (one file, any Python 3.10+)
  and a Windows portable zip. winget manifests (`Calas.StuntKey`) and an
  `npx stuntkey` package are prepared. `start --simple` walks people who build with
  Lovable, Bolt, Replit or Vercel through it one plain question at a time, and
  `install` ends by showing which AI tools are connected.
- **Agent Leak Benchmark** (`python -m leakbench`): 61 ways an AI coding agent can
  expose a key. With no protection 54 leak; with `stuntkey-full` 58 are stopped (46
  blocked, 12 masked) and 3 still leak: scripts the AI writes that print a secret
  when they are run later.
- **Trust kit.**
  - docs/THREAT_MODEL.md: what stuntkey protects, from whom, and where it stops.
  - SECURITY.md: report privately by GitHub advisory or security@calasautomations.com;
    90-day disclosure; security reports are never closed as stale; supported versions.
  - `selftest` and `doctor` print a beta notice.
  - README: a simpler first path (get, install, doctor), how SDK code works today, how
    the permission windows behave, and what stuntkey does not do.
  - CONTRIBUTING: a recipe template and how to submit community recipes.
  - Releases publish build provenance attestations, a SHA256SUMS file and a GitHub
    release; actions are pinned by commit SHA; an OpenSSF Scorecard workflow was added.

## 0.8.0

oathkey joins two lines of work: the key-capture line (0.7.x: `capture_key`,
`allow-agent`, the consent window, the Claude Code hook, `oathkey.json`) and the
call-broker line.

- **New: your AI can use a key without holding it.** `oathkey call`, the MCP
  `call_api` tool and `oathkey serve` make the request for the AI: the real
  address only (https, public servers only, no redirects), the key added by
  oathkey, any trace of the key removed from the answer. Writes wait for your click.
- **New: tamper-evident activity log** (`audit verify|show|reset`).
- **New: `oathkey selftest`**: 73 simulated attacks against oathkey's own rules.
  It does not test the live network layer and is not a security audit.
- **New: `install` / `uninstall`** into Claude Desktop, Cursor, Claude Code and VS Code,
  plus `remote`, `trust-server`, `deploy`, `start`, `overview`.
- **New: `scan-git`** (git history and a pre-commit hook). `scan` is unchanged.
- **Changed names:** the product is `oathkey`; `status` is the project key report
  and the connection summary is `overview`.
- **Changed:** a custom recipe may replace a built-in one only if it talks to the
  same server; otherwise it is ignored with a message.
- **Changed: the Claude Code hook is stricter.** It now also watches MCP tool calls
  (every text in their arguments), refuses an agent running `oathkey remote`,
  `deploy`, `trust-server`, `export`, `run`, `serve` or `call`, refuses wildcard
  paths that could expand to `~/.oathkey` (`~/.*/keys/x`), refuses writes to
  `.claude/settings.json`, `.claude/settings.local.json`, `~/.claude.json` and
  `.mcp.json`, refuses a shell command over 100,000 characters unread, and
  `hook install` now blocks the call if the hook itself fails (`--fail-open` to
  opt out). Run `oathkey hook install` again to update an installed hook.
- **Changed: sending a key to a server asks in a pop-up window** that shows the
  server's key fingerprint (the terminal only when no window can be shown); the
  key-bearing ssh connection then accepts only the key you confirmed
  (`StrictHostKeyChecking=yes`). `export --yes` counts only at a real terminal;
  elsewhere a window must be clicked.
- **Changed: `install` and `setup-agent` write `--default-store keychain`**, and the
  MCP server defaults to the keychain when there is one, so a key an AI captures
  is one `call_api` can use. `rotate` replaces the key where it is stored.
  An unknown service name exits 3 with a "Did you mean" line.
- **Fixed:** `oathkey start`; `remote ... -- cmd` after `--project-dir`; the web door
  binds its port exclusively on Windows; the pop-up helper runs with a fixed
  environment. Known limits are listed in SECURITY.md.
- **A fresh start for the rename.** Nothing is migrated from the old `safeeasyapi`
  names: no data, keychain entries or settings. To move over, re-run
  `oathkey get <service>` and `oathkey install`, and remove any old `safeeasyapi`
  hook or MCP entry by hand.
- No independent security review has been done yet.

## 0.7.5

After the owner said "my AI assistant" sounded fraudulent.

- **The window names who is asking.** The MCP client's own name from `initialize`
  (`clientInfo.name`) is shown: *Claude Code wants to connect GitHub for "my-shop".*
  Known names get friendly forms (Claude Code, Claude, Cursor, Codex, Gemini CLI,
  Windsurf, Cline, Zed, VS Code ...); an unknown name is shown cleaned (ASCII, 30
  characters); none at all is "An AI program". It is what the program reports about
  itself - said in the README and SKILL, not in the window.
- **Line 1 says who made the tool:** *oathkey (free key-safe tool, made by Calas
  Automations, installed on this computer)*. New `oathkey about` and a README
  section on checking it is the real program (`pip show`, PyPI, GitHub).
- **A dead stored key is not protected by a question.** Before the REPLACE window the
  stored key is tested with the vendor; if the vendor rejects it, the replace question is
  skipped (normal capture, `stored_key_note` tells the agent). Untestable keys still get
  the replace window.
- **A closed window is never a remembered No.** The No button is told apart from a
  closed window where the platform allows it (macOS no longer has a cancel button; zenity
  uses two extra buttons); where it cannot (kdialog, old zenity) a silent exit is passed
  on as a No but is not remembered for 10 minutes. Expired and closed windows are
  `consent_expired`.

## 0.7.4

A plain-words pass on the windows, after a real person used 0.7.3 on Windows.

- **Wording.** Every window is at most five short lines, in everyday words, and says
  what is going on first: *oathkey (installed on this computer) asks: Your AI
  assistant wants to connect GitHub for "my-shop". oathkey will save the key
  safely; the assistant never sees it. Did you ask your assistant to do this? No =
  nothing is stored or changed.* The buttons are **Yes / No** on every platform (the
  macOS, zenity and kdialog buttons are now labelled Yes / No too); "Allow" and
  "Deny" are gone. The project is shown as its last folder name only.
- **Account window** leads with the account: *GitHub account: octo-cat / Is this your
  account?*
- **One question per action.** Replacing a key with no earlier permission is ONE
  window (not a permission window and then a replace window); asking again while a
  window is open never opens another.
- **Time.** Windows stay open 5 minutes (330 s) and say so. If one closes by itself
  the next status is `consent_expired` (and the account window's failure says
  "expired"): the agent is told to tell the person it expired and that they can simply
  ask again. An expired window is not a "no".
- **Windows:** the box is brought to the front and its taskbar button flashes, with the
  system question sound (all best effort; it stays top-most).

## 0.7.3

Fixes from the independent verification of 0.7.2.

- **The keychain is the authority.** `ChainSecret` reads the 0600 file only when the
  keychain returns nothing - never because the file has a "newer" counter - and
  deletes the file once the keychain saves, so a planted `consent.key` cannot take over.
- **A window, when one can be shown, is the only consent.** A permission file on disk
  (even a valid one) is ignored while a window is available; the terminal grant applies
  only with no window, or when the server runs with `OATHKEY_NO_WINDOW=1`.
- **A failing helper is not a "no".** Crashes, odd exit statuses and unsupported flags
  give `None` (`consent_needed`, ask again); only an explicit Deny is remembered.
  zenity is retried without `--no-markup` / `--default-cancel` on old versions; kdialog
  text has `< > &` removed.
- **Refusals are visible.** When a helper is on PATH but is not a trusted (root-owned)
  install, the answer says where it found it and why it was refused. Trust is not widened,
  clipboard tools included (the key passes through them).
- **Hook:** wildcards that could expand to `.oathkey` (`~/.safe*/*`, `.s*/c*`,
  `.saf?easyapi/*`, `tar c ~/.safe*`) are refused; `.*`, `man security` and friends are not.
- Lock: stale limit 180 s, stale locks are renamed away before removal; the consent
  folder is created 0700. macOS: the keychain secret is passed to `security -i` on stdin,
  not in argv. A start that fails as busy or rate-limited keeps the replace permission;
  the window check-and-set is under the lock.

## 0.7.2

Fixes from the second review of 0.7.x.

- **Helpers are trusted ones only.** `zenity`, `kdialog`, `osascript`, `security`,
  `secret-tool` and the clipboard tools are looked up only in `/usr/bin`, `/bin`
  and `/usr/local/bin`, only if root owns them and neither they nor their folder
  are writable by others, and run with a fixed `PATH` and a minimal environment
  (`safeexec.py`).
- **Honest consent.** The window's yes is kept in the server's memory for the
  session, never on disk. The terminal `allow-agent` grant in the signed file is
  advisory (a same-user program can read the secret or fake a terminal); README,
  SKILL.md and docstrings say so. The consent file carries a counter that is also
  kept with the secret, so an old copy no longer verifies; no `.bak` copies; the
  write is under a lock and the secret file is created with `O_EXCL`; a keyring
  that cannot save falls back to the 0600 file; `allow-agent` reports a grant it
  could not save.
- **Second window.** After the vendor accepts the key, a window shows the account
  (GitHub login, `[A-Za-z0-9-]{1,39}` only) and the person confirms before anything
  is stored (`confirming`, `account_confirmed_by_person`).
- **Windows.** The message box has a time limit (a timeout is not a "no" and can be
  asked again); the clipboard getter raises when it cannot open the clipboard.
- **Dialogs:** zenity `--no-markup`, ASCII-only text (look-alike letters become
  `?`), the project path cut to its last 120 characters.
- **Clipboard.** `clear_verified` is false when `clear()` reports failure or the
  clipboard cannot be read back. Strict, anchored (`\Z`, documented length)
  `capture_accept` gates for the services with a documented format.
- **Status:** a pending question makes `status` wait for the answer; an old answer
  expires; `replace_granted` says to pass `replace=true`; `bool("false")` is false.
- **Hook:** the steal rules are also applied to the quote-squashed text; `consent.key`,
  `agent-consent` and the `.oathkey` folder by relative path are protected (speed
  bump, not a lock).
- **setup-agent / skill install:** line ends, BOM and UTF-8 kept; markers must be
  paired and in order; a stale Codex entry is updated; non-text files are refused
  with a reason; shell-correct quoting of the Claude Code command.
- More tests: 94 new (helpers, dialogs, stores, replay, status wait, setup-agent).

## 0.7.1

Fixes from an independent review of 0.7.0 (security, correctness, architecture, tests).

- **Hook:** a quote-split file name (`cat .e''nv`) is now refused like `.env`.
- **Consent cannot be forged by a file edit.** The permission is asked in a window of
  the operating system shown by the MCP server (`dialog.py`; terminal route as the
  weaker fallback), and recorded in `~/.oathkey/agent-consent.json` (home from the
  user database) with an HMAC; the secret lives in DPAPI / the macOS keychain / the
  Linux Secret Service, else a 0600 file marked advisory. A file that does not verify
  is no consent. Corrupt files are kept as `.bak`, never overwritten silently.
- Replacing a stored key needs its own yes in a window; the keychain case is checked
  too; the result names the account (GitHub login).
- Agent writes only the project's `.env` (or a file the grant names); one shared
  `.env`-name rule for writer and hook; public/static/dist folders refused.
- Services without a documented key format answer `unsupported_gateless`; per-field
  gates for two-value services; a copied value must be one line without spaces;
  only a stale value shaped like the service's key is wiped, other clipboard content
  is left alone.
- The clipboard is emptied and verified (`clipboard_warning` instead of a false
  "emptied"), Windows uses the clipboard sequence number, xclip/wl-copy no longer stall.
- States `validating` and `storing`; `status` waits ~25 s and returns on any change;
  `cancel` is honest (`too_late`); a failed arm never leaves the manager busy; server
  shutdown cancels and clears; clipboard-history check fails closed.
- Hook: clipboard readers, and quote/variable-insensitive consent-file and
  `allow-agent` mentions (a speed bump, not the lock).
- Client-neutral rules; `setup-agent` for Claude Code/Desktop, Cursor, Codex, Gemini
  (absolute Python path); `skill install --for cursor|codex|gemini|all`; README
  "what is enforced where".

## 0.7.0

**Agent-driven key capture.** The person says "connect GitHub"; the agent opens
the key page, makes the key and clicks the vendor's Copy button; oathkey
takes the key from the clipboard, empties it, tests it, stores it, and tells the
agent only `stored`. Nobody opens a terminal, copies or pastes; the key is never
in the chat or on screen.

- New MCP tool `capture_key` (`start` / `status` / `cancel`), `oathkey/capture.py`.
  Background capture in the server process; one at a time; 10-180 s; six starts
  an hour; built-in recipes only; only a *changed*, key-shaped (service-shaped
  when the recipe has a format) clipboard value; the old clipboard is wiped; the
  clipboard is emptied the moment a key is taken; a rejected or unstorable key is
  kept nowhere; results hold state words, variable names, where stored and a
  length class - never the key or a part of it.
- New `oathkey allow-agent <service>` (`--revoke`, `--list`,
  `--allow-clipboard-history`): the person's one-time yes, typed in a terminal,
  kept in `~/.oathkey/agent-consent.json` (not in the project, where an
  agent could edit it). The hook refuses an agent running it.
- Windows clipboard history on: `capture_key` refuses unless the person accepted
  it when granting; the answer says so.
- `request_connect` now returns `browser` steps (from the recipe, least privilege,
  short expiry) and `rules` (never read the key field, never type it, only click
  Copy, never enter passwords/2FA/CAPTCHA - stop and ask the person). SKILL.md,
  README and the hook messages now say: use `capture_key`; ask the person to run
  `connect` only when capture is unavailable. `connect --clipboard` is unchanged.

Not tested against a real Windows/macOS clipboard in CI: the tests use a fake
clipboard and a fake vendor. See the README ("Agent-driven capture").

## 0.6.3

- **Security / UX.** The question after a key was taken from the clipboard
  ("Is that the key?") echoed whatever was typed or pasted, and a person who
  pasted the key there saw it on screen and had it accepted. Now:
  - the question is read without echo (a password-style read; from a pipe it
    shows nothing either), and the rest of a multi-line paste is discarded;
  - only Enter, y and n answer it; anything long or key-shaped is refused with
    "That looked like a key. Do not paste it here. Nothing was saved.", is not
    kept, and the question is asked again (three tries, then cancelled);
  - the wording says the key is already taken, hidden, and not to paste.
  - the same reader is used for the y/N questions that can follow a key: the
    plain-text `.env` fallback of `--store keychain`, `export`, and
    `scan --validate`.
  - the hidden paste prompt drops terminal paste markers and leftover lines.

## 0.6.2

Fixes for what the test matrix (Linux, macOS, Windows; Python 3.10-3.14) found.

- `run`: Ctrl-C that lands while the output readers are still starting no
  longer ends in "could not acquire lock for <stdout> at interpreter shutdown"
  (exit -6) or a traceback; the interrupt is held until the readers are up,
  every reader is finished before `run` leaves, and the child is never left
  running. Exit status is 130 as documented.
- MCP: JSON nested more than 200 levels deep is a Parse error (-32700) on every
  Python version; before, Python 3.14 could parse it and the reply was
  Invalid params (-32602). A reply nested deeper than that is likewise an
  Internal error on every Python (macOS 3.14 could write it).
- Hook: a `oathkey` program in the current folder is never used as the hook
  command, also when the folder has another spelling (macOS `/var` and
  `/private/var`, links, Windows case and short names).
- `detect` does not read a symbolic link on Windows (no `O_NOFOLLOW` there).
- Tests only: Windows-aware hook, symlink, file-mode and own-recipe tests.

## 0.6.1

Fixes from an independent review of 0.6.0.

**Security**
- A redirect from a query-auth check (OpenWeather, your own recipes) no longer
  prints the address with the key in it: only scheme, host and path are shown,
  and every validation error is scrubbed of the key and its encodings.
- The hook also refuses `oathkey run --no-redact`, keychain readers
  (`secret-tool`, `security find-generic-password`, `cmdkey`, `Get-Secret`,
  `keyring`), `/proc/*/environ` and `~/.oathkey`. `run --no-redact` is
  refused unless input and output are a terminal. Agent-facing text now says
  "ask the person to run it". README states plainly what an agent that can
  use `run` can still do.
- `.env` writes take a lock (20 parallel writers used to leave 7 keys), the
  read no longer follows a link swapped in after the check, and a result is
  re-read after writing.
- A manifest's `env_file` must be a `.env`-style name inside the project;
  `oathkey.json` is only looked for up to the git project's top folder
  (or the folder itself); `--project-dir` names it explicitly. `connect`,
  `rotate`, `forget` and `export` use the manifest's env file like `run`.
- The MCP output guard blanks only secret-looking values (not ordinary
  settings) and never member names. `needs_keys` stays inside the project;
  `request_connect` opens at most 3 key pages a minute in all.
- Recipe patterns that could run for ages on crafted input are refused.
- `doctor-recipes` never visits private addresses (also not through a
  redirect), and each service has a time budget. The weekly workflow pins its
  actions by commit.
- A recipe that sends the key to localhost or a private network asks you to
  confirm first. `export` names the repository / Vercel project it will send
  to, taken from the git remote / `.vercel`, and uses it explicitly.

**Behaviour**
- Copy-and-go: a stale key-shaped value is emptied, a second identical Copy is
  noticed, Ctrl-C cancels, the clipboard is emptied after the prompt fallback,
  host:port, paths, e-mail addresses and plain words are not taken as keys,
  and a key with no documented shape is confirmed (length only).
- AWS: a clock more than 5 minutes off is reported as that, not as a dead key.
- OpenAI: a 403 is "real key with limits", not a dead one.
- Redaction also catches upper and lower case forms.
- `oathkey skill install` copies the agent skill (now shipped in the wheel).

## 0.6.0

One flow from the vendor's key page into your project, and the agent never
touches a key.

**Recipes (all 36 re-checked against the vendors' own documentation)**
- Two separate ideas for a key's shape: `accept` (what `--clipboard` will
  take: only documented shapes, matched from the start, so a valid key is never
  refused - removed for Groq, Hugging Face, OpenAI, OpenRouter, SendGrid, Tavily,
  GitHub, Vercel and Cloudflare) and `detect` (what `scan` looks for: the
  commonly used shapes are kept, labelled "format is a guess"). The old
  `pattern` still works. Fixes a bug where a prefix-only gate would have been
  matched against the whole key.
- Keys that are real but limited are no longer "dead": `validate.limited` (a
  403 from a Stripe restricted key, a Supabase / Vercel / GitHub fine-grained /
  SendGrid token without that permission) and `validate.body_rules` (Resend's
  401 `restricted_api_key`). `connect` stores the key and says what it cannot do.
- `least_privilege` (shown by `connect`) and `unverified` (parts the docs do
  not confirm, shown by `connect`) on the recipes.
- Corrections: AWS uses the documented STS POST; OpenRouter checks `/api/v1/key`
  and wants a credit limit; eBay and Spotify are judged by the token call alone;
  Cohere `/v1/models`; PayPal live and `paypal-sandbox` are separate; Mailgun asks
  for the main account key; Postmark a server token; GitHub recommends
  fine-grained tokens; ElevenLabs, Vercel and Notion key pages; many "starts
  with ..." claims the vendors never made are gone; OpenWeather's two-hour
  delay and Brave's plan requirement are said plainly.
- `scan` also finds Supabase `sb_secret_` keys.

**New commands**
- `doctor-recipes`: visits each recipe's key page, docs and test server over
  HTTPS with no key and reports moved or gone pages (exit 1 on rot). A weekly
  GitHub Action keeps one issue up to date. `CONTRIBUTING.md` and a pull
  request template ask for a docs link and a fake-key test. A real run found
  three moved pages, now fixed.
- `init`, `setup`, `status` and `oathkey.json` (names only, committed):
  detect the services a project uses (never opening a real `.env`), connect every
  missing one in order (skipping those already stored, resumable), and list where
  each key lives and how old it is, with a rotate hint after 90 days (a small
  local record holds dates, never keys).
- `run` reads the keychain or the `.env` file, `--all` injects every service in
  the manifest, and the program's output is scrubbed of the key by default
  (`--redact`; exact value, base64, hex, URL- and JSON-encoded forms;
  `--no-redact` to turn it off). The limits are in the README.
- `export <service> --to github|vercel`: through `gh secret set` / `vercel env
  add`, with the key on standard input only, never in a command line.
- MCP tools `request_connect` and `needs_keys`: the agent asks, the person runs
  `oathkey connect` in their own terminal. Answers hold names and statuses
  only; a second filter blanks any reachable secret. The hook message and the new
  `skills/oathkey/SKILL.md` point agents at this.
- Windows: `--clipboard` falls back to the hidden prompt when clipboard history
  (Win+V) is on, because the history keeps a copy this tool cannot remove
  (`--allow-clipboard-history` overrides).
- Error messages no longer repeat an unknown service or tool name that is long
  or odd (it could be a key pasted in the wrong place).

**Tests** run with no real network at all: any connection that is not to
127.0.0.1 fails the test.

## 0.5.2

- The hook now also covers `Edit`, `Write`, `MultiEdit` and `NotebookEdit`:
  they are refused for a real `.env` file (a key the agent writes has passed
  through the agent, and a `Write` can overwrite yours). Templates
  (`.env.example` ...) stay writable. The agent is told "Claude can't write to
  .env - your keys stay out of the chat. Run: oathkey connect <service>
  (or edit the file yourself)."
- `OATHKEY_HOOK_ALLOW_WRITE=1` (in Claude Code's environment) allows
  those writes; reads stay refused.
- `hook install` upgrades an older install's matcher in place (only our own
  entry); `hook status` says OUTDATED when the matcher is the old one.

## 0.5.1

Fixes from a security review of 0.5.0.

- `scan` can no longer be made to hang: the `NAME=value` pattern was
  quadratic (20,000 `A`s on one line took 9-26 seconds, a 1 MB file ten
  minutes). Every pattern now runs on bounded pieces of a line, each file has
  a 10-second budget, and a long minified line is scanned in 8 KB pieces
  instead of being cut off after 20,000 characters.
- `scan` no longer says "no keys found" after a partial look. Only files that
  will be read count toward the limits (an agent file behind 50,000 empty
  files is found), build output (`target`, `build`, `dist`, `.next` ...) is
  skipped, and when any limit is hit (too many files or folders, too deep, a
  folder or agent file that could not be read, out of time) the report says
  `INCOMPLETE` and the exit status is 2 (`--fail-on` never gives a clean 0).
  JSON has `incomplete`; SARIF has a notification.
- `scan --validate`: a key found only by its variable name is no longer sent
  to the service its name suggests unless it has that service's key format
  (a wrong guess used to send a key to the wrong vendor and then say "delete
  the line"). Only a 401 means rejected, now worded "rejected ... may not be
  an X key; rotate it if you are unsure"; a 403 is "could not be checked".
  Names with `webhook`, `anon`, `maps` or `public` are never matched to a
  service. With no terminal and no `--yes` the report is still printed (keys
  "not checked") instead of being dropped.
- `scan` uses only the recipes shipped in the package. Your own recipes in
  `~/.oathkey/recipes` (their regular expression and the host a key is
  sent to) are used only with the new `--my-recipes`, under a timer, and with
  `--validate` they need a typed `y` every time, even with `--yes`.
- `scan` finds more: a PEM private key on one line inside JSON, a password in
  a connection URL, `*_PASSWORD` names, an unnamed `Bearer <token>`, Slack and
  Discord webhook URLs, Stripe `whsec_` secrets, and UTF-16 `.env` files
  (what PowerShell's `>` writes). A stand-in is recognised by word, not by
  letters inside a key, so real keys containing `abc123` or `fake` are no
  longer thrown away. Trailing `.`, `-`, `_` are no longer part of a match
  ("the key is sk-...abc." redacts and validates the key, not the full stop).
  The same file reached through a link is reported once, under its real path;
  the "skipped" line states the real reasons.
- `hook status` no longer runs a command read from a settings file (a cloned
  repository's `.claude/settings.json` could run anything). It tests only the
  command this installation would write, without a shell.
- The hook now also covers PowerShell and Monitor (it missed both). `hook
  check` reads all of its input however big; input too big or not JSON is
  searched for a `.env` name as text. New `hook install --fail-closed`
  (`onFailure: block`, Claude Code 2.1.295+).
- The hook is recognised by a `statusMessage` marker or by the exact command
  0.5.0 wrote, not by "ends with hook check". It always installs into a group
  of its own; another group's matcher and handlers are never edited.
- Windows: the hook is written in the documented exec form (`command` +
  `args`) so a backslash or space in the path survives Git Bash and
  PowerShell; `--shell-form` is the fallback for an older Claude Code. The
  self-test starts the hook the way Claude Code does (no shell). Not run on a
  real Windows machine - see the README.
- Settings are written through a symbolic link; every change gets its own
  backup in `~/.oathkey/backups` (not once, and not inside the project).
- The release workflow now requires the tagged commit to be on `main`, the
  tests to pass first, the sdist's own tests to pass, and has time limits.
- README: what the hook does NOT stop; what `--fail-on live` does with keys
  that could not be checked.

## 0.5.0

- New: `oathkey scan [PATH]` finds API keys that leaked into files an AI
  agent can read (`.env*`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursorrules`, the `.claude` folder, `.mcp.json`) and says, for each one,
  where it is and what to do. Offline by default; a key is shown as at most
  its first 4 and last 2 characters; stand-in values are ignored. It skips
  `.git`, `node_modules`, binaries, files over 1 MB, pipes, devices and links
  leading outside the folder.
- `scan --validate` asks each key's own service whether it still works
  (`live` / `dead` / `unknown`). It prints the host first and needs a `y` or
  `--yes`; https only; a check on another domain still needs a typed `yes`.
- `scan --json`, `--sarif` (SARIF 2.1.0), `--fail-on live|any`, `--all`.
  Exit status 0 clean, 1 keys found, 2 could not run.
- New: `oathkey hook install | uninstall | status` adds a Claude Code
  PreToolUse hook that refuses Read, Grep and Bash calls touching `.env`
  files (templates like `.env.example` are allowed). It merges into
  `~/.claude/settings.json` (or `--project`), never overwrites other hooks,
  and is safe to run twice. `hook check` is the hook itself.
- The built-in key formats are now also used to recognise a key anywhere in
  a file, not only on the clipboard.

## 0.4.2

- Safer on Windows: `icacls` is started from the Windows System32 folder and
  `gh` (for `--via-cli`) by its full path, never from the current folder, so a
  cloned repository cannot slip in a program of its own.
- The `.env` file is locked to its owner before the key is written into it,
  not after.
- After saving to `.env`, a warning if the file is inside a git repository and
  not ignored by it.
- `--store keychain` no longer falls back to a plain-text `.env` on its own:
  it asks `[y/N]` (default no) and, with no terminal to ask on, saves nothing
  and exits 1. A key stored in the keychain is read back to confirm it is there.
- A recipe of your own in `~/.oathkey/recipes` that replaces a built-in
  one is now announced in `list` and at the start of `connect`.
- Copy-and-go never takes a link as the key, says plainly that the clipboard
  is emptied, and 8 built-in recipes (OpenAI, Anthropic, Groq, Hugging Face,
  Replicate, SendGrid, Tavily, OpenRouter) recognise their own key format.
- A folder named `.env` is refused before the browser opens.
- Packaging: GitHub Actions run the tests on Linux, Windows and macOS (Python
  3.10, 3.12, 3.14) and build the package; tagged releases publish to PyPI.
  `.gitattributes` keeps line endings consistent. Python 3.14 and the three
  operating systems are listed in the package metadata.

## 0.4.1

- The public-API list ignores a cache dated in the future.
- Recipes saved with a byte-order mark load.
- Windows device names (`nul`, `con`, ...) are refused as recipe names.
- `forget` looks the Secret Service entry up first.
- HTTP error responses are closed.

## 0.4.0

- Copy-and-go (`--clipboard`), two-value credentials, every common check
  (headers, basic, field, query, OAuth2 client credentials, AWS SigV4),
  `--via-cli`, 6 new recipes.

## 0.3.3

- Recipes may contain non-breaking spaces and emoji; closed standard streams
  give one line; `forget` says what it removed.

## 0.3.2

- `.env` values that are safe to `source`; hostile recipe text is escaped;
  validation uses GET/HEAD only; keychain timeouts; public-suffix heuristics.

## 0.3.1

- Byte-exact `.env` saves, no writes through links, CRLF and duplicate keys,
  international host names, MCP error codes, closed pipes on Windows.

## 0.3.0

- Registrable-domain comparison, safer key saving, `forget`, 25 verified
  recipes.

## 0.2.0

- Stops redirect key leaks, private `.env` writes, install layout fix, OS
  keychain storage.
