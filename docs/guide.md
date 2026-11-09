> This is the full guide. The short front page is the [README](../README.md).

# stuntkey

**Quickstart**

```bash
pipx install stuntkey          # Python 3.10+, no other dependencies
stuntkey scan                  # find keys an AI agent can read (works offline)
stuntkey hook install          # stop Claude Code reading your .env files
stuntkey list                  # the services it knows (37 built in)
stuntkey connect github        # opens the key page, shows the exact steps
#   paste the key when asked (typing is hidden), or use --clipboard and
#   click the vendor's Copy button; the key is tested with one API call
#   and only then saved to .env (owner-only) - or to the OS keychain:
stuntkey connect openai --store keychain
stuntkey run openai -- python app.py     # keychain key goes to that command only
stuntkey forget openai         # remove it from the keychain and .env

# a whole project at once (0.6.0):
stuntkey init --write          # list the services the project uses (stuntkey.json, no secrets)
stuntkey setup                 # connect every service that has no key yet
stuntkey status                # where each key lives, how old it is
```

The key is never displayed, never logged, never in shell history.

**Why `scan` comes first.** AI coding agents read your project's
instruction files and, if you let them, your `.env`. A key pasted into
one of those is in the agent's memory and its conversation log. Radware
(August 2026) looked at about 100,000 agent instruction files: roughly
0.69% held a real credential, and 60% of the keys it could test still
worked. `stuntkey scan` finds them in seconds and tells you what to
do about each.

stuntkey lets your AI use your API keys without holding them, and gets a key
set up in one command. Connecting a website tool usually means 40 minutes of
hunting through dashboards, imprecise docs, and fumbling a secret into the
right file. `stuntkey get github` does it in one step: it opens the exact key
page, takes the key when you click Copy (or from hidden typing), **validates it
with a test API call**, and saves it in your OS keychain.

`stuntkey connect github` is the older, longer way: it walks the saved steps and
writes the key to `.env` with owner-only permissions unless you add
`--store keychain`. If the keychain does not work, it asks before using `.env`
instead; nothing is saved to a file without your yes. The key is never
displayed, never logged, never in shell history.

## One flow: from the vendor's dashboard into your project

The promise: **a key goes from the vendor's page into your project in one
flow - no Notepad, no pasting into a terminal, never on screen, never in
shell history, never in an AI agent's chat.** Here is exactly what that
means, what you do, and what the tool does.

```bash
stuntkey connect openai --clipboard
```

| You | The tool |
| --- | --- |
| Run the command. | Shows the vendor's steps and which exact address your key will be tested against, then opens the vendor's key page in your browser. |
| Sign in to the vendor and click their "Create key" button (the tool cannot do this for you - see below). | Waits. Nothing is shown. |
| Click the vendor's own **Copy** button. | Sees a new key-shaped value on the clipboard, takes it, and **empties the clipboard**. |
| Nothing. | Tests the key with one harmless read-only request. A key that is real but limited (for example a Stripe restricted key, a Resend "sending only" key) is accepted and told so, not called dead. |
| Nothing. | Saves it to `.env` (owner-only, written so a crash cannot leave half a file) or, with `--store keychain`, to your OS keychain. It prints where, never the key. |

Without `--clipboard` the same flow ends with a hidden prompt (what you
type or paste is not shown). That is the default because it works
everywhere; `--clipboard` is the "no pasting" mode. `--via-cli` (GitHub) is
the zero-copy mode: GitHub's own `gh` signs you in and hands the token over.

Then, in your project:

```bash
stuntkey init --write      # writes stuntkey.json: service names + variable names, no secrets, commit it
stuntkey setup             # walks every service that has no key yet; safe to run again
stuntkey run --all -- python app.py   # the program gets the keys; its output is scrubbed of them
stuntkey export groq --to github      # copy a key into GitHub Actions secrets, through gh's standard input
stuntkey status            # which keys exist, where, how old; says when to rotate
```

**AI agents.** Claude Code (or any MCP client) never handles a key. The
`capture_key` tool (0.7.0) lets the agent do the whole job: it drives the
browser, makes the key and clicks the vendor's own Copy button; stuntkey
takes the key from the clipboard, empties it, tests it and stores it, and the
agent is told only `{state: "stored", env_vars, stored_in, key_length}`.
`request_connect` answers `{service, env_var, status, instructions, browser,
rules}`, and `needs_keys` lists which keys a project lacks. Only when
`capture_key` is unavailable (no clipboard access, headless, or the person
has not allowed it) is the person asked to run `stuntkey connect
<service>` in their own terminal. No tool can return a
secret value: answers are built from names and status words only, and a
second filter blanks any secret the server can reach (a variable in its
environment, a value in the project's `.env`), also in base64, hex and
URL-encoded form. A test plants canary keys everywhere and searches every
tool answer and every JSON output for them. The agent skill (the same rules, written for the agent) ships inside the package. Install it with `stuntkey skill install` (for you) or `stuntkey skill install --project` (this project only); it never overwrites a different file without asking.

### What it cannot do

- **It cannot make the key for you.** Vendor dashboards sit behind your
  login and none offers a way to mint a key without it. You sign in and click
  "Create"; the tool does everything after that. The steps shown come from
  each vendor's own documentation, and anything the docs do not confirm is
  listed in the recipe as `unverified` and shown to you.
- **It cannot keep a copy out of a clipboard history.** `--clipboard` empties
  the clipboard, but Windows clipboard history (Win+V, and its cloud sync)
  and clipboard managers (Maccy, CopyQ, Klipper ...) record a copy the moment
  you press the vendor's Copy button, and only the program that copies can
  ask Windows to leave something out of history - here that is the vendor's
  web page. Windows has settings for that (`CanIncludeInClipboardHistory`,
  `ExcludeClipboardContentFromMonitorProcessing`); they are set by the
  writer, not by a reader like this tool, so it cannot use them. What it does
  instead: on Windows, when the registry says clipboard history is on,
  `--clipboard` switches to the hidden prompt and tells you why
  (`--allow-clipboard-history` overrides). On macOS and Linux it cannot
  detect a clipboard manager: if you run one, use the hidden prompt.
- **It cannot stop the vendor's page, a browser extension or malware** that
  can read the page or your clipboard from seeing the key.
- **An agent that can run `stuntkey run` can still get the key.** The key
  lives in the child program's environment, readable by the same user, and a
  program started by the agent can print it reversed, hashed, split or
  encoded in a way redaction does not know. The hook refuses the obvious
  routes (`run --no-redact`, `secret-tool`, `security find-generic-password`,
  `cmdkey`, `Get-Secret`, `keyring`, `/proc/*/environ`, `~/.stuntkey`), and
  `--no-redact` refuses to work unless you are at a terminal. None of that
  is a wall. For a sensitive service, run agent sessions without permission
  to use `stuntkey run` (a deny rule in Claude Code), and start the
  program yourself in your own terminal: the agent writes the code, you run
  it. The MCP instructions tell agents to ask you, not to run it themselves.
- **Redaction is not a vault.** `run` scrubs the exact key and its common
  re-writings (base64, hex, URL-encoded, JSON-escaped, upper and lower case) from the program's
  output. It cannot catch a key the program hashes, truncates, reverses or
  splits across lines, one written to a file or sent over the network, or one
  shorter than 6 characters. With redaction on, the program's output is a
  pipe, not a terminal, so some programs lose colours or stop prompting: use
  `--no-redact` for those (it works only when input and output are both a
  terminal; with a pipe it is refused).
- **Copy-and-go empties the clipboard, and asks when it cannot be sure.** A
  key-shaped value already on the clipboard when waiting starts is emptied,
  so copying it again is noticed. For a service with no documented key shape,
  it tells you what it took (length and kinds of characters, never the
  characters) and asks you to confirm. Ctrl-C cancels; the clipboard is
  emptied after the hidden-prompt fallback too.
- **Two runs at once are safe.** Writes to `.env` take a short lock, so two
  `connect` runs at the same time cannot drop each other's key.
- **The `.env` file is plain text** (owner-only). The OS keychain is better.
- **The hook is a guardrail, not a wall** (see below), and `scan` finds keys by
  their shape: a key with no recognisable shape can slip past it.
- **It was not run against real vendor dashboards** for this release: the
  recipes follow the vendors' documentation, and `stuntkey doctor-recipes`
  (also a weekly check on GitHub) tells you when an address has moved.
- **`export` works only through `gh` and `vercel`** (installed and signed in);
  the key reaches them on standard input, never on a command line. Other
  destinations are not offered because no other vendor tool was confirmed to
  read secrets that way.

## Install

Zero dependencies — Python 3.10+ stdlib only.

```bash
pipx install stuntkey        # or: pip install stuntkey
stuntkey --version
```

From source: `pip install git+https://github.com/calasdan-sketch/stuntkey`.

No pip? Each release also has `stuntkey.pyz`, one file that runs with any
Python 3.10+: `python stuntkey.pyz doctor`. The first run unpacks it once into
`~/.stuntkey/pyz/`. Build it yourself with `python scripts/build_pyz.py`.
`npx stuntkey` and winget packages are prepared (see
[packaging.md](packaging.md)). `hook install` works from the `.pyz` too: the
hook then starts the same `.pyz` again.

That installs the `stuntkey` command (`py -m stuntkey` / `python -m
stuntkey` works too). From a checkout: `pip install .`

### Coming from oathkey 0.8

stuntkey was called OathKey in 0.8. Nothing
needs to be done by hand, and nothing old is deleted unless you ask:

- **Your settings folder.** The first run copies `~/.oathkey` to
  `~/.stuntkey` (only when `~/.stuntkey` does not exist yet) and says so once.
  The old folder is left as it was.
- **Saved keys.** 0.8 saved keys in the OS keychain as `oathkey:<service>`.
  stuntkey still finds them there, and `stuntkey migrate` copies each one to
  its new name `stuntkey:<service>`, reads the copy back to check it, and
  never shows a key. The old entries stay; `stuntkey migrate --remove-old`
  deletes each one after its copy checked out. `stuntkey doctor` reminds you
  until `migrate` has run cleanly.
- **Project files.** An old `oathkey.json` or `oathkey.policy` is used when
  there is no `stuntkey.json` / `stuntkey.policy`, with a note. Rename it when
  you like.
- **AI tool settings.** `stuntkey install` replaces 0.8's `oathkey` MCP
  entry, and `stuntkey hook install` (add `--project` for a project's file)
  replaces 0.8's hook. Both show the change and ask first (`hook install
  --yes` does not ask). `stuntkey doctor` points out any old entry left.
- **The old command.** `pip install oathkey` now installs a small package
  that says "oathkey is now stuntkey" and passes the command on to stuntkey.

**Windows:** run it from PowerShell or Windows Terminal. Under Git Bash /
mintty the hidden key prompt (`getpass`) may echo what you type or appear
to hang, because mintty is not a Windows console; if you must use Git
Bash, prefix the command with `winpty` (`winpty stuntkey connect
stripe`).

## Scan: find keys an AI agent can read

```bash
stuntkey scan                  # this folder, offline, nothing leaves your computer
stuntkey scan ~/projects/app   # another folder (or one file)
stuntkey scan --validate       # ALSO ask each key's service if it still works
stuntkey scan --json           # or --sarif, for scripts and code-scanning tools
stuntkey scan --all            # every text file, not just the agent-readable ones
```

It reads `.env` files (`.env`, `.env.local`, `prod.env` ...), `CLAUDE.md`,
`AGENTS.md`, `GEMINI.md`, `.cursorrules`, `CLAUDE.local.md`,
`.windsurfrules`, `.mcp.json` and everything inside a `.claude` folder. UTF-8
and UTF-16 files (what PowerShell's `>` writes) are both read. It skips `.git`,
`node_modules`, build output (`target`, `build`, `dist`, `.next` ...),
binary files, pipes and devices, and links that lead outside the folder; it
never opens anything but a regular file, so it cannot hang on one.

What it recognises: the key format of each built-in recipe (OpenAI,
Anthropic, Stripe, GitHub, AWS ...), a few well-known prefixes for services
without a recipe (Slack tokens and webhook URLs, Stripe `whsec_` signing
secrets, npm, Shopify, Google, a PEM private key - also when it sits on one
line inside JSON), `Bearer <token>`, a password inside a connection URL
(`postgres://user:PASSWORD@host/db`), and any `NAME=value` where the name
ends in `KEY`, `TOKEN`, `SECRET` or `PASSWORD` and the value looks random. A
few prefixes are marked "format is a guess" in the output because the vendor
documents them thinly. Stand-ins such as `your_key_here`, `xxxx`, `<token>`
and `example` are ignored - by word, so a real key that happens to contain
`abc123` in the middle is not thrown away.

**It cannot be made to hang, and it does not call a partial look clean.**
Every pattern runs on pieces of a line (a 1 MB minified line is scanned in
8 KB pieces, not cut off), each file has a 10-second budget, and the walk
counts only the files it will read, so an agent file behind 50,000 empty files
is found. If a limit is hit anyway (too many files or folders, more than 12
folders deep, a folder or an agent file it could not open or read - a `.env`
over 1 MB - or out of time) the report starts with an `INCOMPLETE` line, says
what was not looked at, and the exit status is 2 (1 if keys were found; with
`--fail-on live` it is never 0 when incomplete).

A finding looks like this (the key is never shown in full; at most its
first 4 and last 2 characters):

```
  .env:3   OpenAI   sk-p...Wx   not checked
      next: Rotate it at https://platform.openai.com/api-keys, then run
      `stuntkey connect openai` to save the new one safely.
```

Each finding has one of four states: `unchecked` (the default; nothing was
sent anywhere), `live` (the service still accepts it), `dead` (the service
answered 401: it rejected it - it may be revoked or may not be that
service's key at all, so the advice is "rotate it if you are unsure", never
"delete the line") or `unknown` (it could not be checked, with the reason; a
403 is `unknown`, because it can mean "valid key, no permission").

**`--validate` sends keys over the internet, so it asks first.** It lists
the exact host each kind of key will go to, then needs a `y` at the prompt
or `--yes`. With no terminal to ask on and no `--yes`, it sends nothing and
still prints the report (every key `not checked`), with the exit status the
findings give. Only https checks run, one read-only request per distinct key,
through the same code as `connect`. A check on a different domain than the
key's page still needs a typed `yes` (`--yes` does not replace that). Keys of
services that need a second value (AWS, Twilio), keys whose format several
services share (Google), services without a recipe, and a key found only by
its NAME whose value does not have that service's key format (an
`OPENAI_API_KEY` holding something that is not an `sk-` key) are listed as
`unknown` and never sent. Names containing `webhook`, `anon`, `maps` or
`public` are never matched to a service.

**Only the recipes shipped inside the package are used.** A recipe in
`~/.stuntkey/recipes` brings its own regular expression and names the
host a key is sent to, so `scan` ignores it - and cannot be made to send a
key to it - unless you pass `--my-recipes`. With that flag its key format is
searched for under a 0.25-second timer per piece of text (where the system
has no timer signal, such as Windows, its pattern is not used), and with
`--validate` its keys need a typed `y` at a terminal every time, even with
`--yes`.

Exit status: `0` nothing found, `1` keys found, `2` could not run (bad
path, bad option) or the scan was incomplete and found nothing. `--fail-on
live` exits 1 only for a key that still works (it needs `--validate`); **a
key that could not be checked (`unknown`, or `not checked`) is not live, so
`--fail-on live` exits 0 for it** - it says so on stderr. `--json` and
`--sarif` print only the report on stdout (with an `incomplete` flag, and a
SARIF notification when the scan was incomplete); questions and the host
list go to stderr. SARIF is version 2.1.0, with the redacted key in each
message. The same file reached through a link is reported once, under its
real path.

## Hook: stop Claude Code reading `.env`

```bash
stuntkey hook install            # for you, in ~/.claude/settings.json
stuntkey hook install --project  # for this project, in .claude/settings.json
stuntkey hook status             # is it there, and does it work?
stuntkey hook uninstall          # take it out again
```

This adds a Claude Code "PreToolUse hook": a small check Claude Code runs
before every Read, Grep, Bash, PowerShell, Monitor, Edit, Write, MultiEdit
and NotebookEdit call, and every MCP tool call (`mcp__...`, where it looks at
every text in the call's arguments). If the call touches a `.env` file (`.env`,
`.env.local`, `prod.env`, `.envrc`) it says no and tells the agent why, in
plain words. Templates (`.env.example`, `.env.sample`, `.env.template`) are
allowed, for reading and writing.

It also refuses, for an agent: running `stuntkey remote`, `deploy`,
`trust-server`, `export`, `run`, `serve` or `call` (also as `python -m stuntkey
...`; only you run those; `list`, `selftest`, `doctor`, `scan`, `scan-git`,
`overview`, `audit show`, `--version` and `--help` are fine); wildcard paths
that could expand to the `~/.stuntkey` folder (`~/.*/keys/x`); and writing
`.claude/settings.json`, `.claude/settings.local.json`, `~/.claude.json` or
`.mcp.json`, which control which hooks and tools run. A shell command longer
than 100,000 characters is refused unread (it could otherwise keep the hook
busy until it times out).

Writing is refused too (since 0.5.2): a real key an agent types into `.env`
has passed through the agent, which is what this tool exists to prevent, and a
`Write` can overwrite your keys. The agent is told: "Claude can't write to
.env - your keys stay out of the chat. Run: stuntkey connect <service> (or
edit the file yourself)." If your `.env` holds nothing secret and you want the
agent to edit it (or those settings files), start Claude Code with
`STUNTKEY_HOOK_ALLOW_WRITE=1` in its environment (only writes are allowed;
reads stay refused). `Glob` is not
matched: it lists names only.

Upgrading from 0.5.0 or 0.5.1: run `stuntkey hook install` again. It
updates our own entry's matcher in place and touches nothing else;
`hook status` says "OUTDATED" until you do.

Your other hooks and settings are kept. The hook always sits in a matcher
group of its own: another group's matcher or handlers are never edited, and
`uninstall` removes only our handler (found by a `statusMessage` marker or by
the exact command an older version wrote - a hook that merely mentions
`stuntkey` is not ours). Every change first copies the old file to a new
backup in `~/.stuntkey/backups` (the last 20 per file are kept; private to
you; never inside a project, where a `.claude/` folder is often committed). A
settings file that is a symbolic link is changed through the link; one that is
not valid JSON is left alone (exit 2). Installing twice changes nothing.

`hook status` **never runs a command it reads from a settings file** (a
cloned repository's `.claude/settings.json` is not yours). It tests only the
command this installation would write, and says when the file's command is a
different one.

How the command is written: on macOS and Linux a shell string with the
installed `stuntkey` by its full path (or this Python with `-I`, which
ignores the current folder). On Windows the documented exec form -
`"command"` is the program and `"args"` is `["hook", "check"]`, no shell - so
a backslash or a space in the path survives Git Bash and PowerShell. Claude
Code's documentation does not say which version introduced `args`; for a
client that predates it use `stuntkey hook install --shell-form` (forward
slashes, quoted; works in Git Bash, not in PowerShell). The timeout is 10
seconds. `stuntkey hook check` is the hook itself: it reads Claude Code's
JSON on stdin (all of it, however big) and prints the answer. Restart Claude
Code after installing.

**If the hook itself fails** (it cannot start, crashes, times out, or is sent
something it cannot parse), `stuntkey hook install` now makes Claude Code block
the tool call: "fail-closed", the default since 0.8.0 (it sets
`"onFailure": "block"`; needs Claude Code 2.1.295 or later; a missing or broken
`stuntkey` then blocks every call until you fix or uninstall it). Input that is
not valid JSON is first searched for a `.env` file name as plain text and
refused if one is there. If you would rather let calls through when the hook is
broken, install with `--fail-open`. `hook status` says when an installed hook
fails open or does not watch MCP tools, and `hook install` updates it in place.

### What this hook does NOT stop

It is a guardrail, not a wall. It looks at the file names in the call, so it
does not stop:

- a name built from pieces: `cat .e""nv`, `cat $(echo .en)v`, `python -c
  "open('.'+'env')"`;
- a folder sweep that never names the file: `grep -r KEY .`, `rg KEY`, `cat
  *`, `cat .[e]nv`, `find . -name '.env*' -exec cat {} +`;
- a link to the file under another name (`ln -s .env notes.txt; cat
  notes.txt`) or a copy made before the hook was installed;
- a program that prints the settings, such as `docker compose config`,
  `printenv` or `npm run env`;
- tools this hook is not attached to: an MCP filesystem server, `Glob`
  (names only), a subagent in another session without the hook, and a file
  you `@`-mention in your prompt (Claude Code inserts it without a tool call
  - add a `Read` deny rule for that);
- anything when the hook fails and you did not use `--fail-closed`.

And it blocks some harmless things: a virtual environment folder named
`.env` (`source .env/bin/activate`), and a command that merely names the
file (`echo .env >> .gitignore`). Keep keys out of the files too:
`stuntkey connect <service> --store keychain`.

## Commands

```bash
stuntkey install | uninstall         # plug stuntkey into (or out of) Claude Desktop, Cursor, Claude Code, VS Code; ends with "Claude Code: connected" etc.
stuntkey start                       # first run: check this computer, look for loose keys, say what is next
stuntkey start --simple              # plain-English setup, one question at a time, for apps made with Lovable, Bolt, Replit or Vercel
stuntkey overview [--json]           # what is connected, and is the activity log intact
stuntkey doctor [--json]             # is this computer ready (keychain, ssh, git, a quick self-attack)
stuntkey trust-server user@host      # make a server trust this PC (used by remote and deploy)
stuntkey scan [PATH]                 # find keys an AI agent can read (offline)
stuntkey scan --validate [--yes]     # also check if they still work (sends them; asks first)
stuntkey scan --json | --sarif       # machine-readable reports
stuntkey scan --fail-on live         # exit 1 only for keys that still work
stuntkey scan --all                  # every text file, not only agent-readable ones
stuntkey hook install [--project] [--fail-open]    # stop Claude Code reading .env files (blocks if the hook breaks, unless --fail-open)
stuntkey hook status | uninstall     # check it / remove it (--settings FILE for another file)
stuntkey list                        # services with saved recipes
stuntkey connect <service>           # guided key setup -> .env
stuntkey connect <service> --env-file /path/to/.env
stuntkey connect <service> --store keychain   # OS keychain instead of .env
stuntkey connect <service> --clipboard        # copy-and-go: click Copy, no pasting
stuntkey connect github --via-cli    # zero-copy: the vendor CLI's browser sign-in
stuntkey connect <service> --no-browser       # don't open the key page (its address is printed)
stuntkey run <service> -- <command>  # run with a stored key (keychain, else .env) in its env only
stuntkey run --all -- <command>      # ... every service in stuntkey.json
stuntkey run <service> --no-redact -- <command>   # don't scrub the output (interactive programs)
stuntkey run <service> --redact -- <command>      # scrub it (the default)
stuntkey run <service> --env-file FILE -- <command>   # read keys from another .env
stuntkey --project-dir DIR <command>   # work as if started in DIR (manifest and .env live there)
stuntkey skill install [--project] [--yes]   # copy the agent skill to ~/.claude/skills (never overwrites unasked)
stuntkey init [--write] [--add] [--force]   # write stuntkey.json from the project's variable names
stuntkey setup [service ...] [--dry-run]    # connect every missing service in order (resumable)
stuntkey setup --env-file FILE | --no-browser | --clipboard | --allow-clipboard-history
stuntkey status [--json] [--max-age DAYS] [--env-file FILE]   # where keys live, how old
stuntkey export <service> --to github|vercel [--repo OWNER/REPO] [--environment NAME] [--overwrite] [--yes]
stuntkey about                       # who made it and how to check it is the real one
stuntkey allow-agent <service>       # your one-time yes (terminal route; the normal way is the window the server shows)
stuntkey allow-agent <service> --env-file .env.local   # let the agent write to this .env-style file (default: .env only; terminal route only)
stuntkey setup-agent claude-code|claude-desktop|cursor|codex|gemini [--write]   # the MCP entry, with this Python's absolute path
stuntkey skill install --for cursor|codex|gemini|all   # the rules file for that client (marked block, never overwrites yours)
stuntkey mcp --default-store keychain   # where agent-captured keys go (default: the keychain when there is one; install and setup-agent write it)
stuntkey allow-agent <service> --allow-clipboard-history   # ... and accept Windows' clipboard history (terminal route only; with a window, turn history off)
stuntkey allow-agent --list | --revoke [service]   # what is allowed in this project / take it back
stuntkey doctor-recipes [service ...] [--json] [--timeout S] [--my-recipes]   # have recipe addresses rotted?
stuntkey connect <service> --allow-clipboard-history   # keep copy-and-go even if Windows keeps a history
stuntkey rotate <service>            # replace a stored key
stuntkey panic <service> [--dry-run] [--env-file FILE] [--no-browser]   # leaked key: revoke (API or page), get a new one, find the old one (terminal only)
stuntkey forget <service>            # remove the key: OS keychain entry + .env line(s)
stuntkey add                         # capture a new service recipe interactively
stuntkey find <query>                # find free public APIs for a task
stuntkey find <query> --category <name>   # only that category (part of its name)
stuntkey find <query> --refresh      # download the directory again now
stuntkey mcp                         # stdio MCP server (for Claude Code)
stuntkey proxy -- <command>          # run a program whose SDK talks to a local stuntkey address (OPENAI/ANTHROPIC/GROQ/TOGETHER_BASE_URL); its *_API_KEY is a throwaway password
stuntkey proxy --print-env           # print those variables for a tool you start yourself
stuntkey caps show                   # spending limits per key and today's usage
stuntkey caps set <service> --calls-session N --calls-day N --tokens-day N   # limit a key (counted across every program)
stuntkey caps set <service> --clear  # remove that key's limits
stuntkey stop | resume               # kill switch for every brokered and proxied call (resume asks you)
stuntkey policy show | approve       # stuntkey.policy: allowed methods and paths per service; a new or changed file needs your approval
stuntkey scan --no-mcp               # skip the AI tools' MCP server configs (scanned by default)
stuntkey scan --bundle dist/|https://your-app.com   # secret keys a website ships to every visitor
stuntkey wrap <client> <server> [--file CONFIG] [--dry-run]   # move an MCP server's key into the keychain; it then starts through `stuntkey run`
stuntkey wrap --all --dry-run        # preview every MCP server
stuntkey wrap <client> <server> --undo   # put the old settings back
```

Output can be piped (`stuntkey list | head -1`): when the reader
stops early the command ends quietly with exit status 1 — no traceback,
no "Exception ignored" noise at exit. On Windows Python reports that
closed pipe as a plain `OSError` 22 instead of `BrokenPipeError` (a
short output only fails when it is flushed); that is recognised too, for
every command and for the MCP server.

## A connect, annotated

```bash
$ stuntkey connect stripe

  Connect Stripe  (key opens in your browser)        # 1. your browser opens
                                                     #    the exact key page
    1. If it asks, check the mode: test keys (sandbox) contain _test_,
       live keys contain _live_
    ...
  Key page: https://dashboard.stripe.com/apikeys

  This key will be validated with: GET https://api.stripe.com/v1/balance
                                                       # 2. EXACT validation
                                                       #    endpoint shown BEFORE
                                                       #    you ever paste the key

  Paste your API key (hidden):                         # 3. hidden paste —
  validating…                                          #    key never displayed
  ✓ added STRIPE_SECRET_KEY in .env (mode 0600 - never displayed, never logged)
```

(On Windows the line says `owner-only ACL` instead of `mode 0600` — see
*Where the key goes*.)

`--no-browser` (for `connect` and `rotate`) does not open the key page in
your browser. Its address is still printed under `Key page:`, so you can
open it yourself: on another machine, over SSH, in a container.

The validation preview is the security hinge: you see exactly where the
key will be sent, and the recipe must use `https://` for both the key page
and the validation URL (a plain-`http://` recipe is rejected). If the
validation URL belongs to a **different owner** than the key page,
`stuntkey` stops and requires you to type `yes` — anything else aborts,
and no key is ever asked for or sent:

```bash
  This key will be validated with: GET https://third-party-validator.example/check
  ⚠ The validation URL is on a DIFFERENT domain than the key page above (third-party-validator.example vs acme.test).
    Your key will be sent to both domains. Make sure you trust both.
  Type 'yes' to continue:                            # Enter alone aborts
```

"Different owner" means a different **registrable domain**, not a
different hostname: `dashboard.stripe.com` and `api.stripe.com` are both
`stripe.com`, so Stripe, GitHub (`github.com` / `api.github.com`) and
Resend connect without a prompt — the transcript above is the whole
flow. Multi-part public suffixes are understood (`a.co.uk` and `b.co.uk`
are two owners; so are `a.github.io` and `b.github.io`, `a.blogspot.com` and
`b.blogspot.com`, `a.run.app` and `evil.run.app`). Case, a trailing
dot, a port and `user@` in front of the host never change the answer, and
names with non-English letters are compared in their `xn--` (punycode)
form, so `bücher.example` and `xn--bcher-kva.example` are one owner. When
the domains differ and either one is such a name, the warning shows both
spellings (`аpple.com [xn--pple-43d.com] vs apple.com`, where the first
`а` is Cyrillic) so a look-alike letter cannot hide. A few vendors
genuinely keep their API on a second domain (Anthropic's console is
`platform.claude.com`, its API `api.anthropic.com`; Mailgun `.com` /
`.net`; Google AI Studio / `googleapis.com`; Notion `.so` / `.com`):
their **built-in** recipes name that host in `validate.trusted_hosts`
and connect without a prompt, with a one-line note. Only recipes shipped
inside the package get that shortcut — a recipe from
`~/.stuntkey/recipes` (yours, or one somebody sent you) always prompts
when the domains differ, whatever it claims.

Which names count as "anyone can register a sub-domain here" is a **compact
snapshot, not the full Public Suffix List**: country registries by one rule
(`co`, `com`, `org`, `net`, `gov`, `edu`, `ac`, `or`, `ne`, `go`, `gob`,
`nom`, `mil`, `sch`, `ltd` or `plc` under a two-letter country code, as in
`co.uk`, `com.au`, `com.gr`, `gob.mx`) plus a few named ones; a list of the
hosting and site-builder platforms that hand a sub-domain to anyone
(`github.io`, `vercel.app`, `pages.dev`, `blogspot.com`, `myshopify.com`,
...); and a short list of clouds where every single host belongs to one
customer (`*.amazonaws.com`, `*.run.app`). A registry or platform on none of
them - the many other country registries (`info.pl`, `gc.ca`), dynamic-DNS
and small hosting services - is treated as an ordinary domain: two
sub-domains there look like one owner and connect does not ask. The
validation preview above, which always shows the full URL, is the check that
does not depend on the lists.

A recipe is somebody else's text, so it cannot drive your terminal. One
that holds a control or invisible character anywhere (an ESC that would
hide the lines below it, a newline that forges one, a right-to-left
override, a zero-width space) is refused when it is loaded - the other
recipes still load, and a one-line warning on stderr names the file and
the field - and whatever of a recipe's words reaches the screen is
printed so that such a character is shown as a visible escape
(`\x1b[8m`) instead of being sent. Accented and CJK letters and emoji
are ordinary text and pass untouched. So does what writing needs in the
recipe's own sentences (its name, its steps and its scopes): a space of
another width - the no-break space of French typography (`Clé API :
copiez`), the narrow no-break space, the ideographic space - and the
zero-width joiner or non-joiner between two visible characters, which
glue an emoji such as the woman technologist together and shape Persian
and Indic words.

What is refused, exactly: everything Python's `str.isprintable()` refuses,
that is the control characters (ESC, NUL, tab, carriage return, newline
and the C1 range), the line and paragraph separators (U+2028, U+2029),
the invisible "format" characters (the bidirectional marks and overrides
U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069 and U+061C, the
zero-width space, the word joiner, the byte order mark, the soft hyphen
and tag characters), lone surrogates, private-use code points and code
points that are unassigned - except the spaces and joiners above, and
those only in a name, a step or a scope. In a URL, a host name, a header
or any other field a space of another width or a joiner is refused too,
and so is a joiner at the start or the end of a text, or next to a blank
or another joiner. An emoji built with tag characters (the flag of
England) is refused. What is unassigned is up to the Unicode tables of
the Python that runs `stuntkey`: Python 3.10 knows Unicode 13, so an
emoji from a later version passes on Python 3.13 and not on 3.10.

In the transcript above the key is shown as `sk-…` — in reality it is
never printed at all, not even redacted.

If the validation endpoint **redirects** somewhere else — another host,
another port, or from `https://` down to `http://` — the credential
header is stripped before the redirect is followed (what browsers and
`requests` do) and the connect stops with *validation endpoint redirected
to a different origin* instead of guessing from a response that proves
nothing about the key. A redirect within the same origin (`/me` →
`/me/`) is followed normally.

A key the request **cannot carry** is turned back too, **before any
request** is made. An HTTP header holds Latin-1 text only, so a key with a
character outside it (a curly quote copied along with the key, an emoji)
or with one you cannot see (a line break, a tab) is refused right after
the paste, with `✗ that key contains ... Nothing was sent`, and you can
paste it again. A recipe that uses HTTP Basic puts the key through base64
first, so any character you can see passes there. The message never
repeats the key, and neither does the one for anything else the HTTP
library might refuse to send.

**Run it on your own computer.** The check only means something when it
is sent straight from your machine. Cloud coding agents, sandboxes and
some company proxies add their own credentials to outgoing requests, so
the API can answer "valid" for any key, even a made-up one. If a key you
know is wrong gets accepted, that is the likely reason: run
`stuntkey connect` in a terminal on your own computer instead.

## Where the key goes

**`.env` file (default).** `ENV_VAR=<key>` is written to `.env` (or
`--env-file`; a missing folder is created), private from the first byte:
the content goes into a randomly named temp file created with
`O_CREAT|O_EXCL` and mode `0600` in the same directory, is fsync'd, and
is then atomically renamed over the target. No reader ever sees a
half-written or world-readable key, a crash leaves the old file
untouched, and a file somebody pre-planted at a guessable name is never
written through. An existing `ENV_VAR=` or `export ENV_VAR=` line is
replaced in place (keeping `export`). A value made only of
`A-Z a-z 0-9 _ . + / = : -` is written as it is; any other value is
**single-quoted** (`ACME_API_KEY='ab#c d"e'`). A shell that sources the
file takes every character inside single quotes literally, so `$(...)`,
backticks and `$VAR` in a value can never run or expand (inside double
quotes they do), and an unquoted `#` or space cannot cut the value
short. A key with a single quote, a backslash, `${` or a character you
cannot see (a tab, a line break, a zero-width or no-break space) is
**refused**: the readers disagree about those, real API keys contain
none of them, and a pasted key that has one is nearly always a copy
accident (a quote mark copied along with the key, say). `connect` says
so right after the paste, before the key is sent anywhere, and lets you
paste it again (the OS keychain, `--store keychain`, does not apply this
rule). If the file cannot be written (`--env-file` in
a folder that is a file, or unwritable), the connect ends with
`✗ the key was validated but could NOT be saved` and exit 1 — the key is
never printed, and nothing is written.

**What was checked.** The tests source the file in a real `sh` and
`bash` (skipped where there is no POSIX shell) and split every line with
Python's `shlex`: none of the awkward values (`$(...)`, backticks, `;`,
`&`, `$HOME`, `~`, spaces, `#`, quote marks) runs anything or comes back
different. The other readers were checked by hand on Linux in October
2026 with about sixty awkward values, written by the real code: Node
dotenv 17.4.2, python-dotenv 1.2.3 and docker compose 5.5.1 all gave
every storable value back exactly. That is why `${` and a backslash are refused rather
than written: python-dotenv expands `${NAME}` and reads `\\` as one
backslash even inside single quotes, and docker compose rejects a value
that ends in a backslash. Tools that expand `$` after reading the file
(frameworks that add `dotenv-expand`, for example) were not checked and
may treat a `$` in a value specially.

**Older files.** Versions 0.3.1 and earlier wrote double quotes, inside
which a shell still runs `$(...)` and backticks and expands `$VAR`. A key
made only of letters, digits and `_ . + / = : -` was never quoted, so
those are unaffected. Double-quoted values are still read, and such a
line is rewritten in the new form the next time its key is saved:
`stuntkey rotate <service>` does it, and nothing else in the file
moves.

If the same variable is set more than once in the file, the **last**
line is the one that is updated: python-dotenv, Node dotenv, docker
compose and a shell `source` all let the last assignment win, so
changing the first would save a key that never takes effect. Earlier
lines are left exactly as they were, and the success line says so
(`ACME_API_KEY appears twice in .env; I updated the one that takes
effect`).

A quoted value that **runs over several lines** (a PEM block in single
quotes, say) belongs to its variable, the way python-dotenv, Node dotenv
and a shell read it: a line inside it that happens to look like
`ACME_API_KEY=...` is part of that value, so it is never rewritten or
removed, and if the variable's own value runs over several lines, they are
replaced (or removed by `forget`) together. A quote that is never closed,
or whose closing line has other text after it, is read as a one-line
value, as those readers do.

Only your key's line changes; every other byte of an existing file is
kept exactly as it was. A file saved in a Windows code page (cp1252: an
accented comment from Notepad) is not valid UTF-8, and a key is still
saved into it without complaint. A CRLF file stays CRLF and an LF file
stays LF: the line that is added or changed uses the file's own style, a
missing final newline is added in that style, and a brand-new file uses
LF. The byte-order mark that PowerShell and some Windows editors put at
the start of a UTF-8 file is kept, and does not hide a key on the first
line. Two things are refused with one plain sentence and exit 1,
**before** the browser opens or any key is asked for: a `.env` that is a
**link** to another file (a key is never written through a link, and a
link is never silently replaced — name the real file with `--env-file`
if you mean it), and a file that is not plain text, such as the UTF-16
that Windows PowerShell's `>` creates (appending UTF-8 to it would wreck
it — re-save it as UTF-8).

- Linux / macOS: the file is `chmod 0600` (owner read/write only).
- Windows: POSIX mode bits don't exist, so the file's ACL is reduced to
  the current user (`icacls <file> /inheritance:r /grant:r <user>:(F)`,
  best effort). The success line says `owner-only ACL` only when `icacls`
  actually succeeded; otherwise it says `could not restrict ACL` so you
  know the file has the folder's default permissions.

`stuntkey forget <service>` undoes a connect: it deletes the keychain
entry (when this OS has a keychain) and removes the `ENV_VAR=` line from
`.env` (`--env-file` to point elsewhere), and says what it removed. If
the variable is set more than once, every one of those lines goes —
otherwise an older one would take over again — and it says how many.

On Linux, `secret-tool clear` exits 0 whether or not it found anything, so
`forget` looks the entry up first and clears it only when it is there. Run
twice, the second `forget` says `nothing stored` instead of claiming to have
removed the entry again; an entry that is there and cannot be cleared is
reported as such, with exit status 1.

`forget` also looks for the temp file an interrupted write (a `kill -9`,
a power cut) can leave next to the `.env` file - `..env.` and eight
random characters and `.tmp`, a complete copy of the file - and deletes
it when it still holds the key; the success line names it. Other names of
the file are another matter: a hard link (a `.env.bak` made with `ln`)
keeps the old contents, key included, however the file is rewritten.
`forget` cannot change that and does not delete files it did not make: it
names the hard link, says the key is still there, and exits 1 instead of
claiming it is gone. Copies it cannot know about - an editor's backup
(`.env~`), version-control history, a shell history, a backup of the
folder - are yours to remove.

**OS keychain (`--store keychain`).** No `keyring` package; each OS
uses what it ships with, and the key never goes through `argv`:

| OS      | backend                                                            | how |
|---------|--------------------------------------------------------------------|-----|
| macOS   | login Keychain, via the `security` command                         | commands fed over stdin (`security -i`), generic password `stuntkey:<service>` / account `<ENV_VAR>` |
| Windows | Credential Manager (Windows Vault), via `ctypes` → `advapi32` `CredWriteW`/`CredReadW`/`CredDeleteW` | generic credential `stuntkey:<service>`, persisted for the local machine, UTF-16-LE blob like `cmdkey` |
| Linux   | Secret Service (GNOME Keyring / KWallet) via `secret-tool`, when installed | key on stdin; attributes `service=stuntkey account=<ENV_VAR> slug=<service>` |
| anything else, or the tool is missing | — | no keychain: asks `[y/N]` before using the `.env` file (nothing is saved without a yes, or with no terminal) |

A keychain-stored key is consumed with `stuntkey run <service> --
<command>`: the key is read back and placed in that one child process's
environment, never printed. (Your app does not need to change — it
still reads `$STRIPE_SECRET_KEY`.) Without a keychain backend `run`
exits 1 and tells you the key lives in `.env`.

`run` hands back the command's own exit status. A command that cannot
be started is reported in one line, with no traceback and before the
keychain is asked for the key: exit status 127 for a command that is not
on your `PATH` (`command not found`), 126 for one that is there but
cannot be run (not an executable file, a directory). A command that a
signal stops gives 128 plus the signal number (137 for a kill), as in a
shell. Ctrl-C ends `run`, the MCP server or any other command with
`interrupted.` and exit status 130. On Windows the command is looked up
the way the shell does it (`PATHEXT`), so `npm` finds `npm.cmd`.

A keychain tool that does not answer within 30 seconds, or cannot be
started, is handled like any other keychain failure. `connect --store
keychain` asks `[y/N]` (default no) before putting the key in the plain-text
`.env` file instead, and with no terminal to ask on saves nothing and exits 1;
the stored entry is read back to make sure it is really there; `forget` still removes the `.env` line(s),
then says the keychain entry may still be there and exits 1 (run it again
when the keychain answers); `run` exits 1 with a message.

`forget` says what it removed before it says what it could not do. With
a `.env` that is a link (never edited, see *Security model*) it still
removes the keychain entry and any leftover copies of an interrupted
write, then names the link and exits 1: the key may still be in the
file the link points to.

## Find public APIs

stuntkey is also a discovery front door. `stuntkey find` searches the public
APIs directory (~2,100 free APIs, cached locally for 7 days):

```bash
stuntkey find "weather" --auth No        # only keyless APIs
stuntkey find "crypto price" --limit 5
stuntkey find "facts" --category animals # only that category
stuntkey find "weather" --refresh        # download the directory again now
```

`--auth` takes the directory's own word (`No`, `apiKey`, `OAuth`, ...) and
`--limit` caps the list (10 by default). `--category` keeps one category: a
part of its name, in any case (`animals` finds `Animals`). `--refresh`
downloads the directory again now, whatever the age of the copy.

A copy older than 7 days is downloaded again, and so is one dated in the
future by more than an hour (a clock that was wrong when it was saved):
without that, the old list would be served until that date. A copy dated a
few seconds or minutes ahead is normal - two clocks never agree exactly - and
is used. The file is swapped in whole, so an interrupted download never
leaves half a list behind.

APIs needing a key point straight back at the tunnel:

```
    Weatherstack [apiKey]
      Real-time weather
      https://weatherstack.com/  (Weather)
      needs a key — save its recipe with `stuntkey add`.
```

### MCP co-work skills

The MCP server exposes the directory to Claude Code as tools, so the agent
discovers free APIs instead of improvising or reaching for paid services:

- `find_public_apis {query, auth?, category?, limit?}` — search the directory
- `get_public_api {name}` — details plus wiring: no-auth APIs get a
  call-it-directly note; `apiKey` APIs get the exact `stuntkey add` +
  `stuntkey connect` flow (the agent never asks the user to paste a key)

No secrets ever pass through MCP — only public how-to.

## Copy-and-go, two-value keys, every kind of check (0.4.0)

**Copy-and-go** (`--clipboard`): instead of pasting, click the vendor's own
**Copy** button. stuntkey notices the new, key-shaped value on the
clipboard, takes it and **empties the clipboard**, then validates and
stores it as usual; nothing is typed, pasted or shown. It looks only while
it is waiting for a key, takes only a value that matches the field's
`accept` pattern (when the recipe has one; it names only a shape the vendor documents, and only its start, so a valid key is never refused) or looks like a key (one line, no
spaces, 8-4096 visible characters, different from what was already on the
clipboard), and falls back to the hidden prompt after 3 minutes or when no
clipboard tool exists (Windows needs nothing; macOS uses `pbpaste`; Linux
`wl-paste`, `xclip` or `xsel`). Windows clipboard history (Win+V) and
clipboard managers can keep their own copy, which stuntkey cannot clear.

**Zero-copy** (`--via-cli`): for a built-in recipe whose vendor has a CLI
with a browser sign-in (`github` uses `gh auth login --web`), stuntkey
runs that sign-in and reads the token from the CLI, then validates and
stores it. The programs a recipe may run are fixed in the code
(`recipes.CLI_PROGRAMS`); a recipe from `~/.stuntkey` cannot use this.

**Two-value credentials**: a recipe may list several `fields` (an App ID
and a secret, an access key and its secret). Each is collected hidden (or
copied), they are validated together, and each is stored under its own
variable; `run` injects them all and `forget` removes them all.

**Every common check**: besides `bearer`, `header` and `basic`, a recipe can
use `headers` (several headers from `{field}` templates), `basic` with a
field as the username (`username_field`), `query` (the key as a URL
parameter; such a request follows no redirect), `oauth2_client_credentials`
(the client id and secret go in ONE POST to the vendor's `token_url`, which
follows no redirect, is shown in the preview, must be `https://` and needs
a typed `yes` on another domain; the short-lived token then makes the
`GET`, or with `token_only` the token answer is the verdict), and
`aws_sigv4` (a signed STS `GetCallerIdentity`; the secret signs and is
never sent, and the signature is tested against botocore's). A recipe is
refused at load time when it names a field it does not collect, collects
one it never checks, or puts its token endpoint on `http://`.

## Why it exists

Agents (and humans) forget per-service key flows and improvise imprecise
steps. Recipes are the memory: plain JSON files with the key URL, the
exact click path, scopes, and a validation endpoint. Teach it once with
`stuntkey add`, use it forever — and Claude Code can pull the exact recipe via
`stuntkey mcp` instead of guessing.

Ships with 37 recipes inside the package (so `pip install` carries
them), each checked against the provider's own docs for the key page,
the validation endpoint and the auth header, and smoke-tested live with
a fake key (every one answers with a clean "key rejected"):

| area | services |
|---|---|
| LLM / AI | `openai`, `anthropic`, `google-gemini`, `groq`, `mistral`, `cohere`, `huggingface`, `together`, `openrouter`, `replicate` |
| speech | `elevenlabs`, `deepgram`, `assemblyai` |
| infra | `github`, `supabase` (Management API token), `vercel`, `netlify`, `cloudflare`, `cloudflare-keymaker` (lets `stuntkey mint` make Cloudflare keys), `pinecone` |
| email / payments | `stripe`, `resend`, `sendgrid`, `mailgun`, `postmark` (server token) |
| productivity / search | `notion`, `airtable`, `discord` (bot token), `tavily`, `brave-search` |
| two values / other checks (0.4.0) | `ebay` and `spotify` (OAuth2 client credentials), `paypal` (OAuth2, token only), `twilio` (Account SID + token), `aws` (SigV4), `openweather` (key in the URL) |

Each validation call is a free, read-only request (list models, "who am
I", verify token) — except `brave-search`, whose only authenticated
endpoint is the search itself, so validating costs one tiny query (the
recipe says so). The 0.4.0 recipes were written from each provider's docs,
checked against a local fake API, and smoke-tested live with fake
credentials (each answers "rejected"). Not included: Slack (`auth.test`
answers HTTP 200 even to a bad token), Linear (GraphQL needs a POST
body), Shopify (per-store URL), Perplexity/Exa/Serper (no free GET
endpoint), Fireworks (the documented list-models URL is per account).

`stuntkey add` walks you through capturing your own (Headroom, RPX,
Ponytail…); those are saved to `~/.stuntkey/recipes/`
(`%USERPROFILE%\.stuntkey\recipes\` on Windows) and override a
built-in recipe with the same slug. `--recipes-dir` writes elsewhere.
A recipe file may be saved with Windows (CRLF) line ends and a UTF-8
byte-order mark, as Windows PowerShell and older Notepad write them: a
recipe saved with one loads like any other.
A slug is `[a-z0-9][a-z0-9_-]{0,63}` — it becomes the file name, so
`../../evil` is refused, and so is a name Windows keeps for a device
(`con`, `prn`, `aux`, `nul`, `com0` to `com9`, `lpt0` to `lpt9`: a file called
`nul.json` cannot be saved there, and the refusal says so in one line) —
and the expected status codes must be numbers
(`200,201`). The validation call must be a `GET` or `HEAD`: it only
reads, so a recipe cannot make `connect` send your key with a `DELETE`
or a `POST`. Besides `bearer` / `header` / `basic`, a recipe's
`validate` block may set `auth.scheme` (`Token` for Deepgram, `Bot` for
Discord), `auth.username` for Basic auth with the key as the password
(Mailgun's `api:<key>`), static `headers` (`anthropic-version`,
`Notion-Version`), and `reject` — the statuses that mean "bad key" when
a provider does not answer 401/403 (Google and Resend say 400, Brave
422).

## What a recipe says (0.6.0)

Beyond the steps and the check, a recipe can carry:

- `accept` / `detect`: two different jobs for a key's shape. `accept` is the
  copy-and-go gate: only a shape the vendor documents, matched from the start
  of the value, or nothing (then any one-line value of 8-4096 visible
  characters is taken). `detect` is what `scan` looks for; a commonly used but
  undocumented shape (Groq's `gsk_`, SendGrid's `SG.` ...) lives only there and
  is reported as "format is a guess". The older single `pattern` still works
  and does both.
- `validate.limited`: statuses that mean "real key, missing a permission" (a
  403 from a Stripe restricted key, a Supabase token without projects-read, a
  scoped Vercel token ...). `connect` stores the key and says what it cannot
  do, instead of calling it dead.
- `validate.body_rules`: the same idea when the status alone is not enough
  (Resend answers 401 for a "sending only" key too; the body says
  `restricted_api_key`). Only a phrase from the recipe is looked for in the
  first 4 KB of the answer; none of it is kept or shown.
- `least_privilege`: the smallest scope or permission that works, shown by
  `connect`.
- `unverified`: parts the vendor's docs do not confirm, shown by `connect`.

PayPal has two recipes, `paypal` (live) and `paypal-sandbox`, so you choose explicitly.

AWS's check is the one POST besides OAuth token calls: AWS documents STS
`GetCallerIdentity` as a POST, it only says who the key is, and the recipe
loader refuses a POST to anything else.

`doctor-recipes` visits each recipe's key page, docs link and check server over
HTTPS with no key at all and prints a table: `ok`, `moved` (redirected),
`warn` (403, 429, 5xx: look by hand) or `ROT` (404/410, name not found, broken
certificate, refused connection, too many redirects, a redirect to plain
HTTP). It exits 1 on rot. A weekly GitHub Action
(`.github/workflows/recipes.yml`, read-only except for one `issues: write` in
the job that opens or updates a single issue) runs it. To fix a recipe, see
`CONTRIBUTING.md`.

## The MCP server

Add to Claude Code (`claude mcp add`) or `~/.claude.json`:

```json
{ "mcpServers": { "stuntkey": {
  "command": "python", "args": ["-m", "stuntkey", "mcp"] } } }
```

(`python` is the Windows launcher's name; on macOS/Linux use whatever
runs your Python 3.) Eight tools: `list_services`, `get_recipe`,
`find_public_apis`, `get_public_api`, `request_connect`, `capture_key`,
`needs_keys` (the agent handshake, above) and `call_api` (make a brokered call
with a saved key: service, method, path, optional `query_json` and `body_json`, and `max_chars`: the answer body is cut at 24,000 characters by default, up to 1,000,000;
`list_services` takes `connected_only: true`;
it reads the OS keychain only, and anything but a GET asks you first). The recipe tells the agent the
exact steps and ends with: call `capture_key` (or, if that is unavailable,
ask the person to run `stuntkey connect <service>`) — never ask the user
to paste the key into chat.

### Agent-driven capture (`capture_key`, experimental)

The person says "connect GitHub". The agent calls `capture_key` (`action`:
`start`, `status`, `cancel`), opens the key page with its own browser tools,
chooses the smallest permissions and a short expiry, and clicks **Copy**. The
MCP server — a program running as you, on your computer — sees a new
key-shaped value on the clipboard, takes it, **empties the clipboard and checks
that it is empty**, asks the vendor whether it works (the same check as
`connect`, including "real but limited"), and stores it in `.env` or the OS
keychain. The agent gets back only the state, the variable name, where it was
stored, a length class and — for GitHub — the account's login name, so you can
see which account was connected. A key the vendor rejects is kept nowhere.

**States** (`state`): `consent_pending` (a window is on your screen),
`consent_needed` (no window possible: use `allow-agent`; or the window failed or timed
out, which is not a refusal: ask again),
`consent_expired` (the window closed by itself after 5 minutes: tell the person, they can ask
again), `consent_denied`, `consent_granted` (then call `start`), `replace_granted` (then
call `start` with `replace=true`), `confirming` (a window asks you to confirm the
account), `unavailable` (no clipboard, SSH, WSL ...: the reason is
given), `unsupported_gateless` (the service has no documented key format),
`refused` (clipboard history, a recipe of your own, limits), `busy`,
`already_stored`, `waiting`, `validating`, `storing`, `stored`, `failed`,
`timeout`, `cancelled`, `idle`. `status` waits up to 25 seconds and returns as
soon as the state changes. `cancel` during `storing` answers `cancel: too_late`.

Rules that make this safe enough to allow:

- **Your yes is asked in a window of the operating system** (a Windows
  message box that stays open 5 minutes, macOS `osascript`, Linux `zenity`/`kdialog`)
  shown by the server itself — not by anything the agent can type into. **When a
  window can be shown, only that window counts**: any permission file on disk is
  ignored, even a well-formed one, so a file an agent wrote cannot start a
  capture. Your yes is kept in the server's memory for that session only (it
  ends when the MCP server stops), never on disk. A window that fails to open,
  crashes, or is not answered is **not** a "no": the agent is told to ask again
  (only an explicit No is remembered, for 10 minutes). After the key is checked
  a **second window** shows which account it belongs to (GitHub: the login name)
  and asks you to confirm before anything is stored. Replacing a stored key needs
  its own window.
  - *What the window protects against:* an agent that works through chat, files
    and shell commands and cannot run code as you — it cannot answer the window
    and cannot plant a consent.
  - *What it does not protect against:* an agent that can run programs as your
    user (it can reach the same operating-system facilities: it could, for
    example, drive the screen or tamper with this very program), one that controls
    your screen and presses Yes, and a browser tool that reads the key field.
- **Who is named, and who made the tool.** The window says which AI program is asking
  ("Claude Code", "Cursor", "Codex" ...). That name is what the program **reports
  about itself** when it connects (the MCP `clientInfo.name`); stuntkey cannot prove
  it, so it is a label, not an identity check. An unknown name is shown cleaned (plain
  letters, 30 characters) and a missing one as "An AI program". The first line of
  every window says the tool is *free key-safe tool, made by Calas Automations,
  installed on this computer*. To check that this really is the program you installed:
  `stuntkey about`, `pip show stuntkey` (author Calas Automations Inc.), the
  package page https://pypi.org/project/stuntkey/ and the source
  https://github.com/calasdan-sketch/stuntkey.
- **A closed window is not a No.** Only the No button, where the operating system lets
  stuntkey tell (Windows, macOS, Linux zenity), counts as a refusal. A window that
  closes by itself or is closed without choosing is reported as expired/closed and
  can simply be asked again; on kdialog or an old zenity, where "No" and "closed" look
  the same, the answer is passed on as a No but never remembered for 10 minutes.
- **A dead stored key is not protected.** Before a REPLACE window is shown, the stored
  key is tested with the vendor (never shown). If the vendor rejects it, no replace
  question is asked - it is handled as a normal first capture and the agent is told the
  stored key no longer works. If it can't be tested, the replace window is shown.
- **Helper programs are trusted ones only.** `zenity`, `kdialog`, `osascript`,
  `security`, `secret-tool` and the clipboard tools are looked up only in
  `/usr/bin`, `/bin` and `/usr/local/bin`, only when root owns them and nobody
  else can write to them or their folder, and they run with a fixed `PATH` and a
  minimal environment. That is deliberate and not relaxed for the clipboard tools
  either (the key passes through them). The cost: a Homebrew or Nix copy, which
  your user owns, is refused — and the result **says so** (for example *found
  xclip at /opt/homebrew/bin/xclip but it is not a trusted install ... use
  `stuntkey connect`*) instead of failing quietly.
- **`stuntkey allow-agent <service>`** in a terminal is the fallback **only
  where no window can be shown** (SSH, headless), or when the server is started
  with `STUNTKEY_NO_WINDOW=1`. On a computer that can show a window the server
  does not use it. It is **advisory**: it is kept in
  `~/.stuntkey/agent-consent.json` (in a 0700 folder) with an HMAC and a
  counter (an old copy of the file does not verify). The signing secret is in
  Windows DPAPI, the macOS keychain or the Linux Secret Service; where those work
  they are the authority and a file is never preferred over them; otherwise it is
  a 0600 file. Where the keychain is empty or absent, a file planted by a program
  that can write files is accepted on this route, and a program running as you
  can still read that secret or fake a terminal, so this route proves little.
  An agent that can edit your MCP client's config can also set
  `STUNTKEY_NO_WINDOW=1` for the server, so that switch is a convenience, not a lock. A file that does not verify counts as
  no consent. The hook's rules about these files (including wildcards such as
  `~/.safe*/*`) are a speed bump, not a lock; a known false positive is that a word such as
  `ls .s*` is refused too, since it could expand to the folder.
- Built-in services **that have a documented key format** only (GitHub,
  Stripe, Anthropic, AWS, Cloudflare, Replicate, Twilio, Vercel). Other
  services answer `unsupported_gateless`. One capture at a time; 10 to 180
  seconds; six starts an hour.
- The agent writes only to the project's `.env` (or the one file you named with
  `--env-file`), never to a folder a web server publishes.
- Only a value that *changes* the clipboard after arming and has the service's
  key format — one line, no spaces — is taken. A stale copy shaped like that
  key is removed and not used (said in the result); anything else on the
  clipboard is left alone. A copy that is not that service's key is ignored and
  counted.
- **Clipboard history (Win+V)** keeps its own copy that nothing can remove.
  While it is on, or cannot be checked, `capture_key` refuses (with a window: turn
  history off; on the terminal route you may accept it with
  `--allow-clipboard-history`). Clipboard-manager apps may do the
  same and cannot be detected.
- If the clipboard cannot be emptied the result says so (`clipboard_warning`)
  and never claims it was.
- The agent's rules (also in the skill): never look at the key; never type it;
  only click Copy; never enter a password, 2FA code or CAPTCHA; with no browser
  tool, stop and use `connect`.

What still needs you: signing in, 2FA, CAPTCHAs and GitHub's "sudo mode"
password prompt. If the agent's browser tools read the key field (page text, a
screenshot), the agent sees the key — the rules forbid it and nothing here can
stop a browser tool.

The server speaks JSON-RPC 2.0 properly: notifications
(`notifications/cancelled`, `notifications/initialized`, anything without an
`id`) are never answered, a non-object message gets `-32600 Invalid Request`,
bad JSON (a hundred thousand open brackets included) `-32700 Parse error`, and
`params` that is not an object (`null`, a list, a string...), `arguments` that
is not an object, or a missing or wrongly typed required argument gets
`-32602 Invalid params` - never a crash or `-32603` - after which the server
simply carries on. (A tool-level miss, such as a service that has no recipe, is
an ordinary result with `isError`.) If standard input or standard output is
closed (`stuntkey mcp >&-`; `pythonw` on Windows) there is no client to talk
to: one `error:` line on stderr and exit status 2, before any request is read,
not a traceback.

### What is enforced where

| | Claude Code | Claude Desktop, Cursor, Codex, Gemini |
|---|---|---|
| MCP tools never return a key | yes | yes |
| Permission window (session only) and advisory signed terminal consent | yes | yes |
| Hook blocks reading `.env`, clipboard readers, keychain readers | **yes** (`hook install`) | **no hook exists**: the agent can read a `.env` file |
| Where keys go | `.env` (or keychain) | keychain by default (`setup-agent`) |
| Rules file | `skill install` | `skill install --for cursor\|codex\|gemini` |

## Security model

- Key input via `getpass` (no echo); never printed, never logged.
- `.env` written atomically through a random, exclusive, `0600` temp
  file + rename (owner-only ACL on Windows); keychain storage never
  passes the key on a command line.
- A `.env` that is a link is refused, never written through or replaced,
  and the permission step (chmod / icacls) never follows a link to change
  something else.
- Whatever a recipe or a paste contains, the `.env` file gets exactly one
  `NAME=value` line from it: a name is a plain identifier (a trailing
  newline does not slip through), and a value is single-quoted or
  refused, so sourcing the file runs nothing.
- Validation is a single minimal HTTPS call; only the status is read,
  response bodies are discarded. The credential never follows a
  redirect to another origin or to plain `http://`.
- Rejected keys are scrubbed immediately; 3 failed attempts aborts.
- The exact validation URL and HTTP method are printed BEFORE the key is
  asked for; a validation URL under another registrable domain needs a
  typed `yes` (built-in recipes may declare their vendor's second API
  domain; user recipes cannot).
- A reply that is not HTTP at all (a captive portal, a TLS mismatch, a
  non-HTTP service on the port) is reported as a validation error, not a
  traceback.
- A recipe with a control or invisible character in it is refused at load
  time, and any recipe text that reaches the screen is shown as a visible
  escape, so a recipe cannot hide or forge the validation preview. (The
  one leeway: a space of another width and a joiner between two visible
  characters are text in a name, a step or a scope - the list of what is
  refused is in *A connect, annotated*.)
- The only POST stuntkey sends is the OAuth2 token request, to the
  `token_url` the recipe names and shown before anything is asked for;
  it and a `query` request follow no redirect. Copy-and-go empties the
  clipboard as soon as it takes a value.
- Recipes must use `https://` for the key page and the validation URL —
  plain-`http://` recipes (and ones whose URL is malformed) are rejected
  at load time.
- Recipes contain no secrets — only public how-to.
- `scan` is offline unless `--validate` is given; a key is shown as at most
  its first 4 and last 2 characters in the text, JSON and SARIF output, in
  errors, and in every message; the full value is held in memory only for a
  `--validate` check. Before anything is sent, the host for each service is
  printed and a `y` (or `--yes`) is required.
- `scan` opens only regular files of at most 1 MB, without blocking, and
  never follows a link out of the folder it was pointed at.

## Testing

```bash
python -m unittest discover -s tests -v
python -m pytest -q                    # same suite
```

The tests use only the standard library and no network beyond
127.0.0.1 (nothing is downloaded, not even to build a wheel). Two groups
skip, with a reason, where they cannot run: the tests that build the
wheel and the sdist need a setuptools 77 or newer, with a `packaging` 24.2
or newer, installed in the Python that runs them; the tests that read
`pyproject.toml` need `tomllib`, so they skip on Python 3.10. What they
cover: recipe schema,
HTTPS-URL rejection and malformed URLs, slug validation, every shipped
recipe (parses, https, file name = slug, credential header built),
`.env` create/update/permissions (random exclusive temp file, crash
safety, never world-readable, value quoting (sourced in a real shell,
split with `shlex`, values the readers disagree on refused), `export` lines,
an unwritable path, a cp1252 file, a byte-order mark, CRLF/LF/mixed
endings and a variable set twice (the last line wins) kept
byte-for-byte, a UTF-16 file and a symbolic link refused, permissions
that never follow a link), redirect credential stripping against a local
redirecting server pair, full connect flow against a local fake HTTP
service (bearer/header/basic auth, custom schemes and static headers,
401 rejection, custom reject statuses, network failure, a non-HTTP
reply), validation-URL preview ordering, registrable-domain matching
(punycode names, trailing dots, ports, `user@`, a look-alike letter
shown in the warning) and typed-`yes` on a real mismatch, keychain
dispatch for every OS with the real keychain faked (the Windows path
through a fake `advapi32`), the `.env` fallback, `forget`, the honest
Windows ACL line, MCP provenance labels and quarantine of poisoned
directory entries, JSON-RPC notification, invalid-request and
invalid-params handling, MCP protocol round-trip over real stdio, a
wheel build that must contain the recipes and an sdist that must carry the
tests (both built from a clean copy of the folder, so a leftover `build/`
cannot reach them),
the package metadata and one version number everywhere, output into a pipe that closes early (the
real thing, and the different error Windows gives, simulated), and
never-log assertions on every output path. Tests point
`HOME`/`USERPROFILE`/`APPDATA` at a throwaway directory, so they never
read your real `~/.stuntkey` or `.env`.

Windows 11 is a first-class target: the wire format of the MCP server
is UTF-8 bytes regardless of console code page, console output is
reconfigured to replace unencodable characters instead of crashing, and
every text file is opened as UTF-8.

## Scope / limits (v0.9.1)

- `scan` finds keys by their shape. It misses a key with no recognisable
  prefix under a name that does not end in KEY, TOKEN, SECRET or PASSWORD, and
  a key split over several lines (a PEM private key is the exception); it can
  flag a random-looking value that is not a key. A value longer than about
  1.7 KB after `NAME=` is looked at only up to that length. `live` means "the
  service accepted it", `dead` means "the service said 401": a network failure,
  a 403 or an unexpected answer is `unknown`. Build folders such as `dist/` are
  not scanned.
- `hook`: the settings shape, the exec form (`command` + `args`), `onFailure`
  and the answer format were checked against Claude Code's hooks
  documentation (code.claude.com/docs/en/hooks); the Read, Grep, Bash and
  PowerShell tool-input field names are in that page too. The Edit, Write,
  MultiEdit and NotebookEdit field names (`file_path`; `notebook_path` for
  NotebookEdit) could not be confirmed there, so the hook reads `file_path`,
  `notebook_path` and `path` for all four. The `Monitor` tool's
  input is not documented field by field, so the hook reads every text field
  of it except `description`. The documentation does not say which Claude Code
  version added `args` (hence `--shell-form`). The hook was exercised by
  feeding it Claude Code's JSON, not inside a running Claude Code. **Nothing
  here was run on Windows**: the Windows command (exec form, forward-slash
  shell form), the junction check in the folder walk and the "no timer, so no
  patterns from your own recipes" path were written from the documentation
  and tested with the platform faked on Linux, not on a Windows machine.

- 0.6.0: `doctor-recipes` was run once for real against the 36 recipes' addresses
  before release; its tests, like every test, use no network beyond
  127.0.0.1. The `limited` and body rules follow the vendors' docs where they
  speak (Stripe, Supabase, Vercel, GitHub, Resend, SendGrid); for ElevenLabs the
  docs do not say how a restricted key answers, so that rule is flagged
  `unverified`. `export` was checked against the `gh` and `vercel` manuals and
  run against a stand-in `gh`, not a real GitHub or Vercel account. Nothing of
  the Windows clipboard-history check was run on Windows (it reads the
  `EnableClipboardHistory` registry value). The agent handshake was exercised
  over the MCP wire format and with a stand-in client, not inside a running
  Claude Code.
- Keychain storage is best effort. `get` saves to the keychain; `connect` saves
  to `.env` unless you add `--store keychain`; when the keychain fails, `.env` is
  used only if you agree. No Doppler / Vault backends.
- Recipe catalog is curated manually — verify a new service's key URL and
  validation endpoint before trusting it. Provider dashboards move:
  if a key page URL redirects, follow it and send a fix.
- `forget` removes what stuntkey wrote and what a killed write left
  next to it; it does not find other copies of the file (editor backups,
  version-control history), and it names - rather than deletes - another
  hard link to the `.env` file, exiting 1 because the key is still there.
- Windows: `run` finds `npm.cmd` and other `.cmd`/`.bat` commands through
  `PATHEXT`. That lookup is tested with a stand-in for the Windows search,
  not on a Windows machine, and `cmd.exe`, which starts such a file, reads
  `& | < > ^ %` in its arguments as its own syntax: do not pass one text you
  do not trust.
- "Same owner" (the cross-domain prompt) knows a compact snapshot of country
  registries and hosting platforms, not the whole Public Suffix List: a
  platform it does not list is treated as an ordinary domain, so two
  tenants of it do not trigger the prompt. The validation preview always
  shows the full URL.
- Linux: `secret-tool` is driven through stand-ins in the tests, not against
  a real Secret Service (GNOME Keyring, KWallet): none was available. That
  includes `forget`, which relies on `secret-tool lookup` finding nothing
  (exit status 1) when no entry matches.
- Windows: the refusal of device names (`nul`, `con`, `com1` ...) as recipe
  slugs is a plain list of names, tested on Linux, not on a Windows machine.
- Windows: the owner-only ACL goes on the empty temporary file before the key
  is written into it, and is checked again once the file is in place. This is
  read from the code and checked against a stand-in for `icacls`, not on a
  Windows machine.

## Using a key without holding it (call, serve, remote)

These commands let an AI use a saved key while only stuntkey ever holds it.

- `stuntkey call SERVICE METHOD PATH [--query name=value] [--data JSON] [--json]`: call a service's API; the key is added for you and hidden from the output.
- `stuntkey serve [--port 8787]`: a local web door for tools that do not speak MCP.
- `stuntkey remote SERVICE user@host [--as USER] [--ssh-arg ARG] -- COMMAND`: run a command on another machine with the key sent over ssh stdin.
- `stuntkey deploy user@host --service NAME --dir FOLDER [--as USER] [--then COMMAND]`: trust the server, send the key, `git pull`, optionally restart.
- `stuntkey audit verify|show|reset [--last N]`: check the activity log has not been tampered with.
- `stuntkey selftest [--verbose]`: attack stuntkey with a made-up key; `--verbose` lists every attack.
- `stuntkey scan-git [--staged] [--install-hook]`: look through git history, or what is about to be committed, for keys.
- `stuntkey get SERVICE [--no-clipboard]`: one command: open the key page, take the key from your copy, test it, save it in the keychain.
