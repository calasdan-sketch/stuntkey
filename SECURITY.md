# Security

**Beta: not independently security-reviewed yet. Use at your own risk; MIT, no warranty.** The threat model, with links to the code, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

stuntkey is built so an AI agent can use your API keys without being handed them. It reduces risk. It does not remove it. No independent security review has been done yet.

### What we do instead of a paid audit

A paid external review is not affordable for a project at this stage, so rather
than claim a review that has not happened, the evidence is published and
runnable:

- **A threat model with links to the code** — [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **`leakbench`**, a vendor-neutral benchmark of 63 ways an agent leaks a
  credential. Run it against stuntkey with `python -m leakbench --profile
  stuntkey-hook` (the default profile, `none`, is the unprotected baseline), or
  against another tool. The hook alone leaves **2 leaks**, named
  (`runaway-loop-no-cap`, `unbounded-retry`: a loop of paid calls, which
  the spending caps in `stuntkey-full` stop, leaving 0), rather than
  scoring only what it passes. The probes are simulated tool calls, not a
  real model.
- **`stuntkey selftest`**, which attacks stuntkey's own rules and currently
  reports 77 of 77 simulated attacks stopped. Note what it does *not* prove:
  the attacks are simulated against a pretend server, so it does not exercise
  the live network layer.
- **A test suite that encodes its own known gaps as passing tests**, so a gap
  cannot quietly close over or widen without a test changing.

An audit is a stranger's opinion you have to take on trust. The above is
something you can run. It is not a substitute for a review, and this section
will say so until one happens.

## What it defends against
- **An AI reading a key out of chat, a prompt or tool output.** The tool adds the key itself. Replies and program output are scrubbed for the key in many disguises (encoded, escaped, split by spaces). If a disguised key is still detected, the whole reply is withheld.
- **A prompt-injected AI sending your key to another server.** The destination comes from the saved service profile, never from the AI. Private and internal addresses are refused, the connection goes to the address we checked, redirects are not followed, proxies are ignored, and odd path tricks are refused.
- **An AI making changes you did not approve.** In a brokered call (the MCP tool, `call`), anything other than a read asks you first, in a pop-up window (or, with no window available, on the console with a code shown only on screen). The pop-up shows the method, address, every query parameter and the whole body (anything too long to show in full is refused). Three refusals stop further requests. The call limit and the three-refusal stop are counted separately by each running stuntkey program (MCP server, web door, `call`), not across all of them.
- **Accidental or casual edits to the activity log.** Each entry carries the hash of the one before it (`stuntkey audit verify`).
- **An AI turning a harmless-looking read into new credentials.** For AWS, only plain look-ups are allowed (`GetCallerIdentity` for STS; `Describe*`/`List*` elsewhere); actions that create keys (`GetSessionToken`, `AssumeRole`, ...) are refused.
- **A request padded to hide what it does.** The approval window lists every query parameter and shows the whole body with its size and hash; a query value over 200 characters or a body over 400 bytes is refused, never shown cut off. The pop-up program is found by its full system path, never through PATH or the current folder.
- **A planted recipe that sends a built-in service's key somewhere else.** A recipe in your own recipes folder cannot redirect a built-in service (or reuse its key name) to a different server.
- **Dangerous ssh options** passed to `remote`.
- **Web pages and rebinding tricks** against the local web door (`serve`): loopback only, secret token, exact Host check, Origin refused, no CORS.

## What it does NOT defend against
- **Malware, or an AI agent that can run programs as you.** Anything running as you can read your keychain or `.env` directly, edit the activity log (it has no secret key), or drive the screen to click a pop-up. The broker protects against an AI that only uses the tool, not one with full control of your computer. Run risky agents in a separate account or container.
- **`run` and `remote` handed to an AI that can run commands.** They give the key to a program you name; a program can print its own environment, and a terminal-style session is not scrubbed. Give AIs the MCP tool or `call` only.
- **A key left where an AI can simply read the file** (`.env`, shell history, AI-tool settings). `stuntkey scan` finds these; prefer `--store keychain`.
- **The sign-in request for OAuth services** (the token fetch). It checks the address is public, ignores proxy settings and never follows redirects, but unlike ordinary calls it is not pinned to the address it checked.
- **Log flooding.** Refused requests count toward the call limit and are logged with a clipped path, but a patient attacker with a few dozen refused calls can still push older lines out of the default `audit show` view; use `--last`.
- **Harmful actions inside what a key is allowed to do.** GET requests are treated as reads, but some services let a GET change things. Limit each key at the provider (read-only keys, narrow scopes).
- **What the AI company sees.** Replies from the API go to the AI. If you let the AI read your email through this tool, the AI vendor sees that email.
- **The approval window cannot show everything.** It shows the first part of a body, not all of it.
- **Secrets we have not thought of how to disguise.** The scrubber is best effort; Python also cannot reliably erase secrets from memory.
- **A compromised service**, or one that logs or leaks your key itself.
- **The clipboard.** Copy-and-go (`stuntkey get`) empties the clipboard right after taking the key, but other programs and clipboard-history tools can read it while it is there and may keep their own copy. If that worries you, use `--no-clipboard` (hidden typing instead).
- **A tamper-proof log.** The activity log is tamper-evident, not tamper-proof. Edits, deleted lines, a cut-off end and a deleted file are detected (a small second file remembers how many entries there should be), but someone running as you can rewrite both files. Nothing is anchored outside your account yet.

## Known limits
These are known and not fixed. They are listed so you can judge for yourself.
- **The Claude Code hook masks Bash output only.** Read, Write, PowerShell and MCP output is not masked.
- **The Bash output mask is narrow.** The PostToolUse mask matches only whole words, and the parts of a word either side of `=` or `:`, against a stored key's plain, URL-encoded and base64 forms, plus text in known key formats. It does not detect a key with changed case (lower or upper), reversed text, hex, URL-safe base64, a key split across lines, or a key inside a `Basic` auth header. (Checked with a temp key and `stuntkey.scrub.mask_secrets`.)
- **stuntkey protects its own stored keys and the usual file shapes (`.env`, `.pem`/`.key`, `~/.ssh`), not other tools' credential files.** For `.netrc`, `.npmrc`, Docker `config.json`, `.kube/config` and `.aws/credentials` the hook refuses a Read, or a plain `cat`, `head` or `type`, by name, but it does not mask their contents, and a copy or a script (`cp`, `python -c "open(...)"`) that reaches them passes. GitHub CLI's `hosts.yml` and `gh auth token` are not covered at all: Bash and Read can reach them. (Checked with `stuntkey.hook.check` on a temp home.)
- **The pre-call hook reads command text, not what a shell will make of it.** Glob forms (`cat ./.e*`, `cat .en[v]`, `cat .e?v`) and paths built at run time (`cat $(printf '.en%s' v)`, a variable holding part of the name) are not recognised as a `.env` read and pass the hook; plain `cat .env` is blocked. (Checked on 0.9.1 with `stuntkey.hook.check`.)
- **The hook does not mask some stored keys in output.** A key longer than 512 characters, or one containing a space or one of `; , ( ) & |` or a quote, is not found by the output mask, which looks at words up to 512 characters split on those characters. (Checked by saving such keys and masking text that holds them.)
- **`proxy` does not ask per call.** A chat prompt is far too long to review in a window, so proxy mode sends `POST` to the usual AI endpoints (chat, responses, messages, embeddings) without asking, and refuses every other write unless an `stuntkey.policy` file you approved allows it. Its streamed answers get the key-scrubber but not the whole-body disguise check a brokered call adds. Brokered calls are the ones that ask.
- **A short piece of a key echoed back is not caught.** The scrubber removes whole forms of the key, and the fail-closed check also withholds a reply holding 32 or more of the key's characters in a row. A shorter run (a vendor's own `sk-...Zk` style hint, which is meant to be public) is left alone, so a service that echoes only the first few characters of your key passes them through.
- **A GET can read other secrets.** stuntkey hides the key it added, but a read-only call to a vendor's own endpoints (a settings, tokens or environment listing) can return other secrets, and those are not recognised. Use read-only, minimum-permission keys, and do not connect services whose reads expose secrets.
- **The activity log is only tamper-evident against casual edits.** It has no secret key and nothing outside your account holds a copy, so someone running as you can rebuild it so that it verifies.
- **The OAuth token fetch is not pinned to the address it checked** (see above). It is checked to be public, ignores proxies and never follows redirects, but a DNS answer could change between the check and the connection.
- **`STUNTKEY_ENV_FILE` can point `call_api` at a file.** The MCP server reads it from its own environment, which the AI app's config sets. An agent that can edit that config (the Claude Code hook now refuses writes to `.claude/settings.json`, `.mcp.json` and `~/.claude.json`, but not to other apps' config files) could point it at a `.env` it planted, or a recipe in `~/.stuntkey/recipes`.
- **`serve`.** On Windows the port is now bound exclusively, but the token file's permissions rely on your user profile's folder permissions (Windows ignores the 0600 mode); on macOS and Linux `~/.stuntkey` is made owner-only (0700) when stuntkey creates it. Any program running as you can still read the token.
- **The MCP server handles one request at a time.** A slow call or an approval window nobody answers holds up the AI's other requests until it times out. That is a nuisance, not a leak.
- **The Claude Code hook is a speed bump.** It reads the text of a call. A program that builds its command at run time, a tool it is not attached to, or an AI app other than Claude Code gets past it. A shell command over 100,000 characters is refused unread, and very large text sent to an MCP tool is only checked in part.
- **Pop-ups can be clicked by a program that drives your screen**, and a window helper such as `zenity` is trusted if it sits in a system folder owned by root.

## Check it yourself

- `stuntkey selftest` attacks stuntkey with a made-up key and a pretend server (no network, no real key) and prints PASS or FAIL for each attack. It checks the rules listed above only; it cannot show that nothing else can go wrong.
- The package uses only Python's standard library, no outside code. A test (`tests/test_stdlib_only.py`) fails if that ever changes.

## Report a problem

**Please report privately. Do not open a public issue, pull request or discussion, and do not post a working exploit first.**

- **Preferred:** GitHub private vulnerability reporting at https://github.com/calasdan-sketch/stuntkey/security/advisories/new
- **Or email:** security@calasautomations.com

Tell us the stuntkey version (`stuntkey --version`), your operating system and AI app, and the steps to reproduce. A made-up key is enough; never send a real one.

What happens next:

- We aim to reply within 7 days and to agree on a fix plan with you.
- **90-day disclosure.** We ask you to wait up to 90 days from your report, or until a fix is released if that is sooner, before publishing. If a fix needs longer we will say why and ask; if we stop answering, you may publish after 90 days.
- We credit you in the advisory and the changelog unless you would rather not be named.
- **Security reports are never closed for being stale.** No bot closes them, and they stay open until they are fixed or we agree with you that they are not a vulnerability.

## Supported versions

stuntkey is in beta. Only the latest release on PyPI gets security fixes; please upgrade (`pipx upgrade stuntkey`) before reporting. Older versions get none.

| Version | Security fixes |
|---|---|
| latest 0.x release | yes |
| older 0.x releases | no |
