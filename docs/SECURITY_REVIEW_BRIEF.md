# stuntkey: brief for an outside security reviewer

**Status:** beta, 0.9.4. No independent review has been done. This page is the scope we
would hand to a reviewer. It makes no claim about the result.

## What it is

A Python program (standard library only, Python 3.10+) that keeps API keys out of an AI
agent's environment. The agent asks stuntkey to call a service; stuntkey adds the key
itself, scrubs the reply, and asks the user before any write. An optional Claude Code hook
refuses some tool calls that would read or print a key. Source: `stuntkey/`.

## What to attack (most valuable first)

1. **Key never reaches the agent.** Try to get a stored key back through the MCP server
   (`stuntkey/mcp.py`), the local web door (`httpd.py`), `call`, `proxy`, `run`, `export`.
2. **Scrubbing** (`scrub.py`, `redact.py`): disguises that get a key through a reply
   (encodings, splits, case, unicode, very long or odd keys).
3. **Destination control** (`broker.py`, `recipes.py`): make a key go to a host the recipe
   did not name (DNS rebinding, redirects, proxies, IP forms, planted recipes).
4. **Approval** (`approve.py`, `dialog.py`, `policy.py`): get a write through without a
   click, or make the pop-up show something other than what is sent.
5. **The hook** (`hook.py`): read `.env`, the keychain or a key by a route it misses. Its own
   limits are listed in SECURITY.md; new ones are what we want.
6. **Activity log and caps** (`ledger.py`, `caps.py`): forge, hide or reset without
   detection by `stuntkey audit verify`.
7. **Installers and config writers** (`agentsetup.py`, `install` paths): can a crafted
   existing config make a write corrupt or redirect something?

## Threat model and stated limits

Read `docs/THREAT_MODEL.md` and the "does NOT defend against" and "Known limits" sections of
`SECURITY.md` first. In particular, **out of scope by design:** malware or an agent running
arbitrary code as the same user (it can read the keychain), and a compromised vendor.

## Build and run (no network, fake keys only)

```
git clone https://github.com/calasdan-sketch/stuntkey && cd stuntkey
python -m venv .venv && .venv\Scripts\activate      (Linux/macOS: source .venv/bin/activate)
pip install -e . pytest
python -m pytest -q -p no:cacheprovider             # the test suite
python -m stuntkey selftest                         # simulated attacks, pretend server
python -m leakbench --profile stuntkey-hook --extended
```

Use a throwaway home so your real keys are untouched: set `HOME`, `USERPROFILE`, `APPDATA`
and `LOCALAPPDATA` to an empty folder, and `STUNTKEY_KEYCHAIN=memory` (a test-only in-memory
keychain; it is not secure). Use made-up keys only.

## Known numbers (from `leakbench/README.md`, real runs)

- Core 64 probes, `stuntkey-hook`, key registered: 55 blocked, 7 masked, 2 leaked.
- Same with a key stuntkey never saw and no known format (`--canary opaque`): 7 of 64 leak.
- The probes are simulated tool calls, not a real model.

## What we want back

A list of findings with: version, steps to reproduce (made-up key), what leaked or what was
bypassed, and how bad you think it is. Findings that match a known limit are still useful if
they show it is worse than written.

## How to report

Privately, not in a public issue: GitHub private vulnerability reporting at
https://github.com/calasdan-sketch/stuntkey/security/advisories/new, or
security@calasautomations.com. We aim to reply within 7 days and ask for up to 90 days
before publishing (see `SECURITY.md`). We credit you unless you prefer not.

## Cost note

A paid review is not budgeted yet. This brief is also what we would post for a volunteer or
community review. We will not describe the project as reviewed until a written result exists.
