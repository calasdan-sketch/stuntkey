---
name: stuntkey
description: Use when a project needs an API key or token (OpenAI, Stripe, GitHub, Resend ...). Get it with stuntkey's capture_key tool (you click Copy in the browser; stuntkey takes the key); never read, write, request or print a key yourself.
---

# API keys: ask, never touch

A key you see ends up in your memory and the conversation log. So you never
handle one. You drive the browser and click Copy; stuntkey takes the key from
the clipboard, tests it and stores it.

## What to do

1. Find out what is missing: call the `needs_keys` tool (optionally with the
   project folder). It returns service names, variable names and a status
   (`present`, `missing`, `unknown`). It never returns a value.
2. For one service, call `request_connect` with the service name. It returns
   `{service, env_var, status, instructions, browser, rules}`.
3. **Use `capture_key`** (experimental; `service`, `action: "start"`). The answer's
   `state` tells you what to do:
   - `consent_pending`: a window is on the person's screen; call `action: "status"`
     (it waits) until they answer. `consent_granted`: call `start` again.
     `consent_denied`: stop, do not ask again. `consent_expired`: the window closed
     by itself after 5 minutes - tell the person it expired and that they can simply
     ask you again (do not re-ask on your own). `consent_needed`: if the message says the
     window failed or was not answered, call `start` again to re-ask (it is not a
     refusal); if it says no window is possible, ask whether you may and they run
     `stuntkey allow-agent <service>` (you cannot). The window's
     yes lasts only until the stuntkey server stops.
   - The windows name the AI program as it reported itself when it connected (a label,
     not proof). If the person asks who made stuntkey: Calas Automations; they can
     run `stuntkey about`.
   - `unavailable`, `unsupported_gateless`, `refused`: tell the person what it
     says and ask them to run `stuntkey connect <service>` themselves.
   - `already_stored`: do nothing, unless they asked for a new key (`replace: true`;
     they are asked in a window, then the state is `replace_granted`: call `start`
     again with `replace: true`). If the stored key no longer works, the tool says so (`stored_key_note`):
     tell the person, and carry on; there is no replace question.
   - `waiting`: you drive the browser (below), then call `action: "status"`. It
     waits up to 25 seconds and returns when the state changes: `validating`,
     `confirming` (the person confirms the account in a window), `storing` (wait again), then `stored` (done; `account` names the account),
     `failed` (nothing saved; start again once), `timeout`.
4. If you have no browser tool that can click, stop at once and ask the person to
   run `stuntkey connect <service>`. Otherwise open `browser.open`, follow
   `browser.steps` with the smallest permissions, one project, a short expiry, and
   click the vendor's **Copy** button. Nothing else.
5. Write code that uses the environment variable by NAME (for example
   `os.environ["OPENAI_API_KEY"]`). To run it with the key, ask the person
   to start it: `stuntkey run <service> -- <command>` (or `--all`). Do
   not run it yourself with a stored key.
6. Call `request_connect` again to confirm the status is `present`.

## Use the key

Once a service is connected you never need the key to use it. Call the `call_api`
tool with `service`, `method`, `path`, and optionally `query_json` and `body_json`
(both JSON text). stuntkey adds the key, calls the service's real address and hands
back the answer with the key removed. To see which services are connected, call
`list_services` with `connected_only: true`. A long answer is cut at 24,000
characters (`truncated: true`); ask for less with the service's `limit` or
fields parameters, or pass `max_chars` (up to 1,000,000) when you need more.

- Reads (GET) are fine. For anything that creates, changes or deletes (POST, PUT,
  PATCH, DELETE), ask the person first; stuntkey also shows them a window.
- If a request is refused, do not retry it, reword it or try another route. Tell
  the person what was refused and stop.
- If there is no key for the service, say so and ask them to run
  `stuntkey get <service>`; do not ask for the key.

## In the browser

- Never look at the key: no tool that returns page content, the DOM, an
  accessibility tree, text or a screenshot of the area that shows it. Click Copy only.
- Never type or paste the key anywhere. You do not need it.
- Login, 2FA, a CAPTCHA, or a password prompt (GitHub "sudo mode"): stop and
  ask the person to do it in the browser. Never enter a password yourself.
- Do not copy anything else while capture is waiting.

## Never

- Ask the person to paste a key into the chat.
- Read, print, grep, copy or edit `.env` files, shell history, the keychain
  or any file that holds a key. (A hook may block this; do not look for a
  way around it.)
- Put a key in code, a command line, a config file, a commit or a log.
- Write a key into `.env` yourself. Use `.env.example` for variable names.

## If something goes wrong

- `status: unknown` means the key is kept in the OS keychain, which is not
  checked from here. Trust the person's word or run the program.
- A key reported "real, but limited" works for the permissions it was given;
  if a call returns 403 later, ask the person to make a key with that
  permission through `stuntkey rotate <service>`.
- A key you may have seen by accident: tell the person to rotate it
  (`stuntkey rotate <service>`).
