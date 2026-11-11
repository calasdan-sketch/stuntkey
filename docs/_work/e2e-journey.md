# StuntKey 0.9.2 end-to-end journey

Wheel built offline, installed with --no-deps into a TEMP venv (C:\Users\danie\AppData\Local\Temp\sk-venv), run in an isolated HOME (C:\Users\danie\AppData\Local\Temp\sk-journey-home) with STUNTKEY_KEYCHAIN=file:<temp>\kc and fake keys only. Real ~/.stuntkey, Credential Manager and activity log untouched.

## version

```
> stuntkey --version
stuntkey 0.9.2
(exit code 0)
```

## try (practice)

```
> stuntkey try --auto

  Practice run - nothing real is touched.
  I use a throwaway store and a temporary folder. Your real keys, your
  keychain and your activity log are not opened. When this ends,
  everything I made here is deleted.
  The key is made up: it is not a real key. (You will see the words
  "not secure" below: that is on purpose, it is only the practice store.)

  Step 1 of 3: ADD a key
  The real command is:  stuntkey get <site>
  It opens the key page, you copy the key, stuntkey tests it and
  saves it in your computer's keychain. Here I copy a pretend key for you.

  Connect Practice service  (open the key page yourself - the address is below)

    1. Pretend you are on the website's key page
    2. Copy the key (here, I do that part for you)

  Key page: https://practice.example.com/keys


  This key will NOT be tested: stuntkey does not know this site's API yet, so nothing is sent now.
  Later calls go only to api.practice.example.com.

  Γ£ô stored PRACTICE_API_KEY in the test memory keychain (not secure) (never displayed, never logged); use it with `stuntkey run practice -- <command>`

  Γ£ô Your Practice service key has been added.

  Saved. Not tested - stuntkey doesn't know this site's API yet, so it cannot say the key works.
  `stuntkey add` teaches it how to check a key.

  Step 2 of 3: USE the key
  The real command is:  stuntkey run <service> -- <your command>
  Your program gets the key; the screen never shows it. Watch: the
  little program below tries to print the key.
the key is: [REDACTED]
  The key was hidden from the output, as shown above.

  Step 3 of 3: FORGET the key
  The real command is:  stuntkey forget <service>
  It removes the key from the keychain (and asks first).
  Γ£ô forgot practice: removed the test memory keychain (not secure) entry.

  Done. The practice folder is deleted. Now the real thing:
    stuntkey get <the site you want a key for>   e.g. stuntkey get github
(exit code 0)
```

## get example.com from stdin

```
> echo <fake key> | stuntkey get example.com --key-from-stdin

  This will read the example.com key from the pipe, test it and save it in your computer's keychain.

  Connect example.com  (open the key page yourself - the address is below)

    1. Sign in to example.com (the page that opens is a search for its API key page)
    2. Create an API key, or open one you have - pick the fewest permissions it offers
    3. Copy the key

  I could not check this site's key test settings. If the screen looks different, trust the screen.

  Key page: https://example.com/


  This key will NOT be tested: stuntkey does not know this site's API yet, so nothing is sent now.
  Later calls go only to api.example.com.

  Γ£ô stored EXAMPLE_API_KEY in the test file keychain (not secure) (never displayed, never logged); use it with `stuntkey run example -- <command>`

  Γ£ô Your example.com key has been added.

  Saved. Not tested - stuntkey doesn't know this site's API yet, so it cannot say the key works.
  `stuntkey add` teaches it how to check a key.
(exit code 0)
```

## status

```
> stuntkey status
This folder has no stuntkey setup. Run `stuntkey init` to create one.
(To see keys saved anywhere on this computer, run `stuntkey overview`.)
(exit code 0)
```

## doctor

```
> stuntkey doctor
  [ok ] python: 3.12.10
  [ok ] keychain: test file keychain (not secure)
  [info] keychain: test backend file:C:\Users\danie\AppData\Local\Temp\sk-journey-home\kc
  [ok ] ssh: found
  [ok ] git: found
  [ok ] activity log: 0 entries, chain intact
  [ok ] AI tools: none yet
  [ok ] self-attack test: 77 of 77 attacks stopped

  Ready. Next: stuntkey get github
  Beta: not independently security-reviewed yet. Use at your own risk; MIT, no warranty.
(exit code 0)
```

## import a sample .env

```
> stuntkey import sample.env --yes
  This will read the keys, save them in your computer's keychain and show only their names.

  Found 2 key(s) I can save in the test file keychain (not secure):
    OPENAI_API_KEY               -> openai
    GITHUB_TOKEN                 -> github
  Left alone (no service for them): SOME_UNRELATED_SETTING
  Γ£ô saved OPENAI_API_KEY
  Γ£ô saved GITHUB_TOKEN

  The file you imported from still holds every key in plain text:
    C:\Users\danie\AppData\Local\Temp\sk-journey-home\proj\sample.env
  Delete it now. In Explorer or Finder a deleted file waits in the
  Recycle Bin or Trash, so use the command (Windows PowerShell):
    Remove-Item -LiteralPath "C:\Users\danie\AppData\Local\Temp\sk-journey-home\proj\sample.env"
  (macOS/Linux: rm). Also delete the export from any download or
  sync folder, and empty the Recycle Bin / Trash.
(exit code 0)
```

## list stored (status again)

```
> stuntkey status
This folder has no stuntkey setup. Run `stuntkey init` to create one.
(To see keys saved anywhere on this computer, run `stuntkey overview`.)
(exit code 0)
```

## forget example.com

```
> stuntkey forget example.com --yes
  Γ£ô forgot example: removed the test file keychain (not secure) entry.
(exit code 0)
```

## audit before any call (empty log)

```
> stuntkey audit
activity log: intact (0 entries)
(exit code 0)
```

## write 3 synthetic log entries the way the broker does (library call in the venv)

```
> python -c AuditLog(...).write(...) x3
{'ok': True, 'n': 3, 'mode': 'signed', 'reason': None, 'note': ''}
(exit code 0)
```

## audit (verify keyed chain)

```
> stuntkey audit
activity log: intact (3 entries)
(exit code 0)
```

## audit verify (json)

```
> stuntkey audit verify --json
{
  "intact": true,
  "entries": 3
}
(exit code 0)
```

## audit show

```
> stuntkey audit show
2026-11-10 22:09  example  GET api.example.com/v0  -> 200 (ok)
2026-11-10 22:09  example  GET api.example.com/v1  -> 200 (ok)
2026-11-10 22:09  example  GET api.example.com/v2  -> 200 (ok)
(exit code 0)
```

## start

```
> stuntkey start

stuntkey - your AI can use your keys, and never see them.

  [ok ] python: 3.12.10
  [ok ] keychain: test file keychain (not secure)
  [info] keychain: test backend file:C:\Users\danie\AppData\Local\Temp\sk-journey-home\kc
  [ok ] ssh: found
  [ok ] git: found
  [ok ] activity log: 3 entries, chain intact
  [ok ] AI tools: none yet
  [ok ] self-attack test: 77 of 77 attacks stopped

  Ready. Next: stuntkey get github
  Beta: not independently security-reviewed yet. Use at your own risk; MIT, no warranty.

Heads up: 2 place(s) where a key is lying around in plain text. Run `stuntkey scan` to see where (it never shows the key).

Connected already: github, openai.
Next: run `stuntkey install` to plug it into Claude, Cursor or VS Code (or `stuntkey serve` for other AI tools). Then fully quit and reopen that app.
(exit code 0)
```

## serve: the page

```
> stuntkey serve  (then fetch the one-time link)
link line: http://127.0.0.1:55271/?c=<one-time>
GET / with no cookie -> 401
GET one-time link -> 303 Location: / cookie set: True
GET / with cookie -> 200 bytes 25471
placeholders left: False False
version text: True True
status json: {"keys":[{"name":"GitHub"},{"name":"OpenAI"}],"practice_cmd":"stuntkey try"}
mentions stuntkey try: True | mentions selftest: False
one-time link used a second time -> 401
(exit code 0)
```

## tamper test: edit one log line, then verify must fail

```
> (edit audit.log in the isolated home) ; stuntkey audit
log file: C:\Users\danie\AppData\Local\Temp\sk-journey-home\kc\audit.log
activity log: TAMPERED (1 entries) - the log does not check out
--- restoring is not possible; this home is thrown away ---
(exit code 1)
```


> Notes: (1) stuntkey start is the text tour; the web page is served by stuntkey serve (one-time link in its output), tested in the 'serve: the page' step. (2) Top-level status is the per-project table and needs a stuntkey.json (stuntkey init); overview shows keys anywhere. (3) The empty-log, 3-entry and tamper steps use the library to write synthetic log lines because no real network call is made in this journey. (4) Bugs found and fixed during the journey: the venv first ran an older wheel (rebuilt); serve output was not flushed when redirected; bare stuntkey audit errored (now means verify); a brand-new empty log wrongly warned 'not signed' (now silent until it has entries).

