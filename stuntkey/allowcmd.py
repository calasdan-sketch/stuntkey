"""`stuntkey allow-agent <service>`: the person's one-time yes to agent-driven capture.

It only runs in a real terminal and asks for a typed "yes", so an agent that
can run shell commands cannot grant itself the permission (the hook also
refuses the command). The grant lives in the user's home folder
(~/.stuntkey/agent-consent.json), not in the project: a file the project's
own tools can edit could not be trusted to say the person agreed.
"""

from __future__ import annotations

import sys

from . import capture as capture_mod
from . import consent as consent_mod
from . import manifest as manifest_mod
from . import recipes as recipes_mod


def _terminal() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
    except (OSError, ValueError):
        return False


EXPLAIN = """
  You are about to let an AI agent get a {display} key for THIS project
  ({project}) without you copying or pasting anything.

  What happens: the agent opens {display}'s key page in your browser and clicks
  the Copy button. This program then takes the key off your clipboard, EMPTIES the
  clipboard, tests the key with {display}, and stores it as {env_var}. The agent
  is told only that it is stored - never the key.

  What it cannot do: log in for you, answer 2FA, or type passwords - you do
  that in the browser when asked. While it is waiting (up to 3 minutes) do not
  copy anything else.
"""

HISTORY_NOTE = """
  Windows clipboard history is ON on this computer. It keeps its own copy of
  everything copied, including the key, and nothing can remove that copy.
  Better: turn it off (Settings > System > Clipboard) and run this again.
"""


def cmd_allow_agent(args, catalog: dict, ask=input, terminal=_terminal, out=None,
                    consent_file: str | None = None, cwd: str | None = None,
                    store=None) -> int:
    out = out or sys.stdout
    root = capture_mod.project_root(cwd)
    if args.list:
        grants = consent_mod.grants_for(root, consent_file, store)
        if not grants:
            out.write("  No service is allowed for agent capture in this project.\n")
        for g in grants:
            extra = " (clipboard history accepted)" if g.get("clipboard_history_ok") else ""
            out.write(f"  {recipes_mod.printable(g['service'])}{extra}\n")
        return 0
    if args.revoke:
        n = consent_mod.revoke(root, args.service, consent_file, store)
        out.write(f"  Removed {n} permission(s) for agent capture in this project.\n")
        return 0
    if not args.service:
        out.write("error: name a service, for example: stuntkey allow-agent github\n")
        return 2
    recipe = catalog.get(args.service)
    if recipe is None or recipe.get("_builtin") is not True:
        out.write("error: agent capture works only with the built-in services "
                  "(see `stuntkey list`).\n")
        return 2
    env_file = getattr(args, "env_file", None)
    if env_file:
        problem = manifest_mod.env_file_problem(env_file)
        if problem:
            out.write(f"error: {recipes_mod.printable(problem)}\n")
            return 2
    if not terminal():
        out.write("error: this must be typed by a person in a terminal. An agent cannot "
                  "give itself this permission.\n")
        return 2
    out.write(EXPLAIN.format(display=recipes_mod.printable(recipe["display"], words=True),
                             project=recipes_mod.printable(root),
                             env_var=recipe["env_var"]))
    from . import clipboard as clipboard_mod
    warning = clipboard_mod.history_warning()
    if warning:
        out.write(HISTORY_NOTE)
        if not args.allow_clipboard_history:
            out.write("  Without --allow-clipboard-history the agent will be refused "
                      "while history is on.\n")
    try:
        answer = ask("  Type 'yes' to allow, anything else cancels: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if (answer or "").strip().lower() != "yes":
        out.write("  Nothing changed.\n")
        return 1
    try:
        consent_mod.grant(root, args.service, args.allow_clipboard_history, consent_file,
                          env_file, store)
    except OSError as e:
        out.write("error: the permission could NOT be saved "
                  f"({recipes_mod.printable(getattr(e, 'strerror', None) or e)}). Nothing "
                  "changed. Check the OS keyring and that ~/.stuntkey can be written.\n")
        return 1
    out.write(f"  (Kept in {consent_mod.integrity() if store is None else store.kind}. "
              "This terminal permission is advisory: a program running as you could "
              "read its signing secret or fake a terminal. The permission window is "
              "stronger and lasts one session.)\n")
    from . import dialog as dialog_mod
    if dialog_mod.available():
        out.write("  Note: a permission window can be shown on this computer, so the server "
                  "asks you in that window and does NOT use this terminal permission. It "
                  "is used only where no window is possible (SSH, headless) or when the "
                  "server runs with STUNTKEY_NO_WINDOW=1.\n")
    out.write(f"  Allowed. Undo any time: stuntkey allow-agent {args.service} --revoke\n")
    return 0
