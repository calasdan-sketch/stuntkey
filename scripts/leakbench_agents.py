"""Score the Codex and Cursor adapters on leakbench's probes. The probes are Claude Code shaped; each is converted to the app's DOCUMENTED
hook format (Codex: hook_event_name PreToolUse/PostToolUse, tool_name Bash; Cursor: preToolUse, tool_name Shell) and sent through the adapter.
NOT the real apps: it measures this repository's adapters against the documented formats. Run from the repo root:
    python scripts/leakbench_agents.py
Writes nothing outside a throwaway sandbox that leakbench builds and deletes."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from leakbench import harness, profiles  # noqa: E402
from stuntkey import codexhook, cursorhook, scrub as scrub_mod  # noqa: E402

TO_CURSOR = {"Bash": "Shell", "PowerShell": "Shell"}


def codex_profile():
    state = {"home": None}

    def prepare(sbx):
        state["home"] = sbx.home
        path = os.path.join(sbx.home, ".stuntkey", scrub_mod.FINGERPRINT_FILE)
        if not os.path.exists(path):
            scrub_mod.remember_key("keycanary/API_KEY", sbx.canary, path)

    def profile(payload):
        with profiles._home(state["home"]):
            st, out, _err = codexhook.run(json.dumps({**payload, "hook_event_name": "PreToolUse"}))
        if st == 2:
            return True, "blocked (hook failed closed)"
        try:
            return json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny", "denied"
        except Exception:
            return False, None

    def post(payload, response):
        with profiles._home(state["home"]):
            st, out, _err = codexhook.run(json.dumps({**payload, "hook_event_name": "PostToolUse", "tool_response": response}))
        if out and json.loads(out).get("decision") == "block":
            return {**response, "stdout": "[redacted] withheld by stuntkey", "stderr": ""}
        return response
    profile.prepare, profile.post = prepare, post
    return profile


def cursor_profile():
    state = {"home": None}

    def prepare(sbx):
        state["home"] = sbx.home
        path = os.path.join(sbx.home, ".stuntkey", scrub_mod.FINGERPRINT_FILE)
        if not os.path.exists(path):
            scrub_mod.remember_key("keycanary/API_KEY", sbx.canary, path)

    def profile(payload):
        p = dict(payload)
        p["tool_name"] = TO_CURSOR.get(p.get("tool_name"), p.get("tool_name"))
        with profiles._home(state["home"]):
            st, out, _err = cursorhook.run(json.dumps({**p, "hook_event_name": "preToolUse"}))
        if st == 2:
            return True, "blocked (hook failed closed)"
        try:
            return json.loads(out).get("permission") == "deny", "denied"
        except Exception:
            return False, None
    profile.prepare = prepare       # no post: Cursor cannot hide a shell command's output
    return profile


orig = profiles.get
profiles.get = lambda name: {"codex": codex_profile, "cursor": cursor_profile}[name]() if name in ("codex", "cursor") else orig(name)
res = {}
for name in ("none", "stuntkey-hook", "codex", "cursor"):
    attack = harness.run(name)
    benign = harness.run_benign(name)
    sa, sb = {}, {}
    for r in attack:
        sa[r.status] = sa.get(r.status, 0) + 1
    for r in benign:
        sb[r.status] = sb.get(r.status, 0) + 1
    res[name] = {"attack": sa, "benign": sb, "leaked": sorted(r.probe_id for r in attack if r.status == "leaked")}
    print(name.ljust(14), "attack", sa, "| harmless", sb)
if "--json" in sys.argv:
    print(json.dumps(res, indent=1))
