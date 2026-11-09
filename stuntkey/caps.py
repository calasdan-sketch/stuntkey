"""Per-key spending caps and the kill switch.

~/.stuntkey/caps.json   {service: {"calls_session": N, "calls_day": N, "tokens_day": N}}
~/.stuntkey/usage/<service>.json   {"day": "YYYY-MM-DD", "calls": N, "tokens": N}
~/.stuntkey/STOP   while it exists, no brokered call is made (`stuntkey stop`)

Usage is shared by every stuntkey process (MCP, serve, proxy, call) and is
updated under the broker's file lock. Caps are checked before each call, and
tokens are only known once the answer is back, so a cap can be passed by the
calls already under way (at most one call each). Tokens are counted from the
`usage` the API reports; an answer without one (an OpenAI stream without
stream_options.include_usage, say) counts as 0 tokens.
"""
from __future__ import annotations

import datetime
import json
import os

from .broker import BrokerError, _file_lock

LIMITS = ("calls_session", "calls_day", "tokens_day")
STOPPED = ("stuntkey is stopped (someone ran `stuntkey stop`), so no API call "
           "was made. A person can run `stuntkey resume` to allow calls again.")


def caps_path(home: str) -> str:
    return os.path.join(home, "caps.json")


def usage_path(home: str, service: str) -> str:
    folder = os.path.join(home, "usage")
    try:
        os.makedirs(folder, exist_ok=True)     # the lock file lives beside it
    except OSError:
        pass
    return os.path.join(folder, f"{service}.json")


def stop_path(home: str) -> str:
    return os.path.join(home, "STOP")


def _today() -> str:
    return datetime.date.today().isoformat()


def load_caps(home: str) -> dict:
    """{service: {limit: int}}. A damaged file refuses everything (fail closed)."""
    try:
        with open(caps_path(home), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise BrokerError("~/.stuntkey/caps.json cannot be read, so no call was "
                          "made. Fix or delete it with `stuntkey caps set`.", 5) from None
    if not isinstance(data, dict):
        raise BrokerError("~/.stuntkey/caps.json is not valid, so no call was made.", 5)
    out = {}
    for s, c in data.items():
        if not isinstance(c, dict):
            continue
        for k, v in c.items():
            if k not in LIMITS or not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise BrokerError(f"~/.stuntkey/caps.json has a bad value for "
                                  f"'{_short(s)}' {_short(k)}, so no call was made. "
                                  "Fix it with `stuntkey caps set`.", 5)
        out[s] = dict(c)
    return out


def _short(text) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))[:40]


def _read_usage(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            u = json.load(f)
    except FileNotFoundError:
        u = {}
    except (OSError, ValueError):
        raise BrokerError("The usage record in ~/.stuntkey/usage cannot be read, "
                          "so no call was made.", 5) from None
    if not isinstance(u, dict) or u.get("day") != _today():
        return {"day": _today(), "calls": 0, "tokens": 0}
    try:
        return {"day": u["day"], "calls": max(0, int(u.get("calls", 0))),
                "tokens": max(0, int(u.get("tokens", 0)))}
    except (TypeError, ValueError, OverflowError):
        raise BrokerError("The usage record in ~/.stuntkey/usage cannot be read, "
                          "so no call was made.", 5) from None


def _write_usage(path: str, u: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(u, f)
    os.replace(tmp, path)


def usage(home: str, service: str) -> dict:
    path = usage_path(home, service)
    with _file_lock(path):
        return _read_usage(path)


def begin(home: str, service: str, session_calls: int) -> None:
    """Before a call: refuse when stopped or over a cap, else count the call.
    `session_calls` is how many calls this process already made for it."""
    if os.path.lexists(stop_path(home)):
        raise BrokerError(STOPPED, 5)
    cap = load_caps(home).get(service, {})
    path = usage_path(home, service)
    with _file_lock(path) as got:
        if not got:
            if cap:
                raise BrokerError("The usage record is busy, so no call was made. "
                                  "Try again.", 5)
            return
        u = _read_usage(path)
        over = None
        if "calls_session" in cap and session_calls >= cap["calls_session"]:
            over = f"{cap['calls_session']} calls this session"
        elif "calls_day" in cap and u["calls"] >= cap["calls_day"]:
            over = f"{cap['calls_day']} calls today"
        elif "tokens_day" in cap and u["tokens"] >= cap["tokens_day"]:
            over = f"{cap['tokens_day']} tokens today"
        if over:
            raise BrokerError(f"The '{service}' key has reached its cap of {over}, "
                              "so no call was made. A person can raise it with "
                              "`stuntkey caps set`.", 5)
        u["calls"] += 1
        _write_usage(path, u)


def add_tokens(home: str, service: str, n: int) -> None:
    if n <= 0:
        return
    path = usage_path(home, service)
    with _file_lock(path) as got:
        if got:
            try:
                u = _read_usage(path)
            except BrokerError:
                return
            u["tokens"] += n
            _write_usage(path, u)


# ---- tokens from an API answer ---------------------------------------------------

_IN = ("input_tokens", "prompt_tokens")
_OUT = ("output_tokens", "completion_tokens")


class TokenMeter:
    """Reads the `usage` an LLM API reports (OpenAI chat: prompt/completion;
    OpenAI responses and Anthropic: input/output), in a plain JSON answer or
    a stream of server-sent events. Takes the largest input and output seen,
    because Anthropic reports input at the start and output at the end."""

    LIMIT = 2_000_000

    def __init__(self, content_type: str = ""):
        self.sse = "event-stream" in content_type.lower()
        self.inp = self.out = 0
        self._buf = b""

    def _see(self, obj) -> None:
        if not isinstance(obj, dict):
            return
        for holder in (obj, obj.get("message"), obj.get("response")):
            u = holder.get("usage") if isinstance(holder, dict) else None
            if isinstance(u, dict):
                for names, attr in ((_IN, "inp"), (_OUT, "out")):
                    for n in names:
                        v = u.get(n)
                        if isinstance(v, int) and v > getattr(self, attr):
                            setattr(self, attr, v)

    def _line(self, line: bytes) -> None:
        line = line.strip()
        if line.startswith(b"data:"):
            try:
                self._see(json.loads(line[5:]))
            except (ValueError, RecursionError):
                pass

    def feed(self, chunk: bytes) -> None:
        if len(self._buf) > self.LIMIT:
            return
        self._buf += chunk
        if self.sse:
            *lines, self._buf = self._buf.split(b"\n")
            for line in lines:
                self._line(line)

    def total(self) -> int:
        if self.sse:
            self._line(self._buf)
        else:
            try:
                self._see(json.loads(self._buf))
            except (ValueError, RecursionError, UnicodeDecodeError):
                pass
        self._buf = b""
        return self.inp + self.out


def tokens_in(content_type: str, body: bytes) -> int:
    m = TokenMeter(content_type)
    m.feed(body)
    return m.total()


# ---- commands --------------------------------------------------------------------

def cmd_caps(args, home: str, ask) -> int:
    if args.caps_cmd == "show":
        caps = load_caps(home)
        names = sorted(set(caps) | {f[:-5] for f in _usage_files(home)})
        if not names:
            print("no caps set and no usage yet. `stuntkey caps set SERVICE "
                  "--calls-day 500` sets one.")
        for s in names:
            u = usage(home, s)
            limits = ", ".join(f"{k}={v}" for k, v in caps.get(s, {}).items()) or "no caps"
            print(f"  {s:14} today: {u['calls']} calls, {u['tokens']} tokens   ({limits})")
        if os.path.lexists(stop_path(home)):
            print("\n  stuntkey is STOPPED: no calls are made until `stuntkey resume`.")
        return 0
    caps = load_caps(home)
    new = dict(caps.get(args.service, {}))
    for k in LIMITS:
        v = getattr(args, k)
        if v is not None:
            if v < 0:
                print("error: a cap cannot be negative.")
                return 2
            new[k] = v
    if args.clear:
        new = {}
    shown = ", ".join(f"{k}={v}" for k, v in new.items()) or "no caps"
    if not ask(f"Set the caps for '{args.service}' to: {shown}"):
        print("not changed: the person did not approve.")
        return 5
    caps[args.service] = new
    if not new:
        caps.pop(args.service)
    from .store import write_private
    write_private(caps_path(home), json.dumps(caps, indent=2) + "\n")
    print(f"caps for '{args.service}': {shown}")
    return 0


def _usage_files(home: str) -> list:
    try:
        return [f for f in os.listdir(os.path.join(home, "usage")) if f.endswith(".json")]
    except OSError:
        return []


def cmd_stop(home: str) -> int:
    os.makedirs(home, exist_ok=True)
    with open(stop_path(home), "w", encoding="utf-8") as f:
        f.write("stopped by `stuntkey stop`\n")
    print("stuntkey is stopped: no API call will be made through it until a "
          "person runs `stuntkey resume`.")
    return 0


def cmd_resume(home: str, ask) -> int:
    if not os.path.lexists(stop_path(home)):
        print("stuntkey is not stopped.")
        return 0
    if not ask("Resume stuntkey: allow API calls through it again?"):
        print("still stopped: the person did not approve.")
        return 5
    os.remove(stop_path(home))
    print("resumed: API calls are allowed again.")
    return 0
