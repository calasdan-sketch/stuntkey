import shutil
import subprocess

import unittest

try:
    import pytest
except ImportError:   # CI's plain unittest run has no pytest
    raise unittest.SkipTest("pytest is not installed")

from stuntkey import cli, remote

GITHUB = {"service": "github", "env_var": "GITHUB_TOKEN",
          "fields": [{"env_var": "GITHUB_TOKEN", "name": "key", "label": "token"}]}
TOKEN = "gho_" + "A" * 36


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "home_dir", lambda: str(tmp_path / "home"))
    return tmp_path


def _env(tmp_path, token=TOKEN):
    f = tmp_path / ".env"
    f.write_text(f"GITHUB_TOKEN={token}\n")
    return str(f)


def _run(tmp_path, command=("git", "pull"), **kw):
    seen = {}

    def runner(argv, input=None, **_):
        seen["argv"], seen["input"] = argv, input
        return subprocess.CompletedProcess(argv, 0)

    kw.setdefault("isatty", True)
    kw.setdefault("ask", lambda _q: "y")
    kw.setdefault("window", lambda *_a: None)          # no pop-up in tests: ask on the terminal
    kw.setdefault("scan", lambda *_a: (None, None))     # no ssh-keyscan either
    code = remote.run_remote(GITHUB, "root@203.0.113.7", list(command),
                             env_file=_env(tmp_path), runner=runner,
                             backend=None, **kw)
    return code, seen


def test_secret_goes_on_stdin_only(tmp_path):
    code, seen = _run(tmp_path, run_as="calas")
    assert code == 0
    assert TOKEN not in " ".join(seen["argv"])           # never on a command line
    assert seen["input"] == (TOKEN + "\n").encode()       # only on stdin
    assert "BatchMode=yes" in seen["argv"]                # never waits on a password
    assert "runuser -u calas -- git pull" in seen["argv"][-1]


def test_new_server_needs_a_person_to_say_yes(tmp_path):
    with pytest.raises(remote.RemoteError):               # no terminal, not confirmed
        _run(tmp_path, isatty=False)
    with pytest.raises(remote.RemoteError):               # person says no
        _run(tmp_path, ask=lambda _q: "n")
    code, _ = _run(tmp_path)                              # person says yes -> remembered
    assert code == 0
    code, _ = _run(tmp_path, isatty=False)                # later runs need no prompt
    assert code == 0


def test_github_header_is_scoped_and_keeps_existing_git_config():
    s = remote.build_script(GITHUB, ["git", "pull"])
    assert "http.https://github.com/.extraHeader" in s
    assert "GIT_CONFIG_COUNT:-0" in s                     # appends, never overwrites
    assert TOKEN not in s


def test_hosts_users_and_variable_names_are_checked():
    for bad in ("-oProxyCommand=x", "a b", "x;y", "", "h@x\n"):
        with pytest.raises(remote.RemoteError):
            remote.check_host(bad)
    with pytest.raises(remote.RemoteError):
        remote.build_script(GITHUB, ["git"], run_as="root\n")
    for bad in ("LD_PRELOAD", "BASH_ENV", "PATH", "GIT_SSH_COMMAND", "NODE_OPTIONS"):
        with pytest.raises(remote.RemoteError):
            remote.check_var(bad)
    remote.check_var("GITHUB_TOKEN")


def test_one_word_command_line_runs_as_a_shell_line():
    s = remote.build_script(GITHUB, ["cd /opt && git pull"])
    assert "sh -c 'cd /opt && git pull'" in s


def test_user_ssh_options_come_first_so_they_win():
    argv = remote.ssh_command("h", "true", ["-oStrictHostKeyChecking=yes"])
    assert argv.index("-oStrictHostKeyChecking=yes") < argv.index("StrictHostKeyChecking=yes")


def test_options_after_the_host_are_not_swallowed(monkeypatch):
    got = {}

    def fake(recipe, host, command, **kw):
        got.update(host=host, command=command, **kw)
        return 0

    monkeypatch.setattr(remote, "run_remote", fake)
    code = cli.main(["remote", "github", "root@h", "--as", "calas", "--env-file", "x.env",
                     "--", "git", "pull"])
    assert code == 0
    assert got["run_as"] == "calas" and got["env_file"] == "x.env"
    assert got["command"] == ["git", "pull"]


def test_symlinked_env_file_is_refused(tmp_path):
    real = tmp_path / "real.env"
    real.write_text(f"GITHUB_TOKEN={TOKEN}\n")
    link = tmp_path / "link.env"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("cannot make symlinks here")
    with pytest.raises(remote.RemoteError):
        remote.collect_values(GITHUB, str(link), backend=None)


def test_trust_server_installs_key_then_proves_it(tmp_path):
    calls = []
    state = {"installed": False}

    def runner(argv, input=None, capture_output=False, **_):
        calls.append(argv[0])
        if argv[0] == "ssh-keygen":
            f = argv[argv.index("-f") + 1]
            open(f, "w").write("PRIVATE")
            open(f + ".pub", "w").write("ssh-ed25519 AAAA test\n")
            return subprocess.CompletedProcess(argv, 0)
        if input is not None:                     # the install step
            assert input == b"ssh-ed25519 AAAA test\n"
            state["installed"] = True
            return subprocess.CompletedProcess(argv, 0)
        return subprocess.CompletedProcess(argv, 0 if state["installed"] else 255)

    out = []
    key = remote.ensure_ssh_access("root@h", runner=runner, out=out.append)
    assert key.endswith("_ed25519") and state["installed"]
    assert any("now trusts" in o for o in out)


@pytest.mark.skipif(shutil.which("sh") is None or shutil.which("base64") is None,
                    reason="needs a POSIX shell")
def test_script_really_exports_token_and_scoped_git_header():
    script = remote.build_script(
        GITHUB, ["sh", "-c",
                 'echo "$GITHUB_TOKEN|$GIT_CONFIG_COUNT|$GIT_CONFIG_KEY_0|$GIT_CONFIG_VALUE_0"'])
    # a clean environment: a host that already sets GIT_CONFIG_COUNT (some CI
    # and sandboxes do) would shift the slot the script appends to
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG_")}
    out = subprocess.run(["sh", "-c", script], input=(TOKEN + "\n").encode(),
                         capture_output=True, env=env).stdout.decode().strip()
    tok, count, key, header = out.split("|")
    assert tok == TOKEN and count == "1"
    assert key == "http.https://github.com/.extraHeader"
    assert header.startswith("Authorization: Basic ")
