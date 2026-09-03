"""The command layer: output contract, and the races around sign-in.

`_emit` is the one user-visible contract that was only ever tested indirectly --
a table when a person is watching, JSON the moment it is piped, and the size
warning on stderr where it cannot corrupt either.
"""
import json
import time

import pytest

from proshort_cli import cli, render
from proshort_cli.errors import EXIT_ERROR, EXIT_USAGE, CliError
from proshort_cli.store import Credentials, CredentialStore


def _creds(**over) -> Credentials:
    base = {
        "access_token": "psmcp_at_a",
        "refresh_token": "psmcp_rt_a",
        "expires_at": time.time() + 600,
        "scopes": ["deals:read"],
        "base_url": "https://example.invalid",
        "client_id": "proshort-cli",
    }
    base.update(over)
    return Credentials(**base)


def _args(argv):
    return cli.build_parser().parse_args(argv)


# ----------------------------------------------------------------- the output


def _emit(monkeypatch, capsys, argv, body, *, tty: bool, table="deals"):
    monkeypatch.setattr(render, "is_tty", lambda: tty)
    cli._emit(_args(argv), body, table=table)
    return capsys.readouterr()


def test_a_person_watching_gets_a_table(monkeypatch, capsys):
    out = _emit(
        monkeypatch, capsys, ["deals", "list"],
        {"data": [{"name": "Acme", "stage": "Won"}], "truncated": False},
        tty=True,
    )
    assert "NAME" in out.out and "Acme" in out.out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out.out)


def test_a_pipe_gets_json_without_asking(monkeypatch, capsys):
    """The rule that makes `| jq` work with no flag. It also means
    `proshort deals list > out.txt` writes JSON, which the README now says."""
    out = _emit(
        monkeypatch, capsys, ["deals", "list"],
        {"data": [{"name": "Acme"}], "truncated": False},
        tty=False,
    )
    assert json.loads(out.out)["data"] == [{"name": "Acme"}]


def test_json_is_forced_even_on_a_terminal(monkeypatch, capsys):
    out = _emit(
        monkeypatch, capsys, ["deals", "list", "--json"],
        {"data": [{"name": "Acme"}], "truncated": False},
        tty=True,
    )
    assert json.loads(out.out)["data"] == [{"name": "Acme"}]


def test_ndjson_is_one_object_per_line(monkeypatch, capsys):
    out = _emit(
        monkeypatch, capsys, ["deals", "list", "--ndjson"],
        {"data": [{"id": 1}, {"id": 2}], "truncated": False},
        tty=True,
    )
    lines = out.out.strip().splitlines()
    assert [json.loads(line)["id"] for line in lines] == [1, 2]


def test_the_truncation_warning_goes_to_stderr_and_names_what_went(monkeypatch, capsys):
    """On stderr, so it cannot corrupt the JSON a script is parsing, and it names
    the sections so a caller can tell a clipped answer from a complete one."""
    out = _emit(
        monkeypatch, capsys, ["deals", "list"],
        {"data": [], "truncated": True, "omitted": ["risks", "meddicc"]},
        tty=False,
    )
    assert "risks" in out.err and "meddicc" in out.err
    assert "clipped" in out.err
    # The warning itself stays off stdout; `omitted` legitimately appears in the
    # JSON body, which is where a script should read it from.
    assert "clipped" not in out.out
    assert json.loads(out.out)["omitted"] == ["risks", "meddicc"]


def test_machine_output_is_never_sanitised(monkeypatch, capsys):
    """A script consuming --json must get the bytes the server sent; the JSON
    encoder escapes them losslessly. Only human output is rewritten."""
    hostile = "Acme\x1b[2K\rgone"
    out = _emit(
        monkeypatch, capsys, ["deals", "list"],
        {"data": [{"name": hostile}], "truncated": False},
        tty=False,
    )
    assert json.loads(out.out)["data"][0]["name"] == hostile


def test_human_output_is_sanitised(monkeypatch, capsys):
    out = _emit(
        monkeypatch, capsys, ["deals", "list"],
        {"data": [{"name": "Acme\x1b[2K\rgone"}], "truncated": False},
        tty=True,
    )
    assert "\x1b" not in out.out


# ------------------------------------------------------------------ arguments


@pytest.mark.parametrize(
    "argv", [["deals", "list", "--limit", "0"], ["deals", "list", "--limit", "-1"],
             ["whoami", "--timeout", "0"], ["whoami", "--timeout", "-5"]]
)
def test_a_non_positive_count_is_refused_at_the_parser(argv):
    """`type=int` accepted `-1`, and a negative --timeout made the command
    deadline expire before the first request -- reported as "Proshort is
    unavailable", which is a wrong answer about somebody else."""
    with pytest.raises(SystemExit) as caught:
        _args(argv)
    assert caught.value.code == EXIT_USAGE


def test_an_explicit_timeout_is_not_read_as_unset():
    """`or` treats every falsy value as unset, so `--timeout 0` silently became
    60. The parser refuses 0 now; this pins that the idiom below it is `is None`.
    """
    assert _args(["whoami"]).timeout is None
    assert _args(["whoami", "--timeout", "5"]).timeout == 5


# -------------------------------------------------------------- sign-in races


def test_relogin_revokes_what_is_on_disk_now_not_what_it_saw_before_the_browser(
    tmp_path, monkeypatch
):
    """`cmd_login` loads the existing pair, waits up to five minutes for a
    browser, then revokes. A command run in that window rotates the family, so
    the snapshot it holds is a *spent* refresh token -- and presenting one is the
    server's theft signal, which would revoke the family the other command just
    stored. Re-read under the lock, at revoke time.
    """
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    CredentialStore("default").save(_creds(refresh_token="rt_before_browser"))

    def login_while_another_command_refreshes(**_):
        # What a parallel `proshort deals list` does during the browser wait.
        CredentialStore("default").save(_creds(refresh_token="rt_rotated"))
        return {"access_token": "at_new", "refresh_token": "rt_new", "expires_in": 600}

    revoked: list[str] = []
    monkeypatch.setattr(cli.oauth, "login", login_while_another_command_refreshes)
    monkeypatch.setattr(cli.oauth, "revoke", lambda **kw: revoked.append(kw["token"]))
    monkeypatch.setattr(cli, "Client", _no_network)

    assert cli.cmd_login(_args(["login", "--url", "https://example.invalid"])) == 0
    assert revoked == ["rt_rotated"], "revoked a token that had already been rotated away"
    assert CredentialStore("default").load().refresh_token == "rt_new"


def test_the_new_grant_is_stored_before_the_old_one_is_revoked(tmp_path, monkeypatch):
    """A revocation that fails, or throws, must not leave the user with neither
    session."""
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    CredentialStore("default").save(_creds(refresh_token="rt_old"))

    def explode(**_):
        raise RuntimeError("revocation endpoint is down")

    monkeypatch.setattr(cli.oauth, "revoke", explode)
    monkeypatch.setattr(
        cli.oauth, "login",
        lambda **_: {"access_token": "at_new", "refresh_token": "rt_new", "expires_in": 600},
    )
    monkeypatch.setattr(cli, "Client", _no_network)

    assert cli.cmd_login(_args(["login", "--url", "https://example.invalid"])) == 0
    assert CredentialStore("default").load().refresh_token == "rt_new"


def test_sign_in_holds_the_refresh_lock_while_it_swaps_the_grant(tmp_path, monkeypatch):
    """Not just the re-read: the window between reading and writing has to be
    closed, or a concurrent refresh lands after this save and overwrites the new
    grant with a pair this login has already revoked.
    """
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    CredentialStore("default").save(_creds())

    held: list[bool] = []
    real_lock = CredentialStore.refresh_lock

    def watched(self):
        held.append(True)
        return real_lock(self)

    monkeypatch.setattr(CredentialStore, "refresh_lock", watched)
    monkeypatch.setattr(cli.oauth, "revoke", lambda **_: None)
    monkeypatch.setattr(
        cli.oauth, "login",
        lambda **_: {"access_token": "at", "refresh_token": "rt", "expires_in": 600},
    )
    monkeypatch.setattr(cli, "Client", _no_network)

    cli.cmd_login(_args(["login", "--url", "https://example.invalid"]))
    assert held, "sign-in swapped the grant without taking the refresh lock"

    held.clear()
    cli.cmd_logout(_args(["logout"]))
    assert held, "sign-out revoked and cleared without taking the refresh lock"


def _no_network(*_a, **_k):
    """Stand in for the courtesy `whoami` after sign-in."""
    raise CliError("no network in this test", EXIT_ERROR)


def test_the_duration_windows_are_validated_before_a_request_is_made():
    """`--duration`'s help used to say "see `proshort filters`", and `filters` does
    not supply it -- it is a fixed enum, and the server's own tool description says
    the opposite. The same wrong pointer had already been fixed twice on the server
    (the OpenAPI description and the handler's error message) and was still here.

    `choices`, like `--type`, so a wrong window is refused at the parser with the
    valid list rather than after a round trip.
    """
    with pytest.raises(SystemExit) as caught:
        _args(["reps", "--duration", "LAST_WEEK"])
    assert caught.value.code == EXIT_USAGE
    assert _args(["reps", "--duration", "ALL_TIME"]).duration == "ALL_TIME"


def test_no_help_text_points_at_an_endpoint_that_cannot_answer():
    """`proshort filters` supplies stage, owner, group, department, rep, sentiment
    and call type. It has nothing to say about `duration`, and any help naming it
    has to be about a value it actually carries."""
    import contextlib
    import io

    parser = cli.build_parser()
    for argv in (["reps", "--help"], ["deals", "list", "--help"]):
        buffer = io.StringIO()
        with contextlib.suppress(SystemExit), contextlib.redirect_stdout(buffer):
            parser.parse_args(argv)
        text = buffer.getvalue()
        if "filters" in text:
            assert "duration" not in text.split("filters")[0][-120:], text


def test_the_readme_documents_every_command_and_no_others():
    """The README's command table is the first thing a new person reads.

    A table that lists a command the parser does not have sends someone to a
    usage error on their first five minutes; one that omits a command hides it
    forever. Both are the kind of drift nothing else here would catch, because
    documentation has no tests unless it is given one.
    """
    import pathlib
    import re

    readme = pathlib.Path(__file__).resolve().parent.parent / "README.md"
    documented = {
        row.split()[0]
        for row in re.findall(r"^\| `proshort ([a-z ]+?)(?: [-<].*)?` \|", readme.read_text(), re.M)
    }
    parser = cli.build_parser()
    actual = {
        name
        for action in parser._subparsers._group_actions
        for name in action.choices
    }
    assert documented == actual, f"README and parser disagree: {documented ^ actual}"
