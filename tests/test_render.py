"""Terminal safety.

The server bounds third-party text by length and shape, not by character -- which
is right for JSON and not sufficient for a terminal, because a terminal acts on
what it reads. These tests are the control.
"""
import io
import json

from proshort_cli import render


def test_escape_sequences_are_removed_from_human_output():
    """A deal name can erase the line above it, and a reader would never know.

    Deal names come from the customer's CRM and a prospect chooses their own
    company name, so this is attacker-influenced text by construction.
    """
    hostile = "Acme\x1b[2K\rNothing to see here"
    assert render.sanitize(hostile) == "AcmeNothing to see here"
    assert "\x1b" not in render.sanitize(hostile)


def test_window_title_sequences_are_removed():
    assert render.sanitize("Deal\x1b]0;pwned\x07 name") == "Deal name"


def test_a_lone_escape_leaves_nothing_behind():
    """Stripping controls before sequences would leave `[2K` as visible text."""
    assert render.sanitize("a\x1bb") == "ab"


def test_carriage_returns_and_backspaces_go():
    assert render.sanitize("real\r\x08\x08\x08\x08fake") == "realfake"


def test_tabs_survive():
    """A tab is a separator, not an instruction."""
    assert render.sanitize("a\tb") == "a\tb"


def test_nested_strings_are_reached():
    payload = {"deals": [{"name": "x\x1b[31my", "tags": ["\x1b[2Kz"]}]}
    assert render.sanitize_deep(payload) == {"deals": [{"name": "xy", "tags": ["z"]}]}


def test_keys_are_sanitized_too():
    assert render.sanitize_deep({"a\x1b[2Kb": 1}) == {"ab": 1}


def test_json_output_is_escaped_not_stripped(monkeypatch):
    """`--json` must be the bytes the server sent.

    The JSON encoder escapes control characters losslessly, which is the correct
    treatment. Quietly altering data on its way into a file would be a different
    and worse bug than the one sanitisation exists to prevent.
    """
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    render.emit_json({"name": "a\x1b[2Kb"})
    written = out.getvalue()
    assert "\\u001b" in written
    assert json.loads(written)["name"] == "a\x1b[2Kb"


def test_diagnostics_never_reach_stdout(monkeypatch):
    """So `ps deals list --json | jq` works with nothing thrown away."""
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    render.note("heads up")
    assert out.getvalue() == ""
    assert "heads up" in err.getvalue()


def test_a_runaway_field_cannot_push_columns_off_screen(monkeypatch):
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    render.emit_table([{"name": "x" * 500}], [("NAME", "name")])
    assert max(len(line) for line in out.getvalue().splitlines()) <= 48


def test_global_flags_work_on_either_side_of_the_subcommand():
    """`ps whoami --json` is what people type; `ps --json whoami` is what argparse wants.

    Both must work, and the `SUPPRESS` default on the subparser copies is what
    stops the second form being silently overwritten by the first's default.
    """
    from proshort_cli.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["whoami", "--json"]).json is True
    assert parser.parse_args(["--json", "whoami"]).json is True
    assert parser.parse_args(["whoami"]).json is False
    # And on a nested subcommand.
    assert parser.parse_args(["deals", "list", "--json"]).json is True
    assert parser.parse_args(["--timeout", "5", "deals", "list"]).timeout == 5
