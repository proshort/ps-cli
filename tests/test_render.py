"""Terminal safety.

The server bounds third-party text by length and shape, not by character -- which
is right for JSON and not sufficient for a terminal, because a terminal acts on
what it reads. These tests are the control.
"""
import io
import json

import pytest

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


# ------------------------------------------------------------- bidi overrides


def test_a_bidi_override_cannot_forge_a_table_cell():
    """The forgery left standing after escape sequences and newlines were closed.

    These reorder the *visible* text without changing a byte, so neither
    stripping controls nor collapsing newlines touches them. `Acme
    Corp\\u202e000,000$2` renders as `Acme Corp$2,000,000` in a terminal, and a
    person auditing the row by eye has no way to tell. Same trick as the "Trojan
    Source" attack on code review, pointed at a table cell.
    """
    forged = "Acme Corp‮000,000$2"
    assert render.sanitize_line(forged) == "Acme Corp000,000$2"


@pytest.mark.parametrize(
    "codepoint",
    ["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"],
)
def test_every_bidi_override_and_isolate_is_stripped(codepoint):
    assert codepoint not in render.sanitize_line(f"a{codepoint}b")
    # The prose form too: a reordered sentence in a call summary is as much a lie
    # as a reordered cell, and only the *layout* class is the line form's alone.
    assert codepoint not in render.sanitize(f"a{codepoint}b")


def test_stripping_an_override_does_not_join_the_words_around_it():
    """Removed rather than replaced with a space, unlike the layout class: an
    override has no width of its own, so deleting it leaves the text as written."""
    assert render.sanitize_line("Acme‎Corp") == "AcmeCorp"


def test_json_output_still_carries_the_bytes_the_server_sent(capsys):
    """Same rule as every other class here: machine output is escaped by the JSON
    encoder, which is lossless, and altering data on its way into a file would be
    a different and worse bug."""
    render.emit_json({"name": "Acme‮Corp"})
    assert "\\u202e" in capsys.readouterr().out
