"""Turning a response into something safe to put on a terminal.

**This module is a security control, and it does not look like one.**

Deal names, prospect names, meeting titles, CRM notes, email bodies and AI call
summaries are all third-party text: a prospect chooses their own company name,
and an external party writes the emails logged against a deal. The server bounds
that text by *length and shape* -- `dto.passthrough` truncates strings and caps
nesting -- and deliberately does not bound its *characters*, because rewriting
customer data would be worse than passing it through.

Which is correct for a model client reading JSON, and not sufficient the moment
that text reaches a terminal. A terminal executes what it reads: a name carrying
CSI or OSC sequences can move the cursor, erase what was printed above it, repaint
the screen, or set the window title. So a deal called
`Acme\\x1b[2K\\rNothing to see here` can hide the row above it, and a person
reading the output would never know.

Two rules, and they are different on purpose:

- **Human output is sanitized.** Control characters are stripped and escape
  sequences removed, because the destination interprets them.
- **JSON output is not.** It is escaped by the JSON encoder, which is the correct
  and lossless treatment, and a script consuming `--json` must get the bytes the
  server sent. Silently altering data on its way into a file would be a different
  and worse bug.
"""

import json
import re
import sys
from typing import Any

# C0 controls, DEL and the C1 block. Tab and newline are handled separately by
# the two entry points below, because they are a different kind of problem: an
# escape sequence makes the terminal *act*, while a newline or a tab forges
# *structure*. Both matter and they do not have the same fix.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# Newline and tab. Stripped only where the output has one line per record.
_LAYOUT = re.compile(r"[\t\n\r\x0b\x0c\u2028\u2029]+")

# ANSI escape sequences: CSI (cursor movement, colour, erase), OSC (window title,
# hyperlinks -- terminated by BEL or ST), and the short two-character forms.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"       # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL | ST
    r"|\x1b[@-Z\\-_]"                # two-character escapes
)


def sanitize(value: str) -> str:
    """Make one string safe to *print*. Escapes first, then stray controls.

    Order matters: stripping the lone `\x1b` first would leave `[2K` behind as
    literal text, and would break the sequence match so a longer OSC payload
    survived as visible garbage.

    Newline and tab survive here, because this is the prose form -- a call recap
    or a deal summary keeps its paragraphs. Anywhere the output is one line per
    record, use `sanitize_line`.
    """
    return _CONTROL.sub("", _ANSI.sub("", value))


def sanitize_line(value: str) -> str:
    """`sanitize`, plus anything that would forge a line or a column.

    A terminal acts on what it reads, and that cuts two ways. An escape sequence
    makes it *do* something -- `sanitize` handles that. A newline or a tab makes
    it *lay out* something, and in a row-per-record table or a one-line
    diagnostic that is just as effective: a deal named

        Acme\nFAKE ROW    Closed Won    $2,000,000

    prints as two rows, and the second one is a lie the reader has no way to spot.
    `\r` was already covered as a C0 control and `\n` was not, which made the
    protection look present while the more useful character walked through it.

    Collapsed to a single space rather than removed, so the words on either side
    do not run together into a different word.
    """
    return _LAYOUT.sub(" ", sanitize(value)).strip()


def sanitize_deep(value: Any) -> Any:
    """Sanitize every string in a decoded response, for human rendering only.

    The prose form, because this also feeds the pretty-printed single-object view
    where a call recap should keep its paragraphs. Table cells go through
    `sanitize_line` separately in `_cell`, since a row is one line by definition.
    """
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, list):
        return [sanitize_deep(item) for item in value]
    if isinstance(value, dict):
        # Keys use the line form: a key is a label, never a paragraph.
        return {sanitize_line(str(k)): sanitize_deep(v) for k, v in value.items()}
    return value


def is_tty() -> bool:
    return sys.stdout.isatty()


def emit_json(payload: Any, *, ndjson_rows: list[Any] | None = None) -> None:
    """Machine output. Never sanitized -- the JSON encoder escapes it losslessly."""
    if ndjson_rows is not None:
        for row in ndjson_rows:
            sys.stdout.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
        return
    sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")


def note(message: str) -> None:
    """Diagnostics go to stderr, always, and are sanitized on the way.

    Stderr is a terminal too. Almost everything printed here has passed through
    the server from somewhere else -- an error message, the list of omitted
    sections, a deal name inside an exception -- so sanitizing at each call site
    means sanitizing at every call site, forever, including the ones added later.
    Doing it here instead makes that impossible to forget.

    `sanitize_line`, not `sanitize`: a diagnostic is one line, and a newline in it
    would let a CRM field forge a second one that looks like our own output.
    """
    sys.stderr.write(f"{sanitize_line(message)}\n")


def emit_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> None:
    """Human output. Sanitized, because the destination interprets what it reads."""
    if not rows:
        note("no results")
        return

    header = [label for label, _ in columns]
    body: list[list[str]] = []
    for row in rows:
        body.append([_cell(row.get(key)) for _, key in columns])

    widths = [len(h) for h in header]
    for line in body:
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(cell))
    # A single runaway field should not push every other column off screen.
    widths = [min(w, 48) for w in widths]

    sys.stdout.write("  ".join(h.ljust(w)[:w] for h, w in zip(header, widths)) + "\n")
    for line in body:
        sys.stdout.write("  ".join(c.ljust(w)[:w] for c, w in zip(line, widths)) + "\n")


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, dict)):
        return sanitize_line(json.dumps(value, default=str))[:48]
    return sanitize_line(str(value))
