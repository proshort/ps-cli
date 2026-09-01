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

# C0 controls except tab, plus DEL and the C1 block. Tab survives because it is a
# legitimate separator and a terminal does not act on it beyond advancing.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# ANSI escape sequences: CSI (cursor movement, colour, erase), OSC (window title,
# hyperlinks -- terminated by BEL or ST), and the short two-character forms.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"       # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL | ST
    r"|\x1b[@-Z\\-_]"                # two-character escapes
)


def sanitize(value: str) -> str:
    """Make one string safe to print. Escapes first, then stray controls.

    Order matters: stripping the lone `\\x1b` first would leave `[2K` behind as
    literal text, which is harmless but wrong, and would break the sequence match
    so a longer OSC payload survived as visible garbage.
    """
    return _CONTROL.sub("", _ANSI.sub("", value))


def sanitize_deep(value: Any) -> Any:
    """Sanitize every string in a decoded response, for human rendering only."""
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, list):
        return [sanitize_deep(item) for item in value]
    if isinstance(value, dict):
        return {sanitize(str(k)): sanitize_deep(v) for k, v in value.items()}
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
    """Diagnostics go to stderr, always.

    So `ps deals list --json | jq` works with nothing thrown away and nothing
    interleaved -- which is the difference between a tool a person uses and a tool
    a script uses being the same tool.
    """
    sys.stderr.write(f"{message}\n")


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
        return sanitize(json.dumps(value, default=str))[:48]
    return sanitize(str(value))
