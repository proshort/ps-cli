"""Command definitions and the entry point.

Output rule, applied everywhere: **data on stdout, everything else on stderr**,
and JSON whenever stdout is not a terminal. So the same command serves a person
reading a table and a script running `| jq`, without a flag and without
`2>/dev/null`.
"""

import argparse
import sys
import time

from proshort_cli import oauth, render
from proshort_cli.api import Client
from proshort_cli.errors import CliError, EXIT_OK, EXIT_USAGE
from proshort_cli.render import emit_json, emit_table, note
from proshort_cli.store import CredentialStore, Credentials

DEFAULT_BASE_URL = "https://ps-mcp-prod-apps.internal.proshort.ai"

SCOPES = [
    "profile:read",
    "filters:read",
    "deals:read",
    "reps:read",
    "recordings:read",
    "meetings:read",
]

# Columns for the human table. Deliberately few: a terminal row that wraps is
# worse than one that omits, and `--json` is right there for everything else.
TABLES = {
    "deals": [("NAME", "name"), ("STAGE", "stage"), ("AMOUNT", "amount"), ("CLOSE", "close_date")],
    "recordings": [("TITLE", "title"), ("WHEN", "start_time"), ("SENTIMENT", "call_sentiment")],
    "meetings": [("TITLE", "title"), ("WHEN", "start_time"), ("PLATFORM", "platform")],
    "activities": [("DEAL", "deal_id"), ("TYPE", "activity_type"), ("WHEN", "activity_time")],
    "reps": [("REP", "name"), ("DEALS", "deal_count"), ("REVENUE", "revenue")],
    "calls": [("DOCUMENT", "document_id"), ("RECAP", "overview")],
    "filters": [("FILTER", "name"), ("TYPE", "type")],
}


def _repeat(values, name):
    return [(name, v) for v in (values or [])]


# --------------------------------------------------------------------- commands


def cmd_login(args) -> int:
    store = CredentialStore(args.profile)
    existing = store.load()
    scopes = list(SCOPES)
    if args.scope:
        scopes = [s.strip() for s in args.scope.split(",") if s.strip()]
    if args.add_scope:
        base = existing.scopes if existing else SCOPES
        scopes = sorted(set(base) | {args.add_scope})

    unknown = [s for s in scopes if s not in SCOPES]
    if unknown:
        raise CliError(f"unknown permission(s): {', '.join(unknown)}", EXIT_USAGE)

    base_url = (args.url or (existing.base_url if existing else None) or DEFAULT_BASE_URL).rstrip("/")
    payload = oauth.login(
        base_url=base_url,
        client_id=args.client_id,
        scopes=scopes,
        open_browser=not args.no_browser,
    )
    granted = (payload.get("scope") or " ".join(scopes)).split()
    store.save(
        Credentials(
            access_token=payload["access_token"],
            refresh_token=payload["refresh_token"],
            expires_at=time.time() + int(payload.get("expires_in", 600)),
            scopes=granted,
            base_url=base_url,
            client_id=args.client_id,
        )
    )
    who = Client(store).get("/v1/me").get("data", {})
    name = render.sanitize(str(who.get("display_name") or "your account"))
    note(f"✓ signed in as {name} · {len(granted)} permissions")
    return EXIT_OK


def cmd_logout(args) -> int:
    CredentialStore(args.profile).clear()
    note("✓ signed out")
    return EXIT_OK


def cmd_whoami(args) -> int:
    body = Client(CredentialStore(args.profile), timeout=args.timeout).get("/v1/me")
    return _emit(args, body, table=None, single=True)


def cmd_filters(args) -> int:
    body = _client(args).get("/v1/filters")
    return _emit(args, body, table="filters")


def cmd_deals_list(args) -> int:
    params = [("type", args.type), ("page_size", str(args.limit))]
    if args.q:
        params.append(("q", args.q))
    params += _repeat(args.stage, "stage") + _repeat(args.owner, "owner")
    client = _client(args)
    body = client.get_all("/v1/deals", params) if args.all else client.get("/v1/deals", params)
    return _emit(args, body, table="deals")


def cmd_deals_get(args) -> int:
    body = _client(args).get(f"/v1/deals/{args.deal_id}")
    return _emit(args, body, table=None, single=True)


def cmd_activities(args) -> int:
    params = _repeat(args.deal, "deal_id")
    if not params:
        raise CliError("--deal is required (repeat it for up to 25).", EXIT_USAGE)
    if args.since:
        params.append(("since", args.since))
    body = _client(args).get("/v1/activities", params)
    return _emit(args, body, table="activities")


def cmd_reps(args) -> int:
    params = [("duration", args.duration), ("page_size", str(args.limit))]
    body = _client(args).get("/v1/reps", params)
    return _emit(args, body, table="reps")


def cmd_recordings(args) -> int:
    path = "/v1/recordings/shared" if args.shared else "/v1/recordings"
    params = [("page_size", str(args.limit))]
    if args.q:
        params.append(("q", args.q))
    if args.since:
        params.append(("from", args.since))
    client = _client(args)
    body = client.get_all(path, params) if args.all else client.get(path, params)
    return _emit(args, body, table="recordings")


def cmd_calls(args) -> int:
    params = _repeat(args.document_id, "document_id")
    if not params:
        raise CliError("at least one document id is required.", EXIT_USAGE)
    body = _client(args).get("/v1/calls", params)
    return _emit(args, body, table="calls")


def cmd_meetings(args) -> int:
    params = [("page_size", str(args.limit))]
    if args.include_ongoing:
        params.append(("include_ongoing", "true"))
    body = _client(args).get("/v1/meetings/upcoming", params)
    return _emit(args, body, table="meetings")


# ----------------------------------------------------------------------- shared


def _client(args) -> Client:
    return Client(CredentialStore(args.profile), timeout=args.timeout, verbose=args.verbose)


def _emit(args, body, *, table: str | None, single: bool = False) -> int:
    data = body.get("data")

    if body.get("truncated"):
        omitted = ", ".join(body.get("omitted") or [])
        note(f"warning: the answer was clipped to fit the size limit{': ' + omitted if omitted else ''}")

    if args.ndjson:
        emit_json(None, ndjson_rows=data if isinstance(data, list) else [data])
        return EXIT_OK
    if args.json or not render.is_tty():
        emit_json(body)
        return EXIT_OK

    # Human output only from here, so this is where sanitisation happens.
    if single or not isinstance(data, list):
        emit_json(render.sanitize_deep(data))
        return EXIT_OK
    emit_table(render.sanitize_deep(data), TABLES.get(table or "", [("VALUE", "name")]))
    page = body.get("page") or {}
    if page.get("total") is not None:
        note(f"{page.get('returned', len(data))} of {page['total']}")
    return EXIT_OK


# ------------------------------------------------------------------------ parse


def _add_global_flags(parser: argparse.ArgumentParser, *, top: bool) -> None:
    """The flags that mean the same thing wherever they appear.

    Added to the top-level parser *and* to every subparser, because `ps whoami
    --json` is what a person actually types and argparse otherwise only accepts
    `ps --json whoami`.

    The subparser copies default to `SUPPRESS`, which is what makes that safe: an
    absent flag leaves the attribute unset rather than writing a default over the
    value the top-level parser already put in the namespace. Without it, adding
    these to the subparsers would silently break `ps --json whoami` -- the
    subparser's `False` would land on top of the top-level `True`.
    """
    default = (lambda value: value) if top else (lambda _value: argparse.SUPPRESS)
    parser.add_argument("--profile", default=default("default"), help="Named credential set.")
    parser.add_argument(
        "--json", action="store_true", default=default(False),
        help="Force JSON (the default when output is piped).",
    )
    parser.add_argument(
        "--ndjson", action="store_true", default=default(False), help="One JSON object per line."
    )
    parser.add_argument(
        "--timeout", type=int, default=default(60), help="Seconds to spend, including waits."
    )
    parser.add_argument(
        "--verbose", action="store_true", default=default(False), help="Diagnostics on stderr."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ps", description="Your own Proshort sales data.")
    _add_global_flags(parser, top=True)
    common = argparse.ArgumentParser(add_help=False)
    _add_global_flags(common, top=False)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("login", help="Sign in through your browser.", parents=[common])
    p.add_argument("--url", help=f"Proshort API base URL (default {DEFAULT_BASE_URL}).")
    p.add_argument("--client-id", default=oauth.DEFAULT_CLIENT_ID)
    p.add_argument("--scope", help="Comma-separated permissions to request.")
    p.add_argument("--add-scope", help="Add one permission to what you already granted.")
    p.add_argument("--no-browser", action="store_true", help="Print the URL instead of opening it.")
    p.set_defaults(func=cmd_login)

    sub.add_parser("logout", help="Forget stored credentials.", parents=[common]).set_defaults(func=cmd_logout)
    sub.add_parser("whoami", help="Who this session is signed in as.", parents=[common]).set_defaults(func=cmd_whoami)
    sub.add_parser("filters", help="Filter values you may use.", parents=[common]).set_defaults(func=cmd_filters)

    deals = sub.add_parser("deals", help="Deals.", parents=[common]).add_subparsers(
        dest="deals_command", required=True
    )
    p = deals.add_parser("list", parents=[common])
    p.add_argument("--type", default="ACTIVE", choices=["ACTIVE", "WON", "LOST", "DORMANT"])
    p.add_argument("--q", help="Match against deal names.")
    p.add_argument("--stage", action="append")
    p.add_argument("--owner", action="append")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--all", action="store_true", help="Follow pages to the server's cap.")
    p.set_defaults(func=cmd_deals_list)
    p = deals.add_parser("get", parents=[common])
    p.add_argument("deal_id")
    p.set_defaults(func=cmd_deals_get)

    p = sub.add_parser("activities", parents=[common], help="Activity timeline for up to 25 deals.")
    p.add_argument("--deal", action="append", required=False)
    p.add_argument("--since")
    p.set_defaults(func=cmd_activities)

    p = sub.add_parser("reps", parents=[common], help="Per-rep performance.")
    p.add_argument("--duration", required=True, help="Window; see `ps filters`.")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_reps)

    p = sub.add_parser("recordings", parents=[common], help="Call recordings.")
    p.add_argument("--shared", action="store_true", help="Recordings shared with you instead.")
    p.add_argument("--q")
    p.add_argument("--since", help="From this date, YYYY-MM-DD.")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_recordings)

    p = sub.add_parser("calls", parents=[common], help="AI summaries for recorded calls.")
    p.add_argument("document_id", nargs="*")
    p.set_defaults(func=cmd_calls)

    p = sub.add_parser("meetings", parents=[common], help="Your upcoming meetings.")
    p.add_argument("--include-ongoing", action="store_true")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_meetings)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        note(f"error: {exc}")
        if exc.hint:
            note(f"  {exc.hint}")
        return exc.code
    except KeyboardInterrupt:
        note("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
