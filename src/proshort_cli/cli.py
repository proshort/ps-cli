"""Command definitions and the entry point.

Output rule, applied everywhere: **data on stdout, everything else on stderr**,
and JSON whenever stdout is not a terminal. So the same command serves a person
reading a table and a script running `| jq`, without a flag and without
`2>/dev/null`.
"""

import argparse
import os
import sys
import time
from contextlib import suppress
from urllib.parse import quote

from proshort_cli import __version__, oauth, render
from proshort_cli.api import Client
from proshort_cli.errors import EXIT_OK, EXIT_USAGE, CliError, KeychainUnavailable
from proshort_cli.render import emit_json, emit_table, note
from proshort_cli.scopes import SCOPES
from proshort_cli.store import Credentials, CredentialStore

# Deliberately no default. The previous one was `*.internal.proshort.ai`, which a
# customer's machine cannot resolve at all -- so the first `proshort login` failed
# with "Proshort is unavailable", which is both wrong and the hardest possible
# thing to diagnose from the outside. An explicit value, or a clear refusal.
BASE_URL_ENV = "PROSHORT_URL"



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


def positive_int(raw: str) -> int:
    """`type=int` accepts `-1`, and the help text promises otherwise.

    A negative `--timeout` makes the command deadline expire before the first
    request, which surfaces as "Proshort is unavailable" -- a wrong answer about
    somebody else. A negative `--limit` is the server's problem to refuse, and
    making it ours is cheaper than a round trip to be told.
    """
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not a whole number.") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or greater, not {value}.")
    return value


# --------------------------------------------------------------------- commands


def _previous(store: CredentialStore):
    """What is already stored, or `None` if that cannot be established.

    `load` raises when the keychain is unreadable and holds the only possible
    copy, which is the right answer for a command that is about to *use* a
    session. `login` and `logout` are the two that are about to replace or end
    one, and neither should be blocked by a locked keychain: `save` now stamps a
    generation above anything this machine has issued, so a new grant written
    while the keychain is locked still wins once it unlocks.
    """
    try:
        return store.load()
    except KeychainUnavailable:
        return None


def cmd_login(args) -> int:
    store = CredentialStore(args.profile)
    existing = _previous(store)
    if args.scope and args.add_scope:
        # --add-scope used to overwrite --scope entirely, so one of the two the
        # user typed was silently dropped. Refused rather than guessed at.
        raise CliError(
            "--scope and --add-scope do the same job from opposite ends; pass one.",
            EXIT_USAGE,
            hint="--scope replaces the whole set; --add-scope widens what you already have.",
        )
    scopes = list(SCOPES)
    if args.scope:
        scopes = [s.strip() for s in args.scope.split(",") if s.strip()]
    if args.add_scope:
        base = existing.scopes if existing else SCOPES
        scopes = sorted(set(base) | {args.add_scope})

    unknown = [s for s in scopes if s not in SCOPES]
    if unknown:
        raise CliError(f"unknown permission(s): {', '.join(unknown)}", EXIT_USAGE)

    base_url = (
        args.url
        or os.environ.get(BASE_URL_ENV)
        or (existing.base_url if existing else None)
    )
    if not base_url:
        raise CliError(
            "No Proshort API address configured.",
            EXIT_USAGE,
            hint=f"Pass --url https://<your-proshort-host>, or set {BASE_URL_ENV}.",
        )
    base_url = base_url.rstrip("/")
    # Checked here, before the browser opens, so a bad address is a usage error
    # rather than a failed sign-in the user has to interpret.
    oauth.require_secure(base_url)
    payload = oauth.login(
        base_url=base_url,
        client_id=args.client_id,
        scopes=scopes,
        timeout=LOGIN_TIMEOUT if args.timeout is None else args.timeout,
        open_browser=not args.no_browser,
    )
    granted = (payload.get("scope") or " ".join(scopes)).split()

    # Revoke-then-replace, under the same lock a refresh takes, and on a *re-read*
    # of what is on disk right now -- not on `existing`, which was loaded before
    # a browser wait that can last five minutes.
    #
    # Both halves matter. Without the lock, a concurrent command can rotate the
    # family between the re-read and the save, and either (a) this revokes a
    # token that has already been spent, which is the server's theft signal, so
    # it kills the family that command just stored, or (b) that command's save
    # lands after this one and overwrites the new grant with a pair this login
    # has already revoked. Without the re-read, (a) happens every time somebody
    # runs a command while the browser is open.
    #
    # The browser wait is deliberately *outside* the lock: holding it for five
    # minutes would block every other command on the machine.
    with store.refresh_lock():
        superseded = _previous(store)
        store.save(
            announce=True,
            credentials=Credentials(
                access_token=payload["access_token"],
                refresh_token=payload["refresh_token"],
                # `_token_payload` guarantees a positive int.
                expires_at=time.time() + payload["expires_in"],
                scopes=granted,
                base_url=base_url,
                client_id=args.client_id,
                generation=superseded.generation if superseded else 0,
            ),
        )
        # After the save, never before: a failure here must not leave the user
        # with neither session. The new grant is a different family, so revoking
        # the old one cannot touch it. Best-effort, like `logout`.
        if superseded is not None and superseded.refresh_token != payload["refresh_token"]:
            with suppress(Exception):
                oauth.revoke(
                    base_url=superseded.base_url,
                    client_id=superseded.client_id,
                    token=superseded.refresh_token,
                )

    # The grant is real and stored from here on. Naming the user is a courtesy,
    # so a failure past this point must not look like a failed sign-in -- which
    # it did when `--scope` omitted `profile:read`, or when /v1/me was briefly
    # down: the user saw exit 4 or 6 and reasonably concluded they were not
    # signed in, while working credentials sat on disk.
    name = "your account"
    try:
        who = Client(store).get("/v1/me").get("data", {})
        name = str(who.get("display_name") or name)
    except CliError:
        pass
    note(f"\u2713 signed in as {name} \u00b7 {len(granted)} permissions")
    return EXIT_OK


def cmd_logout(args) -> int:
    """Revoke server-side first, then forget locally.

    Clearing the file alone left a refresh token valid for thirty days, so "I
    logged out" was not true of anything except this machine's copy.
    """
    store = CredentialStore(args.profile)
    revoked = False
    # Under the refresh lock, and loaded inside it: without that, a concurrent
    # refresh can rotate the family between the load and the revoke, and this
    # would present a spent token -- which the server reads as theft, and which
    # is a strange way to end a session the user asked to end politely. It also
    # stops that refresh from writing the credentials back after `clear()`.
    with store.refresh_lock():
        existing = _previous(store)
        if existing is not None:
            # Suppressed rather than caught-and-ignored: revocation is best effort
            # by design and the outcome is reported below, so there is nothing to
            # log here that the user is not about to be told.
            with suppress(Exception):
                oauth.revoke(
                    base_url=existing.base_url,
                    client_id=existing.client_id,
                    token=existing.refresh_token,
                )
                revoked = True
        cleared = store.clear()
    if not cleared:
        # The keychain refused the delete, so the credential is still there and
        # will come back when it unlocks. Saying "signed out" over that is the
        # same lie as reporting a locked keychain as a signed-out user.
        note(
            "\u2713 revoked, but the OS keychain could not be cleared \u2014 unlock it and "
            "run `proshort logout` again"
            if revoked
            else "\u2717 could not revoke the session and could not clear the OS keychain"
        )
    elif existing is not None and not revoked:
        note("\u2713 signed out locally \u2014 could not reach Proshort to revoke the session")
    else:
        note("\u2713 signed out")
    return EXIT_OK


def cmd_whoami(args) -> int:
    body = Client(
        CredentialStore(args.profile),
        timeout=DEFAULT_TIMEOUT if args.timeout is None else args.timeout,
    ).get("/v1/me")
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
    # Encoded, not interpolated. A `/` or a `..` in an id would otherwise be a
    # different request than the one the user typed -- the server validates the
    # id too, but composing the path is this function's job.
    body = _client(args).get(f"/v1/deals/{quote(args.deal_id, safe='')}")
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


DEFAULT_TIMEOUT = 60
LOGIN_TIMEOUT = 300


def _client(args) -> Client:
    return Client(
        CredentialStore(args.profile),
        # `is None`, not `or`: `or` reads every falsy value as "unset", so
        # `--timeout 0` silently became 60. `positive_int` refuses 0 at the
        # parser now, but an idiom that is only correct because something else
        # rejects its bad case is one edit away from being wrong again.
        timeout=DEFAULT_TIMEOUT if args.timeout is None else args.timeout,
        verbose=args.verbose,
    )


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

    Added to the top-level parser *and* to every subparser, because `proshort
    whoami --json` is what a person actually types and argparse otherwise only
    accepts `proshort --json whoami`.

    The subparser copies default to `SUPPRESS`, which is what makes that safe: an
    absent flag leaves the attribute unset rather than writing a default over the
    value the top-level parser already put in the namespace. Without it, adding
    these to the subparsers would silently break `proshort --json whoami` -- the
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
    # `None` rather than `60`, so a subcommand can tell "not given" from "given
    # 60" and pick its own default. `login` waits on a human opening a browser
    # and needs minutes; everything else is a handful of requests. Without this
    # the flag was accepted on `login` and silently ignored, which is worse than
    # not offering it.
    parser.add_argument(
        "--timeout",
        type=positive_int,
        default=default(None),
        help="Seconds to spend, including waits (default: 60; 300 for login).",
    )
    parser.add_argument(
        "--verbose", action="store_true", default=default(False), help="Diagnostics on stderr."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or "proshort",
        description="Your own Proshort sales data.",
    )
    # The first thing support asks for. Read from the installed metadata rather
    # than a second constant, so it cannot disagree with what was installed.
    parser.add_argument("--version", action="version", version=f"proshort {__version__}")
    _add_global_flags(parser, top=True)
    common = argparse.ArgumentParser(add_help=False)
    _add_global_flags(common, top=False)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("login", help="Sign in through your browser.", parents=[common])
    p.add_argument("--url", help=f"Proshort API base URL. Or set {BASE_URL_ENV}.")
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
    p.add_argument("--limit", type=positive_int, default=25)
    p.add_argument(
        "--all",
        action="store_true",
        help="Follow every page. --limit is the size of each page, not a total.",
    )
    p.set_defaults(func=cmd_deals_list)
    p = deals.add_parser("get", parents=[common])
    p.add_argument("deal_id")
    p.set_defaults(func=cmd_deals_get)

    p = sub.add_parser("activities", parents=[common], help="Activity timeline for up to 25 deals.")
    p.add_argument("--deal", action="append", required=False)
    p.add_argument("--since")
    p.set_defaults(func=cmd_activities)

    p = sub.add_parser("reps", parents=[common], help="Per-rep performance.")
    p.add_argument("--duration", required=True, help="Window; see `proshort filters`.")
    p.add_argument("--limit", type=positive_int, default=10)
    p.set_defaults(func=cmd_reps)

    p = sub.add_parser("recordings", parents=[common], help="Call recordings.")
    p.add_argument("--shared", action="store_true", help="Recordings shared with you instead.")
    p.add_argument("--q")
    p.add_argument("--since", help="From this date, YYYY-MM-DD.")
    p.add_argument("--limit", type=positive_int, default=25)
    p.add_argument(
        "--all",
        action="store_true",
        help="Follow every page. --limit is the size of each page, not a total.",
    )
    p.set_defaults(func=cmd_recordings)

    p = sub.add_parser("calls", parents=[common], help="AI summaries for recorded calls.")
    p.add_argument("document_id", nargs="*")
    p.set_defaults(func=cmd_calls)

    p = sub.add_parser("meetings", parents=[common], help="Your upcoming meetings.")
    p.add_argument("--include-ongoing", action="store_true")
    p.add_argument("--limit", type=positive_int, default=10)
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
