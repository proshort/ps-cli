"""The client's retry, error-mapping and pagination behaviour.

This module had no tests, and the `--all` defect below is exactly the kind one
would have caught: it turned a mid-scan server error into a short list and an
exit code of zero.
"""
import time

import httpx
import pytest

from proshort_cli import api
from proshort_cli.api import Client
from proshort_cli.errors import (
    EXIT_AUTH,
    EXIT_ERROR,
    EXIT_RATE_LIMIT,
    EXIT_UNAVAILABLE,
    EXIT_USAGE,
    CliError,
    InsufficientScope,
    NotAuthenticated,
)
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


@pytest.fixture
def client(tmp_path, monkeypatch) -> Client:
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    store = CredentialStore("test")
    store.save(_creds())
    return Client(store, timeout=5)


def _response(status: int, payload=None, headers=None) -> httpx.Response:
    return httpx.Response(
        status,
        json=payload if payload is not None else {},
        headers=headers or {},
        request=httpx.Request("GET", "https://example.invalid/v1/deals"),
    )


class _Streamed:
    """Stands in for `httpx.stream`'s context manager.

    The client streams and abandons a body past its ceiling rather than checking
    the size of one it has already downloaded, so the stub has to be a context
    manager over a response, not a return value.
    """

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    def __enter__(self) -> httpx.Response:
        return self._response

    def __exit__(self, *_exc: object) -> bool:
        return False


def _queue(monkeypatch, responses: list[httpx.Response]) -> list[dict]:
    """Serve `responses` in order, recording the params each call was made with."""
    seen: list[dict] = []

    def fake_stream(_method, _url, **kwargs):
        seen.append(dict(kwargs.get("params") or []))
        return _Streamed(responses.pop(0))

    monkeypatch.setattr(api.httpx, "stream", fake_stream)
    return seen


# ------------------------------------------------------------------ pagination


def test_all_stops_on_a_short_page(client, monkeypatch):
    _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": 1}, {"id": 2}], "page": {"page_size": 2}}),
            _response(200, {"data": [{"id": 3}], "page": {"page_size": 2}}),
        ],
    )
    body = client.get_all("/v1/deals", [])
    assert [row["id"] for row in body["data"]] == [1, 2, 3]
    assert body["page"]["returned"] == 3


def test_all_asks_for_each_page_in_turn(client, monkeypatch):
    seen = _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": 1}], "page": {"page_size": 1}}),
            _response(200, {"data": [], "page": {"page_size": 1}}),
        ],
    )
    client.get_all("/v1/deals", [("type", "ACTIVE")])
    assert [call["page"] for call in seen] == ["1", "2"]
    assert all(call["type"] == "ACTIVE" for call in seen)


def test_all_fails_loudly_on_a_mid_scan_error(client, monkeypatch):
    """The regression this file exists for.

    An error on page two used to be swallowed as "the depth cap, reached": the
    command returned page one and exited 0, so a Skill would summarise a partial
    pipeline as the whole thing. Silent truncation is the one failure mode this
    command must not have.

    The 422 here is the real shape -- walking past `max_page_number` is what
    ps-mcp refuses mid-scan. What matters is that it *raises*; the code is exit 2
    because a refused value is the caller having built the request wrong.
    """
    _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": 1}], "page": {"page_size": 1}}),
            _response(422, {"error": {"code": "invalid_argument", "message": "bad page"}}),
        ],
    )
    with pytest.raises(CliError) as caught:
        client.get_all("/v1/deals", [])
    assert caught.value.code == EXIT_USAGE


def test_all_surfaces_an_unavailable_downstream_rather_than_truncating(client, monkeypatch):
    _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": 1}], "page": {"page_size": 1}}),
            _response(502, {"error": {"code": "upstream_error", "message": "down"}}),
        ],
    )
    with pytest.raises(CliError) as caught:
        client.get_all("/v1/deals", [])
    assert caught.value.code == EXIT_UNAVAILABLE


# --------------------------------------------------------------------- retries


def test_an_expired_token_is_refreshed_once_and_the_call_retried(client, monkeypatch):
    _queue(monkeypatch, [_response(401, {}), _response(200, {"data": []})])
    refreshed: list[str] = []

    def fake_refresh(*, base_url, client_id, refresh_token, **_):
        refreshed.append(refresh_token)
        return {"access_token": "psmcp_at_b", "refresh_token": "psmcp_rt_b", "expires_in": 600}

    monkeypatch.setattr(api.oauth, "refresh", fake_refresh)
    assert client.get("/v1/deals") == {"data": []}
    assert refreshed == ["psmcp_rt_a"]


def test_a_second_401_after_refreshing_is_not_retried_forever(client, monkeypatch):
    """A 401 that survives a good refresh is a dead grant, not a timing problem."""
    _queue(monkeypatch, [_response(401, {}), _response(401, {})])
    monkeypatch.setattr(
        api.oauth,
        "refresh",
        lambda **_: {"access_token": "b", "refresh_token": "c", "expires_in": 600},
    )
    with pytest.raises(NotAuthenticated):
        client.get("/v1/deals")


def test_a_429_is_waited_out_and_the_call_retried(client, monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(api.time, "sleep", slept.append)
    _queue(
        monkeypatch,
        [_response(429, {}, {"Retry-After": "2"}), _response(200, {"data": []})],
    )
    assert client.get("/v1/deals") == {"data": []}
    assert slept == [2]


def test_a_wait_longer_than_the_deadline_gives_up_with_its_own_code(client, monkeypatch):
    monkeypatch.setattr(api.time, "sleep", lambda _s: None)
    _queue(monkeypatch, [_response(429, {}, {"Retry-After": "9999"})])
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_RATE_LIMIT


def test_a_junk_retry_after_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    store = CredentialStore("t2")
    store.save(_creds())
    client = Client(store, timeout=120)  # the fallback wait is 30s
    slept: list[float] = []
    monkeypatch.setattr(api.time, "sleep", slept.append)
    _queue(
        monkeypatch,
        [_response(429, {}, {"Retry-After": "Wed, 01 Jan 2027 00:00:00 GMT"}), _response(200, {})],
    )
    client.get("/v1/deals")
    assert slept == [30]


# --------------------------------------------------------------- error mapping


def test_a_missing_scope_is_named_from_the_challenge(client, monkeypatch):
    _queue(
        monkeypatch,
        [
            _response(
                403,
                {"error": {"code": "insufficient_scope", "message": "no"}},
                {"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="reps:read"'},
            )
        ],
    )
    with pytest.raises(InsufficientScope) as caught:
        client.get("/v1/reps")
    assert "reps:read" in str(caught.value)
    assert "reps:read" in (caught.value.hint or "")


def test_a_grant_that_cannot_be_refreshed_sends_the_user_back_to_login(client, monkeypatch):
    """What a consent-text bump actually looks like from here.

    The server cannot distinguish a stale consent version from an expired token
    by the time a request reaches a handler -- `load_access_token` returns None
    for both -- so this arrives as a 401, the refresh is attempted, and the
    refresh fails too because the family carries the same consent version.
    Exit 3 with "sign in again" is the correct end state.
    """
    _queue(monkeypatch, [_response(401, {})])

    def dead(**_kwargs):
        raise NotAuthenticated("Your session has ended.")

    monkeypatch.setattr(api.oauth, "refresh", dead)
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == 3


def test_an_error_body_that_is_not_an_object_does_not_traceback(client, monkeypatch):
    """`.json().get("error")` raised AttributeError on a bare string.

    That escaped `main()` as a traceback and exit 1, breaking the exit-code
    contract at the moment a script most needs it.
    """
    _queue(monkeypatch, [_response(400, {"error": "just a string"})])
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_ERROR


def test_a_non_json_body_does_not_traceback(client, monkeypatch):
    _queue(
        monkeypatch,
        [
            httpx.Response(
                500,
                content=b"<html>gateway</html>",
                request=httpx.Request("GET", "https://example.invalid/v1/deals"),
            )
        ],
    )
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_an_unreachable_host_reports_unavailable(client, monkeypatch):
    def boom(_method, _url, **_kwargs):
        raise httpx.ConnectError("nope")

    monkeypatch.setattr(api.httpx, "stream", boom)
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_a_declared_oversized_body_is_refused_before_it_is_read(client, monkeypatch):
    """`Content-Length` is checked before the first chunk.

    Written so it fails if only the streaming ceiling is doing the work: the
    declared length is over the cap and the actual body is a single byte, so the
    only way to refuse it is to have read the header. Otherwise this is just a
    slower copy of the streamed test below.
    """
    read = False

    class _Declaring:
        status_code = 200
        headers = httpx.Headers({"Content-Length": str(api.MAX_RESPONSE_BYTES + 1)})

        def iter_bytes(self, chunk_size=None):
            nonlocal read
            read = True
            yield b"x"

    monkeypatch.setattr(api.httpx, "stream", lambda *_a, **_k: _Streamed(_Declaring()))
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE
    assert read is False, "the body was read despite a Content-Length over the cap"


def test_the_bearer_header_is_the_only_thing_carrying_identity(client, monkeypatch):
    sent: dict = {}

    def fake_stream(_method, _url, **kwargs):
        sent.update(kwargs)
        return _Streamed(_response(200, {"data": []}))

    monkeypatch.setattr(api.httpx, "stream", fake_stream)
    client.get("/v1/deals", [("type", "ACTIVE")])
    assert sent["headers"]["Authorization"] == "Bearer psmcp_at_a"
    assert not any(k in dict(sent["params"]) for k in ("user_id", "customer_id", "ps_user_id"))


def test_logout_clears_locally_even_when_revocation_fails(tmp_path, monkeypatch):
    """A network failure must not leave credentials on disk.

    Revocation is best-effort by design; forgetting locally is not.
    """
    from proshort_cli import cli

    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    # Patched on the *class*, not on one instance. `cmd_logout` builds its own
    # `CredentialStore`, and so does the assertion below, so patching an instance
    # left both of them talking to the developer's real keychain -- which meant
    # this test read, and then deleted, whatever credentials the person running
    # it actually had. The assertion passed for the wrong reason, and the cost
    # was being signed out by the test suite.
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    store = CredentialStore("default")
    store.save(_creds())

    def boom(**_kwargs):
        raise httpx.ConnectError("nope")

    monkeypatch.setattr(cli.oauth, "revoke", boom)
    args = cli.build_parser().parse_args(["logout"])
    assert cli.cmd_logout(args) == 0
    assert CredentialStore("default").load() is None


# ------------------------------------------- what a 200 is allowed to contain


def test_a_success_body_that_is_not_an_object_does_not_traceback(client, monkeypatch):
    """The failure path was already careful about this; the success path was not.

    `.get("data")` on a list is an AttributeError, and `json.loads` on a captive
    portal's HTML is a ValueError. Either escapes `main()` as a traceback and
    exit 1 -- the exit-code contract breaking at the moment a script most needs
    it, which is the whole argument for guarding the other path.
    """
    _queue(monkeypatch, [_response(200, [{"id": 1}])])
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_a_success_body_that_is_not_json_does_not_traceback(client, monkeypatch):
    _queue(
        monkeypatch,
        [
            httpx.Response(
                200,
                content=b"<html>signed in to the wifi?</html>",
                request=httpx.Request("GET", "https://example.invalid/v1/deals"),
            )
        ],
    )
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_a_page_that_is_not_a_list_is_not_counted_as_results(client, monkeypatch):
    """`extend` on a dict walks its keys, so a shape change downstream would read
    as a successful scan of the wrong thing."""
    _queue(monkeypatch, [_response(200, {"data": {"unexpected": "shape"}})])
    with pytest.raises(CliError) as caught:
        client.get_all("/v1/deals", [])
    assert caught.value.code == EXIT_UNAVAILABLE


def test_a_junk_page_size_does_not_crash_the_walk(client, monkeypatch):
    """Every field in `page` comes off the wire, so `int()` on any of them can
    raise -- mid-scan, where it escapes as a traceback."""
    _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": 1}], "page": {"page_size": "twenty"}}),
        ],
    )
    body = client.get_all("/v1/deals", [])
    assert [row["id"] for row in body["data"]] == [1]


def test_the_walk_stops_rather_than_following_pages_forever(client, monkeypatch):
    """A short page is the normal terminator, which is a promise about the
    *server*. A bug or a proxy that always returns a full page turns `--all` into
    an unbounded loop against a host `--url` chose."""
    monkeypatch.setattr(api, "MAX_PAGES", 3)

    def endless(_method, _url, **_kwargs):
        return _Streamed(_response(200, {"data": [{"id": 1}], "page": {"page_size": 1}}))

    monkeypatch.setattr(api.httpx, "stream", endless)
    with pytest.raises(CliError) as caught:
        client.get_all("/v1/deals", [])
    assert caught.value.code == EXIT_UNAVAILABLE
    assert "3 pages" in str(caught.value)


def test_an_oversized_body_is_abandoned_rather_than_downloaded(client, monkeypatch):
    """`httpx.get` buffers the whole body first, so checking its length afterwards
    refused to *parse* what had already been pulled into memory. `--url` names the
    host, so the thing this bounds is a client that would otherwise accept
    gigabytes from wherever it was pointed.
    """
    monkeypatch.setattr(api, "MAX_RESPONSE_BYTES", 64)
    pulled = 0

    class _Endless:
        """Duck-typed rather than an `httpx.Response`: constructing one of those
        eagerly reads the whole body, which is the behaviour under test."""

        status_code = 200
        headers = httpx.Headers({})

        def iter_bytes(self, chunk_size=None):
            nonlocal pulled
            while True:
                pulled += 32
                assert pulled < 4096, "the stream was never abandoned"
                yield b"x" * 32

    monkeypatch.setattr(api.httpx, "stream", lambda *_a, **_k: _Streamed(_Endless()))

    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE
    assert pulled <= 128, "more was read than the ceiling allows"


def test_the_timeout_is_a_budget_for_the_command_not_for_each_request(tmp_path, monkeypatch):
    """`--timeout` says "seconds to spend, including waits". Per-request, `--all`
    over twelve pages could spend twelve times the budget and still be inside
    every individual limit.
    """
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    store = CredentialStore("t3")
    store.save(_creds())
    client = Client(store, timeout=1)
    client._deadline = time.monotonic() - 1  # the budget is already spent

    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


# -------------------------------------------------------------------- re-login


def test_signing_in_again_revokes_the_grant_it_replaces(tmp_path, monkeypatch):
    """`logout` exists so a copied credential file dies in thirty days. Signing in
    again left the previous refresh token live, which is exactly what somebody who
    copied the file is counting on.
    """
    from proshort_cli import cli

    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    CredentialStore("default").save(_creds(refresh_token="rt_previous"))

    revoked: list[str] = []
    monkeypatch.setattr(cli.oauth, "revoke", lambda **kw: revoked.append(kw["token"]))
    monkeypatch.setattr(
        cli.oauth,
        "login",
        lambda **_: {"access_token": "at_new", "refresh_token": "rt_new", "expires_in": 600},
    )
    monkeypatch.setattr(cli, "Client", _unavailable_client)

    args = cli.build_parser().parse_args(["login", "--url", "https://example.invalid"])
    assert cli.cmd_login(args) == 0
    assert revoked == ["rt_previous"], "the previous grant was left live"
    assert CredentialStore("default").load().refresh_token == "rt_new"


def _unavailable_client(*_a, **_k):
    """Stand in for the courtesy `whoami` after sign-in, which needs no network."""
    raise CliError("no network in this test", EXIT_ERROR)


def test_a_stored_cleartext_address_asks_for_a_sign_in_not_a_retry(tmp_path, monkeypatch):
    """A bad `--url` is exit 2 because the user typed it. A bad address inside a
    stored credential is not something a Skill can fix by rebuilding its command
    line, and exit 2 tells it to retry forever.
    """
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    store = CredentialStore("t4")
    store.save(_creds(base_url="http://mcp.example.com"))

    with pytest.raises(CliError) as caught:
        Client(store, timeout=5)
    assert caught.value.code == EXIT_AUTH


def test_a_null_page_object_does_not_crash_a_completed_walk(client, monkeypatch):
    """`setdefault` returns the existing value, so an explicit `"page": null` came
    back as `None` and `None["returned"]` was a TypeError -- raised *after* a
    complete, successful walk, on the one command whose whole argument is that it
    never returns quietly wrong results.
    """
    _queue(monkeypatch, [_response(200, {"data": [{"id": 1}], "page": None})])
    body = client.get_all("/v1/deals", [])
    assert body["page"]["returned"] == 1
    assert [row["id"] for row in body["data"]] == [1]


def test_the_walk_stops_on_a_short_page_with_no_page_size(client, monkeypatch):
    """`returned` answers a different question and made the terminator dead.

    It is how many rows are in *this* response, so on an honest server it equals
    `len(rows)` and `len(rows) < returned` is never true. A last page of ten with
    `{"returned": 10}` and no `page_size` asked for page eleven -- and a server
    that refuses a page past the end, rather than returning an empty one, then
    makes the whole command raise and discard every row it already had.
    """
    pages = _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": n} for n in range(10)], "page": {"returned": 10}}),
            _response(400, {"error": {"code": "invalid_argument", "message": "no such page"}}),
        ],
    )
    body = client.get_all("/v1/deals", [])
    assert len(body["data"]) == 10
    assert len(pages) == 1, "asked for a page past the end of the results"


def test_a_scope_the_client_does_not_know_is_not_put_in_the_hint(client, monkeypatch):
    """The hint is a line the reference Skill is told to act on.

    `sanitize_line` strips escape sequences and newlines -- not `;`, backticks or
    `$()`. Against a compromised host or an intercepting proxy, an agent pasting
    the printed line into a shell is the injection, and the CLI handed it over.
    """
    _queue(
        monkeypatch,
        [
            _response(
                403,
                {"error": {"code": "insufficient_scope", "message": "nope"}},
                {"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="deals:read; echo pwned"'},
            )
        ],
    )
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert "echo pwned" not in str(caught.value)
    assert "echo pwned" not in (caught.value.hint or "")
    assert caught.value.hint == "Run: proshort login"


def test_a_scope_the_client_does_know_is_still_named(client, monkeypatch):
    """The allowlist must not cost the useful case."""
    _queue(
        monkeypatch,
        [
            _response(
                403,
                {"error": {"code": "insufficient_scope", "message": "nope"}},
                {"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="deals:read"'},
            )
        ],
    )
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.hint == "Run: proshort login --add-scope deals:read"


def test_one_command_will_not_hold_more_than_its_total_ceiling(client, monkeypatch):
    """`MAX_RESPONSE_BYTES` bounds one response; `--all` multiplies it by up to
    `MAX_PAGES`, and `get_all` keeps every row. Against a wrong or hostile host
    the user has already signed into, the walk is the denial of service."""
    monkeypatch.setattr(api, "MAX_TOTAL_BYTES", 4096)
    row = {"id": "x" * 200}
    pages = 0

    def endless(_method, _url, **_kwargs):
        nonlocal pages
        pages += 1
        return _Streamed(_response(200, {"data": [row] * 20, "page": {"page_size": 20}}))

    monkeypatch.setattr(api.httpx, "stream", endless)
    with pytest.raises(CliError) as caught:
        client.get_all("/v1/deals", [])

    assert caught.value.code == EXIT_UNAVAILABLE
    # Named, because `MAX_PAGES` also ends this walk with the same exit code --
    # 400 pages later, and long after the memory this bounds was allocated.
    assert "willing to hold in memory" in str(caught.value)
    assert pages < api.MAX_PAGES, f"the page ceiling stopped it first, after {pages}"


@pytest.mark.parametrize(
    ("status", "code"),
    [(422, "invalid_argument"), (422, ""), (400, "invalid_argument")],
)
def test_a_value_the_server_refuses_is_a_usage_error(client, monkeypatch, status, code):
    """Exit 2, the same code argparse gives a malformed command line.

    The server refusing a value is the caller having built the request wrong,
    which is what exit 2 means and what a Skill is told to do about it. This fell
    through to exit 1 -- "something unexpected; do not retry blindly" -- so an
    agent that sent `--duration LAST_WEEK` was told to give up rather than to
    correct it, and the message naming the eight valid values went to waste.

    Found by running the CLI against a live server. Every unit test here asserted
    what the code did rather than what the contract says.
    """
    _queue(monkeypatch, [_response(status, {"error": {"code": code, "message": "bad value"}})])
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_USAGE


def test_an_unclassified_failure_is_still_exit_one(client, monkeypatch):
    """The usage mapping must not swallow everything else: a 400 the server did
    not describe is not the caller knowing which argument to change."""
    _queue(monkeypatch, [_response(409, {"error": {"code": "conflict", "message": "nope"}})])
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_ERROR


def test_a_wait_that_exactly_consumes_the_budget_is_still_a_rate_limit(client, monkeypatch):
    """The guard used `>`, so a wait equal to the remaining budget was slept
    through -- after which `_remaining()` raised "gave up after Ns" at exit 6, and
    a Skill said Proshort was down about a server that had told it exactly how
    long to back off. The tests covered 9999s and 2s; not the last second."""
    slept: list[float] = []
    monkeypatch.setattr(api.time, "sleep", slept.append)
    # The clock is frozen so `now + wait` lands *exactly* on the deadline. Without
    # that, microseconds elapse between setting it and comparing it, and the test
    # passes under `>` as well -- which is how the boundary went untested.
    monkeypatch.setattr(api.time, "monotonic", lambda: 1000.0)
    _queue(monkeypatch, [_response(429, {}, {"Retry-After": "5"})])
    client._deadline = 1005.0

    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_RATE_LIMIT
    assert slept == [], "slept through the whole budget before giving up"


def test_a_budget_spent_while_waiting_is_still_a_rate_limit(client, monkeypatch):
    """Re-checked after the sleep, because the budget can be gone by then for
    reasons that have nothing to do with this wait."""
    def burn(_seconds):
        client._deadline = time.monotonic() - 1

    monkeypatch.setattr(api.time, "sleep", burn)
    _queue(monkeypatch, [_response(429, {}, {"Retry-After": "1"}), _response(200, {})])
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_RATE_LIMIT


def test_a_unicode_content_length_does_not_traceback(client, monkeypatch):
    """`"²".isdigit()` is True and `int("²")` raises -- a traceback and exit 1,
    off the contract, from exactly the hostile or broken header this ceiling
    exists to survive."""
    # Built from bytes, the way httpx builds them off the wire: a str with a
    # non-ASCII character is refused at construction, but `b"\xb2"` decodes to
    # `"²"` through httpx's latin-1 fallback, so a server really can send this.
    class _Odd:
        status_code = 200
        headers = httpx.Headers([(b"content-length", b"\xb2")])

        def iter_bytes(self, chunk_size=None):
            yield b'{"data": []}'

    monkeypatch.setattr(api.httpx, "stream", lambda *_a, **_k: _Streamed(_Odd()))
    assert client.get("/v1/deals") == {"data": []}


def test_the_walk_stops_when_the_reported_total_is_reached(client, monkeypatch):
    """`len(rows) < page_size` trusts the server's own claim about the size it
    sent, and a page reported larger than it was ends the walk early with exit 0
    and a short list. `total` is independent of that claim."""
    pages = _queue(
        monkeypatch,
        [
            _response(200, {"data": [{"id": 1}, {"id": 2}], "page": {"page_size": 2, "total": 4}}),
            _response(200, {"data": [{"id": 3}, {"id": 4}], "page": {"page_size": 2, "total": 4}}),
            _response(500, {}),
        ],
    )
    body = client.get_all("/v1/deals", [])
    assert [row["id"] for row in body["data"]] == [1, 2, 3, 4]
    assert len(pages) == 2, "kept paging past the reported total"


def test_whoami_keeps_verbose(monkeypatch):
    """It built its `Client` by hand and dropped `--verbose`, so rate-limit waits
    were silent on the one command a Skill is told to run first."""
    from proshort_cli import cli

    seen = {}
    monkeypatch.setattr(cli, "Client", lambda store, **kwargs: seen.update(kwargs) or _Boom())
    args = cli.build_parser().parse_args(["whoami", "--verbose"])
    with pytest.raises(CliError):
        cli.cmd_whoami(args)
    assert seen.get("verbose") is True


class _Boom:
    def get(self, *_a, **_k):
        raise CliError("stop here", EXIT_ERROR)
