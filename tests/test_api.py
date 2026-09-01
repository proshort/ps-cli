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
    EXIT_ERROR,
    EXIT_RATE_LIMIT,
    EXIT_UNAVAILABLE,
    CliError,
    InsufficientScope,
    NotAuthenticated,
)
from proshort_cli.store import CredentialStore, Credentials


def _creds(**over) -> Credentials:
    base = dict(
        access_token="psmcp_at_a",
        refresh_token="psmcp_rt_a",
        expires_at=time.time() + 600,
        scopes=["deals:read"],
        base_url="https://example.invalid",
        client_id="proshort-cli",
    )
    base.update(over)
    return Credentials(**base)


@pytest.fixture
def client(tmp_path, monkeypatch) -> Client:
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    store = CredentialStore("test")
    monkeypatch.setattr(store, "_keyring", lambda: None)
    store.save(_creds())
    return Client(store, timeout=5)


def _response(status: int, payload=None, headers=None) -> httpx.Response:
    return httpx.Response(
        status,
        json=payload if payload is not None else {},
        headers=headers or {},
        request=httpx.Request("GET", "https://example.invalid/v1/deals"),
    )


def _queue(monkeypatch, responses: list[httpx.Response]) -> list[dict]:
    """Serve `responses` in order, recording the params each call was made with."""
    seen: list[dict] = []

    def fake_get(url, **kwargs):
        seen.append(dict(kwargs.get("params") or []))
        return responses.pop(0)

    monkeypatch.setattr(api.httpx, "get", fake_get)
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

    A 500 on page two used to be swallowed as "the depth cap, reached": the
    command returned page one and exited 0, so a Skill would summarise a partial
    pipeline as the whole thing. Silent truncation is the one failure mode this
    command must not have.
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
    assert caught.value.code == EXIT_ERROR


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

    def fake_refresh(*, base_url, client_id, refresh_token):
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
    store = CredentialStore("t2")
    monkeypatch.setattr(store, "_keyring", lambda: None)
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
    bad = httpx.Response(
        500, content=b"<html>gateway</html>",
        request=httpx.Request("GET", "https://example.invalid/v1/deals"),
    )
    monkeypatch.setattr(api.httpx, "get", lambda url, **kw: bad)
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_an_unreachable_host_reports_unavailable(client, monkeypatch):
    def boom(url, **kwargs):
        raise httpx.ConnectError("nope")

    monkeypatch.setattr(api.httpx, "get", boom)
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_an_oversized_body_is_refused(client, monkeypatch):
    huge = httpx.Response(
        200, content=b"x" * (api.MAX_RESPONSE_BYTES + 1),
        request=httpx.Request("GET", "https://example.invalid/v1/deals"),
    )
    monkeypatch.setattr(api.httpx, "get", lambda url, **kw: huge)
    with pytest.raises(CliError) as caught:
        client.get("/v1/deals")
    assert caught.value.code == EXIT_UNAVAILABLE


def test_the_bearer_header_is_the_only_thing_carrying_identity(client, monkeypatch):
    sent: dict = {}

    def fake_get(url, **kwargs):
        sent.update(kwargs)
        return _response(200, {"data": []})

    monkeypatch.setattr(api.httpx, "get", fake_get)
    client.get("/v1/deals", [("type", "ACTIVE")])
    assert sent["headers"]["Authorization"] == "Bearer psmcp_at_a"
    assert not any(k in dict(sent["params"]) for k in ("user_id", "customer_id", "ps_user_id"))


def test_logout_clears_locally_even_when_revocation_fails(tmp_path, monkeypatch):
    """A network failure must not leave credentials on disk.

    Revocation is best-effort by design; forgetting locally is not.
    """
    from proshort_cli import cli

    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    store = CredentialStore("default")
    monkeypatch.setattr(store, "_keyring", lambda: None)
    store.save(_creds())

    def boom(**_kwargs):
        raise httpx.ConnectError("nope")

    monkeypatch.setattr(cli.oauth, "revoke", boom)
    args = cli.build_parser().parse_args(["logout"])
    assert cli.cmd_logout(args) == 0
    assert CredentialStore("default").load() is None
