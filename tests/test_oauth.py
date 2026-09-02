"""The parts of sign-in that are load-bearing."""
import base64
import hashlib
import http.server
import io
import time

import httpx
import pytest

from proshort_cli import oauth
from proshort_cli.errors import EXIT_AUTH, EXIT_UNAVAILABLE, EXIT_USAGE, CliError


def _token_response(status: int, payload) -> httpx.Response:
    return httpx.Response(
        status, json=payload, request=httpx.Request("POST", "https://example.invalid/token")
    )


def test_pkce_challenge_is_a_real_s256_of_the_verifier():
    verifier, challenge = oauth._pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    assert challenge == expected
    assert "=" not in challenge  # unpadded, per RFC 7636


def test_each_flow_gets_a_fresh_verifier():
    assert oauth._pkce()[0] != oauth._pkce()[0]


def _drive(path: str, expected_state: str, host: str = "127.0.0.1:1234") -> int:
    """Run one request through the real handler without a socket."""
    oauth._Catcher.expected_state = expected_state
    oauth._Catcher.result = {}

    class _Fake(oauth._Catcher):
        def __init__(self):
            self.path = path
            self.headers = {"Host": host}
            self.status = 0
            self.wfile = io.BytesIO()

        def send_response(self, code, *a):
            self.status = code

        def send_header(self, *a):
            pass

        def end_headers(self):
            pass

    handler = _Fake()
    handler.do_GET()
    return handler.status


def test_a_mismatched_state_is_refused_and_does_not_end_the_flow():
    """Without this, a local process can sign you in as somebody else.

    Any process that can see our listening port can push its own authorization
    code at us. PKCE does not cover it -- that binds the code to the client, not
    the session to the user -- so the CLI would faithfully redeem an attacker's
    code and the victim would read a stranger's pipeline believing it is theirs.

    The refusal must also leave the listener running: an attacker who wins the
    race should not get to decide that the sign-in is over.
    """
    status = _drive("/callback?code=attacker&state=wrong", expected_state="ours")
    assert status == 400
    assert oauth._Catcher.result == {}, "a foreign callback must not be stored"


def test_an_error_response_is_state_checked_too():
    """`?error=access_denied` used to abort the flow with no state check at all."""
    status = _drive("/callback?error=access_denied&state=wrong", expected_state="ours")
    assert status == 400
    assert oauth._Catcher.result == {}


def test_a_matching_callback_is_stored():
    status = _drive("/callback?code=ours&state=ours", expected_state="ours")
    assert status == 200
    assert oauth._Catcher.result["code"] == "ours"


def test_a_stray_request_does_not_end_the_sign_in():
    """A favicon probe, a health check, or an <img src> on a page the user has open.

    This used to consume the single request the listener served, leaving the user
    with "timed out waiting for the browser" -- the wrong diagnosis, and a local
    denial of service anyone could trigger from a browser tab.
    """
    assert _drive("/favicon.ico", expected_state="ours") == 404
    assert oauth._Catcher.result == {}


def test_a_callback_under_a_foreign_host_is_refused():
    status = _drive("/callback?code=x&state=ours", expected_state="ours", host="evil.example")
    assert status == 400
    assert oauth._Catcher.result == {}


def test_the_callback_handler_does_not_log_the_request_line():
    """The default handler logs the path -- which contains the authorization code."""
    assert oauth._Catcher.log_message is not __import__(
        "http.server", fromlist=["BaseHTTPRequestHandler"]
    ).BaseHTTPRequestHandler.log_message


def test_revocation_sends_the_field_the_server_requires(monkeypatch):
    """The server's request model requires `client_secret` even from a public client.

    Omitting it is rejected as a malformed request before revocation is reached,
    so `logout` silently did nothing and the refresh token stayed live for thirty
    days. Sent empty: client authentication for `token_endpoint_auth_method=none`
    ignores the value, but the field has to be present.
    """
    sent: dict = {}

    class _Ok:
        def raise_for_status(self):
            return None

    def fake_post(url, data=None, timeout=None):
        sent["url"] = url
        sent["data"] = data
        return _Ok()

    monkeypatch.setattr(oauth.httpx, "post", fake_post)
    oauth.revoke(base_url="https://example.invalid/", client_id="proshort-cli", token="psmcp_rt_x")

    assert sent["url"] == "https://example.invalid/revoke"
    assert sent["data"]["client_secret"] == ""
    assert sent["data"]["token"] == "psmcp_rt_x"
    assert sent["data"]["token_type_hint"] == "refresh_token"


# --------------------------------------------------- the token plane's exit codes
#
# `3` tells a Skill to say "run proshort login"; `6` tells it "Proshort is down,
# not your fault". Mapping every non-200 to `3` and letting a transport error
# escape as a traceback got both wrong, and exit 1 is not even in the Skill's
# table.


def _post_returning(monkeypatch, response):
    def fake_post(url, **kwargs):
        return response

    monkeypatch.setattr(oauth.httpx, "post", fake_post)


def _post_raising(monkeypatch, exc):
    def fake_post(url, **kwargs):
        raise exc

    monkeypatch.setattr(oauth.httpx, "post", fake_post)


@pytest.mark.parametrize("status", [500, 502, 503, 429])
def test_a_server_failure_on_refresh_is_not_the_end_of_the_session(monkeypatch, status):
    """A 503 during the silent ten-minute refresh used to say "your session has
    ended" and throw away a refresh token that was still perfectly good."""
    _post_returning(monkeypatch, _token_response(status, {}))
    with pytest.raises(CliError) as caught:
        oauth.refresh(base_url="https://example.invalid", client_id="c", refresh_token="r")
    assert caught.value.code == EXIT_UNAVAILABLE


@pytest.mark.parametrize(
    "exc",
    [httpx.ConnectError("down"), httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow")],
)
def test_a_transport_failure_on_refresh_is_not_a_traceback(monkeypatch, exc):
    _post_raising(monkeypatch, exc)
    with pytest.raises(CliError) as caught:
        oauth.refresh(base_url="https://example.invalid", client_id="c", refresh_token="r")
    assert caught.value.code == EXIT_UNAVAILABLE


@pytest.mark.parametrize("status", [400, 401, 403])
def test_a_dead_grant_still_sends_the_user_back_to_login(monkeypatch, status):
    """The other side of the split: these really do mean the grant is gone."""
    _post_returning(monkeypatch, _token_response(status, {"error": "invalid_grant"}))
    with pytest.raises(CliError) as caught:
        oauth.refresh(base_url="https://example.invalid", client_id="c", refresh_token="r")
    assert caught.value.code == EXIT_AUTH


def test_a_server_failure_on_sign_in_is_not_a_refused_sign_in(monkeypatch):
    """`exchange_code` had the same gap: a 503 after the browser came back looks
    like a failed sign-in, while the grant may already exist server-side."""
    _post_returning(monkeypatch, _token_response(503, {}))
    with pytest.raises(CliError) as caught:
        oauth.exchange_code(
            base_url="https://example.invalid",
            client_id="c",
            code="x",
            verifier="v",
            redirect_uri="http://127.0.0.1:1/callback",
        )
    assert caught.value.code == EXIT_UNAVAILABLE


# -------------------------------------------------------------- transport safety


@pytest.mark.parametrize(
    "url",
    ["http://proshort.example.com", "http://10.0.0.5:8080", "ftp://example.invalid", "example.invalid"],
)
def test_a_grant_is_never_sent_in_the_clear(url):
    """RFC 8252 excuses loopback HTTP for the *redirect*, not for the token
    endpoint, which carries the code_verifier and the thirty-day refresh token."""
    with pytest.raises(CliError) as caught:
        oauth.require_secure(url)
    assert caught.value.code == EXIT_USAGE


@pytest.mark.parametrize(
    "url",
    ["https://mcp.proshort.ai", "http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"],
)
def test_https_and_a_local_server_are_both_fine(url):
    oauth.require_secure(url)


def test_the_browser_wait_is_bounded_by_the_timeout(monkeypatch):
    """`--timeout` says "seconds to spend, including waits". `login` accepted the
    flag on every subparser and then never passed it on, so the wait stayed at
    the hardcoded 300s and the help text was simply untrue.

    Asserted on the bound `login` hands down, not on how long the call took. Wall
    clock measures the runner as much as the code -- an earlier version of this
    test failed on macOS CI at 36 seconds, and the 36 seconds were a reverse DNS
    lookup inside `HTTPServer.server_bind`, not a deadline being ignored. A test
    whose failure points at the wrong function is worse than no test.
    """
    handed: list[float] = []

    def fake_serve(_server, timeout):
        handed.append(timeout)
        return {}

    monkeypatch.setattr(oauth, "_serve_until_callback", fake_serve)
    with pytest.raises(CliError) as caught:
        oauth.login(base_url="https://example.invalid", timeout=7, open_browser=False)
    assert "Timed out" in str(caught.value)
    assert handed and handed[0] <= 7, f"login waited on {handed} for a 7s budget"


def test_the_wait_loop_returns_when_its_deadline_passes():
    """The other half: the bound `login` hands down is one the loop honours.

    Driven with a stub server rather than a socket, so this measures the loop and
    nothing about the machine it runs on.
    """
    calls: list[int] = []

    class _NeverCalledBack:
        timeout = None

        def handle_request(self):
            calls.append(1)
            time.sleep(0.01)

    oauth._Catcher.result = {}
    started = time.monotonic()
    assert oauth._serve_until_callback(_NeverCalledBack(), 0.1) == {}
    assert time.monotonic() - started < 5
    assert calls, "the loop never served anything"


def test_signing_in_does_not_wait_on_reverse_dns(monkeypatch):
    """`HTTPServer.server_bind` calls `socket.getfqdn` to fill in a field nothing
    reads. Where the resolver is slow or absent -- a CI runner, hotel wifi, a
    locked-down corporate network -- that blocks for tens of seconds *before the
    browser opens*, so `proshort login` appears to hang at the one moment the
    user is watching it. A GitHub macOS runner spent 36 seconds there.

    Driven through `login` rather than by constructing `_LoopbackServer`
    directly. Testing the subclass in isolation passes just as happily when
    `login` has been changed back to the stock `HTTPServer` -- and the wiring is
    the half that broke.
    """

    def explode(_host=None):
        raise AssertionError("bind performed a reverse DNS lookup")

    # Patched where `HTTPServer.server_bind` reaches for it, which is the call
    # this subclass exists to not make.
    monkeypatch.setattr(http.server.socket, "getfqdn", explode)
    monkeypatch.setattr(oauth, "_serve_until_callback", lambda _server, _timeout: {})
    with pytest.raises(CliError) as caught:
        oauth.login(base_url="https://example.invalid", timeout=1, open_browser=False)
    assert "Timed out" in str(caught.value)
