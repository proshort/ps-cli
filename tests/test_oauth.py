"""The parts of sign-in that are load-bearing."""
import base64
import hashlib
import io

from proshort_cli import oauth


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
        def __init__(self):  # noqa: D107 - bypasses BaseHTTPRequestHandler's socket setup
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
