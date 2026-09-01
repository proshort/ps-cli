"""The parts of sign-in that are load-bearing."""
import base64
import hashlib

import pytest

from proshort_cli import oauth
from proshort_cli.errors import EXIT_AUTH, CliError


def test_pkce_challenge_is_a_real_s256_of_the_verifier():
    verifier, challenge = oauth._pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    assert challenge == expected
    assert "=" not in challenge  # unpadded, per RFC 7636


def test_each_flow_gets_a_fresh_verifier():
    assert oauth._pkce()[0] != oauth._pkce()[0]


def test_a_mismatched_state_discards_the_code_unredeemed(monkeypatch):
    """Without this, a local process can sign you in as somebody else.

    Any process that can see our listening port can push its own authorization
    code at us. PKCE does not cover it -- that binds the code to the client, not
    the session to the user -- so the CLI would faithfully redeem an attacker's
    code and the victim would read a stranger's pipeline believing it is theirs.
    """
    redeemed: list[str] = []
    monkeypatch.setattr(oauth, "exchange_code", lambda **kw: redeemed.append(kw["code"]))

    class _Thread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            oauth._Catcher.result = {"code": "attacker-code", "state": "not-the-one-we-sent"}

        def join(self, *a):
            pass

    monkeypatch.setattr(oauth.threading, "Thread", _Thread)
    monkeypatch.setattr(oauth.webbrowser, "open", lambda *_a: True)

    with pytest.raises(CliError) as caught:
        oauth.login(base_url="https://example.invalid", open_browser=False)

    assert caught.value.code == EXIT_AUTH
    assert redeemed == [], "the code must never be exchanged when state does not match"


def test_the_callback_handler_does_not_log_the_request_line():
    """The default handler logs the path -- which contains the authorization code."""
    assert oauth._Catcher.log_message is not __import__(
        "http.server", fromlist=["BaseHTTPRequestHandler"]
    ).BaseHTTPRequestHandler.log_message
