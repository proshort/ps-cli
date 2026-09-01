"""Signing in from a terminal: authorization code + PKCE over a loopback redirect.

The whole browser half of this is the Proshort connector's existing flow,
unchanged -- the same `/authorize`, the same parked `request_id`, the same consent
page, the same `/token`. Two things are new and both live entirely in this
process: the listener we bind on 127.0.0.1, and the callback it catches.

Three details are load-bearing:

- **PKCE (S256).** We invent a verifier, send only its hash to start the flow, and
  present the verifier when redeeming. A code stolen out of a URL is worthless
  without it.
- **`state`.** Generated here and compared on the way back. Without it, any local
  process that can see our port can push *its* authorization code at us, and this
  CLI would faithfully redeem it -- leaving the user signed in as somebody else
  and reading a stranger's pipeline believing it is theirs. PKCE does not cover
  this; it binds the code to the client, not the session to the user.
- **A self-contained callback page.** No external references of any kind, and
  `Referrer-Policy: no-referrer`, so the authorization code in our URL cannot be
  carried anywhere by a subresource fetch.
"""

import base64
import hashlib
import http.server
import secrets
import socket
import threading
import urllib.parse
import webbrowser

import httpx

from proshort_cli.errors import CliError, EXIT_AUTH
from proshort_cli.render import note

DEFAULT_CLIENT_ID = "proshort-cli"
CALLBACK_PATH = "/callback"

_PAGE = b"""<!doctype html><meta charset=utf-8><title>Proshort</title>
<style>body{font:15px -apple-system,system-ui,sans-serif;margin:18vh auto;max-width:32em;
text-align:center;color:#10202e}h1{font-size:1.3rem;margin:0 0 .5em}</style>
<h1>%s</h1><p>%s</p>"""


def _pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


class _Catcher(http.server.BaseHTTPRequestHandler):
    """Catches exactly one callback and stops."""

    result: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        type(self).result = query
        ok = "code" in query
        body = _PAGE % (
            b"You&rsquo;re signed in." if ok else b"Sign-in failed.",
            b"You can close this tab and go back to your terminal."
            if ok
            else b"Go back to your terminal for the details.",
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # The authorization code is in this page's URL. Nothing here loads a
        # subresource, and this makes sure nothing can carry the code outward if
        # that ever changes.
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        """Silence. The default logs the request line -- which contains the code."""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def login(
    *,
    base_url: str,
    client_id: str = DEFAULT_CLIENT_ID,
    scopes: list[str] | None = None,
    timeout: int = 300,
    open_browser: bool = True,
) -> dict:
    """Run the full flow and return the token response."""
    base_url = base_url.rstrip("/")
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)
    port = _free_port()
    redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"

    _Catcher.result = {}
    server = http.server.HTTPServer(("127.0.0.1", port), _Catcher)
    server.timeout = timeout
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if scopes:
        params["scope"] = " ".join(scopes)
    authorize_url = f"{base_url}/authorize?{urllib.parse.urlencode(params)}"

    note(f"→ opened your browser · listening on 127.0.0.1:{port}")
    if open_browser:
        webbrowser.open(authorize_url)
    else:
        note(f"  open this to continue:\n  {authorize_url}")

    thread.join(timeout)
    server.server_close()
    result = _Catcher.result
    _Catcher.result = {}

    if not result:
        raise CliError("Timed out waiting for the browser to come back.", EXIT_AUTH)
    if "error" in result:
        raise CliError(f"Sign-in was refused: {result.get('error')}", EXIT_AUTH)

    # Compared before the code is used for anything at all. A mismatch means this
    # callback did not belong to the flow we started, and the only safe response
    # is to throw the code away unredeemed.
    if not secrets.compare_digest(result.get("state", ""), state):
        raise CliError(
            "The sign-in response did not match the request this session started, "
            "so it was discarded. Try again.",
            EXIT_AUTH,
        )
    if "code" not in result:
        raise CliError("The browser came back without an authorization code.", EXIT_AUTH)

    return exchange_code(
        base_url=base_url,
        client_id=client_id,
        code=result["code"],
        verifier=verifier,
        redirect_uri=redirect_uri,
    )


def exchange_code(
    *, base_url: str, client_id: str, code: str, verifier: str, redirect_uri: str
) -> dict:
    response = httpx.post(
        f"{base_url}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        },
        timeout=30,
    )
    if response.status_code != 200:
        raise CliError(f"Could not complete sign-in ({response.status_code}).", EXIT_AUTH)
    return response.json()


def refresh(*, base_url: str, client_id: str, refresh_token: str) -> dict:
    response = httpx.post(
        f"{base_url.rstrip('/')}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
        timeout=30,
    )
    if response.status_code != 200:
        raise CliError("Your session has ended.", EXIT_AUTH, hint="Run: ps login")
    return response.json()
