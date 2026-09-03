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
- **A self-contained callback page.** No external references of any kind, plus
  `Referrer-Policy: no-referrer` and a `default-src 'none'` CSP, so the
  authorization code in our URL cannot be carried anywhere by a subresource
  fetch -- enforced by a header rather than asserted by a comment.

The listener keeps serving until it gets a callback that belongs to *this* flow.
An earlier version handled exactly one request, which meant any GET to the port
during the wait -- a favicon probe, a health checker, an `<img src>` on a page the
user happens to have open -- consumed the listener and turned the sign-in into a
misleading "timed out". A request that is not ours is answered and ignored.
"""

import base64
import hashlib
import http.server
import secrets
import socketserver
import time
import urllib.parse
import webbrowser
from typing import ClassVar

import httpx

from proshort_cli.errors import EXIT_AUTH, EXIT_USAGE, CliError, RateLimited, Unavailable
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


class _LoopbackServer(http.server.HTTPServer):
    """The listener, without the reverse DNS lookup that comes free with it.

    `HTTPServer.server_bind` calls `socket.getfqdn(host)` to populate
    `server_name`, a field nothing here reads. On a machine whose reverse
    resolver is slow or absent -- a locked-down corporate network, a CI runner,
    a laptop on hotel wifi -- that blocks for tens of seconds *before the browser
    is opened*, so `proshort login` appears to hang at the one moment the user is
    waiting on it. A GitHub macOS runner spent 36 seconds there.

    The host is `127.0.0.1`. There is nothing to look up.
    """

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]


class _Catcher(http.server.BaseHTTPRequestHandler):
    """Answers callbacks. Stores only one that belongs to this flow."""

    # ClassVar, and deliberately so: this is how the handler hands a result back
    # to the loop that is serving it. Pinned to the class rather than the
    # instance because a fresh handler is constructed per request.
    expected_state: ClassVar[str] = ""
    result: ClassVar[dict[str, str]] = {}

    def do_GET(self) -> None:
        # Loopback only. The redirect is registered as 127.0.0.1, so a request
        # arriving under any other Host reached us some other way and has no
        # business being answered with a page that carries a code.
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1"):
            self._reply(400, b"Bad host", b"")
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != CALLBACK_PATH:
            # Something else on this machine poked the port. Answer it and keep
            # listening -- this used to end the sign-in.
            self._reply(404, b"Not found", b"")
            return

        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        # `state` is checked *here*, before anything in the response is read --
        # including `error`. Checking it later meant a forged
        # `?error=access_denied` could end a sign-in without ever being matched
        # against the flow that started it.
        if not secrets.compare_digest(query.get("state", ""), _Catcher.expected_state):
            self._reply(
                400,
                b"That didn&rsquo;t match.",
                b"This response did not belong to the sign-in your terminal started.",
            )
            return

        _Catcher.result = query
        ok = "code" in query
        self._reply(
            200,
            b"You&rsquo;re signed in." if ok else b"Sign-in failed.",
            b"You can close this tab and go back to your terminal."
            if ok
            else b"Go back to your terminal for the details.",
        )

    def _reply(self, status: int, heading: bytes, detail: bytes) -> None:
        body = _PAGE % (heading, detail)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # The authorization code is in this page's URL. Nothing here loads a
        # subresource, and these two make that a guarantee rather than a promise.
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        """Silence. The default logs the request line -- which contains the code."""


def login(
    *,
    base_url: str,
    client_id: str = DEFAULT_CLIENT_ID,
    scopes: list[str] | None = None,
    timeout: int = 300,
    open_browser: bool = True,
) -> dict:
    """Run the full flow and return the token response.

    `timeout` bounds the whole thing -- the browser wait *and* the redemption --
    because that is what `--timeout` says it does. The redemption gets whatever is
    left rather than a second full budget of its own.
    """
    base_url = base_url.rstrip("/")
    require_secure(base_url)
    deadline = time.monotonic() + timeout
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)

    # Bound to port 0 and read back, rather than probing for a free port and
    # rebinding it: between the probe and the rebind another process can take it.
    _Catcher.expected_state = state
    _Catcher.result = {}
    server = _LoopbackServer(("127.0.0.1", 0), _Catcher)
    port = int(server.server_address[1])
    redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"

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

    opened = webbrowser.open(authorize_url) if open_browser else False
    if opened:
        note(f"\u2192 opened your browser \u00b7 listening on 127.0.0.1:{port}")
    else:
        # `webbrowser.open` returns False on a headless box, over SSH, or with no
        # handler registered. Announcing a browser that never opened and then
        # waiting out the whole timeout is the least useful thing this could do.
        note(f"\u2192 listening on 127.0.0.1:{port} \u00b7 open this to continue:")
        note(f"  {authorize_url}")

    try:
        result = _serve_until_callback(server, max(1, int(deadline - time.monotonic())))
    finally:
        server.server_close()
        _Catcher.expected_state = ""
        _Catcher.result = {}

    if not result:
        raise CliError("Timed out waiting for the browser to come back.", EXIT_AUTH)
    # `state` was verified in the handler before this dict was stored. Re-checked
    # here so the guarantee does not depend on reading another function.
    if not secrets.compare_digest(result.get("state", ""), state):
        raise CliError("The sign-in response did not match this session.", EXIT_AUTH)
    if "error" in result:
        raise CliError(f"Sign-in was refused: {result.get('error')}", EXIT_AUTH)
    if "code" not in result:
        raise CliError("The browser came back without an authorization code.", EXIT_AUTH)

    return exchange_code(
        base_url=base_url,
        client_id=client_id,
        code=result["code"],
        verifier=verifier,
        redirect_uri=redirect_uri,
        timeout=max(1, int(deadline - time.monotonic())),
    )


def _serve_until_callback(server: http.server.HTTPServer, timeout: float) -> dict[str, str]:
    """Serve requests until one is ours, or the deadline passes.

    `handle_request` services exactly one request, so calling it once meant the
    first stray GET to the port ended the sign-in. The short per-call timeout is
    what lets the deadline be checked between requests.
    """
    deadline = time.monotonic() + timeout
    server.timeout = 1.0
    while not _Catcher.result and time.monotonic() < deadline:
        server.handle_request()
    return dict(_Catcher.result)


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def as_origin(base_url: str) -> str:
    """Reduce a caller-supplied address to `scheme://host[:port]`, or refuse it.

    Every caller concatenates onto this (`{base}/authorize`, `{base}/v1/deals`),
    so it has to be an origin and not a prefix. `require_secure` checked the
    scheme and the host and let the rest through, which meant
    `https://host/v1` built `/v1/v1/deals`, `https://host?x=1` built
    `https://host?x=1/authorize?...`, and a fragment swallowed the path glued
    after it. The first `login` then *stored* that string, so every later command
    inherited it and failed as "Proshort is unavailable" or a bare 404 -- the
    undiagnosable-from-outside failure that got the internal default removed.

    Refused rather than trimmed. Silently dropping a path somebody typed is the
    same "answer a different question" this client refuses everywhere else, and
    the one thing a wrong host must not do is look like it worked.
    """
    require_secure(base_url)
    parts = urllib.parse.urlsplit(base_url)
    if parts.path.strip("/") or parts.query or parts.fragment:
        raise CliError(
            f"--url must be a host, not a full address: got {base_url!r}.",
            EXIT_USAGE,
            hint="Pass the origin only, e.g. https://mcp.example.com -- no path, query or #fragment.",
        )
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def require_secure(base_url: str) -> None:
    """Refuse to send a grant over cleartext.

    RFC 8252 makes loopback HTTP an exception for the *redirect*, and only that:
    the token endpoint is a different address and carries the `code_verifier` and
    the refresh token, which is the credential worth thirty days. `--url` is
    caller-supplied, so without this a mistyped or downgraded `http://` host gets
    the whole grant in the clear and nothing says a word.

    Loopback stays allowed because that is a local `ps-mcp` on a developer's own
    machine, where there is no network to be on.
    """
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme == "https":
        return
    host = (parts.hostname or "").strip("[]")
    if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
        return
    raise CliError(
        f"Refusing to send credentials to {base_url!r} over {parts.scheme or 'no'} scheme.",
        EXIT_USAGE,
        hint="Use an https:// address. http:// is only accepted for 127.0.0.1.",
    )


def _post_token(*, base_url: str, data: dict, what: str, timeout: int) -> dict:
    """Redeem or refresh a grant, and classify the failure the way `/v1` does.

    The exit codes are the interface a Skill branches on: `3` means "tell the
    user to sign in again", `6` means "Proshort is down, not their fault". This
    used to map *every* non-200 to `3` and let a transport error escape as a
    traceback and exit `1` -- a code the Skill's table does not even list. So a
    503 during the silent ten-minute refresh told the user their session had
    ended, and a connect timeout told them nothing at all.

    `api._interpret` already made this split for the data plane. This is the same
    split for the token plane, and the same rule decides it: a status that says
    the *grant* is gone is the user's to fix; anything that says the *server* did
    not answer is not.
    """
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}/token",
            data=data,
            timeout=max(1, timeout),
            # Already the default. Pinned because this request carries the
            # `code_verifier` or the refresh token, and a 302 must not be able to
            # deliver either to a second host.
            follow_redirects=False,
        )
    except httpx.RequestError as exc:
        raise Unavailable(f"Could not reach Proshort: {exc.__class__.__name__}.") from exc

    if response.status_code == 200:
        return _token_payload(response, what)
    # 5xx is the server failing, and 429 is the server asking us to wait; neither
    # is evidence that the grant is gone. Answering either with "sign in again"
    # sends the user to redo a sign-in that was never the problem -- and, on a
    # refresh, throws away a refresh token that is still perfectly good.
    if response.status_code == 429:
        # Exit 5, not 6. The data plane already tells "slow down" from "the server
        # is broken", and answering a throttled token endpoint with "Proshort is
        # unavailable" told a Skill to give up on a refresh token that is still
        # perfectly good. `Retry-After` where the server sent one, so the wait is
        # theirs rather than a number invented here.
        raise RateLimited(_retry_after(response))
    if response.status_code >= 500:
        raise Unavailable(f"Proshort could not complete the {what} ({response.status_code}).")
    raise CliError(
        "Your session has ended." if what == "refresh" else f"Sign-in was refused ({response.status_code}).",
        EXIT_AUTH,
        hint="Run: proshort login",
    )


def exchange_code(
    *,
    base_url: str,
    client_id: str,
    code: str,
    verifier: str,
    redirect_uri: str,
    timeout: int = 30,
) -> dict:
    return _post_token(
        base_url=base_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        },
        what="sign-in",
        timeout=timeout,
    )


def refresh(*, base_url: str, client_id: str, refresh_token: str, timeout: int = 30) -> dict:
    return _post_token(
        base_url=base_url,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
        what="refresh",
        timeout=timeout,
    )


def _retry_after(response: "httpx.Response") -> int:
    raw = response.headers.get("Retry-After")
    try:
        return max(1, int(raw)) if raw else 30
    except ValueError:
        return 30


def _token_payload(response: "httpx.Response", what: str) -> dict:
    """Validate a token response before anything indexes into it.

    `response.json()` returns whatever the other end sent. Treating that as a dict
    with the keys we want turns a malformed or unexpected body into a `KeyError`
    or an `AttributeError` -- which escapes `main()` as a traceback and exit 1,
    breaking the exit-code contract at exactly the moment a script most needs it.
    """
    # `Unavailable`, not `EXIT_AUTH`, for both. A 200 that cannot be parsed is the
    # server failing exactly as a 200 missing `access_token` is, and the missing
    # field already answered 6 -- telling a user to sign in again over a garbage
    # 200 sends them to redo something that was never the problem.
    try:
        payload = response.json()
    except ValueError as exc:
        raise Unavailable(f"Proshort's {what} response could not be read.") from exc
    if not isinstance(payload, dict):
        raise Unavailable(f"Proshort's {what} response was not in the expected form.")
    # `refresh_token` is required on *both* grants, including the refresh, which
    # RFC 6749 does not demand: rotation is optional there, and a server may
    # legitimately return only a new access token. Required anyway because this
    # client talks to `ps-mcp`, which always rotates and treats re-use of a spent
    # token as theft -- so a refresh response without a replacement means
    # something is wrong on the server, and saying so is better than carrying the
    # old token forward and being revoked as a thief on the call after next.
    # `api._refresh_locked` indexes this directly on the strength of this check.
    #
    # `Unavailable`, not `EXIT_AUTH`. A 200 that does not carry a usable grant is
    # the *server* failing, and telling the user to sign in again sends them to
    # redo something that was never the problem -- the same misclassification
    # `_post_token` exists to stop, applied to the other side of the same call.
    for required in ("access_token", "refresh_token"):
        if not isinstance(payload.get(required), str) or not payload[required]:
            raise Unavailable(f"Proshort's {what} response was missing {required}.")

    # Coerced here so every caller can index a real int. `.get("expires_in", 600)`
    # defaults only when the key is *absent*: an explicit `null` became
    # `int(None)`, which is a TypeError escaping as a traceback and exit 1 -- and
    # it does it on the silent ten-minute refresh, where nobody is watching.
    lifetime = payload.get("expires_in", 600)
    if isinstance(lifetime, bool) or not isinstance(lifetime, (int, float)) or lifetime <= 0:
        if lifetime is not None:
            # A present-but-unusable value is worth refusing; an explicit null is
            # the server declining to say, which the default already covers.
            raise Unavailable(f"Proshort's {what} response gave an unusable expires_in.")
        lifetime = 600
    payload["expires_in"] = int(lifetime)
    return payload


def revoke(*, base_url: str, client_id: str, token: str) -> None:
    """Best-effort RFC 7009 revocation.

    `ps-mcp` enables the revocation endpoint and revokes the whole refresh family
    from either half of the pair, so this actually ends the grant rather than
    just forgetting it locally. Without it, "I logged out" leaves a token that
    keeps working for thirty days -- which is exactly what somebody who copied
    the credential file is counting on.

    Best-effort on purpose: a network failure must not stop the local credentials
    being cleared. The caller reports what happened.
    """
    require_secure(base_url)
    httpx.post(
        f"{base_url.rstrip('/')}/revoke",
        data={
            "token": token,
            "token_type_hint": "refresh_token",
            "client_id": client_id,
            # Required by the server's request model even though this is a public
            # client with no secret. Sent empty rather than omitted: client
            # authentication for `token_endpoint_auth_method="none"` ignores the
            # value entirely, but the field has to be present or the request is
            # rejected as malformed before it reaches revocation at all.
            "client_secret": "",
        },
        timeout=15,
        follow_redirects=False,
    ).raise_for_status()
