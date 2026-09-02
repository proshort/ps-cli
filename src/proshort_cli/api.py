"""The HTTP client: one bearer header, and the two retries worth making.

Everything the server needs to know about who is calling is in a single
`Authorization` header. Nothing else in the request carries identity -- no user id
in a path, no organisation in a parameter, no cookie -- because the server will
not read one if we send it.

Two things are retried and nothing else is. A `401` means the access token aged
out, which is normal every ten minutes and should be invisible. A `429` means we
were told to slow down, and the server said by how much. Everything else is
reported.
"""

import json
import time
from typing import Any

import httpx

from proshort_cli import oauth
from proshort_cli.errors import (
    EXIT_AUTH,
    EXIT_ERROR,
    CliError,
    InsufficientScope,
    NotAuthenticated,
    RateLimited,
    Unavailable,
)
from proshort_cli.render import note
from proshort_cli.store import Credentials, CredentialStore

# Well above the server's 128KB response ceiling, so this only fires on
# something genuinely wrong rather than on a large legitimate page.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# A ceiling on `--all`. The walk's normal terminator is a short page, which is a
# promise about the *server*: a bug or a proxy that always returns a full page
# turns `--all` into an unbounded loop against a host `--url` chose. 400 pages at
# the default size is far past any real pipeline and still bounded, and it fails
# loudly rather than returning a truncated answer -- the same rule the walk
# already applies to an error mid-scan.
MAX_PAGES = 400


class Client:
    def __init__(self, store: CredentialStore, *, timeout: int = 60, verbose: bool = False) -> None:
        self._store = store
        self._timeout = timeout
        self._verbose = verbose
        # One deadline for the life of the command, not one per request. `--timeout`
        # says "seconds to spend, including waits", and a per-request timeout does
        # not mean that: `--all` over twelve pages could spend twelve times the
        # budget and still be inside every individual limit. A `Client` is built
        # once per command, so its lifetime *is* the command.
        self._deadline = time.monotonic() + timeout
        credentials = store.load()
        if credentials is None:
            raise NotAuthenticated()
        try:
            oauth.require_secure(credentials.base_url)
        except CliError as exc:
            # Re-coded on purpose. `require_secure` raises a usage error, which is
            # right for a mistyped `--url` -- the user is holding the command
            # wrong. Here the bad address is in a *stored* credential, which a
            # Skill cannot fix by rebuilding its command line, and exit 2 tells it
            # to retry forever. The remedy is a fresh sign-in, so say that.
            raise CliError(
                str(exc), EXIT_AUTH, hint="Run: proshort login --url https://<your-proshort-host>"
            ) from exc
        self._credentials = credentials

    def _remaining(self) -> float:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise Unavailable(f"Gave up after {self._timeout}s (--timeout).")
        return left

    @property
    def base_url(self) -> str:
        return self._credentials.base_url.rstrip("/")

    # ------------------------------------------------------------------- tokens

    def _ensure_fresh(self) -> None:
        """Refresh if the token has aged out locally."""
        if not self._credentials.expired():
            return
        self._refresh_locked(stale=self._credentials.access_token)

    def _refresh_locked(self, *, stale: str) -> None:
        """Refresh once, under an exclusive lock, unless somebody already did.

        The re-read inside the lock is the point. Two commands starting together
        both want to refresh; the first does it, and the second -- which would
        otherwise present a token that is now spent, and be treated as a thief --
        finds the fresh one on disk and uses it.

        **The test is "is it different from the one that failed", not "is it
        unexpired".** An earlier version checked only expiry, which meant a 401 on
        a token that still looked fresh locally -- a server-side revocation, a
        clock skew, a consent-version bump -- re-read the same unexpired
        credentials, skipped the refresh, and retried with the token that had just
        been rejected. The user was told to sign in again for something a refresh
        would have fixed.
        """
        with self._store.refresh_lock():
            latest = self._store.load()
            if latest is not None and latest.access_token != stale and not latest.expired():
                self._credentials = latest
                return

            current = latest or self._credentials
            payload = oauth.refresh(
                base_url=current.base_url,
                client_id=current.client_id,
                refresh_token=current.refresh_token,
                timeout=int(self._remaining()),
            )
            self._credentials = Credentials(
                access_token=payload["access_token"],
                # Indexed, not `.get(..., current.refresh_token)`. `_token_payload`
                # already requires a rotated token on this grant and refuses the
                # response without one, so the default was unreachable code saying
                # the opposite of the check that guards it -- and quietly carrying
                # a spent token forward is the one outcome worth never guessing at.
                refresh_token=payload["refresh_token"],
                # `_token_payload` has already coerced this to a positive int, so
                # a `null` on the wire cannot arrive here as `int(None)`.
                expires_at=time.time() + payload["expires_in"],
                scopes=(payload.get("scope") or " ".join(current.scopes)).split(),
                base_url=current.base_url,
                client_id=current.client_id,
                # Carried forward so `save` can bump past it even when the
                # keychain is unreadable and cannot report what it holds.
                generation=current.generation,
            )
            self._store.save(self._credentials)

    # ------------------------------------------------------------------ request

    def get(self, path: str, params: list[tuple[str, str]] | None = None) -> dict[str, Any]:
        self._ensure_fresh()
        refreshed = False

        while True:
            response, body = self._send(path, params)

            if response.status_code == 401 and not refreshed:
                # One retry. A second 401 after a successful refresh is not a
                # timing problem -- the grant is gone, or the consent copy moved.
                refreshed = True
                self._refresh_locked(stale=self._credentials.access_token)
                continue

            if response.status_code == 429:
                wait = _retry_after(response)
                if time.monotonic() + wait > self._deadline:
                    raise RateLimited(wait)
                if self._verbose:
                    note(f"rate limited; waiting {wait}s")
                time.sleep(wait)
                continue

            return self._interpret(response, body)

    def _send(
        self, path: str, params: list[tuple[str, str]] | None
    ) -> tuple[httpx.Response, bytes]:
        """One request, read incrementally and abandoned if it runs away.

        **Streamed, not buffered.** `httpx.get` downloads the whole body before
        returning, so checking `len(response.content)` afterwards refused to
        *parse* what had already been pulled into memory -- which is not a
        ceiling, it is a comment. `--url` names the host, so the thing this
        bounds is a client that would otherwise happily accept gigabytes from
        wherever it was pointed. The connection is dropped at the cap.

        `Content-Length` is checked first where the server sends one, so an
        honest large response costs nothing at all.
        """
        try:
            with httpx.stream(
                "GET",
                f"{self.base_url}{path}",
                params=params or [],
                headers={
                    "Authorization": f"Bearer {self._credentials.access_token}",
                    "Accept": "application/json",
                    "User-Agent": "proshort-cli",
                },
                timeout=self._remaining(),
                # Already the httpx default. Pinned because this request carries a
                # bearer token, and a 302 must not be allowed to carry it to a
                # second host.
                follow_redirects=False,
            ) as response:
                declared = response.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                    raise Unavailable("Proshort returned an unexpectedly large response.")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise Unavailable("Proshort returned an unexpectedly large response.")
                return response, bytes(body)
        except httpx.RequestError as exc:
            raise Unavailable(f"Could not reach Proshort: {exc.__class__.__name__}.") from exc

    def _interpret(self, response: httpx.Response, raw: bytes) -> dict[str, Any]:
        decoded = _decode(raw)

        if response.status_code == 200:
            # Held to the same standard as the failure path below, which was
            # already careful about this. A 200 carrying a JSON array, or HTML
            # from a captive portal, used to reach `_emit` and `get_all` as
            # whatever it happened to be -- and `.get("data")` on a list is an
            # AttributeError, which escapes as a traceback and exit 1. That is
            # the exit-code contract breaking at the moment a script most needs
            # it, which is exactly the argument for guarding the other path.
            if not isinstance(decoded, dict):
                raise Unavailable("Proshort returned a response this client could not read.")
            return decoded

        # Whatever the other end sent, not necessarily an object with an object
        # inside it. `.json().get(...)` raises AttributeError on a bare string,
        # which would escape main() as a traceback and exit 1 -- breaking the
        # exit-code contract at the moment a script most needs it.
        body: dict[str, Any] = {}
        if isinstance(decoded, dict) and isinstance(decoded.get("error"), dict):
            body = decoded["error"]
        code = str(body.get("code") or "")
        message = str(body.get("message") or f"Request failed ({response.status_code}).")

        if code == "insufficient_scope":
            raise InsufficientScope(_scope_from(response))
        if code == "consent_required":
            # `ps-mcp` cannot currently raise this -- a token issued under an
            # older consent version is refused by the verifier and is
            # indistinguishable from an expired one, which is why the server
            # deliberately does not publish the code. Kept because the answer it
            # gives is right either way, and a 403 carrying it would otherwise
            # fall through to a bare exit 1.
            raise CliError(message, 3, hint="Run: proshort login")
        if response.status_code == 401:
            raise NotAuthenticated(message)
        # Any 5xx, not just the gateway ones. A 500 is still "Proshort is
        # broken, and there is nothing you can change about your request" --
        # which is what a script needs to know, and it is a different action from
        # the generic failure that exit 1 means.
        if response.status_code >= 500 or code == "upstream_error":
            raise Unavailable(message)
        raise CliError(message, EXIT_ERROR)

    # --------------------------------------------------------------- pagination

    def get_all(self, path: str, params: list[tuple[str, str]], *, rows_key: str = "data") -> dict:
        """Walk pages until the server stops giving new ones.

        **Every error ends the walk by raising**, including one that arrives after
        some pages have already been fetched. An earlier version swallowed any
        generic failure past page 1 and returned what it had with exit 0 -- so a
        500 halfway through a scan produced a short list that looked complete, and
        a Skill would summarise a partial pipeline as the whole thing. Silent
        truncation is the one failure mode this command must not have.

        The normal terminator is a short page: fewer rows than the page size means
        the last one. Where that leaves us is the server's page-depth cap, which
        refuses beyond a fixed page and so surfaces as a plain failure with the
        server's own message. That is honest but blunt, and the fix belongs on the
        other side -- a distinct `page_limit` error code would let this stop
        cleanly and report the cap. Until then, loud beats short.
        """
        merged: list[Any] = []
        page = 1
        first: dict[str, Any] = {}
        while True:
            paged = [p for p in params if p[0] != "page"] + [("page", str(page))]
            body = self.get(path, paged)
            first = first or body
            rows = body.get(rows_key)
            if rows is None:
                rows = []
            if not isinstance(rows, list):
                # `extend` on a dict would walk its keys and call that a page of
                # results, so a shape change downstream would read as a
                # successful scan of the wrong thing.
                raise Unavailable("Proshort returned a page this client could not read.")
            merged.extend(rows)
            if not rows or len(rows) < _page_size(body):
                break
            if page >= MAX_PAGES:
                raise Unavailable(
                    f"Stopped after {MAX_PAGES} pages without reaching the end of the results."
                )
            page += 1
        first[rows_key] = merged
        # `setdefault` returns the existing value, so an explicit `"page": null`
        # came back as `None` and `None["returned"]` was a TypeError -- a
        # traceback and exit 1 raised *after* a complete, successful walk, on the
        # one command whose whole argument is that it never returns quietly wrong
        # results.
        page = first.get("page")
        first["page"] = page if isinstance(page, dict) else {}
        first["page"]["returned"] = len(merged)
        return first


def _decode(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _page_size(body: dict[str, Any]) -> int:
    """The page size the server reported, or a sane default.

    Every field here comes off the wire, so `int()` on any of them can raise --
    and a `ValueError` from inside the pagination walk escapes `main()` as a
    traceback and exit 1, which is the contract breaking mid-scan.
    """
    page = body.get("page")
    if not isinstance(page, dict):
        return 25
    for key in ("page_size", "returned"):
        value = page.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return 25


def _retry_after(response: httpx.Response) -> int:
    raw = response.headers.get("Retry-After")
    try:
        return max(1, int(raw)) if raw else 30
    except ValueError:
        return 30


def _scope_from(response: httpx.Response) -> str | None:
    challenge = response.headers.get("WWW-Authenticate", "")
    marker = 'scope="'
    if marker in challenge:
        return challenge.split(marker, 1)[1].split('"', 1)[0]
    return None
