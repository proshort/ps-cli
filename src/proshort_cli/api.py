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

import time
from typing import Any

import httpx

from proshort_cli import oauth
from proshort_cli.errors import (
    CliError,
    EXIT_ERROR,
    InsufficientScope,
    NotAuthenticated,
    RateLimited,
    Unavailable,
)
from proshort_cli.render import note
from proshort_cli.store import CredentialStore, Credentials

# Well above the server's 128KB response ceiling, so this only fires on
# something genuinely wrong rather than on a large legitimate page.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class Client:
    def __init__(self, store: CredentialStore, *, timeout: int = 60, verbose: bool = False) -> None:
        self._store = store
        self._timeout = timeout
        self._verbose = verbose
        credentials = store.load()
        if credentials is None:
            raise NotAuthenticated()
        self._credentials = credentials

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
            )
            self._credentials = Credentials(
                access_token=payload["access_token"],
                refresh_token=payload.get("refresh_token", current.refresh_token),
                expires_at=time.time() + int(payload.get("expires_in", 600)),
                scopes=(payload.get("scope") or " ".join(current.scopes)).split(),
                base_url=current.base_url,
                client_id=current.client_id,
            )
            self._store.save(self._credentials)

    # ------------------------------------------------------------------ request

    def get(self, path: str, params: list[tuple[str, str]] | None = None) -> dict[str, Any]:
        self._ensure_fresh()
        deadline = time.monotonic() + self._timeout
        refreshed = False

        while True:
            response = self._send(path, params)

            if response.status_code == 401 and not refreshed:
                # One retry. A second 401 after a successful refresh is not a
                # timing problem -- the grant is gone, or the consent copy moved.
                refreshed = True
                self._refresh_locked(stale=self._credentials.access_token)
                continue

            if response.status_code == 429:
                wait = _retry_after(response)
                if time.monotonic() + wait > deadline:
                    raise RateLimited(wait)
                if self._verbose:
                    note(f"rate limited; waiting {wait}s")
                time.sleep(wait)
                continue

            return self._interpret(response)

    def _send(self, path: str, params: list[tuple[str, str]] | None) -> httpx.Response:
        try:
            response = httpx.get(
                f"{self.base_url}{path}",
                params=params or [],
                headers={
                    "Authorization": f"Bearer {self._credentials.access_token}",
                    "Accept": "application/json",
                    "User-Agent": "proshort-cli",
                },
                timeout=self._timeout,
            )
        except httpx.RequestError as exc:
            raise Unavailable(f"Could not reach Proshort: {exc.__class__.__name__}.") from exc

        # The server bounds its own responses; this is the client agreeing not to
        # be the place an unbounded one lands. Generous relative to the server's
        # 128KB ceiling, so it only ever catches something genuinely wrong.
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise Unavailable("Proshort returned an unexpectedly large response.")
        return response

    def _interpret(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 200:
            return response.json()

        # Whatever the other end sent, not necessarily an object with an object
        # inside it. `.json().get(...)` raises AttributeError on a bare string,
        # which would escape main() as a traceback and exit 1 -- breaking the
        # exit-code contract at the moment a script most needs it.
        body: dict[str, Any] = {}
        try:
            decoded = response.json()
        except ValueError:
            decoded = None
        if isinstance(decoded, dict) and isinstance(decoded.get("error"), dict):
            body = decoded["error"]
        code = str(body.get("code") or "")
        message = str(body.get("message") or f"Request failed ({response.status_code}).")

        if code == "insufficient_scope":
            raise InsufficientScope(_scope_from(response))
        if code == "consent_required":
            raise CliError(message, 3, hint="Run: ps login")
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
            rows = body.get(rows_key) or []
            merged.extend(rows)
            if not rows or len(rows) < _page_size(body):
                break
            page += 1
        first[rows_key] = merged
        first.setdefault("page", {})["returned"] = len(merged)
        return first


def _page_size(body: dict[str, Any]) -> int:
    page = body.get("page") or {}
    return int(page.get("page_size") or page.get("returned") or 25) or 25


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
