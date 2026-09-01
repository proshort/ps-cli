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
        """Refresh if needed, once, under an exclusive lock.

        The re-read inside the lock is the whole point. Two commands starting
        together both see an expired token and both want to refresh; the first one
        through does it, and the second -- which would otherwise present a token
        that is now spent, and be treated as a thief -- finds the fresh one already
        on disk and uses it.
        """
        if not self._credentials.expired():
            return

        with self._store.refresh_lock():
            latest = self._store.load()
            if latest is not None and not latest.expired():
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
                self._force_refresh()
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
            return httpx.get(
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

    def _force_refresh(self) -> None:
        self._credentials.expires_at = 0
        self._ensure_fresh()

    def _interpret(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 200:
            return response.json()

        body: dict[str, Any] = {}
        try:
            body = response.json().get("error") or {}
        except ValueError:
            pass
        code = str(body.get("code") or "")
        message = str(body.get("message") or f"Request failed ({response.status_code}).")

        if code == "insufficient_scope":
            raise InsufficientScope(_scope_from(response))
        if code == "consent_required":
            raise CliError(message, 3, hint="Run: ps login")
        if response.status_code == 401:
            raise NotAuthenticated(message)
        if response.status_code in (502, 503, 504) or code == "upstream_error":
            raise Unavailable(message)
        raise CliError(message, EXIT_ERROR)

    # --------------------------------------------------------------- pagination

    def get_all(self, path: str, params: list[tuple[str, str]], *, rows_key: str = "data") -> dict:
        """Walk pages until the server stops giving new ones.

        Bounded by the server's own page cap, not by anything decided here: when
        it refuses a page beyond its limit, that refusal ends the walk. A client
        that kept asking would just be generating refusals.
        """
        merged: list[Any] = []
        page = 1
        first: dict[str, Any] = {}
        while True:
            paged = [p for p in params if p[0] != "page"] + [("page", str(page))]
            try:
                body = self.get(path, paged)
            except CliError as exc:
                if page > 1 and exc.code == EXIT_ERROR:
                    # The page cap, reached. Everything gathered so far is real.
                    note(f"note: stopped at page {page - 1} ({exc})")
                    break
                raise
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
