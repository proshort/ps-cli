"""Where the tokens live, and the lock that stops two commands losing them.

**The lock is the important part of this file.**

The server rotates refresh tokens and treats re-use of a spent one as theft: it
revokes the whole grant. That is exactly right against a stolen token and exactly
wrong against a shell running two commands at once. Both see an expired access
token, both present the same refresh token, one wins, and the loser looks like an
attacker -- so the user is signed out at random, having done nothing but run two
things in parallel.

The server deliberately has no grace window for this. A server-side grace would
mean handing the same replacement to whoever presents a spent token, which turns
a loud theft signal into a silent one: attacker and victim would both quietly
receive working credentials and nothing would look unusual. So the fix belongs
here, where the race actually is -- an exclusive lock, with the loser re-reading
the file and using the winner's token rather than spending its own.

That covers one machine with several processes, which is the real case. It does
not cover a credential file copied to a second machine, and it is not meant to:
that *is* the case the theft signal exists for, and it should still be loud.
"""

import fcntl
import json
import os
import time
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path

from proshort_cli.render import note

_SERVICE = "proshort-cli"


def config_dir() -> Path:
    return Path(os.environ.get("PROSHORT_CONFIG_DIR") or (Path.home() / ".proshort"))


@dataclass
class Credentials:
    access_token: str
    refresh_token: str
    # Absolute epoch seconds. Stored rather than a duration so a process that
    # starts hours later does not think a stale token is fresh.
    expires_at: float
    scopes: list[str]
    base_url: str
    client_id: str

    def expired(self, *, skew: int = 30) -> bool:
        # A little early, so a token does not expire in flight between the check
        # and the request reaching the server.
        return time.time() >= (self.expires_at - skew)


class CredentialStore:
    """Keychain when there is one, a 0600 file when there is not."""

    def __init__(self, profile: str = "default") -> None:
        self._profile = profile
        self._dir = config_dir()
        self._path = self._dir / f"{profile}.json"
        self._lock_path = self._dir / f"{profile}.lock"

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------ keyring

    def _keyring(self):
        try:
            import keyring
            return keyring
        except Exception:
            return None

    # --------------------------------------------------------------- read/write

    def load(self) -> Credentials | None:
        raw = None
        ring = self._keyring()
        if ring is not None:
            try:
                raw = ring.get_password(_SERVICE, self._profile)
            except Exception:
                raw = None
        if raw is None and self._path.exists():
            raw = self._path.read_text(encoding="utf-8")
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return Credentials(**data)
        except (json.JSONDecodeError, TypeError):
            # A corrupt file is not a reason to crash every command. Treat it as
            # signed out; `ps login` will overwrite it.
            return None

    def save(self, credentials: Credentials, *, announce: bool = False) -> None:
        raw = json.dumps(asdict(credentials))
        ring = self._keyring()
        if ring is not None:
            # A locked or broken keychain falls through to the file, which is the
            # documented behaviour; there is nothing actionable to log.
            with suppress(Exception):
                ring.set_password(_SERVICE, self._profile, raw)
                # Remove any earlier file copy, so the token does not survive on
                # disk once the keychain is holding it.
                self._path.unlink(missing_ok=True)
                return

        self._dir.mkdir(parents=True, exist_ok=True)
        # Written to a sibling temp file and renamed, because `os.replace` is
        # atomic on POSIX. Truncating the real file first leaves a window where a
        # concurrent `load()` -- and `Client.__init__` does one, outside the lock
        # -- reads an empty file and reports the user as signed out.
        #
        # Created 0600 *before* anything is written to it: writing first and
        # chmod-ing after leaves a window where the token is world-readable.
        tmp = self._path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
        finally:
            tmp.unlink(missing_ok=True)

        if announce:
            # Only when the user asked for something, not on every silent refresh.
            note(f"note: no OS keychain available; credentials are in {self._path} (0600)")

    def clear(self) -> None:
        ring = self._keyring()
        if ring is not None:
            # Nothing stored is the desired end state either way.
            with suppress(Exception):
                ring.delete_password(_SERVICE, self._profile)
        self._path.unlink(missing_ok=True)

    # -------------------------------------------------------------------- lock

    @contextmanager
    def refresh_lock(self):
        """Serialise refreshes across processes on this machine.

        A real file lock rather than a lock file whose existence is the signal:
        `flock` is released by the kernel when the process dies, so a command
        killed mid-refresh does not wedge every later one.
        """
        self._dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
