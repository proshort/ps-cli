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

    def _parse(self, raw: str | None) -> Credentials | None:
        if not raw:
            return None
        try:
            return Credentials(**json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            # A corrupt copy is not a reason to crash every command, and it must
            # not shadow a good copy in the other store either -- hence a value
            # per source rather than one shared `raw`.
            return None

    def load(self) -> Credentials | None:
        """Whichever store holds the *newer* pair, not whichever we look at first.

        Preferring the keychain unconditionally is what made a failed keychain
        write catastrophic rather than merely inconvenient. The sequence, on a
        locked macOS keychain, which is an ordinary afternoon:

        1. A refresh succeeds and the server rotates the pair.
        2. `set_password` raises, so the new pair goes to the 0600 file.
        3. The keychain unlocks. The next command reads it and finds the *old*
           refresh token.
        4. It presents that token. The server does exactly what it was designed
           to do about a spent refresh token and revokes the whole family.

        The refresh lock cannot help: both processes agree on the same stale
        keychain value. Two stores only work if one of them is authoritative, and
        `expires_at` is what says which -- every refresh sets it from the clock,
        so the later one is always the newer pair. `save` also drops the keychain
        copy when it falls back to the file, which fixes it at the source; this
        fixes it when even that delete could not run.
        """
        found = [
            self._parse(self._from_keyring()),
            self._parse(self._path.read_text(encoding="utf-8") if self._path.exists() else None),
        ]
        live = [c for c in found if c is not None]
        if not live:
            return None
        return max(live, key=lambda c: c.expires_at)

    def _from_keyring(self) -> str | None:
        ring = self._keyring()
        if ring is None:
            return None
        try:
            return ring.get_password(_SERVICE, self._profile)
        except Exception:
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
            # The write failed and the pair is about to go to the file instead.
            # Delete whatever the keychain still holds: it is the *previous*
            # pair, and leaving it there is how a rotated-away refresh token gets
            # presented again and read as theft. Best-effort, because the same
            # locked keychain that refused the write will refuse this -- which is
            # why `load` also compares the two rather than trusting this alone.
            with suppress(Exception):
                ring.delete_password(_SERVICE, self._profile)

        self._dir.mkdir(parents=True, exist_ok=True)
        # Written to a temp file and renamed, because `os.replace` is atomic on
        # POSIX. Truncating the real file first leaves a window where a
        # concurrent `load()` -- and `Client.__init__` does one, outside the lock
        # -- reads an empty file and reports the user as signed out.
        #
        # `O_EXCL` and a pid in the name, not a fixed `{profile}.tmp` opened with
        # `O_CREAT`: that only applies its mode when it *creates* the file, so a
        # pre-existing world-readable temp file -- planted in a shared
        # `PROSHORT_CONFIG_DIR`, or left by a killed process -- would be written
        # to at its own mode and then renamed over the real one. `O_EXCL` means
        # the file is ours and 0600 is ours; `O_NOFOLLOW` means it is a file and
        # not a symlink pointing somewhere else.
        tmp = self._dir / f"{self._profile}.{os.getpid()}.tmp"
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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
