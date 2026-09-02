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
import re
import time
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path

from proshort_cli.errors import EXIT_USAGE, CliError
from proshort_cli.render import note

_SERVICE = "proshort-cli"

# A profile names a file. `--profile ../../tmp/other` would otherwise write a
# 0600 JSON blob and a lock file wherever it pointed -- the same class of bug as
# the planted temp file this module already defends against with `O_EXCL` and
# `O_NOFOLLOW`, and the same check the reference Skill applies to a deal id
# before putting it in a path.
_PROFILE = re.compile(r"\A[A-Za-z0-9._-]+\Z")


_FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "access_token": str,
    "refresh_token": str,
    "expires_at": (int, float),
    "scopes": list,
    "base_url": str,
    "client_id": str,
    "generation": int,
}


def _check_profile(profile: str) -> None:
    if profile in (".", "..") or not _PROFILE.match(profile):
        raise CliError(
            f"--profile must be letters, digits, dot, dash or underscore; got {profile!r}.",
            EXIT_USAGE,
        )


def config_dir() -> Path:
    return Path(os.environ.get("PROSHORT_CONFIG_DIR") or (Path.home() / ".proshort"))


@dataclass
class Credentials:
    access_token: str
    refresh_token: str
    # Absolute epoch seconds. Stored rather than a duration so a process that
    # starts hours later does not think a stale token is fresh.
    #
    # **Not a recency signal.** This says when the *access token* dies, which is
    # a different question from which of two stored blobs was written last --
    # see `generation` and `CredentialStore.load`.
    expires_at: float
    scopes: list[str]
    base_url: str
    client_id: str
    # Which write this pair came from. Defaulted so a credential file written
    # before this field existed still parses, as generation 0 -- the oldest
    # possible, which is the safe direction for the comparison in `load`.
    generation: int = 0

    def expired(self, *, skew: int = 30) -> bool:
        # A little early, so a token does not expire in flight between the check
        # and the request reaching the server.
        return time.time() >= (self.expires_at - skew)


class CredentialStore:
    """Keychain when there is one, a 0600 file when there is not."""

    def __init__(self, profile: str = "default") -> None:
        _check_profile(profile)
        self._profile = profile
        self._dir = config_dir()
        self._path = self._dir / f"{profile}.json"
        self._lock_path = self._dir / f"{profile}.lock"
        # Belt to the regex's braces, and it catches what a character class
        # cannot: a `PROSHORT_CONFIG_DIR` that is itself a symlink out of where
        # the caller thinks they are.
        if self._path.resolve().parent != self._dir.resolve():
            raise CliError(f"--profile {profile!r} does not stay inside {self._dir}.", EXIT_USAGE)

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
        """Decode one stored blob, or `None` if it is not one.

        Types are checked, not just keys. `Credentials(**data)` raises on an
        *extra* or *missing* key and accepts anything at all for the values, so
        `{"expires_at": "soon"}` parsed happily and then threw a `TypeError` out
        of `expired()` or out of the comparison in `load` -- which contradicts
        the whole reason this returns `None` instead of raising. A corrupt copy
        must cost a sign-in, never a traceback.
        """
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        for name, kinds in _FIELD_TYPES.items():
            value = data.get(name)
            if name == "generation" and value is None:
                continue  # written before the field existed
            # `bool` is a subclass of `int`, and `True` is not an expiry.
            if isinstance(value, bool) or not isinstance(value, kinds):
                return None
        try:
            return Credentials(**data)
        except TypeError:
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
        keychain value. Two stores only work if one of them is authoritative.

        **`generation`, not `expires_at`.** The first version of this compared
        expiry, on the reasoning that a refresh sets it from the clock so the
        later one must be the newer pair. That is a coincidence, not an
        invariant: `expires_at` answers "when does this access token die", and
        the two only move together when every refresh happens near expiry and
        `expires_in` never changes. `_refresh_locked` exists precisely because
        neither holds -- it refreshes a token that still looks fresh locally, on
        a 401 caused by a server-side revocation or a clock skew. Step the clock
        backwards between two saves, or shorten `expires_in`, and the *newer*
        pair carries the *smaller* number. The comparison then picks the spent
        refresh token, and the outage this whole mechanism exists to prevent
        happens anyway, now with a test suite saying it cannot.

        A counter has no clock in it at all. `save` reads the highest generation
        in either store and writes one above it, under the same lock the refresh
        takes, so the answer to "which was written last" is recorded rather than
        inferred.

        **Ties go to the file**, and that is an invariant rather than a
        preference. `save` writes the file only when the keychain write failed,
        and deletes the file whenever the keychain write succeeded -- so the two
        existing at once means the keychain lost. The tie is reachable because a
        locked keychain is unreadable as well as unwritable: `_next_generation`
        cannot see the number it needs to beat, so the fallback write can land on
        the same one. That is precisely the case this method exists for, so it
        had better not be the case it gets wrong.
        """
        file_copy = self._parse(self._read_file())
        keychain_copy = self._parse(self._from_keyring())
        live = [(1, file_copy), (0, keychain_copy)]
        candidates = [(gen_break, c) for gen_break, c in live if c is not None]
        if not candidates:
            return None
        return max(candidates, key=lambda pair: (pair[1].generation, pair[0]))[1]

    def _read_file(self) -> str | None:
        return self._path.read_text(encoding="utf-8") if self._path.exists() else None

    def _both(self) -> list[Credentials | None]:
        return [self._parse(self._from_keyring()), self._parse(self._read_file())]

    def _next_generation(self, at_least: int = 0) -> int:
        """One above everything visible, and above what the caller already held.

        `at_least` is the generation of the pair being replaced. It matters when a
        store is unreadable rather than empty -- a locked keychain hides the
        number to beat, and without this the fallback write would restart the
        count and collide with the copy it is meant to supersede.
        """
        seen = [c.generation for c in self._both() if c is not None]
        return max([at_least, *seen], default=0) + 1

    def _from_keyring(self) -> str | None:
        ring = self._keyring()
        if ring is None:
            return None
        try:
            return ring.get_password(_SERVICE, self._profile)
        except Exception:
            return None

    def save(self, credentials: Credentials, *, announce: bool = False) -> None:
        """Persist a pair, stamped one generation above anything already stored.

        Mutates the argument rather than copying it: the caller holds this object
        as its in-memory view of the session, and a stored generation the caller
        does not know about is a second source of truth waiting to disagree.
        """
        credentials.generation = self._next_generation(at_least=credentials.generation)
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
