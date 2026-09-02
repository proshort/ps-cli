"""Credential storage and the lock that keeps two commands from losing the grant."""
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import ClassVar

from proshort_cli.store import Credentials, CredentialStore


def _creds(**over) -> Credentials:
    base = {
        "access_token": "psmcp_at_x",
        "refresh_token": "psmcp_rt_x",
        "expires_at": time.time() + 600,
        "scopes": ["deals:read"],
        "base_url": "https://example.invalid",
        "client_id": "proshort-cli",
    }
    base.update(over)
    return Credentials(**base)


def _store(tmp_path, monkeypatch) -> CredentialStore:
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    # Patched on the class, so a test that builds a second store -- which is how
    # a real second process is simulated -- cannot reach the developer's own
    # keychain and read, or delete, credentials they actually use.
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    return CredentialStore("test")


def test_the_file_is_never_world_readable(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    store.save(_creds())
    mode = os.stat(store.path).st_mode & 0o777
    assert mode == 0o600, f"credential file is {oct(mode)}"


def test_a_round_trip_preserves_everything(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    original = _creds()
    store.save(original)
    assert store.load() == original


def test_a_corrupt_file_reads_as_signed_out_rather_than_crashing(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    store.save(_creds())
    store.path.write_text("{not json", encoding="utf-8")
    assert store.load() is None


def test_expiry_is_checked_early_enough_to_survive_the_flight(tmp_path, monkeypatch):
    """A token that dies in transit is a 401 the user did not need to see."""
    assert _creds(expires_at=time.time() + 5).expired() is True
    assert _creds(expires_at=time.time() + 600).expired() is False


def test_the_lock_actually_excludes_another_process(tmp_path, monkeypatch):
    """The whole point: two commands must not both spend the same refresh token.

    Driven with a real second process, because a same-process `flock` on a second
    descriptor would succeed and prove nothing.
    """
    store = _store(tmp_path, monkeypatch)
    store.save(_creds())

    probe = (
        "import os,sys,fcntl\n"
        f"fd=os.open({str(store._lock_path)!r}, os.O_RDWR|os.O_CREAT, 0o600)\n"
        "try:\n"
        "    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
        "    print('acquired')\n"
        "except BlockingIOError:\n"
        "    print('blocked')\n"
    )
    with store.refresh_lock():
        held = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    free = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)

    assert held.stdout.strip() == "blocked"
    assert free.stdout.strip() == "acquired"


def test_saving_to_the_keychain_removes_any_earlier_file_copy(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    store.save(_creds())
    assert store.path.exists()

    class _Ring:
        stored: ClassVar[dict] = {}

        def set_password(self, service, user, value):
            self.stored[user] = value

        def get_password(self, service, user):
            return self.stored.get(user)

        def delete_password(self, service, user):
            self.stored.pop(user, None)

    ring = _Ring()
    monkeypatch.setattr(store, "_keyring", lambda: ring)
    store.save(_creds(access_token="psmcp_at_new"))
    assert not store.path.exists(), "the token must not survive on disk once the keychain has it"
    assert json.loads(ring.stored["test"])["access_token"] == "psmcp_at_new"


def test_the_credential_write_is_atomic(tmp_path, monkeypatch):
    """A reader must never see a half-written or empty file.

    `Client.__init__` calls `load()` outside the refresh lock, so a truncate-then-write
    left a window where a concurrent command read an empty file and reported the
    user as signed out.
    """
    store = _store(tmp_path, monkeypatch)
    store.save(_creds(access_token="psmcp_at_first"))

    seen: list[str] = []
    real_replace = os.replace

    def watched(src, dst):
        # At the moment of the rename the destination still holds the old,
        # complete value -- never an empty or partial one.
        seen.append(Path(dst).read_text(encoding="utf-8"))
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", watched)
    store.save(_creds(access_token="psmcp_at_second"))

    assert seen and "psmcp_at_first" in seen[0]
    assert store.load().access_token == "psmcp_at_second"
    assert not list(tmp_path.glob("*.tmp")), "the temp file must not survive"


# ----------------------------------------------- which store is authoritative


class _LockableRing:
    """A keychain that can be made to refuse writes, which is what macOS does."""

    def __init__(self) -> None:
        self.stored: dict[str, str] = {}
        self.locked = False

    def set_password(self, service, user, value):
        if self.locked:
            raise RuntimeError("keychain is locked")
        self.stored[user] = value

    def get_password(self, service, user):
        if self.locked:
            raise RuntimeError("keychain is locked")
        return self.stored.get(user)

    def delete_password(self, service, user):
        if self.locked:
            raise RuntimeError("keychain is locked")
        self.stored.pop(user, None)


def test_a_failed_keychain_write_does_not_resurrect_the_previous_token(tmp_path, monkeypatch):
    """The sequence that revokes a user's whole grant for no reason.

    A refresh succeeds and the server rotates the pair. `set_password` fails, so
    the new pair lands in the file. The keychain unlocks; the next command reads
    it and finds the *old* refresh token, presents it, and the server does
    exactly what it is designed to do about a spent one.

    The refresh lock cannot help -- both processes agree on the same stale value.
    """
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    store = CredentialStore("test")

    store.save(_creds(access_token="at_old", refresh_token="rt_old", expires_at=time.time() + 100))
    assert ring.stored, "precondition: the keychain holds the first pair"

    ring.locked = True
    store.save(_creds(access_token="at_new", refresh_token="rt_new", expires_at=time.time() + 600))
    ring.locked = False

    loaded = CredentialStore("test").load()
    assert loaded is not None
    assert loaded.refresh_token == "rt_new", "a spent refresh token was handed back"


def test_the_newer_pair_wins_when_both_stores_hold_one(tmp_path, monkeypatch):
    """The belt to the braces above: the same locked keychain that refuses the
    write refuses the delete, so `load` cannot rely on the delete having run.
    `expires_at` decides, because every refresh sets it from the clock.
    """
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    store = CredentialStore("test")

    # An older pair in the keychain, a newer one in the file, and neither store
    # able to clean the other up.
    ring.stored["test"] = json.dumps(asdict(_creds(refresh_token="rt_old", expires_at=time.time() + 60)))
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    store.save(_creds(refresh_token="rt_new", expires_at=time.time() + 900))
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)

    loaded = store.load()
    assert loaded is not None and loaded.refresh_token == "rt_new"


def test_a_corrupt_copy_does_not_shadow_a_good_one(tmp_path, monkeypatch):
    """One `raw` shared between both sources meant a corrupt keychain blob
    reported the user as signed out while a perfectly good file sat next to it."""
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: None)
    store = CredentialStore("test")
    store.save(_creds(refresh_token="rt_good"))

    ring.stored["test"] = "{not json at all"
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    loaded = store.load()
    assert loaded is not None and loaded.refresh_token == "rt_good"


def test_a_planted_temp_file_cannot_become_the_credential_file(tmp_path, monkeypatch):
    """`os.open(..., O_CREAT)` applies its mode only when it *creates* the file.

    A world-readable `{profile}.tmp` left in a shared `PROSHORT_CONFIG_DIR` -- or
    by a killed process -- would otherwise be written to at its own mode and then
    renamed over the real credential file.
    """
    store = _store(tmp_path, monkeypatch)
    planted = tmp_path / "test.tmp"
    planted.write_text("{}")
    planted.chmod(0o666)

    store.save(_creds())

    assert os.stat(store.path).st_mode & 0o777 == 0o600
    assert not planted.exists() or os.stat(planted).st_mode & 0o777 == 0o666
