"""Credential storage and the lock that keeps two commands from losing the grant."""
import json
import os
import subprocess
import sys
import time
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
    store = CredentialStore("test")
    monkeypatch.setattr(store, "_keyring", lambda: None)  # force the file path
    return store


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
