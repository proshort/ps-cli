"""Credential storage and the lock that keeps two commands from losing the grant."""
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import ClassVar

import pytest

from proshort_cli.errors import EXIT_USAGE, CliError, KeychainUnavailable
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
        # complete value -- never an empty or partial one. Only the credential
        # file matters here; `save` also renames the sequence file.
        if Path(dst) == store.path:
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

    `generation` decides, not `expires_at` -- see `load`. This comment said
    `expires_at` long after the code stopped using it, which is exactly how the
    next person to "simplify" the comparison would reintroduce the bug.
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


def test_the_newer_pair_wins_even_when_it_expires_sooner(tmp_path, monkeypatch):
    """The hole in the first version of the dual-store fix.

    It compared `expires_at`, reasoning that a refresh sets it from the clock so
    the later one must be the newer pair. That is a coincidence, not an
    invariant: `expires_at` says when the *access token* dies. Step the clock
    back between two saves, or shorten `expires_in`, and the newer pair carries
    the smaller number -- so the comparison picks the spent refresh token and the
    family gets revoked, with a passing test suite saying it cannot.

    Nothing in the old dual-store tests ever inverted the two clocks, which is
    why they all passed.
    """
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    store = CredentialStore("test")

    # Written first, and long-lived.
    store.save(_creds(refresh_token="rt_old", expires_at=time.time() + 3600))
    # Written second, and shorter-lived -- the keychain is locked, so it lands in
    # the file and the stale keychain copy cannot be deleted.
    ring.locked = True
    store.save(_creds(refresh_token="rt_new", expires_at=time.time() + 60))
    ring.locked = False

    loaded = CredentialStore("test").load()
    assert loaded is not None
    assert loaded.refresh_token == "rt_new", "recency was decided by expiry, not by write order"


def test_a_profile_cannot_escape_the_config_directory(tmp_path, monkeypatch):
    """`--profile ../../tmp/other` would write a 0600 JSON blob and a lock file
    wherever it pointed -- the same class of bug as the planted temp file this
    module already defends against, and the same check the Skill applies to a
    deal id before putting it in a path.
    """
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path / "cfg"))
    for hostile in ("../other", "../../tmp/other", "a/b", "..", ".", "", "with space", "x\x00y"):
        with pytest.raises(CliError) as caught:
            CredentialStore(hostile)
        assert caught.value.code == EXIT_USAGE, hostile


def test_ordinary_profile_names_still_work(tmp_path, monkeypatch):
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path / "cfg"))
    for good in ("default", "work", "acme-staging", "a.b", "a_b", "Prod2"):
        assert CredentialStore(good).path.name == f"{good}.json"


def test_a_blob_with_the_right_keys_and_wrong_types_is_treated_as_signed_out(tmp_path, monkeypatch):
    """`Credentials(**data)` raises on a missing or extra key and accepts anything
    at all for the values, so `{"expires_at": "soon"}` parsed and then threw a
    TypeError out of `expired()` -- which is exactly what returning None instead
    of raising was supposed to prevent.
    """
    store = _store(tmp_path, monkeypatch)
    store.save(_creds())
    for broken in (
        {"expires_at": "soon"},
        {"scopes": "deals:read"},
        {"access_token": None},
        {"base_url": 12},
        {"generation": "two"},
        {"expires_at": True},
    ):
        blob = asdict(_creds())
        blob.update(broken)
        store.path.write_text(json.dumps(blob), encoding="utf-8")
        assert store.load() is None, broken


def test_a_locked_keychain_does_not_read_as_signed_out(tmp_path, monkeypatch):
    """The path that actually happens on a Mac.

    A successful keychain write deletes the file, so on the happy path the
    keychain is the only copy. Treating "locked" as "empty" therefore reported a
    signed-in user as signed out and sent them to `proshort login` to fix a
    keychain problem -- which is both the wrong instruction and the start of the
    generation loss below.
    """
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    store = CredentialStore("test")
    store.save(_creds(refresh_token="rt_live"))
    assert not store.path.exists(), "precondition: the keychain holds the only copy"

    ring.locked = True
    with pytest.raises(KeychainUnavailable) as caught:
        store.load()
    assert "keychain" in str(caught.value).lower()
    assert caught.value.hint and "unlock" in caught.value.hint.lower()

    ring.locked = False
    assert store.load().refresh_token == "rt_live"


def test_a_login_while_the_keychain_is_locked_is_not_lost_when_it_unlocks(tmp_path, monkeypatch):
    """The half `at_least` could not cover.

    `at_least` only works when the caller is holding the number to beat, and on a
    locked keychain nobody is: `load` finds nothing, `cmd_login` passes
    `generation=0`, `_next_generation` cannot see the hidden copy either, and the
    new grant is written as generation 1 against a keychain holding 5. On unlock
    the comparison picks the old grant -- so the re-login silently reverts, and a
    narrowed `--scope` or a different user reverts with it.
    """
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    store = CredentialStore("test")
    for n in range(5):
        store.save(_creds(refresh_token=f"rt_{n}"))
    hidden = json.loads(ring.stored["test"])["generation"]
    assert hidden == 5 and not store.path.exists()

    ring.locked = True
    store.save(_creds(refresh_token="rt_after_relogin"))
    written = json.loads(store.path.read_text())["generation"]
    assert written > hidden, f"new grant written as {written} against a hidden {hidden}"

    ring.locked = False
    assert CredentialStore("test").load().refresh_token == "rt_after_relogin"


def test_a_keychain_that_cannot_be_cleared_is_not_reported_as_signed_out(tmp_path, monkeypatch):
    """A locked keychain refuses `delete_password` exactly as it refuses
    `set_password`, so "signed out" was printed over a credential that comes back
    on unlock."""
    monkeypatch.setenv("PROSHORT_CONFIG_DIR", str(tmp_path))
    ring = _LockableRing()
    monkeypatch.setattr(CredentialStore, "_keyring", lambda self: ring)
    store = CredentialStore("test")
    store.save(_creds())

    ring.locked = True
    assert store.clear() is False
    ring.locked = False
    assert store.clear() is True


def test_a_scopes_list_of_non_strings_is_treated_as_corrupt(tmp_path, monkeypatch):
    """`list` alone lets `[1, 2]` through, and `" ".join(...)` on it is a traceback
    several commands later -- the same standard already applied to `expires_at`."""
    store = _store(tmp_path, monkeypatch)
    store.save(_creds())
    blob = asdict(_creds())
    blob["scopes"] = [1, 2]
    store.path.write_text(json.dumps(blob), encoding="utf-8")
    assert store.load() is None
