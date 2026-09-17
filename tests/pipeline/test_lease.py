"""Tests for nexus_pipeline.containment.lease (spec section 6.2).

Covers fresh acquire, double-acquire blocked, expired reclaim, a genuine
concurrent-reclaim race with a single winner (forced deterministically, not
a probabilistic thread race), release, renew, and fail-closed behavior when
the lease store itself is unreadable/uncreatable.

The read-check-write critical section for acquire/renew/release is
serialized per-issue by an advisory flock on a lockfile (see
nexus_pipeline.containment.lease._issue_lock). This replaces an earlier
marker-file compare-and-swap design that had both a genuine TOCTOU window
(an owner's renew() could land between a reclaimer's re-check and its
os.replace, producing two simultaneous holders) and an orphan-marker DoS if
a process crashed mid-reclaim. The flock closes the TOCTOU window entirely
(the whole read-check-write happens atomically under one lock) and cannot be
orphaned by a crash (the OS releases flock locks when the holding process's
file descriptors are closed, including on SIGKILL).
"""

import threading
import time

import pytest

from nexus_pipeline.containment import lease
from nexus_pipeline.state import paths


@pytest.fixture(autouse=True)
def isolated_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(tmp_path / "state"))


def test_fresh_acquire_succeeds():
    result = lease.acquire("SFE-1", "worker-a", ttl_s=60)

    assert isinstance(result, lease.Lease)
    assert result.issue_id == "SFE-1"
    assert result.owner_id == "worker-a"


def test_double_acquire_blocked_by_valid_lease():
    lease.acquire("SFE-1", "worker-a", ttl_s=60)

    result = lease.acquire("SFE-1", "worker-b", ttl_s=60)

    assert result is None


def test_expired_lease_is_reclaimed():
    lease.acquire("SFE-1", "worker-a", ttl_s=-1)  # already expired

    result = lease.acquire("SFE-1", "worker-b", ttl_s=60)

    assert isinstance(result, lease.Lease)
    assert result.owner_id == "worker-b"


def test_concurrent_acquire_serializes_deterministically(monkeypatch):
    """Forces the exact interleaving a broken/removed lock would need to
    produce a double-winner. Thread A is paused (via an injected delay)
    inside its own critical section, after deciding to reclaim but before
    writing. Thread B is then started and given a generous window to run.

    This is deterministic, not probabilistic: if the per-issue flock is
    doing its job, thread B cannot even begin its own critical section
    until thread A's finishes (including the injected delay), so B is
    still alive (blocked) at the 0.3s checkpoint on every single run. A
    mutation that removes the lock lets B race ahead immediately, which
    fails the `is_alive()` assertion deterministically -- not ~7% of the
    time like the old real-thread race test.
    """
    lease.acquire("SFE-1", "original-owner", ttl_s=-1)  # already expired

    thread_a_in_critical_section = threading.Event()
    allow_thread_a_to_finish = threading.Event()
    real_write_lease = lease._write_lease

    def delayed_write_lease(path, candidate):
        # Deliberately no assert in here: this runs in a background thread,
        # and an assertion failing there reports asynchronously (and slowly,
        # via pytest's thread-exception hook) instead of failing the test
        # immediately at the intended checkpoint below. A short, ungated
        # wait is enough to force the interleaving window.
        if candidate.owner_id == "thread-a":
            thread_a_in_critical_section.set()
            allow_thread_a_to_finish.wait(timeout=2)
        real_write_lease(path, candidate)

    monkeypatch.setattr(lease, "_write_lease", delayed_write_lease)

    results: dict[str, lease.Lease | None] = {}

    def run_a():
        results["a"] = lease.acquire("SFE-1", "thread-a", ttl_s=60)

    def run_b():
        results["b"] = lease.acquire("SFE-1", "thread-b", ttl_s=60)

    thread_a = threading.Thread(target=run_a)
    thread_a.start()
    assert thread_a_in_critical_section.wait(timeout=5)

    thread_b = threading.Thread(target=run_b)
    thread_b.start()
    thread_b.join(timeout=0.3)
    # The single load-bearing assertion: if the per-issue lock is broken or
    # removed, B races ahead and finishes within the 0.3s window, so this
    # fails immediately and deterministically in the main thread.
    assert thread_b.is_alive(), "thread B was not blocked by thread A's held lock"

    allow_thread_a_to_finish.set()
    thread_a.join(timeout=5)
    thread_b.join(timeout=5)
    assert not thread_a.is_alive()
    assert not thread_b.is_alive()

    assert results["a"].owner_id == "thread-a"
    assert results["b"] is None  # B must see A's fresh, non-expired lease


def test_release_frees_the_lease_for_the_next_acquirer():
    held = lease.acquire("SFE-1", "worker-a", ttl_s=60)

    lease.release(held)

    result = lease.acquire("SFE-1", "worker-b", ttl_s=60)
    assert isinstance(result, lease.Lease)


def test_release_does_not_remove_a_lease_it_does_not_own():
    lease.acquire("SFE-1", "worker-a", ttl_s=60)
    foreign = lease.Lease(
        issue_id="SFE-1", owner_id="worker-b", expiry_ts=time.time() + 60
    )

    lease.release(foreign)

    result = lease.acquire("SFE-1", "worker-c", ttl_s=60)
    assert result is None  # worker-a's lease is still held


def test_release_is_a_noop_when_the_lease_file_never_existed():
    ghost = lease.Lease(
        issue_id="SFE-1", owner_id="worker-a", expiry_ts=time.time() + 60
    )

    lease.release(ghost)  # must not raise


def test_renew_extends_expiry_and_keeps_ownership():
    held = lease.acquire("SFE-1", "worker-a", ttl_s=1)

    renewed = lease.renew(held, ttl_s=3600)

    assert renewed.owner_id == "worker-a"
    assert renewed.expiry_ts > held.expiry_ts
    # Nobody else can acquire it now that it is renewed far into the future.
    assert lease.acquire("SFE-1", "worker-b", ttl_s=60) is None


def test_renew_rejects_a_lease_it_does_not_own():
    lease.acquire("SFE-1", "worker-a", ttl_s=60)
    foreign = lease.Lease(
        issue_id="SFE-1", owner_id="worker-b", expiry_ts=time.time() + 60
    )

    with pytest.raises(lease.LeaseOwnershipError):
        lease.renew(foreign, ttl_s=60)


def test_renew_wraps_a_vanished_lease_as_store_error():
    held = lease.acquire("SFE-1", "worker-a", ttl_s=60)
    lease._lease_path("SFE-1").unlink()  # simulate a concurrent release/vanish

    with pytest.raises(lease.LeaseStoreError):
        lease.renew(held, ttl_s=60)


def test_store_uncreatable_fails_closed(tmp_path, monkeypatch):
    state_dir = tmp_path / "state2"
    state_dir.mkdir(mode=0o700)
    (state_dir / "leases").write_text("not a directory")
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(state_dir))

    with pytest.raises(lease.LeaseStoreError):
        lease.acquire("SFE-1", "worker-a", ttl_s=60)


def test_corrupt_lease_file_fails_closed(tmp_path, monkeypatch):
    state_dir = tmp_path / "state3"
    state_dir.mkdir(mode=0o700)
    leases_dir = state_dir / "leases"
    leases_dir.mkdir(mode=0o700)
    (leases_dir / "SFE-1.json").write_text("{not valid json")
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(state_dir))

    with pytest.raises(lease.LeaseStoreError):
        lease.acquire("SFE-1", "worker-a", ttl_s=60)


def test_unwritable_leases_dir_fails_closed(tmp_path, monkeypatch):
    state_dir = tmp_path / "state4"
    state_dir.mkdir(mode=0o700)
    leases_dir = state_dir / "leases"
    leases_dir.mkdir(mode=0o500)  # read + execute only: cannot create entries
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(state_dir))

    with pytest.raises(lease.LeaseStoreError):
        lease.acquire("SFE-1", "worker-a", ttl_s=60)


def test_write_lease_wraps_write_failure_and_cleans_up_temp_file(tmp_path, monkeypatch):
    state_dir = tmp_path / "state5"
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(state_dir))

    def _boom_replace(*args, **kwargs):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(lease.os, "replace", _boom_replace)

    with pytest.raises(lease.LeaseStoreError):
        lease.acquire("SFE-1", "worker-a", ttl_s=60)

    leases_dir = state_dir / "leases"
    assert list(leases_dir.glob("SFE-1.json.tmp-*")) == []


def test_unreadable_lease_file_fails_closed(tmp_path, monkeypatch):
    state_dir = tmp_path / "state6"
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(state_dir))
    lease.acquire("SFE-1", "worker-a", ttl_s=60)
    lease_file = state_dir / "leases" / "SFE-1.json"
    lease_file.chmod(0o000)

    try:
        with pytest.raises(lease.LeaseStoreError):
            lease.acquire("SFE-1", "worker-b", ttl_s=60)
    finally:
        lease_file.chmod(0o600)


def test_acquire_rejects_path_traversal_issue_id():
    with pytest.raises(paths.UnsafePathComponentError):
        lease.acquire("../../../../../../tmp/pwned-lease", "attacker", ttl_s=60)

    # Hermetic no-write proof: safe_component raises before any path is built,
    # so nothing is created in the isolated lease store. Do NOT assert on a
    # global path like /tmp/pwned-lease.json -- that is not hermetic and
    # false-fails if another process (e.g. a mutation-test run) left an
    # artifact there.
    leases = paths.state_dir() / "leases"
    assert not leases.exists() or not any(leases.iterdir())


def test_acquire_rejects_absolute_path_issue_id():
    with pytest.raises(paths.UnsafePathComponentError):
        lease.acquire("/tmp/pwned-abs-lease", "attacker", ttl_s=60)
