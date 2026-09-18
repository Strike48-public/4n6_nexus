"""Tests for the detached background-job runner (SFE-eiqz).

The runner decouples slow mechanical forensic tools (Volatility on a 4GB image,
Plaso timelines) from the interactive MCP session: ``start_job`` spawns a
DETACHED worker and returns a ``job_id`` immediately; the worker reads its real
arguments from a 0o600 payload file (so evidence paths never appear on the
process command line) and writes status transitions to a JSON state file that
``poll_job`` / ``load_results`` read back later.

These tests pin down the three contracts:

  1. SECURITY: sensitive args live in a 0o600 payload file and are ABSENT from
     the spawned worker's argv (only the non-sensitive job dir is passed).
  2. STATE MACHINE: staging -> running -> complete (and -> failed), each
     transition persisted atomically.
  3. FAST START: start_job spawns-and-returns without waiting; poll/load read
     committed state.

RED-first: sift_find_evil/mcp/jobs.py does not exist yet.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from sift_find_evil.mcp.jobs import (
    JobRunner,
    JobState,
    JobStore,
)


# -- JobStore: pure state + payload persistence (no subprocess) --------------


def test_new_job_starts_in_staging(tmp_path):
    store = JobStore(root=tmp_path)
    record = store.create(command="volatility", args=["-f", "/evidence/mem.dmp"])
    assert record.state is JobState.STAGING
    assert record.job_id
    # The job dir exists and is scoped under the store root.
    job_dir = store.job_dir(record.job_id)
    assert job_dir.is_dir()
    assert job_dir.parent == tmp_path


def test_payload_written_0600_and_holds_the_real_args(tmp_path):
    store = JobStore(root=tmp_path)
    secret_args = ["-f", "/cases/evidence/secret_victim.dmp", "windows.pslist"]
    record = store.create(command="volatility", args=secret_args)

    payload_path = store.payload_path(record.job_id)
    assert payload_path.is_file()
    # 0o600: owner read/write only -- the payload carries evidence paths.
    mode = stat.S_IMODE(payload_path.stat().st_mode)
    assert mode == 0o600, f"payload must be 0o600, got {oct(mode)}"

    payload = json.loads(payload_path.read_text())
    assert payload["command"] == "volatility"
    assert payload["args"] == secret_args


def test_state_transitions_are_persisted_and_readable(tmp_path):
    store = JobStore(root=tmp_path)
    record = store.create(command="plaso", args=["image.dd"])

    store.mark_running(record.job_id, pid=4242)
    reread = store.read(record.job_id)
    assert reread.state is JobState.RUNNING
    assert reread.pid == 4242

    store.mark_complete(record.job_id, exit_code=0, result={"events": 5})
    done = store.read(record.job_id)
    assert done.state is JobState.COMPLETE
    assert done.exit_code == 0
    assert done.result == {"events": 5}


def test_failure_transition_records_nonzero_exit(tmp_path):
    store = JobStore(root=tmp_path)
    record = store.create(command="volatility", args=["-f", "x"])
    store.mark_running(record.job_id, pid=99)
    store.mark_failed(record.job_id, exit_code=1, error="tool crashed")

    failed = store.read(record.job_id)
    assert failed.state is JobState.FAILED
    assert failed.exit_code == 1
    assert failed.error == "tool crashed"


def test_state_file_is_written_atomically(tmp_path):
    """No .tmp residue after a transition (tmp-then-replace, like the ledger)."""
    store = JobStore(root=tmp_path)
    record = store.create(command="tsk", args=["x"])
    store.mark_running(record.job_id, pid=1)
    job_dir = store.job_dir(record.job_id)
    assert not list(job_dir.glob("*.tmp")), "atomic write left a .tmp file behind"


def test_read_unknown_job_raises(tmp_path):
    store = JobStore(root=tmp_path)
    with pytest.raises(KeyError):
        store.read("nonexistent-job-id")


def test_concurrent_writes_and_reads_never_corrupt_state(tmp_path):
    """Regression for SFE-g5js: a job's state file has TWO concurrent writers.

    The parent (``start_job`` -> ``mark_running``) and the detached worker
    (``mark_complete``/``mark_failed``) both write the same ``state.json`` and
    race for a fast tool. When ``_write_state`` used a fixed ``state.json.tmp``
    they clobbered each other's tmp, so ``os.replace`` could publish a truncated/
    empty file and a concurrent ``read`` raised ``JSONDecodeError`` (the flaky
    ``JSONDecodeError: Expecting value: line 1 column 1 (char 0)`` seen on CI).

    Hammer the same job with concurrent writers and readers; every read must
    return a valid record and no write may raise. Pre-fix this fails with
    thousands of JSONDecodeErrors; post-fix (per-writer tmp + bounded read
    retry) it is clean.
    """
    import threading

    store = JobStore(root=tmp_path)
    job_id = store.create(command="sleep", args=["evidence"]).job_id
    errors: list[str] = []

    def writer(mark_running: bool) -> None:
        for _ in range(300):
            try:
                if mark_running:
                    store.mark_running(job_id, pid=1234)
                else:
                    store.mark_complete(job_id, exit_code=0, result={"ok": True})
            except Exception as exc:  # noqa: BLE001 - the test asserts on this
                errors.append(f"write: {exc!r}")

    def reader() -> None:
        for _ in range(1200):
            try:
                store.read(job_id)
            except Exception as exc:  # noqa: BLE001 - the test asserts on this
                errors.append(f"read: {exc!r}")

    threads = [
        threading.Thread(target=writer, args=(True,)),
        threading.Thread(target=writer, args=(False,)),
        threading.Thread(target=reader),
        threading.Thread(target=reader),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent access corrupted job state: {errors[:5]}"
    # And no tmp residue from any of the racing writers.
    assert not list(store.job_dir(job_id).glob("*.tmp"))


# -- terminal state is absorbing (SFE-wqm1) ----------------------------------


def test_mark_running_cannot_revert_a_terminal_job(tmp_path):
    """Regression for SFE-wqm1: the monotonic guard makes a terminal state win.

    Once a job is COMPLETE (or FAILED) a later ``mark_running`` -- e.g. the
    parent's post-spawn call arriving after a fast worker already finished --
    must be a no-op, not a revert to RUNNING that loses the result and strands
    the job. ``_transition`` refuses any backward move and returns the
    already-committed terminal record.
    """
    store = JobStore(root=tmp_path)
    rec = store.create(command="vol", args=["-f", "x"])
    store.mark_complete(rec.job_id, exit_code=0, result={"ok": True})

    returned = store.mark_running(rec.job_id, pid=999)

    assert returned.state is JobState.COMPLETE
    reread = store.read(rec.job_id)
    assert reread.state is JobState.COMPLETE
    assert reread.result == {"ok": True}, "the fast worker's result was lost"

    # A FAILED job is likewise absorbing -- mark_running cannot resurrect it.
    rec2 = store.create(command="vol", args=["-f", "y"])
    store.mark_failed(rec2.job_id, exit_code=1, error="boom")
    store.mark_running(rec2.job_id, pid=1)
    assert store.read(rec2.job_id).state is JobState.FAILED


def test_fast_worker_completion_survives_parent_mark_running(tmp_path):
    """Regression for SFE-wqm1: start_job spawns the worker BEFORE mark_running.

    ``JobRunner.start_job`` forks the detached worker and only then calls
    ``mark_running`` with its pid. A sub-second tool can drive the job to a
    terminal state inside that window. Pre-fix, the parent's bare
    read-modify-write reverted COMPLETE -> RUNNING, losing the result and
    stranding the job as RUNNING forever (the worker is already dead, so nothing
    moves it terminal again). Here the injected spawn fn stands in for that
    instant worker.
    """
    store = JobStore(root=tmp_path)

    def instant_worker_spawn(argv, **kwargs):
        # argv == [python, -m, <worker_module>, <job_id>, <root>]. The detached
        # worker wins the race: mark the job complete before start_job returns
        # from spawn and calls mark_running.
        job_id = argv[3]
        store.mark_complete(job_id, exit_code=0, result={"rows": 7})
        return 4242

    runner = JobRunner(store=store, spawn=instant_worker_spawn)
    job_id = runner.start_job(command="vol", args=["-f", "x"])

    record = store.read(job_id)
    assert (
        record.state is JobState.COMPLETE
    ), f"fast worker's COMPLETE was clobbered to {record.state.value}"
    assert record.result == {"rows": 7}
    assert record.exit_code == 0


def test_terminal_state_wins_under_concurrent_mark_running(tmp_path):
    """Regression for SFE-wqm1 (TOCTOU facet): the per-job lock + guard together.

    Drives the exact interleaving ``start_job`` creates: for many jobs, one
    thread marks the job complete (the fast worker) while another calls
    ``mark_running`` (the parent, post-spawn), released together on a barrier so
    they genuinely race the read-modify-write. The exclusive per-job lock
    serializes the critical section so the guard always sees the latest committed
    state and refuses the backward move -- every job settles COMPLETE, never
    stranded RUNNING. Pre-fix (bare read-modify-write, no lock, no guard) a
    fraction revert to RUNNING.
    """
    import threading

    store = JobStore(root=tmp_path)
    stranded: list[tuple[str, str]] = []
    n_jobs = 200
    for i in range(n_jobs):
        job_id = store.create(command="vol", args=[f"-f=j{i}"]).job_id
        barrier = threading.Barrier(2)

        def worker() -> None:
            barrier.wait()
            store.mark_complete(job_id, exit_code=0, result={"i": i})

        def parent() -> None:
            barrier.wait()
            store.mark_running(job_id, pid=100 + i)

        tw = threading.Thread(target=worker)
        tp = threading.Thread(target=parent)
        tw.start()
        tp.start()
        tw.join()
        tp.join()

        final = store.read(job_id).state
        if final is not JobState.COMPLETE:
            stranded.append((job_id, final.value))

    assert (
        not stranded
    ), f"{len(stranded)}/{n_jobs} jobs stranded non-COMPLETE: {stranded[:5]}"


# -- JobRunner.start_job: the argv shape (security contract) -----------------


def _capture_spawner():
    """A fake spawn fn that records argv/kwargs instead of forking a process."""
    calls: list[dict] = []

    def spawn(argv, **kwargs):
        calls.append({"argv": list(argv), "kwargs": kwargs})
        return 31337  # a fake pid

    return spawn, calls


def test_start_job_returns_id_without_blocking(tmp_path):
    spawn, calls = _capture_spawner()
    runner = JobRunner(store=JobStore(root=tmp_path), spawn=spawn)
    job_id = runner.start_job(command="volatility", args=["-f", "/e/mem.dmp"])
    assert job_id
    # Exactly one detached process was spawned.
    assert len(calls) == 1


def test_sensitive_args_are_absent_from_worker_argv(tmp_path):
    """The core security guarantee: evidence paths never hit the command line."""
    spawn, calls = _capture_spawner()
    runner = JobRunner(store=JobStore(root=tmp_path), spawn=spawn)
    secret = "/cases/evidence/victim_disk_secret_name.E01"
    job_id = runner.start_job(command="volatility", args=["-f", secret, "pslist"])

    argv = calls[0]["argv"]
    flat = " ".join(argv)
    assert secret not in flat, "evidence path leaked onto the worker command line"
    assert "pslist" not in flat, "a tool arg leaked onto the worker command line"
    assert "volatility" not in argv, "the wrapped command leaked onto the argv"
    # The job id (non-sensitive) is the handle the worker gets to find its payload.
    assert job_id in flat


def test_worker_is_spawned_detached(tmp_path):
    """The spawn must request a new session so the child outlives the caller."""
    spawn, calls = _capture_spawner()
    runner = JobRunner(store=JobStore(root=tmp_path), spawn=spawn)
    runner.start_job(command="plaso", args=["image.dd"])
    kwargs = calls[0]["kwargs"]
    assert kwargs.get("start_new_session") is True


def test_start_job_records_pid_and_running_after_spawn(tmp_path):
    spawn, _ = _capture_spawner()
    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store, spawn=spawn)
    job_id = runner.start_job(command="volatility", args=["-f", "x"])
    # After a successful spawn the job is running with the spawner's pid.
    record = store.read(job_id)
    assert record.state is JobState.RUNNING
    assert record.pid == 31337


def test_poll_and_load_results_round_trip(tmp_path):
    spawn, _ = _capture_spawner()
    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store, spawn=spawn)
    job_id = runner.start_job(command="vol", args=["-f", "x"])

    assert runner.poll_job(job_id).state is JobState.RUNNING
    # The worker (simulated here) finishes and writes its result.
    store.mark_complete(job_id, exit_code=0, result={"rows": 3})
    assert runner.poll_job(job_id).state is JobState.COMPLETE
    assert runner.load_results(job_id) == {"rows": 3}


def test_load_results_before_completion_raises(tmp_path):
    spawn, _ = _capture_spawner()
    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store, spawn=spawn)
    job_id = runner.start_job(command="vol", args=["-f", "x"])
    with pytest.raises(ValueError):
        runner.load_results(job_id)  # still running -> no results yet


# -- reconcile marker + retention (SFE-dup8) --------------------------------


def test_reconcile_marker_is_durable_and_idempotent(tmp_path):
    store = JobStore(root=tmp_path)
    record = store.create(command="vol", args=["-f", "x"])
    assert store.is_reconciled(record.job_id) is False
    store.mark_reconciled(record.job_id)
    assert store.is_reconciled(record.job_id) is True
    # A second mark is harmless (idempotent) and the marker persists.
    store.mark_reconciled(record.job_id)
    assert JobStore(root=tmp_path).is_reconciled(record.job_id) is True


def test_prune_reconciled_keeps_newest_and_never_touches_unreconciled(tmp_path):
    store = JobStore(root=tmp_path)
    ids = []
    for i in range(5):
        rec = store.create(command="vol", args=[f"-f=job{i}"])
        store.mark_reconciled(rec.job_id)
        # Force a strictly increasing MARKER mtime so "oldest reconciled first" is
        # deterministic (prune_reconciled sorts by the marker's mtime).
        marker = store._reconciled_path(rec.job_id)
        os.utime(marker, (1_700_000_000 + i, 1_700_000_000 + i))
        ids.append(rec.job_id)
    # An unreconciled job must survive pruning regardless of keep_last.
    unreconciled = store.create(command="vol", args=["-f=keep-me"])

    pruned = store.prune_reconciled(keep_last=2)

    assert set(pruned) == set(ids[:3]), "the 3 oldest reconciled jobs are pruned"
    for gone in ids[:3]:
        assert not store.job_dir(gone).exists()
    for kept in ids[3:]:
        assert store.job_dir(kept).exists()
    assert store.job_dir(unreconciled.job_id).exists(), "unreconciled job preserved"


def test_prune_reconciled_on_missing_root_is_noop(tmp_path):
    store = JobStore(root=tmp_path / "does-not-exist")
    assert store.prune_reconciled() == []


def test_try_mark_reconciled_is_atomic_win_once(tmp_path):
    store = JobStore(root=tmp_path)
    rec = store.create(command="vol", args=["-f", "x"])
    # First caller wins the atomic create; the second loses (marker already there).
    assert store.try_mark_reconciled(rec.job_id) is True
    assert store.try_mark_reconciled(rec.job_id) is False
    assert store.is_reconciled(rec.job_id) is True
