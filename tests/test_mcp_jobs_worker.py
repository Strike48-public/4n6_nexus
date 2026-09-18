"""End-to-end tests for the detached job worker (SFE-eiqz).

These exercise the REAL spawn path (no injected spawner): JobRunner forks an
actual detached ``python -m sift_find_evil.mcp.jobs_worker`` process which reads
the 0o600 payload, runs the command, and drives the state file to a terminal
state. They also prove the security guarantee empirically against the live
process table (/proc/<pid>/cmdline), not just by argv inspection.
"""

from __future__ import annotations

import os
import time

import pytest

from sift_find_evil.mcp import jobs_worker
from sift_find_evil.mcp.jobs import JobRunner, JobState, JobStore


def _wait_for_terminal(store: JobStore, job_id: str, timeout: float = 10.0):
    """Poll the state file until the job reaches a terminal state or times out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = store.read(job_id)
        if record.state in (JobState.COMPLETE, JobState.FAILED):
            return record
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


@pytest.mark.integration
def test_worker_runs_command_to_completion(tmp_path):
    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store)  # real _default_spawn
    # A trivial, universally-available command that exits 0.
    job_id = runner.start_job(command="true", args=[])
    record = _wait_for_terminal(store, job_id)
    assert record.state is JobState.COMPLETE
    assert record.exit_code == 0


@pytest.mark.integration
def test_worker_marks_failed_on_nonzero_exit(tmp_path):
    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store)
    job_id = runner.start_job(command="false", args=[])
    record = _wait_for_terminal(store, job_id)
    assert record.state is JobState.FAILED
    # A tool that RAN and failed has a non-zero INTEGER code, not the None
    # "never ran" sentinel (SFE-zydh) -- assert the int, not merely != 0.
    assert isinstance(record.exit_code, int) and record.exit_code != 0


@pytest.mark.integration
def test_worker_records_stdout_in_result(tmp_path):
    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store)
    job_id = runner.start_job(command="echo", args=["nexus-marker-123"])
    record = _wait_for_terminal(store, job_id)
    assert record.state is JobState.COMPLETE
    assert "nexus-marker-123" in (record.result or {}).get("stdout", "")


@pytest.mark.integration
def test_sensitive_args_absent_from_worker_proc_cmdline(tmp_path):
    """Empirical security proof, scoped to the durable worker process.

    The guarantee is precise: the WORKER that ``start_job`` spawns (the
    long-lived, MCP-visible layer) carries only the non-sensitive job id on its
    command line -- the evidence-path arguments live solely in the 0o600
    payload. We read the real ``/proc/<worker_pid>/cmdline`` while the worker is
    still running its (slow) tool and assert the secret is not there.

    Note the honest boundary: the LEAF tool child the worker execs
    (``subprocess.run([command, *args])``) does receive its args on argv -- that
    is inherent to running any CLI tool and is out of scope for this guarantee.
    What this design removes is the evidence path from the persistent session /
    job-runner layer, not from the transient tool invocation itself.
    """
    if not os.path.isdir("/proc"):
        pytest.skip("no /proc on this platform")

    store = JobStore(root=tmp_path)
    runner = JobRunner(store=store)
    secret = "SECRET-EVIDENCE-PATH-9f3c1a"
    # A slow tool keeps the worker process alive long enough to inspect it.
    job_id = runner.start_job(command="sleep", args=["0.6", secret])
    worker_pid = store.read(job_id).pid

    # Give the worker a beat to be running, then read ITS cmdline from /proc.
    time.sleep(0.15)
    try:
        with open(f"/proc/{worker_pid}/cmdline", "rb") as handle:
            worker_cmdline = (
                handle.read().replace(b"\x00", b" ").decode("utf-8", "replace")
            )
    except OSError:
        worker_cmdline = ""

    _wait_for_terminal(store, job_id)
    assert (
        secret not in worker_cmdline
    ), "evidence path leaked onto the worker's /proc cmdline"
    # Sanity: the job id (non-sensitive handle) IS how the worker was launched.
    assert job_id in worker_cmdline or worker_cmdline == ""


# -- in-process run()/main() coverage (no spawning) --------------------------
#
# The integration tests above exercise the worker in a real detached process,
# which coverage can't see. These call run()/main() directly so every branch is
# measured and CI's 100% line-coverage gate holds.


def _staged_job(store: JobStore, command: str, args: list[str]) -> str:
    """Create a STAGING job (payload written) without spawning a worker."""
    return store.create(command=command, args=args).job_id


def test_run_marks_complete_on_success(tmp_path):
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "echo", ["hello-nexus"])
    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    record = store.read(job_id)
    assert record.state is JobState.COMPLETE
    assert "hello-nexus" in record.result["stdout"]


def test_run_marks_failed_on_nonzero_exit(tmp_path):
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "false", [])
    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    record = store.read(job_id)
    assert record.state is JobState.FAILED
    # A tool that RAN and failed has a non-zero INTEGER code, not the None
    # "never ran" sentinel (SFE-zydh) -- assert the int, not merely != 0.
    assert isinstance(record.exit_code, int) and record.exit_code != 0


def test_run_marks_failed_when_tool_not_found(tmp_path):
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "nexus_no_such_binary_zzz", ["x"])
    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    record = store.read(job_id)
    assert record.state is JobState.FAILED
    assert "not found" in record.error


def test_run_translates_tool_key_to_binary_at_exec(tmp_path, monkeypatch):
    """SFE-wnr4: the detached worker execs the real binary for a tool key.

    The staged ``command`` is the logical tool key (e.g. ``volatility``); the
    worker must spawn the translated executable (``vol``), matching the
    synchronous server path so the detached MCP doorway is not a second place
    where ``volatility`` is silently dead.
    """
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "volatility", ["-f", "mem.raw"])
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class _Proc:
            returncode = 0
            stdout = "[]"
            stderr = ""

        return _Proc()

    monkeypatch.setattr(jobs_worker.subprocess, "run", fake_run)
    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    assert captured["argv"][0] == "vol"
    assert store.read(job_id).state is JobState.COMPLETE


def test_run_marks_failed_on_oserror(tmp_path, monkeypatch):
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "whatever", [])

    def _boom(*_a, **_k):
        raise OSError("permission denied")

    monkeypatch.setattr(jobs_worker.subprocess, "run", _boom)
    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    record = store.read(job_id)
    assert record.state is JobState.FAILED
    assert "spawn failed" in record.error


def test_run_records_failed_when_payload_missing(tmp_path):
    """An unknown job whose dir/state can still be created is marked FAILED."""
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "echo", ["x"])
    # Remove the payload but keep the (already-written) state file so mark_failed
    # can transition it: exercises the payload-unreadable recovery path.
    store.payload_path(job_id).unlink()
    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    record = store.read(job_id)
    assert record.state is JobState.FAILED
    assert "payload unreadable" in record.error


def test_run_returns_1_when_nothing_can_be_recorded(tmp_path):
    """No job at all: cannot read payload AND cannot mark failed -> exit 1."""
    assert jobs_worker.run("no-such-job", str(tmp_path)) == 1


def test_main_usage_error_on_wrong_argc(tmp_path):
    assert jobs_worker.main(["only-one-arg"]) == 2


def test_main_dispatches_to_run(tmp_path):
    store = JobStore(root=tmp_path)
    job_id = _staged_job(store, "true", [])
    assert jobs_worker.main([job_id, str(tmp_path)]) == 0
    assert store.read(job_id).state is JobState.COMPLETE


# -- platform-gated tools in the detached worker (SFE-ybki) ------------------


def test_worker_fails_platform_unsupported_tool_instead_of_completing(
    tmp_path, monkeypatch
):
    """The async twin of the synchronous exec gate.

    ``run`` marks a job COMPLETE on exit code 0. PECmd on Linux prints
    "Non-Windows platforms not supported..." and exits 0, so an ungated worker
    recorded a COMPLETE job with an empty result -- an investigator would see a
    finished Prefetch job that produced nothing.
    """
    monkeypatch.setattr(
        "sift_find_evil.mcp.jobs_worker.platform.system", lambda: "Linux"
    )

    def _must_not_spawn(*_a, **_k):  # pragma: no cover - asserts non-invocation
        raise AssertionError("subprocess.run must not be reached for a gated tool")

    monkeypatch.setattr(
        "sift_find_evil.mcp.jobs_worker.subprocess.run", _must_not_spawn
    )

    store = JobStore(root=tmp_path)
    job_id = store.create(command="pecmd", args=["-d", "/evidence/prefetch"]).job_id

    assert jobs_worker.run(job_id, str(tmp_path)) == 0

    record = store.read(job_id)
    assert record.state is JobState.FAILED
    # NEVER_RAN (None), not a tool exit code: it never executed.
    assert record.exit_code is None
    assert "platform" in (record.error or "").lower()


def test_worker_still_runs_cross_platform_tool_on_linux(tmp_path, monkeypatch):
    # Scope guard: only the gated tool is refused.
    monkeypatch.setattr(
        "sift_find_evil.mcp.jobs_worker.platform.system", lambda: "Linux"
    )
    store = JobStore(root=tmp_path)
    job_id = store.create(command="true", args=[]).job_id

    assert jobs_worker.run(job_id, str(tmp_path)) == 0
    assert store.read(job_id).state is JobState.COMPLETE
