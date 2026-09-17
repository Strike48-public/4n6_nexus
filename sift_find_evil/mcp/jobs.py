"""Detached background-job runner for long-running forensic tools (SFE-eiqz).

Gallery idea #37 (independently built by ChainsawMCP): decouple slow mechanical
work -- Volatility on a 4GB image, a Plaso timeline, Chainsaw over GBs of logs --
from the interactive MCP session so a tool call never hits the transport timeout.

  * ``JobRunner.start_job`` writes the real arguments to a 0o600 ``payload.json``,
    spawns a DETACHED worker (its own session, stdio to /dev/null), and returns a
    ``job_id`` immediately -- the caller never blocks on the tool.
  * The worker (``sift_find_evil.mcp.jobs_worker``) is handed only the
    non-sensitive job id, reads the payload, and drives the state file
    ``running -> complete|failed``. Because the arguments live in the payload and
    NOT on the command line, evidence paths never appear in ``ps`` /
    ``/proc/<pid>/cmdline`` -- the security guarantee that motivates the design.
  * ``poll_job`` / ``load_results`` read the committed state back later.

The persistence mirrors the sibling primitives (``hypothesis_ledger``,
``loop_control``): frozen records, atomic tmp-then-``os.replace`` writes, and a
schema version stamped into each state file so an old file can never be silently
misread. Job artifacts live under ``exports/jobs/`` (already gitignored), so a
running investigation never leaks intermediate state into git.

Standalone primitive: not yet wired into ``EvidenceMCPServer`` (single-pass /
synchronous today). Wiring -- exposing start/poll/load as MCP tools with the
guardrail boundary applied to the payload rather than the argv -- is a follow-up,
matching how the other self-correction primitives landed.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

# Stamped into every state file. Bump when the on-disk shape changes so an old
# file (a different contract) can never be silently misread.
_SCHEMA_VERSION = "v1"

# Sentinel meaning the tool NEVER RAN (environment failure: spawn failed, tool
# not found, unreadable payload, timeout before exec). It is ``None`` -- the
# ABSENCE of an exit code -- on purpose: a process that actually ran always has
# an integer returncode, INCLUDING a signal death (SIGHUP -> -1, SIGSEGV -> -11),
# so keying "never ran" on ``None`` cannot collide with any real code the way a
# magic negative (e.g. -1, which is also SIGHUP) would. Both the synchronous
# _execute path and the detached worker stamp this for their never-ran cases;
# the circuit breaker treats ONLY this (None) as exempt (SFE-zydh), so a
# ran-and-crashed tool still counts as a failure.
NEVER_RAN_EXIT_CODE = None

# The module a spawned worker runs: ``python -m sift_find_evil.mcp.jobs_worker``.
_WORKER_MODULE = "sift_find_evil.mcp.jobs_worker"

# read() retry budget for the brief window a reader can race a concurrent write
# (SFE-g5js). Small and bounded: ~5 * 5ms = 25ms worst case, which comfortably
# covers an os.replace swap without turning a genuinely corrupt file into a hang.
_READ_RETRIES = 5
_READ_RETRY_BACKOFF_SEC = 0.005

# A spawn function: (argv, **kwargs) -> pid. Injectable so the argv shape is
# unit-testable without forking a real process. The default forks a detached
# subprocess (see :func:`_default_spawn`).
SpawnFn = Callable[..., int]


class JobState(str, Enum):
    """The lifecycle of a background job."""

    STAGING = "staging"  # created; payload written; not yet spawned
    RUNNING = "running"  # worker spawned and executing
    COMPLETE = "complete"  # worker finished with exit code 0
    FAILED = "failed"  # worker finished non-zero, crashed, or errored

    @property
    def is_terminal(self) -> bool:
        """True for the absorbing end states (COMPLETE / FAILED).

        A terminal state is the worker's final verdict and must never be
        reverted -- see the monotonic guard in :meth:`JobStore._transition`.
        """
        return self in (JobState.COMPLETE, JobState.FAILED)


@dataclass(frozen=True)
class JobRecord:
    """A point-in-time snapshot of one job's state (frozen; never mutated).

    Transitions produce a NEW record via :class:`JobStore` write methods, which
    also persist it. ``result`` is populated only on COMPLETE; ``error`` only on
    FAILED.
    """

    job_id: str
    command: str
    args: tuple[str, ...]
    state: JobState
    pid: Optional[int] = None
    exit_code: Optional[int] = None
    result: Optional[dict] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "schema_version": _SCHEMA_VERSION,
            "job_id": self.job_id,
            "command": self.command,
            "args": list(self.args),
            "state": self.state.value,
            "pid": self.pid,
            "exit_code": self.exit_code,
            "result": self.result,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JobRecord":
        return cls(
            job_id=str(data["job_id"]),
            command=str(data["command"]),
            args=tuple(data.get("args", [])),
            state=JobState(data["state"]),
            pid=data.get("pid"),
            exit_code=data.get("exit_code"),
            result=data.get("result"),
            error=data.get("error"),
        )


class JobStore:
    """Filesystem-backed job state: one directory per job under ``root``.

    Layout (``root`` defaults to ``exports/jobs``)::

        <root>/<job_id>/payload.json   # 0o600, the real command + args
        <root>/<job_id>/state.json     # the JobRecord, atomically rewritten

    Pure persistence -- no subprocess logic -- so the whole state machine is
    unit-testable in isolation.
    """

    _STATE_FILE = "state.json"
    _PAYLOAD_FILE = "payload.json"

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root is not None else Path("exports/jobs")

    # -- paths ---------------------------------------------------------------

    def job_dir(self, job_id: str) -> Path:
        return self.root / job_id

    def payload_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / self._PAYLOAD_FILE

    def _state_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / self._STATE_FILE

    # -- creation ------------------------------------------------------------

    def create(self, command: str, args: list[str]) -> JobRecord:
        """Create a STAGING job: make its dir, write the 0o600 payload + state.

        The payload carries the real (possibly evidence-path) arguments so they
        can be handed to the worker off the command line. It is written with
        mode 0o600 (owner-only) from creation, never widened.
        """
        job_id = uuid.uuid4().hex
        job_dir = self.job_dir(job_id)
        job_dir.mkdir(parents=True, exist_ok=False)

        self._write_payload(job_id, command, list(args))
        record = JobRecord(
            job_id=job_id,
            command=command,
            args=tuple(args),
            state=JobState.STAGING,
        )
        self._write_state(record)
        return record

    def _write_payload(self, job_id: str, command: str, args: list[str]) -> None:
        """Write payload.json with 0o600 perms enforced from creation.

        ``os.open`` with mode 0o600 sets the permission at creation (not a
        chmod-after-write race), so the evidence-path arguments are never
        world-readable for even an instant.
        """
        path = self.payload_path(job_id)
        body = json.dumps({"command": command, "args": args}, sort_keys=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)

    # -- transitions (each persists atomically) ------------------------------

    def mark_running(self, job_id: str, pid: int) -> JobRecord:
        return self._transition(job_id, state=JobState.RUNNING, pid=pid)

    def mark_complete(
        self, job_id: str, exit_code: int, result: Optional[dict] = None
    ) -> JobRecord:
        return self._transition(
            job_id, state=JobState.COMPLETE, exit_code=exit_code, result=result
        )

    def mark_failed(
        self, job_id: str, exit_code: Optional[int], error: str
    ) -> JobRecord:
        return self._transition(
            job_id, state=JobState.FAILED, exit_code=exit_code, error=error
        )

    _LOCK_FILE = "state.lock"

    def _lock_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / self._LOCK_FILE

    @contextmanager
    def _job_lock(self, job_id: str) -> Iterator[None]:
        """Hold an exclusive cross-process lock for the duration of the block.

        A job's state file has TWO writer processes -- the parent
        (``start_job`` -> ``mark_running``) and the detached worker
        (``mark_complete``/``mark_failed``). ``fcntl.flock`` on a dedicated lock
        file serializes their read-modify-write critical sections across
        processes, so the monotonic guard in :meth:`_transition` always decides
        against the LATEST committed state -- closing the check-then-write TOCTOU
        a bare guard would still have (read STAGING, worker completes, write
        RUNNING). The lock file is separate from ``state.json`` so locking never
        touches the file ``os.replace`` swaps (SFE-wqm1).
        """
        self.job_dir(job_id).mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path(job_id), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _transition(self, job_id: str, **changes: Any) -> JobRecord:
        """Apply a state change under the per-job lock, monotonic guard enforced.

        A terminal state (COMPLETE/FAILED) is absorbing: once the worker has
        recorded its verdict, a later transition -- notably the parent's
        post-spawn ``mark_running`` arriving after a sub-second worker already
        finished -- is a no-op that returns the committed terminal record rather
        than reverting it. Without this guard the parent's read-modify-write
        clobbered COMPLETE -> RUNNING, losing the result and stranding the job as
        RUNNING forever (SFE-wqm1). The lock (see :meth:`_job_lock`) makes the
        read-decide-write atomic across the two processes so the guard reads the
        latest state, not a stale one.
        """
        with self._job_lock(job_id):
            current = self.read(job_id)
            # Terminal is fully absorbing: the first worker verdict to land wins.
            # Any later transition -- the parent's post-spawn mark_running, or a
            # second differing terminal write -- is refused and returns the
            # committed record unchanged. The worker emits exactly one terminal
            # state, so this never blocks a legitimate move.
            if current.state.is_terminal:
                return current
            updated = replace(current, **changes)
            self._write_state(updated)
            return updated

    def _write_state(self, record: JobRecord) -> None:
        """Persist a JobRecord atomically (tmp file then ``os.replace``).

        The tmp filename is UNIQUE per write (pid + uuid), not a fixed
        ``state.json.tmp``. This matters because a job's state file has TWO
        concurrent writers: the parent process (``start_job`` -> ``mark_running``)
        and the detached worker (``mark_complete``/``mark_failed``), which race for
        a fast tool. A shared tmp path let them clobber each other's tmp mid-write
        -- one writer's ``O_TRUNC`` open emptied the other's tmp, so ``os.replace``
        could move a truncated/empty file into place and a concurrent ``read``
        would hit ``JSONDecodeError`` (empty file -> "Expecting value: char 0";
        interleaved -> "Extra data"). A per-writer tmp removes the shared mutable
        file, and ``os.replace`` is atomic, so the target is only ever swapped for
        a fully-written file (SFE-g5js).
        """
        target = self._state_path(record.job_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_text(
                json.dumps(record.to_dict(), sort_keys=True, indent=2),
                encoding="utf-8",
            )
            os.replace(tmp, target)
        finally:
            # If os.replace succeeded the tmp is gone; if write_text/replace threw,
            # remove the orphan so a crashed writer never leaks tmp files.
            tmp.unlink(missing_ok=True)

    # -- reads ---------------------------------------------------------------

    def read(self, job_id: str) -> JobRecord:
        """Return the current JobRecord, or raise ``KeyError`` if unknown.

        Retries briefly on a partial/empty parse. With the per-writer tmp fix in
        :meth:`_write_state`, ``os.replace`` swaps the target atomically, so a
        reader sees either the old or the new complete file -- never a torn one.
        The bounded retry is defense-in-depth for the residual window where a
        reader could open the state file at the instant a (buggy or external)
        writer left it empty; it turns a transient ``JSONDecodeError`` into a
        short wait-and-reread rather than a spurious failure (SFE-g5js).
        """
        path = self._state_path(job_id)
        if not path.is_file():
            raise KeyError(f"unknown job {job_id!r}")
        last_exc: Optional[json.JSONDecodeError] = None
        for attempt in range(_READ_RETRIES):
            try:
                with path.open(encoding="utf-8") as handle:
                    return JobRecord.from_dict(json.load(handle))
            except json.JSONDecodeError as exc:
                # Transient partial read racing a write; back off and retry. If the
                # file is still unparseable after the last attempt, re-raise so a
                # genuinely corrupt file is not silently swallowed.
                last_exc = exc
                if attempt < _READ_RETRIES - 1:
                    time.sleep(_READ_RETRY_BACKOFF_SEC)
        raise last_exc  # type: ignore[misc]  # non-None after the loop ran

    def read_payload(self, job_id: str) -> dict:
        """Return the ``{command, args}`` payload, or raise ``KeyError``."""
        path = self.payload_path(job_id)
        if not path.is_file():
            raise KeyError(f"no payload for job {job_id!r}")
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)

    # -- reconcile marker (SFE-dup8) -----------------------------------------
    #
    # The server audits a detached job's result exactly ONCE, the first time it
    # observes a terminal state (option B: guard-at-start, reconcile-at-poll).
    # A filesystem marker (not in-memory state) makes "already reconciled"
    # durable across separate poll/load calls AND across server processes, so a
    # restart cannot double-log the same invocation.

    _RECONCILED_FILE = "reconciled"

    def _reconciled_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / self._RECONCILED_FILE

    def is_reconciled(self, job_id: str) -> bool:
        """True iff this job's terminal result has already been reconciled."""
        return self._reconciled_path(job_id).is_file()

    def mark_reconciled(self, job_id: str) -> None:
        """Record that this job's result has been reconciled (idempotent).

        The marker's existence, not its content, is the signal; a re-touch of an
        existing marker is harmless, so reconcile can call this unconditionally.
        """
        self._reconciled_path(job_id).touch()

    def try_mark_reconciled(self, job_id: str) -> bool:
        """Atomically claim the reconcile marker. True iff THIS caller created it.

        Uses ``O_CREAT | O_EXCL`` so the create-or-fail is a single filesystem
        operation: of two callers observing an unreconciled terminal job, exactly
        one wins the create and proceeds to audit it; the loser gets ``False`` and
        must not re-log. This closes the check-then-set race in the reconcile-once
        guarantee (a plain ``is_reconciled`` + ``mark_reconciled`` has a window
        between the two).
        """
        marker = self._reconciled_path(job_id)
        try:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        os.close(fd)
        return True

    # -- retention (SFE-dup8) ------------------------------------------------

    def prune_reconciled(self, keep_last: int = 50) -> list[str]:
        """Delete the oldest already-reconciled job dirs, keeping the newest N.

        exports/jobs/ grows one directory per job; left unbounded it accumulates
        indefinitely. This is an OPERATOR-invoked sweep (never automatic): a job
        is only eligible once its result has been reconciled (audited), so
        pruning never discards an un-recorded forensic result. Non-reconciled
        jobs are always kept regardless of age. "Oldest" is by the RECONCILE
        MARKER's mtime -- the moment the job was reconciled -- not the job dir's
        mtime (which a late-arriving file could bump), so the order tracks
        reconciliation time. Operator retention has no strict creation-order
        requirement. Returns the pruned job ids.
        """
        if not self.root.is_dir():
            return []
        reconciled = [
            d
            for d in self.root.iterdir()
            if d.is_dir() and (d / self._RECONCILED_FILE).is_file()
        ]
        # Oldest first by the reconcile marker's mtime; keep the newest N.
        reconciled.sort(key=lambda d: (d / self._RECONCILED_FILE).stat().st_mtime)
        to_prune = reconciled[:-keep_last] if keep_last > 0 else reconciled
        pruned: list[str] = []
        for job_dir in to_prune:
            shutil.rmtree(job_dir, ignore_errors=True)
            pruned.append(job_dir.name)
        return pruned


def _default_spawn(argv: list[str], **kwargs: Any) -> int:
    """Fork a fully detached worker; return its pid.

    ``start_new_session=True`` puts the child in its own session so it survives
    the caller exiting. stdio is redirected to /dev/null (a detached job has no
    console). Only the non-sensitive job id rides on ``argv``; the real
    arguments are read from the 0o600 payload.
    """
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs,
    )
    return proc.pid


class JobRunner:
    """Starts detached jobs and reads their state back.

    The spawn function is injectable (default :func:`_default_spawn`) so the
    argv the worker is launched with -- and the security guarantee that no
    sensitive argument appears on it -- can be asserted in a unit test without
    forking a real process.
    """

    def __init__(
        self, store: Optional[JobStore] = None, spawn: Optional[SpawnFn] = None
    ) -> None:
        self.store = store if store is not None else JobStore()
        self._spawn = spawn if spawn is not None else _default_spawn

    def start_job(self, command: str, args: list[str]) -> str:
        """Stage a job, spawn its detached worker, and return the job id.

        Fast by contract: it writes the payload, forks the worker, records the
        pid, and returns -- it never waits for the tool to finish. The worker's
        argv carries ONLY ``-m <worker> <job_id> <root>``; the command and its
        (evidence-path) arguments stay in the 0o600 payload, off the command
        line.
        """
        record = self.store.create(command=command, args=args)
        argv = [
            sys.executable,
            "-m",
            _WORKER_MODULE,
            record.job_id,
            str(self.store.root),
        ]
        pid = self._spawn(argv, start_new_session=True)
        self.store.mark_running(record.job_id, pid=pid)
        return record.job_id

    def poll_job(self, job_id: str) -> JobRecord:
        """Return the job's current state record."""
        return self.store.read(job_id)

    def load_results(self, job_id: str) -> dict:
        """Return a COMPLETE job's result payload.

        Raises:
            ValueError: if the job has not completed (no results to load yet).
            KeyError: if the job id is unknown.
        """
        record = self.store.read(job_id)
        if record.state is not JobState.COMPLETE:
            raise ValueError(
                f"job {job_id} is {record.state.value}, not complete -- no results yet"
            )
        return record.result or {}
