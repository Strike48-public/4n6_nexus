"""Detached worker entrypoint for the background-job runner (SFE-eiqz).

Launched by :meth:`sift_find_evil.mcp.jobs.JobRunner.start_job` as a fully
detached process::

    python -m sift_find_evil.mcp.jobs_worker <job_id> <store_root>

Only the NON-sensitive job id and store root ride on the command line. The
worker reads the real command + arguments from the 0o600 ``payload.json`` (so
evidence paths never appear in ``ps`` / ``/proc/<pid>/cmdline``), runs the tool,
and drives the job state file to ``complete`` (exit 0) or ``failed`` (non-zero
exit, tool-not-found, or any unexpected error). It never raises out to the shell
uncaught: a crash is itself recorded as a FAILED transition so a polling caller
always sees a terminal state.
"""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

from .guardrails import tool_binary, tool_supported_on_platform
from .jobs import NEVER_RAN_EXIT_CODE, JobStore


def run(job_id: str, store_root: str) -> int:
    """Execute one staged job to a terminal state. Returns a process exit code.

    Reads the payload for ``job_id`` under ``store_root``, runs its command, and
    records the outcome. Returns 0 when the job reached a terminal state (even a
    FAILED one -- the worker did its job of recording the failure); returns 1
    only if it could not even load the payload / record state.
    """
    store = JobStore(root=Path(store_root))
    try:
        payload = store.read_payload(job_id)
    except (KeyError, OSError) as exc:
        # Cannot find the work to do. Try to mark the job failed; if even that
        # is impossible, signal a worker-level error via the exit code.
        try:
            store.mark_failed(
                job_id,
                exit_code=NEVER_RAN_EXIT_CODE,
                error=f"payload unreadable: {exc}",
            )
        except (KeyError, OSError):
            return 1
        return 0

    command = payload["command"]
    args = list(payload.get("args", []))

    # ``command`` is the logical tool key (what the guardrail + audit recorded);
    # translate to the real executable at the exec boundary, exactly as the
    # synchronous server path does. Error/audit strings keep the logical key.
    #
    # Platform gate, mirroring server._execute (SFE-ybki): this worker marks a job
    # COMPLETE on exit code 0, and PECmd on Linux refuses to work while exiting 0,
    # so an ungated run recorded a finished Prefetch job with an empty result.
    # NEVER_RAN, not a tool exit code, because it never executed.
    if not tool_supported_on_platform(command):
        store.mark_failed(
            job_id,
            exit_code=NEVER_RAN_EXIT_CODE,
            error=(
                f"tool {command} is not supported on this platform "
                f"({platform.system()}): refused before execution"
            ),
        )
        return 0

    try:
        proc = subprocess.run(
            [tool_binary(command), *args],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        store.mark_failed(
            job_id, exit_code=NEVER_RAN_EXIT_CODE, error=f"tool not found: {command}"
        )
        return 0
    except OSError as exc:  # e.g. permission denied on the executable
        store.mark_failed(
            job_id, exit_code=NEVER_RAN_EXIT_CODE, error=f"spawn failed: {exc}"
        )
        return 0

    result = {"stdout": proc.stdout, "stderr": proc.stderr}
    if proc.returncode == 0:
        store.mark_complete(job_id, exit_code=0, result=result)
    else:
        store.mark_failed(
            job_id,
            exit_code=proc.returncode,
            error=proc.stderr.strip() or f"exited {proc.returncode}",
        )
    return 0


def main(argv: list[str]) -> int:
    """CLI entry: ``jobs_worker <job_id> <store_root>``."""
    if len(argv) != 2:
        sys.stderr.write("usage: jobs_worker <job_id> <store_root>\n")
        return 2
    job_id, store_root = argv
    return run(job_id, store_root)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
