"""Tests for the Linux /proc process-capture parser (SFE-4fnv.6).

Builds a synthetic ``<root>/proc`` tree on disk (including the ``exe`` symlink
the kernel exposes) and asserts the parser normalizes it correctly and stays
contained within the mounted root: the ``exe`` symlink target is recovered via
readlink (never followed), and a ``comm``/``cmdline`` symlink escaping the root
is refused by the shared containment helper.
"""

from __future__ import annotations

import os
from pathlib import Path

from sift_find_evil.parsers.linux_proc import parse_proc_processes


def _make_proc(
    root: Path,
    pid: int,
    *,
    comm: str = "bash",
    cmdline_argv: tuple[str, ...] = ("/bin/bash",),
    ppid: int = 1000,
    exe_target: str | None = "/usr/bin/bash",
) -> Path:
    """Create <root>/proc/<pid>/ with comm, cmdline, status and exe."""
    pid_dir = root / "proc" / str(pid)
    pid_dir.mkdir(parents=True)
    (pid_dir / "comm").write_text(comm + "\n", encoding="utf-8")
    # /proc/<pid>/cmdline is NUL-separated and NUL-terminated.
    (pid_dir / "cmdline").write_bytes(
        b"".join(arg.encode() + b"\0" for arg in cmdline_argv)
    )
    (pid_dir / "status").write_text(f"Name:\t{comm}\nPPid:\t{ppid}\n", encoding="utf-8")
    if exe_target is not None:
        os.symlink(exe_target, pid_dir / "exe")
    return pid_dir


def test_parses_process_fields(tmp_path: Path) -> None:
    """A well-formed /proc/<pid> is normalized to the process dict contract."""
    _make_proc(
        tmp_path,
        4242,
        comm="beacon",
        cmdline_argv=("/tmp/.x/beacon", "--quiet"),
        ppid=1337,
        exe_target="/tmp/.x/beacon",
    )

    procs = parse_proc_processes(tmp_path)

    assert len(procs) == 1
    proc = procs[0]
    assert proc["pid"] == 4242
    assert proc["comm"] == "beacon"
    assert proc["cmdline"] == "/tmp/.x/beacon --quiet"
    assert proc["ppid"] == 1337
    assert proc["exe_target"] == "/tmp/.x/beacon"
    assert proc["source_path"] == "/proc/4242"


def test_deleted_exe_target_preserved(tmp_path: Path) -> None:
    """The '(deleted)' suffix on an exe symlink target survives verbatim."""
    _make_proc(tmp_path, 5, exe_target="/usr/sbin/httpd (deleted)")

    procs = parse_proc_processes(tmp_path)

    assert procs[0]["exe_target"] == "/usr/sbin/httpd (deleted)"


def test_kernel_thread_without_exe(tmp_path: Path) -> None:
    """A kernel thread has no exe symlink, so exe_target is empty (not an error)."""
    _make_proc(tmp_path, 2, comm="[kthreadd]", cmdline_argv=(), exe_target=None)

    procs = parse_proc_processes(tmp_path)

    assert procs[0]["exe_target"] == ""
    assert procs[0]["cmdline"] == ""


def test_non_numeric_entries_skipped_and_sorted(tmp_path: Path) -> None:
    """Non-PID /proc entries are ignored and results are PID-sorted."""
    _make_proc(tmp_path, 30)
    _make_proc(tmp_path, 4)
    (tmp_path / "proc" / "cpuinfo").write_text("x", encoding="utf-8")
    (tmp_path / "proc" / "self").symlink_to("30")

    procs = parse_proc_processes(tmp_path)

    assert [p["pid"] for p in procs] == [4, 30]


def test_missing_proc_returns_empty(tmp_path: Path) -> None:
    """A dead-disk image with no /proc capture parses to an empty list."""
    assert parse_proc_processes(tmp_path) == []


def test_numeric_symlink_to_pid_dir_not_double_counted(tmp_path: Path) -> None:
    """A numeric symlink to a real PID dir must not yield a duplicate entry.

    Real procfs has no numeric symlinks; a corrupted/synthetic image with
    /proc/9999 -> /proc/1234 would otherwise double-count PID 1234's data.
    """
    _make_proc(tmp_path, 1234)
    os.symlink("1234", tmp_path / "proc" / "9999")

    procs = parse_proc_processes(tmp_path)

    assert [p["pid"] for p in procs] == [1234]


def test_ppid_none_when_status_absent_or_malformed(tmp_path: Path) -> None:
    """PPid resolves to None when status is missing, or PPid is non-numeric.

    Both are defensive: a truncated/absent status file, or a corrupted PPid
    line, must degrade to ppid=None rather than raise.
    """
    # No status file at all.
    d1 = tmp_path / "proc" / "10"
    d1.mkdir(parents=True)
    (d1 / "comm").write_text("a\n", encoding="utf-8")
    # status present but PPid is non-numeric, and there is no PPid line for #20.
    d2 = tmp_path / "proc" / "20"
    d2.mkdir(parents=True)
    (d2 / "comm").write_text("b\n", encoding="utf-8")
    (d2 / "status").write_text("Name:\tb\nPPid:\tnot-a-number\n", encoding="utf-8")
    d3 = tmp_path / "proc" / "30"
    d3.mkdir(parents=True)
    (d3 / "comm").write_text("c\n", encoding="utf-8")
    (d3 / "status").write_text("Name:\tc\n", encoding="utf-8")  # no PPid line

    procs = {p["pid"]: p for p in parse_proc_processes(tmp_path)}

    assert procs[10]["ppid"] is None
    assert procs[20]["ppid"] is None
    assert procs[30]["ppid"] is None


def test_exe_symlink_escaping_root_is_not_followed(tmp_path: Path) -> None:
    """An exe symlink to a host path returns the target STRING, never its content.

    readlink recovers the link text without dereferencing it, so a target that
    resolves against the analyst host (an absolute path outside the image) is
    reported as evidence but its contents are never read.
    """
    pid_dir = _make_proc(tmp_path, 99, exe_target="/etc/shadow")

    procs = parse_proc_processes(tmp_path)

    assert procs[0]["exe_target"] == "/etc/shadow"
    # Sanity: exe is a symlink, and we only ever read its link text.
    assert (pid_dir / "exe").is_symlink()


def test_comm_symlink_escaping_root_is_refused(tmp_path: Path) -> None:
    """A comm symlink pointing outside the root is refused (contained read)."""
    outside = tmp_path.parent / "secret_comm"
    outside.write_text("rootkit\n", encoding="utf-8")
    pid_dir = tmp_path / "proc" / "77"
    pid_dir.mkdir(parents=True)
    os.symlink(outside, pid_dir / "comm")
    (pid_dir / "status").write_text("PPid:\t1\n", encoding="utf-8")

    procs = parse_proc_processes(tmp_path)

    # The escaping comm read is refused -> empty, not the host file's content.
    assert procs[0]["comm"] == ""
    assert procs[0]["ppid"] == 1
