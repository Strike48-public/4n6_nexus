"""Linux ``/proc`` process-capture parser (SFE-4fnv.6, Tranche 2).

A live-response bundle (or a mounted image collected while the host was live)
carries a snapshot of the ``/proc`` pseudo-filesystem: one ``/proc/<pid>/``
directory per running process, holding the kernel's own view of that process
(``comm``, ``cmdline``, ``status``, and the ``exe`` symlink to the backing
executable). This parser walks that capture off a mounted root and returns one
normalized process dict per PID for :class:`LinuxProcessDetector`.

Everything under the mounted root is attacker-controlled evidence, so the file
reads route through :func:`~sift_find_evil.parsers._linux_fs.read_text_contained`
(symlink-escape containment + size cap). The ``exe`` symlink is handled
specially: it is *never followed* -- following it would read the analyst's host
filesystem (a symlink target such as ``/usr/bin/python3`` resolves against the
host root, not the image). Instead its target string is recovered with
:meth:`pathlib.Path.readlink`, which reads only the link contents. The kernel
appends ``" (deleted)"`` to that target when the backing inode was unlinked
while the process kept running, so the raw target string is itself the signal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from ._linux_fs import is_within_root, read_text_contained

# The procfs capture lives at ``<root>/proc``.
_PROC_DIRNAME = "proc"

# ``/proc/<pid>/status`` PPid line, e.g. ``PPid:\t1``.
_PPID_PREFIX = "PPid:"


def _read_comm(pid_dir: Path, root: Path) -> str:
    """Read ``/proc/<pid>/comm`` (the kernel process name), stripped."""
    text = read_text_contained(pid_dir / "comm", root)
    return text.strip() if text else ""


def _read_cmdline(pid_dir: Path, root: Path) -> str:
    """Read ``/proc/<pid>/cmdline`` and join its NUL-separated argv with spaces.

    A kernel thread has an empty ``cmdline`` (all args live in kernel space), so
    the empty string is a legitimate, informative value -- not an error.
    """
    text = read_text_contained(pid_dir / "cmdline", root)
    if not text:
        return ""
    return " ".join(part for part in text.split("\0") if part)


def _read_ppid(pid_dir: Path, root: Path) -> Optional[int]:
    """Read the parent PID from ``/proc/<pid>/status``; None when unavailable."""
    text = read_text_contained(pid_dir / "status", root)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith(_PPID_PREFIX):
            try:
                return int(line[len(_PPID_PREFIX) :].strip())
            except ValueError:
                return None
    return None


def _read_exe_target(pid_dir: Path, root: Path) -> str:
    """Recover the ``/proc/<pid>/exe`` symlink target WITHOUT following it.

    Reading the link's *contents* (``readlink``) is safe: unlike opening the
    link, it never dereferences the target, so a target that points outside the
    mounted root (e.g. an absolute ``/usr/bin/...`` path, which would resolve
    against the analyst host) is returned as text and never read. Returns an
    empty string when ``exe`` is absent or is not a symlink (e.g. a kernel
    thread, which has no backing executable).
    """
    exe = pid_dir / "exe"
    if not exe.is_symlink():
        return ""
    try:
        return str(exe.readlink())
    except OSError:
        return ""


def parse_proc_processes(root: Path) -> list[dict[str, Any]]:
    """Parse a ``/proc`` process capture from a mounted image root.

    Args:
        root: Mounted image root (or a live-response bundle laid out like a root
            filesystem). A missing ``/proc`` directory yields an empty list, so
            a dead-disk image with no live capture parses cleanly.

    Returns:
        One dict per ``/proc/<pid>`` directory, sorted by numeric PID, each with
        keys ``pid`` (int), ``comm`` (str), ``cmdline`` (str, space-joined
        argv), ``ppid`` (int or None), ``exe_target`` (str, the raw ``exe``
        symlink target, empty when absent) and ``source_path``
        (``"/proc/<pid>"``). Non-numeric ``/proc`` entries (``self``, ``cpuinfo``
        ...) are skipped. The mounted root is never mutated.
    """
    proc_dir = root / _PROC_DIRNAME
    if not proc_dir.is_dir() or not is_within_root(proc_dir, root):
        return []

    processes: list[dict[str, Any]] = []
    for entry in proc_dir.iterdir():
        # A real procfs has no numeric symlinks; a numeric symlink-to-a-pid-dir
        # in synthetic/corrupted evidence would otherwise double-count a process.
        if not entry.name.isdigit() or entry.is_symlink() or not entry.is_dir():
            continue
        pid = int(entry.name)
        processes.append(
            {
                "pid": pid,
                "comm": _read_comm(entry, root),
                "cmdline": _read_cmdline(entry, root),
                "ppid": _read_ppid(entry, root),
                "exe_target": _read_exe_target(entry, root),
                "source_path": f"/{_PROC_DIRNAME}/{pid}",
            }
        )

    processes.sort(key=lambda proc: proc["pid"])
    return processes
