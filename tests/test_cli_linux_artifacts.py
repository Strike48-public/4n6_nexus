"""CLI: `analyze --linux-artifacts` runs LinuxPersistenceDetector standalone.

SFE-fibx.9.2 decouples Linux persistence analysis from the Windows
mft/prefetch/evtx triad: `--linux-artifacts <bundle.json>` is its own evidence
group. These E2E tests pin that the flag works WITHOUT the triad and fails loudly
on a bad bundle (the same contract as --memory/--yara). cli.py is coverage-omitted,
so this is an end-to-end smoke, not a unit test.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = (
    REPO_ROOT
    / "scenarios"
    / "synthetic"
    / "25_linux_persistence"
    / "linux_artifacts.json"
)


def _run_analyze(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sift_find_evil", "analyze", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def test_linux_artifacts_runs_without_the_windows_triad(tmp_path: Path) -> None:
    """--linux-artifacts alone (no --mft/--prefetch/--evtx) produces persistence
    findings across all five surfaces and exits 0."""
    out = tmp_path / "findings.json"
    proc = _run_analyze(
        "--linux-artifacts", str(FIXTURE), "--output", str(out), cwd=tmp_path
    )
    assert proc.returncode == 0, f"standalone Linux analyze failed: {proc.stderr}"

    report = json.loads(out.read_text(encoding="utf-8"))
    entries = report["findings"] if isinstance(report, dict) else report
    cats = {e["finding"]["category"] for e in entries}
    assert cats == {"persistence"}, f"expected only persistence findings, got {cats}"
    assert (
        len(entries) == 5
    ), f"expected 5 Linux persistence findings, got {len(entries)}"


def test_linux_artifacts_bundle_must_be_a_json_object(tmp_path: Path) -> None:
    """A malformed bundle (JSON array, not an object) fails loudly, not silently."""
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    proc = _run_analyze("--linux-artifacts", str(bad), cwd=tmp_path)
    assert proc.returncode != 0
    assert "must be a JSON object" in proc.stderr


def test_missing_linux_artifacts_file_is_rejected(tmp_path: Path) -> None:
    proc = _run_analyze("--linux-artifacts", str(tmp_path / "nope.json"), cwd=tmp_path)
    assert proc.returncode != 0
    assert "not found" in proc.stderr


# SHA256 of the empty string -- what the receipt image digest degrades to when
# NO evidence path is bound (the bug: linux_artifacts missing from
# _EVIDENCE_PATH_ARGS, so --harden minted receipts that bound nothing).
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_linux_artifacts_are_bound_into_the_harden_receipt(tmp_path: Path) -> None:
    """--harden receipts must bind the --linux-artifacts bundle, so a swapped
    bundle would fail verification (SFE-fibx.9.2). Regression for the receipt
    binding gap: without linux_artifacts in _EVIDENCE_PATH_ARGS the image digest
    is the empty-string SHA256 (nothing hashed)."""
    out = tmp_path / "findings.json"
    proc = _run_analyze(
        "--linux-artifacts",
        str(FIXTURE),
        "--output",
        str(out),
        "--harden",
        cwd=tmp_path,
    )
    assert proc.returncode == 0, f"harden run failed: {proc.stderr}"

    hardened = out.with_name("findings.hardened.json")
    assert hardened.is_file(), "no hardened report written"
    text = hardened.read_text(encoding="utf-8")
    assert _EMPTY_SHA256 not in text, (
        "harden receipt bound NO evidence (empty-string digest) -- the "
        "--linux-artifacts bundle is not in _EVIDENCE_PATH_ARGS"
    )


# --- hidden-process cross-check shipping wiring (SFE-6mqd) --------------------
# Memory analysis needs Volatility, which CI may lack, so exercise the shipping
# helpers directly: raw-row capture (raw_out) + the correlation join. This is the
# CLI-path analog of the harness scenario 32_linux_proc_pslist_hidden.


def test_linux_artifacts_json_stashes_proc_rows_into_raw_out(tmp_path: Path) -> None:
    """`_run_linux_persistence_detector(raw_out=...)` must capture the /proc rows
    so the caller can run the cross-check without re-walking the bundle."""
    from sift_find_evil.cli import _run_linux_persistence_detector

    bundle = tmp_path / "linux.json"
    bundle.write_text(
        json.dumps({"proc_processes": [{"pid": 1000, "comm": "systemd"}]}),
        encoding="utf-8",
    )
    raw: dict = {}
    _run_linux_persistence_detector(bundle, verbose=False, raw_out=raw)
    assert raw["proc_processes"] == [{"pid": 1000, "comm": "systemd"}]


def test_shipping_correlation_flags_pslist_pid_absent_from_proc() -> None:
    """The shipping helper joins the captured raw rows into a T1014 finding."""
    from sift_find_evil.cli import _run_hidden_process_correlation
    from sift_find_evil.memory.volatility_runner import LinuxProcessRow

    memory_raw = {
        "linux_pslist": [
            LinuxProcessRow(1000, 1, "systemd", 0, None, {}),
            LinuxProcessRow(31337, 1000, "kdevtmpfsi", 0, None, {}),
        ]
    }
    linux_raw = {"proc_processes": [{"pid": 1000, "comm": "systemd"}]}

    findings = _run_hidden_process_correlation(memory_raw, linux_raw, verbose=False)

    assert len(findings) == 1
    assert "31337" in findings[0].title
    assert "T1014" in findings[0].techniques


def test_shipping_correlation_noop_without_both_inputs() -> None:
    """No memory rows (or no proc rows) -> no cross-check, no findings."""
    from sift_find_evil.cli import _run_hidden_process_correlation
    from sift_find_evil.memory.volatility_runner import LinuxProcessRow

    row = LinuxProcessRow(31337, 1000, "kdevtmpfsi", 0, None, {})
    assert _run_hidden_process_correlation({"linux_pslist": [row]}, {}, False) == []
    assert (
        _run_hidden_process_correlation({}, {"proc_processes": [{"pid": 1}]}, False)
        == []
    )


# --- wtmp + /proc detector parity on the shipping CLI path (SFE-jsuq) ---------
# The scenario harness scored LinuxLoginSessionDetector (wtmp) and
# LinuxProcessDetector (/proc), but the shipping `_analyze_linux_artifacts` ran
# only persistence/auth/execution -- those two surfaces were scored-but-not-
# shipped. These guards fail if the two detectors are dropped from the CLI path.


def test_cli_path_runs_login_session_detector() -> None:
    """A privileged external login in the bundle must produce a wtmp T1078
    finding on the shipping CLI path (not just in the harness)."""
    from sift_find_evil.cli import _analyze_linux_artifacts

    findings = _analyze_linux_artifacts(
        {"login_sessions": [{"user": "root", "source_ip": "45.83.122.10"}]}
    )
    wtmp = [f for f in findings if f.artifact_sources == ["wtmp"]]
    assert len(wtmp) == 1, "LinuxLoginSessionDetector did not run on the CLI path"
    assert "T1078" in wtmp[0].evidence["mitre_technique"]


def test_cli_path_runs_proc_process_detector() -> None:
    """A deleted-binary process in the bundle must produce a /proc T1070.004
    finding on the shipping CLI path (not just in the harness)."""
    from sift_find_evil.cli import _analyze_linux_artifacts

    findings = _analyze_linux_artifacts(
        {
            "proc_processes": [
                {
                    "pid": 4242,
                    "comm": "x",
                    "cmdline": "/tmp/x",
                    "ppid": 1000,
                    "exe_target": "/usr/sbin/httpd (deleted)",
                    "source_path": "/proc/4242",
                }
            ]
        }
    )
    proc = [f for f in findings if f.artifact_sources == ["proc"]]
    assert len(proc) == 1, "LinuxProcessDetector did not run on the CLI path"
    assert proc[0].evidence["mitre_technique"] == "T1070.004"
