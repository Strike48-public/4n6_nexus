"""Tests for the cross-source memory-vs-disk correlator (SFE-md4v).

A pass that runs after the domain analysts and consumes their verified evidence to
emit typed cross-source discrepancies that no single domain can see:

  * GHOST_PROCESS       -- a process live in memory with no on-disk artifact
                           (hollowing / rootkit). T1055 / T1014.
  * UNINSTALLED_EXECUTION-- an execution in prefetch with no registry install
                           footprint. T1543 / T1547.
  * PHANTOM_CONNECTION  -- a connection in memory to an IP that no DNS query in
                           the PCAP resolved. T1071.

The correlator reconciles the 15-byte _EPROCESS.ImageFileName truncation so a
truncated memory name ("iCloudDrive.ex") is matched to its full disk name
("iCloudDrive.exe") rather than misread as a ghost. It is pure and deterministic
and only runs when a memory image is present, >=1 finding was verified, and >=2
source types are available. RED-first: the module did not exist before.
"""

import pytest

from sift_find_evil.correlation.cross_source import (
    CrossSourceInput,
    DiscrepancyType,
    correlate_cross_source,
    names_reconcile,
    normalize_eprocess_name,
)


def _base(**overrides):
    """A gate-passing input (memory present, 1 verified finding, 2+ sources)."""
    kwargs = dict(
        memory_process_names=["evil.exe"],
        disk_artifact_names=["evil.exe"],
        verified_finding_count=1,
    )
    kwargs.update(overrides)
    return CrossSourceInput(**kwargs)


# -- EPROCESS truncation reconciliation ------------------------------------


def test_normalize_truncates_to_eprocess_length():
    # A >15-char name is truncated to the 15-byte ImageFileName buffer.
    assert normalize_eprocess_name("aVeryLongProcessName.exe") == "averylongproces"


def test_exact_names_reconcile():
    assert names_reconcile("evil.exe", "evil.exe") is True


def test_truncated_memory_name_reconciles_with_full_disk_name():
    # The headline case: memory shows the EPROCESS-truncated form, disk has the
    # full name. They are the same process, not a ghost.
    assert names_reconcile("iCloudDrive.ex", "iCloudDrive.exe") is True


def test_reconcile_is_case_insensitive():
    assert names_reconcile("EVIL.EXE", "evil.exe") is True


def test_short_prefix_does_not_spuriously_reconcile():
    # "evil.exe" is not a truncation of "evilcorp_installer.exe" -- a short name
    # that merely prefixes a longer one must NOT reconcile, or every ghost hides.
    assert names_reconcile("evil.exe", "evilcorp_installer.exe") is False


def test_short_genuine_prefix_below_truncation_boundary_does_not_reconcile():
    # "svchost" IS a literal prefix of "svchost_evil.exe", but at 7 chars it is
    # far below the 14-char EPROCESS truncation boundary, so it cannot be a
    # truncation of it -- a rootkit naming itself with a benign prefix must still
    # surface as a ghost. This guards the length gate specifically (a bare
    # startswith check would wrongly reconcile and hide the ghost).
    assert names_reconcile("svchost", "svchost_evil.exe") is False


def test_disk_path_basename_reconciles():
    # Disk artifacts arrive as full paths; the basename is what matches.
    assert names_reconcile("evil.exe", "C:\\Users\\v\\Downloads\\evil.exe") is True


# -- GHOST_PROCESS ---------------------------------------------------------


def test_ghost_process_detected_when_no_disk_artifact():
    result = correlate_cross_source(
        _base(
            memory_process_names=["rootkit.exe"],
            disk_artifact_names=["notepad.exe", "explorer.exe"],
        )
    )
    ghosts = [d for d in result if d.type is DiscrepancyType.GHOST_PROCESS]
    assert len(ghosts) == 1
    assert ghosts[0].subject == "rootkit.exe"
    assert "T1055" in ghosts[0].mitre
    assert "rootkit.exe" in ghosts[0].memory_evidence


def test_process_present_on_disk_is_not_a_ghost():
    result = correlate_cross_source(
        _base(
            memory_process_names=["notepad.exe"],
            disk_artifact_names=["C:\\Windows\\System32\\notepad.exe"],
        )
    )
    assert [d for d in result if d.type is DiscrepancyType.GHOST_PROCESS] == []


def test_truncated_process_is_not_flagged_as_ghost():
    # Regression against the EPROCESS-truncation false positive.
    result = correlate_cross_source(
        _base(
            memory_process_names=["iCloudDrive.ex"],
            disk_artifact_names=["C:\\Program Files\\iCloud\\iCloudDrive.exe"],
        )
    )
    assert [d for d in result if d.type is DiscrepancyType.GHOST_PROCESS] == []


def test_fileless_kernel_processes_are_allowlisted():
    # System / Registry / MemCompression have no backing image file; their
    # absence from disk artifacts is expected, not a ghost.
    result = correlate_cross_source(
        _base(
            memory_process_names=["System", "Registry", "MemCompression", "evil.exe"],
            disk_artifact_names=["evil.exe"],
        )
    )
    ghosts = [d.subject for d in result if d.type is DiscrepancyType.GHOST_PROCESS]
    assert ghosts == []  # evil.exe is on disk; the pseudo-processes are allowlisted


def test_custom_allowlist_overrides_default():
    result = correlate_cross_source(
        _base(
            memory_process_names=["customsvc.exe"],
            disk_artifact_names=["notepad.exe"],
        ),
        system_allowlist={"customsvc.exe"},
    )
    assert [d for d in result if d.type is DiscrepancyType.GHOST_PROCESS] == []


# -- UNINSTALLED_EXECUTION -------------------------------------------------


def test_uninstalled_execution_detected():
    result = correlate_cross_source(
        CrossSourceInput(
            memory_process_names=["x.exe"],  # memory bucket for the gate
            prefetch_executions=["dropper.exe"],
            registry_installed=["chrome.exe", "office.exe"],
            verified_finding_count=1,
        )
    )
    hits = [d for d in result if d.type is DiscrepancyType.UNINSTALLED_EXECUTION]
    assert len(hits) == 1
    assert hits[0].subject == "dropper.exe"
    assert "T1543" in hits[0].mitre


def test_installed_execution_is_not_flagged():
    result = correlate_cross_source(
        CrossSourceInput(
            memory_process_names=["x.exe"],
            prefetch_executions=["chrome.exe"],
            registry_installed=["chrome.exe"],
            verified_finding_count=1,
        )
    )
    assert [d for d in result if d.type is DiscrepancyType.UNINSTALLED_EXECUTION] == []


# -- PHANTOM_CONNECTION ----------------------------------------------------


def test_phantom_connection_detected():
    result = correlate_cross_source(
        CrossSourceInput(
            memory_foreign_ips=["203.0.113.7"],
            pcap_resolved_ips=["93.184.216.34"],
            verified_finding_count=1,
        )
    )
    hits = [d for d in result if d.type is DiscrepancyType.PHANTOM_CONNECTION]
    assert len(hits) == 1
    assert hits[0].subject == "203.0.113.7"
    assert "T1071" in hits[0].mitre


def test_resolved_connection_is_not_phantom():
    result = correlate_cross_source(
        CrossSourceInput(
            memory_foreign_ips=["93.184.216.34"],
            pcap_resolved_ips=["93.184.216.34"],
            verified_finding_count=1,
        )
    )
    assert [d for d in result if d.type is DiscrepancyType.PHANTOM_CONNECTION] == []


def test_benign_direct_ip_infra_is_not_phantom():
    # Public DNS resolvers are legitimately reached by hardcoded IP with no prior
    # DNS lookup; consistent with the network-presence detector's benign-infra rule.
    result = correlate_cross_source(
        CrossSourceInput(
            memory_foreign_ips=["8.8.8.8", "1.1.1.1"],
            pcap_resolved_ips=[],
            verified_finding_count=1,
        )
    )
    assert [d for d in result if d.type is DiscrepancyType.PHANTOM_CONNECTION] == []


# -- gate ------------------------------------------------------------------


def test_gate_blocks_when_no_memory_source():
    # Disk + prefetch only, no memory image -> the whole pass is skipped.
    result = correlate_cross_source(
        CrossSourceInput(
            disk_artifact_names=["a.exe"],
            prefetch_executions=["b.exe"],
            registry_installed=[],
            verified_finding_count=1,
        )
    )
    assert result == []


def test_gate_blocks_when_no_verified_finding():
    result = correlate_cross_source(
        _base(
            memory_process_names=["rootkit.exe"],
            disk_artifact_names=["notepad.exe"],
            verified_finding_count=0,
        )
    )
    assert result == []


def test_gate_blocks_when_fewer_than_two_source_types():
    # Memory present and a verified finding, but memory is the ONLY source -- no
    # second source to correlate against.
    result = correlate_cross_source(
        CrossSourceInput(
            memory_process_names=["rootkit.exe"],
            verified_finding_count=1,
        )
    )
    assert result == []


def test_gate_passes_with_memory_plus_one_other_source():
    result = correlate_cross_source(
        _base(
            memory_process_names=["rootkit.exe"],
            disk_artifact_names=["notepad.exe"],
        )
    )
    assert len(result) == 1


def test_empty_disk_source_still_runs_and_flags_all_memory_procs():
    # A PRESENT-but-empty disk source ([] not None) is meaningful: every memory
    # process is a ghost. Distinguishes "disk searched, found nothing" from
    # "disk not consulted".
    result = correlate_cross_source(
        _base(
            memory_process_names=["a.exe", "b.exe"],
            disk_artifact_names=[],
        )
    )
    ghosts = {d.subject for d in result if d.type is DiscrepancyType.GHOST_PROCESS}
    assert ghosts == {"a.exe", "b.exe"}


# -- shape / determinism ---------------------------------------------------


def test_discrepancy_is_frozen():
    result = correlate_cross_source(
        _base(memory_process_names=["ghost.exe"], disk_artifact_names=["x.exe"])
    )
    with pytest.raises(Exception):
        result[0].subject = "changed"  # frozen


def test_result_is_deterministic_and_order_stable():
    inp = _base(
        memory_process_names=["zebra.exe", "alpha.exe", "mid.exe"],
        disk_artifact_names=["mid.exe"],
    )
    r1 = correlate_cross_source(inp)
    r2 = correlate_cross_source(inp)
    subjects1 = [d.subject for d in r1]
    assert subjects1 == [d.subject for d in r2]
    # Ghosts are emitted in a stable (sorted) order regardless of input order.
    assert subjects1 == sorted(subjects1)


def test_duplicate_entries_are_deduped_per_type():
    # Repeated names/IPs in a source list must yield one discrepancy each, not one
    # per occurrence -- triage should not drown in near-duplicate rows.
    result = correlate_cross_source(
        CrossSourceInput(
            memory_process_names=["ghost.exe", "ghost.exe", "GHOST.EXE"],
            disk_artifact_names=["clean.exe"],
            prefetch_executions=["drop.exe", "drop.exe"],
            registry_installed=[],
            memory_foreign_ips=["203.0.113.5", "203.0.113.5"],
            pcap_resolved_ips=[],
            verified_finding_count=1,
        )
    )
    ghosts = [d for d in result if d.type is DiscrepancyType.GHOST_PROCESS]
    drops = [d for d in result if d.type is DiscrepancyType.UNINSTALLED_EXECUTION]
    phantoms = [d for d in result if d.type is DiscrepancyType.PHANTOM_CONNECTION]
    assert len(ghosts) == 1
    assert len(drops) == 1
    assert len(phantoms) == 1


def test_long_name_truncation_reconciles():
    # A disk name longer than the 15-byte EPROCESS buffer and its memory-side
    # truncation both normalize to the same clipped key -> not a ghost.
    result = correlate_cross_source(
        _base(
            memory_process_names=["WindowsDefender"],  # kernel-truncated form
            disk_artifact_names=["C:\\Program Files\\WindowsDefender.exe"],
        )
    )
    assert [d for d in result if d.type is DiscrepancyType.GHOST_PROCESS] == []


def test_multiple_discrepancy_types_coexist():
    result = correlate_cross_source(
        CrossSourceInput(
            memory_process_names=["ghost.exe"],
            disk_artifact_names=["clean.exe"],
            prefetch_executions=["dropper.exe"],
            registry_installed=[],
            memory_foreign_ips=["203.0.113.9"],
            pcap_resolved_ips=[],
            verified_finding_count=2,
        )
    )
    types = {d.type for d in result}
    assert types == {
        DiscrepancyType.GHOST_PROCESS,
        DiscrepancyType.UNINSTALLED_EXECUTION,
        DiscrepancyType.PHANTOM_CONNECTION,
    }
