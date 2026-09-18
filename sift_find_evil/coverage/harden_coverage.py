"""Coverage audit for the shipping harden path (SFE-fibx.5 PR-B).

Why not reuse ``assess_coverage``? That function's value is distinguishing
"present but not evaluated" from "covered" -- a distinction that only exists when
a tool can be applicable-yet-unrun against present evidence (the MCP/orchestrator
model). On the ``harden_findings`` path, evidence arrives ALREADY PARSED: passing
an artifact class to the CLI is what runs its detector, so supplied == evaluated
and the "not_evaluated"/gap axis is vacuously empty. Feeding harden-path data to
``assess_coverage`` would therefore emit a misleading "no gaps" pass -- the exact
vacuous-clean-bill trap the coverage module exists to prevent.

This module computes the two coverage signals that ARE honest on the harden path:

  * ``uncited`` -- artifact classes supplied+parsed this run that NO finding
    cites. The real blind-spot detector: "we parsed the registry and drew no
    conclusion from it" is a fact the investigator should see, not silence.
  * ``not_examined`` -- high/critical catalog classes whose evidence was NOT
    supplied this run, so their silence is honestly not a clean bill of health.

Both are computed at the CLI's detector-dispatch granularity (the coarse classes
below), because one ``--evtx`` flag drives several fine catalog classes at once;
the coarse unit is the honest resolution for "did a finding cite this input".

Pure and deterministic: no I/O, never mutates a finding, produces no verdict.
The blocking gate that consumes it is PR-D.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .audit import ARTIFACT_CATALOG, GAP_IMPORTANCE

# The coarse artifact classes, at the CLI's detector-dispatch granularity. These
# are the unit both "what was supplied this run" and "what a finding cites" are
# expressed in, so the two can be compared.
COARSE_CLASSES: frozenset[str] = frozenset(
    {"disk", "pst", "network", "registry", "lnk_jumplist", "memory", "yara", "linux"}
)

# Finding ``artifact_sources`` token -> coarse class. Tokens are matched
# case-insensitively. A token absent here (e.g. a dynamic node id like
# ``node-42``, or the injection-defense sanitizer source) maps to None and
# contributes no class, so an unmappable source is never force-fit into a wrong
# bucket. Keys are lowercased.
_SOURCE_TO_COARSE: dict[str, str] = {
    # disk / timeline family (MFT, Prefetch, Event Log, USN, disk image)
    "$mft": "disk",
    "mft": "disk",
    "eventlog": "disk",
    "evtx": "disk",
    "disk": "disk",
    "disk_image": "disk",
    "$usnjrnl:$j": "disk",
    "prefetch": "disk",
    # email
    "pst": "pst",
    # network (browser_history is the SOLE source a webmail/cloud-exfil finding
    # stamps when there is no pcap/mft corroboration -- webmail_exfil_detector.py,
    # cloud_upload_detector.py -- so it MUST normalize to network, else a
    # --browser-history run whose only network finding is browser-only would
    # report network as a false blind-spot).
    "pcap": "network",
    "network": "network",
    "browser_history": "network",
    # registry / execution-registry artifacts
    "registry": "registry",
    # shortcuts / jump lists
    "lnk_jumplist": "lnk_jumplist",
    # memory
    "memory": "memory",
    # signature scans
    "yara": "yara",
    "sigma_scan": "yara",
    # Linux persistence surfaces (LinuxPersistenceDetector artifact_sources).
    # These normalize to the same coarse class the --linux-artifacts CLI flag
    # declares (_ARG_TO_COVERAGE_CLASS), so a Linux-only run's findings are
    # citeable and 'linux' is never a false blind-spot (SFE-fibx.9.2).
    "systemd": "linux",
    "cron": "linux",
    "ld.so.preload": "linux",
    "sudoers": "linux",
    "shell_init": "linux",
    # Linux auth-log surface (LinuxAuthDetector, SFE-rfhz). Same --linux-artifacts
    # collector/flag, so it rolls up into the same coarse 'linux' class.
    "auth_log": "linux",
    # Linux shell-history surface (LinuxExecutionDetector, SFE-jdii). Same
    # --linux-artifacts collector/flag, so it rolls up into 'linux' too.
    "bash_history": "linux",
    # Linux wtmp/utmp login-session surface (LinuxLoginSessionDetector,
    # SFE-fjla). Same --linux-artifacts collector/flag; rolls up into 'linux'.
    "wtmp": "linux",
    # Linux /proc process-capture surface (LinuxProcessDetector, SFE-4fnv.6).
    # Same --linux-artifacts collector/flag; rolls up into 'linux' too.
    "proc": "linux",
    # Linux journald surface (SFE-4igf): a captured journalctl dump normalizes
    # into the auth/login streams via the same --linux-artifacts collector, so a
    # journald-sourced auth/login finding rolls up into the same 'linux' class.
    "journald": "linux",
}

# Which coarse class each fine ARTIFACT_CATALOG class rolls up into, so the
# catalog's per-class importance metadata drives the coarse ``not_examined``
# signal. A catalog class with no coarse home (none today) is simply ignored for
# this path.
_CATALOG_TO_COARSE: dict[str, str] = {
    "mft": "disk",
    "usn": "disk",
    "amcache": "registry",
    "registry_hives": "registry",
    "prefetch": "disk",
    "lnk": "lnk_jumplist",
    "browser_history": "network",
    "pcap": "network",
    "memory": "memory",
    "security": "disk",
    "system": "disk",
    "powershell_operational": "disk",
    "dns_client": "network",
    "sysmon": "disk",
    "task_scheduler": "disk",
}


def _coarse_gap_classes() -> frozenset[str]:
    """Coarse classes that are high/critical importance per the catalog.

    A coarse class is "important" if ANY fine catalog class rolling up into it is
    high/critical, so a coarse class inherits the strongest importance of its
    members. These are the classes whose absence is worth flagging as
    not-examined.
    """
    important: set[str] = set()
    for fine, meta in ARTIFACT_CATALOG.items():
        coarse = _CATALOG_TO_COARSE.get(fine)
        if coarse is not None and meta["importance"] in GAP_IMPORTANCE:
            important.add(coarse)
    return frozenset(important)


def normalize_source(token: str) -> Optional[str]:
    """Map one finding ``artifact_sources`` token to a coarse class or None.

    Args:
        token: A single artifact-source string a detector stamped on a finding.

    Returns:
        The coarse class name, or None when the token has no coarse mapping.
    """
    if not token:
        return None
    return _SOURCE_TO_COARSE.get(token.lower())


def finding_supplied_class(finding: Any) -> frozenset[str]:
    """The distinct coarse classes one finding cites via its artifact sources.

    Args:
        finding: A finding carrying an ``artifact_sources`` list.

    Returns:
        The frozenset of coarse classes the finding cites (unmappable tokens
        dropped).
    """
    classes: set[str] = set()
    for token in getattr(finding, "artifact_sources", None) or []:
        coarse = normalize_source(str(token))
        if coarse is not None:
            classes.add(coarse)
    return frozenset(classes)


@dataclass(frozen=True)
class HardenCoverage:
    """The harden-path coverage assessment.

    Attributes:
        uncited: Coarse classes supplied this run that no finding cites, sorted.
            A supplied-but-uncited class is a blind spot: it was parsed but drew
            no conclusion.
        not_examined: High/critical coarse classes whose evidence was not
            supplied this run, sorted. Their silence is not a clean result.
        supplied: The coarse classes supplied this run, sorted (echoed for the
            report so a reader sees the coverage denominator).
    """

    uncited: tuple[str, ...]
    not_examined: tuple[str, ...]
    supplied: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "uncited": list(self.uncited),
            "not_examined": list(self.not_examined),
            "supplied": list(self.supplied),
        }


def harden_coverage(
    findings: list[Any],
    supplied_classes: set[str] | None = None,
) -> HardenCoverage:
    """Assess coverage for one harden-path run.

    Args:
        findings: The findings the run emitted (only ``artifact_sources`` read).
        supplied_classes: The coarse classes whose evidence was supplied+parsed
            this run (the CLI derives this from which artifact flags were given).
            Values outside :data:`COARSE_CLASSES` are ignored. ``None`` (or an
            empty set) means "nothing declared supplied": no class can be uncited,
            and every important class is not-examined -- an honest all-blind run,
            not a vacuous clean pass.

    Returns:
        A HardenCoverage with the ``uncited`` blind-spots and the ``not_examined``
        important-but-absent classes. Never mutates ``findings``.
    """
    supplied = {c for c in (supplied_classes or set()) if c in COARSE_CLASSES}

    cited: set[str] = set()
    for finding in findings:
        cited |= finding_supplied_class(finding)

    uncited = supplied - cited
    not_examined = _coarse_gap_classes() - supplied

    return HardenCoverage(
        uncited=tuple(sorted(uncited)),
        not_examined=tuple(sorted(not_examined)),
        supplied=tuple(sorted(supplied)),
    )
