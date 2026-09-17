"""Randomized adversarial recall harness (SFE-fibx.3).

Ported from FindEvil's ``red_team_loop.py`` and ADAPTED for our deterministic
engine. FindEvil plants files onto a filesystem and runs a live LLM agent; our
detection is deterministic Python over CSV/JSON fixtures, so "reset-snapshot →
random-plant → score → teardown" becomes: each iteration procedurally GENERATES
fresh fixtures with randomized executable names + RFC-5737 C2 IPs that satisfy
the engine's *structural* detection rule (MFT-modify-after-prefetch + matching
Event 4688), runs the REAL engine over a temp dir, scores recall + hallucination,
and discards the fixtures.

Why this is a stronger number than F1=1.00 on the frozen 16:
  * The causality engine fires on STRUCTURE (``$SI`` mtime after prefetch
    last-run by >300 s, matched by name across MFT+Prefetch), not on the literal
    names ``ransom_note.exe`` etc. A detector that memorized the 16 fixture names
    would score recall<1.0 here; one that generalizes scores 1.0.
  * Hallucination is measured two ways: any IPv4 in output that was never planted
    (RFC-5737 planting makes real IPs stand out), and cross-iteration marker
    pollution (an earlier iteration's unique random name surfacing in a later
    one ⇒ leaked global state / hardcoded emit).

Determinism: everything is seeded, so a given ``seed`` reproduces the exact same
score — the property that lets CI gate on it. This module is benchmark-only: it
NEVER touches the F1 recall harness or the committed scenario tree; it writes only
to a caller-supplied :class:`tempfile.TemporaryDirectory`.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# RFC-5737 documentation ranges. Planted C2 IPs come from these blocks so that a
# real-world (routable) IP appearing in engine output is unambiguously fabricated.
_RFC5737_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# The engine's causality rule: an $SI modification later than the prefetch
# last-run by MORE than this tolerance is a violation. We plant well beyond it.
_CAUSALITY_TOLERANCE_S = 300


@dataclass(frozen=True)
class PlantedScenario:
    """One procedurally-generated adversarial scenario.

    ``fixtures`` maps a relative filename (e.g. ``mft.csv``) to its full CSV text.
    ``malicious`` is the set of executable names the engine MUST flag (lowercased);
    empty for negative controls and planted-false-IOC cases. ``planted_ips`` is the
    set of IPv4 strings deliberately embedded, so the scorer can tell a planted IP
    from a fabricated one.
    """

    attack_class: str
    fixtures: dict[str, str]
    malicious: frozenset[str]
    # Allowlist: every IPv4 deliberately written into the fixtures. Surfacing one
    # of these is never counted as a fabrication (FindEvil's "not planted" rule).
    planted_ips: frozenset[str] = field(default_factory=frozenset)
    # Recall markers: the subset of planted IPs the engine MUST surface. Empty for
    # planters whose IPs ride in evidence but are not expected to be flagged (the
    # causality command-line IP, the false-IOC bait); == planted_ips for memory-C2.
    expected_ips: frozenset[str] = field(default_factory=frozenset)
    unique_markers: frozenset[str] = field(default_factory=frozenset)
    # Pre-parsed Volatility plugin fixtures: plugin_key -> relative JSON path.
    # Only the memory-C2 planter populates this; the causality/negative/false-IOC
    # planters leave it empty (they exercise the MFT/Prefetch/EVTX path).
    memory_fixtures: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RedTeamObservation:
    """What the engine emitted for one planted scenario, reduced to scorable sets."""

    flagged: frozenset[str]
    ipv4s: frozenset[str]


@dataclass(frozen=True)
class IterationScore:
    """Scored outcome for one planted+observed iteration."""

    attack_class: str
    recall: float
    missed: frozenset[str]
    false_positives: frozenset[str]
    hallucinated_ips: frozenset[str]
    polluted_markers: frozenset[str]

    def to_dict(self) -> dict:
        return {
            "attack_class": self.attack_class,
            "recall": round(self.recall, 4),
            "missed": sorted(self.missed),
            "false_positives": sorted(self.false_positives),
            "hallucinated_ips": sorted(self.hallucinated_ips),
            "polluted_markers": sorted(self.polluted_markers),
        }


@dataclass(frozen=True)
class RedTeamReport:
    """Aggregate outcome across a seeded multi-iteration run."""

    iterations: int
    seed: int
    mean_recall: float
    total_false_positives: int
    total_hallucinated_ips: int
    total_polluted_markers: int
    attack_classes_seen: frozenset[str]
    per_iteration: tuple[IterationScore, ...]

    @property
    def passed(self) -> bool:
        """True only on a court-defensible clean run: perfect recall, zero over-call,
        zero fabricated IP, zero cross-iteration pollution."""
        return (
            self.mean_recall == 1.0
            and self.total_false_positives == 0
            and self.total_hallucinated_ips == 0
            and self.total_polluted_markers == 0
        )

    def to_dict(self) -> dict:
        return {
            "iterations": self.iterations,
            "seed": self.seed,
            "mean_recall": round(self.mean_recall, 4),
            "total_false_positives": self.total_false_positives,
            "total_hallucinated_ips": self.total_hallucinated_ips,
            "total_polluted_markers": self.total_polluted_markers,
            "attack_classes_seen": sorted(self.attack_classes_seen),
            "passed": self.passed,
            "per_iteration": [s.to_dict() for s in self.per_iteration],
        }


# ─── planters ────────────────────────────────────────────────────────────────


def _rand_ip(rng) -> str:
    """A random host address inside a randomly-chosen RFC-5737 block."""
    net = rng.choice(_RFC5737_NETS)
    host = rng.randint(1, 254)
    return str(net.network_address + host)


def _rand_name(rng, *, evil_looking: bool = False) -> str:
    """A randomized, non-fixture executable name.

    ``evil_looking`` biases toward names an over-eager name-heuristic would flag
    (the TRUDI false-IOC bait), without changing the *structure* of the fixture.
    """
    token = "".join(rng.choice("0123456789abcdef") for _ in range(8))
    if evil_looking:
        stem = rng.choice(("svch0st", "lsass_", "rundl132", "mimidump", "beacon"))
        return f"{stem}{token[:4]}.exe"
    stem = rng.choice(("proc", "task", "svc", "job", "mod", "app"))
    return f"{stem}_{token}.exe"


def _mft_row(name: str, created: datetime, modified: datetime) -> str:
    """One MFT CSV row. Only the columns the parser reads are populated."""
    c, m = created.isoformat() + "Z", modified.isoformat() + "Z"
    return (
        f"40000,{name},C:\\Users\\victim\\AppData,131072,False,True,"
        f"{c},{m},{m},{m},{c},{c},{c},{c}"
    )


def _prefetch_row(name: str, last_run: datetime) -> str:
    """One Prefetch CSV row for ``name`` executed at ``last_run``."""
    up = name.upper()
    return (
        f"{up}-A1B2C3D4.pf,{up},1,{last_run.isoformat()}Z,,,,,,,,"
        f"A1B2C3D4,C:,1A2B-3C4D,C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL"
    )


def _evtx_row(name: str, ran_at: datetime, record_id: int, c2_ip: str) -> str:
    """One 4688 process-creation row. The C2 IP rides in the command-line column
    so a network-aware detector could surface it; the causality engine ignores it."""
    path = f"C:\\Users\\victim\\AppData\\{name}"
    cmd = f"{name} --c2 {c2_ip}"
    return (
        f"{ran_at.isoformat()}Z,4688,{record_id},VICTIM-PC,Security,Information,"
        f"S-1-5-21-1,{path},%%1936,0xBEE1,C:\\Windows\\explorer.exe,0xF001,{cmd},"
        f"Process Create (Event ID 4688)"
    )


_MFT_HEADER = (
    "EntryNumber,FileName,ParentPath,FileSize,IsDirectory,InUse,"
    "Created0x10,Modified0x10,Accessed0x10,Changed0x10,"
    "Created0x30,Modified0x30,Accessed0x30,Changed0x30"
)
_PREFETCH_HEADER = (
    "SourceFilename,Executable,RunCount,LastRunTime,PreviousRunTime0,"
    "PreviousRunTime1,PreviousRunTime2,PreviousRunTime3,PreviousRunTime4,"
    "PreviousRunTime5,PreviousRunTime6,Hash,Volume0Name,Volume0Serial,FilesLoaded"
)
_EVTX_HEADER = (
    "TimeCreated,EventId,RecordId,Computer,Channel,Level,UserId,"
    "PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,"
    "PayloadData6,MapDescription"
)


def _base_time(rng) -> datetime:
    """A deterministic, seed-varied base timestamp (no wall clock)."""
    day = rng.randint(1, 27)
    hour = rng.randint(0, 20)
    return datetime(2025, 3, day, hour, 0, 0)


def _assemble(mft: list[str], prefetch: list[str], evtx: list[str]) -> dict[str, str]:
    """Join header + rows into the three fixture files the harness consumes."""
    return {
        "mft.csv": "\n".join([_MFT_HEADER, *mft]) + "\n",
        "prefetch.csv": "\n".join([_PREFETCH_HEADER, *prefetch]) + "\n",
        "evtx.csv": "\n".join([_EVTX_HEADER, *evtx]) + "\n",
    }


def plant_causality_violation(rng) -> PlantedScenario:
    """Plant N randomly-named executables that each show a real causality violation.

    Each exe is modified (``$SI``) well AFTER its prefetch last-run and after its
    4688 execution, so the engine's structural rule fires regardless of the name.
    """
    n = rng.randint(2, 4)
    base = _base_time(rng)
    c2 = _rand_ip(rng)
    mft, prefetch, evtx = [], [], []
    names: set[str] = set()
    for i in range(n):
        name = _rand_name(rng)
        while name in names:
            name = _rand_name(rng)
        names.add(name)
        created = base + timedelta(minutes=i)
        ran = created + timedelta(minutes=10)
        # Modify well beyond the 300 s tolerance AFTER execution ⇒ violation.
        modified = ran + timedelta(minutes=30)
        mft.append(_mft_row(name, created, modified))
        prefetch.append(_prefetch_row(name, ran))
        evtx.append(_evtx_row(name, ran, 40000 + i, c2))
    return PlantedScenario(
        attack_class="causality_violation",
        fixtures=_assemble(mft, prefetch, evtx),
        malicious=frozenset(n.lower() for n in names),
        planted_ips=frozenset({c2}),
        unique_markers=frozenset(n.lower() for n in names),
    )


def plant_negative_control(rng) -> PlantedScenario:
    """Plant benign executables with NO causality violation (mtime before run).

    The engine must flag nothing. A flag here is a false positive.
    """
    n = rng.randint(2, 4)
    base = _base_time(rng)
    mft, prefetch, evtx = [], [], []
    names: set[str] = set()
    for i in range(n):
        name = _rand_name(rng)
        while name in names:
            name = _rand_name(rng)
        names.add(name)
        created = base + timedelta(minutes=i)
        modified = created + timedelta(minutes=2)  # modified BEFORE it ran
        ran = modified + timedelta(minutes=30)
        mft.append(_mft_row(name, created, modified))
        prefetch.append(_prefetch_row(name, ran))
        evtx.append(_evtx_row(name, ran, 50000 + i, "10.0.0.5"))
    return PlantedScenario(
        attack_class="negative_control",
        fixtures=_assemble(mft, prefetch, evtx),
        malicious=frozenset(),
        planted_ips=frozenset(),  # private RFC-1918 noise only; nothing to defend
        unique_markers=frozenset(n.lower() for n in names),
    )


def plant_false_ioc(rng) -> PlantedScenario:
    """TRUDI-style planted false IOC: a suspicious NAME but benign STRUCTURE.

    The exe is named like malware (``svch0st…``) and its command line carries an
    RFC-5737 IP, but it was modified BEFORE it ran — no causality violation. A
    name-anchoring analyst would flag it; the structural engine must not.
    """
    base = _base_time(rng)
    name = _rand_name(rng, evil_looking=True)
    c2 = _rand_ip(rng)
    created = base
    modified = created + timedelta(minutes=1)  # before run ⇒ no violation
    ran = modified + timedelta(minutes=45)
    fixtures = _assemble(
        [_mft_row(name, created, modified)],
        [_prefetch_row(name, ran)],
        [_evtx_row(name, ran, 60000, c2)],
    )
    return PlantedScenario(
        attack_class="false_ioc",
        fixtures=fixtures,
        malicious=frozenset(),
        # The IP is present in evidence but is a BENIGN plant: the engine must not
        # escalate it. It is NOT in planted_ips-to-defend; if the engine surfaces
        # it as a finding-anchor that is a (name/IP) anchoring false positive.
        planted_ips=frozenset(),
        unique_markers=frozenset({name.lower()}),
    )


def plant_memory_c2(rng) -> PlantedScenario:
    """Plant a LOLBAS-owned netscan socket to a randomized RFC-5737 C2 endpoint.

    This is the ONLY planter that exercises a real engine path which surfaces an
    IPv4 into a finding (the memory detector's exfil/C2 finding). It makes the
    RFC-5737 hallucination heuristic load-bearing on a REAL run rather than only
    in the grader-calibration meta-test: the planted C2 must be surfaced (recall)
    and no OTHER IPv4 may appear (no fabrication).
    """
    c2 = _rand_ip(rng)
    owner = rng.choice(("powershell.exe", "rundll32.exe", "mshta.exe"))
    pid = rng.randint(1000, 9999)
    netscan = [
        {
            "PID": pid,
            "Owner": owner,
            "Proto": "TCP",
            "LocalAddr": "10.0.0.42",
            "LocalPort": rng.randint(49152, 65535),
            "ForeignAddr": c2,
            "ForeignPort": 4444,
            "State": "ESTABLISHED",
        }
    ]
    return PlantedScenario(
        attack_class="memory_c2",
        fixtures={"windows_netscan.json": json.dumps(netscan)},
        # Scored as a memory_finding count, not a named executable — the socket's
        # C2 IP is the marker the scorer checks, so ``malicious`` stays empty and
        # recall/FP are asserted via the IP sets.
        malicious=frozenset(),
        planted_ips=frozenset({c2}),
        expected_ips=frozenset({c2}),
        unique_markers=frozenset({c2}),
        memory_fixtures={"windows_netscan": "windows_netscan.json"},
    )


# ─── engine bridge ────────────────────────────────────────────────────────────


def extract_observation(planted: PlantedScenario, tmp_dir: Path) -> RedTeamObservation:
    """Materialize ``planted`` under ``tmp_dir``, run the REAL engine, observe.

    Reuses the production scenario runner (``tests.scenario_harness.run_scenario``)
    over an in-memory ``ScenarioExpectation`` so the harness scores the SAME code
    path CI scores, not a reimplementation. Returns the flagged executables and
    every IPv4 that appears anywhere in the emitted findings.
    """
    # Imported lazily: the harness lives under tests/, so importing it at module
    # load would couple the package to the test tree.
    from tests.scenario_harness import ScenarioExpectation, run_scenario

    for rel, text in planted.fixtures.items():
        (tmp_dir / rel).write_text(text, encoding="utf-8")

    # A memory-only planter has no causality triple; leave those fixture fields
    # empty so run_scenario runs only the memory path. The CSV planters leave
    # ``memory_fixtures`` empty, so the memory path is skipped for them.
    has_causality = {"mft.csv", "prefetch.csv", "evtx.csv"} <= planted.fixtures.keys()
    expectation = ScenarioExpectation(
        name=f"redteam_{planted.attack_class}",
        directory=tmp_dir,
        malicious_executables=planted.malicious,
        description="procedurally-generated adversarial scenario",
        mft_fixture="mft.csv" if has_causality else "",
        prefetch_fixture="prefetch.csv" if has_causality else "",
        evtx_fixture="evtx.csv" if has_causality else "",
        memory_fixtures=dict(planted.memory_fixtures),
    )
    result = run_scenario(expectation)

    flagged = {n for n in result.detected_executables if n}
    ipv4s = _collect_ipv4s(result.findings)
    return RedTeamObservation(
        flagged=frozenset(flagged),
        ipv4s=frozenset(ipv4s),
    )


def _collect_ipv4s(findings) -> set[str]:
    """Every syntactically-valid IPv4 appearing in any finding's text/evidence."""
    found: set[str] = set()
    for finding in findings:
        blobs = [finding.title, finding.description, *finding.reasoning_chain]
        blobs.extend(str(v) for v in finding.evidence.values())
        for blob in blobs:
            for match in _IPV4_RE.findall(blob or ""):
                try:
                    ipaddress.ip_address(match)
                except ValueError:
                    continue
                found.add(match)
    return found


# ─── scorer ───────────────────────────────────────────────────────────────────


def _is_defensible_noise(ip: str) -> bool:
    """True for IPs a finding may legitimately mention without it being a
    fabrication: private/loopback/link-local ranges (RFC-1918 & friends).

    RFC-5737 documentation ranges are explicitly EXCLUDED even though Python's
    ``ipaddress`` classifies them as private (they sit in IANA's special-purpose
    registry). The planters use ONLY those ranges for C2, so treating them as
    noise would filter out the very fabrications this harness exists to catch —
    a non-planted RFC-5737 IP is a fabrication by construction. A planted one is
    already allowed upstream via ``planted.planted_ips`` before this check runs.
    """
    addr = ipaddress.ip_address(ip)
    if any(addr in net for net in _RFC5737_NETS):
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def score_iteration(
    planted: PlantedScenario,
    observed: RedTeamObservation,
    forbidden_markers: frozenset[str],
) -> IterationScore:
    """Score one planted+observed iteration.

    recall           = expected markers (malicious execs + expected C2 IPs)
                       surfaced in the engine output.
    false_positives  = flagged executables that were not planted-malicious.
    hallucinated_ips = IPv4s in output that were neither planted nor private noise.
    polluted_markers = a PRIOR iteration's unique marker (exec name OR C2 IP)
                       surfacing here — evidence of leaked global state.
    """
    flagged = observed.flagged
    malicious = planted.malicious

    # Recall spans two marker kinds: executable names AND expected C2 IPs. A
    # memory-C2 planter has no malicious exec, so its recall is measured purely on
    # whether the planted IP was surfaced.
    expected = malicious | planted.expected_ips
    surfaced = flagged | observed.ipv4s
    hits = expected & surfaced
    missed = expected - surfaced
    recall = len(hits) / len(expected) if expected else 1.0

    # Over-calling is measured on executable names only: flagging a benign exe is
    # a false positive. An IP appearing in output is scored via the IP sets below,
    # not here, so a legitimately-surfaced planted IP is never a false positive.
    false_positives = flagged - malicious

    hallucinated = {
        ip
        for ip in observed.ipv4s
        if ip not in planted.planted_ips and not _is_defensible_noise(ip)
    }
    polluted = (flagged | observed.ipv4s) & forbidden_markers

    return IterationScore(
        attack_class=planted.attack_class,
        recall=recall,
        missed=frozenset(missed),
        false_positives=frozenset(false_positives),
        hallucinated_ips=frozenset(hallucinated),
        polluted_markers=frozenset(polluted),
    )


# ─── loop ─────────────────────────────────────────────────────────────────────

# Round-robin the attack classes so a short seeded run exercises all four.
_PLANTERS = (
    ("causality_violation", plant_causality_violation),
    ("negative_control", plant_negative_control),
    ("false_ioc", plant_false_ioc),
    ("memory_c2", plant_memory_c2),
)


def run_red_team(iterations: int, seed: int) -> RedTeamReport:
    """Run the seeded reset→plant→engine→score→teardown loop ``iterations`` times.

    Each iteration draws a fresh planter (round-robin over the four classes),
    generates fixtures into a private temp dir, runs the real engine, scores, and
    tears the temp dir down. ``forbidden_markers`` accumulates every prior
    iteration's unique markers so cross-iteration pollution is detectable.
    """
    import random
    import tempfile

    rng = random.Random(seed)
    scores: list[IterationScore] = []
    seen_markers: set[str] = set()
    classes_seen: set[str] = set()

    for i in range(iterations):
        _, planter = _PLANTERS[i % len(_PLANTERS)]
        planted = planter(rng)
        forbidden = frozenset(seen_markers - planted.unique_markers)
        with tempfile.TemporaryDirectory(prefix="redteam-") as tmp:
            observed = extract_observation(planted, Path(tmp))
        scores.append(score_iteration(planted, observed, forbidden))
        seen_markers |= set(planted.unique_markers)
        classes_seen.add(planted.attack_class)

    n = len(scores)
    mean_recall = sum(s.recall for s in scores) / n if n else 1.0
    return RedTeamReport(
        iterations=iterations,
        seed=seed,
        mean_recall=mean_recall,
        total_false_positives=sum(len(s.false_positives) for s in scores),
        total_hallucinated_ips=sum(len(s.hallucinated_ips) for s in scores),
        total_polluted_markers=sum(len(s.polluted_markers) for s in scores),
        attack_classes_seen=frozenset(classes_seen),
        per_iteration=tuple(scores),
    )


# Default CI budget: enough iterations to exercise every attack class several
# times over while staying well under a second of engine work. Seeded so the
# score is reproducible run-to-run.
_CI_ITERATIONS = 24
_CI_SEED = 20260814


def main() -> None:
    """Run the seeded CI budget and print the report; exit non-zero on any failure.

    Deterministic and LLM-free, so it is safe to gate CI on. It NEVER touches the
    F1 recall harness or the committed scenario tree.
    """
    import json as _json
    import sys

    report = run_red_team(iterations=_CI_ITERATIONS, seed=_CI_SEED)
    print(_json.dumps(report.to_dict(), indent=2))
    if not report.passed:
        print("RED-TEAM HARNESS FAILED", file=sys.stderr)
        sys.exit(1)
    print(
        f"\nRED-TEAM PASS: {report.iterations} iterations, "
        f"mean_recall={report.mean_recall:.2f}, "
        f"0 FP / 0 fabricated-IP / 0 pollution across "
        f"{sorted(report.attack_classes_seen)}"
    )


if __name__ == "__main__":
    main()
