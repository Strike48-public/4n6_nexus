"""Benchmark corpus: hallucination/abstention ground truth (gallery idea #7).

Each case pairs the artifacts that MUST be flagged with two adversarial
dimensions the recall harness lacks:

  * ``false_positive_traps`` - benign artifacts an over-eager agent will wrongly
    flag (an Outlook updater, an AV self-scan, a legitimate admin logon).
  * ``negative_assertions`` - facts the agent must ACTIVELY prove absent (no C2
    beacon, no ransomware note) rather than stay silent about.

The corpus is deliberately small and hand-authored; it is the specificity/
abstention counterpart to the 23 recall scenarios, not a replacement. Grow it as
new over-calling failure modes are discovered.
"""

from __future__ import annotations

from .hallucination import BenchmarkCase

# Frozen ground truth. Kept as a module constant AND returned as a fresh list by
# load_corpus() so a caller can never mutate the canonical set.
BENCHMARK_CORPUS: tuple[BenchmarkCase, ...] = (
    BenchmarkCase(
        name="benign_updater_masquerade",
        # Real evil: a dropper. Trap: a legitimately-signed updater that runs from
        # a temp path and would fool a path-heuristic-only agent.
        malicious=frozenset({"dropper.exe"}),
        false_positive_traps=frozenset({"officeclicktorun.exe", "mpcmdrun.exe"}),
        negative_assertions=frozenset(),
    ),
    BenchmarkCase(
        name="clean_host_negative_assertions",
        # A genuinely clean host: nothing to flag, but the agent must PROVE the
        # absence of the things a lazy agent would simply not mention.
        malicious=frozenset(),
        false_positive_traps=frozenset(
            {"chrome_update.exe", "svchost.exe", "backup_job.exe"}
        ),
        negative_assertions=frozenset(
            {"no_c2_beacon", "no_ransomware_note", "no_credential_dumping"}
        ),
    ),
    BenchmarkCase(
        name="planted_obvious_bait",
        # Real evil is subtle; a decoy 'hacktool.exe' is planted to bait an agent
        # into the loud-but-wrong call while missing the quiet real one.
        malicious=frozenset({"svc_update_x.exe"}),
        false_positive_traps=frozenset({"totally_not_malware.exe", "hacktool.txt"}),
        negative_assertions=frozenset({"no_scheduled_task_persistence"}),
    ),
    BenchmarkCase(
        name="legit_admin_activity",
        # Legitimate administration that resembles lateral movement: a real admin
        # using psexec during a maintenance window. Must NOT be flagged as evil.
        malicious=frozenset(),
        false_positive_traps=frozenset({"psexec.exe", "admin_logon_4624"}),
        negative_assertions=frozenset({"no_pass_the_hash"}),
    ),
)


def load_corpus() -> list[BenchmarkCase]:
    """Return a fresh list of the benchmark cases (isolated from the constant)."""
    return list(BENCHMARK_CORPUS)
