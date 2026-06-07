"""Case-agnostic finding categories.

Every detector emits findings tagged with one of these categories. The label is
chosen by the artifact signatures that fired, not by the analyst's prior belief
about what the image contains. That keeps acceptance tests artifact-centric: a
test can assert `category == FindingCategory.DATA_EXFILTRATION` for any image
that exhibits the pattern, regardless of whether the case is Jean, ransomware
staging, or IP theft.

Adding a new category is a deliberate act: it changes the vocabulary the whole
system uses. Prefer mapping new signals onto existing categories unless the
signal is genuinely outside all of them.
"""

from __future__ import annotations

from enum import StrEnum


class FindingCategory(StrEnum):
    """Fixed, case-agnostic taxonomy of what a finding represents.

    Values are lowercase_snake strings so they round-trip cleanly through JSON
    without enum-specific serialization logic in the CLI.
    """

    DATA_EXFILTRATION = "data_exfiltration"
    """Evidence that sensitive data left the system.

    Examples: on-disk file bytes matching an outbound email attachment, an
    archive staged then uploaded, a file copied to removable media and the
    media subsequently disconnected.
    """

    TIMELINE_TAMPERING = "timeline_tampering"
    """Evidence that artifact timestamps have been manipulated.

    Examples: $STANDARD_INFORMATION older than $FILE_NAME, event log gaps,
    prefetch run times that predate executable creation.
    """

    PROCESS_INJECTION = "process_injection"
    """Evidence of code running inside a process that did not load it.

    Examples: unbacked executable memory, hollowed processes, DLL side-loading
    with mismatched parent-child execution records.
    """

    CREDENTIAL_THEFT = "credential_theft"
    """Evidence of access to authentication material.

    Examples: LSASS memory read by a non-system process, SAM/SECURITY hive
    copies outside their canonical paths, Kerberos ticket dumps.
    """

    PERSISTENCE = "persistence"
    """Evidence that an attacker installed a mechanism to survive reboot.

    Examples: new Run keys, scheduled tasks, service installations, WMI
    subscriptions, startup folder drops.
    """

    LATERAL_MOVEMENT = "lateral_movement"
    """Evidence of movement between hosts in the environment.

    Examples: Sysmon network connections to internal RFC1918 targets paired
    with remote-execution artifacts (PsExec, WMIExec, WinRM), admin share
    writes followed by service creation on the remote host.
    """

    ANTI_FORENSICS = "anti_forensics"
    """Evidence of active efforts to hide activity from an investigator.

    Examples: wiped partition tables, cleared event logs, Prefetch directory
    deletion, USN journal truncation, timestomping (also tagged separately as
    timeline_tampering when timestamps are the specific signal).
    """

    MALWARE_CLASSIFICATION = "malware_classification"
    """Evidence that a file matches a known malware signature or family marker.

    Examples: a packed binary matching a UPX signature, a script matching a
    known dropper's YARA rule, an archive containing a sample flagged by a
    community ruleset. Emitted by the YARA detector; kept distinct from
    PERSISTENCE and DATA_EXFILTRATION because the signal is the file content
    itself, not the file's installed effect.
    """

    RECONNAISSANCE = "reconnaissance"
    """Evidence of system or network enumeration activity.

    Examples: netstat, ipconfig, whoami, systeminfo, net user/group commands,
    domain controller enumeration, process listing, network share discovery.
    """

    CREDENTIAL_ACCESS = "credential_access"
    """Evidence of credential dumping or authentication material access.

    Examples: mimikatz execution, LSASS memory dumps, SAM/SYSTEM hive exports,
    NTDS.dit extraction, volume shadow copy manipulation for credential access.
    """

    EXECUTION = "execution"
    """Evidence of command or script execution via native interpreters.

    Examples: PowerShell with suspicious arguments, encoded commands, download
    cradles, script-based malware execution, living-off-the-land binary abuse.
    """

    COMMAND_AND_CONTROL = "command_and_control"
    """Evidence of communication with attacker infrastructure.

    Examples: beaconing patterns, PowerShell download strings, malware downloads,
    remote file transfers, suspicious network connections to external IPs.
    """

    ANALYSIS_GAP = "analysis_gap"
    """Evidence that the analysis itself is incomplete or unreliable.

    Not an attacker behavior — a meta-finding about evidence reliability, so
    an operator never mistakes a tooling failure for a clean result. Examples:
    a Volatility list-walk plugin (pslist/cmdline/malfind) returning zero rows
    while a pool-scan plugin (psscan/netscan) finds processes, which means the
    active-process list did not traverse (KDBG / symbol mismatch) and any
    "no injection / no suspicious cmdline" conclusion is unsound. Kept distinct
    from every attack category because it must not be scored as a detection
    (true or false positive) — it describes the engine's blind spot, not the
    host's behavior.
    """

    UNKNOWN = "unknown"
    """Escape hatch for findings that do not yet map to a named category.

    Use sparingly. If a detector keeps emitting `unknown`, either the category
    vocabulary needs extending or the detector is too generic to be useful.
    """
