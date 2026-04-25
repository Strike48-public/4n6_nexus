"""Attack Pattern Detector - Detect malicious command line patterns.

Analyzes Event ID 4688 command lines for:
- Reconnaissance commands
- PowerShell attack patterns
- Credential dumping
- Lateral movement
- LOLBins abuse
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List


class AttackTechnique(Enum):
    """MITRE ATT&CK technique categories."""

    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    EXFILTRATION = "exfiltration"
    EXECUTION = "execution"
    COMMAND_AND_CONTROL = "command_and_control"


@dataclass
class AttackPattern:
    """Represents a detected attack pattern in command line."""

    technique: AttackTechnique
    pattern_name: str
    description: str
    confidence: float  # 0.0-1.0
    severity: str  # critical, high, medium, low
    mitre_id: Optional[str] = None  # e.g., T1059.001


class AttackPatternDetector:
    """Detects malicious patterns in process command lines."""

    # Reconnaissance patterns (T1087, T1082, T1016)
    RECON_PATTERNS = [
        (
            r"netstat\s+(-[aonr]+|--all)",
            "Network connection enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1049",
            0.85,
        ),
        (
            r"ipconfig\s+(/all)?",
            "Network configuration enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1016",
            0.80,
        ),
        (
            r"whoami(\s+/all)?",
            "User identity enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1033",
            0.85,
        ),
        (
            r"systeminfo",
            "System information enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1082",
            0.85,
        ),
        (
            r"net\s+(user|localgroup|group|accounts|share)",
            "Account/share enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1087",
            0.90,
        ),
        (
            r"tasklist",
            "Process enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1057",
            0.75,
        ),
        (
            r"quser|query\s+user",
            "Logged-on user enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1033",
            0.85,
        ),
        (
            r"nltest\s+/dclist",
            "Domain controller enumeration",
            AttackTechnique.RECONNAISSANCE,
            "T1018",
            0.90,
        ),
    ]

    # PowerShell attack patterns (T1059.001)
    POWERSHELL_ATTACK_PATTERNS = [
        (
            r"(IEX|Invoke-Expression).*\(.*downloadstring",
            "PowerShell download cradle",
            AttackTechnique.EXECUTION,
            "T1059.001",
            0.95,
        ),
        (
            r"-e(nc(odedcommand)?|nco)\s+[A-Za-z0-9+/=]{20,}",
            "Encoded PowerShell command",
            AttackTechnique.DEFENSE_EVASION,
            "T1027",
            0.90,
        ),
        (
            r"-nop(rofile)?.*-w(indowstyle)?\s+hidden",
            "Hidden PowerShell execution",
            AttackTechnique.DEFENSE_EVASION,
            "T1564",
            0.85,
        ),
        (
            r"Invoke-Mimikatz",
            "Mimikatz credential dumping",
            AttackTechnique.CREDENTIAL_ACCESS,
            "T1003.001",
            0.98,
        ),
        (
            r"Invoke-ReflectivePEInjection",
            "Reflective PE injection",
            AttackTechnique.DEFENSE_EVASION,
            "T1055",
            0.95,
        ),
        (
            r"DownloadFile.*\.exe",
            "Malware download via PowerShell",
            AttackTechnique.COMMAND_AND_CONTROL,
            "T1105",
            0.90,
        ),
    ]

    # Credential dumping patterns (T1003)
    CREDENTIAL_DUMP_PATTERNS = [
        (
            r"mimikatz",
            "Mimikatz credential dumping",
            AttackTechnique.CREDENTIAL_ACCESS,
            "T1003.001",
            0.98,
        ),
        (
            r"procdump.*lsass",
            "LSASS memory dump",
            AttackTechnique.CREDENTIAL_ACCESS,
            "T1003.001",
            0.95,
        ),
        (
            r"reg\s+(save|export).*\b(SAM|SYSTEM|SECURITY)\b",
            "Registry hive export (credential access)",
            AttackTechnique.CREDENTIAL_ACCESS,
            "T1003.002",
            0.92,
        ),
        (
            r"vssadmin.*create\s+shadow",
            "Volume shadow copy (credential access)",
            AttackTechnique.CREDENTIAL_ACCESS,
            "T1003.003",
            0.85,
        ),
        (
            r"ntdsutil.*ifm.*create",
            "NTDS.dit extraction",
            AttackTechnique.CREDENTIAL_ACCESS,
            "T1003.003",
            0.95,
        ),
    ]

    # Lateral movement patterns (T1021, T1570)
    LATERAL_MOVEMENT_PATTERNS = [
        (
            r"psexec",
            "PsExec lateral movement",
            AttackTechnique.LATERAL_MOVEMENT,
            "T1021.002",
            0.95,
        ),
        (
            r"wmic.*process\s+call\s+create",
            "WMI remote execution",
            AttackTechnique.LATERAL_MOVEMENT,
            "T1047",
            0.90,
        ),
        (
            r"sc\s+\\\\[^\\]+\s+(create|start)",
            "Remote service manipulation",
            AttackTechnique.LATERAL_MOVEMENT,
            "T1021.002",
            0.88,
        ),
        (
            r"powershell.*-ComputerName.*Invoke-Command",
            "PowerShell remoting",
            AttackTechnique.LATERAL_MOVEMENT,
            "T1021.006",
            0.85,
        ),
    ]

    # LOLBins abuse patterns (T1218)
    LOLBINS_PATTERNS = [
        (
            r"certutil.*-urlcache.*http",
            "Certutil download abuse",
            AttackTechnique.DEFENSE_EVASION,
            "T1105",
            0.90,
        ),
        (
            r"bitsadmin\s+/transfer",
            "BITSAdmin download abuse",
            AttackTechnique.DEFENSE_EVASION,
            "T1105",
            0.88,
        ),
        (
            r"rundll32.*javascript:",
            "Rundll32 JavaScript abuse",
            AttackTechnique.DEFENSE_EVASION,
            "T1218.011",
            0.92,
        ),
        (
            r"mshta.*http",
            "MSHTA remote execution",
            AttackTechnique.DEFENSE_EVASION,
            "T1218.005",
            0.90,
        ),
        (
            r"regsvr32.*\/[siu].*http",
            "Regsvr32 Squiblydoo attack",
            AttackTechnique.DEFENSE_EVASION,
            "T1218.010",
            0.95,
        ),
    ]

    # Persistence patterns (T1053, T1547)
    PERSISTENCE_PATTERNS = [
        (
            r"schtasks\s+/create",
            "Scheduled task creation",
            AttackTechnique.PERSISTENCE,
            "T1053.005",
            0.80,
        ),
        (
            r"reg\s+add.*\\Run",
            "Registry Run key persistence",
            AttackTechnique.PERSISTENCE,
            "T1547.001",
            0.85,
        ),
        (
            r"sc\s+create",
            "Service creation",
            AttackTechnique.PERSISTENCE,
            "T1543.003",
            0.75,
        ),
        (
            r"wmic.*SHADOWCOPY.*DELETE",
            "Shadow copy deletion (anti-forensics)",
            AttackTechnique.DEFENSE_EVASION,
            "T1490",
            0.95,
        ),
    ]

    # Data staging/exfiltration patterns (T1560, T1041)
    EXFILTRATION_PATTERNS = [
        (
            r"(7z|zip|rar|winrar).*-p\w+",
            "Password-protected archive creation",
            AttackTechnique.EXFILTRATION,
            "T1560.001",
            0.85,
        ),
        (
            r"ftp.*-s:",
            "Automated FTP upload",
            AttackTechnique.EXFILTRATION,
            "T1048.002",
            0.88,
        ),
    ]

    def __init__(self):
        """Initialize attack pattern detector."""
        self.all_patterns = (
            self.RECON_PATTERNS
            + self.POWERSHELL_ATTACK_PATTERNS
            + self.CREDENTIAL_DUMP_PATTERNS
            + self.LATERAL_MOVEMENT_PATTERNS
            + self.LOLBINS_PATTERNS
            + self.PERSISTENCE_PATTERNS
            + self.EXFILTRATION_PATTERNS
        )

    def analyze_command_line(self, command_line: str) -> List[AttackPattern]:
        """Analyze a command line for attack patterns.

        Args:
            command_line: Full command line string from Event ID 4688

        Returns:
            List of detected attack patterns (empty if none found)
        """
        if not command_line:
            return []

        patterns_detected = []

        # Normalize command line for case-insensitive matching
        cmd_lower = command_line.lower()

        for pattern_regex, description, technique, mitre_id, confidence in (
            self.all_patterns
        ):
            if re.search(pattern_regex, cmd_lower, re.IGNORECASE):
                # Determine severity based on technique and confidence
                if technique in (
                    AttackTechnique.CREDENTIAL_ACCESS,
                    AttackTechnique.LATERAL_MOVEMENT,
                ):
                    severity = "critical"
                elif technique == AttackTechnique.DEFENSE_EVASION and confidence >= 0.90:
                    severity = "critical"
                elif technique in (
                    AttackTechnique.PERSISTENCE,
                    AttackTechnique.EXECUTION,
                ):
                    severity = "high"
                elif technique == AttackTechnique.RECONNAISSANCE:
                    severity = "medium"
                else:
                    severity = "medium"

                patterns_detected.append(
                    AttackPattern(
                        technique=technique,
                        pattern_name=description,
                        description=f"{description}: {command_line[:200]}",
                        confidence=confidence,
                        severity=severity,
                        mitre_id=mitre_id,
                    )
                )

        return patterns_detected

    def get_highest_severity_pattern(
        self, patterns: List[AttackPattern]
    ) -> Optional[AttackPattern]:
        """Get the highest severity pattern from a list.

        Args:
            patterns: List of detected patterns

        Returns:
            Highest severity pattern, or None if list is empty
        """
        if not patterns:
            return None

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        return max(patterns, key=lambda p: (severity_order.get(p.severity, 0), p.confidence))
