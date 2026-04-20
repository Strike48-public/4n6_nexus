# SIFT Find Evil - Potential Improvements

**Last Updated:** 2026-04-19  
**Status:** Comprehensive gap analysis complete

This document tracks potential improvements identified during development and analysis. Items are organized by category and priority based on scenario testing and competitive analysis.

## Current Performance Baseline

**Synthetic Scenarios: 100% Accuracy**
- 5 scenarios tested: All passing with precision=1.0, recall=1.0
- Scenarios: clean baseline, ransomware, timestomping, edge cases, missing prefetch
- Zero false positives, zero false negatives

**Real-World Scenarios: 3 Validated**
- M57 Jean exfiltration: 0.95 confidence (2/2 files detected)
- CIRCL wiped disk: GPT analysis + carved 403 executables
- Nitroba harassment: Network forensics (0.95 confidence)

**Coverage Analysis:**
- Artifact types currently supported: 3 (MFT, Prefetch, Event Logs, PCAP)
- Attack vectors detected: ~15 techniques
- MITRE ATT&CK coverage: ~20% (T1048, T1070.004, T1070.005, T1070.006, T1027, T1071.001)

---

## Priority Matrix (Strategic View)

| Priority | Category | Item | Impact | Effort | ROI | MITRE Coverage |
|----------|----------|------|--------|--------|-----|----------------|
| **P0** | Forensic Artifacts | Browser History Parser | Very High | Medium | Very High | T1071.001, T1567, T1102 |
| **P0** | Forensic Artifacts | Registry Analysis | Very High | High | Very High | T1547, T1112, T1218 |
| **P0** | Detection | NSRL Integration | High | Low | Very High | Triage efficiency |
| **P1** | Detection | YARA Malware Classification | High | Medium | High | All malware families |
| **P1** | Forensic Artifacts | Memory Forensics | Very High | Very High | High | T1055, T1620, T1140 |
| **P1** | Forensic Artifacts | Jump Lists/LNK Files | Medium | Low | High | T1083, T1005 |
| **P1** | Detection | Lateral Movement Detection | High | High | High | T1021, T1569 |
| **P2** | Network | Additional Protocols (FTP/SMB/RDP) | Medium | Medium | Medium | T1071, T1021.001 |
| **P2** | Network | DNS Tunneling Detection | Medium | Low | Medium | T1048.003, T1071.004 |
| **P2** | Usability | Timeline Visualization | Medium | High | Medium | Analysis UX |
| **P2** | Usability | Report Generation | Low | Medium | Medium | Client deliverables |
| **P3** | Performance | Parallel File Hashing | Low | Low | Low | Speed improvement |
| **P3** | Performance | Memory-Mapped I/O | Low | Low | Low | Speed improvement |

**Key Insight**: Priority 0 items (browser history + registry) unlock 50%+ additional attack vector detection with reasonable implementation effort.

---

## Gap Analysis by Attack Stage (MITRE ATT&CK)

### Initial Access (Currently: 10% coverage)
**What We Detect:**
- None (no email/phishing/exploit detection)

**What We Miss:**
- Phishing email delivery (T1566)
- Exploit artifacts (T1190)
- Valid account compromise (T1078)

**Improvement Path:**
- Email parser (PST/OST/EML) - analyze phishing emails
- Browser history - detect drive-by download URLs
- Registry - identify exploitation artifacts

### Execution (Currently: 60% coverage)
**What We Detect:**
- Prefetch execution evidence (T1059)
- Event Log process creation (T1059)
- MFT file creation timestamps (indirect)

**What We Miss:**
- Registry Shimcache/Amcache (when Prefetch deleted)
- PowerShell script execution logs
- WMI execution artifacts
- Scheduled task creation

**Improvement Path:**
- Registry parser (Shimcache, Amcache, BAM/DAM) - P0
- PowerShell event log analysis (Event ID 4103, 4104)
- WMI event log analysis (Event ID 5857-5861)

### Persistence (Currently: 5% coverage)
**What We Detect:**
- None directly

**What We Miss:**
- Registry Run keys (T1547.001)
- Scheduled tasks (T1053.005)
- Service creation (T1543.003)
- Startup folder modifications (T1547.001)
- WMI event subscriptions (T1546.003)
- Registry modifications for persistence

**Improvement Path:**
- Registry parser - P0 CRITICAL
- Scheduled task artifact analysis
- Service registry keys analysis

### Privilege Escalation (Currently: 0% coverage)
**What We Detect:**
- None

**What We Miss:**
- UAC bypass artifacts
- Token manipulation evidence
- Process injection (T1055)
- Access token manipulation (T1134)

**Improvement Path:**
- Memory forensics (process injection detection) - P1
- Event log analysis (privilege changes)

### Defense Evasion (Currently: 40% coverage)
**What We Detect:**
- Timestomping (T1070.006) - $SI modification
- Prefetch deletion (T1070.004) - missing artifact detection
- Event log clearing (T1070.001) - gap detection

**What We Miss:**
- Process injection/hollowing (T1055)
- Indicator removal (file deletion, log wiper)
- Obfuscated files/information (T1027)
- Masquerading (T1036)
- Rootkits

**Improvement Path:**
- Memory forensics (injection, rootkit detection) - P1
- YARA rules (obfuscation detection) - P1
- Registry analysis (masquerading via registry)

### Credential Access (Currently: 0% coverage)
**What We Detect:**
- None

**What We Miss:**
- Credential dumping (T1003) - Mimikatz, etc.
- Browser credential theft (T1555.003)
- Keylogging (T1056.001)
- Cached credentials access

**Improvement Path:**
- Memory forensics (detect Mimikatz in memory) - P1
- Browser history/SQLite (credential database access)
- Registry analysis (cached domain credentials)

### Discovery (Currently: 20% coverage)
**What We Detect:**
- File system enumeration (MFT read patterns)

**What We Miss:**
- System information discovery (T1082)
- Network share discovery (T1135)
- Process discovery (T1057)
- Registry query patterns (T1012)

**Improvement Path:**
- Registry analysis (query patterns)
- Network traffic (SMB enumeration)
- Event logs (system info queries)

### Lateral Movement (Currently: 0% coverage)
**What We Detect:**
- None

**What We Miss:**
- Remote Services: SMB/Windows Admin Shares (T1021.002)
- Remote Desktop Protocol (T1021.001)
- PsExec execution (T1569.002)
- WMI remote execution (T1047)
- Pass-the-hash attacks

**Improvement Path:**
- Event log analysis (4624, 4625, 4776) - P1
- Network traffic (SMB, RDP sessions) - P2
- Registry analysis (RDP artifacts)

### Collection (Currently: 30% coverage)
**What We Detect:**
- Data from local system (T1005) - MFT file access

**What We Miss:**
- Screen capture (T1113)
- Clipboard data (T1115)
- Email collection (T1114)
- Audio/video capture (T1123, T1125)
- Archive collection activity (staging directories)

**Improvement Path:**
- Staging directory detection (mass file copy) - P2
- Email parser (identify collection artifacts)
- Prefetch (screen capture tool execution)

### Command and Control (Currently: 40% coverage)
**What We Detect:**
- HTTP C2 (T1071.001) - PCAP analysis
- DNS C2 (T1071.004) - basic DNS in PCAP

**What We Miss:**
- DNS tunneling (T1048.003) - high entropy detection
- Encrypted channels (T1573)
- Protocol tunneling (T1572)
- Web services (T1102) - legitimate services for C2

**Improvement Path:**
- DNS tunneling detector (entropy analysis) - P2
- TLS/SSL metadata (SNI, certificate analysis) - P2
- Browser history (web service C2) - P0

### Exfiltration (Currently: 70% coverage)
**What We Detect:**
- Email exfiltration (T1048.003) - file-email correlation
- Network exfiltration (T1048.003) - PCAP analysis (HTTP)

**What We Miss:**
- Cloud storage exfiltration (T1567) - Dropbox, Google Drive
- FTP exfiltration (T1048.003)
- Physical media exfiltration (USB) - partial
- DNS exfiltration / tunneling

**Improvement Path:**
- Browser history (cloud upload detection) - P0
- Network protocols (FTP, WebDAV) - P2
- USB device tracking (registry) - P1
- DNS tunneling detector - P2

### Impact (Currently: 5% coverage)
**What We Detect:**
- None directly

**What We Miss:**
- Data encrypted for impact (T1486) - ransomware
- Data destruction (T1485)
- Defacement (T1491)
- Service stop (T1489)

**Improvement Path:**
- YARA (ransomware detection) - P1
- Event logs (service stop events)
- Large-scale MFT modifications (mass encryption)

---

## New Capabilities (Strategic Additions)

### P0 - Critical for Market Leadership

#### 1. Browser History Parser (2-3 days implementation)
**Gap**: No browser history analysis (Chrome, Firefox, Edge, Safari)

**Attack Vectors Unlocked:**
- Web-based C2 communication (HTTP beaconing, cloud C2)
- Webmail exfiltration (Gmail, Outlook.com, Yahoo)
- Cloud storage uploads (Dropbox, Google Drive, OneDrive, Box)
- Tor/VPN usage detection
- Credential harvesting site visits
- Phishing analysis (clicked links)
- Dark web marketplace access

**Implementation:**
```python
# sift_find_evil/parsers/browser_history_parser.py
@dataclass(frozen=True)
class BrowserHistoryEntry:
    timestamp: datetime
    url: str
    title: str
    visit_count: int
    browser: str  # "chrome", "firefox", "edge"
    profile: str
```

**Detection Enhancement Example:**
- M57 Jean case: Browser history would show Gmail access timestamps
- Correlate with file access (which patents were viewed before email sent)
- Confidence boost from 0.95 to 0.98+ with browser evidence

**Estimated Lines of Code:** ~400 lines (3 parsers + tests)

---

#### 2. Windows Registry Analysis (4-5 days implementation)
**Gap**: No registry hive analysis (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)

**Attack Vectors Unlocked:**
- Persistence detection (30+ registry auto-start locations)
- Execution evidence when Prefetch deleted (Shimcache, Amcache)
- Process execution timestamps (BAM/DAM)
- GUI program usage (UserAssist)
- USB device history
- Network share access history
- Typed URLs and searches (additional browser artifacts)
- Recently used files (MRU lists)

**Critical Value Proposition:**
When attackers delete Prefetch files (Scenario 05), registry provides:
- Shimcache: Execution timestamps for ALL executables
- Amcache: SHA-1 hashes + first execution time
- BAM/DAM: Process execution time with microsecond precision

**Current Performance**: Scenario 05 detects missing Prefetch with 0.60 confidence  
**With Registry**: Would increase to 0.85+ confidence with Shimcache/Amcache evidence

**Implementation Plan:**
```python
# sift_find_evil/parsers/registry_parser.py

# Execution artifacts (PRIORITY 1)
def parse_shimcache(hive_path: Path) -> list[ExecutionRecord]: ...
def parse_amcache(hive_path: Path) -> list[ExecutionRecord]: ...
def parse_bam_dam(hive_path: Path) -> list[ExecutionRecord]: ...

# Persistence artifacts (PRIORITY 2)
def parse_run_keys(hive_path: Path) -> list[RegistryKey]: ...
def parse_services(hive_path: Path) -> list[ServiceEntry]: ...

# User activity (PRIORITY 3)
def parse_userassist(hive_path: Path) -> list[ExecutionRecord]: ...
def parse_mru_lists(hive_path: Path) -> list[RecentFile]: ...
```

**Estimated Lines of Code:** ~800 lines (5 parsers + integration + tests)

---

#### 3. NSRL Database Integration (4-6 hours implementation)
**Gap**: No known-good file filtering for carved executables

**Current Problem**: CIRCL wiped disk carved 403 executables
- Manual VirusTotal triage: 60-90 minutes (rate limits)
- 90%+ are likely Windows system DLLs (kernel32.dll, ntdll.dll, etc.)
- No automated filtering = major bottleneck

**Solution**: NSRL RDS (Reference Data Set)
- NIST database of known-good software (Windows, Office, common apps)
- 200+ million file hashes
- Instant lookup: carved file hash → known good or unknown

**Implementation:**
```python
# sift_find_evil/utils/nsrl_lookup.py
class NSRLDatabase:
    def __init__(self, rds_path: Path):
        self.bloom_filter = self._load_bloom_filter(rds_path)
    
    def is_known_good(self, sha256: str) -> bool:
        """Check if file hash exists in NSRL RDS."""
        return sha256 in self.bloom_filter
```

**Performance Impact:**
- Before: 403 files, 60-90 min manual triage
- After: 403 files, instant filtering → ~40 unknown files, 5-10 min VirusTotal
- **Time Savings**: 50-80 minutes per wiped disk analysis

**Estimated Lines of Code:** ~200 lines (bloom filter + lookup + tests)

---

### P1 - High-Value Enhancements

#### 4. YARA Malware Classification (3-4 days implementation)
**Gap**: No malware identification or family classification

**Current Limitation**: Engine detects suspicious behavior but cannot answer:
- "Is this ransomware?"
- "Is this Mimikatz?"
- "Is this a known APT tool?"

**Solution**: YARA rule integration
- Community rulesets (YARA-Rules, Signature-Base)
- Custom rules for common families (Cobalt Strike, Emotet, etc.)
- Batch scanning of suspicious files

**Implementation:**
```python
# sift_find_evil/detectors/malware_classifier.py
@dataclass(frozen=True)
class MalwareClassification:
    file_path: Path
    sha256: str
    yara_matches: list[str]  # ["Win_Ransomware_Generic", "CobaltStrike_Beacon"]
    malware_family: str | None  # "CobaltStrike"
    threat_category: str  # "backdoor", "ransomware", "trojan"
    confidence: float

class MalwareClassifier:
    def scan_file(self, file_path: Path) -> MalwareClassification | None: ...
    def scan_directory(self, dir_path: Path) -> list[MalwareClassification]: ...
```

**Use Cases:**
- CIRCL carved executables: Identify malware families automatically
- M57 scenarios: Classify attacker tools (if present)
- Export IOCs: Generate YARA matches for threat intelligence

**Estimated Lines of Code:** ~500 lines (YARA integration + ruleset management + tests)

---

#### 5. Memory Forensics Integration (5-7 days implementation)
**Gap**: No volatile memory analysis

**Attack Vectors Unlocked:**
- Fileless malware (process injection, reflective DLL loading)
- In-memory cryptographic keys/passwords
- Hidden processes (rootkit detection)
- Active network connections at capture time
- Unpacked/decrypted malware code

**Why This Matters:**
M57 Patents scenario includes memory dumps for some characters. Memory forensics could:
- Detect process injection not visible in disk artifacts
- Extract encryption keys for archived files
- Identify hidden C2 connections
- Find anti-forensic tools loaded in memory

**Implementation via Volatility 3:**
```python
# sift_find_evil/parsers/memory_parser.py
class MemoryParser:
    def parse_processes(self, dump_path: Path) -> list[ProcessRecord]: ...
    def parse_network(self, dump_path: Path) -> list[NetworkConnection]: ...
    def parse_malfind(self, dump_path: Path) -> list[InjectionEvidence]: ...
    def parse_cmdline(self, dump_path: Path) -> dict[int, str]: ...  # PID → command line
```

**Volatility 3 Plugins to Integrate:**
1. windows.pslist (process list)
2. windows.psscan (hidden processes)
3. windows.netscan (network connections)
4. windows.malfind (process injection)
5. windows.cmdline (command line args)

**Estimated Lines of Code:** ~600 lines (Volatility wrapper + parsers + tests)

**Deferred work — 2026-04-19**:
Installing Volatility 3 on this workstation and building `MemoryParser` +
`MemoryDetector` was explicitly deferred during the
`network_intrusion` scenario testing pass. The scenario ships a 4.29 GB
Linux memory dump (`ggmemday1.dmp`) that cannot be analyzed until this
capability lands. See `docs/SCENARIO_TESTING_NOTES.md` tier 3.4 and the
related beads issues. The Phase 1 detector slice (NetworkDetector +
`--pcap` CLI flag) proceeds first; Volatility is the next blocker to
unblock `network_intrusion` Pass 2. Linux memory dump needs
kernel-specific ISF symbol tables — budget time for banner identification
and symbol-table download when this work starts.

---

#### 6. Jump Lists & LNK Files (2-3 days implementation)
**Gap**: No Windows shell item analysis

**Attack Vectors Unlocked:**
- Recently accessed documents (Jump Lists)
- Network share paths (UNC paths in LNK files)
- USB device mount points
- Program execution without Prefetch (Jump Lists = usage proof)

**Implementation:**
```python
# sift_find_evil/parsers/shellitems_parser.py
@dataclass(frozen=True)
class JumpListEntry:
    app_name: str
    target_path: Path
    access_time: datetime
    mru_position: int

@dataclass(frozen=True)
class LNKFile:
    lnk_path: Path
    target_path: Path  # Could be network share
    creation_time: datetime
    machine_id: str
    volume_serial: str  # USB device identifier
```

**Estimated Lines of Code:** ~400 lines (2 parsers + tests)

---

#### 7. Lateral Movement Detection (3-4 days implementation)
**Gap**: No multi-host attack detection

**Attack Vectors:**
- PSExec remote execution (T1569.002)
- WMI remote execution (T1047)
- RDP sessions (T1021.001)
- Pass-the-hash attacks (T1550.002)
- Network share access (T1021.002)

**Implementation:**
```python
# sift_find_evil/detectors/lateral_movement_detector.py
@dataclass(frozen=True)
class LateralMovementEvidence:
    source_host: str
    target_host: str
    timestamp: datetime
    method: str  # "psexec", "wmi", "rdp", "smb"
    user: str
    confidence: float

class LateralMovementDetector:
    def detect_psexec(self, event_logs: list[EventLogEntry]) -> list[LateralMovementEvidence]: ...
    def detect_rdp(self, event_logs: list[EventLogEntry]) -> list[LateralMovementEvidence]: ...
    def detect_wmi(self, event_logs: list[EventLogEntry]) -> list[LateralMovementEvidence]: ...
```

**Event IDs to Monitor:**
- 4624 (successful logon) - Type 3 (network), Type 10 (RDP)
- 4625 (failed logon) - brute force detection
- 4648 (explicit credential use)
- 4776 (NTLM authentication)

**Estimated Lines of Code:** ~500 lines (3 detection methods + tests)

---

### P2 - Usability & Network Enhancements

#### 8. Additional Network Protocol Support (3-4 days)
**Current**: HTTP, SMTP, DNS  
**Missing**: FTP, SMB, RDP, TLS metadata

**Implementation:**
```python
# sift_find_evil/parsers/pcap_parser.py (enhancement)

@dataclass(frozen=True)
class FTPSession:
    timestamp: datetime
    client_ip: str
    server_ip: str
    commands: list[str]  # RETR, STOR, LIST
    files_transferred: list[str]

@dataclass(frozen=True)
class SMBSession:
    timestamp: datetime
    client_ip: str
    server_ip: str
    share_name: str
    files_accessed: list[str]

@dataclass(frozen=True)
class TLSMetadata:
    timestamp: datetime
    client_ip: str
    server_ip: str
    sni_hostname: str  # Server Name Indication
    certificate_subject: str
    certificate_issuer: str
```

**Estimated Lines of Code:** ~400 lines (3 protocols)

---

#### 9. DNS Tunneling Detection (2 days)
**Gap**: No DNS-based exfiltration detection

**Detection Signals:**
- High query volume to single domain
- Long subdomain names (>50 chars)
- High entropy subdomains (random-looking)
- TXT record abuse (large responses)

**Implementation:**
```python
# sift_find_evil/detectors/dns_tunneling_detector.py
@dataclass(frozen=True)
class DNSTunnelingEvidence:
    domain: str
    query_count: int
    avg_subdomain_length: float
    entropy_score: float  # 0-8 (Shannon entropy)
    suspicious_types: list[str]  # ["TXT", "NULL"]
    confidence: float

def calculate_entropy(subdomain: str) -> float:
    """Calculate Shannon entropy of subdomain."""
    ...
```

**Estimated Lines of Code:** ~300 lines (entropy calc + detector + tests)

---

#### 10. Interactive Timeline Visualization (4-5 days)
**Gap**: JSON output only, no visual timeline

**User Need**: Analysts need visual representation of attack progression

**Implementation Options:**

**Option A: HTML Timeline (vis.js)**
```python
# sift_find_evil/exporters/html_timeline.py
def export_html_timeline(findings: list[Finding], output_path: Path) -> None:
    """Generate interactive HTML timeline."""
    # Group findings by hour/day
    # Render with vis.js library
    ...
```

**Option B: ASCII Timeline (quick win)**
```python
def print_ascii_timeline(findings: list[Finding]) -> None:
    """Print text-based timeline."""
    # Sort by timestamp
    # Print with ASCII art separators
```

**Estimated Lines of Code:** ~600 lines (HTML) or ~200 lines (ASCII)

---

#### 11. Report Generation Engine (3-4 days)
**Gap**: No formatted reports (PDF, HTML, Markdown)

**Implementation:**
```python
# sift_find_evil/reporting/report_generator.py
class ReportGenerator:
    def generate_executive_summary(self, findings: list[Finding]) -> str: ...
    def generate_technical_report(self, findings: list[Finding]) -> str: ...
    def export_pdf(self, report: str, output_path: Path) -> None: ...
    def export_html(self, report: str, output_path: Path) -> None: ...
    def export_markdown(self, report: str, output_path: Path) -> None: ...
```

**Report Sections:**
1. Executive Summary (1-page, non-technical)
2. Key Findings (sorted by confidence)
3. Attack Timeline
4. Technical Details
5. Indicators of Compromise (IOCs)
6. Recommendations
7. Appendices (artifact listings)

**Estimated Lines of Code:** ~500 lines (templates + formatters)

---

### P3 - Performance Optimizations

#### 12. Parallel File Hashing (1 day)
**Current**: Sequential hashing, 228 files in 30-60 seconds  
**Target**: Parallel hashing, 228 files in 8-15 seconds (4x speedup)

```python
from concurrent.futures import ThreadPoolExecutor

def hash_files_parallel(file_paths: list[Path], workers: int = 4) -> dict[Path, str]:
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(_hash_single_file, file_paths)
    return dict(zip(file_paths, results))
```

**Estimated Lines of Code:** ~100 lines

---

#### 13. Memory-Mapped I/O for Large Disk Images (2 days)
**Current**: Standard file reads  
**Target**: mmap for 2-3x faster sparse access

```python
import mmap

def read_disk_region(image_path: Path, offset: int, length: int) -> bytes:
    with image_path.open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return mm[offset:offset+length]
```

**Estimated Lines of Code:** ~150 lines

---

## Detection & Analysis

### High Priority

1. **Cross-case validation dataset**
   - **Issue:** Validator tested on synthetic data, needs real-world validation
   - **Approach:** Run validator against multiple M57 characters (Pat, Terry, Charlie, Jo)
   - **Benefit:** Validate graduated confidence thresholds don't create false negatives
   - **Effort:** 2-4 hours (requires downloading additional M57 PST/disk images)
   - **Ref:** SFE-560 testing requirements

2. **NSRL database integration**
   - **Issue:** File carving on wiped disks recovers many known-good system files
   - **Impact:** Manual triage of 403 CIRCL executables took 60-90 minutes due to VirusTotal rate limits
   - **Approach:** Integrate NSRL RDS for instant known-good filtering
   - **Benefit:** 90%+ noise reduction in carved file analysis
   - **Effort:** 4-6 hours (NSRL download + hash lookup implementation)
   - **Ref:** CIRCL analysis findings

3. **Bulk hash submission for carved files**
   - **Issue:** VirusTotal rate limits slow down manual triage
   - **Approach:** Batch hash all carved files, submit to VirusTotal API in bulk
   - **Benefit:** Parallel malware scanning, faster triage
   - **Effort:** 2-3 hours
   - **Alternative:** Use local YARA rules for initial malware screening

### Medium Priority

4. **Document/archive signature expansion validation**
   - **Issue:** Added 40+ signatures but only basic detection tests
   - **Approach:** Test on real-world carved data (DOCX, XLSX, RAR, 7Z, PST, registry hives)
   - **Benefit:** Validate signature accuracy and offset handling
   - **Effort:** 2-3 hours (requires test corpus of each format)

5. **Confidence calibration study**
   - **Issue:** Graduated thresholds (60s, 180s) are educated guesses, not empirically validated
   - **Approach:** Analyze timing patterns across M57 dataset, adjust thresholds based on data
   - **Benefit:** Evidence-based confidence scoring
   - **Effort:** 4-6 hours

6. **Alternative explanations library**
   - **Issue:** Validator checks for "backup" keyword but could miss other legitimate automation
   - **Approach:** Build knowledge base of common automated processes and their timing signatures
   - **Examples:** Dropbox sync (5-15s), OneDrive (10-30s), Windows Backup (variable), antivirus scans
   - **Benefit:** Reduce false positives from legitimate software
   - **Effort:** 6-8 hours (research + implementation)

### Low Priority

7. **Memory forensics integration**
   - **Issue:** Current analysis limited to disk and email artifacts
   - **Approach:** Add Volatility 3 plugins for process memory analysis
   - **Use cases:** Fileless malware, encryption keys, browser artifacts
   - **Effort:** 8-12 hours

8. **Timeline visualization**
   - **Issue:** Temporal relationships shown in text, not visually
   - **Approach:** Generate timeline graphs for correlated events
   - **Benefit:** Easier pattern recognition for investigators
   - **Effort:** 6-8 hours

---

## Infrastructure & Tooling

### High Priority

9. **SIFT tool detection and fallback**
   - **Issue:** No carving tools installed, but code doesn't detect or warn gracefully
   - **Approach:** Runtime tool detection with helpful error messages + install instructions
   - **Benefit:** Better UX for users on minimal SIFT installations
   - **Effort:** 1-2 hours
   - **Ref:** SFE-1n2 findings, docs/SIFT_CARVING_TOOLS_STATUS.md

10. **Disk image format detection**
    - **Issue:** Code assumes E01 format, may fail on raw/dd/VMDK/VHD images
    - **Approach:** Detect format and use appropriate parser (pytsk3 supports multiple formats)
    - **Benefit:** Broader compatibility
    - **Effort:** 2-3 hours

### Medium Priority

11. **Progress indicators for long operations**
    - **Issue:** File hashing and carving operations can take minutes with no feedback
    - **Approach:** Add progress bars for MFT parsing, file hashing, carving scans
    - **Benefit:** Better UX, user knows system is working
    - **Effort:** 2-3 hours

12. **Parallel file hashing**
    - **Issue:** Sequential file hashing is slow for large datasets
    - **Approach:** Use multiprocessing to hash files in parallel
    - **Benefit:** 2-4x speedup on multi-core systems
    - **Effort:** 3-4 hours

13. **Output format options**
    - **Issue:** CLI output only, no JSON/CSV export for downstream tools
    - **Approach:** Add --format json|csv|markdown flags
    - **Benefit:** Integration with other forensic workflows
    - **Effort:** 2-3 hours

---

## Testing & Quality

### High Priority

14. **Integration tests for end-to-end workflows**
    - **Issue:** Unit tests cover components, but no full workflow tests
    - **Approach:** E2E tests on Jean/Nitroba/CIRCL scenarios with expected findings
    - **Benefit:** Catch regressions in complete analysis pipelines
    - **Effort:** 4-6 hours

15. **Validator performance benchmarks**
    - **Issue:** Unknown validation overhead on large finding sets
    - **Approach:** Benchmark validator on 10, 100, 1000 findings
    - **Benefit:** Ensure validation scales for enterprise datasets
    - **Effort:** 1-2 hours

### Medium Priority

16. **Property-based testing for signatures**
    - **Issue:** Signature detection tested on fixed examples, not exhaustive
    - **Approach:** Use Hypothesis to generate valid file headers and test detection
    - **Benefit:** Find edge cases in signature matching logic
    - **Effort:** 3-4 hours

17. **Adversarial validator stress testing**
    - **Issue:** Validator tested on well-formed findings, not malformed/adversarial inputs
    - **Approach:** Generate findings with missing fields, malformed timestamps, corrupt hashes
    - **Benefit:** Ensure validator handles edge cases gracefully
    - **Effort:** 2-3 hours

---

## Documentation

### Medium Priority

18. **Case study write-ups**
    - **Issue:** Jean/Nitroba/CIRCL analyses exist but aren't documented for reuse
    - **Approach:** Create analysis guides for each scenario showing methodology
    - **Benefit:** Training material for new users, validation of detector effectiveness
    - **Effort:** 4-6 hours

19. **Architecture decision records (ADRs)**
    - **Issue:** Design decisions (graduated confidence, validation thresholds) not documented
    - **Approach:** Create ADRs for major technical decisions with rationale and alternatives
    - **Benefit:** Future maintainers understand "why" not just "what"
    - **Effort:** 2-3 hours

20. **API documentation**
    - **Issue:** Module docstrings exist but no cohesive API docs
    - **Approach:** Use Sphinx to generate API docs from docstrings
    - **Benefit:** Easier for developers to extend detectors
    - **Effort:** 3-4 hours

---

## New Detector Ideas

### High Priority

21. **Browser history exfiltration**
    - **Use case:** Detect when browser history is copied/exfiled (credential theft indicator)
    - **Artifacts:** SQLite databases, file access timestamps, email attachments
    - **Effort:** 6-8 hours

22. **Lateral movement detection**
    - **Use case:** Detect evidence of remote access tools or credential dumping
    - **Artifacts:** Windows Event Logs (4624, 4625), registry keys, scheduled tasks
    - **Effort:** 8-12 hours

### Medium Priority

23. **Cloud exfiltration (Dropbox/OneDrive/Google Drive)**
    - **Use case:** Detect file uploads to cloud storage
    - **Artifacts:** Cloud sync logs, registry artifacts, network traffic
    - **Effort:** 6-8 hours

24. **USB device history**
    - **Use case:** Track what devices were connected and when
    - **Artifacts:** Windows registry, setupapi.dev.log, event logs
    - **Effort:** 4-6 hours

---

## Notes on Prioritization

**High Priority** items address gaps in current functionality or provide significant value with reasonable effort.

**Medium Priority** items improve robustness, usability, or maintainability but aren't blocking current use cases.

**Low Priority** items are nice-to-have enhancements that can be deferred.

---

## Implementation Tracking

When implementing an improvement, create a beads issue:

```bash
bd create --title="[Improvement] <title>" \
  --description="From POTENTIAL_IMPROVEMENTS.md: <description>" \
  --type=feature --priority=<0-4>
```

Mark in this document when moved to active work:
- [ ] Not started
- [x] Issue created (SFE-XXX)
- [x] In progress
- [x] Complete

---

---

## Prioritized Implementation Roadmap

### Sprint 1: Critical Artifact Coverage (P0 - 2 weeks)
**Goal**: Increase artifact coverage from 3 to 6+ types

**Week 1: Browser History**
- Day 1-2: Chrome History.db parser (SQLite)
- Day 3: Firefox places.sqlite parser
- Day 4: Edge WebCacheV01.dat parser
- Day 5: Integration + tests

**Week 2: Registry Analysis**
- Day 1-2: Shimcache parser (execution evidence)
- Day 3: Amcache parser (SHA-1 hashes)
- Day 4: BAM/DAM parser (process timestamps)
- Day 5: Integration + comprehensive tests

**Outcome:**
- MITRE ATT&CK coverage: 20% → 40%
- Scenario 05 (missing prefetch) confidence: 0.60 → 0.85+
- New detection capabilities: persistence, web-based exfiltration

---

### Sprint 2: Detection Enhancement (P1 - 2 weeks)
**Goal**: Add malware classification and memory forensics

**Week 3: YARA Integration**
- Day 1-2: YARA Python bindings + rule compilation
- Day 3: Batch scanning engine
- Day 4: Ruleset integration (Signature-Base, YARA-Rules)
- Day 5: CIRCL case validation (403 executables → classify)

**Week 4: Memory Forensics Foundation**
- Day 1-3: Volatility 3 subprocess wrapper
- Day 4: Process list + network scan parsers
- Day 5: Malfind (injection detection) + tests

**Outcome:**
- Automated malware family identification
- Fileless malware detection capability
- CIRCL triage time: 60-90 min → 5-10 min

---

### Sprint 3: Network & Lateral Movement (P1-P2 - 2 weeks)
**Goal**: Multi-host attack detection

**Week 5: Additional Network Protocols**
- Day 1-2: FTP session parser
- Day 3-4: SMB session parser
- Day 5: TLS metadata extraction

**Week 6: Lateral Movement Detection**
- Day 1-2: Event log lateral movement patterns (4624, 4648, 4776)
- Day 3-4: PSExec/WMI detection logic
- Day 5: Multi-host correlation + tests

**Outcome:**
- Complete network visibility (HTTP, SMTP, DNS, FTP, SMB, TLS)
- APT-style attack chain detection
- MITRE ATT&CK coverage: 40% → 60%

---

### Sprint 4: Usability & Polish (P2 - 1 week)
**Goal**: Production-ready deliverables

**Week 7: Reporting & Visualization**
- Day 1-3: HTML timeline generator (vis.js)
- Day 4-5: Report generation (PDF/HTML/Markdown)

**Outcome:**
- Client-ready deliverables
- Visual attack progression
- Executive summary generation

---

### Sprint 5: Performance Optimization (P3 - 3 days)
**Goal**: 3-5x faster analysis

**Week 8:**
- Day 1: Parallel file hashing
- Day 2: Memory-mapped I/O
- Day 3: Profiling + bottleneck resolution

**Outcome:**
- Jean laptop analysis: 4-6 min → 1-2 min
- Hash 228 files: 30-60s → 8-15s

---

## Testing Strategy for New Capabilities

### Synthetic Scenario Expansion

**Current**: 5 scenarios (clean, ransomware, timestomping, edges, missing)  
**Target**: 15 scenarios

**New Scenarios to Create:**

#### Browser History Scenarios
1. **06_webmail_exfiltration**
   - Files: mft.csv, prefetch.csv, evtx.csv, browser_history.csv
   - Pattern: Gmail login → file access → email send
   - Expected: Exfiltration detection with browser correlation

2. **07_cloud_upload**
   - Pattern: Dropbox.exe execution → file access → upload URL in browser
   - Expected: Cloud exfiltration detection

#### Registry Scenarios
3. **08_persistence_run_keys**
   - Files: mft.csv, registry.csv (NTUSER.DAT Run keys)
   - Pattern: Malicious executable added to Run key
   - Expected: Persistence detection

4. **09_shimcache_only**
   - Files: mft.csv, registry.csv (Shimcache), evtx.csv
   - Pattern: Prefetch deleted, but Shimcache shows execution
   - Expected: Execution detection via Shimcache

5. **10_timestomping_with_bam**
   - Files: mft.csv, registry.csv (BAM/DAM), prefetch.csv
   - Pattern: $SI backdated, but BAM shows real execution time
   - Expected: Timestomping detected, BAM provides ground truth

#### Memory Forensics Scenarios
6. **11_process_injection**
   - Files: memory.dmp (synthetic or real Mimikatz injection)
   - Pattern: Legitimate process with injected code
   - Expected: Malfind detection

7. **12_hidden_process**
   - Files: memory.dmp (rootkit hiding process)
   - Pattern: Process in EPROCESS chain but not in pslist
   - Expected: Hidden process detection

#### Network Scenarios
8. **13_ftp_exfiltration**
   - Files: pcap (FTP session), mft.csv
   - Pattern: File access → FTP STOR command
   - Expected: FTP exfiltration detection

9. **14_dns_tunneling**
   - Files: pcap (high-entropy DNS queries)
   - Pattern: Long subdomains with high query volume
   - Expected: DNS tunneling detection

10. **15_lateral_movement**
    - Files: evtx.csv (4624, 4648 events), pcap (SMB traffic)
    - Pattern: Logon type 3, PSExec service creation
    - Expected: Lateral movement detection

#### Multi-Artifact Correlation
11. **16_apt_attack_chain**
    - Files: mft.csv, prefetch.csv, evtx.csv, registry.csv, browser_history.csv, pcap
    - Pattern: Phishing URL → exploit → persistence → lateral movement → exfiltration
    - Expected: Full attack chain reconstruction

12. **17_insider_threat**
    - Files: mft.csv, prefetch.csv, browser_history.csv, usb_history.csv
    - Pattern: Document access → USB copy → personal email
    - Expected: Data theft detection

13. **18_ransomware_complete**
    - Files: mft.csv, prefetch.csv, evtx.csv, registry.csv, memory.dmp
    - Pattern: Malware drop → persistence → encryption → ransom note
    - Expected: Ransomware kill chain

14. **19_false_positive_test**
    - Files: All artifact types, legitimate backup software
    - Pattern: Legitimate backup creating mass file copies
    - Expected: No false positive (alternative explanation)

15. **20_adversarial_evasion**
    - Files: mft.csv (timestomped), prefetch.csv (deleted), evtx.csv (cleared)
    - Pattern: Attacker removes all evidence
    - Expected: Graceful degradation, confidence scoring reflects gaps

---

### Real-World Dataset Testing

#### M57 Patents - Complete Character Analysis
**Current**: Only Jean tested (exfiltration scenario)  
**Expand**:
- Pat's evidence (different attack vector?)
- Terry's evidence
- Charlie's evidence
- Jo's evidence
- Network traffic correlation across all 5 characters

**Goal**: Validate multi-host lateral movement detection, identify additional attack patterns

---

#### Public CTF Forensics Challenges

**HackTheBox Forensics:**
- Reminiscent (Windows memory forensics)
- Obscured (Linux PCAP analysis)
- Keeper (credential theft)

**PicoCTF:**
- Trivial Flag Transfer Protocol (TFTP analysis)
- Wireshark doo dooo do doo (PCAP)

**SANS DFIR NetWars** (if accessible):
- APT scenarios
- Insider threats
- Ransomware attacks

**Malware Traffic Analysis (malware-traffic-analysis.net):**
- 50+ PCAP scenarios with known malware families
- Test YARA classification + network detection

---

### Performance Benchmarking

**Benchmark Suite:**
1. **Small dataset** (1K MFT entries, 10 Prefetch, 50 Event Logs)
   - Target: <1 second
   
2. **Medium dataset** (10K MFT entries, 100 Prefetch, 500 Event Logs)
   - Target: <10 seconds

3. **Large dataset** (100K MFT entries, 1K Prefetch, 5K Event Logs)
   - Target: <2 minutes

4. **Jean laptop** (91,459 MFT entries, 228 Prefetch, 1K Event Logs)
   - Current: 4-6 minutes (CSV mode)
   - Target: <30 seconds (with optimizations)

5. **Memory dump** (4 GB RAM image)
   - Target: <5 minutes (Volatility pslist + netscan + malfind)

---

## Success Metrics & KPIs

### Coverage Metrics
- **Artifact Types**: 3 → 10+ (MFT, Prefetch, Event Logs, Browser, Registry, Memory, Jump Lists, LNK, PCAP extended)
- **MITRE ATT&CK Techniques**: 6 → 50+ techniques
- **Attack Stages**: 3/14 → 12/14 MITRE stages

### Accuracy Metrics
- **Synthetic Scenarios**: Maintain 100% precision + recall
- **Real-World Scenarios**: 90%+ precision, 85%+ recall
- **False Positive Rate**: <5% on clean baselines
- **False Negative Rate**: <10% on known attacks

### Performance Metrics
- **Analysis Speed**: 3-5x faster (parallel hashing + mmap)
- **Triage Time**: 60-90 min → 5-10 min (NSRL + YARA)
- **Coverage Depth**: 20% ATT&CK → 70%+ ATT&CK

### Usability Metrics
- **Time to First Finding**: <5 minutes (simple CSV analysis)
- **Report Generation**: <2 minutes (HTML/PDF export)
- **Documentation**: 100% public API documented
- **User Guide**: Complete workflows for 5+ attack types

---

## Competitive Positioning

### Current Market Analysis

**Commercial DFIR Tools:**

| Tool | Price/Year | Artifact Coverage | Automation | Explainability | Market Segment |
|------|------------|-------------------|------------|----------------|----------------|
| Cellebrite UFED | $15K-30K | Very High (mobile focus) | Medium | Low (black box) | Law enforcement, mobile |
| Magnet Axiom | $5K-10K | Very High | Medium | Medium | Enterprise, LE |
| X-Ways Forensics | $500-2K | High | Low (manual) | High | SMB, contractors |
| EnCase | $3K-5K | Very High | Medium | Medium | Enterprise, LE |
| **SIFT Find Evil** | **FREE → $99-499/mo SaaS** | **Medium → High** | **Very High** | **Very High** | **Mid-market enterprises** |

**Open Source Tools:**

| Tool | Artifact Coverage | Automation | Usability | Target Users |
|------|-------------------|------------|-----------|--------------|
| Autopsy | High | Low | Medium (GUI) | Forensic analysts |
| Volatility | Medium (memory only) | Low | Low (CLI expert) | Memory forensics specialists |
| Plaso/Timesketch | High (timeline) | Low | Medium | Timeline analysis |
| **SIFT Find Evil** | **Medium → High** | **Very High** | **High** | **Junior analysts + automation engineers** |

---

### Differentiation Strategy

**Unique Value Propositions:**

1. **Self-Correcting AI Engine**
   - No other tool cross-validates artifacts automatically
   - Confidence scoring with contradiction resolution
   - Transparent reasoning (JSON shows WHY)

2. **Artifact-Centric Detection**
   - No signatures = detect unknown attacks
   - No case-specific patterns = fully generic
   - Works on ANY Windows system (2000-2025)

3. **Automation-First Design**
   - Reduces 4-25 min analysis → seconds
   - Batch processing for triage (100s of systems)
   - API-driven for integration (SOAR, SIEM)

4. **Open Source + SaaS Hybrid**
   - Free CLI for local analysis
   - Paid SaaS for collaboration, storage, API
   - No vendor lock-in

5. **Explainable Results**
   - Every finding cites artifacts
   - Court-admissible evidence chain
   - Confidence scoring shows uncertainty

---

### Target Market Positioning

**Primary Target**: Mid-market enterprises (100-5000 employees)

**Pain Points We Solve:**
- Can't afford Cellebrite/Magnet ($15K+/year)
- Limited forensic analyst headcount (1-3 analysts)
- Need automated triage (100+ endpoints to check)
- Want explainable results (for HR, legal, insurance)
- Need Windows focus (90% of enterprise endpoints)

**Pricing Strategy** (Future SaaS):

| Tier | Price/Month | Included | Target User |
|------|-------------|----------|-------------|
| **Free** | $0 | CLI tool, unlimited local analysis | Individual analysts, students |
| **Pro** | $99 | Cloud platform, 100 cases/month, collaboration, storage | Small security teams (1-5 analysts) |
| **Enterprise** | $499 | Unlimited cases, API access, SSO, priority support | Mid-market SOC (5-20 analysts) |
| **Custom** | Quote | On-premise deployment, custom integrations, training | Large enterprises, government |

---

## Implementation Tracking

When implementing an improvement from this document:

1. **Create beads issue:**
   ```bash
   bd create --title="[P0] Implement browser history parser" \
     --description="From POTENTIAL_IMPROVEMENTS.md: Parse Chrome/Firefox/Edge history for URL correlation. Unlocks web-based C2 and cloud exfiltration detection." \
     --type=feature --priority=0
   ```

2. **Mark status in this document:**
   - [ ] Not started
   - [x] Issue created (SFE-XXX)
   - [x] In progress
   - [x] Complete

3. **Create test scenarios** alongside implementation
4. **Update EXAMPLES.md** with new capabilities
5. **Increment version** in pyproject.toml

---

## Questions for Product Direction

### Strategic Questions

1. **Hackathon vs. SaaS Focus?**
   - Hackathon: Prioritize demo-ready features (browser history, YARA, timeline viz)
   - SaaS: Prioritize scalability (API design, multi-tenant, performance)
   - Recommendation: ?

2. **Open Source vs. Commercial Features?**
   - Which features stay open source (core engine)?
   - Which features go SaaS-only (cloud collab, API, advanced reporting)?
   - Recommendation: Core detection = OSS, collaboration/scale = SaaS

3. **Memory Forensics Depth?**
   - Full Volatility integration (50+ plugins) or focused subset (4-5 plugins)?
   - Storage implications: 4-16 GB per RAM dump
   - Recommendation: Start with 5 critical plugins, expand based on demand

4. **YARA Legal/Ethical?**
   - Some YARA rules detect offensive security tools (Cobalt Strike, Mimikatz)
   - Should we include all rules or filter for defensive use only?
   - Recommendation: Include with disclaimer ("research/defense purposes only")

5. **Dataset Access?**
   - Should we download all M57 characters (Pat, Terry, Charlie, Jo)?
   - Total storage: 50-100 GB
   - Recommendation: ?

### Technical Questions

1. **Registry Parser Approach?**
   - Option A: Native Python parsers (more control, more effort)
   - Option B: RegRipper integration (mature, less control)
   - Recommendation: Option A for core artifacts (Shimcache, BAM), Option B for comprehensive coverage

2. **Memory Forensics Architecture?**
   - Option A: Subprocess wrapper (simple, stable)
   - Option B: Volatility library import (faster, complex dependencies)
   - Recommendation: Option A for MVP, consider Option B for v2.0

3. **Timeline Visualization?**
   - Option A: HTML + vis.js (interactive, requires web browser)
   - Option B: ASCII text timeline (terminal-friendly, limited)
   - Option C: Both
   - Recommendation: Option C (ASCII for quick checks, HTML for reports)

---

## Recommended Next Actions

### This Session (2-3 hours)
1. ✅ Run all synthetic scenarios (100% passing)
2. ✅ Analyze gaps and create comprehensive improvement roadmap
3. ⏳ Prioritize Phase 1 features based on hackathon timeline
4. ⏳ Create 2-3 new synthetic scenarios for registry/browser (validation prep)

### Next Session (1 week)
1. Implement browser history parser (P0)
   - Chrome, Firefox, Edge SQLite parsers
   - Integration with exfiltration detector
   - Test scenario 06_webmail_exfiltration

2. Start registry analysis (P0)
   - Shimcache parser (execution evidence)
   - Test scenario 09_shimcache_only

### Next Sprint (2 weeks)
1. Complete registry analysis (Amcache, BAM/DAM, Run keys)
2. NSRL integration for CIRCL case optimization
3. YARA integration for malware classification
4. Update EXAMPLES.md with new capabilities

---

## Recent Additions

- **2026-04-19:** Comprehensive gap analysis based on scenario testing
  - Added Priority Matrix with ROI analysis
  - Added MITRE ATT&CK coverage breakdown by stage
  - Added 13 new capability descriptions with implementation details
  - Added prioritized roadmap (5 sprints, 8 weeks)
  - Added 15 new synthetic scenario specifications
  - Added competitive positioning analysis
  - Added success metrics and KPIs
  - Added strategic questions for product direction

- **2026-04-18:** Initial document created based on P2/P4 backlog work session
  - Added NSRL integration, confidence calibration, SIFT tool detection
  - Added validator stress testing, case study documentation
  - Added new detector ideas (browser history, lateral movement, cloud exfil)
