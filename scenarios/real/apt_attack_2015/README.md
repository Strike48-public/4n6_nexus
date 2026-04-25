# Real Scenario: APT Attack on Enterprise Network (2015)

**Source:** SANS Security Reinforcement Labs (SRL-2015)

**Evidence Location:** `/media/jtomek/TESLADRIVE/sift_evidence/compromised_apt_attack/SRL-2015-Compromised_Enterprise_Network/`

**Description:** Multi-system APT (Advanced Persistent Threat) compromise of an enterprise network including domain controller, file servers, remote desktop servers, workstations, and DMZ FTP server.

---

## Evidence Inventory

| System | Image File | Size | Role |
|--------|-----------|------|------|
| **Domain Controller** | `base-dc-cdrive.E01` | 12 GB | Windows Domain Controller (likely 2008/2012) |
| **File Server** | `base-file-cdrive.E01` | 16 GB | Enterprise file server |
| **Remote Desktop 1** | `base-rd-01-cdrive.E01` | 17 GB | RDP server or jump box |
| **Remote Desktop 2** | `base-rd-02-cdrive.E01` | 17 GB | RDP server or jump box |
| **Workstation 1** | `base-wkstn-01-c-drive.E01` | 16 GB | Employee workstation |
| **Workstation 5** | `base-wkstn-05-cdrive.E01` | 14 GB | Employee workstation |
| **DMZ FTP Server** | `dmz-ftp-cdrive.E01` | 12 GB | External-facing FTP server (likely initial compromise) |

**Additional archives (memory/network captures):**
- `win2008R2-controller-10.3.58.4.zip` (17 GB) - Domain controller memory/network
- `win7-32-nromanoff-10.3.58.5.zip` (15 GB) - Win7 32-bit workstation
- `win7-64-nfury-10.3.58.6.zip` (14 GB) - Win7 64-bit workstation
- `xp-tdungan-10.3.58.7.zip` (12 GB) - Windows XP workstation

**Total evidence size:** ~104 GB disk images + ~59 GB archives = **163 GB**

---

## Attack Scenario (Expected)

This is a classic APT lateral movement scenario:

### Phase 1: Initial Compromise
- **Entry point:** DMZ FTP server (external-facing, likely vulnerable)
- **Technique:** Exploit vulnerability or stolen credentials
- **Goal:** Establish foothold in DMZ

### Phase 2: Lateral Movement
- **From DMZ → Internal network** via credential theft or network pivot
- **Targets:** Workstations (base-wkstn-01, base-wkstn-05)
- **Technique:** Pass-the-hash, credential dumping, or exploit

### Phase 3: Privilege Escalation
- **From workstations → Domain Controller** (base-dc)
- **Technique:** Kerberoasting, Golden Ticket, or admin credential theft
- **Goal:** Full domain compromise

### Phase 4: Persistence & Data Exfiltration
- **File server access** (base-file) for sensitive data
- **RDP servers** (base-rd-01, base-rd-02) for persistent access
- **Goal:** Long-term access and data theft

---

## Expected Findings

Based on typical APT campaigns, we should detect:

### 1. Initial Compromise (DMZ FTP Server)
- Exploit artifacts or webshell deployment
- Unusual FTP activity or admin access
- Network connections to internal network
- Credential theft attempts (Mimikatz, procdump)

### 2. Lateral Movement
- Pass-the-hash attacks (Event ID 4624 Type 3)
- SMB share access across systems (ADMIN$, C$)
- Remote execution (PsExec, WMI, PowerShell remoting)
- Credential dumping (LSASS memory access)

### 3. Privilege Escalation
- Kerberos ticket manipulation (Golden/Silver tickets)
- Domain Admin credential theft
- DCSync attack (replication of password hashes)
- Event ID 4672 (special privileges assigned)

### 4. Persistence Mechanisms
- Scheduled tasks on multiple systems
- Service creation (Event ID 7045)
- Registry Run keys
- WMI event subscriptions

### 5. Data Exfiltration
- Large file transfers to external IPs
- Archive creation (RAR, ZIP) of sensitive data
- Network traffic to C2 servers
- DNS tunneling or HTTPS exfiltration

### 6. Anti-Forensics
- Event log clearing (Event ID 1102)
- Timestomping
- File deletion with secure wiping
- Prefetch file deletion

---

## Analysis Plan

### Phase 1: Triage Analysis (Start Here)

**Priority targets (lowest hanging fruit):**

1. **DMZ FTP Server** - Initial compromise point
   ```bash
   # Mount and analyze MFT
   ewfmount dmz-ftp-cdrive.E01 /mnt/ewf_dmz
   mmls /mnt/ewf_dmz/ewf1
   mount -o ro,loop,offset=$((OFFSET * 512)) /mnt/ewf_dmz/ewf1 /mnt/dmz_mount
   
   # Extract MFT
   python -m sift_find_evil.cli_mcp analyze-live \
     --case-id apt_dmz_ftp \
     --mft-file /mnt/dmz_mount/\$MFT \
     --output-dir /cases/apt_attack_2015/dmz_ftp
   ```

2. **Domain Controller** - Highest-value target
   ```bash
   # Analyze DC for privilege escalation and persistence
   python -m sift_find_evil.cli_mcp analyze-live \
     --case-id apt_domain_controller \
     --mft-file /mnt/dc_mount/\$MFT \
     --output-dir /cases/apt_attack_2015/domain_controller
   ```

3. **Workstation 1** - User activity and lateral movement
   ```bash
   # Analyze workstation for initial access and credential theft
   python -m sift_find_evil.cli_mcp analyze-live \
     --case-id apt_workstation_01 \
     --mft-file /mnt/wkstn01_mount/\$MFT \
     --output-dir /cases/apt_attack_2015/workstation_01
   ```

### Phase 2: Full Network Analysis

Analyze all 7 systems and correlate findings:

```bash
# Create master timeline across all systems
for system in dmz_ftp domain_controller file_server rd_01 rd_02 wkstn_01 wkstn_05; do
  python -m sift_find_evil.cli_mcp analyze-live \
    --case-id apt_${system} \
    --mft-file /mnt/${system}_mount/\$MFT \
    --output-dir /cases/apt_attack_2015/${system}
done

# Correlate findings across systems
python -m sift_find_evil.correlation.multi_system_timeline \
  --input-dir /cases/apt_attack_2015/ \
  --output /cases/apt_attack_2015/master_timeline.json
```

### Phase 3: Memory & Network Analysis

Analyze ZIP archives for memory dumps and network captures:

```bash
# Extract archives
unzip win2008R2-controller-10.3.58.4.zip -d /cases/apt_attack_2015/memory/dc
unzip win7-32-nromanoff-10.3.58.5.zip -d /cases/apt_attack_2015/memory/win7_32
unzip win7-64-nfury-10.3.58.6.zip -d /cases/apt_attack_2015/memory/win7_64
unzip xp-tdungan-10.3.58.7.zip -d /cases/apt_attack_2015/memory/xp

# Volatility 3 analysis for memory dumps
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.malfind

# Network PCAP analysis (if present)
tshark -r capture.pcap -Y "ip.dst != 10.3.58.0/24" -T fields -e ip.dst | sort | uniq
```

---

## Performance Testing

This scenario is ideal for performance benchmarking because:

1. **Multiple systems** - Test parallel processing across 7 images
2. **Large scale** - 104 GB total, realistic enterprise environment
3. **Complex attack chain** - Tests correlation engine
4. **Real evidence** - Validates accuracy against real APT techniques

### Benchmark Goals

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Time per system** | < 15 minutes | MFT extraction + detection |
| **Total analysis time** | < 2 hours | All 7 systems + correlation |
| **Memory usage** | < 8 GB RAM | Per-system peak |
| **Findings accuracy** | F1 >= 0.90 | Validated against SANS ground truth |
| **False positive rate** | < 10% | Suppressed by self-correction |

### Comparison to Manual Analysis

**Human analyst (typical):**
- Triage: 8-16 hours
- Full analysis: 40-80 hours (1-2 weeks)
- Report: 8-16 hours
- **Total: 56-112 hours**

**Traditional tools (Autopsy/EnCase):**
- Image mounting: 30 min
- Index building: 2-4 hours per system
- Analysis: 1-2 hours per system
- Triage alerts: 2-4 hours per system
- **Total: 20-40 hours**

**Our engine (target):**
- Image mounting: 30 min
- MFT extraction: 7 systems × 5 min = 35 min
- Detection + self-correction: 7 systems × 10 min = 70 min
- Correlation: 15 min
- **Total: 2-3 hours**

**Speedup: 10-50x faster than manual, 7-13x faster than traditional tools**

---

## Validation Strategy

### Ground Truth Sources

1. **SANS documentation** - If available with evidence
2. **Known APT TTPs** - MITRE ATT&CK framework
3. **Manual validation** - Spot-check high-confidence findings
4. **Cross-system correlation** - Validate lateral movement chains

### Accuracy Metrics

Calculate per-system and aggregate:
- **Precision:** `TP / (TP + FP)` - How many findings are real
- **Recall:** `TP / (TP + FN)` - How many real attacks did we catch
- **F1 Score:** `2 * (Precision * Recall) / (Precision + Recall)` - Harmonic mean

### Expected Challenges

1. **No official ground truth** - Must validate manually or compare to existing research
2. **Large scale** - 163 GB of evidence requires storage and compute
3. **Complex attack chains** - Multi-system correlation is hard
4. **Memory analysis** - Current engine focuses on disk artifacts, not memory

---

## Next Steps

1. **Triage analysis** - Start with DMZ FTP server (most likely initial compromise)
2. **Document findings** - Create detailed report per system
3. **Validate accuracy** - Compare to known APT techniques
4. **Benchmark performance** - Measure time, memory, throughput
5. **Update documentation** - Add to ACCURACY_REPORT.md and PERFORMANCE_BENCHMARK.md

---

## Competition Value

**Why this matters for judges:**

1. **Real APT scenario** - Not synthetic, proves engine works on real attacks
2. **Enterprise scale** - 7 systems, realistic business environment
3. **Complex attack chain** - Tests correlation and self-correction capabilities
4. **Performance proof** - Can demonstrate 2-3 hour analysis vs 40-80 hour manual
5. **Reproducible** - Evidence is available (SANS SRL), judges can verify

**Demo potential:**
- Show findings from DMZ FTP → Workstation → Domain Controller lateral movement
- Demonstrate self-correction on false positive alerts
- Prove attack chain reconstruction across systems
- Compare to traditional tools (Autopsy would take 20+ hours)

---

## References

- SANS Security Reinforcement Labs: https://www.sans.org/
- MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
- APT Lateral Movement: https://attack.mitre.org/tactics/TA0008/
- Credential Dumping: https://attack.mitre.org/techniques/T1003/

---

**Status:** Ready for analysis
**Priority:** High (major competition differentiator)
**Estimated effort:** 8-16 hours for complete analysis and validation
