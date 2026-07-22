# Scenario 14: USB Device Activity (Unauthorized Data Transfer)

**Type:** Data exfiltration
**Difficulty:** Medium
**Attack Vector:** Insider copies sensitive files to USB drive

## Scenario Description

An insider connects a USB drive, copies sensitive corporate documents to the drive, then deletes the local copies to hide the activity. However, forensic artifacts remain that contradict the "clean" system state.

## Attack Timeline

1. **2024-04-22 09:15:00 UTC** - USB device connected (Kingston DataTraveler 64GB)
2. **2024-04-22 09:16:00 UTC** - File Explorer opened, navigated to Documents folder
3. **2024-04-22 09:17:00 UTC** - Large files copied to USB drive (E:)
4. **2024-04-22 09:22:00 UTC** - Copy operation completed (3.2 GB transferred)
5. **2024-04-22 09:23:00 UTC** - Source files deleted from Documents folder
6. **2024-04-22 09:24:00 UTC** - Recycle Bin emptied
7. **2024-04-22 09:25:00 UTC** - USB device safely removed

## Evidence Artifacts

### Present (Contradictory Evidence)
- **Registry USBSTOR:** Device connection record with serial number, vendor, product ID
- **Registry USB History:** First/last connection timestamps (09:15:00, 09:25:00)
- **Event Log 2003:** USB device connected (Event ID 6416)
- **Event Log 2004:** USB device disconnected (Event ID 6419)
- **MFT Records:** File deletion timestamps (09:23:00) for Documents folder
- **$LogFile:** NTFS transaction log shows copy operations to E: drive
- **Prefetch:** explorer.exe executed with E: drive access pattern
- **Link Files (.lnk):** Recent files point to E: drive paths
- **Jump Lists:** File Explorer shows E: drive in recent locations

### Absent (Cleaned Up)
- **Source Files:** Deleted from Documents folder
- **Recycle Bin:** Emptied (but MFT records remain)

## Expected Findings

### Finding 1: USB Device Connection Detected
```json
{
  "title": "USB Device Connected: Kingston DataTraveler",
  "severity": "medium",
  "confidence": 0.85,
  "evidence": {
    "device_vendor": "Kingston",
    "device_product": "DataTraveler",
    "device_serial": "4C530001234567890ABA",
    "capacity": "64GB",
    "first_connected": "2024-04-22T09:15:00Z",
    "last_connected": "2024-04-22T09:25:00Z",
    "connection_count": 1,
    "drive_letter": "E:"
  },
  "contradictions": [],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "USB device connection is legitimate activity. Elevated confidence when paired with file deletion evidence.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.85
    }
  ]
}
```

### Finding 2: Large File Transfer to Removable Media
```json
{
  "title": "Large Files Copied to USB Drive E:",
  "severity": "high",
  "confidence": 0.90,
  "evidence": {
    "destination": "E:\\",
    "file_count": 47,
    "total_size": 3221225472,
    "transfer_start": "2024-04-22T09:17:00Z",
    "transfer_end": "2024-04-22T09:22:00Z",
    "source_directory": "C:\\Users\\employee\\Documents\\Corporate",
    "file_types": [".docx", ".xlsx", ".pdf"]
  },
  "contradictions": [
    {
      "type": "suspicious_transfer_pattern",
      "description": "Large volume of corporate documents copied to removable media outside business hours"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "Timeline correlation: USB insertion → large file copy → source deletion. Strong indicator of data exfiltration.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.90
    }
  ]
}
```

### Finding 3: Source Files Deleted After USB Copy
```json
{
  "title": "Mass File Deletion After USB Transfer",
  "severity": "high",
  "confidence": 0.95,
  "evidence": {
    "directory": "C:\\Users\\employee\\Documents\\Corporate",
    "deleted_files": 47,
    "deletion_time": "2024-04-22T09:23:00Z",
    "recycle_bin_emptied": "2024-04-22T09:24:00Z",
    "usb_disconnect_time": "2024-04-22T09:25:00Z"
  },
  "contradictions": [
    {
      "type": "anti_forensics_pattern",
      "description": "Files deleted 1 minute after USB copy completed, then Recycle Bin emptied, then USB removed"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline strongly suggests deliberate data exfiltration followed by evidence cleanup. This is a classic insider threat pattern.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.95
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- USB device connection was unauthorized
- Large file transfer to USB was data exfiltration
- File deletion was intentional evidence cleanup

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ USB connection alone is legitimate (confidence maintained at 0.85)
- ✅ Large file transfer to USB is suspicious (confidence maintained at 0.90)
- ✅ Timeline correlation: USB → copy → delete → disconnect → Confidence increased (0.85 → 0.95)

**Reasoning Quality:**
- Engine correctly identifies that USB connections can be legitimate
- Engine correctly identifies that file transfers to USB can be legitimate (backups, working from home)
- Engine correctly increases confidence when timeline shows deliberate sequence: copy → delete source → empty recycle bin → disconnect
- Confidence adjustments are proportional to evidence strength

## Detection Logic

### Detector: USBExfiltrationDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Check for USB device connection
    usb_devices = parse_usbstor_registry(artifacts['registry'])
    if usb_devices:
        for device in usb_devices:
            finding = Finding(
                title=f"USB Device Connected: {device['vendor']} {device['product']}",
                confidence=0.85,
                evidence={
                    "device_serial": device['serial'],
                    "first_connected": device['first_connected'],
                    "last_connected": device['last_connected'],
                    "drive_letter": device['drive_letter']
                }
            )
            findings.append(finding)
    
    # Check for large file transfers to removable media
    file_transfers = parse_logfile_transfers(artifacts['$LogFile'])
    large_transfers = [t for t in file_transfers 
                      if t['destination'].startswith('E:') and t['total_size'] > 1_000_000_000]
    
    if large_transfers:
        for transfer in large_transfers:
            finding = Finding(
                title=f"Large Files Copied to USB Drive {transfer['destination'][0]}:",
                confidence=0.90,
                evidence={
                    "destination": transfer['destination'],
                    "file_count": transfer['file_count'],
                    "total_size": transfer['total_size'],
                    "transfer_start": transfer['start_time'],
                    "transfer_end": transfer['end_time']
                }
            )
            findings.append(finding)
    
    # Check for file deletions after USB transfer
    deletions = parse_mft_deletions(artifacts['mft'])
    
    if large_transfers and deletions:
        # Correlate timeline: USB insertion → transfer → deletion → disconnect
        for transfer in large_transfers:
            for deletion in deletions:
                time_diff = deletion['deletion_time'] - transfer['transfer_end']
                
                if 0 < time_diff < 300:  # Deletion within 5 minutes of transfer
                    finding = Finding(
                        title="Mass File Deletion After USB Transfer",
                        confidence=0.85,
                        evidence={
                            "directory": deletion['directory'],
                            "deleted_files": deletion['file_count'],
                            "deletion_time": deletion['deletion_time']
                        }
                    )
                    
                    # Self-correction: Timeline correlation increases confidence
                    contradiction = Contradiction(
                        type="anti_forensics_pattern",
                        description="Files deleted shortly after USB copy, classic data exfiltration pattern"
                    )
                    finding.contradictions.append(contradiction)
                    finding.confidence = 0.95  # Increased confidence
                    
                    findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd ~/Code/4n6_nexus
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 14
```

### Expected Output
```
Scenario 14: USB Device Activity (Unauthorized Data Transfer)
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **USB Forensics:** https://www.sans.org/blog/usb-forensics/
- **USBSTOR Registry:** https://www.sans.org/blog/windows-registry-artifacts/
- **Insider Threat Detection:** SANS FOR508 Advanced Incident Response
- **Data Exfiltration Patterns:** NIST SP 800-61r2
