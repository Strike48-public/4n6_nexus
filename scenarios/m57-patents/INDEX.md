# M57 Patents Scenario - Documentation Index

Complete documentation package for the M57 Patents corporate espionage scenario from Digital Corpora.

## Files in This Directory

| File | Size | Purpose |
|------|------|---------|
| **README.md** | 4.9 KB | Overview and navigation guide |
| **QUICKSTART.md** | 6.3 KB | 30-minute getting started guide |
| **SCENARIO_INFO.md** | 13 KB | Complete scenario description and background |
| **ANALYSIS_WORKFLOW.md** | 9.4 KB | Phase-by-phase analysis methodology |
| **DOWNLOAD_URLS.txt** | 5.3 KB | All download URLs for manual retrieval |
| **files_manifest.json** | 12 KB | Structured metadata about all evidence |
| **download_all.sh** | 8.9 KB | Automated download script with verification |
| **verify_files.sh** | 4.3 KB | Hash calculation and integrity verification |

## Where to Start

### I'm New to This Scenario
**Start here:** `README.md`

Overview of the scenario, characters, and objectives.

### I Want to Begin Immediately
**Start here:** `QUICKSTART.md`

Get analyzing in 30 minutes with Jean's evidence (primary suspect).

### I Need Complete Information
**Start here:** `SCENARIO_INFO.md`

Full scenario background, all characters, complete file inventory, and investigation guidance.

### I Want a Structured Approach
**Start here:** `ANALYSIS_WORKFLOW.md`

10-phase workflow covering all forensic techniques and cross-correlation.

### I Want to Download Evidence
**Start here:** `./download_all.sh help`

```bash
./download_all.sh jean     # Primary suspect only
./download_all.sh all      # Everything (50-100 GB)
./download_all.sh docs     # Teaching materials only
```

## Scenario Quick Facts

- **Type:** Corporate espionage / IP theft
- **Company:** M57.biz (fictional patent consulting firm)
- **Date:** November-December 2009
- **Difficulty:** Advanced
- **Time Required:** 20-40 hours of analysis
- **Total Size:** 50-100 GB (all evidence)

## Evidence Available

### Primary Suspect
- **Jean** - Technical staff with laptop and USB drive

### Additional Employees
- **Pat** - Desktop computer and USB drive
- **Terry** - Laptop and USB drive
- **Charlie** - Laptop and USB drive
- **Jo** - Laptop and USB drive

### Supplementary Evidence
- **Network captures** - PCAP files from company network
- **Memory dumps** - RAM images from suspect systems
- **Teaching materials** - Scenario docs, guides, solutions

## Investigation Objectives

1. Determine if intellectual property theft occurred
2. Identify the perpetrator(s)
3. Establish timeline of suspicious activities
4. Recover evidence of data exfiltration
5. Document chain of custody for legal proceedings
6. Identify external parties or accomplices

## Key Forensic Areas

- Disk forensics (filesystem, deleted files, timeline)
- Registry analysis (USB devices, system info)
- Email communications
- Browser artifacts
- USB device forensics
- Network traffic analysis
- Memory forensics
- Document metadata analysis
- Timeline correlation across devices

## Recommended Tools (Available on SANS SIFT)

- **Autopsy / Sleuth Kit** - Disk forensics
- **log2timeline / Plaso** - Super timeline generation
- **Volatility** - Memory forensics
- **Wireshark** - Network analysis
- **RegRipper** - Registry analysis
- **bulk_extractor** - Feature extraction
- **ewfmount** - E01 image mounting

## File Structure After Download

```
m57-patents/
├── README.md                      # This index
├── QUICKSTART.md                  # Fast start guide
├── SCENARIO_INFO.md               # Complete scenario info
├── ANALYSIS_WORKFLOW.md           # Methodology guide
├── DOWNLOAD_URLS.txt              # URL reference
├── files_manifest.json            # Structured metadata
├── download_all.sh                # Download automation
├── verify_files.sh                # Hash verification
├── file_hashes.txt                # Generated after verify
├── jean/                          # Jean's evidence
│   ├── nps-2008-jean.E01
│   ├── nps-2008-jean.E02
│   ├── nps-2008-jean.E03
│   └── jean-usb-2009-12-11.E01
├── pat/                           # Pat's evidence
├── terry/                         # Terry's evidence
├── charlie/                       # Charlie's evidence
├── jo/                            # Jo's evidence
├── network/                       # PCAP files
├── memory/                        # RAM dumps
├── docs/                          # Teaching materials
└── analysis/                      # Your analysis work
    ├── timelines/
    ├── registry/
    ├── email/
    ├── recovered/
    └── reports/
```

## Usage Examples

### Download Primary Suspect Evidence
```bash
./download_all.sh jean
```

### Verify Downloaded Files
```bash
./verify_files.sh
```

### Mount Evidence
```bash
sudo ewfmount jean/nps-2008-jean.E01 /mnt/ewf/jean
sudo mount -o ro /mnt/ewf/jean/ewf1 /mnt/evidence/jean
```

### Generate Timeline
```bash
log2timeline.py --storage-file analysis/jean.plaso /mnt/ewf/jean/ewf1
psort.py -o l2tcsv -w analysis/jean_timeline.csv analysis/jean.plaso
```

### Launch Autopsy GUI
```bash
autopsy
# Add data source: /mnt/ewf/jean/ewf1
```

## Learning Objectives

This scenario teaches:
- Multi-device investigation coordination
- Timeline analysis and correlation
- Email threading and communication analysis
- USB device forensics
- Network traffic correlation with disk activity
- Memory forensics integration
- Anti-forensics detection
- Report writing with proper evidence citation
- Chain of custody documentation
- Legal admissibility considerations

## Educational Use

Ideal for:
- Advanced digital forensics courses (graduate level)
- Professional certification preparation (GCFE, EnCE, CCE)
- Law enforcement training
- Corporate security training
- Forensic tool validation research
- Academic research in forensic methodologies

## Citation

When using this scenario in academic work:

```
Garfinkel, S., Farrell, P., Roussev, V., & Dinolt, G. (2009).
M57-Patents Scenario. Digital Corpora.
https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
```

## Additional Resources

- **Digital Corpora:** https://digitalcorpora.org/
- **Scenario Page:** https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
- **Solution Access:** https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/
- **SANS SIFT:** https://www.sans.org/tools/sift-workstation/
- **FOR508 Course:** https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/

## Getting Help

- **Download Issues:** Check Digital Corpora website
- **Tool Issues:** Consult SANS SIFT documentation
- **Forensic Techniques:** SANS FOR508 course materials
- **Scenario Discussion:** DFIR community forums

## Status & Notes

**Documentation Status:** Complete  
**Last Updated:** 2026-04-17  
**Download Verification:** Pending (awaiting file downloads)  

**Known Limitations:**
- URLs estimated based on Digital Corpora conventions
- Hash values will be calculated during first download
- Some directory structures may vary from documentation
- Network/memory directories may require browsing

**Recommended Next Steps:**
1. Run `./download_all.sh jean` to get primary suspect evidence
2. Run `./verify_files.sh` to generate hash inventory
3. Follow `QUICKSTART.md` for rapid initial analysis
4. Refer to `ANALYSIS_WORKFLOW.md` for comprehensive methodology

---

**Ready to begin? Start with `README.md` or `QUICKSTART.md`**
