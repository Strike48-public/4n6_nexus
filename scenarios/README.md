# DFIR Practice Scenarios

This directory contains documentation, download scripts, and metadata for Digital Forensics practice scenarios. Binary evidence files are stored separately in `../practice_images/`.

## Directory Structure

```
scenarios/
├── README.md                    # This file
├── nitroba/                     # Nitroba University Harassment (2008)
│   ├── NITROBA_SCENARIO_INFO.md
│   ├── download_all.sh
│   └── files_manifest.json
├── m57-patents/                 # M57 Patents Scenario (2009)
│   ├── SCENARIO_INFO.md
│   ├── QUICKSTART.md
│   ├── ANALYSIS_WORKFLOW.md
│   ├── download_all.sh
│   └── files_manifest.json
└── circl-2023-wiped/            # CIRCL Wiped Disk Challenge (2023)
```

## Available Scenarios

### 1. Nitroba University Harassment (2008)

**Difficulty:** Beginner  
**Focus:** Network forensics, email tracing  
**Size:** 53.6 MB (PCAP only)

**Scenario:** Lily Tuckridge at Nitroba State University received harassing emails. Network capture from July 21, 2008 contains evidence to identify which Chemistry 109 student sent the emails via web-based service.

**Files:** 1 PCAP, teaching materials (slides), password-protected solutions

**Location:** 
- Documentation: `scenarios/nitroba/`
- Evidence: `practice_images/nitroba/`

**Download:** `cd scenarios/nitroba && ./download_all.sh`

### 2. M57 Patents Scenario (2009)

**Difficulty:** Intermediate to Advanced  
**Focus:** Corporate espionage, disk forensics, memory analysis, timeline reconstruction  
**Size:** 50-100 GB (full scenario)

**Scenario:** Corporate intellectual property theft investigation at M57.biz involving 5 employees (Jean, Pat, Terry, Charlie, Jo) during November-December 2009.

**Files:** 
- 5 laptop/desktop disk images (E01 format)
- 5 USB drive images
- Network packet captures
- Memory dumps
- Teaching materials

**Location:**
- Documentation: `scenarios/m57-patents/`
- Evidence: `practice_images/m57-patents/`

**Download:** 
- Individual character: `cd scenarios/m57-patents && ./download_all.sh jean`
- Full scenario: `cd scenarios/m57-patents && ./download_all.sh all`

**Quick Start:** See `scenarios/m57-patents/QUICKSTART.md` for 30-minute rapid start guide

### 3. CIRCL Wiped Disk Challenge (2023)

**Difficulty:** Advanced  
**Focus:** Data recovery, file carving, anti-forensics  
**Size:** TBD

**Status:** Documentation pending

## Usage Workflow

1. **Choose a scenario** based on difficulty and learning objectives
2. **Read the scenario documentation** in `scenarios/<scenario-name>/`
3. **Download evidence files** using the provided `download_all.sh` script
4. **Verify file integrity** using checksums in `files_manifest.json`
5. **Follow analysis guides** (e.g., `QUICKSTART.md`, `ANALYSIS_WORKFLOW.md`)
6. **Practice with SIFT tools** on the SANS SIFT Workstation

## Design Principles

### Separation of Concerns

- **scenarios/** - Version controlled, contains:
  - Scenario narratives and learning objectives
  - Download scripts and automation
  - File manifests with checksums
  - Analysis workflows and methodologies
  - Teaching materials and references

- **practice_images/** - Git-ignored, contains:
  - ALL binary evidence files (disk images, memory dumps, network captures)
  - Re-downloadable via scripts in scenarios/
  - Not version controlled due to size

### Benefits

1. **Clean git repository** - Only documentation and scripts tracked
2. **Flexible downloads** - Download only what you need
3. **Evidence integrity** - Checksums ensure chain of custody
4. **Consistent structure** - Same pattern across all scenarios
5. **Maintainable** - Easy to add new scenarios

## Adding New Scenarios

When adding a new scenario:

1. Create `scenarios/<scenario-name>/` directory
2. Add required files:
   - `SCENARIO_INFO.md` - Complete documentation
   - `download_all.sh` - Download script with hash verification
   - `files_manifest.json` - Structured metadata
   - `DOWNLOAD_URLS.txt` - Quick reference
3. Create corresponding `practice_images/<scenario-name>/` subdirectories
4. Update this README with scenario details
5. Ensure binary files remain git-ignored

## Resources

- [Digital Corpora](https://digitalcorpora.org/) - Source of many forensic scenarios
- [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/) - Required forensic platform
- [Sleuth Kit Documentation](https://sleuthkit.org/) - File system analysis tools
- [Volatility 3](https://volatility3.readthedocs.io/) - Memory forensics framework

## Contributing

When contributing new scenarios or improvements:

1. Maintain the established directory structure
2. Include comprehensive documentation
3. Provide checksums for all evidence files
4. Test download scripts on clean system
5. Update this index with new scenario details

---

Last updated: 2026-04-17
