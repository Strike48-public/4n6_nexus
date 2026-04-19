# M57 Patents Scenario

Complete documentation for the M57 Patents corporate espionage scenario from Digital Corpora.

## Quick Start

1. **Read the scenario overview:**
   ```bash
   cat SCENARIO_INFO.md
   ```

2. **Download evidence:**
   ```bash
   # Download just Jean's evidence (primary suspect)
   ./download_all.sh jean
   
   # Or download all evidence (50-100 GB!)
   ./download_all.sh all
   ```

3. **Begin analysis:**
   - Mount E01 images with `ewfmount` or FTK Imager
   - Use Autopsy/Sleuth Kit for disk forensics
   - Analyze network captures with Wireshark
   - Review the investigation guide in docs/

## Files in This Directory

- **SCENARIO_INFO.md** - Complete scenario description, characters, timeline, investigation guidance
- **download_all.sh** - Automated download script with hash verification
- **DOWNLOAD_URLS.txt** - All download URLs for manual/selective download
- **files_manifest.json** - Structured metadata about all evidence files
- **README.md** - This file

## Scenario Overview

**Type:** Corporate espionage / Intellectual property theft  
**Setting:** M57.biz (fictional patent consulting firm)  
**Date:** November-December 2009  
**Difficulty:** Advanced  
**Time:** 20-40 hours of analysis

## Characters & Evidence

- **Jean** - Technical staff (primary suspect) - Laptop + USB
- **Pat** - Employee - Desktop + USB
- **Terry** - Employee - Laptop + USB
- **Charlie** - Employee - Laptop + USB
- **Jo** - Employee - Laptop + USB
- **Network** - PCAP captures from company network
- **Memory** - RAM dumps from suspect systems

## Investigation Goals

1. Determine if IP theft occurred
2. Identify the perpetrator(s)
3. Establish timeline of suspicious activities
4. Recover evidence of data exfiltration
5. Document chain of custody
6. Identify external parties involved

## Download Options

```bash
# Show all options
./download_all.sh help

# Download specific character
./download_all.sh jean      # Primary suspect
./download_all.sh pat       # Additional employee
./download_all.sh terry     # Additional employee
./download_all.sh charlie   # Additional employee
./download_all.sh jo        # Additional employee

# Download supplementary evidence
./download_all.sh network   # PCAP files
./download_all.sh memory    # RAM dumps
./download_all.sh docs      # Teaching materials

# Download everything
./download_all.sh all       # WARNING: 50-100 GB!
```

## Storage Requirements

- **Minimum:** 20 GB (single character)
- **Recommended:** 50 GB (multiple characters)
- **Complete:** 100-150 GB (all evidence)

## Tools Recommended

### Disk Forensics
- Autopsy / The Sleuth Kit
- FTK Imager
- X-Ways Forensics
- EnCase

### Memory Analysis
- Volatility
- Rekall

### Network Analysis
- Wireshark
- NetworkMiner
- tcpdump

### Timeline & Correlation
- log2timeline / Plaso
- Timesketch

## Next Steps After Download

1. **Verify integrity** - Check MD5/SHA256 hashes
2. **Mount images** - Use `ewfmount` for E01 files
3. **Initial triage** - Quick scan for obvious artifacts
4. **Timeline creation** - Use log2timeline for super timeline
5. **Email analysis** - Extract and review communications
6. **USB forensics** - Analyze device connection artifacts
7. **Network analysis** - Correlate PCAP with disk timeline
8. **Report writing** - Document findings with evidence

## Teaching Materials

The `docs/` directory (after download) contains:
- Scenario description (scenario.pdf)
- Investigation guide (guide.pdf)
- Solution guide (solution.pdf - password protected, faculty only)

**Password Info:** https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/

## Educational Use

This scenario is excellent for:
- Advanced forensics training courses
- Graduate-level digital forensics
- Professional certification preparation (GCFE, EnCE, CCE)
- Tool validation and testing
- Research in forensic methodologies

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
- **Solution Passwords:** https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/

## Known Issues

- URLs may need verification (some paths estimated based on Digital Corpora conventions)
- Hash values will be calculated during first download
- Network/memory directories may have different structures than documented
- Some files may require browsing the directory structure

## Support

For issues with:
- **Files/Downloads:** Contact Digital Corpora
- **Forensic Analysis:** DFIR community forums
- **Educational Use:** Contact scenario authors

---

**Last Updated:** 2026-04-17  
**Status:** Documentation complete, awaiting download verification
