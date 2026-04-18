# DFIR Training Image Download - Quick Reference

**Last Updated:** 2026-04-17  
**Available Storage:** 175 GB  
**Recommended Total:** 34 GB (19% of available)

---

## Priority Matrix

| Priority | Source | Scenario | Size | Value | Automation |
|----------|--------|----------|------|-------|------------|
| P1 | DFIR.training | Ransomware Investigation | 8 GB | CRITICAL | Manual |
| P1 | DFIR.training | Blue Team IR Challenge | 10 GB | HIGH | Manual |
| P1 | DFIR.training | Insider Threat Case | 6 GB | HIGH | Manual |
| P2 | DFIR.training | Network Intrusion | 4 GB | HIGH | Manual |
| P2 | CFReDS | Data Leakage Case | 0.6 GB | MEDIUM | Automated |
| P2 | CFReDS | Linux Hacking Case | 1.5 GB | MEDIUM | Automated |
| P3 | CFReDS | Memory Analysis Sets | 3 GB | MEDIUM | Automated |
| P3 | CFReDS | File Carving Tests | 1 GB | MEDIUM | Automated |
| SKIP | DFTT | All datasets | <5 GB | LOW | N/A |

**Total Recommended:** ~34 GB

---

## Source Comparison

| Factor | DFIR.training | CFReDS (NIST) | DFTT |
|--------|---------------|---------------|------|
| Last Update | 2023-2026 | ~2015 | ~2012 |
| Training Value | HIGH | MEDIUM | LOW |
| Modern OS | Yes (Win10/11) | No (WinXP-7) | No |
| Automation | Medium | Excellent | Good |
| Access | Registration | Open | Open |

---

## Week 1 Action Plan (Priority 1)

**Goal:** Download modern, high-value scenarios  
**Storage:** 24 GB  
**Time:** 2-3 hours (manual)

### Steps

1. Register at https://www.dfir.training
2. Download scenarios:
   - Ransomware Investigation (8 GB)
   - Blue Team IR Challenge (10 GB)
   - Insider Threat Case (6 GB)
3. Organize into `/cases/dfir_training/`
4. Create metadata entries
5. Verify accessibility

**Guide:** See `scripts/download-dfir-training-guide.md`

---

## Week 2 Action Plan (Priority 2)

**Goal:** Add Linux coverage and tool validation datasets  
**Storage:** 6 GB  
**Time:** 30 minutes (automated)

### Steps

```bash
# Step 1: Verify URLs are current
./scripts/verify-cfreds-urls.sh

# Step 2: If verification passes, download datasets
./scripts/download-cfreds.sh

# Downloads:
# - Data Leakage Case (0.6 GB)
# - Linux Hacking Case (1.5 GB)
# - Verifies integrity with SHA1 checksums
```

**Destination:** `/cases/cfreds/`

**Note:** NIST URLs may change periodically. If downloads fail, see `docs/CFREDS_DOWNLOAD_GUIDE.md` for manual download instructions.

---

## Quick Commands

### Check Available Space

```bash
df -h /cases/
```

### Verify CFReDS URLs

```bash
./scripts/verify-cfreds-urls.sh
```

### Automated CFReDS Download

```bash
./scripts/download-cfreds.sh
```

### Manual DFIR.training Download

See `scripts/download-dfir-training-guide.md` for detailed instructions.

### Verify Downloaded Images

```bash
# List all forensic images
find /cases -type f \( -name "*.E01" -o -name "*.dd" -o -name "*.raw" \) -exec ls -lh {} \;

# Check total storage used
du -sh /cases/dfir_training/ /cases/cfreds/
```

---

## Training Focus Areas

### Priority 1 Scenarios Cover

- Ransomware deployment and encryption analysis
- Memory forensics and timeline correlation
- Lateral movement detection
- Insider threat indicators
- Data exfiltration patterns
- Email and phishing forensics

### Priority 2 Adds

- Network forensics and C2 detection
- Linux system compromise analysis
- Data recovery and deleted file analysis
- Tool validation workflows

---

## Why These Sources?

### DFIR.training (Priority 1)
- Modern Windows 10/11 scenarios
- Realistic enterprise attack patterns
- Active community and support
- Detailed investigation guides
- Regularly updated

### CFReDS/NIST (Priority 2)
- Linux coverage (gaps in DFIR.training)
- Tool validation and verification
- Authoritative source with ground truth
- Fully automated downloads
- No access restrictions

### DFTT (Skip)
- Outdated (pre-2012)
- Academic focus only
- Not realistic investigation scenarios
- Better alternatives available

---

## Success Metrics

- [ ] All P1 scenarios downloaded (24 GB)
- [ ] All P2 datasets downloaded (6 GB)
- [ ] Total storage under 50% capacity
- [ ] Metadata catalog updated
- [ ] At least one scenario analyzed with sift_find_evil
- [ ] Findings documented

---

## Quarterly Maintenance

- Check dfir.training for new scenarios
- Review storage usage
- Archive analyzed scenarios
- Update documentation
- Plan additional downloads

---

## Full Documentation

- **Comprehensive Analysis:** `ADDITIONAL_SOURCES_RESEARCH.md` (21 KB)
- **CFReDS Download Guide:** `docs/CFREDS_DOWNLOAD_GUIDE.md` (troubleshooting and manual steps)
- **CFReDS URL Verification:** `scripts/verify-cfreds-urls.sh` (check URLs before download)
- **CFReDS Automation:** `scripts/download-cfreds.sh` (automated download with validation)
- **DFIR.training Manual Process:** `scripts/download-dfir-training-guide.md`
- **Digital Corpora Catalog:** `docs/digitalcorpora-comprehensive-catalog.md`

---

**Next Action:** Register at dfir.training and begin Priority 1 downloads
