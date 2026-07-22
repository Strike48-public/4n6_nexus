# Scenario Fixes - 2026-04-26

**Goal:** Fix all 5 USB scenarios to enable comprehensive regression testing.

---

## Fixes Applied

### 1. blue_team_challenge - FIXED ✓

**Problem:** scenario.yaml referenced archive files (alison_ws.7z, aamemend.7z) instead of extracted evidence.

**Solution:** Updated scenario.yaml to point to extracted files:
- `evidence/alison_ws.E01` (8.8GB disk image)
- `evidence/aamemend.dmp` (4.3GB memory dump)

**Files Changed:**
- `/mnt/usb-evidence/sift_evidence/blue_team_challenge/scenario.yaml`
- Backup: `scenario.yaml.bak`

**Status:** Ready for testing

---

### 2. ransomware_2021 - FIXED ✓

**Problem:** scenario.yaml referenced archive file (Forensic_Image_Files.zip) instead of extracted evidence.

**Solution:** Updated scenario.yaml to point to extracted files:
- `evidence/Forensic Image Files/LoneWolf.E01` (multi-segment E01, segments E01-E09)
- `evidence/Forensic Image Files/memdump.mem` (memory dump, optional)

**Files Changed:**
- `/mnt/usb-evidence/sift_evidence/ransomware_2021/scenario.yaml`
- Backup: `scenario.yaml.bak`

**Status:** Ready for testing

---

### 3. insider_threat_2022 - IN PROGRESS ⏳

**Problem:** Missing required memory capture file.

**What Exists:**
- Narcos-CCleaner.E01 (7.7GB disk image) ✓

**What's Missing:**
- Narcos-Mem-CCleaner.E01 (1.4GB memory capture)

**Solution:** Downloading from Digital Corpora:
```bash
wget https://downloads.digitalcorpora.org/corpora/scenarios/2019-narcos/Narcos-Mem-CCleaner.E01
```

**Download Progress:** In progress (started at ~21:45)

**Status:** Downloading (ETA: ~15-20 minutes)

---

### 4. national_gallery_2012 - IN PROGRESS ⏳

**Problem:** Missing E01 segments for multi-segment images.

**Evidence Status:**

| Item | Segments | Status |
|------|----------|--------|
| carry-phone | - | ✓ Extracted from zip |
| carry-tablet | E01 only | ✓ Complete |
| tracy-external | E01 only | ✓ Complete |
| tracy-home | E01, E02 | ⏳ E02 downloading |
| tracy-phone | E01 | ⏳ Downloading |

**Downloads in Progress:**
1. tracy-home-2012-07-16-final.E02 (1.5GB) - segment 2 of 2
2. tracy-phone-2012-07-15-final.E01 (788MB) - complete phone image

**Status:** Downloading (ETA: ~15-20 minutes)

---

### 5. m57-patents - ALREADY WORKING ✓

**Status:** PASS (F1=1.00, 2 findings)

**Evidence:**
- charlie-2009-12-11.E01 (3.9GB) ✓
- jo-2009-12-11-001.E01 (5.9GB, missing segment 2) - not required for test to pass

**No changes needed.**

---

## Expected Results After All Fixes

Once all downloads complete:

| Scenario | Expected Status | Evidence Count | Size |
|----------|----------------|----------------|------|
| m57-patents | PASS | 2 images | 9GB |
| blue_team_challenge | PASS/SKIP | 2 files | 13GB |
| ransomware_2021 | PASS/SKIP | 9 segments + mem | 50GB |
| insider_threat_2022 | PASS/SKIP | 2 files | 9GB |
| national_gallery_2012 | PASS/SKIP | 5 evidence items | 25GB |

**Note:** Some scenarios may still SKIP if they require features not yet implemented (e.g., memory analysis requires Volatility integration).

---

## Verification Steps

After downloads complete:

```bash
# Run batch test with updated scenarios
./scripts/run-batch-test-on-sift.sh

# Expected: 5 scenarios discovered, fewer skipped than before
# Check results
cat test-results/usb-batch/latest/SUMMARY.md
```

---

## Files Modified

### On USB Drive (/mnt/usb-evidence/sift_evidence/)

**Backups Created:**
- `blue_team_challenge/scenario.yaml.bak`
- `ransomware_2021/scenario.yaml.bak`

**Updated:**
- `blue_team_challenge/scenario.yaml`
- `ransomware_2021/scenario.yaml`

**Downloaded:**
- `insider_threat_2022/evidence/Narcos-Mem-CCleaner.E01` (in progress)
- `national_gallery_2012/evidence/tracy-home/tracy-home-2012-07-16-final.E02` (in progress)
- `national_gallery_2012/evidence/tracy-phone/tracy-phone-2012-07-15-final.E01` (in progress)

---

## Rollback Instructions

If needed, restore original scenario.yaml files:

```bash
ssh sansforensics@192.168.122.76
sudo cp /mnt/usb-evidence/sift_evidence/blue_team_challenge/scenario.yaml.bak \
       /mnt/usb-evidence/sift_evidence/blue_team_challenge/scenario.yaml
sudo cp /mnt/usb-evidence/sift_evidence/ransomware_2021/scenario.yaml.bak \
       /mnt/usb-evidence/sift_evidence/ransomware_2021/scenario.yaml
```

---

**Last Updated:** 2026-04-26 21:50 (downloads in progress)
