# Jean Case - Acceptance Test Results

**Date**: 2026-04-17
**Image**: nps-2008-jean.E01 (M57 Patents case)
**Test Type**: Artifact-centric acceptance (SFE-5)

## Test Objective

Validate that the SIFT Find Evil engine can detect data exfiltration patterns in real-world forensic images using only artifact-centric criteria (no case-specific string matching).

## Acceptance Criteria

All criteria are artifact-centric; no case-string matching allowed.

- [x] At least one finding with `category == data_exfiltration`
- [x] Finding has `severity == CRITICAL`
- [x] Finding has `confidence >= 0.90`
- [x] Evidence contains two independent SHA-256 values that are byte-equal (cross-artifact hash correlation)
- [x] Evidence contains save-to-send delta under 300s
- [x] Reasoning chain cites at least two independent artifact sources (MFT + PST)
- [x] Finding ranks in top 5 by confidence (ranked #1)
- [x] No acceptance criterion references case-specific strings ("Jean", "m57biz", "exfil", "tuckgorge")

## Results

### Finding Summary

**Title**: Data exfiltration: <unnamed> via email
**Category**: `data_exfiltration`
**Severity**: `CRITICAL`
**Confidence**: `0.95` (Very High)
**Rank**: #1 of 857 findings

### Evidence

```json
{
  "match_type": "hash",
  "file_path": ".\\Documents and Settings\\Jean\\Desktop\\m57biz.xls",
  "file_hash": "34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f",
  "attachment_hash": "34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f",
  "save_time": "2008-07-20T01:28:03.656250+00:00",
  "send_time": "2008-07-20T01:28:47.828125+00:00",
  "delta_seconds": 44.171875,
  "email_subject": "RE: Please send me the information now",
  "email_folder": "<root>/Top of Personal Folders/Sent Items",
  "attachment_name": "<unnamed>",
  "attachment_size": 291840
}
```

### Reasoning Chain

1. File-save-then-email pattern detected (hash match)
2. File: .\Documents and Settings\Jean\Desktop\m57biz.xls
3. Saved: 2008-07-20T01:28:03.656250+00:00
4. Emailed: 2008-07-20T01:28:47.828125+00:00 (44.2s later)
5. Subject: RE: Please send me the information now
6. Attachment: <unnamed> (291840 bytes)
7. SHA-256 match: 34456b5f714dc9d8... (on-disk) == 34456b5f714dc9d8... (email)
8. Cryptographic proof: file bytes are byte-identical

### Cross-Artifact Correlation

**Independent Sources**:
- **MFT** ($STANDARD_INFORMATION timestamps, file path, SHA-256 from disk image)
- **PST** (email metadata, attachment bytes, SHA-256 from attachment)

**Hash Correlation**:
- On-disk file hash: `34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f`
- Email attachment hash: `34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f`
- **Result**: Byte-identical (cryptographic proof)

**Temporal Correlation**:
- File save time: `2008-07-20T01:28:03.656250+00:00`
- Email send time: `2008-07-20T01:28:47.828125+00:00`
- Delta: `44.17 seconds` (well under 300s threshold)

## Analysis

### Key Findings

1. **Hash-based correlation works**: The engine successfully computed SHA-256 for both the on-disk file (via pytsk3 + pyewf) and the PST attachment (via pypff), proving byte-identity without relying on filename or metadata.

2. **Temporal window detection**: The 44-second delta between file save and email send falls well within the 300-second suspicious window, indicating rapid exfiltration.

3. **Artifact-centric detection**: The finding was produced without any case-specific keywords. The detector would flag this pattern in any disk image exhibiting the same hash-identity + temporal correlation.

4. **Confidence scoring**: The 0.95 confidence (Very High) reflects the cryptographic certainty of hash-based matching versus size+name fallback (0.65).

5. **Top-ranked finding**: Among 857 total findings, the exfiltration pattern ranked #1 by confidence, ensuring it surfaces immediately for analyst review.

### Technical Achievements

1. **Fixed partition offset detection**: Implemented automatic NTFS partition detection to handle images with partition tables (Jean uses offset 32256 bytes, not 0).

2. **Fixed CSV BOM handling**: Updated MFT parser to use `utf-8-sig` encoding to correctly parse MFTECmd CSV files with UTF-8 BOM.

3. **Hash-based file identity**: Successfully reads file content from E01 split images and computes SHA-256 for correlation against PST attachments.

4. **Timezone normalization**: PST timestamps normalized to UTC-aware for consistent temporal correlation with MFT $SI timestamps.

### Limitations Addressed

- **Unnamed attachments**: The PST file contains attachments with name `<unnamed>`, but hash-based correlation works regardless of filename.
- **Multi-segment E01 images**: The reader handles split images (.E01, .E02) via pyewf auto-discovery.
- **Large file handling**: Files read in 4 MB windows to avoid memory exhaustion.

## Verdict

**PASS** - All artifact-centric acceptance criteria met.

The engine successfully detected the file-save-then-email exfiltration pattern using:
- Cryptographic hash correlation (SHA-256)
- Independent artifact sources (MFT + PST)
- Temporal proximity analysis (44s delta)
- Case-agnostic detection logic

The finding ranks #1 by confidence and meets all requirements for production deployment.

## Regression Testing

This result is captured for regression testing. If future changes cause:
- Confidence to drop below 0.90
- Finding to fall out of top 5
- Hash correlation to fail
- Evidence to lose independent source citations

Then the regression must be investigated and resolved before deployment.

## Full Results

- **Total findings**: 857
- **Exfiltration findings**: 1
- **Top-ranked finding confidence**: 0.95
- **Raw JSON**: `analysis/real_examples/nps-2008-jean/acceptance_test_results.json`
