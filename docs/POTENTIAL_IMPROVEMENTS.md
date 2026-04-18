# SIFT Find Evil - Potential Improvements

**Last Updated:** 2026-04-18

This document tracks potential improvements identified during development and analysis. Items are organized by category and priority.

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

## Recent Additions

- **2026-04-18:** Initial document created based on P2/P4 backlog work session
  - Added NSRL integration, confidence calibration, SIFT tool detection
  - Added validator stress testing, case study documentation
  - Added new detector ideas (browser history, lateral movement, cloud exfil)
