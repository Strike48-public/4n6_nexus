# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

> **Note:** This repository was developed using internal development tools and workflows. 
> The instructions below reflect the original development environment used to build 4n6 Nexus.


## Build & Test

### Run All Scenarios
```bash
PYTHONPATH=. python3 tests/scenario_harness.py
```

### Run Specific Scenario
```bash
PYTHONPATH=. python3 -m pytest tests/test_scenarios.py::test_scenario_02_ransomware -v
```

### Quality Gates
```bash
ruff check .                          # Linting
ruff format --check .                 # Format check
pytest tests/ --cov=sift_find_evil   # Coverage
```

### Expected Output
All scenarios MUST achieve:
- **Precision:** 1.00
- **Recall:** 1.00
- **F1 Score:** 1.00
- **False Positives:** 0
- **False Negatives:** 0

## Architecture Overview

### Detection Engine Components

- **Scenario Harness:** `tests/scenario_harness.py` - Orchestrates all detection scenarios
- **Detectors:** `sift_find_evil/` modules (ransomware, timestomping, memory, persistence, etc.)
- **YARA Scanner:** `sift_find_evil/yara_scan/scanner.py` - Malware signature detection
- **Synthetic Fixtures:** `scenarios/synthetic/` - JSON fixtures mimicking forensic tool output
- **Ground Truth:** Each scenario has `manifest.json` with expected findings

### Test Scenarios (12 Total)

1. `01_clean_baseline` - No malicious activity
2. `02_ransomware` - Ransomware execution detection
3. `03_timestomping` - Timestamp manipulation
4. `04_edge_cases` - Boundary condition testing
5. `05_missing_prefetch` - Execution without prefetch
6. `06_webmail_exfiltration` - Data exfiltration via webmail
7. `07_cloud_upload` - Cloud storage uploads
8. `08_persistence_run_keys` - Registry persistence
9. `09_shimcache_only` - Shimcache-based detection
10. `10_timestomping_with_bam` - Combined artifact detection
11. `11_yara_malware` - YARA rule matching
12. `12_memory_intrusion` - Memory forensics indicators

## Conventions & Patterns

### Adding New Detectors

1. **Create synthetic fixture** in `scenarios/synthetic/<name>/`
   - Add forensic artifacts (prefetch, shimcache, registry, etc.)
   - Create `manifest.json` with ground truth findings

2. **Implement detector** in `sift_find_evil/<module>/`
   - Follow existing detector patterns
   - Use synthetic fixtures for testing

3. **Register scenario** in test harness
   - Add to `tests/scenario_harness.py`

4. **Validate with harness:**
   ```bash
   PYTHONPATH=. python3 tests/scenario_harness.py
   ```

5. **Required quality gate:** F1=1.00 (perfect detection)

### YARA Rule Integration

- **Rules location:** `rules/yara/community/signature-base/` (git submodule)
- **Wrapper:** `sift_find_evil/yara_scan/scanner.py`
- **Usage:** Detectors call `YaraScanner.scan_directory()` or `scan_file()`

### MCP Threat Intelligence Tools

Available for research during detector development:

**CVE & Vulnerability (23 tools):**
- `nvd_search`, `nvd_get` - Search/get CVE details
- `epss_score`, `epss_top` - Exploit prediction scores
- `kev_check`, `kev_search` - CISA known exploited vulnerabilities
- `exploit_search` - Find public PoC exploits
- `cve_enrich`, `cve_prioritize` - Enhanced CVE analysis

**VirusTotal (7 tools):**
- `get_file_report` - Hash lookups (MD5/SHA-1/SHA-256)
- `get_ip_report`, `get_domain_report`, `get_url_report` - Reputation checks
- `get_file_relationship`, `get_ip_relationship`, `get_url_relationship` - Relationship mapping

**Threat Intelligence (8 tools):**
- `abuseipdb_check` - IP reputation and abuse reports
- `greynoise_ip` - Internet scanner detection
- `threatintel_lookup_hash`, `threatintel_lookup_ip`, `threatintel_lookup_domain` - Multi-source lookups
- `feodo_tracker` - Active botnet C2 servers

**Web Research (5 tools):**
- `tavily_search`, `tavily_research` - Threat intelligence research
- `tavily_extract`, `tavily_crawl`, `tavily_map` - Content extraction

### Evidence Handling

- **Development:** Use synthetic fixtures (fast, deterministic, CI-friendly)
- **Real evidence:** Only process when validating against actual forensic data
- **Never modify:** Files in `/cases/`, `/mnt/`, `/media/`, `evidence/` directories
- **Output routing:** Write analysis to `./analysis/`, `./exports/`, `./reports/`
