# network_intrusion - Pass 1 Findings

**Date**: 2026-04-19
**Git SHA**: `36e39e5`
**Scenario**: `scenarios/training/network_intrusion/`

## Evidence

| File | Size | SHA-256 | Status |
|------|------|---------|--------|
| Day_1_Capture.7z | 925 MB | `3f75a2f7...ef7c31a` | Present, verified |
| ggmemday1.7z | 552 MB | `6d1f09d0...f87d0f` | Present, verified |
| Day 1 Capture [20-09].pcap | 1.2 GB | extracted | 1,544k packets, 2020-09-19 18:53-22:01 UTC |
| ggmemday1.dmp | 4.29 GB | extracted | 4 GB memory image (Linux `gg` host) |

Both SHA-256 hashes match the manifest exactly.

## Engine run

No end-to-end engine run possible:

- CLI has no `--pcap` flag (blocked by beads SFE-* PCAP issue).
- CLI has no `--memory` flag and Volatility 3 is not installed at
  `/opt/volatility3-2.20.0/vol.py` on this workstation despite
  CLAUDE.md referencing it.

Manual `PcapParser` invocation via Python worked end-to-end:

```python
from sift_find_evil.parsers.pcap_parser import PcapParser
p = PcapParser()
http = p.extract_http_requests(pcap)  # 3,548 requests
dns  = p.extract_dns_queries(pcap)    # 12,072 queries
smtp = p.extract_smtp_messages(pcap)  # 0 messages
```

Artifacts persisted:

- `http_requests.json`
- `dns_queries.json`

## Quick PCAP stats (raw)

- **Hosts** (HTTP source IPs): 156.59.33.59, .57, .180, .58, .52
- **HTTP methods**: 2,556 CONNECT, 756 POST, 233 GET
- **Top POST hosts**: all OCSP/CRL certificate status checks (cert validation noise)
- **Top CONNECT targets**: normal browsing (google, facebook, stuff.co.nz, addictinggames)
- **SMTP**: zero messages over plaintext — if exfil occurred it went over TLS or a non-SMTP channel

## Engine vs manifest

Scenario `expected:` block:

```yaml
malicious_executables: []
finding_counts:
  total: 0
min_precision: 1.0
```

The engine produces zero findings (no CLI path for PCAP/memory), so it
**technically matches** the manifest. But this is a Q&A investigative
scenario with four open questions:

1. What C2 channel(s) were used?
2. What data exfiltration occurred over the network?
3. Which process(es) in memory correspond to the network activity?
4. What network-based IOCs should be recorded?

None are answered by today's engine.

## Status

**Pass 1**: `[!]` divergence recorded. Evidence present, hashes verified,
PcapParser extracts artifacts, but the detection pipeline has no exit
point for these artifacts and no memory forensics integration.

## Blockers for Pass 2+

1. Wire `PcapParser` into `cli.py` (already filed: PCAP CLI issue).
2. Add C2/beaconing/exfiltration detectors that consume HTTP + DNS
   artifacts (new detector category: `network_forensics`).
3. Install/integrate Volatility 3 for memory analysis (beads: SFE-ig6
   "Phase 2: Volatility 3 Memory Forensics Integration").
4. Update manifest `expected:` block once detectors exist — the
   current `total: 0` target masks the gap.
