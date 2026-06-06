"""SFE-fqn FP validation against the real Nitroba PCAP.

Runs the two FP-audit candidates that real PCAP can actually reproduce:

1. BeaconingDetector (CoV <= 0.15): the audit hypothesised this floods on
   periodic-but-benign traffic (NTP / telemetry / monitoring). Nitroba is a
   real campus capture full of ordinary browsing + background polling, so any
   beaconing hit here is a candidate false positive to inspect.

2. DNSAnomalyDetector CDN suppression: the audit flagged the CDN allowlist as
   incomplete (missing akamai/fastly/azurefd). We surface every DNS finding
   plus the apex/longest-label so we can see whether real CDN/ad traffic in
   Nitroba trips the long-high-entropy-label rule.

Read-only. Writes a JSON + human summary to analysis/. Run on the SIFT VM
where tshark + nitroba.pcap exist:

    PYTHONPATH=. venv/bin/python analysis/fp_validate_nitroba.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sift_find_evil.parsers.pcap_parser import PcapParser
from sift_find_evil.detectors.stats_detector import (
    BeaconingDetector,
    DNSAnomalyDetector,
)

PCAP = Path("scenarios/real/nitroba/evidence/nitroba.pcap")
OUT = Path("analysis/fp_validate_nitroba.json")


def main() -> int:
    if not PCAP.exists():
        print(f"PCAP not found: {PCAP}", file=sys.stderr)
        return 1

    parser = PcapParser()

    print(f"[*] Parsing {PCAP} ...")
    http = parser.extract_http_requests(PCAP)
    dns = parser.extract_dns_queries(PCAP)
    print(f"[*] HTTP requests: {len(http)}   DNS queries: {len(dns)}")

    # --- Candidate 1: beaconing CoV <= 0.15 on real campus traffic ----------
    beacon = BeaconingDetector()
    beacon_findings = beacon.analyze(http)

    # --- Candidate 2: DNS anomaly + CDN suppression -------------------------
    dns_det = DNSAnomalyDetector()
    dns_findings = dns_det.analyze(dns)

    # For the CDN-list question: which apexes produced the longest labels even
    # if below threshold? Surfaces what real CDN traffic looks like here.
    label_samples = []
    for q in dns:
        longest = max(
            (lbl for lbl in q.query_name.strip(".").split(".") if lbl),
            key=len,
            default="",
        )
        if len(longest) >= 25:  # below the 40-char trigger, but worth seeing
            label_samples.append(
                {
                    "query_name": q.query_name,
                    "longest_label_len": len(longest),
                    "src_ip": q.src_ip,
                }
            )
    label_samples.sort(key=lambda d: d["longest_label_len"], reverse=True)

    result = {
        "pcap": str(PCAP),
        "counts": {"http_requests": len(http), "dns_queries": len(dns)},
        "beaconing": {
            "params": {
                "min_events": beacon.min_events,
                "max_cov": beacon.max_cov,
                "min_mean_seconds": beacon.min_mean_seconds,
                "methods": list(beacon.methods),
            },
            "finding_count": len(beacon_findings),
            "findings": [
                {
                    "host": f.evidence["host"],
                    "src_ip": f.evidence["src_ip"],
                    "event_count": f.evidence["event_count"],
                    "mean_interval_seconds": f.evidence["mean_interval_seconds"],
                    "coefficient_of_variation": f.evidence["coefficient_of_variation"],
                    "confidence": f.confidence,
                }
                for f in beacon_findings
            ],
        },
        "dns_anomaly": {
            "params": {
                "min_label_length": dns_det.min_label_length,
                "min_entropy": dns_det.min_entropy,
                "ignore_known_cdn_patterns": dns_det.ignore_known_cdn_patterns,
            },
            "finding_count": len(dns_findings),
            "findings": [
                {
                    "apex_domain": f.evidence["apex_domain"],
                    "src_ip": f.evidence["src_ip"],
                    "longest_label": f.evidence["longest_label"],
                    "longest_label_length": f.evidence["longest_label_length"],
                    "longest_label_entropy": f.evidence["longest_label_entropy"],
                    "encoding_hint": f.evidence["encoding_hint"],
                    "sample_query_names": f.evidence["sample_query_names"],
                }
                for f in dns_findings
            ],
            "near_miss_long_labels": label_samples[:25],
        },
    }

    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\n=== SFE-fqn FP VALIDATION (Nitroba real PCAP) ===")
    print(f"Beaconing findings (CoV<={beacon.max_cov}): {len(beacon_findings)}")
    for f in beacon_findings:
        print(
            f"  - {f.evidence['host']:40s} "
            f"n={f.evidence['event_count']:4d} "
            f"mean={f.evidence['mean_interval_seconds']:8.1f}s "
            f"CoV={f.evidence['coefficient_of_variation']:.4f}"
        )
    print(f"\nDNS anomaly findings: {len(dns_findings)}")
    for f in dns_findings:
        print(
            f"  - {f.evidence['apex_domain']:40s} "
            f"label_len={f.evidence['longest_label_length']} "
            f"entropy={f.evidence['longest_label_entropy']} "
            f"enc={f.evidence['encoding_hint']}"
        )
    print(
        f"\nNear-miss long DNS labels (>=25 chars, below 40-char trigger): "
        f"{len(label_samples)} (top 25 in JSON)"
    )
    for s in label_samples[:10]:
        print(f"  - len={s['longest_label_len']:3d}  {s['query_name']}")
    print(f"\nFull JSON: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
