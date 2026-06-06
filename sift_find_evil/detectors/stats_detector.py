"""Stats-over-grouped-events detectors: beaconing cadence, DNS anomalies.

Shared shape: group parsed events by a key, compute a score across the group,
threshold the score. The math differs between tenants (coefficient of variation
for beaconing, Shannon entropy for DNS labels) but the plumbing is one pattern.

Two tenants:

- ``BeaconingDetector``: groups HTTP CONNECT / GET by ``(src_ip, host)`` and
  flags (src, host) pairs whose inter-event intervals have low coefficient of
  variation — i.e., the spacing is too regular to be human. Addresses SFE-4wl.

- ``DNSAnomalyDetector``: flags DNS queries with long subdomain labels, high
  character entropy, or base32/base64 encoding patterns. Addresses SFE-tcj.

Neither detector modifies its inputs. Both emit findings with
``FindingCategory.UNKNOWN`` until the taxonomy adds ``command_and_control`` /
``covert_channel`` categories.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.pcap_parser import DNSQuery, HTTPRequest
from ..findings import Finding


# --- beaconing ---------------------------------------------------------------


class BeaconingDetector:
    """Flag (src, host) pairs with near-uniform inter-event intervals.

    Parameters
    ----------
    min_events:
        Minimum number of repeat events to consider periodicity at all. Below
        this there are not enough intervals for the statistic to be meaningful.
        Default 5 yields 4 intervals.
    max_cov:
        Threshold for the coefficient of variation (stddev/mean). A genuinely
        periodic beacon produces CoV well under 0.1; ad-hoc user browsing
        typically produces CoV > 0.3. Default 0.15 is a conservative ceiling.
    min_mean_seconds:
        Ignore bursts where the mean interval is under this many seconds —
        those are usually TCP retries or asset loads, not C2 heartbeats.
    methods:
        HTTP methods to consider. Default includes ``CONNECT`` (HTTPS through
        proxy) and ``GET``. POSTs are excluded because they're usually user-
        initiated.
    """

    def __init__(
        self,
        min_events: int = 5,
        max_cov: float = 0.15,
        min_mean_seconds: float = 30.0,
        methods: tuple[str, ...] = ("CONNECT", "GET"),
    ):
        if min_events < 3:
            raise ValueError("min_events must be >= 3")
        if max_cov <= 0:
            raise ValueError("max_cov must be positive")
        self.min_events = min_events
        self.max_cov = max_cov
        self.min_mean_seconds = min_mean_seconds
        self.methods = tuple(m.upper() for m in methods)

    def analyze(
        self, http_requests: Optional[Iterable[HTTPRequest]] = None
    ) -> list[Finding]:
        """Return one finding per (src_ip, host) pair exhibiting beaconing."""
        if not http_requests:
            return []

        groups: dict[tuple[str, str], list[float]] = {}
        for r in http_requests:
            if r.method not in self.methods:
                continue
            host = self._normalize_host(r.host)
            if not host:
                continue
            key = (r.src_ip, host)
            groups.setdefault(key, []).append(r.timestamp.timestamp())

        findings: list[Finding] = []
        for (src_ip, host), timestamps in sorted(groups.items()):
            if len(timestamps) < self.min_events:
                continue
            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
            ]
            mean = sum(intervals) / len(intervals)
            if mean < self.min_mean_seconds:
                continue
            variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            stddev = math.sqrt(variance)
            cov = stddev / mean if mean else float("inf")
            if cov > self.max_cov:
                continue
            findings.append(
                self._build_finding(
                    src_ip, host, timestamps, intervals, mean, stddev, cov
                )
            )
        return findings

    @staticmethod
    def _normalize_host(host: str) -> str:
        if not host:
            return ""
        lowered = host.lower().strip()
        if "://" in lowered:
            lowered = lowered.split("://", 1)[1]
        lowered = lowered.split("/", 1)[0]
        if ":" in lowered:
            lowered = lowered.split(":", 1)[0]
        return lowered.rstrip(".")

    def _build_finding(
        self,
        src_ip: str,
        host: str,
        timestamps: list[float],
        intervals: list[float],
        mean: float,
        stddev: float,
        cov: float,
    ) -> Finding:
        from datetime import datetime, timezone

        first = datetime.fromtimestamp(timestamps[0], tz=timezone.utc).isoformat()
        last = datetime.fromtimestamp(timestamps[-1], tz=timezone.utc).isoformat()
        # Cadence regularity alone is not a verdict. Real-evidence validation
        # (SFE-fqn, Nitroba PCAP) showed a benign image.weather.com widget
        # producing a near-zero CoV indistinguishable from a textbook C2
        # beacon. A tighter CoV must NOT push confidence into the "High"
        # (near-certain) band: this is a triage signal to review, not proof of
        # C2. Cap below the 0.75 High threshold so beaconing always surfaces as
        # "Medium". Corroborating signals (suspicious host, unresolved IP, exfil
        # ratio) are what should escalate a beacon -- not the cadence by itself.
        _HIGH_THRESHOLD = 0.75
        confidence = min(_HIGH_THRESHOLD - 0.01, 0.55 + (self.max_cov - cov) * 1.0)
        return Finding(
            title=f"Beaconing to {host} from {src_ip}",
            description=(
                f"{len(timestamps)} events to {host} with mean interval "
                f"{mean:.1f}s (stddev {stddev:.2f}s, CoV {cov:.3f}) — "
                f"the cadence is too regular to be human browsing."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.UNKNOWN,
            evidence={
                "src_ip": src_ip,
                "host": host,
                "event_count": len(timestamps),
                "mean_interval_seconds": round(mean, 2),
                "stddev_seconds": round(stddev, 3),
                "coefficient_of_variation": round(cov, 4),
                "first_seen": first,
                "last_seen": last,
            },
            confidence=round(confidence, 2),
            confidence_label="High" if confidence >= 0.75 else "Medium",
            reasoning_chain=[
                f"{len(timestamps)} events to {host} from {src_ip}.",
                f"Inter-event intervals: mean={mean:.1f}s, stddev={stddev:.2f}s.",
                f"Coefficient of variation {cov:.3f} is below threshold {self.max_cov}.",
                "Uniform cadence is consistent with automated/beaconing traffic.",
            ],
            artifact_sources=["pcap"],
        )


# --- DNS anomalies -----------------------------------------------------------

_BASE32_LABEL_RE = re.compile(r"^[a-z2-7]{16,}$")
_BASE64_LABEL_RE = re.compile(r"^[a-zA-Z0-9+/]{20,}=*$")


class DNSAnomalyDetector:
    """Flag DNS queries that look like covert channels (long, high-entropy).

    Parameters
    ----------
    min_label_length:
        Longest individual label in the query must exceed this to consider the
        query anomalous. Default 40.
    min_entropy:
        Shannon entropy (per character) of the longest label must exceed this
        for the query to be flagged. Default 3.5 bits/char — high enough to
        exclude English words but low enough to catch base32 (5 bits/char ideal).
    ignore_known_cdn_patterns:
        If True, suppress findings whose query name matches known CDN/ELB
        naming patterns (AWS ELB, CloudFront, Azure, etc.).
    """

    _CDN_PATTERNS: tuple[re.Pattern, ...] = (
        re.compile(r"elb\.amazonaws\.com$"),
        re.compile(r"cloudfront\.net$"),
        re.compile(r"\.azureedge\.net$"),
        re.compile(r"\.googleusercontent\.com$"),
        re.compile(r"\.googlevideo\.com$"),
        re.compile(r"\.akamaiedge\.net$"),
        re.compile(r"\.safeframe\.googlesyndication\.com$"),
        re.compile(r"\.s3\.amazonaws\.com$"),
        re.compile(r"\.cdn\.cloudflare\.net$"),
    )

    def __init__(
        self,
        min_label_length: int = 40,
        min_entropy: float = 3.5,
        ignore_known_cdn_patterns: bool = True,
    ):
        if min_label_length < 10:
            raise ValueError("min_label_length must be >= 10")
        self.min_label_length = min_label_length
        self.min_entropy = min_entropy
        self.ignore_known_cdn_patterns = ignore_known_cdn_patterns

    def analyze(
        self, dns_queries: Optional[Iterable[DNSQuery]] = None
    ) -> list[Finding]:
        """Return findings for queries with anomalous label shape or encoding."""
        if not dns_queries:
            return []
        # Group per-host by (src_ip, apex_domain) so we don't spam one finding
        # per subdomain when a host makes a burst of related queries.
        groups: dict[tuple[str, str], list[DNSQuery]] = {}
        for q in dns_queries:
            if self._is_cdn_suppressed(q.query_name):
                continue
            longest = self._longest_label(q.query_name)
            if len(longest) < self.min_label_length:
                continue
            if self._shannon_entropy(longest) < self.min_entropy:
                continue
            apex = self._apex_domain(q.query_name)
            groups.setdefault((q.src_ip, apex), []).append(q)
        return [self._build_finding(k, qs) for k, qs in sorted(groups.items())]

    def _is_cdn_suppressed(self, name: str) -> bool:
        if not self.ignore_known_cdn_patterns:
            return False
        lowered = name.lower().rstrip(".")
        return any(pat.search(lowered) for pat in self._CDN_PATTERNS)

    @staticmethod
    def _longest_label(name: str) -> str:
        labels = [label for label in name.strip(".").split(".") if label]
        return max(labels, key=len) if labels else ""

    @staticmethod
    def _apex_domain(name: str) -> str:
        labels = [label for label in name.strip(".").split(".") if label]
        return ".".join(labels[-2:]) if len(labels) >= 2 else ".".join(labels)

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s.lower())
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def _build_finding(
        self,
        key: tuple[str, str],
        queries: list[DNSQuery],
    ) -> Finding:
        src_ip, apex = key
        sample_names = sorted({q.query_name for q in queries})[:5]
        longest_label = max(
            (self._longest_label(q.query_name) for q in queries), key=len
        )
        entropy = self._shannon_entropy(longest_label)
        encoding_hint = self._encoding_hint(longest_label)
        first = min(q.timestamp for q in queries).isoformat()
        last = max(q.timestamp for q in queries).isoformat()

        return Finding(
            title=f"Anomalous DNS queries under {apex} from {src_ip}",
            description=(
                f"{len(queries)} DNS query/queries with long high-entropy "
                f"labels under {apex}. Longest label {len(longest_label)} chars, "
                f"entropy {entropy:.2f} bits/char"
                + (f", encoding hint: {encoding_hint}." if encoding_hint else ".")
            ),
            finding_type="indicator",
            severity="medium",
            category=FindingCategory.UNKNOWN,
            evidence={
                "src_ip": src_ip,
                "apex_domain": apex,
                "query_count": len(queries),
                "longest_label": longest_label,
                "longest_label_length": len(longest_label),
                "longest_label_entropy": round(entropy, 3),
                "encoding_hint": encoding_hint,
                "sample_query_names": sample_names,
                "first_seen": first,
                "last_seen": last,
            },
            confidence=0.65,
            confidence_label="Medium",
            reasoning_chain=[
                f"{src_ip} issued {len(queries)} DNS query/queries under {apex}.",
                f"Longest label is {len(longest_label)} chars "
                f"(threshold {self.min_label_length}).",
                f"Shannon entropy {entropy:.2f} bits/char exceeds "
                f"threshold {self.min_entropy}.",
                (
                    f"Label matches {encoding_hint} pattern — consistent with "
                    f"DNS tunneling / covert channel."
                    if encoding_hint
                    else "High-entropy long labels are consistent with DNS tunneling."
                ),
            ],
            artifact_sources=["pcap"],
        )

    @staticmethod
    def _encoding_hint(label: str) -> Optional[str]:
        if _BASE32_LABEL_RE.match(label):
            return "base32"
        if _BASE64_LABEL_RE.match(label):
            return "base64"
        return None
