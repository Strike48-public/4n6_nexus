"""IOC extraction from findings for standards interop (SFE-b0om).

A PURE, deterministic, read-only helper that pulls atomic indicators of
compromise (IPs, domains, file hashes) out of already-emitted findings so the
STIX / OCSF / SIEM exporters can reference them. Nothing here runs on the
detection scoring path, so F1 is provably unaffected.

Extraction is regex-based over every string value an evidence dict carries
(recursing through lists and nested dicts such as ``evidence["timeline"]``), so
an IOC mentioned only inside a free-form message is still surfaced. Two
correctness rules keep the output SIEM-clean:

  * **Private-range exclusion.** RFC1918 / loopback / link-local / reserved /
    multicast / unspecified addresses are dropped -- an internal victim address
    is not an indicator to hunt for.
  * **Hash collision subtraction.** Within one finding, if a SHA-256 is present
    any MD5 is dropped: the two name the same file, and emitting both would
    produce two indicators for one artifact. The strongest hash wins, mirroring
    the ``sha256 > md5`` priority in :mod:`sift_find_evil.findings.dedup`.

The evidence-key priority for structured IP/hash fields is kept in lockstep with
``findings.dedup`` (the correlation join key) so an IOC's identity equals the
subject's correlation identity.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

# Regexes for free-text IOC extraction. Word-boundary anchored so a hash inside a
# longer token is not half-matched.
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Loose IPv6 candidate: a hex-and-colon run that either contains a ``::``
# compression or is the full 8-group form. Every candidate is re-validated by
# ipaddress, so an over-match is harmless (bad matches are discarded); the
# lookahead just avoids grabbing lone hex tokens. Must handle the compressed
# ``::`` form -- a real finding emits ``2001:db8::1``, not only the expanded form.
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?=[0-9A-Fa-f:]*::|(?:[0-9A-Fa-f]{1,4}:){7})"
    r"[0-9A-Fa-f:]{2,39}"
    r"(?![0-9A-Fa-f:])"
)
# A domain: one-or-more dot-separated labels then an alphabetic TLD (>=2). This
# also matches file names like "evil.exe", so a TLD in _FILE_EXTENSIONS is
# rejected below (a filename is not a domain IOC).
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)

# TLD-shaped tokens that are really file extensions, not domains. Deliberately
# EXCLUDES extensions that are also real TLDs (``com``): a real C2 domain
# ``evil.com`` must survive; a rare file literally named ``x.com`` is acceptable
# collateral. Lowercase for case-insensitive comparison.
_FILE_EXTENSIONS = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "jse",
        "wsf",
        "hta",
        "scr",
        "pif",
        "doc",
        "docx",
        "docm",
        "xls",
        "xlsx",
        "xlsm",
        "ppt",
        "pptx",
        "pdf",
        "rtf",
        "zip",
        "rar",
        "gz",
        "tar",
        "dat",
        "tmp",
        "log",
        "txt",
        "bin",
        "dmp",
        "lnk",
        "pf",
        "evtx",
        "reg",
        "ini",
        "cfg",
        "json",
        "xml",
        "csv",
        "db",
        "sqlite",
        "jpg",
        "jpeg",
        "png",
        "gif",
    }
)

# Structured evidence keys, kept in lockstep with findings.dedup's identity
# priority. IP src/dst are both collected; private-range exclusion drops any
# internal address, so a victim src never becomes a hunt indicator.
_HASH_KEYS = ("sha256", "md5", "hash", "imphash")
_IP_KEYS = ("dst_ip", "foreign_addr", "src_ip", "remote_ip", "ip", "ips")
_DOMAIN_KEYS = ("domain", "domains", "host", "hostname", "url", "sni")


@dataclass(frozen=True)
class IocSet:
    """Deduplicated, sorted atomic IOCs extracted from findings.

    Every field is a sorted tuple so the set is hashable and two extractions of
    the same findings compare equal (stable exporter output).
    """

    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    md5: tuple[str, ...] = ()
    sha256: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        """True when no IOC of any kind was extracted."""
        return not (self.ipv4 or self.ipv6 or self.domains or self.md5 or self.sha256)


@dataclass
class _RawIocs:
    """Mutable per-finding accumulator, frozen into an :class:`IocSet` at the end."""

    ipv4: set[str] = field(default_factory=set)
    ipv6: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    md5: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)

    def update(self, other: "_RawIocs") -> None:
        self.ipv4 |= other.ipv4
        self.ipv6 |= other.ipv6
        self.domains |= other.domains
        self.md5 |= other.md5
        self.sha256 |= other.sha256

    def freeze(self) -> IocSet:
        return IocSet(
            ipv4=tuple(sorted(self.ipv4)),
            ipv6=tuple(sorted(self.ipv6)),
            domains=tuple(sorted(self.domains)),
            md5=tuple(sorted(self.md5)),
            sha256=tuple(sorted(self.sha256)),
        )


def _evidence_of(finding: Any) -> dict:
    """Read the ``evidence`` mapping from a Finding or its ``to_dict`` mapping."""
    if isinstance(finding, dict):
        evidence = finding.get("evidence")
    else:
        evidence = getattr(finding, "evidence", None)
    return evidence if isinstance(evidence, dict) else {}


def _iter_strings(value: Any) -> Iterator[str]:
    """Yield every string reachable in ``value`` (recursing lists and dicts)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)


def _is_public_ip(text: str) -> "ipaddress._BaseAddress | None":
    """Return the parsed address if it is a routable public IP, else None.

    Drops private, loopback, link-local, reserved, multicast and unspecified
    addresses -- none of which is a hunt indicator.
    """
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return None
    return addr


def _looks_like_domain(candidate: str) -> bool:
    """True if ``candidate`` is a domain and not a file name or bare IP."""
    tld = candidate.rsplit(".", 1)[-1].lower()
    if tld in _FILE_EXTENSIONS:
        return False
    # A dotted-decimal that slipped past the domain regex is an IP, not a domain.
    return _is_public_ip(candidate) is None and not _IPV4_RE.fullmatch(candidate)


def _add_hashes(text: str, raw: _RawIocs) -> None:
    """Extract sha256 then md5 from ``text`` (sha256 first so its 32-char
    substrings are not misread as md5)."""
    for match in _SHA256_RE.findall(text):
        raw.sha256.add(match.lower())
    # Blank out sha256 matches before scanning md5 so a 64-hex string does not
    # also yield two overlapping 32-hex "md5" hits.
    md5_text = _SHA256_RE.sub(" ", text)
    for match in _MD5_RE.findall(md5_text):
        raw.md5.add(match.lower())


def _add_ips(text: str, raw: _RawIocs) -> None:
    """Extract public IPv4/IPv6 addresses from ``text``."""
    for match in _IPV4_RE.findall(text):
        if _is_public_ip(match) is not None:
            raw.ipv4.add(match)
    for match in _IPV6_RE.findall(text):
        addr = _is_public_ip(match)
        if addr is not None:
            raw.ipv6.add(addr.compressed)


def _add_domains(text: str, raw: _RawIocs) -> None:
    """Extract domain IOCs from ``text`` (URLs contribute their host)."""
    for match in _DOMAIN_RE.findall(text):
        candidate = match.lower().rstrip(".")
        if _looks_like_domain(candidate):
            raw.domains.add(candidate)


def _finding_raw(finding: Any) -> _RawIocs:
    """Extract raw IOCs from one finding, applying hash collision subtraction."""
    raw = _RawIocs()
    for text in _iter_strings(_evidence_of(finding)):
        _add_hashes(text, raw)
        _add_ips(text, raw)
        _add_domains(text, raw)
    # Collision subtraction: a SHA-256 present in the SAME finding names the same
    # file as any MD5, so drop the weaker hash to avoid a duplicate indicator.
    if raw.sha256:
        raw.md5.clear()
    return raw


def finding_iocs(finding: Any) -> IocSet:
    """Extract the IOCs referenced by a single finding (for STIX sighting links)."""
    return _finding_raw(finding).freeze()


def extract_iocs(findings: Iterable[Any]) -> IocSet:
    """Extract the union of all IOCs across ``findings`` as a sorted :class:`IocSet`.

    Args:
        findings: Findings (:class:`~sift_find_evil.findings.finding.Finding` or
            their ``to_dict`` mappings).

    Returns:
        A deduplicated, sorted :class:`IocSet`. Collision subtraction is applied
        per finding, so an MD5-only finding still contributes its MD5 even if a
        different finding carries a SHA-256.
    """
    combined = _RawIocs()
    for finding in findings:
        combined.update(_finding_raw(finding))
    return combined.freeze()
