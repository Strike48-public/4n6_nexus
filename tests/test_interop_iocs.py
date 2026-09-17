"""Tests for IOC extraction feeding the standards exporters (SFE-b0om).

Each behavior pairs a positive case with a negative control: a private IP is
dropped while a public one survives; an MD5 alone survives but is subtracted when
a SHA-256 co-occurs in the same finding; a file name is not mistaken for a domain.
"""

from __future__ import annotations

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.interop.iocs import IocSet, extract_iocs, finding_iocs


def _finding(evidence: dict | None = None, *, title: str = "t") -> Finding:
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence=evidence or {},
    )


# --- IP extraction + private-range exclusion --------------------------------


def test_extracts_public_ipv4_from_structured_field() -> None:
    # Arrange
    findings = [_finding({"dst_ip": "8.8.8.8"})]
    # Act
    iocs = extract_iocs(findings)
    # Assert
    assert iocs.ipv4 == ("8.8.8.8",)


def test_drops_rfc1918_private_ipv4() -> None:
    # 10.0.0.1 is an internal victim address, not a hunt indicator.
    iocs = extract_iocs([_finding({"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"})])
    assert iocs.ipv4 == ("8.8.8.8",)


def test_drops_loopback_and_linklocal_and_reserved() -> None:
    iocs = extract_iocs(
        [_finding({"ips": ["127.0.0.1", "169.254.1.1", "240.0.0.1", "1.1.1.1"]})]
    )
    assert iocs.ipv4 == ("1.1.1.1",)


def test_extracts_public_ipv6_compressed() -> None:
    iocs = extract_iocs([_finding({"dst_ip": "2001:4860:4860:0:0:0:0:8888"})])
    assert iocs.ipv6 == ("2001:4860:4860::8888",)


def test_extracts_compressed_ipv6() -> None:
    # A real finding emits the compressed :: form, not the fully-expanded one.
    iocs = extract_iocs([_finding({"dst_ip": "2001:4860:4860::8888"})])
    assert iocs.ipv6 == ("2001:4860:4860::8888",)


def test_extracts_compressed_ipv6_from_free_text() -> None:
    # Google public DNS in compressed form (2001:db8::/32 is documentation-only
    # and correctly dropped, so it must not be used as a positive fixture).
    iocs = extract_iocs([_finding({"msg": "c2 at 2001:4860:4860::8844 seen"})])
    assert iocs.ipv6 == ("2001:4860:4860::8844",)


def test_drops_ipv6_loopback() -> None:
    iocs = extract_iocs([_finding({"dst_ip": "::1"})])
    assert iocs.ipv6 == ()


# --- hash extraction + collision subtraction --------------------------------


def test_extracts_sha256_lowercased() -> None:
    h = "A" * 64
    iocs = extract_iocs([_finding({"sha256": h})])
    assert iocs.sha256 == (h.lower(),)


def test_md5_alone_survives() -> None:
    m = "b" * 32
    iocs = extract_iocs([_finding({"md5": m})])
    assert iocs.md5 == (m,)
    assert iocs.sha256 == ()


def test_sha256_subtracts_md5_within_same_finding() -> None:
    # Both name the same file: keep only the strongest hash.
    iocs = extract_iocs([_finding({"md5": "b" * 32, "sha256": "a" * 64})])
    assert iocs.sha256 == ("a" * 64,)
    assert iocs.md5 == ()


def test_md5_from_other_finding_survives_when_sha256_elsewhere() -> None:
    # Subtraction is per-finding: an MD5-only finding keeps its MD5 even if a
    # DIFFERENT finding carries a SHA-256.
    findings = [_finding({"sha256": "a" * 64}), _finding({"md5": "c" * 32})]
    iocs = extract_iocs(findings)
    assert iocs.sha256 == ("a" * 64,)
    assert iocs.md5 == ("c" * 32,)


def test_sha256_not_misread_as_two_md5s() -> None:
    # A 64-hex string must not also yield 32-hex md5 fragments.
    iocs = extract_iocs([_finding({"note": "hash is " + "d" * 64})])
    assert iocs.sha256 == ("d" * 64,)
    assert iocs.md5 == ()


# --- domain extraction ------------------------------------------------------


def test_extracts_domain_from_structured_field() -> None:
    iocs = extract_iocs([_finding({"domain": "evil.example.com"})])
    assert iocs.domains == ("evil.example.com",)


def test_filename_is_not_a_domain() -> None:
    # evil.exe has a file-extension TLD -> not a domain.
    iocs = extract_iocs([_finding({"executable": "evil.exe"})])
    assert iocs.domains == ()


def test_domain_extracted_from_free_text_message() -> None:
    iocs = extract_iocs([_finding({"msg": "beacon to bad-domain.net every 60s"})])
    assert "bad-domain.net" in iocs.domains


def test_ipv4_string_not_classified_as_domain() -> None:
    iocs = extract_iocs([_finding({"note": "connect 8.8.8.8"})])
    assert iocs.domains == ()
    assert iocs.ipv4 == ("8.8.8.8",)


# --- shape / recursion / dedup ----------------------------------------------


def test_recurses_nested_timeline_dicts_and_lists() -> None:
    evidence = {"timeline": [{"target": "9.9.9.9"}, {"actor": "mal.example.org"}]}
    iocs = extract_iocs([_finding(evidence)])
    assert iocs.ipv4 == ("9.9.9.9",)
    assert "mal.example.org" in iocs.domains


def test_accepts_dict_shaped_finding() -> None:
    # A serialized Finding (to_dict) must extract identically.
    finding_dict = {"evidence": {"dst_ip": "8.8.4.4"}}
    iocs = extract_iocs([finding_dict])
    assert iocs.ipv4 == ("8.8.4.4",)


def test_finding_without_evidence_yields_empty() -> None:
    iocs = extract_iocs([_finding(None), {"no_evidence_key": 1}])
    assert iocs.is_empty()


def test_dedupes_and_sorts_across_findings() -> None:
    findings = [_finding({"dst_ip": "8.8.8.8"}), _finding({"dst_ip": "1.1.1.1"})]
    iocs = extract_iocs(findings)
    assert iocs.ipv4 == ("1.1.1.1", "8.8.8.8")  # sorted, deduped


def test_extraction_is_stable_across_calls() -> None:
    findings = [_finding({"dst_ip": "8.8.8.8", "domain": "a.example.com"})]
    assert extract_iocs(findings) == extract_iocs(findings)


def test_empty_input_is_empty_iocset() -> None:
    iocs = extract_iocs([])
    assert isinstance(iocs, IocSet)
    assert iocs.is_empty()


def test_finding_iocs_single() -> None:
    iocs = finding_iocs(_finding({"dst_ip": "8.8.8.8", "sha256": "a" * 64}))
    assert iocs.ipv4 == ("8.8.8.8",)
    assert iocs.sha256 == ("a" * 64,)
