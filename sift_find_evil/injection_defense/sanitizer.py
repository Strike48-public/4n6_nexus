"""Sanitize and sentinel-wrap hostile evidence text against prompt injection.

The pipeline runs in a fixed order so later stages operate on already-cleaned
text:

1. Strip invisible / BIDI / zero-width codepoints (RLO, LRO, ZWSP, ZWJ, BOM,
   directional isolates) FIRST, so hidden reordering cannot smuggle live tokens
   past the neutralizer.
2. Case-insensitively neutralize role / system injection tokens (for example
   "ignore previous instructions", "system:", forged ``{"verdict":"clean"}``
   JSON) to inert ``[NEUTRALIZED:role-token]`` markers.
3. Wrap the cleaned content in a nonce-keyed sentinel and defang any attempt to
   close the untrusted-evidence boundary early.
4. Report counts only: what was stripped / neutralized, never the raw payload.

Functions here are pure and never mutate their inputs.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Dict, List, Optional

from sift_find_evil.findings import Finding, FindingCategory

# Invisible / bidirectional / zero-width codepoints stripped in step 1.
_INVISIBLE_CODEPOINTS = (
    "‪"  # LRE
    "‫"  # RLE
    "‬"  # PDF
    "‭"  # LRO
    "‮"  # RLO
    "​"  # ZWSP
    "‌"  # ZWNJ
    "‍"  # ZWJ
    "﻿"  # BOM / ZWNBSP
    "⁦"  # LRI
    "⁧"  # RLI
    "⁨"  # FSI
    "⁩"  # PDI
)
_INVISIBLE_RE = re.compile(f"[{re.escape(_INVISIBLE_CODEPOINTS)}]")

_NEUTRAL_MARKER = "[NEUTRALIZED:role-token]"

# Role / system injection patterns (case-insensitive). Order does not matter;
# each match is replaced with the inert marker and counted.
_ROLE_TOKEN_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(
        r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions", re.IGNORECASE
    ),
    re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"(?:^|\s)(?:system|assistant|developer|user)\s*:", re.IGNORECASE),
    # Forged tool_call / verdict JSON, for example {"verdict":"clean"}.
    re.compile(
        r'\{\s*"(?:verdict|tool_call|role|action)"\s*:\s*"[^"]*"\s*\}', re.IGNORECASE
    ),
)

_SENTINEL_OPEN_TMPL = "<<UNTRUSTED-EVIDENCE nonce={nonce}>>"
_SENTINEL_CLOSE = "<</UNTRUSTED-EVIDENCE>>"
# Any attempt to emit the closing tag inside the payload is defanged.
_SENTINEL_CLOSE_ATTEMPT_RE = re.compile(
    r"<\s*</?\s*UNTRUSTED-EVIDENCE\s*>?", re.IGNORECASE
)
_DEFANGED_CLOSE = "[DEFANGED:sentinel-close]"


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning and wrapping a piece of evidence text.

    Attributes:
        clean_text: Sanitized text with invisibles stripped and role tokens
            neutralized, before sentinel wrapping.
        wrapped_text: ``clean_text`` enclosed in the nonce-keyed untrusted
            sentinel with any boundary-close attempts defanged.
        findings_meta: Counts-only metadata; each entry is ``{"type", "count"}``
            and never contains the raw offending payload.
    """

    clean_text: str
    wrapped_text: str
    findings_meta: List[Dict[str, object]] = field(default_factory=list)


def derive_session_nonce(salt: str, evidence_hash: str) -> str:
    """Derive a deterministic 16-char session nonce (pure function).

    Args:
        salt: Per-session secret salt.
        evidence_hash: Hex digest identifying the evidence blob.

    Returns:
        The first 16 hex characters of ``HMAC-SHA256(salt, evidence_hash)``.
    """
    digest = hmac.new(salt.encode("utf-8"), evidence_hash.encode("utf-8"), sha256)
    return digest.hexdigest()[:16]


def detect_injection(text: str) -> List[Dict[str, object]]:
    """Detect injection indicators and return counts-only metadata.

    Args:
        text: Raw, untrusted evidence text.

    Returns:
        A list of ``{"type": str, "count": int}`` dicts, one per indicator type
        that fired. The raw offending payload is never included. Empty list when
        the text is clean.
    """
    metas: List[Dict[str, object]] = []

    invisible_count = len(_INVISIBLE_RE.findall(text))
    if invisible_count:
        metas.append({"type": "invisible", "count": invisible_count})

    # Neutralization operates on invisible-stripped text so hidden reordering
    # cannot hide a live token from the role-token matcher.
    stripped = _INVISIBLE_RE.sub("", text)
    role_count = sum(len(pattern.findall(stripped)) for pattern in _ROLE_TOKEN_PATTERNS)
    if role_count:
        metas.append({"type": "role-token", "count": role_count})

    close_count = len(_SENTINEL_CLOSE_ATTEMPT_RE.findall(stripped))
    if close_count:
        metas.append({"type": "sentinel-close", "count": close_count})

    return metas


def scan_and_wrap(text: str, session_nonce: Optional[str] = None) -> ScanResult:
    """Sanitize hostile evidence text and wrap it in an untrusted sentinel.

    Args:
        text: Raw, untrusted evidence text (never mutated).
        session_nonce: Optional nonce for the sentinel boundary. When omitted a
            deterministic nonce is derived from the text content.

    Returns:
        A :class:`ScanResult` with cleaned text, sentinel-wrapped text, and
        counts-only findings metadata.
    """
    findings_meta = detect_injection(text)

    # Step 1: strip invisibles first.
    cleaned = _INVISIBLE_RE.sub("", text)

    # Step 2: neutralize role / system injection tokens.
    for pattern in _ROLE_TOKEN_PATTERNS:
        cleaned = pattern.sub(_NEUTRAL_MARKER, cleaned)

    # Step 3: wrap in nonce-keyed sentinel, defanging embedded close attempts.
    nonce = session_nonce or derive_session_nonce(
        "injection-defense", sha256(text.encode("utf-8")).hexdigest()
    )
    defanged = _SENTINEL_CLOSE_ATTEMPT_RE.sub(_DEFANGED_CLOSE, cleaned)
    wrapped = f"{_SENTINEL_OPEN_TMPL.format(nonce=nonce)}{defanged}{_SENTINEL_CLOSE}"

    return ScanResult(
        clean_text=cleaned, wrapped_text=wrapped, findings_meta=findings_meta
    )


def finding_from_scan(result: ScanResult) -> Optional[Finding]:
    """Emit a Finding when a scan detected any injection attempt.

    Args:
        result: A :class:`ScanResult` from :func:`scan_and_wrap`.

    Returns:
        A :class:`Finding` describing the counts-only indicators, or ``None``
        when the scanned text was clean.
    """
    if not result.findings_meta:
        return None

    total = sum(int(meta["count"]) for meta in result.findings_meta)
    types = sorted(str(meta["type"]) for meta in result.findings_meta)

    return Finding(
        title="Prompt-injection attempt in evidence",
        description=(
            "Evidence text contained adversarial content intended to manipulate "
            "automated analysis. Content was sanitized and sentinel-wrapped; only "
            "aggregate counts are reported, never the raw payload."
        ),
        finding_type="indicator",
        severity="high",
        category=FindingCategory.ANTI_FORENSICS,
        evidence={"indicator_counts": result.findings_meta, "total_indicators": total},
        confidence=0.9,
        confidence_label="High",
        reasoning_chain=[
            f"Detected {total} injection indicator(s) across types: {', '.join(types)}.",
            "Invisible/BIDI codepoints were stripped before token neutralization.",
            "Role/system tokens were replaced with inert markers.",
            "Content was wrapped in a nonce-keyed untrusted-evidence sentinel.",
        ],
        artifact_sources=["injection_defense.sanitizer"],
    )
