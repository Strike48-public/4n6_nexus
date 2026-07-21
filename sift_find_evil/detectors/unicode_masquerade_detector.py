"""Unicode masquerade / RLO / zero-width filename and string detector.

Detects Unicode-based masquerading and anti-forensics tricks in forensic
strings such as MFT filenames, registry values, and file paths. Attackers use
bidirectional-override characters (RLO/LRO) to reverse a displayed filename
extension (the classic ``invoice<RLO>gpj.exe`` that shows as ``invoiceexe.jpg``)
and zero-width characters to hide or split malicious tokens.

Maps to MITRE ATT&CK T1036.002 (Masquerading: Right-to-Left Override).
"""

from __future__ import annotations

from typing import Iterable

from sift_find_evil.findings import Finding, FindingCategory

# Codepoints that should never legitimately appear in a filename, registry
# value, or path on a Windows/Unix forensic artifact. Presence of any of these
# is a strong masquerade / anti-forensics signal.
UNICODE_ANOMALIES: frozenset[int] = frozenset(
    {
        0x202A,  # LEFT-TO-RIGHT EMBEDDING (LRE)
        0x202B,  # RIGHT-TO-LEFT EMBEDDING (RLE)
        0x202C,  # POP DIRECTIONAL FORMATTING (PDF)
        0x202D,  # LEFT-TO-RIGHT OVERRIDE (LRO)
        0x202E,  # RIGHT-TO-LEFT OVERRIDE (RLO)
        0x200B,  # ZERO WIDTH SPACE (ZWSP)
        0x200C,  # ZERO WIDTH NON-JOINER (ZWNJ)
        0x200D,  # ZERO WIDTH JOINER (ZWJ)
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BYTE ORDER MARK (BOM)
        0x2066,  # LEFT-TO-RIGHT ISOLATE (LRI)
        0x2067,  # RIGHT-TO-LEFT ISOLATE (RLI)
        0x2068,  # FIRST STRONG ISOLATE (FSI)
        0x2069,  # POP DIRECTIONAL ISOLATE (PDI)
        0x0300,  # COMBINING GRAVE ACCENT (homoglyph-prone combining mark)
        0x0301,  # COMBINING ACUTE ACCENT
        0x0308,  # COMBINING DIAERESIS
    }
)

# Right-to-left / left-to-right override codepoints that reverse displayed text.
_RTL_OVERRIDE = 0x202E  # RLO
_LTR_OVERRIDE = 0x202D  # LRO

_CONFIDENCE = 0.9
_MITRE_TECHNIQUE = "T1036.002"


class UnicodeMasqueradeDetector:
    """Detects Unicode masquerade / RLO / zero-width tricks in strings."""

    def analyze(self, strings: Iterable[tuple[str, str]]) -> list[Finding]:
        """Analyze labeled strings for Unicode masquerade anomalies.

        Args:
            strings: Iterable of ``(source_label, value)`` tuples, e.g.
                ``('mft_filename', 'invoice\\u202egnp.exe')``. Inputs are never
                mutated.

        Returns:
            A list of ``Finding`` objects, one per value containing at least one
            anomalous Unicode codepoint. Empty if all values are clean.
        """
        findings: list[Finding] = []

        for source, value in strings:
            anomalies = self._find_anomalies(value)
            if not anomalies:
                continue
            findings.append(self._build_finding(source, value, anomalies))

        return findings

    def _find_anomalies(self, value: str) -> list[int]:
        """Return the ordered list of anomalous codepoints found in a value."""
        return [ord(ch) for ch in value if ord(ch) in UNICODE_ANOMALIES]

    def _build_finding(self, source: str, value: str, codepoints: list[int]) -> Finding:
        """Construct a Finding for a value containing Unicode anomalies."""
        value_repr = self._escape(value)
        evidence: dict = {
            "source": source,
            "value_repr": value_repr,
            "codepoints": codepoints,
            "mitre_attack": [_MITRE_TECHNIQUE],
        }

        reasoning_chain = [
            f"Value from {source} contains {len(codepoints)} anomalous Unicode "
            "codepoint(s) that do not legitimately appear in filenames or "
            "registry values.",
            f"Anomalous codepoints: {[f'U+{cp:04X}' for cp in codepoints]}.",
        ]

        if _RTL_OVERRIDE in codepoints or _LTR_OVERRIDE in codepoints:
            display, real = self._display_vs_real(value)
            evidence["display_vs_real"] = {"display": display, "real": real}
            reasoning_chain.append(
                "Bidirectional override present: displayed name "
                f"'{display}' differs from the real name '{real}', a classic "
                "extension-spoofing masquerade (T1036.002)."
            )

        return Finding(
            title="Unicode masquerade in filename/string",
            description=(
                "A forensic string contains Unicode control or homoglyph "
                "codepoints used to disguise a malicious filename or value."
            ),
            finding_type="indicator",
            severity="high",
            category=FindingCategory.ANTI_FORENSICS,
            evidence=evidence,
            confidence=_CONFIDENCE,
            confidence_label="High",
            reasoning_chain=reasoning_chain,
            artifact_sources=[source],
        )

    def _escape(self, value: str) -> str:
        """Return a repr-style escaped form so control chars are visible."""
        return value.encode("unicode_escape").decode("ascii")

    def _display_vs_real(self, value: str) -> tuple[str, str]:
        """Compute the displayed vs real string when an RLO/LRO is present.

        The override reverses the order of characters that follow it, so a
        forensic tool storing raw bytes sees the real name while a file browser
        shows the reversed name.
        """
        real = "".join(ch for ch in value if ord(ch) not in UNICODE_ANOMALIES)

        display_chars: list[str] = []
        reversed_buffer: list[str] = []
        reversing = False
        for ch in value:
            cp = ord(ch)
            if cp in UNICODE_ANOMALIES:
                if cp in (_RTL_OVERRIDE, _LTR_OVERRIDE):
                    reversing = True
                continue
            if reversing:
                reversed_buffer.insert(0, ch)
            else:
                display_chars.append(ch)
        display = "".join(display_chars) + "".join(reversed_buffer)

        return display, real
