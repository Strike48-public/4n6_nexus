"""Command-line obfuscation decoding and scoring helpers.

Pure-function utilities that take a Volatility ``CmdLine.Args`` string and
pull out encoded-payload candidates, decode them, and score the decoded
content against a small set of stage-one loader markers.

The functions are deliberately module-level and stateless so they can be
unit-tested in isolation and re-used by future detectors (e.g. a
registry-based T1140 scorer that looks at RunOnce values).

Scope: T1140 (Deobfuscate/Decode Files or Information). We decode, we do
not *execute* — the decoded text is only inspected for textual markers.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field
from typing import Optional

# Max decoded bytes we keep in evidence. Volatility cmdlines are bounded
# but an operator staging a large payload through a single cmdline is
# possible, so truncate defensively to keep JSON finding payloads sane.
_MAX_DECODED_LENGTH = 8192

# `-EncodedCommand`, `-enc`, and `-e` are all PowerShell aliases for the
# same UTF-16LE+base64 flag. We do not match a bare `-e` when followed by
# alphabetic letters (it would eat `-ep`/`-executionpolicy`), so the
# pattern requires whitespace-then-base64 after the alias. Bounded
# quantifiers on both the whitespace run and the base64 capture cap
# pathological backtracking on malformed input (defense-in-depth; Python
# re is not catastrophic but attackers control this string).
_ENCODED_COMMAND_RE = re.compile(
    r"-(?:encodedcommand|enc|e)\s{1,16}([A-Za-z0-9+/=]{16,32768})",
    re.IGNORECASE,
)

# Stage-one loader markers we look for in the *decoded* text. Each hit
# adds a reason and bumps confidence. Tuned to stay tight: matching
# "IEX" in a random word would be too noisy, so we require the token
# boundary where it matters.
_STAGE_ONE_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bIEX\b", re.IGNORECASE), "Invoke-Expression (IEX)"),
    (re.compile(r"Invoke-Expression", re.IGNORECASE), "Invoke-Expression"),
    (re.compile(r"DownloadString|DownloadFile|DownloadData", re.IGNORECASE),
     "Net.WebClient download cradle"),
    (re.compile(r"Invoke-WebRequest|iwr\b", re.IGNORECASE),
     "Invoke-WebRequest"),
    (re.compile(r"FromBase64String", re.IGNORECASE),
     "nested FromBase64String (double-encoded payload)"),
    (re.compile(r"Reflection\.Assembly", re.IGNORECASE),
     "Reflection.Assembly::Load (in-memory PE load)"),
    (re.compile(r"IO\.Compression\.GzipStream", re.IGNORECASE),
     "Gzip decompression (likely compressed payload)"),
    (re.compile(r"New-Object\s+Net\.", re.IGNORECASE),
     "New-Object Net.* (network object creation)"),
    (re.compile(r"https?://\S+", re.IGNORECASE),
     "URL literal in decoded payload"),
)

# Non-`-enc` obfuscation and download-cradle patterns. Each tuple is
# (compiled regex, reason text, MITRE technique list, high_severity).
# ``high_severity=True`` means the pattern is attack-specific enough
# that a single match warrants a high-severity finding. ``False`` means
# the underlying binary has legitimate admin use (e.g. certutil, bitsadmin)
# so we only escalate when paired with other signals.
_INLINE_OBFUSCATION_PATTERNS: tuple[
    tuple[re.Pattern[str], str, tuple[str, ...], bool], ...
] = (
    (
        re.compile(r"certutil(?:\.exe)?\s+.*-(?:decode|urlcache|encode)", re.IGNORECASE),
        "certutil used as decoder / downloader (LOLBAS)",
        ("T1140", "T1027", "T1105"),
        False,  # admins occasionally use certutil -decode legitimately
    ),
    (
        re.compile(r"rundll32(?:\.exe)?\s+.*javascript:", re.IGNORECASE),
        "rundll32 javascript: protocol handler (squiblydoo)",
        ("T1140", "T1218.011", "T1059.007"),
        True,  # no legitimate use
    ),
    (
        re.compile(r"mshta(?:\.exe)?\s+.*(?:vbscript:|javascript:|http)", re.IGNORECASE),
        "mshta script-host abuse",
        ("T1140", "T1218.005", "T1059"),
        True,  # remote mshta invocation has no legitimate use
    ),
    (
        re.compile(r"bitsadmin(?:\.exe)?\s+.*/transfer", re.IGNORECASE),
        "bitsadmin /transfer used as download cradle",
        ("T1140", "T1105", "T1197"),
        False,  # bitsadmin has legitimate patching / update use
    ),
    (
        re.compile(r"regsvr32(?:\.exe)?\s+.*(?:/i:https?://|scrobj)", re.IGNORECASE),
        "regsvr32 remote scriptlet execution (squiblytwo)",
        ("T1140", "T1218.010"),
        True,  # no legitimate use
    ),
    (
        re.compile(
            r"(?:IEX|Invoke-Expression)\s*\(?\s*(?:New-Object\s+Net\.WebClient|"
            r"Invoke-WebRequest|iwr)",
            re.IGNORECASE,
        ),
        "plaintext PowerShell download cradle (IEX + WebClient/IWR)",
        ("T1140", "T1059.001", "T1105"),
        True,  # canonical download cradle, effectively always malicious
    ),
)


@dataclass(frozen=True)
class DeobfuscationResult:
    """Result of scoring a single cmdline for T1140 signals.

    ``decoded_payload`` is populated when we successfully decode a
    base64 blob; empty otherwise. ``reasons`` accumulates human-readable
    descriptions of why this row is suspicious. ``mitre_attack`` is the
    union of techniques implicated by all matches. ``high_severity`` is
    set when at least one match is attack-specific enough to escalate
    severity without requiring corroborating decoded markers (e.g.
    rundll32 javascript:, IEX download cradles, a successful decode
    that itself surfaced stage-one markers).

    Confidence labels follow the same low/medium/high scale the rest of
    the detector uses so callers do not translate between vocabularies.
    """

    decoded_payload: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)
    mitre_attack: tuple[str, ...] = field(default_factory=tuple)
    high_severity: bool = False

    @property
    def has_signal(self) -> bool:
        return bool(self.reasons)


def analyze_cmdline_obfuscation(args: str) -> Optional[DeobfuscationResult]:
    """Return a DeobfuscationResult if ``args`` exhibits T1140 signals.

    Returns ``None`` when nothing obfuscation-related matches. Returns
    a populated result when either (a) we decode an encoded-command
    payload, or (b) an inline LOLBAS obfuscation pattern fires.

    The function is deliberately forgiving: an invalid base64 blob
    after ``-enc`` is treated as "no T1140 signal" rather than an error,
    so a malformed attacker payload degrades to the legacy cmdline path
    without crashing the run.
    """
    if not args:
        return None

    reasons: list[str] = []
    techniques: set[str] = set()
    decoded_payload = ""
    high_severity = False

    encoded_match = _ENCODED_COMMAND_RE.search(args)
    if encoded_match:
        candidate = encoded_match.group(1)
        decoded = _try_decode_powershell_encoded(candidate)
        if decoded:
            decoded_payload = decoded[:_MAX_DECODED_LENGTH]
            reasons.append(
                "PowerShell -EncodedCommand payload decoded to readable text"
            )
            techniques.update(("T1140", "T1027", "T1059.001"))
            marker_reasons = _score_decoded_text(decoded_payload)
            reasons.extend(marker_reasons)
            # Any decoded stage-one marker is itself attack-specific
            # (DownloadString, Reflection.Assembly::Load, FromBase64String,
            # etc.) so escalate severity here rather than in the builder.
            if marker_reasons:
                high_severity = True

    for pattern, reason, technique_tuple, is_high in _INLINE_OBFUSCATION_PATTERNS:
        if pattern.search(args):
            reasons.append(reason)
            techniques.update(technique_tuple)
            if is_high:
                high_severity = True

    if not reasons:
        return None
    return DeobfuscationResult(
        decoded_payload=decoded_payload,
        reasons=tuple(reasons),
        mitre_attack=tuple(sorted(techniques)),
        high_severity=high_severity,
    )


def _try_decode_powershell_encoded(candidate: str) -> Optional[str]:
    """Decode a UTF-16LE base64 payload; return None on any failure.

    Attackers sometimes pad the base64 blob with stray quotes or
    trailing punctuation; we strip obvious wrappers before attempting
    the decode. If the UTF-16LE path fails, we fall back to UTF-8 so
    non-PowerShell base64 blobs (certutil -decode targets, etc.) still
    produce readable text for scoring.
    """
    cleaned = candidate.strip().strip("\"'")
    if len(cleaned) < 16:
        return None
    # base64 strings must have length divisible by 4; pad defensively.
    padding = (-len(cleaned)) % 4
    cleaned_padded = cleaned + ("=" * padding)
    try:
        raw = base64.b64decode(cleaned_padded, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if not raw:
        return None
    # PowerShell -EncodedCommand is UTF-16LE; try that first, fall back
    # to UTF-8, both with ``errors='replace'`` so the decoded text is
    # always something we can match regexes against.
    try:
        decoded = raw.decode("utf-16-le")
        if "\x00\x00" not in decoded and _looks_like_text(decoded):
            return decoded
    except UnicodeDecodeError:
        pass
    try:
        decoded = raw.decode("utf-8", errors="replace")
        if _looks_like_text(decoded):
            return decoded
    except UnicodeDecodeError:
        return None
    return None


def _looks_like_text(s: str) -> bool:
    """Cheap heuristic: >= 80% of chars printable ASCII or whitespace.

    Binary shellcode base64-encoded still decodes "successfully" but
    produces mostly non-printable bytes; we do not want to stuff that
    into evidence. Returning False here lets the caller fall through to
    the non-decoded path where other markers may still fire.
    """
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return printable / len(s) >= 0.80


def _score_decoded_text(decoded: str) -> list[str]:
    """Return reason strings for every stage-one marker that hit."""
    hits: list[str] = []
    for pattern, reason in _STAGE_ONE_MARKERS:
        if pattern.search(decoded):
            hits.append(f"Decoded payload contains: {reason}")
    # 5.0 is the empirical cut above which base64-decoded text stops
    # looking like English source (~4.0-4.5) and starts looking like
    # compressed or encrypted bytes. 4.5 was tempting but caught legit
    # minified-JS / gzip-config blobs occasionally shipped by installers.
    if shannon_entropy(decoded) >= 5.0:
        hits.append(
            "Decoded payload Shannon entropy >= 5.0 "
            "(suggests further compression / encryption)"
        )
    return hits


def shannon_entropy(s: str) -> float:
    """Shannon entropy over the character histogram of ``s``.

    Plain English averages around 4.0-4.5; compressed/encrypted payloads
    usually sit above 5.0. We use it as a soft signal combined with
    marker regexes rather than a hard gate.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
