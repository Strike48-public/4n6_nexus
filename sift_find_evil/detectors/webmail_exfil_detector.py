"""Webmail exfiltration detector.

Detects data exfiltration via webmail (T1567 — Cloud exfiltration via webmail)
by correlating two or three independent artifact streams:

1. Browser history showing visits to a known webmail compose/send URL.
2. (Optional) MFT entries showing sensitive documents accessed shortly before
   the webmail activity.
3. (Optional) PCAP HTTP POST traffic to known webmail hosts in the same window.

A finding is emitted **only** when the browser-history compose/send signal is
present. MFT and PCAP corroboration raise the confidence but are not required
on their own — a document access without a webmail send is just document
access, and a webmail POST without a compose visit could be an auto-draft save.

Confidence model
----------------
    base              = 0.55   (compose/send URL visit alone)
    + document_access = +0.25  (sensitive doc accessed within window_minutes)
    + pcap_corroboration = +0.15 (POST to webmail host in the same window)
    max                = 0.95

If neither browser history nor PCAP shows a send (only a draft or inbox), the
detector returns nothing — we require evidence that data was actually sent out.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.browser_history_parser import BrowserHistoryEntry
from ..parsers.pcap_parser import HTTPRequest
from ..self_correction.engine import Finding


# URL substrings that indicate an active webmail compose or send action. These
# are chosen to avoid false-positives on inbox/reading activity: reading email
# is normal, composing and sending are the exfiltration signal.
_COMPOSE_SEND_SUBSTRINGS: tuple[str, ...] = (
    "mail.google.com/mail/u/",  # Gmail — further narrowed by fragment below
    "outlook.live.com/mail/",
    "outlook.office.com/mail/",
    "mail.yahoo.com/d/compose",
    "mail.yahoo.com/d/folders/sent",
    "mail.proton.me/u/",
    "tutanota.com/",
)

# Fragments (the part after `#` in a URL) that specifically indicate send or
# compose state. Gmail uses hash-based routing so `#compose` / `#sent` are the
# only reliable signals within mail.google.com.
_SEND_FRAGMENTS: tuple[str, ...] = ("#compose", "#sent", "#drafts")

# Document extensions considered "sensitive" when no explicit allow-list is
# provided. These are the typical exfiltration targets seen in corporate IP
# theft cases. Not exhaustive — callers can override via `sensitive_extensions`.
_DEFAULT_SENSITIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".pdf",
        ".zip",
        ".rar",
        ".7z",
        ".csv",
        ".json",
        ".sql",
        ".key",
        ".pem",
        ".dwg",
    }
)

# Hosts considered webmail providers for PCAP corroboration. Matches are
# substring-based to tolerate port suffixes (`:443`) and subdomains.
_WEBMAIL_HOSTS: tuple[str, ...] = (
    "mail.google.com",
    "gmail.com",
    "outlook.live.com",
    "outlook.office.com",
    "mail.yahoo.com",
    "mail.proton.me",
    "tutanota.com",
)


@dataclass(frozen=True)
class MFTAccessRecord:
    """A minimal view of an MFT entry used by this detector.

    Detectors should not import the full MFT parser types — this dataclass
    captures exactly what the correlation logic needs, which lets us unit-test
    without building full MFT entries.
    """

    filename: str
    parent_path: str
    accessed: datetime


class WebmailExfilDetector:
    """Detect webmail-based data exfiltration via cross-artifact correlation.

    Parameters
    ----------
    window_minutes:
        How close an MFT document access must be to a webmail compose/send
        event to count as corroboration. Default 10 minutes reflects the
        tight "open doc -> copy contents -> paste into compose" sequence.
    sensitive_extensions:
        Filename extensions (lowercase, including leading dot) treated as
        sensitive documents. Defaults to office/archive formats.
    """

    def __init__(
        self,
        window_minutes: int = 10,
        sensitive_extensions: Optional[frozenset[str]] = None,
    ):
        if window_minutes <= 0:
            raise ValueError("window_minutes must be positive")
        self.window = timedelta(minutes=window_minutes)
        self.sensitive_extensions = (
            sensitive_extensions
            if sensitive_extensions is not None
            else _DEFAULT_SENSITIVE_EXTENSIONS
        )

    def analyze(
        self,
        browser_history: Iterable[BrowserHistoryEntry],
        mft_records: Optional[Iterable[MFTAccessRecord]] = None,
        http_requests: Optional[Iterable[HTTPRequest]] = None,
    ) -> list[Finding]:
        """Analyze artifact streams and emit webmail-exfiltration findings.

        The detector groups browser-history send events and emits one finding
        per distinct send session (events within 30 minutes collapse into one).
        """
        history_list = list(browser_history)
        send_events = [e for e in history_list if self._is_send_event(e)]
        if not send_events:
            return []

        mft_list = list(mft_records) if mft_records is not None else []
        http_list = list(http_requests) if http_requests is not None else []

        sessions = self._cluster_send_events(send_events)
        findings: list[Finding] = []
        for session in sessions:
            finding = self._build_finding(session, history_list, mft_list, http_list)
            if finding is not None:
                findings.append(finding)
        return findings

    def _is_send_event(self, entry: BrowserHistoryEntry) -> bool:
        """True if the history entry indicates a compose or send action."""
        url = entry.url.lower()
        if "#compose" in url or "#sent" in url:
            return True
        return any(fragment in url for fragment in _SEND_FRAGMENTS) and any(
            host in url for host in _WEBMAIL_HOSTS
        )

    def _cluster_send_events(
        self, events: list[BrowserHistoryEntry]
    ) -> list[list[BrowserHistoryEntry]]:
        """Group send events into sessions (30-minute contiguity)."""
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        sessions: list[list[BrowserHistoryEntry]] = []
        current: list[BrowserHistoryEntry] = []
        session_gap = timedelta(minutes=30)
        for event in events_sorted:
            if not current or event.timestamp - current[-1].timestamp <= session_gap:
                current.append(event)
            else:
                sessions.append(current)
                current = [event]
        if current:
            sessions.append(current)
        return sessions

    def _build_finding(
        self,
        session: list[BrowserHistoryEntry],
        full_history: list[BrowserHistoryEntry],
        mft_records: list[MFTAccessRecord],
        http_requests: list[HTTPRequest],
    ) -> Optional[Finding]:
        """Build one finding for one send session, or return None if unsent."""
        has_sent_marker = any("#sent" in e.url.lower() for e in session)
        http_corroboration = self._find_http_corroboration(session, http_requests)
        if not has_sent_marker and not http_corroboration:
            return None

        session_start = session[0].timestamp
        session_end = session[-1].timestamp
        provider = self._identify_provider(session)

        accessed_docs = self._find_sensitive_document_accesses(
            mft_records,
            session_start - self.window,
            session_end + self.window,
        )

        confidence = 0.55
        reasoning: list[str] = []
        reasoning.append(
            f"Browser history shows webmail activity at {provider} "
            f"from {session_start.isoformat()} to {session_end.isoformat()}"
        )
        for event in session:
            reasoning.append(f"  {event.timestamp.isoformat()} {event.url}")

        if accessed_docs:
            confidence += 0.25
            reasoning.append(
                f"Sensitive document access within +/-{self.window.total_seconds()/60:.0f} min:"
            )
            for doc in accessed_docs:
                reasoning.append(
                    f"  {doc.accessed.isoformat()} {doc.parent_path}\\{doc.filename}"
                )

        if http_corroboration:
            confidence += 0.15
            reasoning.append(
                f"Network traffic corroborates webmail interaction: "
                f"{len(http_corroboration)} POST/CONNECT requests to {provider}"
            )

        confidence = min(confidence, 0.95)

        evidence = {
            "exfil_type": "webmail",
            "provider": provider,
            "session_start": session_start.isoformat(),
            "session_end": session_end.isoformat(),
            "browser_history_urls": [e.url for e in session],
            "sensitive_documents": [
                {
                    "filename": d.filename,
                    "path": d.parent_path,
                    "accessed": d.accessed.isoformat(),
                }
                for d in accessed_docs
            ],
            "http_corroboration_count": len(http_corroboration),
        }

        title = f"Webmail exfiltration via {provider}"
        if accessed_docs:
            doc_names = ", ".join(sorted({d.filename for d in accessed_docs}))
            description = (
                f"Browser history shows a {provider} send session while "
                f"sensitive document(s) ({doc_names}) were accessed within "
                f"{self.window.total_seconds()/60:.0f} minutes."
            )
        else:
            description = (
                f"Browser history shows a {provider} send session. No "
                f"sensitive document access detected within the correlation "
                f"window — the compose/send evidence stands on its own."
            )

        artifact_sources = ["browser_history"]
        if accessed_docs:
            artifact_sources.append("mft")
        if http_corroboration:
            artifact_sources.append("pcap")

        confidence_label = (
            "Very High"
            if confidence >= 0.9
            else (
                "High"
                if confidence >= 0.75
                else "Medium" if confidence >= 0.5 else "Low"
            )
        )

        return Finding(
            title=title,
            description=description,
            finding_type="behavior",
            severity="high",
            category=FindingCategory.DATA_EXFILTRATION,
            evidence=evidence,
            confidence=confidence,
            confidence_label=confidence_label,
            reasoning_chain=reasoning,
            artifact_sources=artifact_sources,
        )

    def _identify_provider(self, session: list[BrowserHistoryEntry]) -> str:
        """Return a friendly provider name from the session URLs."""
        for event in session:
            url = event.url.lower()
            if "mail.google.com" in url or "gmail.com" in url:
                return "Gmail"
            if "outlook.live.com" in url or "outlook.office.com" in url:
                return "Outlook"
            if "mail.yahoo.com" in url:
                return "Yahoo Mail"
            if "mail.proton.me" in url:
                return "ProtonMail"
            if "tutanota.com" in url:
                return "Tutanota"
        return "unknown webmail provider"

    def _find_sensitive_document_accesses(
        self,
        mft_records: list[MFTAccessRecord],
        window_start: datetime,
        window_end: datetime,
    ) -> list[MFTAccessRecord]:
        """Return MFT records for sensitive docs accessed within the window."""
        hits: list[MFTAccessRecord] = []
        for record in mft_records:
            if not self._is_sensitive(record.filename):
                continue
            if self._is_within(record.accessed, window_start, window_end):
                hits.append(record)
        return hits

    def _is_sensitive(self, filename: str) -> bool:
        """True if the filename has a sensitive extension."""
        lowered = filename.lower()
        return any(lowered.endswith(ext) for ext in self.sensitive_extensions)

    def _find_http_corroboration(
        self,
        session: list[BrowserHistoryEntry],
        http_requests: list[HTTPRequest],
    ) -> list[HTTPRequest]:
        """Return POST/CONNECT requests to webmail hosts in the session window."""
        if not http_requests:
            return []
        window_start = session[0].timestamp - self.window
        window_end = session[-1].timestamp + self.window
        relevant: list[HTTPRequest] = []
        for request in http_requests:
            if request.method not in ("POST", "CONNECT"):
                continue
            host = request.host.lower()
            if not any(w in host for w in _WEBMAIL_HOSTS):
                continue
            if self._is_within(request.timestamp, window_start, window_end):
                relevant.append(request)
        return relevant

    def _is_within(
        self, ts: datetime, window_start: datetime, window_end: datetime
    ) -> bool:
        """True if ts falls inside the window. Handles timezone drift gracefully.

        Browser history is typically UTC-tagged; PCAP timestamps from tshark
        default to local time unless `-u hms` is set. If one side is naive and
        the other is aware, we compare naive-to-naive to avoid the comparison
        raising.
        """
        if (ts.tzinfo is None) != (window_start.tzinfo is None):
            return ts.replace(tzinfo=None) >= window_start.replace(
                tzinfo=None
            ) and ts.replace(tzinfo=None) <= window_end.replace(tzinfo=None)
        return window_start <= ts <= window_end
