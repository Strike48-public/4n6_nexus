"""Cloud-storage upload exfiltration detector.

Detects data exfiltration via cloud-storage web apps (T1567.002 — Exfiltration
to Cloud Storage) by correlating browser history visits to upload surfaces
(Dropbox, Google Drive, OneDrive, Mega, Box, WeTransfer) with optional MFT
document access and PCAP upload corroboration.

Unlike webmail (T1567), cloud-storage browsers do not have a clear "send"
state marker in the URL — a visit to `/upload` or the folder view is the
primary signal. Because the URL alone is weaker evidence than #sent for
webmail, this detector weights the same at 0.55 base but relies more heavily
on MFT / PCAP corroboration in real cases.

Confidence model
----------------
    base              = 0.55   (visit to cloud-upload URL)
    + document_access = +0.25  (sensitive doc accessed within window_minutes)
    + pcap_corroboration = +0.15 (POST to cloud API host in the same window)
    max                = 0.95
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.browser_history_parser import BrowserHistoryEntry
from ..parsers.pcap_parser import HTTPRequest
from ..self_correction.engine import Finding
from .webmail_exfil_detector import MFTAccessRecord


# URL substrings that indicate a cloud-storage upload surface. These match the
# web-app side (what a user's browser history would show). The PCAP side uses
# a separate host list below to cover API endpoints that the browser itself
# talks to during the upload (content.dropboxapi.com, etc.).
_CLOUD_URL_SUBSTRINGS: tuple[str, ...] = (
    "dropbox.com/home",
    "dropbox.com/upload",
    "dropbox.com/h",
    "drive.google.com/drive",
    "drive.google.com/u/",
    "onedrive.live.com",
    "1drv.ms/",
    "mega.nz/fm",
    "mega.io/fm",
    "app.box.com/folder",
    "app.box.com/files",
    "wetransfer.com/",
    "send-anywhere.com",
    "filebin.net",
)

# Hosts considered cloud-storage providers for PCAP corroboration. Matches are
# substring-based to tolerate subdomains (content.dropboxapi.com) and API
# endpoints. Keep in sync with `_CLOUD_URL_SUBSTRINGS` but covers API hosts,
# not just web-app hosts.
_CLOUD_HOSTS: tuple[str, ...] = (
    "dropbox.com",
    "dropboxapi.com",
    "drive.google.com",
    "googleapis.com",
    "onedrive.live.com",
    "1drv.ms",
    "graph.microsoft.com",
    "mega.nz",
    "mega.io",
    "mega.co.nz",
    "box.com",
    "boxcloud.com",
    "wetransfer.com",
    "wetransfer.net",
)

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


class CloudUploadDetector:
    """Detect cloud-storage upload exfiltration via cross-artifact correlation.

    Parameters
    ----------
    window_minutes:
        How close an MFT document access or PCAP POST must be to a cloud
        browser visit to count as corroboration. Default 10 minutes.
    sensitive_extensions:
        Filename extensions (lowercase, including leading dot) treated as
        sensitive documents.
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
        """Analyze artifact streams and emit cloud-upload findings.

        Groups cloud-upload browser visits into sessions (30-minute gap) and
        emits one finding per session.
        """
        history_list = list(browser_history)
        upload_events = [e for e in history_list if self._is_upload_event(e)]
        if not upload_events:
            return []

        mft_list = list(mft_records) if mft_records is not None else []
        http_list = list(http_requests) if http_requests is not None else []

        sessions = self._cluster_events(upload_events)
        findings: list[Finding] = []
        for session in sessions:
            finding = self._build_finding(session, mft_list, http_list)
            if finding is not None:
                findings.append(finding)
        return findings

    def _is_upload_event(self, entry: BrowserHistoryEntry) -> bool:
        """True if the history entry points at a cloud-storage upload surface."""
        url = entry.url.lower()
        return any(sub in url for sub in _CLOUD_URL_SUBSTRINGS)

    def _cluster_events(
        self, events: list[BrowserHistoryEntry]
    ) -> list[list[BrowserHistoryEntry]]:
        """Group upload events into sessions (30-minute contiguity)."""
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
        mft_records: list[MFTAccessRecord],
        http_requests: list[HTTPRequest],
    ) -> Optional[Finding]:
        session_start = session[0].timestamp
        session_end = session[-1].timestamp
        provider = self._identify_provider(session)

        accessed_docs = self._find_sensitive_document_accesses(
            mft_records,
            session_start - self.window,
            session_end + self.window,
        )
        http_corroboration = self._find_http_corroboration(session, http_requests)

        confidence = 0.55
        reasoning: list[str] = [
            f"Browser history shows cloud-upload activity at {provider} "
            f"from {session_start.isoformat()} to {session_end.isoformat()}"
        ]
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
                f"Network traffic corroborates cloud-upload: "
                f"{len(http_corroboration)} POST/PUT requests to {provider} API hosts"
            )

        confidence = min(confidence, 0.95)

        evidence = {
            "exfil_type": "cloud_upload",
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

        title = f"Cloud-storage upload exfiltration via {provider}"
        if accessed_docs:
            doc_names = ", ".join(sorted({d.filename for d in accessed_docs}))
            description = (
                f"Browser history shows a {provider} upload session while "
                f"sensitive document(s) ({doc_names}) were accessed within "
                f"{self.window.total_seconds()/60:.0f} minutes."
            )
        else:
            description = (
                f"Browser history shows a {provider} upload session. No "
                f"sensitive document access detected within the correlation "
                f"window — the upload-URL evidence stands on its own."
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
            if "dropbox.com" in url:
                return "Dropbox"
            if "drive.google.com" in url:
                return "Google Drive"
            if "onedrive.live.com" in url or "1drv.ms" in url:
                return "OneDrive"
            if "mega.nz" in url or "mega.io" in url or "mega.co.nz" in url:
                return "Mega"
            if "box.com" in url:
                return "Box"
            if "wetransfer.com" in url or "wetransfer.net" in url:
                return "WeTransfer"
        return "unknown cloud-storage provider"

    def _find_sensitive_document_accesses(
        self,
        mft_records: list[MFTAccessRecord],
        window_start: datetime,
        window_end: datetime,
    ) -> list[MFTAccessRecord]:
        hits: list[MFTAccessRecord] = []
        for record in mft_records:
            if not self._is_sensitive(record.filename):
                continue
            if self._is_within(record.accessed, window_start, window_end):
                hits.append(record)
        return hits

    def _is_sensitive(self, filename: str) -> bool:
        lowered = filename.lower()
        return any(lowered.endswith(ext) for ext in self.sensitive_extensions)

    def _find_http_corroboration(
        self,
        session: list[BrowserHistoryEntry],
        http_requests: list[HTTPRequest],
    ) -> list[HTTPRequest]:
        """Return POST/PUT requests to cloud hosts in the session window."""
        if not http_requests:
            return []
        window_start = session[0].timestamp - self.window
        window_end = session[-1].timestamp + self.window
        relevant: list[HTTPRequest] = []
        for request in http_requests:
            if request.method not in ("POST", "PUT"):
                continue
            host = request.host.lower()
            if not any(h in host for h in _CLOUD_HOSTS):
                continue
            if self._is_within(request.timestamp, window_start, window_end):
                relevant.append(request)
        return relevant

    def _is_within(
        self, ts: datetime, window_start: datetime, window_end: datetime
    ) -> bool:
        """True if ts falls inside the window. Handles timezone drift gracefully."""
        if (ts.tzinfo is None) != (window_start.tzinfo is None):
            return ts.replace(tzinfo=None) >= window_start.replace(
                tzinfo=None
            ) and ts.replace(tzinfo=None) <= window_end.replace(tzinfo=None)
        return window_start <= ts <= window_end
