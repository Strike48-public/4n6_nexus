"""PCAP parser - Extract network artifacts using tshark.

Provides thin wrappers around tshark subprocess calls to extract HTTP sessions,
SMTP traffic, DNS queries, and other network artifacts for forensic analysis.

Designed for SIFT Workstation environment where tshark is pre-installed.
No GUI dependencies, CLI-only workflow.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class HTTPRequest:
    """A single HTTP request extracted from PCAP.

    Represents an HTTP request with method, host, URI, and optional form data
    for POST requests (used to identify web-based email sends, logins, etc.).
    """

    frame_number: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    method: str  # GET, POST, etc.
    host: str
    uri: str
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    form_data: Optional[str] = None  # URL-encoded form data for POST requests


@dataclass(frozen=True)
class HTTPSession:
    """A collection of HTTP requests that form a logical session.

    Groups requests by source IP and time proximity to represent a user session
    (e.g., login + email send + logout).
    """

    src_ip: str
    start_time: datetime
    end_time: datetime
    requests: tuple[HTTPRequest, ...]
    hosts_accessed: tuple[str, ...]  # Unique hosts in this session


@dataclass(frozen=True)
class DNSQuery:
    """A DNS query extracted from PCAP."""

    frame_number: int
    timestamp: datetime
    src_ip: str
    query_name: str  # Domain being queried
    query_type: str  # A, AAAA, MX, etc.
    response_ip: Optional[str] = None  # Resolved IP (if response available)


@dataclass(frozen=True)
class SMTPMessage:
    """SMTP email traffic extracted from PCAP."""

    frame_number: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    mail_from: Optional[str] = None
    rcpt_to: Optional[str] = None
    subject: Optional[str] = None
    body_preview: Optional[str] = None  # First 500 chars of body


class PcapParser:
    """Parse PCAP files using tshark subprocess calls.

    Usage:
        parser = PcapParser()
        http_requests = parser.extract_http_requests(Path("capture.pcap"))
        dns_queries = parser.extract_dns_queries(Path("capture.pcap"))
    """

    def __init__(self, tshark_path: str = "/usr/bin/tshark"):
        """Initialize parser with tshark binary path.

        Args:
            tshark_path: Path to tshark executable (default: /usr/bin/tshark)

        Raises:
            FileNotFoundError: If tshark is not found at the specified path.
        """
        self.tshark_path = Path(tshark_path)
        if not self.tshark_path.exists():
            raise FileNotFoundError(f"tshark not found at: {tshark_path}")

    def extract_http_requests(
        self, pcap_path: Path, display_filter: Optional[str] = None
    ) -> list[HTTPRequest]:
        """Extract HTTP requests from PCAP file.

        Args:
            pcap_path: Path to PCAP file.
            display_filter: Optional Wireshark display filter (e.g., "http.request.method == POST")

        Returns:
            List of HTTPRequest objects.

        Raises:
            FileNotFoundError: If PCAP file does not exist.
            RuntimeError: If tshark command fails.
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        # Build tshark command to extract HTTP request fields
        filter_expr = display_filter or "http.request"
        cmd = [
            str(self.tshark_path),
            "-r",
            str(pcap_path),
            "-Y",
            filter_expr,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "http.user_agent",
            "-e",
            "http.content_type",
            "-e",
            "http.file_data",  # Form data for POST requests
            "-E",
            "separator=|",
            "-E",
            "quote=d",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=60
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark failed: {e.stderr}") from e
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark timed out after 60 seconds")

        # Parse tshark output
        requests: list[HTTPRequest] = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue

            fields = line.split("|")
            if len(fields) < 7:
                continue  # Skip malformed lines

            try:
                # Strip quotes and whitespace from each field
                def clean(field: str) -> str:
                    return field.strip().strip('"')

                frame_number = int(clean(fields[0]))
                timestamp = datetime.fromtimestamp(float(clean(fields[1])))
                src_ip = clean(fields[2])
                dst_ip = clean(fields[3]) if len(fields) > 3 else ""
                method = clean(fields[4]) if len(fields) > 4 else ""
                host = clean(fields[5]) if len(fields) > 5 else ""
                uri = clean(fields[6]) if len(fields) > 6 else ""
                user_agent = clean(fields[7]) if len(fields) > 7 and fields[7].strip() else None
                content_type = clean(fields[8]) if len(fields) > 8 and fields[8].strip() else None
                form_data = clean(fields[9]) if len(fields) > 9 and fields[9].strip() else None

                requests.append(
                    HTTPRequest(
                        frame_number=frame_number,
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        method=method,
                        host=host,
                        uri=uri,
                        user_agent=user_agent,
                        content_type=content_type,
                        form_data=form_data,
                    )
                )
            except (ValueError, IndexError):
                # Skip lines that fail parsing
                continue

        return requests

    def extract_http_sessions(
        self, pcap_path: Path, session_timeout_seconds: int = 300
    ) -> list[HTTPSession]:
        """Group HTTP requests into logical sessions by source IP and time proximity.

        Args:
            pcap_path: Path to PCAP file.
            session_timeout_seconds: Max time gap between requests in same session (default: 5 min)

        Returns:
            List of HTTPSession objects.
        """
        requests = self.extract_http_requests(pcap_path)
        if not requests:
            return []

        # Sort requests by source IP and timestamp
        requests.sort(key=lambda r: (r.src_ip, r.timestamp))

        # Group into sessions
        sessions: list[HTTPSession] = []
        current_session_requests: list[HTTPRequest] = []
        current_ip: Optional[str] = None
        last_timestamp: Optional[datetime] = None

        for req in requests:
            # Check if we should start a new session
            if (
                current_ip is None
                or req.src_ip != current_ip
                or (
                    last_timestamp
                    and (req.timestamp - last_timestamp).total_seconds()
                    > session_timeout_seconds
                )
            ):
                # Save previous session if exists
                if current_session_requests:
                    sessions.append(self._build_session(current_session_requests))

                # Start new session
                current_session_requests = [req]
                current_ip = req.src_ip
                last_timestamp = req.timestamp
            else:
                # Add to current session
                current_session_requests.append(req)
                last_timestamp = req.timestamp

        # Save final session
        if current_session_requests:
            sessions.append(self._build_session(current_session_requests))

        return sessions

    def _build_session(self, requests: list[HTTPRequest]) -> HTTPSession:
        """Build HTTPSession from list of requests."""
        hosts = tuple(sorted(set(r.host for r in requests if r.host)))
        return HTTPSession(
            src_ip=requests[0].src_ip,
            start_time=requests[0].timestamp,
            end_time=requests[-1].timestamp,
            requests=tuple(requests),
            hosts_accessed=hosts,
        )

    def extract_dns_queries(self, pcap_path: Path) -> list[DNSQuery]:
        """Extract DNS queries from PCAP file.

        Args:
            pcap_path: Path to PCAP file.

        Returns:
            List of DNSQuery objects.
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        cmd = [
            str(self.tshark_path),
            "-r",
            str(pcap_path),
            "-Y",
            "dns.flags.response == 0",  # Queries only, not responses
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.qry.type",
            "-E",
            "separator=|",
            "-E",
            "quote=d",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=60
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark failed: {e.stderr}") from e

        queries: list[DNSQuery] = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue

            fields = line.split("|")
            if len(fields) < 5:
                continue

            try:
                # Strip quotes and whitespace
                def clean(field: str) -> str:
                    return field.strip().strip('"')

                frame_number = int(clean(fields[0]))
                timestamp = datetime.fromtimestamp(float(clean(fields[1])))
                src_ip = clean(fields[2])
                query_name = clean(fields[3])
                query_type = clean(fields[4])

                queries.append(
                    DNSQuery(
                        frame_number=frame_number,
                        timestamp=timestamp,
                        src_ip=src_ip,
                        query_name=query_name,
                        query_type=query_type,
                    )
                )
            except (ValueError, IndexError):
                continue

        return queries

    def extract_smtp_messages(self, pcap_path: Path) -> list[SMTPMessage]:
        """Extract SMTP email traffic from PCAP file.

        Args:
            pcap_path: Path to PCAP file.

        Returns:
            List of SMTPMessage objects.
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        cmd = [
            str(self.tshark_path),
            "-r",
            str(pcap_path),
            "-Y",
            "smtp",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "smtp.req.command",  # MAIL FROM, RCPT TO, etc.
            "-e",
            "smtp.req.parameter",
            "-E",
            "separator=|",
            "-E",
            "quote=d",
        ]

        try:
            subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=60
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark failed: {e.stderr}") from e

        # SMTP parsing is more complex - would need multi-line parsing
        # For now, return basic structure
        # TODO: Implement full SMTP message reconstruction
        return []
