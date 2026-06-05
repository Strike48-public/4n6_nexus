"""Stdio launcher for the Custom MCP server (Claude Code integration).

Run as a stdio MCP server so Claude Code (or any MCP client) can drive the
forensic tools through our architectural boundary:

    python -m sift_find_evil.mcp \\
        --case-id INC-2026-001 \\
        --evidence-root /cases/INC-2026-001/evidence \\
        --audit-path /cases/INC-2026-001/audit.jsonl

Registered in Claude Code via .mcp.json (see repo root) or:

    claude mcp add sift-find-evil -- python -m sift_find_evil.mcp \\
        --case-id INC-2026-001 --evidence-root <dir> --audit-path <file>

Every tool call still crosses ``EvidenceMCPServer.run_tool`` -> ``ToolGuard``,
so read-only enforcement, evidence-path containment, the circuit breaker, and
audit logging are unavoidable regardless of what the agent prompt says.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

from .server import EvidenceMCPServer, build_fastmcp


def build_app(
    case_id: str,
    evidence_root: Path,
    audit_path: Path,
    examiner: Optional[str] = None,
):
    """Compose the dispatch core + FastMCP app (no transport started).

    Separated from ``main`` so tests can assert the app/tool registration
    without binding stdio.
    """
    server = EvidenceMCPServer(
        case_id=case_id,
        evidence_root=Path(evidence_root),
        audit_path=Path(audit_path),
        examiner=examiner,
    )
    return build_fastmcp(server)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m sift_find_evil.mcp",
        description="SIFT Find Evil - Custom MCP server (stdio) for Claude Code",
    )
    parser.add_argument(
        "--case-id",
        default=os.environ.get("SFE_CASE_ID", "INC-2026-001"),
        help="Case identifier stamped on audit entries.",
    )
    parser.add_argument(
        "--evidence-root",
        default=os.environ.get("SFE_EVIDENCE_ROOT", "."),
        help="Directory all tool input paths must resolve inside (read-only).",
    )
    parser.add_argument(
        "--audit-path",
        default=os.environ.get("SFE_AUDIT_PATH", "./audit.jsonl"),
        help="Append-only JSONL audit log path.",
    )
    parser.add_argument(
        "--examiner",
        default=os.environ.get("SFE_EXAMINER"),
        help="Examiner identity recorded in the audit trail.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry: launch the MCP server over stdio for an MCP client."""
    args = _parse_args(argv)
    audit_path = Path(args.audit_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    mcp = build_app(
        case_id=args.case_id,
        evidence_root=Path(args.evidence_root),
        audit_path=audit_path,
        examiner=args.examiner,
    )
    # Blocks serving stdio until the client disconnects.
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
