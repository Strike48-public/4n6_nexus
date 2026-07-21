"""Cross-artifact / cross-host graph correlation.

Exposes a read-only correlation graph and safe query helpers. No write or
delete API is exported; the surface is read-only by construction.
"""

from .correlate import build_graph, lateral_tool_reuse, query, suspicious_ancestry

__all__ = ["build_graph", "lateral_tool_reuse", "suspicious_ancestry", "query"]
