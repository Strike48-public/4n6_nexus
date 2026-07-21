"""Cross-artifact / cross-host correlation graph.

Builds a read-only :class:`networkx.MultiDiGraph` from normalized forensic
events and exposes safe, side-effect-free queries over it. The graph unifies
signals that individual per-host detectors cannot connect on their own: the
same tool binary appearing on several hosts, or a suspicious process-spawn
chain that only reads as malicious once parent role and child identity are
correlated.

Design constraints:

* **Read-only by construction.** The public surface is ``build_graph`` plus
  three pure query helpers. No mutate/delete API is exported, so a caller can
  never edit correlation results in place.
* **MERGE semantics.** Nodes are keyed by ``(kind, id)`` so repeated events for
  the same entity collapse to one node. Building twice from identical events is
  idempotent.
* **No input mutation.** Event dicts handed in are never modified.

Event schema (all dicts):

* Node event: ``{"kind": <host|process|file|socket|user|domain>, "id": str,
  "host": str, **attrs}``.
* Edge event: ``{"edge": <rel>, "src": id, "dst": id, "host": str}`` where
  ``rel`` is one of :data:`KNOWN_RELATIONS`.
"""

from __future__ import annotations

from typing import Any, Iterable

import networkx as nx

from ..findings import Finding, FindingCategory

# Node kinds the correlation graph understands. Anything else is dropped so a
# typo in an upstream parser cannot silently pollute the graph.
KNOWN_KINDS: frozenset[str] = frozenset(
    {"host", "process", "file", "socket", "user", "domain"}
)

# Typed relations permitted on edges. Foreign relations are skipped.
KNOWN_RELATIONS: frozenset[str] = frozenset(
    {"RAN_ON", "SPAWNED", "CONNECTED_TO", "MODIFIED", "LOGGED_IN", "RESOLVED_DNS"}
)

# Placeholder kind used when an edge references an id that had no node event.
_UNKNOWN_KIND = "unknown"

# Shell interpreters whose creation by a service/system parent is suspicious.
_SHELL_NAMES: frozenset[str] = frozenset(
    {"cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "powershell"}
)

# Names that mark a process as a service/system parent even without an explicit
# ``role`` attribute (Windows service host + init shapes).
_SERVICE_NAMES: frozenset[str] = frozenset(
    {"services.exe", "svchost.exe", "wininit.exe", "systemd", "init"}
)

# Node-attribute keys that are managed internally and must not be overwritten by
# raw event attrs.
_RESERVED_ATTRS: frozenset[str] = frozenset({"kind", "id", "hosts", "host"})


def build_graph(events: Iterable[dict[str, Any]]) -> nx.MultiDiGraph:
    """Build a read-only correlation graph from normalized events.

    Nodes are merged by ``(kind, id)``; typed edges are added for recognized
    relations. Malformed events (missing keys, non-dicts, unknown kinds or
    relations) are skipped rather than raising, so a single bad row never aborts
    correlation of an otherwise valid batch.

    Args:
        events: Iterable of node and edge event dicts. See the module docstring
            for the accepted shapes. Inputs are never mutated.

    Returns:
        A :class:`networkx.MultiDiGraph` keyed by ``(kind, id)`` node tuples.
    """
    graph: nx.MultiDiGraph = nx.MultiDiGraph()

    for event in events:
        if not isinstance(event, dict):
            continue
        if "edge" in event:
            _add_edge_event(graph, event)
        else:
            _add_node_event(graph, event)

    return graph


def _add_node_event(graph: nx.MultiDiGraph, event: dict[str, Any]) -> None:
    """Merge a single node event into the graph (internal).

    Args:
        graph: Target graph, mutated in place (the graph, never the event).
        event: A node event dict.
    """
    kind = event.get("kind")
    node_id = event.get("id")
    if kind not in KNOWN_KINDS or node_id is None:
        return

    extra = {k: v for k, v in event.items() if k not in _RESERVED_ATTRS}
    _merge_node(graph, kind, node_id, host=event.get("host"), attrs=extra)


def _add_edge_event(graph: nx.MultiDiGraph, event: dict[str, Any]) -> None:
    """Add a single typed edge event into the graph (internal).

    Endpoints that were never declared via a node event are auto-created as
    ``unknown``-kind placeholders so an edge is never silently dropped for a
    missing node.

    Args:
        graph: Target graph, mutated in place.
        event: An edge event dict.
    """
    rel = event.get("edge")
    src = event.get("src")
    dst = event.get("dst")
    if rel not in KNOWN_RELATIONS or src is None or dst is None:
        return

    src_node = _resolve_node(graph, src, host=event.get("host"))
    dst_node = _resolve_node(graph, dst, host=event.get("host"))

    # MERGE the edge: at most one edge per (src, dst, rel) key.
    if not graph.has_edge(src_node, dst_node, key=rel):
        graph.add_edge(src_node, dst_node, key=rel, rel=rel)


def _merge_node(
    graph: nx.MultiDiGraph,
    kind: str,
    node_id: str,
    *,
    host: str | None,
    attrs: dict[str, Any],
) -> tuple[str, str]:
    """Create or update a node, accumulating hosts and non-reserved attrs.

    Args:
        graph: Target graph, mutated in place.
        kind: Node kind.
        node_id: Node identifier.
        host: Host this observation came from, added to the node's host set.
        attrs: Extra attributes to record on the node.

    Returns:
        The ``(kind, id)`` node key.
    """
    node = (kind, node_id)
    if node not in graph:
        graph.add_node(node, kind=kind, id=node_id, hosts=set())
    data = graph.nodes[node]
    if host is not None:
        data["hosts"].add(host)
    data.update(attrs)
    return node


def _resolve_node(
    graph: nx.MultiDiGraph, raw_id: str, *, host: str | None
) -> tuple[str, str]:
    """Find the existing node for ``raw_id`` or create an unknown placeholder.

    An id is matched against any already-declared node regardless of kind, so an
    edge referencing a process declared elsewhere binds to that process rather
    than spawning a duplicate placeholder.

    Args:
        graph: Target graph, mutated in place if a placeholder is created.
        raw_id: The ``src``/``dst`` identifier from an edge event.
        host: Host the edge observation came from.

    Returns:
        The resolved ``(kind, id)`` node key.
    """
    for kind in KNOWN_KINDS:
        candidate = (kind, raw_id)
        if candidate in graph:
            if host is not None:
                graph.nodes[candidate]["hosts"].add(host)
            return candidate
    return _merge_node(graph, _UNKNOWN_KIND, raw_id, host=host, attrs={})


def lateral_tool_reuse(
    graph: nx.MultiDiGraph, dual_use_denylist: set[str]
) -> list[Finding]:
    """Flag denylisted binaries that RAN_ON more than one distinct host.

    A dual-use administration binary (PsExec, WMIExec, etc.) executing across
    multiple hosts is a strong lateral-movement signal (MITRE T1021). Binaries
    outside the denylist, or run on a single host, are not flagged.

    Args:
        graph: A correlation graph from :func:`build_graph`.
        dual_use_denylist: Binary ids considered dual-use lateral tools.

    Returns:
        One :class:`Finding` per denylisted multi-host binary, most-specific
        first (input order of the graph nodes).
    """
    findings: list[Finding] = []

    for node, data in graph.nodes(data=True):
        kind, node_id = node
        if kind != "process" or node_id not in dual_use_denylist:
            continue

        hosts = _ran_on_hosts(graph, node)
        if len(hosts) <= 1:
            continue

        ordered_hosts = sorted(hosts)
        findings.append(
            Finding(
                title=f"Dual-use tool {node_id} reused across {len(ordered_hosts)} hosts",
                description=(
                    f"Binary {node_id} executed on {len(ordered_hosts)} distinct "
                    f"hosts ({', '.join(ordered_hosts)}). Cross-host reuse of a "
                    "dual-use administration tool is a lateral-movement pattern."
                ),
                finding_type="behavior",
                severity="high",
                category=FindingCategory.LATERAL_MOVEMENT,
                evidence={
                    "binary": node_id,
                    "hosts": ordered_hosts,
                    "host_count": len(ordered_hosts),
                    "mitre": "T1021",
                },
                reasoning_chain=[
                    f"{node_id} is on the dual-use tool denylist.",
                    f"It has RAN_ON edges to {len(ordered_hosts)} distinct hosts.",
                    "Reuse of one operator tool across hosts indicates lateral movement (MITRE T1021).",
                ],
                artifact_sources=[node_id],
            )
        )

    return findings


def _ran_on_hosts(graph: nx.MultiDiGraph, node: tuple[str, str]) -> set[str]:
    """Return the set of distinct host ids ``node`` has RAN_ON edges to.

    Args:
        graph: The correlation graph.
        node: The source ``(kind, id)`` node key.

    Returns:
        Distinct destination ids reached by a ``RAN_ON`` edge.
    """
    hosts: set[str] = set()
    for _, dst, data in graph.out_edges(node, data=True):
        if data.get("rel") == "RAN_ON":
            hosts.add(dst[1])
    return hosts


def suspicious_ancestry(graph: nx.MultiDiGraph) -> list[Finding]:
    """Flag service/system parents that SPAWNED a shell interpreter.

    A service-tier or system process spawning cmd.exe/powershell/bash is a
    classic execution primitive (living-off-the-land, service abuse). Benign
    interactive chains (explorer -> notepad) are not flagged.

    Args:
        graph: A correlation graph from :func:`build_graph`.

    Returns:
        One :class:`Finding` per suspicious parent -> shell spawn edge.
    """
    findings: list[Finding] = []

    for src, dst, data in graph.edges(data=True):
        if data.get("rel") != "SPAWNED":
            continue
        if src[0] != "process" or dst[0] != "process":
            continue

        parent_id = src[1]
        child_id = dst[1]
        if not _is_service_parent(graph, src):
            continue
        if child_id not in _SHELL_NAMES:
            continue

        findings.append(
            Finding(
                title=f"Service parent {parent_id} spawned shell {child_id}",
                description=(
                    f"Process {parent_id} (service/system tier) spawned shell "
                    f"interpreter {child_id}. Service processes rarely launch "
                    "interactive shells; this is a common execution primitive."
                ),
                finding_type="behavior",
                severity="high",
                category=FindingCategory.EXECUTION,
                evidence={
                    "parent": parent_id,
                    "child": child_id,
                    "mitre": "T1059",
                },
                reasoning_chain=[
                    f"{parent_id} is a service/system-tier parent.",
                    f"It SPAWNED shell interpreter {child_id}.",
                    "Service-to-shell spawns are a living-off-the-land execution pattern (MITRE T1059).",
                ],
                artifact_sources=[parent_id, child_id],
            )
        )

    return findings


def _is_service_parent(graph: nx.MultiDiGraph, node: tuple[str, str]) -> bool:
    """Return True if ``node`` is a service/system-tier process.

    Recognized either by an explicit ``role`` of ``service``/``system`` or by a
    well-known service/init binary name.

    Args:
        graph: The correlation graph.
        node: The parent ``(kind, id)`` node key.

    Returns:
        Whether the node qualifies as a service/system parent.
    """
    data = graph.nodes[node]
    if data.get("role") in {"service", "system"}:
        return True
    return node[1] in _SERVICE_NAMES


def query(
    graph: nx.MultiDiGraph, node_kind: str, rel: str
) -> list[tuple[tuple[str, str], tuple[str, str]]]:
    """Read-only traversal: edges of ``rel`` leaving nodes of ``node_kind``.

    Args:
        graph: A correlation graph from :func:`build_graph`.
        node_kind: The source node kind to filter on.
        rel: The relation to match; must be in :data:`KNOWN_RELATIONS`.

    Returns:
        ``(src_node, dst_node)`` pairs (each a ``(kind, id)`` tuple) for every
        matching edge. The graph is never modified.

    Raises:
        ValueError: If ``rel`` is not a recognized relation.
    """
    if rel not in KNOWN_RELATIONS:
        raise ValueError(f"Unknown relation: {rel!r}")

    results: list[tuple[tuple[str, str], tuple[str, str]]] = []
    for src, dst, data in graph.edges(data=True):
        if src[0] == node_kind and data.get("rel") == rel:
            results.append((src, dst))
    return results
