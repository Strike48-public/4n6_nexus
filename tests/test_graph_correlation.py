"""Tests for cross-artifact/cross-host graph correlation.

Validates the read-only correlation graph built with networkx and the safe
query helpers layered on top of it. Fixtures are inline and synthetic; every
positive assertion is paired with an inverse control so a detector that fires
on everything cannot pass.
"""

from __future__ import annotations

import networkx as nx
import pytest

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.graph import (
    build_graph,
    lateral_tool_reuse,
    query,
    suspicious_ancestry,
)


# ---------------------------------------------------------------------------
# build_graph
# ---------------------------------------------------------------------------


def test_build_graph_merges_nodes_by_kind_and_id() -> None:
    """Nodes with the same (kind, id) collapse to a single graph node."""
    # Arrange: the same process referenced twice, on two hosts.
    events = [
        {"kind": "process", "id": "psexec.exe", "host": "h1"},
        {"kind": "process", "id": "psexec.exe", "host": "h2"},
    ]

    # Act
    graph = build_graph(events)

    # Assert: one merged node, not two.
    assert graph.number_of_nodes() == 1
    assert ("process", "psexec.exe") in graph.nodes


def test_build_graph_records_node_attrs_and_hosts() -> None:
    """Node attributes are merged and every host is accumulated."""
    # Arrange
    events = [
        {"kind": "process", "id": "p", "host": "h1", "pid": 4},
        {"kind": "process", "id": "p", "host": "h2", "user": "svc"},
    ]

    # Act
    graph = build_graph(events)
    node = graph.nodes[("process", "p")]

    # Assert
    assert node["kind"] == "process"
    assert node["id"] == "p"
    assert node["hosts"] == {"h1", "h2"}
    assert node["pid"] == 4
    assert node["user"] == "svc"


def test_build_graph_adds_typed_edges() -> None:
    """Edge events create typed directed edges between merged endpoints."""
    # Arrange
    events = [
        {"kind": "process", "id": "svc", "host": "h1"},
        {"kind": "process", "id": "cmd.exe", "host": "h1"},
        {"edge": "SPAWNED", "src": "svc", "dst": "cmd.exe", "host": "h1"},
    ]

    # Act
    graph = build_graph(events)

    # Assert
    assert graph.has_edge(("process", "svc"), ("process", "cmd.exe"))
    rels = {d["rel"] for _, _, d in graph.edges(data=True)}
    assert rels == {"SPAWNED"}


def test_build_graph_edge_creates_missing_endpoints() -> None:
    """An edge referencing an unseen id auto-creates a placeholder node."""
    # Arrange: no node events, only an edge.
    events = [{"edge": "RAN_ON", "src": "tool.exe", "dst": "host7", "host": "host7"}]

    # Act
    graph = build_graph(events)

    # Assert: both endpoints exist as unknown-kind placeholders.
    assert graph.has_edge(("unknown", "tool.exe"), ("unknown", "host7"))


def test_build_graph_is_idempotent() -> None:
    """Rebuilding from the same events yields an isomorphic graph (MERGE)."""
    # Arrange
    events = [
        {"kind": "process", "id": "p", "host": "h1"},
        {"kind": "host", "id": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "p", "dst": "h1", "host": "h1"},
        {"kind": "process", "id": "p", "host": "h1"},
        {"edge": "RAN_ON", "src": "p", "dst": "h1", "host": "h1"},
    ]

    # Act
    g1 = build_graph(events)
    g2 = build_graph(events)

    # Assert: duplicate node/edge events do not multiply nodes or parallel edges.
    assert g1.number_of_nodes() == g2.number_of_nodes() == 2
    assert g1.number_of_edges() == g2.number_of_edges() == 1


def test_build_graph_ignores_unknown_edge_rel() -> None:
    """An edge with an unrecognized rel is skipped, not added."""
    # Arrange
    events = [
        {"kind": "process", "id": "a", "host": "h1"},
        {"kind": "process", "id": "b", "host": "h1"},
        {"edge": "TELEPATHY", "src": "a", "dst": "b", "host": "h1"},
    ]

    # Act
    graph = build_graph(events)

    # Assert: nodes exist but the bogus edge does not.
    assert graph.number_of_edges() == 0


def test_build_graph_ignores_unknown_node_kind() -> None:
    """A node event with an unrecognized kind is skipped."""
    # Arrange
    events = [{"kind": "planet", "id": "mars", "host": "h1"}]

    # Act
    graph = build_graph(events)

    # Assert
    assert graph.number_of_nodes() == 0


def test_build_graph_skips_malformed_events() -> None:
    """Events missing required keys are skipped without raising."""
    # Arrange: node without id, edge without dst, and a non-dict.
    events = [
        {"kind": "process", "host": "h1"},
        {"edge": "SPAWNED", "src": "a", "host": "h1"},
        "not-a-dict",
    ]

    # Act
    graph = build_graph(events)

    # Assert
    assert graph.number_of_nodes() == 0
    assert graph.number_of_edges() == 0


def test_build_graph_returns_multidigraph() -> None:
    """The returned object is a networkx MultiDiGraph."""
    # Arrange / Act
    graph = build_graph([])

    # Assert
    assert isinstance(graph, nx.MultiDiGraph)


def test_build_graph_does_not_mutate_input_events() -> None:
    """Input event dicts are never mutated by the builder."""
    # Arrange
    event = {"kind": "process", "id": "p", "host": "h1", "pid": 9}
    snapshot = dict(event)

    # Act
    build_graph([event])

    # Assert
    assert event == snapshot


# ---------------------------------------------------------------------------
# lateral_tool_reuse
# ---------------------------------------------------------------------------


def test_lateral_tool_reuse_flags_denylisted_multi_host_binary() -> None:
    """A denylisted binary run on >1 host produces a LATERAL_MOVEMENT finding."""
    # Arrange
    events = [
        {"kind": "process", "id": "psexec.exe", "host": "h1"},
        {"kind": "host", "id": "h1", "host": "h1"},
        {"kind": "host", "id": "h2", "host": "h2"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h2", "host": "h2"},
    ]
    graph = build_graph(events)

    # Act
    findings = lateral_tool_reuse(graph, {"psexec.exe"})

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.category == FindingCategory.LATERAL_MOVEMENT
    assert finding.evidence["mitre"] == "T1021"
    assert finding.evidence["binary"] == "psexec.exe"
    assert set(finding.evidence["hosts"]) == {"h1", "h2"}
    assert finding.reasoning_chain  # non-empty "why"
    assert "psexec.exe" in finding.artifact_sources


def test_lateral_tool_reuse_single_host_not_flagged() -> None:
    """A denylisted binary on a single host is not lateral movement (inverse)."""
    # Arrange
    events = [
        {"kind": "process", "id": "psexec.exe", "host": "h1"},
        {"kind": "host", "id": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = lateral_tool_reuse(graph, {"psexec.exe"})

    # Assert
    assert findings == []


def test_lateral_tool_reuse_multi_host_but_not_denylisted() -> None:
    """A multi-host binary absent from the denylist is not flagged (inverse)."""
    # Arrange
    events = [
        {"kind": "process", "id": "backup.exe", "host": "h1"},
        {"edge": "RAN_ON", "src": "backup.exe", "dst": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "backup.exe", "dst": "h2", "host": "h2"},
    ]
    graph = build_graph(events)

    # Act
    findings = lateral_tool_reuse(graph, {"psexec.exe"})

    # Assert
    assert findings == []


def test_lateral_tool_reuse_ignores_non_process_ran_on() -> None:
    """A RAN_ON edge whose source is not a process is ignored."""
    # Arrange: a file node "ran on" two hosts should not count.
    events = [
        {"kind": "file", "id": "psexec.exe", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h2", "host": "h2"},
    ]
    # Rebuild so the psexec.exe node is kind=file, not process.
    graph = build_graph(events)

    # Act
    findings = lateral_tool_reuse(graph, {"psexec.exe"})

    # Assert
    assert findings == []


def test_lateral_tool_reuse_distinct_hosts_only() -> None:
    """Repeated RAN_ON to the same host counts as one host, not lateral."""
    # Arrange
    events = [
        {"kind": "process", "id": "psexec.exe", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = lateral_tool_reuse(graph, {"psexec.exe"})

    # Assert
    assert findings == []


# ---------------------------------------------------------------------------
# suspicious_ancestry
# ---------------------------------------------------------------------------


def test_suspicious_ancestry_service_spawns_powershell_flagged() -> None:
    """A service/system parent spawning a shell yields an EXECUTION finding."""
    # Arrange
    events = [
        {"kind": "process", "id": "services.exe", "host": "h1", "role": "service"},
        {"kind": "process", "id": "powershell.exe", "host": "h1"},
        {
            "edge": "SPAWNED",
            "src": "services.exe",
            "dst": "powershell.exe",
            "host": "h1",
        },
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.EXECUTION
    assert finding.evidence["parent"] == "services.exe"
    assert finding.evidence["child"] == "powershell.exe"
    assert finding.reasoning_chain


def test_suspicious_ancestry_benign_chain_not_flagged() -> None:
    """explorer.exe spawning notepad.exe is benign and not flagged (inverse)."""
    # Arrange
    events = [
        {"kind": "process", "id": "explorer.exe", "host": "h1"},
        {"kind": "process", "id": "notepad.exe", "host": "h1"},
        {"edge": "SPAWNED", "src": "explorer.exe", "dst": "notepad.exe", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert findings == []


def test_suspicious_ancestry_service_parent_non_shell_child_not_flagged() -> None:
    """A service parent spawning a non-shell child is not flagged (inverse)."""
    # Arrange
    events = [
        {"kind": "process", "id": "svchost.exe", "host": "h1", "role": "system"},
        {"kind": "process", "id": "notepad.exe", "host": "h1"},
        {"edge": "SPAWNED", "src": "svchost.exe", "dst": "notepad.exe", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert findings == []


def test_suspicious_ancestry_matches_shell_by_name_when_role_absent() -> None:
    """A known service binary name counts as a service parent without a role."""
    # Arrange: no explicit role; services.exe recognized by name.
    events = [
        {"kind": "process", "id": "services.exe", "host": "h1"},
        {"kind": "process", "id": "cmd.exe", "host": "h1"},
        {"edge": "SPAWNED", "src": "services.exe", "dst": "cmd.exe", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert len(findings) == 1
    assert findings[0].evidence["child"] == "cmd.exe"


def test_suspicious_ancestry_bash_child_flagged() -> None:
    """bash is treated as a shell child too."""
    # Arrange
    events = [
        {"kind": "process", "id": "systemd", "host": "h1", "role": "system"},
        {"kind": "process", "id": "bash", "host": "h1"},
        {"edge": "SPAWNED", "src": "systemd", "dst": "bash", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert len(findings) == 1
    assert findings[0].evidence["child"] == "bash"


def test_suspicious_ancestry_ignores_non_spawned_edges() -> None:
    """A shell reached via a non-SPAWNED edge is not ancestry (inverse)."""
    # Arrange
    events = [
        {"kind": "process", "id": "services.exe", "host": "h1", "role": "service"},
        {"kind": "process", "id": "cmd.exe", "host": "h1"},
        {"edge": "CONNECTED_TO", "src": "services.exe", "dst": "cmd.exe", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert findings == []


def test_suspicious_ancestry_non_process_parent_not_flagged() -> None:
    """A non-process parent spawning a shell is skipped."""
    # Arrange: a user node "spawns" a shell (nonsensical); must be ignored.
    events = [
        {"kind": "user", "id": "services.exe", "host": "h1", "role": "service"},
        {"kind": "process", "id": "cmd.exe", "host": "h1"},
        {"edge": "SPAWNED", "src": "services.exe", "dst": "cmd.exe", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    findings = suspicious_ancestry(graph)

    # Assert
    assert findings == []


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


def test_query_returns_matching_relation_edges() -> None:
    """query returns (src, dst) pairs for nodes of a kind with a given rel."""
    # Arrange
    events = [
        {"kind": "process", "id": "psexec.exe", "host": "h1"},
        {"kind": "host", "id": "h1", "host": "h1"},
        {"kind": "host", "id": "h2", "host": "h2"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h2", "host": "h2"},
    ]
    graph = build_graph(events)

    # Act
    results = query(graph, "process", "RAN_ON")

    # Assert
    assert (("process", "psexec.exe"), ("host", "h1")) in results
    assert (("process", "psexec.exe"), ("host", "h2")) in results
    assert len(results) == 2


def test_query_filters_by_node_kind() -> None:
    """query only traverses out-edges of nodes matching node_kind (inverse)."""
    # Arrange
    events = [
        {"kind": "file", "id": "psexec.exe", "host": "h1"},
        {"edge": "RAN_ON", "src": "psexec.exe", "dst": "h1", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act: ask for process-kind RAN_ON; the source is a file.
    results = query(graph, "process", "RAN_ON")

    # Assert
    assert results == []


def test_query_filters_by_relation() -> None:
    """query ignores edges whose rel does not match (inverse)."""
    # Arrange
    events = [
        {"kind": "process", "id": "a", "host": "h1"},
        {"kind": "process", "id": "b", "host": "h1"},
        {"edge": "SPAWNED", "src": "a", "dst": "b", "host": "h1"},
    ]
    graph = build_graph(events)

    # Act
    results = query(graph, "process", "RAN_ON")

    # Assert
    assert results == []


def test_query_read_only_does_not_modify_graph() -> None:
    """query never adds or removes nodes/edges."""
    # Arrange
    events = [
        {"kind": "process", "id": "a", "host": "h1"},
        {"edge": "RAN_ON", "src": "a", "dst": "h1", "host": "h1"},
    ]
    graph = build_graph(events)
    before_nodes = graph.number_of_nodes()
    before_edges = graph.number_of_edges()

    # Act
    query(graph, "process", "RAN_ON")

    # Assert
    assert graph.number_of_nodes() == before_nodes
    assert graph.number_of_edges() == before_edges


def test_module_exposes_no_write_api() -> None:
    """The public API is read-only: no mutate/delete helpers are exported."""
    # Arrange
    import sift_find_evil.graph as graph_mod

    # Act
    exported = set(graph_mod.__all__)

    # Assert
    assert exported == {
        "build_graph",
        "lateral_tool_reuse",
        "suspicious_ancestry",
        "query",
    }


def test_query_rejects_unknown_relation() -> None:
    """query raises on a relation outside the known set (fail fast)."""
    # Arrange
    graph = build_graph([])

    # Act / Assert
    with pytest.raises(ValueError):
        query(graph, "process", "TELEPATHY")
