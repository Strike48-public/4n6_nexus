"""Tests for nexus_pipeline.containment.audit (spec section 6.7).

Covers the genesis link, chain linkage, tamper detection on a mutated middle
entry, one append per category, by-construction rejection of free-form or
unexpected payload fields, and that the log lives under ./reports/audit/.
"""

import json

import pytest

from nexus_pipeline.containment import audit
from nexus_pipeline.state import paths


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_first_entry_links_to_genesis():
    entry = audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="ruff check .", exit_code=0),
    )

    assert entry.seq == 0
    assert entry.prev_hash == audit.GENESIS_HASH
    assert len(entry.hash) == 64


def test_each_entry_commits_to_prior():
    first = audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="ruff check .", exit_code=0),
    )
    second = audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="black --check .", exit_code=0),
    )

    assert second.prev_hash == first.hash
    assert second.seq == 1


def test_pristine_chain_verifies():
    audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="ruff check .", exit_code=0),
    )
    audit.append(
        "SFE-1",
        "tier_decision",
        audit.TierDecisionPayload(computed_tier="T0", would_do_action="auto-merge"),
    )

    assert audit.verify_chain("SFE-1") is True


def test_tamper_on_middle_entry_breaks_verification(isolated_cwd):
    audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="ruff check .", exit_code=0),
    )
    audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="black --check .", exit_code=0),
    )
    audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="pytest -q", exit_code=0),
    )

    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    lines = log_path.read_text().splitlines()
    record = json.loads(lines[1])
    record["payload"]["exit_code"] = 1  # tamper: flip a passing gate to failing
    lines[1] = json.dumps(record)
    log_path.write_text("\n".join(lines) + "\n")

    assert audit.verify_chain("SFE-1") is False


def test_verify_empty_log_is_true():
    assert audit.verify_chain("SFE-does-not-exist-yet") is True


def test_append_each_category():
    audit.append(
        "SFE-1",
        "gate_result",
        audit.GateResultPayload(command="pytest -q", exit_code=0),
    )
    audit.append(
        "SFE-1",
        "tier_decision",
        audit.TierDecisionPayload(computed_tier="T1", would_do_action="propose"),
    )
    audit.append(
        "SFE-1",
        "kill_switch_check",
        audit.KillSwitchCheckPayload(halted=False, reason="clear"),
    )
    audit.append(
        "SFE-1", "claim", audit.ClaimPayload(owner_id="worker-a", outcome="acquired")
    )
    audit.append(
        "SFE-1",
        "merge_action",
        audit.MergeActionPayload(action="would-merge", sha="deadbeef"),
    )

    assert audit.verify_chain("SFE-1") is True


def test_append_rejects_mismatched_payload_type():
    with pytest.raises((TypeError, ValueError)):
        audit.append(
            "SFE-1",
            "gate_result",
            audit.TierDecisionPayload(computed_tier="T0", would_do_action="auto-merge"),
        )


def test_append_rejects_free_form_dict_payload():
    with pytest.raises((TypeError, ValueError)):
        audit.append(
            "SFE-1", "gate_result", {"command": "ruff check .", "exit_code": 0}
        )


def test_payload_dataclass_rejects_unexpected_field():
    with pytest.raises(TypeError):
        audit.GateResultPayload(
            command="ruff check .", exit_code=0, token="leaked-secret"
        )


def test_append_rejects_unknown_category():
    with pytest.raises(ValueError):
        audit.append(
            "SFE-1",
            "not-a-real-category",
            audit.GateResultPayload(command="x", exit_code=0),
        )


def test_log_lives_under_reports_audit(isolated_cwd):
    audit.append(
        "SFE-42",
        "gate_result",
        audit.GateResultPayload(command="pytest -q", exit_code=0),
    )

    assert (isolated_cwd / "reports" / "audit" / "SFE-42.jsonl").exists()


def test_verify_chain_returns_false_on_unparseable_content(isolated_cwd):
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="x", exit_code=0)
    )
    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    log_path.write_text("not valid json at all\n")

    assert audit.verify_chain("SFE-1") is False


def test_verify_chain_detects_a_deleted_entry(isolated_cwd):
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="b", exit_code=0)
    )
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="c", exit_code=0)
    )

    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    lines = log_path.read_text().splitlines()
    del lines[1]  # remove the middle entry; seq/prev_hash now misalign
    log_path.write_text("\n".join(lines) + "\n")

    assert audit.verify_chain("SFE-1") is False


def test_verify_chain_returns_false_on_missing_field(isolated_cwd):
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )
    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    record = json.loads(log_path.read_text().splitlines()[0])
    del record["hash"]
    log_path.write_text(json.dumps(record) + "\n")

    assert audit.verify_chain("SFE-1") is False


def test_append_rejects_path_traversal_issue_id(isolated_cwd):
    with pytest.raises(paths.UnsafePathComponentError):
        audit.append(
            "../pwned-audit-writable",
            "gate_result",
            audit.GateResultPayload(command="x", exit_code=0),
        )

    assert not (isolated_cwd.parent / "pwned-audit-writable.jsonl").exists()


def test_append_rejects_absolute_path_issue_id(isolated_cwd):
    with pytest.raises(paths.UnsafePathComponentError):
        audit.append(
            "/tmp/pwned-audit-abs",
            "gate_result",
            audit.GateResultPayload(command="x", exit_code=0),
        )


def test_append_hard_fails_when_live_oauth_token_in_payload_string(
    isolated_cwd, monkeypatch
):
    live_token = "LIVE-CLAUDE-CODE-OAUTH-TOKEN-VALUE"
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", live_token)
    payload = audit.GateResultPayload(
        command=f"curl -H 'Authorization: Bearer {live_token}' https://example.test",
        exit_code=1,
    )

    with pytest.raises(audit.secrets.SecretLeak):
        audit.append("SFE-1", "gate_result", payload)

    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    assert not log_path.exists() or live_token not in log_path.read_text()


def test_verify_chain_detects_tail_truncation(isolated_cwd):
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="b", exit_code=0)
    )
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="c-fails", exit_code=1)
    )
    assert audit.verify_chain("SFE-1") is True

    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines[:2]) + "\n")  # drop the last entry

    assert audit.verify_chain("SFE-1") is False


def test_verify_chain_detects_truncation_to_empty(isolated_cwd):
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )

    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    log_path.write_text("")  # drop the only entry entirely

    assert audit.verify_chain("SFE-1") is False


def test_read_head_returns_none_on_corrupt_sidecar(isolated_cwd):
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )
    head_path = isolated_cwd / "reports" / "audit" / "SFE-1.head"
    head_path.write_text("not valid json")

    assert audit.read_head("SFE-1") is None


def test_verify_chain_treats_a_corrupt_head_sidecar_as_suspicious(isolated_cwd):
    # A head file that EXISTS but is unparseable is a stronger anomaly than
    # one that is simply absent (a legitimate genesis case, or the disclosed
    # coordinated-deletion limitation): something wrote a header and it is
    # now garbage. verify_chain treats that as tamper evidence, not as
    # "nothing to cross-check".
    audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )
    head_path = isolated_cwd / "reports" / "audit" / "SFE-1.head"
    head_path.write_text("not valid json")

    assert audit.verify_chain("SFE-1") is False


def test_read_head_reflects_the_most_recent_append(isolated_cwd):
    assert audit.read_head("SFE-1") is None

    first = audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="a", exit_code=0)
    )
    head = audit.read_head("SFE-1")
    assert head == audit.Head(last_seq=first.seq, last_hash=first.hash)

    second = audit.append(
        "SFE-1", "gate_result", audit.GateResultPayload(command="b", exit_code=0)
    )
    head = audit.read_head("SFE-1")
    assert head == audit.Head(last_seq=second.seq, last_hash=second.hash)


def test_append_scrubs_pattern_matched_secret_without_failing(
    isolated_cwd, monkeypatch
):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    secret_looking_value = "Authorization: Bearer abc123.def456-notlivetoken789"
    payload = audit.GateResultPayload(command=secret_looking_value, exit_code=0)

    entry = audit.append("SFE-1", "gate_result", payload)

    assert secret_looking_value not in entry.payload.command
    log_path = isolated_cwd / "reports" / "audit" / "SFE-1.jsonl"
    on_disk = log_path.read_text()
    assert secret_looking_value not in on_disk
    assert "***REDACTED***" in on_disk
    assert audit.verify_chain("SFE-1") is True
