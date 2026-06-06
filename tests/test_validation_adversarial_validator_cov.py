"""Coverage tests for adversarial_validator error/branch paths.

Targets previously-uncovered lines:
- 213,214: timestamp-parse failure in _check_reasoning_logic (except: pass)
- 300:     strptime fallback success in _check_temporal_consistency
- 343,344: invalid MD5 format branch in _check_hash_format
"""

from sift_find_evil.validation import AdversarialValidator


class MockFinding:
    """Lightweight finding stand-in (duck-typed via getattr/hasattr)."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_reasoning_logic_swallows_bad_iso_timestamp():
    """Unparseable ISO timestamps hit the except branch and yield no issue.

    Both file_modified and email_sent are present (so the parse block runs),
    but the strings are not valid ISO, so datetime.fromisoformat raises
    ValueError and the except (ValueError, AttributeError): pass executes.
    """
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Bad timestamp exfil",
        category="data_exfiltration",
        evidence={
            "file_modified": "not-a-timestamp",
            "email_sent": "also-not-a-timestamp",
        },
    )

    check = validator._check_reasoning_logic(finding)
    # Parsing failed silently -> no causality issue raised
    assert check.passed
    assert check.issues == []


def test_reasoning_logic_swallows_non_string_timestamp():
    """Non-string timestamp triggers AttributeError on .replace, swallowed.

    A non-string value is truthy (so it passes the `if file_time_str and
    email_time_str` guard) but calling .replace on it raises AttributeError,
    exercising the same except branch.
    """
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Non-string timestamp exfil",
        category="data_exfiltration",
        evidence={
            "file_modified": 1234567890,  # int -> no .replace
            "email_sent": "2009-12-11T01:28:00+00:00",
        },
    )

    check = validator._check_reasoning_logic(finding)
    assert check.passed
    assert check.issues == []


def test_temporal_consistency_strptime_fallback_via_monkeypatch(monkeypatch):
    """fromisoformat raises but strptime fallback succeeds -> hits line 300.

    Modern fromisoformat is lenient, so to force the documented fallback
    path we patch the module-level datetime so fromisoformat always raises
    while strptime delegates to the real implementation. The value matches
    '%Y-%m-%dT%H:%M:%S', so the timestamp is appended via the fallback.
    """
    import sift_find_evil.validation.adversarial_validator as mod

    real_datetime = mod.datetime
    val = "2022-06-06T12:00:00"

    class FakeDateTime:
        @staticmethod
        def fromisoformat(s):
            raise ValueError("forced iso failure")

        @staticmethod
        def strptime(s, fmt):
            return real_datetime.strptime(s, fmt)

    monkeypatch.setattr(mod, "datetime", FakeDateTime)

    finding = MockFinding(
        title="strptime fallback",
        evidence={"file_time": val},
    )
    check = AdversarialValidator()._check_temporal_consistency(finding)
    # Single naive timestamp parsed via fallback -> no mixed-tz issue
    assert check.passed
    assert check.issues == []


def test_hash_format_invalid_md5():
    """MD5 with wrong length/chars hits the invalid-MD5 branch (343,344)."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="bad md5",
        evidence={"file_md5": "deadbeef"},  # only 8 chars, not 32
    )

    check = validator._check_hash_format(finding)
    assert not check.passed
    assert "Invalid MD5 format" in check.issues[0]
    assert "expected 32 lowercase hex characters" in check.issues[0]


def test_hash_format_valid_md5_passes():
    """A correct 32-hex MD5 produces no issue (guards against false positive)."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="good md5",
        evidence={"file_md5": "0" * 32},
    )

    check = validator._check_hash_format(finding)
    assert check.passed
