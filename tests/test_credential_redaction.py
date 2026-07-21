"""Tests for correlation-preserving credential redaction.

Validates that ``redact_tree`` scrubs credential material from arbitrary
dict/list/scalar trees while preserving correlation via HMAC-tagged
placeholders, and that its hard guards (depth, size, ReDoS, key length,
fail-closed) behave as specified.
"""

import pytest

from sift_find_evil.security.redact import (
    RedactionError,
    redact_tree,
)

KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes


def test_same_secret_yields_same_tag() -> None:
    # Arrange
    secret = "AKIAIOSFODNN7EXAMPLE"
    tree = {"a": secret, "b": secret}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert result["a"] == result["b"]
    assert result["a"].startswith("[REDACTED:")
    assert secret not in result["a"]


def test_different_secrets_yield_different_tags() -> None:
    # Arrange
    tree = {"a": "AKIAIOSFODNN7EXAMPLE", "b": "AKIAABCDEFGHIJKLMNOP"}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert result["a"] != result["b"]
    assert result["a"].startswith("[REDACTED:")
    assert result["b"].startswith("[REDACTED:")


def test_oversize_value_gets_oversize_tag_without_regex() -> None:
    # Arrange
    big = "x" * 70_000  # exceeds MAX_REGEX_INPUT_BYTES (65536)
    tree = {"blob": big}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert result["blob"] == "[REDACTED:OVERSIZE]"


def test_nested_dict_and_list_are_redacted() -> None:
    # Arrange
    tree = {
        "outer": {
            "creds": ["password=hunter2secret", "safe text"],
            "token": "Bearer abcdefghijklmnopqrstuvwxyz012345",
        }
    }

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert "hunter2secret" not in str(result)
    assert "[REDACTED:" in result["outer"]["creds"][0]
    assert result["outer"]["creds"][1] == "safe text"
    assert "[REDACTED:" in result["outer"]["token"]


def test_short_key_raises_value_error() -> None:
    # Arrange
    short_key = b"tooshort"

    # Act / Assert
    with pytest.raises(ValueError):
        redact_tree({"a": "AKIAIOSFODNN7EXAMPLE"}, key=short_key)


def test_non_secret_text_passes_unchanged() -> None:
    # Arrange
    tree = {"msg": "the quick brown fox", "n": 42, "flag": True, "nil": None}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert result == tree


def test_input_tree_is_not_mutated() -> None:
    # Arrange
    tree = {"a": "AKIAIOSFODNN7EXAMPLE", "nested": {"b": ["password=abcdefgh"]}}
    original = {"a": "AKIAIOSFODNN7EXAMPLE", "nested": {"b": ["password=abcdefgh"]}}

    # Act
    redact_tree(tree, key=KEY)

    # Assert
    assert tree == original


def test_exceeding_max_depth_raises_redaction_error() -> None:
    # Arrange: build a tree deeper than MAX_DEPTH (32)
    node: dict = {"secret": "AKIAIOSFODNN7EXAMPLE"}
    for _ in range(40):
        node = {"child": node}

    # Act / Assert
    with pytest.raises(RedactionError):
        redact_tree(node, key=KEY)


def test_pem_private_key_header_redacted() -> None:
    # Arrange
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\n-----END RSA PRIVATE KEY-----"
    tree = {"key": pem}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert "BEGIN RSA PRIVATE KEY" not in result["key"]
    assert "[REDACTED:" in result["key"]


def test_hex_secret_redacted() -> None:
    # Arrange
    tree = {"h": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert "deadbeef" not in result["h"]
    assert "[REDACTED:" in result["h"]


def test_api_key_assignment_redacted() -> None:
    # Arrange
    tree = {"cfg": "api_key=SUPERSECRETVALUE12345"}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert
    assert "SUPERSECRETVALUE12345" not in result["cfg"]
    assert "[REDACTED:" in result["cfg"]


def test_string_exceeding_max_value_bytes_gets_oversize_tag() -> None:
    # Arrange - a scalar string larger than MAX_VALUE_BYTES (1,000,000). This
    # is a distinct guard from the regex-input cap: it short-circuits in
    # _redact_node before _redact_string is ever called.
    huge = "y" * 1_000_001
    tree = {"blob": huge}

    # Act
    result = redact_tree(tree, key=KEY)

    # Assert - node-level oversize guard fires (redact.py line 109)
    assert result["blob"] == "[REDACTED:OVERSIZE]"


def test_unexpected_error_is_wrapped_as_redaction_error() -> None:
    # Arrange - a dict subclass whose .items() raises a generic error while
    # recursing. The fail-closed handler must convert any non-RedactionError
    # into a RedactionError so unredacted output can never leak.
    class ExplodingDict(dict):
        def items(self):
            raise RuntimeError("boom during traversal")

    tree = ExplodingDict()
    tree["secret"] = "AKIAIOSFODNN7EXAMPLE"

    # Act / Assert - generic exception wrapped fail-closed (redact.py 143-144)
    with pytest.raises(RedactionError):
        redact_tree(tree, key=KEY)
