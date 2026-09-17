"""Tests for nexus_pipeline.containment.secrets (spec section 6 defense-in-depth).

assert_no_secrets is the labeled best-effort backstop; the primary control
is by-construction (never pass env into a prompt/log/audit builder). These
tests cover: the live oauth token leaking into text, no false positive when
it is unset, known secret patterns, scrub's redaction, and ordinary text
passing clean.
"""

import pytest

from nexus_pipeline.containment import secrets


def test_live_oauth_token_in_text_raises(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "TESTTOKENVALUE1234567890ABCDEF")

    with pytest.raises(secrets.SecretLeak):
        secrets.assert_no_secrets(
            "here is a log line: TESTTOKENVALUE1234567890ABCDEF end"
        )


def test_token_unset_no_false_positive_on_ordinary_text(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    secrets.assert_no_secrets(
        "a perfectly ordinary log line about gate results"
    )  # no raise


def test_bearer_token_pattern_detected(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    with pytest.raises(secrets.SecretLeak):
        secrets.assert_no_secrets("Authorization: Bearer abc123.def456-ghi789")


def test_openai_style_sk_key_pattern_detected(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    with pytest.raises(secrets.SecretLeak):
        secrets.assert_no_secrets("leaked key sk-abcdefghijklmnopqrstuvwxyz123456")


def test_pem_private_key_header_detected(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    with pytest.raises(secrets.SecretLeak):
        secrets.assert_no_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n")


def test_dotenv_style_secret_key_value_detected(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    with pytest.raises(secrets.SecretLeak):
        secrets.assert_no_secrets("API_SECRET_KEY=abcdef0123456789")


@pytest.mark.parametrize(
    "benign_line",
    [
        "MAX_TOKEN_LENGTH=50",
        "TOKEN_EXPIRY_SECONDS=3600",
        "PASSWORD_MIN_LENGTH=8",
        "API_KEY_HEADER_NAME=X-Api-Key",
        "RETRY_TOKEN_BUDGET=5",
        "SECRET_SAUCE_RECIPE=grandmas",
    ],
)
def test_dotenv_pattern_no_false_positive_on_ordinary_constants(
    monkeypatch, benign_line
):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    secrets.assert_no_secrets(benign_line)  # must not raise


def test_ordinary_text_passes_clean(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    secrets.assert_no_secrets(
        "Gate B: pytest -q --cov=sift_find_evil passed at 98.07%."
    )


def test_scrub_redacts_pattern_matches():
    scrubbed = secrets.scrub("Authorization: Bearer abc123.def456-ghi789 end of line")

    assert "abc123.def456-ghi789" not in scrubbed
    assert "***REDACTED***" in scrubbed
    assert "end of line" in scrubbed


def test_scrub_leaves_ordinary_text_untouched():
    text = "Gate C: F1=1.00, 0 FP, 0 FN"

    assert secrets.scrub(text) == text


def test_contains_live_token_true_when_present(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "LIVE-TOKEN-VALUE-XYZ")

    assert (
        secrets.contains_live_token("command included LIVE-TOKEN-VALUE-XYZ here")
        is True
    )


def test_contains_live_token_false_when_unset(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    assert secrets.contains_live_token("anything at all") is False


def test_contains_live_token_false_when_absent_from_text(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "LIVE-TOKEN-VALUE-XYZ")

    assert secrets.contains_live_token("this text does not mention it") is False
