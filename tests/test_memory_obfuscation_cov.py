"""Coverage tests for sift_find_evil.memory.obfuscation private helpers.

These exercise the decode/guard branches that the public
``analyze_cmdline_obfuscation`` entrypoint cannot reach because its regex
gate (``_ENCODED_COMMAND_RE``) only forwards 16+ char valid-base64
candidates. We call the module-level helpers directly to drive the
defensive guards.
"""

from unittest.mock import patch

import sift_find_evil.memory.obfuscation as obf
from sift_find_evil.memory.obfuscation import (
    _looks_like_text,
    _try_decode_powershell_encoded,
)


def test_decode_returns_none_when_too_short_after_strip():
    """Candidate shorter than 16 chars after stripping wrappers -> None (line 220).

    The leading/trailing quotes are stripped, leaving fewer than 16
    characters, so the length guard short-circuits before any decode.
    """
    # 8 chars inside quotes -> after strip("\"'") it is 8 chars < 16.
    assert _try_decode_powershell_encoded("'abcdefgh'") is None


def test_decode_returns_none_on_invalid_base64_structure():
    """16+ char candidate that fails strict base64 -> None (lines 226-227).

    Discontinuous padding makes base64.b64decode(validate=True) raise
    binascii.Error, which the except clause swallows into None.
    """
    # 17 chars, valid alphabet, but '=' mid-string -> discontinuous padding.
    result = _try_decode_powershell_encoded("AAAA=AAAAAAAAAAAA")
    assert result is None


def test_decode_returns_none_when_decoded_bytes_empty():
    """Empty decoded bytes -> None (line 229).

    A 16+ char candidate passes the length guard, but if b64decode yields
    empty bytes the 'if not raw' guard returns None. Real base64 of that
    length never decodes to empty, so we patch b64decode to force the path.
    """
    with patch.object(obf.base64, "b64decode", return_value=b""):
        assert _try_decode_powershell_encoded("AAAAAAAAAAAAAAAA") is None


def test_looks_like_text_empty_string_returns_false():
    """Empty string is not text (line 257)."""
    assert _looks_like_text("") is False


def test_looks_like_text_printable_returns_true():
    """Mostly-printable string is treated as text (sanity for the guard)."""
    assert _looks_like_text("hello world") is True


def test_decode_falls_back_to_utf8_when_utf16_not_text():
    """UTF-16LE decode yields non-text -> UTF-8 fallback succeeds (line 241-242).

    Odd-length raw bytes make UTF-16LE decode raise (handled earlier), but
    here we craft bytes whose UTF-16LE reading fails the text heuristic so
    execution flows into the UTF-8 fallback branch and returns readable text.
    """
    # 'hello world test' is valid ASCII -> UTF-8 path returns it as text
    # when the UTF-16LE attempt is forced to look non-textual.
    import base64

    raw = b"hello world test"  # 16 bytes
    candidate = base64.b64encode(raw).decode("ascii")
    decoded = _try_decode_powershell_encoded(candidate)
    assert decoded is not None
    assert "hello" in decoded
