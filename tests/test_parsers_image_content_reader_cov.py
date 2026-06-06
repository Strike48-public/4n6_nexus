"""Coverage-completion tests for image_content_reader.py.

Targets the lines the existing suite leaves uncovered: the install-oriented
ImportError raised by _require_forensic_libs (line 35), and the real EwfImgInfo
adapter methods (__init__ super wiring, close, read, get_size) which the existing
coverage test stubs out by patching the EwfImgInfo class entirely.

These tests drive the genuine code paths: EwfImgInfo wraps a duck-typed handle
(pyewf provides read/seek/close/get_media_size), so a lightweight fake exercises
the adapter without requiring a real E01 image.
"""

from __future__ import annotations

import importlib.util

import pytest

import sift_find_evil.parsers.image_content_reader as icr

# EwfImgInfo subclasses pytsk3.Img_Info (a C extension). Without the native
# forensic libs the class is None and cannot be instantiated. Skip in a core
# (non-forensic) environment, matching the sibling coverage test's guard.
_FORENSIC_AVAILABLE = (
    importlib.util.find_spec("pyewf") is not None
    and importlib.util.find_spec("pytsk3") is not None
)


class _FakeEwfHandle:
    """Duck-typed stand-in for a pyewf handle.

    pytsk3's TSK_IMG_TYPE_EXTERNAL adapter only needs seek/read/close and the
    EwfImgInfo wrapper calls get_media_size for sizing.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self.closed = False
        self.seek_calls: list[int] = []
        self.read_calls: list[int] = []

    def seek(self, offset: int) -> None:
        self.seek_calls.append(offset)
        self._pos = offset

    def read(self, size: int) -> bytes:
        self.read_calls.append(size)
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True

    def get_media_size(self) -> int:
        return len(self._data)


# ---------------------------------------------------------------------------
# _require_forensic_libs() — line 35 raise path
# ---------------------------------------------------------------------------


def test_require_forensic_libs_raises_when_pyewf_missing(monkeypatch):
    """Line 35: ImportError raised with an install-oriented message when pyewf is None."""
    monkeypatch.setattr(icr, "pyewf", None)
    # pytsk3 left intact to prove the `pyewf is None` half of the guard triggers.

    with pytest.raises(ImportError) as exc_info:
        icr._require_forensic_libs()

    msg = str(exc_info.value)
    assert "libewf-python" in msg
    assert "pytsk3" in msg
    assert "requirements-forensic.txt" in msg


def test_require_forensic_libs_raises_when_pytsk3_missing(monkeypatch):
    """Line 35: the `pytsk3 is None` half of the guard also triggers the raise."""
    monkeypatch.setattr(icr, "pytsk3", None)

    with pytest.raises(ImportError, match="native dependencies"):
        icr._require_forensic_libs()


def test_require_forensic_libs_noop_when_both_present():
    """When both libs are present (this environment) the guard returns None."""
    if not _FORENSIC_AVAILABLE:
        pytest.skip("pyewf/pytsk3 not installed — forensic extras")
    assert icr._require_forensic_libs() is None


# ---------------------------------------------------------------------------
# EwfImgInfo adapter — lines 58, 59, 63, 75, 76, 84
# ---------------------------------------------------------------------------

pytestmark_forensic = pytest.mark.skipif(
    not _FORENSIC_AVAILABLE,
    reason="pyewf/pytsk3 not installed — EwfImgInfo subclasses pytsk3.Img_Info",
)


@pytestmark_forensic
def test_ewf_img_info_init_stores_handle_and_wires_super():
    """Lines 58-59: __init__ stores the handle and chains pytsk3.Img_Info.__init__."""
    handle = _FakeEwfHandle(b"\x00" * 64)

    img = icr.EwfImgInfo(handle)

    # Line 58: handle stored on the adapter.
    assert img._ewf_handle is handle
    # Line 59 super().__init__ wired the external image type; get_size proves the
    # C base accepted the construction and delegates back into our override.
    assert img.get_size() == 64


@pytestmark_forensic
def test_ewf_img_info_read_seeks_then_reads():
    """Lines 75-76: read() seeks to offset then reads size bytes from the handle."""
    payload = bytes(range(32))  # 0x00..0x1f
    handle = _FakeEwfHandle(payload)

    img = icr.EwfImgInfo(handle)
    result = img.read(8, 4)

    assert result == payload[8:12]
    # Line 75: seek(offset) was issued with the requested offset.
    assert handle.seek_calls[-1] == 8
    # Line 76: read(size) was issued with the requested size.
    assert handle.read_calls[-1] == 4


@pytestmark_forensic
def test_ewf_img_info_get_size_delegates_to_media_size():
    """Line 84: get_size() returns the handle's media size."""
    handle = _FakeEwfHandle(b"A" * 12345)

    img = icr.EwfImgInfo(handle)

    assert img.get_size() == 12345


@pytestmark_forensic
def test_ewf_img_info_close_closes_handle():
    """Line 63: close() closes the underlying EWF handle."""
    handle = _FakeEwfHandle(b"\x00" * 16)

    img = icr.EwfImgInfo(handle)
    assert handle.closed is False

    img.close()

    assert handle.closed is True
