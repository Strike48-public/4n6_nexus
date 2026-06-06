"""Coverage-focused tests for sift_find_evil.carving.nsrl_filter.

Targets the lines not exercised by tests/test_nsrl_filter.py:

* The ``ImportError`` guard in ``_make_bloom`` (rbloom not installed path).
* The "Loaded N entries..." progress log emitted every 1,000,000 rows in
  ``NSRLFilter.load``.

Style mirrors tests/test_nsrl_filter.py: tmp NSRL fixture files, ``NSRLFilter``
constructed against a real path, and ``monkeypatch`` for the import/IO edges.
"""

import sys
import tempfile
from pathlib import Path

import pytest

from sift_find_evil.carving import nsrl_filter as nsrl_mod
from sift_find_evil.carving.nsrl_filter import NSRLFilter, _make_bloom


@pytest.fixture
def mock_nsrl_file():
    """Create a minimal valid NSRLFile.txt with a single data row."""
    content = (
        '"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode",'
        '"OpSystemCode","SpecialCode"\n'
        '"5d41402abc4b2a76b9719d911017c592","7d793037a0760186574b0282f2f435e7",'
        '"12345678","kernel32.dll","1024","1001","WindowsXP",""\n'
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        yield Path(f.name)
    Path(f.name).unlink(missing_ok=True)


# --- _make_bloom ImportError guard (lines 73-74) ---------------------------


def test_make_bloom_missing_rbloom_raises_import_error(monkeypatch):
    """When rbloom cannot be imported, _make_bloom raises a guided ImportError.

    Inserting ``None`` into ``sys.modules`` for ``rbloom`` makes the
    ``from rbloom import Bloom`` statement raise ImportError, driving the
    except branch (the install-hint message and chained cause).
    """
    monkeypatch.setitem(sys.modules, "rbloom", None)

    with pytest.raises(ImportError, match="rbloom is required") as excinfo:
        _make_bloom(1000, 0.001)

    # Install hint is surfaced and the original ImportError is chained.
    assert "pip install rbloom" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, ImportError)


def test_constructor_bloom_missing_rbloom_propagates(monkeypatch, mock_nsrl_file):
    """use_bloom=True surfaces the ImportError from _make_bloom at construction."""
    monkeypatch.setitem(sys.modules, "rbloom", None)

    with pytest.raises(ImportError, match="rbloom is required"):
        NSRLFilter(mock_nsrl_file, use_bloom=True, expected_items=1000)


# --- load() millionth-row progress log (line 188) --------------------------


class _FakeDictReader:
    """Stand-in for csv.DictReader yielding a large synthetic row stream.

    Exposes ``fieldnames`` (so the format check passes) and iterates exactly
    ``row_count`` rows so the ``count % 1_000_000 == 0`` progress branch fires.
    """

    def __init__(self, row_count):
        self.fieldnames = ["SHA-1", "MD5", "CRC32", "FileName"]
        self._row_count = row_count

    def __iter__(self):
        for i in range(self._row_count):
            yield {"SHA-1": f"{i:040x}", "MD5": f"{i:032x}"}


def test_load_emits_progress_log_every_million_rows(
    mock_nsrl_file, monkeypatch, caplog
):
    """load() logs 'Loaded N entries...' when the row count hits a 1M multiple.

    Patching the module's csv.DictReader with a fake that yields exactly
    1,000,000 rows drives the ``count % 1_000_000 == 0`` progress branch
    without materializing a multi-GB fixture file.
    """
    monkeypatch.setattr(
        nsrl_mod.csv, "DictReader", lambda f: _FakeDictReader(1_000_000)
    )

    nsrl_filter = NSRLFilter(mock_nsrl_file)
    with caplog.at_level("INFO", logger=nsrl_mod.logger.name):
        nsrl_filter.load()

    assert nsrl_filter.loaded is True
    assert any("Loaded 1,000,000 entries" in rec.message for rec in caplog.records)
    # Every synthetic row was inserted into the set backend.
    assert len(nsrl_filter.sha1_hashes) == 1_000_000
