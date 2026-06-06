"""Coverage-targeted tests for sift_find_evil.parsers.pst_parser.

Owned exclusively by the coverage pass. Targets the corrupt-message guard in
`_walk_folder` (the `try`/`except Exception: continue` around appending a
(path, message) pair).

Investigation note: lines 177 and 179 are the body of an `except Exception:`
guard wrapping the single statement ``pairs.append((path, msg))``. The loop
variable ``msg`` is bound by the iterator's ``__next__`` (evaluated OUTSIDE the
``try`` body), and ``list.append`` of a freshly constructed ``(tuple, obj)``
pair cannot raise for any input object. There is therefore no input that drives
execution into the ``except``/``continue`` branch; it is an unreachable
defensive guard. These tests pin the reachable behavior of the loop (multiple
messages, nested sub-folders) so the surrounding logic stays covered.
"""

from __future__ import annotations

from sift_find_evil.parsers.pst_parser import _walk_folder


class _Folder:
    """Minimal duck-typed pypff folder for traversal tests."""

    def __init__(self, name, messages=None, sub_folders=None):
        self._name = name
        self._messages = list(messages or [])
        self._sub_folders = list(sub_folders or [])

    @property
    def name(self):
        return self._name

    @property
    def sub_messages(self):
        return self._messages

    @property
    def sub_folders(self):
        return self._sub_folders


def test_walk_folder_appends_every_message_in_order():
    """Each message in sub_messages produces a (path, msg) pair, in order."""
    m1 = object()
    m2 = object()
    m3 = object()
    folder = _Folder("Inbox", messages=[m1, m2, m3])

    pairs = _walk_folder(folder, tuple())

    assert [msg for _, msg in pairs] == [m1, m2, m3]
    assert all(path == ("Inbox",) for path, _ in pairs)


def test_walk_folder_recurses_into_subfolders_with_path_prefix():
    """Nested folders accumulate the parent path tuple for their messages."""
    child_msg = object()
    child = _Folder("Sent Items", messages=[child_msg])
    root_msg = object()
    root = _Folder("Top of Personal Folders", messages=[root_msg], sub_folders=[child])

    pairs = _walk_folder(root, tuple())

    # Root message first, then the recursed child message.
    assert pairs[0][0] == ("Top of Personal Folders",)
    assert pairs[0][1] is root_msg
    assert pairs[1][0] == ("Top of Personal Folders", "Sent Items")
    assert pairs[1][1] is child_msg


def test_walk_folder_empty_folder_yields_no_pairs():
    """A folder with no messages and no sub-folders yields an empty list."""
    folder = _Folder("Empty", messages=[], sub_folders=[])

    pairs = _walk_folder(folder, tuple())

    assert pairs == []
