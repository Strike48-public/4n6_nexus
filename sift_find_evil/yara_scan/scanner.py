"""YaraScanner — compile rules and scan files for malware classification.

yara-python is an **optional** dependency. The module imports cleanly on hosts
without libyara; invoking ``compile_from_directory`` or ``scan_file`` raises
``MissingYaraError`` so callers can fall back gracefully.

Design
------
- ``YaraScanner`` wraps a compiled ``yara.Rules`` object and a scan policy
  (file-size cap, string-capture flag).
- ``YaraMatch`` / ``YaraString`` are immutable dataclasses that mirror the
  yara-python match shape so downstream code never touches yara-python types
  directly — this lets us swap implementations (yara-x, etc.) later without
  rewriting detectors.
- Broken .yar files are skipped by default (logged into ``compile_errors``)
  since community rulesets (YARA-Rules, Signature-Base) routinely ship with
  files that fail to compile under newer libyara; ``strict=True`` restores
  fail-fast behavior for unit tests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional

try:
    import yara as _yara
except ImportError:  # pragma: no cover — only exercised on hosts without libyara
    _yara = None

logger = logging.getLogger(__name__)


class MissingYaraError(RuntimeError):
    """Raised when the yara-python package is not installed.

    Callers should catch this and either skip YARA scanning or surface a
    clear message pointing at the install instructions. Raising a dedicated
    exception (rather than ImportError) lets callers distinguish a missing
    YARA install from any other import failure inside this package.
    """


DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB per-file scan cap


@dataclass(frozen=True)
class YaraString:
    """One matching string instance inside a YARA match.

    yara-python returns string matches as ``(offset, identifier, data)`` in
    v4.2 and as a ``StringMatch`` object in v4.3+. This dataclass normalizes
    both.
    """

    identifier: str
    offset: int
    data: bytes


@dataclass(frozen=True)
class YaraMatch:
    """One rule match against one file.

    ``strings`` captures up to a bounded number of string instances to keep
    memory predictable when scanning large files against noisy rules.
    """

    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]
    strings: tuple[YaraString, ...]
    source_file: Path


@dataclass
class CompileError:
    """Record of a .yar file that failed to compile during bulk load."""

    source: str
    message: str


@dataclass(frozen=True)
class DirectoryScanResult:
    """Structured result from ``scan_directory_details``.

    ``matches`` mirrors the legacy ``scan_directory`` return value so existing
    callers migrate by adding ``.matches`` access. ``oversized`` exposes the
    paths skipped because they exceeded ``max_file_size`` — surfacing this
    signal matters once the scanner runs over carved-file corpora (CIRCL
    wiped, M57 memory) where large blobs can legitimately appear and a silent
    skip looks indistinguishable from a genuine no-match.

    ``matches`` is typed as ``Mapping`` (a read-only view) to match the
    frozen-dataclass contract; the constructor wraps the builder's dict in a
    ``MappingProxyType`` so callers can't mutate scan results post-hoc.
    """

    matches: Mapping[Path, list["YaraMatch"]] = field(default_factory=dict)
    oversized: tuple[Path, ...] = ()
    # Paths skipped because reading/stat-ing them raised OSError (I/O error,
    # permission, corrupt cluster). On real evidence these are common — e.g.
    # Chrome's 'Network Persistent State', locked SQLite, partial-read clusters
    # (SFE-4e9). Surfacing them keeps "couldn't read" distinct from "read and
    # matched nothing", the same reason ``oversized`` exists.
    unreadable: tuple[Path, ...] = ()


class YaraScanner:
    """Compile YARA rules and scan files or directories.

    Prefer ``YaraScanner.compile_from_directory(path)`` to the constructor;
    the classmethod enforces the directory-load policy (skip-on-error,
    aggregation across files). The constructor exists for callers who have
    already compiled a ``yara.Rules`` object and want to wrap it.
    """

    def __init__(
        self,
        rules: Any,
        rule_count: int,
        compile_errors: Optional[list[CompileError]] = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        capture_strings: bool = True,
    ):
        if _yara is None:
            raise MissingYaraError(
                "yara-python is not installed. "
                "Install with `pip install yara-python` and ensure libyara "
                "is available (SIFT: `/usr/local/bin/yara`)."
            )
        self._rules = rules
        self._rule_count = rule_count
        self._compile_errors = list(compile_errors or [])
        self._max_file_size = max_file_size
        self._capture_strings = capture_strings

    @property
    def rule_count(self) -> int:
        """Number of rules successfully compiled into this scanner."""
        return self._rule_count

    @property
    def compile_errors(self) -> list[CompileError]:
        """Rules that failed to compile during ``compile_from_directory``."""
        return list(self._compile_errors)

    @classmethod
    def compile_from_directories(
        cls,
        rules_dirs: list[Path],
        *,
        recursive: bool = True,
        strict: bool = False,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        capture_strings: bool = True,
    ) -> "YaraScanner":
        """Compile rules from multiple directories into one unified scanner.

        Each directory contributes a namespace prefix derived from the
        directory name so seed, community, and internal rulesets cannot
        accidentally shadow each other. Broken rule files are skipped (the
        same ``strict=False`` policy as ``compile_from_directory``) so a
        broken community submodule cannot knock the whole scanner offline.

        This is the entry point SFE-qmh uses to load seed plus the
        YARA-Rules and signature-base submodules in a single pass.
        """
        if _yara is None:
            raise MissingYaraError(
                "yara-python is not installed. Install with `pip install yara-python`."
            )
        if not rules_dirs:
            raise ValueError("compile_from_directories requires at least one path")

        filepaths: dict[str, str] = {}
        errors: list[CompileError] = []
        rule_count = 0
        used_any = False

        for rules_dir in rules_dirs:
            if not rules_dir.is_dir():
                raise FileNotFoundError(f"YARA rules directory not found: {rules_dir}")
            prefix = rules_dir.name or "rules"
            rule_files = _list_rule_files(rules_dir, recursive)
            if not rule_files:
                continue
            used_any = True
            for rule_file in rule_files:
                sub_namespace = _namespace_for(rule_file, rules_dir)
                namespace = f"{prefix}.{sub_namespace}"
                count = _compile_one(rule_file, strict=strict, errors=errors)
                if count is None:
                    continue
                rule_count += count
                filepaths[namespace] = str(rule_file)

        if not used_any:
            raise ValueError(
                "no YARA rule files (*.yar, *.yara) found in any directory: "
                f"{[str(p) for p in rules_dirs]}"
            )
        if not filepaths:
            first = errors[0] if errors else None
            raise ValueError(
                f"no YARA rules compiled successfully from {len(rules_dirs)} "
                f"director(ies) ({len(errors)} file(s) failed"
                + (f"; first error: {first.message}" if first else "")
                + ")"
            )

        rules = _yara.compile(filepaths=filepaths)
        return cls(
            rules=rules,
            rule_count=rule_count,
            compile_errors=errors,
            max_file_size=max_file_size,
            capture_strings=capture_strings,
        )

    @classmethod
    def compile_from_directory(
        cls,
        rules_dir: Path,
        *,
        recursive: bool = True,
        strict: bool = False,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        capture_strings: bool = True,
    ) -> "YaraScanner":
        """Compile every ``*.yar``/``*.yara`` file under ``rules_dir``.

        Parameters
        ----------
        rules_dir:
            Directory to walk for rule files.
        recursive:
            Walk subdirectories when True (default).
        strict:
            When True, a single broken rule file aborts the load. Default
            False is more forgiving and matches community-ruleset reality.
        max_file_size:
            Per-file byte cap for subsequent scans. Files larger than this
            raise ``ValueError`` at scan time to prevent memory blow-up on
            disk images or massive archives.
        capture_strings:
            When True (default), matching string instances (with offsets)
            are returned on every match. Disable for faster bulk scans when
            only the rule-name is needed.
        """
        if _yara is None:
            raise MissingYaraError(
                "yara-python is not installed. Install with `pip install yara-python`."
            )
        if not rules_dir.is_dir():
            raise FileNotFoundError(f"YARA rules directory not found: {rules_dir}")

        rule_files = _list_rule_files(rules_dir, recursive)
        if not rule_files:
            raise ValueError(
                f"no YARA rule files (*.yar, *.yara) found under {rules_dir}"
            )

        filepaths: dict[str, str] = {}
        errors: list[CompileError] = []
        rule_count = 0

        for rule_file in rule_files:
            namespace = _namespace_for(rule_file, rules_dir)
            count = _compile_one(rule_file, strict=strict, errors=errors)
            if count is None:
                continue
            rule_count += count
            filepaths[namespace] = str(rule_file)

        if not filepaths:
            # Every rule file failed to compile. Fail loudly rather than
            # returning an empty scanner that silently matches nothing.
            first = errors[0] if errors else None
            raise ValueError(
                f"no YARA rules compiled successfully from {rules_dir} "
                f"({len(errors)} file(s) failed"
                + (f"; first error: {first.message}" if first else "")
                + ")"
            )

        rules = _yara.compile(filepaths=filepaths)
        return cls(
            rules=rules,
            rule_count=rule_count,
            compile_errors=errors,
            max_file_size=max_file_size,
            capture_strings=capture_strings,
        )

    def scan_file(self, target: Path) -> list[YaraMatch]:
        """Scan one file and return its matches."""
        if not target.is_file():
            raise FileNotFoundError(f"scan target not found: {target}")
        size = target.stat().st_size
        if size > self._max_file_size:
            raise ValueError(
                f"{target} is {size} bytes; exceeds max_file_size {self._max_file_size}"
            )
        raw_matches = self._rules.match(filepath=str(target))
        return [self._normalize(m, target) for m in raw_matches]

    def scan_directory(
        self,
        root: Path,
        *,
        recursive: bool = True,
    ) -> dict[Path, list[YaraMatch]]:
        """Scan every regular file under ``root`` and return a {path: matches} map.

        Files exceeding ``max_file_size`` are returned with an empty match
        list rather than raising, so a single oversized file in a batch does
        not abort the whole scan, and a WARNING is logged per skip so the
        signal isn't silently swallowed. Call ``scan_directory_details`` for
        a structured view of which files were skipped, or ``scan_file``
        directly for strict mode.
        """
        matches, _, _ = self._scan_directory_impl(root, recursive=recursive)
        return matches

    def scan_directory_details(
        self,
        root: Path,
        *,
        recursive: bool = True,
    ) -> DirectoryScanResult:
        """Like ``scan_directory`` but also returns the list of oversized skips.

        Use this when the caller needs to surface "file too large to scan" as
        a distinct outcome from "file scanned and matched nothing" — for
        example when reporting coverage against a carved-file corpus.
        """
        matches, oversized, unreadable = self._scan_directory_impl(
            root, recursive=recursive
        )
        return DirectoryScanResult(
            matches=MappingProxyType(matches),
            oversized=tuple(oversized),
            unreadable=tuple(unreadable),
        )

    def _scan_directory_impl(
        self,
        root: Path,
        *,
        recursive: bool,
    ) -> tuple[dict[Path, list[YaraMatch]], list[Path], list[Path]]:
        """Walk ``root`` and return (matches, oversized, unreadable).

        A single unreadable file must never abort the whole scan: on real
        evidence a directory routinely contains files that raise OSError on
        stat()/read (Chrome's 'Network Persistent State', locked SQLite,
        corrupt clusters). Both the ``is_file()`` filter and ``scan_file``
        can raise OSError, so both are guarded and the bad path is recorded
        as ``unreadable`` rather than propagating (SFE-4e9).
        """
        if not root.is_dir():
            raise FileNotFoundError(f"scan root not found: {root}")
        matches: dict[Path, list[YaraMatch]] = {}
        oversized: list[Path] = []
        files, unreadable = self._iter_files(root, recursive=recursive)
        for path in sorted(files):
            try:
                matches[path] = self.scan_file(path)
            except ValueError as exc:
                matches[path] = []
                oversized.append(path)
                logger.warning(
                    "yara scan skipped %s: exceeds max_file_size (%s)",
                    path,
                    exc,
                )
            except OSError as exc:
                matches[path] = []
                unreadable.append(path)
                logger.warning("yara scan skipped %s: unreadable (%s)", path, exc)
        return matches, oversized, unreadable

    def _iter_files(
        self, root: Path, *, recursive: bool
    ) -> tuple[list[Path], list[Path]]:
        """Return ``(regular_files, unreadable_paths)`` under ``root``.

        ``p.is_file()`` calls os.stat() and raises OSError on an unreadable
        entry. That happens inside the walk itself — before ``scan_file`` is
        ever reached — so it must be guarded here or one bad dirent aborts the
        entire directory scan (SFE-4e9). Paths whose stat() raises are returned
        in the second list so the caller can fold them into the ``unreadable``
        skip set rather than losing them.
        """
        iter_paths = root.rglob("*") if recursive else root.glob("*")
        files: list[Path] = []
        unreadable: list[Path] = []
        for p in iter_paths:
            try:
                if p.is_file():
                    files.append(p)
            except OSError as exc:
                unreadable.append(p)
                logger.warning("yara scan skipped %s: unstatable (%s)", p, exc)
        return files, unreadable

    def _normalize(self, raw: Any, source_file: Path) -> YaraMatch:
        """Convert a yara-python match into our immutable dataclass."""
        strings: tuple[YaraString, ...] = ()
        if self._capture_strings:
            strings = tuple(_flatten_strings(raw.strings))
        tags = tuple(raw.tags or ())
        meta = dict(raw.meta or {})
        return YaraMatch(
            rule=raw.rule,
            namespace=raw.namespace or "default",
            tags=tags,
            meta=meta,
            strings=strings,
            source_file=source_file,
        )


def _namespace_for(rule_file: Path, rules_dir: Path) -> str:
    """Derive a stable namespace from the rule file's path under rules_dir."""
    try:
        relative = rule_file.relative_to(rules_dir)
    except ValueError:
        relative = rule_file
    return str(relative.with_suffix("")).replace("/", ".") or rule_file.stem


def _list_rule_files(rules_dir: Path, recursive: bool) -> list[Path]:
    """Return sorted ``*.yar``/``*.yara`` files under ``rules_dir``."""
    pattern_iter = rules_dir.rglob("*") if recursive else rules_dir.glob("*")
    return sorted(
        p for p in pattern_iter if p.is_file() and p.suffix.lower() in (".yar", ".yara")
    )


def _compile_one(
    rule_file: Path,
    *,
    strict: bool,
    errors: list[CompileError],
) -> Optional[int]:
    """Compile one rule file and return its rule count, or None on failure.

    When ``strict`` is True, compilation errors are re-raised instead of
    being recorded. When False, the error is appended to ``errors`` and
    None is returned so the caller can skip the file.
    """
    try:
        compiled = _yara.compile(filepath=str(rule_file))
    except _yara.Error as exc:  # SyntaxError, Error — all subclasses
        if strict:
            raise
        errors.append(CompileError(source=str(rule_file), message=str(exc)))
        return None
    # Re-count successfully-parsed rules by iterating the compiled object.
    # yara.Rules is iterable in 4.2+ and exposes __len__ via iteration in 4.5.
    return sum(1 for _ in compiled)


def _flatten_strings(raw_strings: Any) -> list[YaraString]:
    """Normalize yara-python string matches across library versions.

    yara-python 4.2.x returns ``[(offset, identifier, data), ...]``.
    yara-python 4.3+ returns ``[StringMatch(identifier=..., instances=[...])]``
    where each ``instance`` has ``offset`` and ``matched_data``.
    """
    if not raw_strings:
        return []
    flat: list[YaraString] = []
    for item in raw_strings:
        if isinstance(item, tuple) and len(item) == 3:
            offset, identifier, data = item
            flat.append(
                YaraString(
                    identifier=str(identifier), offset=int(offset), data=bytes(data)
                )
            )
            continue
        # yara-python 4.3+ StringMatch shape
        instances = getattr(item, "instances", None)
        identifier = getattr(item, "identifier", "")
        if instances is None:
            continue
        for instance in instances:
            flat.append(
                YaraString(
                    identifier=str(identifier),
                    offset=int(getattr(instance, "offset", 0)),
                    data=bytes(getattr(instance, "matched_data", b"")),
                )
            )
    return flat
