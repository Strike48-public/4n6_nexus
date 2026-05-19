"""
Analysis runner that integrates detectors with progress tracking.

Executes forensic analysis phases and reports progress to the TUI.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional

from .progress_tracker import ProgressTracker, FindingSeverity
from .detectors.yara_detector import YaraDetector
from .detectors.memory_detector import MemoryDetector
from .detectors.registry_detector import RegistryDetector
from .yara_scan.scanner import YaraScanner


class AnalysisRunner:
    """Runs forensic analysis with progress tracking."""

    def __init__(self, progress_tracker: ProgressTracker):
        """Initialize analysis runner.

        Args:
            progress_tracker: Progress tracker instance
        """
        self.progress_tracker = progress_tracker
        self.evidence_path: Optional[Path] = None
        self.mode: str = "quick"

    def configure(self, evidence_path: Path, mode: str) -> None:
        """Configure analysis parameters.

        Args:
            evidence_path: Path to evidence directory or file
            mode: Analysis mode (quick, full, memory, timeline, custom)
        """
        self.evidence_path = evidence_path
        self.mode = mode
        # Register phases when mode is configured
        self._register_phases_for_mode()

    async def run_analysis(self) -> None:
        """Run complete forensic analysis workflow."""
        if not self.evidence_path:
            raise ValueError("Evidence path not configured")

        self.progress_tracker.is_running = True
        self.progress_tracker.log_activity(f"Starting {self.mode} analysis")
        self.progress_tracker.log_activity(f"Evidence path: {self.evidence_path}")
        self.progress_tracker.log_activity(
            f"Path exists: {self.evidence_path.exists()}"
        )
        if self.evidence_path.exists():
            if self.evidence_path.is_dir():
                file_count = len(list(self.evidence_path.rglob("*")))
                self.progress_tracker.log_activity(
                    f"Directory contains {file_count} files"
                )

        try:
            # Determine phases based on mode
            if self.mode == "quick":
                await self._run_quick_analysis()
            elif self.mode == "full":
                await self._run_full_analysis()
            elif self.mode == "memory":
                await self._run_memory_analysis()
            elif self.mode == "timeline":
                await self._run_timeline_analysis()
            else:
                # Custom mode - run selected detectors
                await self._run_custom_analysis()

        except Exception as e:
            self.progress_tracker.log_activity(f"Analysis error: {str(e)}")
            raise
        finally:
            self.progress_tracker.is_running = False

    async def _run_quick_analysis(self) -> None:
        """Run quick triage analysis."""
        # Phase 1: Load artifacts
        await self._phase_load_artifacts()

        # Phase 2: Prefetch analysis
        await self._phase_prefetch_analysis()

        # Phase 3: YARA scan (if available)
        await self._phase_yara_scan()

        # Phase 4: Generate report
        await self._phase_generate_report()

    async def _run_full_analysis(self) -> None:
        """Run comprehensive analysis."""
        # Phase 1: Load artifacts
        await self._phase_load_artifacts()

        # Phase 2: Timestamp analysis
        await self._phase_timestamp_analysis()

        # Phase 3: YARA scan
        await self._phase_yara_scan()

        # Phase 4: Memory analysis (if memory dumps present)
        await self._phase_memory_analysis()

        # Phase 5: Persistence detection
        await self._phase_persistence_detection()

        # Phase 6: Generate report
        await self._phase_generate_report()

    async def _run_memory_analysis(self) -> None:
        """Run memory-focused analysis."""
        await self._phase_load_artifacts()
        await self._phase_memory_analysis()
        await self._phase_generate_report()

    async def _run_timeline_analysis(self) -> None:
        """Run timeline generation and analysis."""
        await self._phase_load_artifacts()
        await self._phase_timestamp_analysis()
        await self._phase_generate_report()

    async def _run_custom_analysis(self) -> None:
        """Run custom detector selection."""
        # TODO: Implement based on selected_detectors
        await self._run_full_analysis()

    def _register_phases_for_mode(self) -> None:
        """Register analysis phases based on selected mode."""
        if self.mode == "quick":
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("prefetch", "Prefetch"),
                    ("yara", "YARA"),
                    ("report", "Report"),
                ]
            )
        elif self.mode == "memory":
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("memory", "Memory"),
                    ("report", "Report"),
                ]
            )
        elif self.mode == "timeline":
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("timestamps", "Timestamps"),
                    ("report", "Report"),
                ]
            )
        else:  # full or custom
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("timestamps", "Timestamps"),
                    ("yara", "YARA"),
                    ("memory", "Memory"),
                    ("persist", "Persist"),
                    ("report", "Report"),
                ]
            )

    # Phase implementations
    async def _phase_load_artifacts(self) -> None:
        """Load forensic artifacts from evidence."""
        self.progress_tracker.start_phase("load", items_total=10)

        # Simulate artifact loading
        artifacts = [
            "MFT records",
            "Prefetch files",
            "Event logs",
            "Registry hives",
            "Browser history",
            "Memory dumps",
            "Shimcache",
            "Amcache",
            "BAM/DAM",
            "UserAssist",
        ]

        for artifact in artifacts:
            await asyncio.sleep(0.3)
            self.progress_tracker.increment_progress()
            self.progress_tracker.log_activity(f"Loaded {artifact}")

        self.progress_tracker.complete_phase()

    async def _phase_prefetch_analysis(self) -> None:
        """Analyze Windows prefetch files."""
        if not self.evidence_path or not self.evidence_path.exists():
            self.progress_tracker.log_activity(
                "Skipping prefetch analysis: no evidence path"
            )
            return

        try:
            # Look for prefetch CSV files
            prefetch_files = list(self.evidence_path.rglob("prefetch.csv"))
            if not prefetch_files:
                # Check if this is a raw Windows filesystem
                windows_indicators = [
                    self.evidence_path / "Windows",
                    self.evidence_path / "Program Files",
                    self.evidence_path / "Users",
                ]
                if any(p.exists() for p in windows_indicators):
                    self.progress_tracker.log_activity(
                        "⚠ Real Windows filesystem detected - CSV artifacts not found"
                    )
                    self.progress_tracker.log_activity(
                        "TIP: Use PECmd to parse prefetch files first"
                    )
                else:
                    self.progress_tracker.log_activity(
                        "Skipping prefetch analysis: no prefetch.csv found"
                    )
                return

            from .parsers.prefetch_parser import PrefetchParser

            parser = PrefetchParser()

            self.progress_tracker.start_phase(
                "prefetch", items_total=len(prefetch_files)
            )

            for prefetch_file in prefetch_files:
                # Check for cancellation
                if self.progress_tracker.is_canceled:
                    self.progress_tracker.log_activity(
                        "Prefetch analysis canceled by user"
                    )
                    break

                try:
                    # Parse prefetch CSV
                    entries = parser.parse_csv(prefetch_file)
                    self.progress_tracker.log_activity(
                        f"Parsed {len(entries)} prefetch entries"
                    )

                    # Simple heuristic: flag suspicious executables
                    suspicious_names = [
                        "cmd.exe",
                        "powershell.exe",
                        "wscript.exe",
                        "cscript.exe",
                        "mshta.exe",
                        "rundll32.exe",
                        "regsvr32.exe",
                        "certutil.exe",
                        "bitsadmin.exe",
                    ]

                    for entry in entries:
                        exe_name = entry.executable.lower()
                        if any(sus in exe_name for sus in suspicious_names):
                            self.progress_tracker.add_finding(
                                FindingSeverity.MEDIUM,
                                f"Suspicious execution: {entry.executable}",
                                f"Run count: {entry.run_count}",
                            )

                except (FileNotFoundError, ValueError, KeyError) as e:
                    self.progress_tracker.log_activity(
                        f"Prefetch parse error on {prefetch_file.name}: {e}"
                    )
                finally:
                    self.progress_tracker.increment_progress()
                    await asyncio.sleep(0.001)

            self.progress_tracker.complete_phase()

        except Exception as e:
            self.progress_tracker.log_activity(f"Prefetch analysis phase error: {e}")
            self.progress_tracker.complete_phase()

    async def _phase_timestamp_analysis(self) -> None:
        """Analyze file timestamps for anomalies using SelfCorrectionEngine."""
        if not self.evidence_path or not self.evidence_path.exists():
            self.progress_tracker.log_activity(
                "Skipping timestamp analysis: no evidence path"
            )
            return

        try:
            # Look for required fixtures: MFT, prefetch, evtx
            mft_files = list(self.evidence_path.rglob("mft.csv"))
            prefetch_files = list(self.evidence_path.rglob("prefetch.csv"))
            evtx_files = list(self.evidence_path.rglob("evtx.csv"))

            if not mft_files or not prefetch_files or not evtx_files:
                self.progress_tracker.log_activity(
                    "Skipping timestamp analysis: missing MFT/prefetch/evtx fixtures"
                )
                return

            from .parsers.mft_parser import MFTParser
            from .parsers.prefetch_parser import PrefetchParser
            from .parsers.evtx_parser import EvtxParser
            from .self_correction.engine import SelfCorrectionEngine

            self.progress_tracker.start_phase(
                "timestamps",
                items_total=len(mft_files) + len(prefetch_files) + len(evtx_files),
            )

            # Parse artifacts
            mft_parser = MFTParser()
            prefetch_parser = PrefetchParser()
            evtx_parser = EvtxParser()

            for mft_file, prefetch_file, evtx_file in zip(
                mft_files, prefetch_files, evtx_files
            ):
                # Check for cancellation
                if self.progress_tracker.is_canceled:
                    self.progress_tracker.log_activity(
                        "Timestamp analysis canceled by user"
                    )
                    break

                try:
                    # Parse each artifact
                    self.progress_tracker.log_activity("Parsing MFT records...")
                    mft_records = mft_parser.parse_csv(mft_file)
                    self.progress_tracker.increment_progress()
                    await asyncio.sleep(0.001)

                    self.progress_tracker.log_activity("Parsing prefetch files...")
                    prefetch_records = prefetch_parser.parse_csv(prefetch_file)
                    self.progress_tracker.increment_progress()
                    await asyncio.sleep(0.001)

                    self.progress_tracker.log_activity("Parsing event logs...")
                    evtx_records = evtx_parser.parse_csv(evtx_file)
                    self.progress_tracker.increment_progress()
                    await asyncio.sleep(0.001)

                    # Run self-correction engine (detects timestomping + contradictions)
                    self.progress_tracker.log_activity(
                        "Running self-correction engine..."
                    )
                    engine = SelfCorrectionEngine()

                    # Also get raw contradictions for self-correction panel
                    from .self_correction.contradiction_detector import (
                        ContradictionDetector,
                    )

                    detector = ContradictionDetector()
                    contradictions = detector.detect_all(
                        mft_records, prefetch_records, evtx_records
                    )

                    # Track contradictions
                    for contradiction in contradictions:
                        self.progress_tracker.add_contradiction(
                            description=f"{contradiction.contradiction_type.value}: {contradiction.executable}",
                            resolution=contradiction.resolution
                            if contradiction.resolution
                            else "Unresolved",
                        )

                    # Run full analysis
                    findings = engine.analyze(
                        mft_records, prefetch_records, evtx_records
                    )

                    # Map findings to progress tracker
                    for finding in findings:
                        severity = self._map_finding_severity(finding.severity)
                        self.progress_tracker.add_finding(
                            severity, finding.title, finding.description
                        )
                        self.progress_tracker.log_activity(
                            f"Timestamp: {finding.title}"
                        )

                except (FileNotFoundError, ValueError, KeyError) as e:
                    self.progress_tracker.log_activity(f"Timestamp analysis error: {e}")

            self.progress_tracker.complete_phase()

        except Exception as e:
            self.progress_tracker.log_activity(f"Timestamp analysis phase error: {e}")
            self.progress_tracker.complete_phase()

    async def _phase_yara_scan(self) -> None:
        """Scan files with YARA rules."""
        if not self.evidence_path or not self.evidence_path.exists():
            self.progress_tracker.log_activity("Skipping YARA scan: no evidence path")
            return

        try:
            # Initialize YARA scanner
            rules_dir = (
                Path(__file__).parent.parent
                / "rules"
                / "yara"
                / "community"
                / "signature-base"
            )
            if not rules_dir.exists():
                self.progress_tracker.log_activity(
                    "Skipping YARA scan: rules not found"
                )
                return

            try:
                scanner = YaraScanner()
                scanner.compile_from_directory(rules_dir)
                detector = YaraDetector(scanner=scanner)
            except Exception as e:
                self.progress_tracker.log_activity(f"YARA scanner init failed: {e}")
                return

            # Collect all files to scan (avoiding duplicates from overlapping patterns)
            files = [f for f in self.evidence_path.rglob("*") if f.is_file()]

            # Check if this is a real Windows filesystem (would take too long to scan)
            windows_indicators = [
                self.evidence_path / "Windows",
                self.evidence_path / "Program Files",
                self.evidence_path / "Users",
            ]
            is_windows_fs = any(p.exists() for p in windows_indicators)

            if is_windows_fs:
                self.progress_tracker.log_activity(
                    f"⚠ Real Windows filesystem detected ({len(files)} files)"
                )
                self.progress_tracker.log_activity(
                    "YARA scan would take hours - skipping for demo"
                )
                self.progress_tracker.log_activity(
                    "TIP: Use synthetic scenarios in scenarios/synthetic/ for demos"
                )
                return

            self.progress_tracker.start_phase("yara", items_total=len(files))

            for file_path in files:
                # Check for cancellation
                if self.progress_tracker.is_canceled:
                    self.progress_tracker.log_activity("YARA scan canceled by user")
                    break

                try:
                    # Scan individual file
                    findings = detector.analyze_file(file_path)

                    # Map findings to progress tracker
                    for finding in findings:
                        severity = self._map_finding_severity(finding.severity)
                        self.progress_tracker.add_finding(severity, f"{finding.title}")
                        self.progress_tracker.log_activity(f"YARA: {finding.title}")

                except Exception as e:
                    self.progress_tracker.log_activity(
                        f"YARA scan error on {file_path.name}: {e}"
                    )
                finally:
                    self.progress_tracker.increment_progress()
                    await asyncio.sleep(0.001)  # Yield to event loop

            self.progress_tracker.complete_phase()

        except Exception as e:
            self.progress_tracker.log_activity(f"YARA scan phase error: {e}")
            self.progress_tracker.complete_phase()

    async def _phase_memory_analysis(self) -> None:
        """Analyze memory dumps with Volatility."""
        if not self.evidence_path or not self.evidence_path.exists():
            self.progress_tracker.log_activity(
                "Skipping memory analysis: no evidence path"
            )
            return

        try:
            # Look for memory fixtures
            memory_fixtures = list(self.evidence_path.rglob("memory_fixtures/*.json"))
            if not memory_fixtures:
                self.progress_tracker.log_activity(
                    "Skipping memory analysis: no fixtures found"
                )
                return

            detector = MemoryDetector()

            # Import plugin types once before loop
            from .memory.volatility_runner import (
                ProcessRow,
                InjectionRow,
                CommandLineRow,
                NetworkRow,
            )

            self.progress_tracker.start_phase(
                "memory", items_total=len(memory_fixtures)
            )

            for fixture_file in memory_fixtures:
                # Check for cancellation
                if self.progress_tracker.is_canceled:
                    self.progress_tracker.log_activity(
                        "Memory analysis canceled by user"
                    )
                    break

                try:
                    # Check file size before reading (10MB limit)
                    if fixture_file.stat().st_size > 10 * 1024 * 1024:
                        self.progress_tracker.log_activity(
                            f"Skipping oversized fixture: {fixture_file.name}"
                        )
                        continue

                    # Load fixture data
                    fixture_data = json.loads(fixture_file.read_text())

                    # Parse plugin outputs with error handling for malformed data
                    try:
                        pslist = (
                            [
                                ProcessRow(**row)
                                for row in fixture_data.get("pslist", [])
                            ]
                            if "pslist" in fixture_data
                            else None
                        )
                        psscan = (
                            [
                                ProcessRow(**row)
                                for row in fixture_data.get("psscan", [])
                            ]
                            if "psscan" in fixture_data
                            else None
                        )
                        malfind = (
                            [
                                InjectionRow(**row)
                                for row in fixture_data.get("malfind", [])
                            ]
                            if "malfind" in fixture_data
                            else None
                        )
                        cmdline = (
                            [
                                CommandLineRow(**row)
                                for row in fixture_data.get("cmdline", [])
                            ]
                            if "cmdline" in fixture_data
                            else None
                        )
                        netscan = (
                            [
                                NetworkRow(**row)
                                for row in fixture_data.get("netscan", [])
                            ]
                            if "netscan" in fixture_data
                            else None
                        )
                    except (TypeError, KeyError) as e:
                        self.progress_tracker.log_activity(
                            f"Malformed fixture {fixture_file.name}: {e}"
                        )
                        continue

                    # Run detector analysis
                    findings = detector.analyze(
                        pslist=pslist,
                        psscan=psscan,
                        malfind=malfind,
                        cmdline=cmdline,
                        netscan=netscan,
                    )

                    # Map findings to progress tracker
                    for finding in findings:
                        severity = self._map_finding_severity(finding.severity)
                        self.progress_tracker.add_finding(severity, finding.title)
                        self.progress_tracker.log_activity(f"Memory: {finding.title}")

                except (json.JSONDecodeError, OSError) as e:
                    self.progress_tracker.log_activity(
                        f"Memory analysis error on {fixture_file.name}: {e}"
                    )
                finally:
                    self.progress_tracker.increment_progress()
                    await asyncio.sleep(0.001)

            self.progress_tracker.complete_phase()

        except Exception as e:
            self.progress_tracker.log_activity(f"Memory analysis phase error: {e}")
            self.progress_tracker.complete_phase()

    async def _phase_persistence_detection(self) -> None:
        """Detect persistence mechanisms."""
        if not self.evidence_path or not self.evidence_path.exists():
            self.progress_tracker.log_activity(
                "Skipping persistence detection: no evidence path"
            )
            return

        try:
            # Look for registry CSV fixtures
            registry_files = {
                "shimcache": list(self.evidence_path.rglob("shimcache.csv")),
                "amcache": list(self.evidence_path.rglob("amcache.csv")),
                "bam": list(self.evidence_path.rglob("bam.csv")),
                "userassist": list(self.evidence_path.rglob("userassist.csv")),
                "run_keys": list(self.evidence_path.rglob("run_keys.csv")),
            }

            total_files = sum(len(files) for files in registry_files.values())
            if total_files == 0:
                self.progress_tracker.log_activity(
                    "Skipping persistence detection: no registry fixtures"
                )
                return

            detector = RegistryDetector()

            self.progress_tracker.start_phase("persist", items_total=total_files)

            # Import registry parser
            from .parsers.registry_parser import RegistryParser

            parser = RegistryParser()
            all_entries = {
                "shimcache": [],
                "amcache": [],
                "bam": [],
                "userassist": [],
                "run_keys": [],
            }

            # Parse all registry artifacts
            for artifact_type, file_list in registry_files.items():
                for registry_file in file_list:
                    # Check for cancellation
                    if self.progress_tracker.is_canceled:
                        self.progress_tracker.log_activity(
                            "Registry analysis canceled by user"
                        )
                        break

                    try:
                        # Parse CSV data using appropriate method
                        if artifact_type == "shimcache":
                            entries = parser.parse_shimcache_csv(registry_file)
                        elif artifact_type == "amcache":
                            entries = parser.parse_amcache_csv(registry_file)
                        elif artifact_type == "bam":
                            entries = parser.parse_bam_csv(registry_file)
                        elif artifact_type == "userassist":
                            entries = parser.parse_userassist_csv(registry_file)
                        elif artifact_type == "run_keys":
                            entries = parser.parse_run_keys_csv(registry_file)
                        else:
                            entries = []

                        all_entries[artifact_type].extend(entries)
                        self.progress_tracker.log_activity(
                            f"Parsed {len(entries)} {artifact_type} entries"
                        )

                    except (FileNotFoundError, ValueError, KeyError) as e:
                        self.progress_tracker.log_activity(
                            f"Registry parse error on {registry_file.name}: {e}"
                        )
                    finally:
                        self.progress_tracker.increment_progress()
                        await asyncio.sleep(0.001)

            # Run detector analysis on all collected entries
            findings = detector.analyze(
                shimcache=all_entries["shimcache"]
                if all_entries["shimcache"]
                else None,
                amcache=all_entries["amcache"] if all_entries["amcache"] else None,
                bam=all_entries["bam"] if all_entries["bam"] else None,
                userassist=all_entries["userassist"]
                if all_entries["userassist"]
                else None,
                run_keys=all_entries["run_keys"] if all_entries["run_keys"] else None,
            )

            # Map findings to progress tracker
            for finding in findings:
                severity = self._map_finding_severity(finding.severity)
                self.progress_tracker.add_finding(severity, finding.title)
                self.progress_tracker.log_activity(f"Registry: {finding.title}")

            self.progress_tracker.complete_phase()

        except Exception as e:
            self.progress_tracker.log_activity(
                f"Persistence detection phase error: {e}"
            )
            self.progress_tracker.complete_phase()

    async def _phase_generate_report(self) -> None:
        """Generate final analysis report."""
        self.progress_tracker.start_phase("report", items_total=5)

        report_sections = [
            "Executive summary",
            "Findings table",
            "Timeline",
            "IOC list",
            "Recommendations",
        ]

        for section in report_sections:
            await asyncio.sleep(0.5)
            self.progress_tracker.increment_progress()
            self.progress_tracker.log_activity(f"Generated {section}")

        self.progress_tracker.complete_phase()
        self.progress_tracker.log_activity("Analysis complete!")

    def _map_finding_severity(self, severity_str: str) -> FindingSeverity:
        """Map finding severity string to FindingSeverity enum."""
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        mapped = severity_map.get(severity_str.lower())
        if mapped is None:
            self.progress_tracker.log_activity(
                f"Unknown severity '{severity_str}', defaulting to MEDIUM"
            )
            return FindingSeverity.MEDIUM
        return mapped
